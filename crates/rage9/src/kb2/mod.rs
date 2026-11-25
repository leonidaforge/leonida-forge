//! KB2 movie containers: a 48-byte header, a little-endian frame index and
//! per-frame audio track records.
//!
//! The structure is the one the research established (KB2-F01 and the revised
//! `evidence/kb2j/INDEX.md` rows): `KB2j` or `KB2n`, a header with the frame
//! count, the largest frame size, the dimensions and an uninterpreted flags
//! word, an optional audio descriptor block, and `frame_count + 1` frame
//! index entries whose low bit is a flag and whose remaining bits are an
//! offset.
//!
//! Nothing is decoded: no frame, no codec and no track type is claimed. The
//! flags word stays a value with its bits reported as set or clear.

#[cfg(test)]
mod tests;

use std::fmt;

pub const MAGIC_J: [u8; 4] = *b"KB2j";
pub const MAGIC_N: [u8; 4] = *b"KB2n";
/// The common header.
pub const HEADER_LEN: usize = 0x30;
/// Bytes of one frame index entry.
pub const INDEX_LEN: usize = 4;
/// Bytes of one audio descriptor array per track.
pub const AUDIO_ARRAY_LEN: usize = 12;
/// Failures listed in a report.
pub const MAX_FAILURES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotKB2,
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotKB2 => f.write_str("not a KB2 container"),
            Error::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}

pub fn is_kb2(head: &[u8]) -> bool {
    head.starts_with(&MAGIC_J) || head.starts_with(&MAGIC_N)
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Which signature the payload carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    J,
    N,
}

impl Variant {
    pub fn name(self) -> &'static str {
        match self {
            Variant::J => "KB2j",
            Variant::N => "KB2n",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Track {
    /// The `+0x30` array value. Matches the largest decoded record size in
    /// the observed audio rows; not named.
    pub decoded_max: u32,
    pub rate: u16,
    pub rate_flags: u16,
    pub id: u32,
}

/// One frame index entry: the low bit and the offset after masking it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub index: u32,
    pub raw: u32,
    pub flag: bool,
    pub offset: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameChecks {
    pub monotone: bool,
    pub intervals_within_largest: bool,
    pub last_offset_matches: bool,
    pub first_is_keyframe: bool,
    pub frames_within_table: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AudioRecords {
    pub frames: u64,
    pub non_empty: u64,
    pub zero_records: u64,
    pub bytes: u64,
    pub violations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub variant: Variant,
    /// The value at `+0x04`, which is the payload size minus 8.
    pub declared_len: u32,
    pub frame_count: u32,
    pub largest_frame: u32,
    pub duplicate_count: u32,
    pub width: u32,
    pub height: u32,
    pub rate_num: u32,
    pub rate_den: u32,
    pub flags: u32,
    pub tracks: u32,
    /// The value at `+0x2C`: a per-payload constant, not interpreted.
    pub variant_word: u32,
    pub audio: Vec<Track>,
    /// Whether the track ids are a permutation of `0..tracks`.
    pub track_ids_permutation: bool,
    pub table_offset: u32,
    pub table_end: u32,
    /// The first entries, kept for display; every entry is checked.
    pub frames: Vec<Frame>,
    pub frame_count_checked: u32,
    pub checks: FrameChecks,
    pub audio_records: AudioRecords,
    pub failures: Vec<String>,
    pub size: u64,
    pub issues: Vec<String>,
}

/// Reader limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_len: u64,
    pub max_frames: u32,
    pub max_tracks: u32,
    /// Frames listed in the report.
    pub max_kept: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // The largest observed payload is 373,705,456 bytes.
            max_len: 512 << 20,
            max_frames: 4 << 20,
            max_tracks: 64,
            max_kept: 16,
        }
    }
}

/// Parses one KB2 container.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Report, Error> {
    let variant = match bytes.get(..4) {
        Some(magic) if magic == MAGIC_J => Variant::J,
        Some(magic) if magic == MAGIC_N => Variant::N,
        _ => return Err(Error::NotKB2),
    };
    if bytes.len() < HEADER_LEN {
        return Err(invalid("the header is truncated"));
    }
    if bytes.len() as u64 > limits.max_len {
        return Err(invalid(format!(
            "the payload is {} bytes, more than the {} byte limit",
            bytes.len(),
            limits.max_len
        )));
    }
    let declared_len = le_u32(bytes, 4).ok_or_else(|| invalid("the header is truncated"))?;
    let frame_count = le_u32(bytes, 8).ok_or_else(|| invalid("the header is truncated"))?;
    let largest_frame = le_u32(bytes, 0x0C).ok_or_else(|| invalid("the header is truncated"))?;
    let duplicate_count = le_u32(bytes, 0x10).ok_or_else(|| invalid("the header is truncated"))?;
    let width = le_u32(bytes, 0x14).ok_or_else(|| invalid("the header is truncated"))?;
    let height = le_u32(bytes, 0x18).ok_or_else(|| invalid("the header is truncated"))?;
    let rate_num = le_u32(bytes, 0x1C).ok_or_else(|| invalid("the header is truncated"))?;
    let rate_den = le_u32(bytes, 0x20).ok_or_else(|| invalid("the header is truncated"))?;
    let flags = le_u32(bytes, 0x24).ok_or_else(|| invalid("the header is truncated"))?;
    let tracks = le_u32(bytes, 0x28).ok_or_else(|| invalid("the header is truncated"))?;
    let variant_word = le_u32(bytes, 0x2C).ok_or_else(|| invalid("the header is truncated"))?;
    if frame_count > limits.max_frames {
        return Err(invalid(format!(
            "the header declares {frame_count} frames, more than the {} limit",
            limits.max_frames
        )));
    }
    if tracks > limits.max_tracks {
        return Err(invalid(format!(
            "the header declares {tracks} tracks, more than the {} limit",
            limits.max_tracks
        )));
    }
    let logical = u64::from(declared_len) + 8;
    let mut issues = Vec::new();
    if logical != bytes.len() as u64 {
        issues.push(format!(
            "the header declares {logical} bytes, but the payload is {}",
            bytes.len()
        ));
    }
    // The declared extent bounds every frame and record. A stored payload
    // padded to the archive alignment can be longer than the declared extent.
    let extent = logical.min(bytes.len() as u64);

    if duplicate_count != frame_count {
        issues.push(format!(
            "the field at +0x10 is {duplicate_count}, not the frame count {frame_count}"
        ));
    }

    // The audio descriptor arrays, grouped by field.
    let mut audio = Vec::new();
    let tracks_at = HEADER_LEN;
    if tracks > 0 {
        let needed = tracks_at + AUDIO_ARRAY_LEN * tracks as usize;
        if needed > bytes.len() {
            return Err(invalid(format!(
                "the audio descriptors need {needed} bytes, but the payload holds {}",
                bytes.len()
            )));
        }
        for ix in 0..tracks as usize {
            let base = tracks_at;
            let decoded_max = le_u32(bytes, base + 4 * ix).unwrap_or(0);
            let rate_flags = le_u32(bytes, base + 4 * tracks as usize + 4 * ix).unwrap_or(0);
            let id = le_u32(bytes, base + 8 * tracks as usize + 4 * ix).unwrap_or(0);
            audio.push(Track {
                decoded_max,
                rate: (rate_flags & 0xFFFF) as u16,
                rate_flags: (rate_flags >> 16) as u16,
                id,
            });
        }
    }
    let mut sorted_ids: Vec<u32> = audio.iter().map(|track| track.id).collect();
    sorted_ids.sort_unstable();
    let track_ids_permutation = tracks == 0
        || (sorted_ids.len() == tracks as usize
            && sorted_ids
                .iter()
                .enumerate()
                .all(|(ix, &id)| id == ix as u32));

    // The frame index.
    let table_offset = HEADER_LEN + AUDIO_ARRAY_LEN * tracks as usize;
    let entries = u64::from(frame_count) + 1;
    let table_end = table_offset as u64 + entries * INDEX_LEN as u64;
    if table_end > bytes.len() as u64 {
        return Err(invalid(format!(
            "the frame index ends at {table_end:#x}, past the {} byte payload",
            bytes.len()
        )));
    }
    let mut frames = Vec::new();
    let mut checks = FrameChecks {
        monotone: true,
        intervals_within_largest: true,
        last_offset_matches: false,
        first_is_keyframe: false,
        frames_within_table: true,
    };
    let mut failures = Vec::new();
    let mut previous: Option<u32> = None;
    let mut first_offset = 0u32;
    let mut last_offset = 0u32;
    for ix in 0..entries as usize {
        let at = table_offset + ix * INDEX_LEN;
        let raw = le_u32(bytes, at).ok_or_else(|| invalid("a frame entry is truncated"))?;
        let flag = raw & 1 != 0;
        let offset = raw & !1;
        if ix == 0 {
            checks.first_is_keyframe = flag;
            first_offset = offset;
        }
        if let Some(previous) = previous
            && offset < previous
        {
            checks.monotone = false;
            if failures.len() < MAX_FAILURES {
                failures.push(format!(
                    "frame entry {ix} holds {offset:#x}, below the previous entry {previous:#x}"
                ));
            }
        }
        if ix > 0
            && previous.is_some_and(|previous| offset.saturating_sub(previous) > largest_frame)
        {
            checks.intervals_within_largest = false;
            if failures.len() < MAX_FAILURES {
                failures.push(format!(
                    "frame {ix} spans more than the largest frame size {largest_frame}"
                ));
            }
        }
        if ix > 0 && ((offset as u64) < table_end || (offset as u64) > extent) {
            checks.frames_within_table = false;
            if failures.len() < MAX_FAILURES {
                failures.push(format!(
                    "frame entry {ix} holds {offset:#x}, outside {table_end:#x}..{extent:#x}"
                ));
            }
        }
        last_offset = offset;
        if frames.len() < limits.max_kept {
            frames.push(Frame {
                index: ix as u32,
                raw,
                flag,
                offset,
            });
        }
        previous = Some(offset);
    }
    checks.last_offset_matches = u64::from(last_offset) == extent
        && le_u32(bytes, table_offset + (entries as usize - 1) * INDEX_LEN)
            .is_some_and(|raw| raw & 1 == 0);
    if first_offset != table_end as u32 {
        issues.push(format!(
            "the first masked entry is {first_offset:#x}, not the table end {table_end:#x}"
        ));
    }
    if !checks.last_offset_matches {
        issues.push(format!(
            "the last entry is {last_offset:#x}, not the declared extent {extent:#x} with its low bit clear"
        ));
    }
    if !checks.monotone {
        issues.push("the masked frame offsets are not non-decreasing".to_string());
    }
    if !checks.intervals_within_largest {
        issues.push(format!(
            "a frame interval exceeds the largest frame size {largest_frame}"
        ));
    }
    if !checks.frames_within_table {
        issues.push("a frame offset lies outside the frame-data extent".to_string());
    }
    if !track_ids_permutation {
        issues.push("the track ids are not a permutation of 0..tracks".to_string());
    }

    // Per-frame audio records, counted without keeping the packets.
    let mut audio_records = AudioRecords::default();
    if tracks > 0 {
        let frame_starts: Vec<u32> = (0..entries as usize)
            .map(|ix| le_u32(bytes, table_offset + ix * INDEX_LEN).unwrap_or(0) & !1)
            .collect();
        for frame in 0..frame_count as usize {
            let start = frame_starts.get(frame).copied().unwrap_or(extent as u32) as usize;
            let end = frame_starts
                .get(frame + 1)
                .copied()
                .unwrap_or(extent as u32) as usize;
            let end = end.min(bytes.len()).min(extent as usize);
            let start = start.min(end);
            if start >= end {
                continue;
            }
            audio_records.frames += 1;
            let mut at = start;
            for track in 0..tracks as usize {
                if at + 4 > end {
                    audio_records.violations += 1;
                    if failures.len() < MAX_FAILURES {
                        failures.push(format!(
                            "frame {frame} track {track} has no record inside the frame"
                        ));
                    }
                    break;
                }
                let record_bytes = le_u32(bytes, at).unwrap_or(0);
                if record_bytes == 0 {
                    audio_records.zero_records += 1;
                    at += 4;
                    continue;
                }
                if record_bytes < 4 {
                    audio_records.violations += 1;
                    if failures.len() < MAX_FAILURES {
                        failures.push(format!(
                            "frame {frame} track {track} declares {record_bytes} record bytes"
                        ));
                    }
                    break;
                }
                // [u32 record_bytes][u32 decoded_bytes][record_bytes - 4 data].
                let next = at + 4 + record_bytes as usize;
                if next > end {
                    audio_records.violations += 1;
                    if failures.len() < MAX_FAILURES {
                        failures.push(format!(
                            "frame {frame} track {track} record ends at {next:#x}, past the frame end {end:#x}"
                        ));
                    }
                    break;
                }
                if at + 8 > end {
                    audio_records.violations += 1;
                    if failures.len() < MAX_FAILURES {
                        failures.push(format!(
                            "frame {frame} track {track} has no decoded-size field"
                        ));
                    }
                    break;
                }
                audio_records.non_empty += 1;
                audio_records.bytes += u64::from(record_bytes);
                at = next;
            }
        }
    }

    Ok(Report {
        variant,
        declared_len,
        frame_count,
        largest_frame,
        duplicate_count,
        width,
        height,
        rate_num,
        rate_den,
        flags,
        tracks,
        variant_word,
        audio,
        track_ids_permutation,
        table_offset: table_offset as u32,
        table_end: table_end as u32,
        frames,
        frame_count_checked: entries as u32,
        checks,
        audio_records,
        failures,
        size: bytes.len() as u64,
        issues,
    })
}
