//! Tests on synthetic KB2 containers built in memory.

use super::*;

struct Build {
    variant: [u8; 4],
    frames: Vec<Vec<u8>>,
    tracks: Vec<(u32, u32, u32)>,
    flags: u32,
    largest: Option<u32>,
    /// Overrides the frame entries after the builder fills them.
    override_entries: Vec<(usize, u32)>,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            variant: MAGIC_N,
            frames: vec![vec![0x11; 8], vec![0x22; 12]],
            tracks: Vec::new(),
            flags: 0x0004_0013,
            largest: None,
            override_entries: Vec::new(),
        }
    }
}

impl Build {
    fn payload(&self) -> Vec<u8> {
        let tracks = self.tracks.len();
        let entries = self.frames.len() + 1;
        let table_offset = HEADER_LEN + AUDIO_ARRAY_LEN * tracks;
        let table_end = table_offset + INDEX_LEN * entries;
        let mut data = Vec::new();
        let mut offsets = vec![table_end as u32];
        for frame in &self.frames {
            data.extend_from_slice(frame);
            offsets.push(table_end as u32 + data.len() as u32);
        }
        let size = table_end + data.len();
        let largest = self.largest.unwrap_or_else(|| {
            self.frames
                .windows(2)
                .map(|pair| pair[1].len())
                .chain(self.frames.first().map(Vec::len))
                .max()
                .unwrap_or(0) as u32
        });
        let mut bytes = vec![0u8; table_end];
        bytes[..4].copy_from_slice(&self.variant);
        bytes[4..8].copy_from_slice(&((size - 8) as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(self.frames.len() as u32).to_le_bytes());
        bytes[0x0C..0x10].copy_from_slice(&largest.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&(self.frames.len() as u32).to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&640u32.to_le_bytes());
        bytes[0x18..0x1C].copy_from_slice(&480u32.to_le_bytes());
        bytes[0x1C..0x20].copy_from_slice(&30u32.to_le_bytes());
        bytes[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x24..0x28].copy_from_slice(&self.flags.to_le_bytes());
        bytes[0x28..0x2C].copy_from_slice(&(tracks as u32).to_le_bytes());
        bytes[0x2C..0x30].copy_from_slice(&0x87E9_0500u32.to_le_bytes());
        for (ix, (decoded, rate_flags, id)) in self.tracks.iter().enumerate() {
            let base = HEADER_LEN;
            bytes[base + 4 * ix..base + 4 * ix + 4].copy_from_slice(&decoded.to_le_bytes());
            bytes[base + 4 * tracks + 4 * ix..base + 4 * tracks + 4 * ix + 4]
                .copy_from_slice(&rate_flags.to_le_bytes());
            bytes[base + 8 * tracks + 4 * ix..base + 8 * tracks + 4 * ix + 4]
                .copy_from_slice(&id.to_le_bytes());
        }
        for (ix, &offset) in offsets.iter().enumerate() {
            let raw = if ix == 0 { offset | 1 } else { offset };
            bytes[table_offset + 4 * ix..table_offset + 4 * ix + 4]
                .copy_from_slice(&raw.to_le_bytes());
        }
        for (ix, raw) in &self.override_entries {
            let at = table_offset + 4 * ix;
            bytes[at..at + 4].copy_from_slice(&raw.to_le_bytes());
        }
        bytes.extend_from_slice(&data);
        bytes
    }
}

fn audio_record(record_bytes: u32, decoded: u32, data_len: usize) -> Vec<u8> {
    let mut bytes = record_bytes.to_le_bytes().to_vec();
    if record_bytes > 0 {
        bytes.extend_from_slice(&decoded.to_le_bytes());
    }
    bytes.extend(std::iter::repeat_n(0x33u8, data_len));
    bytes
}

#[test]
fn parses_both_variants() {
    for variant in [MAGIC_J, MAGIC_N] {
        let bytes = Build {
            variant,
            ..Build::default()
        }
        .payload();
        let report = parse(&bytes, &Limits::default()).unwrap();
        assert_eq!(
            report.variant.name(),
            if variant == MAGIC_J { "KB2j" } else { "KB2n" }
        );
        assert_eq!(report.frame_count, 2);
        assert_eq!(report.width, 640);
        assert_eq!(report.height, 480);
        assert_eq!((report.rate_num, report.rate_den), (30, 1));
        assert_eq!(report.table_offset, HEADER_LEN as u32);
        assert!(report.checks.monotone);
        assert!(report.checks.first_is_keyframe);
        assert!(report.checks.last_offset_matches);
        assert!(report.checks.intervals_within_largest);
        assert!(report.checks.frames_within_table);
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        assert_eq!(report.frames[0].offset, report.table_end);
        assert!(report.frames[0].flag);
    }
}

#[test]
fn a_non_monotone_frame_table_is_reported() {
    let bytes = Build {
        override_entries: vec![(2, 0x0000_0010)],
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert!(!report.checks.monotone);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("non-decreasing"))
    );
}

#[test]
fn an_invalid_final_offset_is_reported() {
    let bytes = Build {
        override_entries: vec![(2, 0x0000_0100)],
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert!(!report.checks.last_offset_matches);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("declared extent"))
    );
}

#[test]
fn a_frame_beyond_the_declared_extent_is_reported() {
    let mut build = Build::default();
    let mut bytes = build.payload();
    // Shrink the declared length by 8 bytes.
    let declared = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    bytes[4..8].copy_from_slice(&(declared - 8).to_le_bytes());
    build.largest = Some(0x1000);
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert!(!report.checks.frames_within_table);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("frame-data extent"))
    );
}

#[test]
fn audio_records_are_counted_with_empty_and_non_empty_entries() {
    // Two frames, one track. Frame 0 has an empty record, frame 1 a packet.
    let record = audio_record(8, 32, 4);
    let mut frame0 = vec![0u8; 4];
    frame0.extend_from_slice(&[0xAA; 4]);
    let mut frame1 = record.clone();
    frame1.extend_from_slice(&[0xBB; 4]);
    let bytes = Build {
        frames: vec![frame0, frame1],
        tracks: vec![(145_920, 0x7000_BB80, 0)],
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert_eq!(report.tracks, 1);
    assert_eq!(report.audio[0].decoded_max, 145_920);
    assert_eq!(report.audio[0].rate, 0xBB80);
    assert_eq!(report.audio[0].rate_flags, 0x7000);
    assert!(report.track_ids_permutation);
    assert_eq!(report.audio_records.frames, 2);
    assert_eq!(report.audio_records.zero_records, 1);
    assert_eq!(report.audio_records.non_empty, 1);
    assert_eq!(report.audio_records.violations, 0);
    assert_eq!(report.audio_records.bytes, 8);
}

#[test]
fn a_record_below_four_bytes_is_a_violation() {
    let mut frame = 3u32.to_le_bytes().to_vec();
    frame.extend_from_slice(&[0u8; 8]);
    let bytes = Build {
        frames: vec![frame],
        tracks: vec![(0, 0, 0)],
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert_eq!(report.audio_records.violations, 1);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("record bytes"))
    );
}

#[test]
fn a_truncated_decoded_size_field_is_a_violation() {
    // record_bytes = 4 with no room for the decoded word.
    let frame = vec![4u8, 0, 0, 0];
    let bytes = Build {
        frames: vec![frame],
        tracks: vec![(0, 0, 0)],
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert_eq!(report.audio_records.violations, 1);
}

#[test]
fn an_oversized_packet_range_is_a_violation() {
    let mut frame = 64u32.to_le_bytes().to_vec();
    frame.extend_from_slice(&16u32.to_le_bytes());
    frame.extend_from_slice(&[0u8; 4]);
    let bytes = Build {
        frames: vec![frame],
        tracks: vec![(0, 0, 0)],
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert_eq!(report.audio_records.violations, 1);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("past the frame end"))
    );
}

#[test]
fn nonstandard_track_identifiers_are_reported_separately() {
    let bytes = Build {
        frames: vec![vec![0u8; 8]],
        tracks: vec![(144_000, 0x7000_BB80, 3), (144_000, 0x7000_BB80, 1)],
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert!(!report.track_ids_permutation);
    let ids: Vec<u32> = report.audio.iter().map(|track| track.id).collect();
    assert_eq!(ids, vec![3, 1]);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("permutation"))
    );
}

#[test]
fn unknown_flags_stay_values() {
    let bytes = Build {
        flags: 0x0014_0012,
        ..Build::default()
    }
    .payload();
    let report = parse(&bytes, &Limits::default()).unwrap();
    assert_eq!(report.flags, 0x0014_0012);
    let text = format!("{report:?}");
    assert!(!text.contains("alpha"));
}

#[test]
fn a_truncated_header_and_index_are_errors() {
    assert!(matches!(
        parse(b"KB2x", &Limits::default()),
        Err(Error::NotKB2)
    ));
    assert!(matches!(
        parse(b"KB2n", &Limits::default()),
        Err(Error::Invalid(_))
    ));
    let mut bytes = Build::default().payload();
    bytes.truncate(0x20);
    assert!(parse(&bytes, &Limits::default()).is_err());
    let mut bytes = Build::default().payload();
    bytes.truncate(HEADER_LEN + 4);
    assert!(parse(&bytes, &Limits::default()).is_err());
}

#[test]
fn excessive_counts_are_refused() {
    let bytes = Build::default().payload();
    let limits = Limits {
        max_frames: 1,
        ..Limits::default()
    };
    assert!(parse(&bytes, &limits).is_err());
    let limits = Limits {
        max_tracks: 0,
        ..Limits::default()
    };
    let bytes = Build {
        tracks: vec![(0, 0, 0)],
        ..Build::default()
    }
    .payload();
    assert!(parse(&bytes, &limits).is_err());
}
