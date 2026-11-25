//! RDS5: a flat record container that holds an ETPF chunk and data blocks.
//!
//! The layout is the recovery documentation's, checked against 57 sample
//! files; no engine code was traced. Every count is bounded and every offset
//! checked, and a structural violation is an error rather than a guess.
//!
//! ```text
//! 0x00  header, 0x10 bytes
//! 0x10  record array, record_count * 8 bytes
//!       zero padding to the next 0x100 boundary
//!       ETPF chunk: 0x10-byte header, entry_count * 16-byte entries,
//!                   16 * entry_count + field_m bytes of content
//!       zero padding to a 0x1000 boundary from the chunk start
//!       data blocks, each starting on a 0x100 boundary
//! ```
//!
//! Block records carry a storage selector. Only one value is identified, and
//! it selects zlib in all but 82 of the observed blocks. A block with another
//! selector, or with the zlib selector and no zlib header, is reported as an
//! unidentified codec and is never decoded by guesswork.
//!
//! Entry fields carry no established meaning, so they are exposed as words.
//! Block payload bytes are never part of a report; [`decode_block`] hands
//! them to a caller that asks for them.

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::{Decompress, FlushDecompress, Status as ZlibStatus};

/// The four bytes every container starts with.
pub const MAGIC: [u8; 4] = *b"RDS5";
/// The four bytes the chunk after the record array starts with.
pub const ETPF_MAGIC: [u8; 4] = *b"ETPF";
/// The only ETPF type word observed.
pub const ETPF_TYPE: u32 = 0x27A;
/// The versions whose header layout was observed. Others are rejected.
pub const VERSIONS: [u32; 2] = [0x1600_0000, 0x1600_0001];
/// The fixed header length.
pub const HEADER_LEN: u64 = 0x10;
/// Offsets are stored in units of this many bytes, so a record cannot address
/// more than 4 GiB.
pub const OFFSET_UNIT: u64 = 0x100;
/// Blocks start on this boundary.
pub const BLOCK_ALIGN: u64 = 0x100;
/// The first block is aligned from the ETPF start to this boundary.
const ETPF_ALIGN: u64 = 0x1000;
const RECORD_LEN: u64 = 8;
const ETPF_HEADER_LEN: u64 = 0x10;
const ENTRY_LEN: u64 = 16;
const OFFSET_MASK: u32 = 0x00FF_FFFF;
/// Bytes scanned per step by the padding check and the block classifier.
const STEP: usize = 1024 * 1024;
/// Stored bytes fed to the decoder per step.
const DECODE_INPUT: usize = 64 * 1024;
/// Decoded bytes produced per step.
const DECODE_OUTPUT: usize = 64 * 1024;

#[derive(Debug)]
pub enum Error {
    NotRds5,
    /// The input breaks the format contract or a limit.
    Invalid(String),
    Io(io::Error),
    Cancelled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotRds5 => f.write_str("not an RDS5 container"),
            Error::Invalid(reason) => f.write_str(reason),
            Error::Io(err) => err.fmt(f),
            Error::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}

fn check(cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// Reader limits. Every one of them is checked before memory is allocated for
/// the thing it bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The whole container.
    pub max_len: u64,
    pub max_records: u32,
    pub max_entries: u32,
    /// One block's stored range.
    pub max_block_stored: u64,
    /// One block's decoded size.
    pub max_block_len: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // The offset field cannot address past 4 GiB; the largest observed
            // file is 2.63 GiB.
            max_len: 4 << 30,
            max_records: 2_000_000,
            max_entries: 2_000_000,
            max_block_stored: 256 << 20,
            max_block_len: 64 << 20,
        }
    }
}

/// Whether `head` starts an RDS5 container.
pub fn is_rds5(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

/// One 8-byte record. Its offset is absolute and a multiple of
/// [`OFFSET_UNIT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub index: u32,
    pub offset: u64,
    /// Bits 24..31 of the record's first word. Selects the block codec on
    /// block records; 0 on every observed record 0.
    pub high_byte: u8,
    /// The record's second word.
    pub second_word: u32,
}

impl Record {
    /// Bits 0..15 of the second word: on block records a 16-bit wrapping
    /// counter of the uncompressed position in units of 0x4000 bytes.
    pub fn counter(&self) -> u16 {
        (self.second_word & 0xFFFF) as u16
    }

    /// Bits 16..31 of the second word. Meaning unknown.
    pub fn upper(&self) -> u16 {
        (self.second_word >> 16) as u16
    }

    /// Bits 2..3 of the high byte: the 2-bit storage selector of a block.
    pub fn selector(&self) -> u8 {
        (self.high_byte >> 2) & 0x03
    }
}

/// How a block's bytes are stored, as far as the record and the stream header
/// establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// The selector names zlib and the bytes start with a zlib header. The
    /// stream itself is only checked when it is decoded.
    Zlib,
    /// The selector names zlib but the bytes do not start with a zlib
    /// header. 82 observed blocks are like this; their codec is unknown.
    NotZlib,
    /// The selector names a codec that was not identified. Carries the
    /// selector value.
    Unidentified(u8),
    /// Not read.
    Unread,
}

impl Storage {
    pub fn name(self) -> &'static str {
        match self {
            Storage::Zlib => "zlib",
            Storage::NotZlib => "not_zlib",
            Storage::Unidentified(_) => "unidentified",
            Storage::Unread => "unread",
        }
    }

    /// Whether [`decode_block`] will try to inflate the block.
    pub fn is_zlib(self) -> bool {
        self == Storage::Zlib
    }
}

/// One data block: the range from its record's offset to the next record's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    /// The block's position among the blocks, starting at 0.
    pub index: u32,
    /// The record that holds the block, starting at 1.
    pub record: u32,
    pub offset: u64,
    pub stored_len: u64,
    pub high_byte: u8,
    pub counter: u16,
    /// The second word's upper half. Meaning unknown.
    pub upper: u16,
    pub storage: Storage,
}

impl Block {
    pub fn selector(&self) -> u8 {
        (self.high_byte >> 2) & 0x03
    }
}

/// One 16-byte ETPF entry. No field meaning is established, so the four words
/// are exposed as they are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub index: u32,
    pub words: [u32; 4],
}

impl Entry {
    /// Low 16 bits of the third word: a wrapping counter in units of 0x1000
    /// bytes. The rest of the entry has no established meaning.
    pub fn page(&self) -> u16 {
        (self.words[2] & 0xFFFF) as u16
    }
}

/// A parsed container: header, records, the ETPF chunk's extent and the
/// blocks. Block storage is [`Storage::Unread`] until [`Container::classify`]
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// The file length the container was parsed against.
    pub len: u64,
    pub version: u32,
    /// `0x1000` plus the sum of the block sizes, as observed. Not checked
    /// against the blocks.
    pub uncompressed_total: u32,
    pub records: Vec<Record>,
    pub etpf_offset: u64,
    pub entry_count: u32,
    pub field_m: u32,
    /// The end of the ETPF content: the chunk position plus
    /// `0x10 + 0x20 * entry_count + field_m`.
    pub content_end: u64,
    /// The first block, which is record 1's offset.
    pub first_block: u64,
    pub blocks: Vec<Block>,
    /// Observations that do not break the contract but differ from every
    /// sample the documentation covers.
    pub warnings: Vec<String>,
}

impl Container {
    /// Reads the structure of the container that occupies the first `len`
    /// bytes of `source`. Nothing beyond the record array, the ETPF header and
    /// the padding is read, so large blocks cost nothing here.
    pub fn read<R: Read + Seek>(
        source: &mut R,
        len: u64,
        limits: &Limits,
        cancel: &AtomicBool,
    ) -> Result<Self, Error> {
        if len < HEADER_LEN {
            return Err(invalid(format!(
                "the container is {len} bytes, shorter than the {HEADER_LEN:#x}-byte header"
            )));
        }
        if len > limits.max_len {
            return Err(invalid(format!(
                "the container is {len} bytes, more than the {} byte limit",
                limits.max_len
            )));
        }
        let head = read_at(source, 0, HEADER_LEN as usize, len)?;
        if !is_rds5(&head) {
            return Err(Error::NotRds5);
        }
        let record_count = u32_at(&head, 4);
        let uncompressed_total = u32_at(&head, 8);
        let version = u32_at(&head, 0x0C);
        if !VERSIONS.contains(&version) {
            return Err(invalid(format!(
                "unsupported RDS5 version 0x{version:08X}; the observed versions are {}",
                VERSIONS
                    .iter()
                    .map(|version| format!("0x{version:08X}"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            )));
        }
        if record_count < 3 {
            return Err(invalid(format!(
                "the record array holds {record_count} records; a container needs at least 3"
            )));
        }
        if record_count > limits.max_records {
            return Err(invalid(format!(
                "the record array holds {record_count} records, more than the {} limit",
                limits.max_records
            )));
        }
        let record_bytes = RECORD_LEN * u64::from(record_count);
        let record_end = HEADER_LEN + record_bytes;
        if record_end > len {
            return Err(invalid(format!(
                "the record array ends at 0x{record_end:X}, after the end of the container (0x{len:X})"
            )));
        }
        let raw = read_at(source, HEADER_LEN, record_bytes as usize, len)?;
        let mut records = Vec::with_capacity(record_count as usize);
        for index in 0..record_count {
            let at = index as usize * RECORD_LEN as usize;
            let lo = u32_at(&raw, at);
            records.push(Record {
                index,
                offset: u64::from(lo & OFFSET_MASK) * OFFSET_UNIT,
                high_byte: (lo >> 24) as u8,
                second_word: u32_at(&raw, at + 4),
            });
        }

        let etpf_offset = align_up(record_end, BLOCK_ALIGN)
            .ok_or_else(|| invalid("the ETPF chunk position overflows the container length"))?;
        if etpf_offset > len.saturating_sub(ETPF_HEADER_LEN) {
            return Err(invalid(format!(
                "the ETPF chunk at 0x{etpf_offset:X} is outside the container (0x{len:X})"
            )));
        }
        if records[0].offset != etpf_offset {
            return Err(invalid(format!(
                "record 0 points at 0x{:X}, but the ETPF chunk starts at 0x{etpf_offset:X}",
                records[0].offset
            )));
        }
        check(cancel)?;
        let etpf = read_at(source, etpf_offset, ETPF_HEADER_LEN as usize, len)?;
        if !etpf.starts_with(&ETPF_MAGIC) {
            return Err(invalid(format!(
                "the chunk at 0x{etpf_offset:X} does not start with ETPF"
            )));
        }
        let etpf_type = u32_at(&etpf, 4);
        if etpf_type != ETPF_TYPE {
            return Err(invalid(format!(
                "the ETPF chunk has type 0x{etpf_type:X}; only 0x{ETPF_TYPE:X} is known"
            )));
        }
        let entry_count = u32_at(&etpf, 8);
        let field_m = u32_at(&etpf, 0x0C);
        if entry_count > limits.max_entries {
            return Err(invalid(format!(
                "the ETPF chunk declares {entry_count} entries, more than the {} limit",
                limits.max_entries
            )));
        }
        if !field_m.is_multiple_of(16) {
            return Err(invalid(format!(
                "the ETPF field M is 0x{field_m:X}, not a multiple of 16"
            )));
        }
        let table_len = ENTRY_LEN * u64::from(entry_count);
        let table_end = etpf_offset + ETPF_HEADER_LEN + table_len;
        if table_end > len {
            return Err(invalid(format!(
                "the ETPF entry table ends at 0x{table_end:X}, after the end of the container (0x{len:X})"
            )));
        }
        // The content after the entry table is as long as the table plus M.
        let content_end = table_end + table_len + u64::from(field_m);
        if content_end > len {
            return Err(invalid(format!(
                "the ETPF chunk ends at 0x{content_end:X}, after the end of the container (0x{len:X})"
            )));
        }

        let first_block = records[1].offset;
        if content_end > first_block {
            return Err(invalid(format!(
                "the ETPF content ends at 0x{content_end:X}, after the first block at 0x{first_block:X}"
            )));
        }
        for record in &records[1..record_count as usize - 1] {
            if record.offset >= len {
                return Err(invalid(format!(
                    "record {} points at 0x{:X}, outside the container (0x{len:X})",
                    record.index, record.offset
                )));
            }
        }
        for pair in records[1..].windows(2) {
            if pair[0].offset >= pair[1].offset {
                return Err(invalid(format!(
                    "the record offsets do not increase: record {} is at 0x{:X} and record {} at 0x{:X}",
                    pair[0].index, pair[0].offset, pair[1].index, pair[1].offset
                )));
            }
        }
        let last = &records[records.len() - 1];
        if last.offset != len {
            return Err(invalid(format!(
                "the last record points at 0x{:X}, not at the end of the container (0x{len:X})",
                last.offset
            )));
        }
        check_zero(source, content_end, first_block, cancel)?;

        let mut warnings = Vec::new();
        let aligned = align_up(
            ETPF_HEADER_LEN + 2 * table_len + u64::from(field_m),
            ETPF_ALIGN,
        )
        .and_then(|offset| offset.checked_add(etpf_offset))
        .and_then(|offset| {
            offset.checked_add(u64::from(records[0].second_word >> 28) * BLOCK_ALIGN)
        });
        if aligned != Some(first_block) {
            warnings.push(format!(
                "the first block is at 0x{first_block:X}; the relation observed in every sample puts it at {}",
                match aligned {
                    Some(offset) => format!("0x{offset:X}"),
                    None => "an unrepresentable offset".to_string(),
                }
            ));
        }
        if !uncompressed_total.is_multiple_of(0x1000) {
            warnings.push(format!(
                "the uncompressed total 0x{uncompressed_total:X} is not a multiple of 0x1000, as it is in every sample"
            ));
        }

        let blocks = records[1..record_count as usize - 1]
            .iter()
            .enumerate()
            .map(|(index, record)| Block {
                index: index as u32,
                record: record.index,
                offset: record.offset,
                stored_len: records[record.index as usize + 1].offset - record.offset,
                high_byte: record.high_byte,
                counter: record.counter(),
                upper: record.upper(),
                storage: Storage::Unread,
            })
            .collect();

        Ok(Self {
            len,
            version,
            uncompressed_total,
            records,
            etpf_offset,
            entry_count,
            field_m,
            content_end,
            first_block,
            blocks,
            warnings,
        })
    }

    pub fn record_count(&self) -> u32 {
        self.records.len() as u32
    }

    /// The length of the entry table.
    pub fn entry_table_len(&self) -> u64 {
        ENTRY_LEN * u64::from(self.entry_count)
    }

    /// Where the entries start.
    pub fn entry_table_offset(&self) -> u64 {
        self.etpf_offset + ETPF_HEADER_LEN
    }

    /// The length of the region after the entry table.
    pub fn region_len(&self) -> u64 {
        self.entry_table_len() + u64::from(self.field_m)
    }

    pub fn blocks_zlib(&self) -> usize {
        self.blocks
            .iter()
            .filter(|block| block.storage.is_zlib())
            .count()
    }

    /// Reads `count` entries from `offset`, or fewer at the end of the table.
    /// Nothing else of the table is read, so a report can sample it.
    pub fn entries<R: Read + Seek>(
        &self,
        source: &mut R,
        offset: u32,
        count: u32,
    ) -> Result<Vec<Entry>, Error> {
        if offset > self.entry_count {
            return Err(invalid(format!(
                "entry {offset} is past the end of the {} entry table",
                self.entry_count
            )));
        }
        let count = count.min(self.entry_count - offset);
        if count == 0 {
            return Ok(Vec::new());
        }
        let len = u64::from(count) * ENTRY_LEN;
        let at = self.entry_table_offset() + u64::from(offset) * ENTRY_LEN;
        let raw = read_at(source, at, len as usize, self.len)?;
        Ok((0..count)
            .map(|index| {
                let base = index as usize * ENTRY_LEN as usize;
                Entry {
                    index: offset + index,
                    words: [
                        u32_at(&raw, base),
                        u32_at(&raw, base + 4),
                        u32_at(&raw, base + 8),
                        u32_at(&raw, base + 12),
                    ],
                }
            })
            .collect())
    }

    /// Reads the first bytes of up to `max` blocks, from the first, and
    /// records their storage form. Returns how many blocks were classified.
    pub fn classify<R: Read + Seek>(
        &mut self,
        source: &mut R,
        max: usize,
        cancel: &AtomicBool,
    ) -> Result<usize, Error> {
        let mut done = 0;
        for index in 0..self.blocks.len().min(max) {
            check(cancel)?;
            let (offset, stored_len) = {
                let block = &self.blocks[index];
                (block.offset, block.stored_len)
            };
            let len = stored_len.min(2) as usize;
            let head = read_at(source, offset, len, self.len)?;
            let block = &mut self.blocks[index];
            block.storage = storage_of(block.high_byte, &head);
            done += 1;
        }
        Ok(done)
    }
}

/// Decoded bytes of one block, with the stored bytes left after the stream
/// inside the block's range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    pub len: u64,
    pub stored_len: u64,
    /// Bytes after the end of the stream. A block's range is rounded up to
    /// [`BLOCK_ALIGN`], so up to 0xFF padding bytes can trail a stream.
    pub trailing: u64,
}

/// Inflates one block, passing the decoded bytes to `sink`. The stored range
/// and the decoded size are both capped, and the stream must reach its end.
///
/// A block whose storage is not zlib is refused with the reason, including the
/// blocks that carry the zlib selector value and are not zlib.
pub fn decode_block<R: Read + Seek>(
    source: &mut R,
    container: &Container,
    index: u32,
    limits: &Limits,
    cancel: &AtomicBool,
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<Decoded, Error> {
    let block = container.blocks.get(index as usize).ok_or_else(|| {
        invalid(format!(
            "block {index} does not exist; the container holds {}",
            container.blocks.len()
        ))
    })?;
    match block.storage {
        Storage::Zlib => {}
        Storage::Unread => {
            return Err(invalid(format!(
                "block {index} was not classified; classify the blocks first"
            )));
        }
        Storage::NotZlib => {
            return Err(invalid(format!(
                "block {index} carries the zlib selector value but does not start with a zlib header; its codec is unknown"
            )));
        }
        Storage::Unidentified(selector) => {
            return Err(invalid(format!(
                "block {index} uses compressor selector {selector}, which has not been identified"
            )));
        }
    }
    if block.stored_len > limits.max_block_stored {
        return Err(invalid(format!(
            "block {index} stores {} bytes, more than the {} byte limit",
            block.stored_len, limits.max_block_stored
        )));
    }
    let end = block.offset + block.stored_len;
    let mut zlib = Decompress::new(true);
    let mut input = vec![0u8; DECODE_INPUT];
    let mut output = vec![0u8; DECODE_OUTPUT];
    let mut pos = block.offset;
    loop {
        check(cancel)?;
        let remaining = end - pos;
        if remaining == 0 {
            // The stream can end on the last stored byte while the output
            // buffer is full, in which case the decoder only reports it on the
            // next call. Ask once more before rejecting the block.
            let (out_before, in_before) = (zlib.total_out(), zlib.total_in());
            let status = zlib
                .decompress(&[], &mut output, FlushDecompress::None)
                .map_err(|err| {
                    invalid(format!("block {index} is not a valid zlib stream: {err}"))
                })?;
            let produced = (zlib.total_out() - out_before) as usize;
            let consumed = zlib.total_in() - in_before;
            if consumed != 0 {
                return Err(invalid(format!(
                    "the zlib decoder of block {index} consumes input after the stored range"
                )));
            }
            if zlib.total_out() > limits.max_block_len {
                return Err(invalid(format!(
                    "block {index} decodes to more than the {} byte limit",
                    limits.max_block_len
                )));
            }
            if produced > 0 {
                sink(&output[..produced]).map_err(Error::Io)?;
            }
            if status == ZlibStatus::StreamEnd {
                return Ok(Decoded {
                    len: zlib.total_out(),
                    stored_len: block.stored_len,
                    trailing: 0,
                });
            }
            return Err(invalid(format!(
                "the zlib stream of block {index} ends before its {} stored bytes do",
                block.stored_len
            )));
        }
        let take = remaining.min(DECODE_INPUT as u64) as usize;
        source.seek(SeekFrom::Start(pos))?;
        source.read_exact(&mut input[..take]).map_err(|err| {
            invalid(format!(
                "cannot read the {} bytes of block {index} at 0x{pos:X}: {err}",
                take
            ))
        })?;
        let mut consumed_in_step = 0;
        while consumed_in_step < take {
            let (in_before, out_before) = (zlib.total_in(), zlib.total_out());
            let status = zlib
                .decompress(
                    &input[consumed_in_step..take],
                    &mut output,
                    FlushDecompress::None,
                )
                .map_err(|err| {
                    invalid(format!("block {index} is not a valid zlib stream: {err}"))
                })?;
            let consumed = (zlib.total_in() - in_before) as usize;
            let produced = (zlib.total_out() - out_before) as usize;
            consumed_in_step += consumed;
            pos += consumed as u64;
            if zlib.total_out() > limits.max_block_len {
                return Err(invalid(format!(
                    "block {index} decodes to more than the {} byte limit",
                    limits.max_block_len
                )));
            }
            if produced > 0 {
                sink(&output[..produced]).map_err(Error::Io)?;
            }
            if status == ZlibStatus::StreamEnd {
                return Ok(Decoded {
                    len: zlib.total_out(),
                    stored_len: block.stored_len,
                    trailing: end - pos,
                });
            }
            if consumed == 0 && produced == 0 {
                return Err(invalid(format!(
                    "the zlib decoder of block {index} makes no progress"
                )));
            }
        }
    }
}

fn storage_of(high_byte: u8, head: &[u8]) -> Storage {
    match (high_byte >> 2) & 0x03 {
        0 => {
            if is_zlib_header(head) {
                Storage::Zlib
            } else {
                Storage::NotZlib
            }
        }
        selector => Storage::Unidentified(selector),
    }
}

/// A zlib header: DEFLATE, a window of at most 32 KiB, no preset dictionary,
/// and a check value divisible by 31. Every observed block is `78 DA`.
fn is_zlib_header(bytes: &[u8]) -> bool {
    let [cmf, flg, ..] = *bytes else {
        return false;
    };
    cmf & 0x0F == 8
        && cmf >> 4 <= 7
        && flg & 0x20 == 0
        && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
}

fn align_up(value: u64, to: u64) -> Option<u64> {
    value.checked_add(to - 1).map(|value| value & !(to - 1))
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|slice| slice.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn read_at<R: Read + Seek>(
    source: &mut R,
    at: u64,
    len: usize,
    file_len: u64,
) -> Result<Vec<u8>, Error> {
    if at.checked_add(len as u64).is_none_or(|end| end > file_len) {
        return Err(invalid(format!(
            "the read of {len} bytes at 0x{at:X} is outside the container (0x{file_len:X})"
        )));
    }
    let mut bytes = vec![0u8; len];
    source.seek(SeekFrom::Start(at))?;
    source
        .read_exact(&mut bytes)
        .map_err(|err| invalid(format!("cannot read {len} bytes at 0x{at:X}: {err}")))?;
    Ok(bytes)
}

/// Scans `from..to` in bounded pieces and rejects the first non-zero byte.
fn check_zero<R: Read + Seek>(
    source: &mut R,
    from: u64,
    to: u64,
    cancel: &AtomicBool,
) -> Result<(), Error> {
    let mut buf = vec![0u8; STEP];
    let mut pos = from;
    while pos < to {
        check(cancel)?;
        let take = (to - pos).min(STEP as u64) as usize;
        source.seek(SeekFrom::Start(pos))?;
        source.read_exact(&mut buf[..take]).map_err(|err| {
            invalid(format!(
                "cannot read the padding at 0x{pos:X}, {} bytes before the first block: {err}",
                to - pos
            ))
        })?;
        if let Some(at) = buf[..take].iter().position(|&byte| byte != 0) {
            return Err(invalid(format!(
                "the padding after the ETPF chunk has a non-zero byte at 0x{:X}",
                pos + at as u64
            )));
        }
        pos += take as u64;
    }
    Ok(())
}
