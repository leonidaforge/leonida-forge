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
//! Block records carry a storage class in bits 24..29 of their first word.
//! Two classes are decoded: `0x20` is one complete zlib stream and `0x00` is
//! stored content of the block's virtual length. The other six observed
//! classes are reported with their id and refused; no codec name is assigned
//! to them.
//!
//! Two readings of the first word fit the observed population: a six-bit
//! class in bits 24..29 with a 24-bit offset, or a four-bit class in bits
//! 26..29 with a 26-bit offset. Bits 24 and 25 are zero in every sampled
//! record, so dispatch masks them off. A record that sets either bit is
//! reported as ambiguous with both candidate offsets.
//!
//! Entry fields carry no established meaning, so they are exposed as words
//! and as the bit fields the research defines. Block payload bytes are never
//! part of a report; [`decode_block`] hands them to a caller that asks for
//! them.

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
    /// Decoded bytes across every block decoded from one container.
    pub max_total_len: u64,
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
            max_total_len: 1 << 30,
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
    /// Absolute block position, from the 24-bit offset reading.
    pub offset: u64,
    /// Bits 24..31 of the record's first word. Bits 24..29 hold the storage
    /// class; bits 30..31 hold the low bits of the virtual page position.
    pub high_byte: u8,
    /// The record's second word.
    pub second_word: u32,
}

/// `lo[24:30]`: the six-bit storage class.
const CLASS_MASK: u8 = 0x3F;
/// Bits 24 and 25 of `lo`, which differ between the class readings.
const CLASS_AMBIGUOUS: u8 = 0x03;

impl Record {
    /// The six-bit class value of bits 24..29.
    pub fn class_id(&self) -> u8 {
        self.high_byte & CLASS_MASK
    }

    /// The class used for dispatch, `id & 0x3C`. Bits 24 and 25 never change
    /// it, so the six-bit and four-bit readings dispatch alike.
    pub fn dispatch_class(&self) -> u8 {
        self.class_id() & 0x3C
    }

    /// Whether bit 24 or 25 is set. The six-bit class reading then overlaps
    /// the offset field the four-bit reading implies.
    pub fn is_ambiguous(&self) -> bool {
        self.class_id() & CLASS_AMBIGUOUS != 0
    }

    /// The offset the 26-bit reading implies: bits `0..25` in units of 0x100.
    pub fn offset26(&self) -> u64 {
        let low = self.offset >> 8;
        let bits = u64::from(self.high_byte & CLASS_AMBIGUOUS) << 24 | low;
        bits * OFFSET_UNIT
    }

    /// Bits 0..19 of the second word: the virtual counter in units of
    /// 0x4000 bytes.
    pub fn counter(&self) -> u32 {
        self.second_word & 0x000F_FFFF
    }

    /// Bits 30..31 of the first word: the low two bits of the virtual page
    /// position.
    pub fn page_term(&self) -> u8 {
        self.high_byte >> 6
    }

    /// Bits 20..31 of the second word: trailing padding of the stored span.
    pub fn padding(&self) -> u32 {
        self.second_word >> 20
    }

    /// `counter * 0x4000 + page_term * 0x1000`. There is no additional
    /// constant term.
    pub fn virtual_position(&self) -> u64 {
        u64::from(self.counter()) * 0x4000 + u64::from(self.page_term()) * 0x1000
    }
}

/// How a block's bytes are stored, as far as the record establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// Class `0x20`: one complete zlib stream.
    Zlib,
    /// Class `0x00`: stored content of the block's virtual length.
    Stored,
    /// Class `0x20` without a zlib header. This contradicts the class, so
    /// the block is reported and never decoded.
    ZlibHeaderMissing,
    /// A class whose payload is not decoded. Carries the six-bit class id.
    Undecoded(u8),
    /// Not read.
    Unread,
}

impl Storage {
    pub fn name(self) -> &'static str {
        match self {
            Storage::Zlib => "zlib",
            Storage::Stored => "stored",
            Storage::ZlibHeaderMissing => "zlib_header_missing",
            Storage::Undecoded(_) => "undecoded",
            Storage::Unread => "unread",
        }
    }

    /// Whether [`decode_block`] will inflate the block.
    pub fn is_zlib(self) -> bool {
        self == Storage::Zlib
    }

    /// The six-bit class id, when one was classified.
    pub fn class_id(self) -> Option<u8> {
        match self {
            Storage::Zlib => Some(0x20),
            Storage::Stored => Some(0x00),
            Storage::ZlibHeaderMissing => Some(0x20),
            Storage::Undecoded(id) => Some(id),
            Storage::Unread => None,
        }
    }

    fn of(class: u8, head: &[u8]) -> Self {
        match class & 0x3C {
            0x00 => Storage::Stored,
            0x20 => {
                if is_zlib_header(head) {
                    Storage::Zlib
                } else {
                    Storage::ZlibHeaderMissing
                }
            }
            id => Storage::Undecoded(id),
        }
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
    /// The stored span: the next record's offset minus this one's.
    pub stored_len: u64,
    /// The trailing zero bytes of the span.
    pub padding: u32,
    /// `stored_len - padding`: the bytes the stream or content occupies.
    pub content_len: u64,
    /// `virtual_position` of the next record minus this one's.
    pub virtual_len: u64,
    /// Bits 24..29 of the record's first word.
    pub class_id: u8,
    /// Whether bit 24 or 25 is set, so the offset width is undecided.
    pub ambiguous: bool,
    /// The offset the 26-bit reading implies, when it differs.
    pub offset26: Option<u64>,
    pub virtual_position: u64,
    pub storage: Storage,
}

/// One 16-byte ETPF entry, parsed as the descriptor model the research
/// establishes. Fields whose meaning is unknown keep neutral names; no value
/// is given a codec or pixel meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub index: u32,
    pub words: [u32; 4],
}

impl Entry {
    /// `w0[0:13] + 1`.
    pub fn width(&self) -> u32 {
        (self.words[0] & 0x3FFF) + 1
    }

    /// `w0[14:27] + 1`.
    pub fn height(&self) -> u32 {
        ((self.words[0] >> 14) & 0x3FFF) + 1
    }

    /// `w0[28:31`. Up to 9 observed. The meaning of a multi-level value is
    /// not established.
    pub fn mip(&self) -> u8 {
        (self.words[0] >> 28) as u8
    }

    /// `w1[0:2`.
    pub fn flags(&self) -> u8 {
        (self.words[1] & 0x7) as u8
    }

    /// `w1[3:9]`, seven bits. A format identifier, not a decoded pixel
    /// format.
    pub fn format_id(&self) -> u8 {
        ((self.words[1] >> 3) & 0x7F) as u8
    }

    /// `w1[10:19] + 1`.
    pub fn array_size(&self) -> u32 {
        ((self.words[1] >> 10) & 0x3FF) + 1
    }

    /// `w1[20:23]`. Values 2, 4, 6 and 10 were observed.
    pub fn kind(&self) -> u8 {
        ((self.words[1] >> 20) & 0xF) as u8
    }

    /// `w1[24:27]`. Its meaning is not established.
    pub fn tile_mode(&self) -> u8 {
        ((self.words[1] >> 24) & 0xF) as u8
    }

    /// `w1[28:31]`. Meaning unknown.
    pub fn unknown_high_nibble(&self) -> u8 {
        ((self.words[1] >> 28) & 0xF) as u8
    }

    /// The 64-bit locator.
    pub fn locator(&self) -> u64 {
        u64::from(self.words[2]) | u64::from(self.words[3]) << 32
    }

    /// `locator[0:20]`: the first 4 KiB page of the referenced range.
    pub fn locator_page(&self) -> u32 {
        (self.locator() & 0x001F_FFFF) as u32
    }

    /// `locator[21:63]`. Meaning unknown; nonzero in most descriptors.
    pub fn locator_high(&self) -> u64 {
        self.locator() >> 21
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
    /// Decoded bytes produced by [`decode_block`] so far.
    pub decoded_total: u64,
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
            .map(|(index, record)| {
                let next = &records[record.index as usize + 1];
                let stored_len = next.offset - record.offset;
                let padding = record.padding();
                let content_len = stored_len.saturating_sub(u64::from(padding));
                let virtual_position = record.virtual_position();
                let virtual_len = next.virtual_position().saturating_sub(virtual_position);
                let offset26 = record
                    .is_ambiguous()
                    .then(|| record.offset26())
                    .filter(|&offset| offset != record.offset);
                Block {
                    index: index as u32,
                    record: record.index,
                    offset: record.offset,
                    stored_len,
                    padding,
                    content_len,
                    virtual_len,
                    class_id: record.class_id(),
                    ambiguous: record.is_ambiguous(),
                    offset26,
                    virtual_position,
                    storage: Storage::Unread,
                }
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
            decoded_total: 0,
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
        self.classify_range(source, 0, max, cancel)
    }

    /// Classifies at most `count` blocks starting at `start`. A caller that
    /// reads one descriptor does not pay for the blocks before it.
    pub fn classify_range<R: Read + Seek>(
        &mut self,
        source: &mut R,
        start: usize,
        count: usize,
        cancel: &AtomicBool,
    ) -> Result<usize, Error> {
        let end = start.saturating_add(count).min(self.blocks.len());
        let mut done = 0;
        for index in start..end {
            check(cancel)?;
            let (offset, stored_len, class) = {
                let block = &self.blocks[index];
                (block.offset, block.stored_len, block.class_id)
            };
            let len = stored_len.min(2) as usize;
            let head = read_at(source, offset, len, self.len)?;
            let block = &mut self.blocks[index];
            block.storage = Storage::of(class, &head);
            done += 1;
        }
        Ok(done)
    }

    /// The `descriptor_count` 8-byte keys after the descriptor table, in
    /// table order. Their values are texture keys and are never published.
    pub fn keys<R: Read + Seek>(&self, source: &mut R) -> Result<Vec<u64>, Error> {
        let at = self
            .entry_table_offset()
            .checked_add(self.entry_table_len())
            .ok_or_else(|| invalid("the key table offset overflows"))?;
        let len = self.entry_table_len() / 2;
        if at.checked_add(len).is_none_or(|end| end > self.content_end) {
            return Err(invalid(format!(
                "the key table ends at {:#x}, after the ETPF content ({:#x})",
                at + len,
                self.content_end
            )));
        }
        let raw = read_at(source, at, len as usize, self.len)?;
        Ok(raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|key| u64::from_le_bytes(*key))
            .collect())
    }

    /// Whether `keys` is strictly increasing, the property every sampled
    /// store holds.
    pub fn keys_sorted(keys: &[u64]) -> bool {
        keys.windows(2).all(|pair| pair[0] < pair[1])
    }
}

/// Decoded bytes of one block, with the trailing bytes left after the stream
/// or content inside the block's range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    pub len: u64,
    pub stored_len: u64,
    /// Bytes after the end of the stream or content: the declared padding.
    pub trailing: u64,
}

/// Decodes one block, passing the decoded bytes to `sink`. Zlib blocks are
/// inflated completely and must consume exactly `content_len` bytes; stored
/// blocks are copied verbatim and must match the virtual length. Any other
/// class is refused with its id.
///
/// `container.decoded_total` carries the cumulative decoded size so a chain
/// of blocks stays within [`Limits::max_total_len`].
pub fn decode_block<R: Read + Seek>(
    source: &mut R,
    container: &mut Container,
    index: u32,
    limits: &Limits,
    cancel: &AtomicBool,
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<Decoded, Error> {
    let block = *container.blocks.get(index as usize).ok_or_else(|| {
        invalid(format!(
            "block {index} does not exist; the container holds {}",
            container.blocks.len()
        ))
    })?;
    match block.storage {
        Storage::Zlib | Storage::Stored => {}
        Storage::Unread => {
            return Err(invalid(format!(
                "block {index} was not classified; classify the blocks first"
            )));
        }
        Storage::ZlibHeaderMissing => {
            return Err(invalid(format!(
                "block {index} carries zlib class 0x20 but does not start with a zlib header"
            )));
        }
        Storage::Undecoded(class) => {
            return Err(invalid(format!(
                "block {index} uses storage class {class:#04x}, whose payload is not decoded"
            )));
        }
    }
    if block.stored_len > limits.max_block_stored {
        return Err(invalid(format!(
            "block {index} stores {} bytes, more than the {} byte limit",
            block.stored_len, limits.max_block_stored
        )));
    }
    if u64::from(block.padding) > block.stored_len {
        return Err(invalid(format!(
            "block {index} declares {} padding bytes, more than its {} stored bytes",
            block.padding, block.stored_len
        )));
    }
    let len = match block.storage {
        Storage::Stored => {
            if block.content_len != block.virtual_len {
                return Err(invalid(format!(
                    "stored block {index} holds {} bytes, but its virtual length is {}",
                    block.content_len, block.virtual_len
                )));
            }
            block.content_len
        }
        // The virtual length is the inflated length of a zlib block. The
        // stream must consume `content_len` stored bytes and produce it.
        _ => block.virtual_len,
    };
    if len > limits.max_block_len {
        return Err(invalid(format!(
            "block {index} decodes to {len} bytes, more than the {} byte limit",
            limits.max_block_len
        )));
    }
    if container.decoded_total.saturating_add(len) > limits.max_total_len {
        return Err(invalid(format!(
            "decoding block {index} would reach {} bytes, more than the {} byte cumulative limit",
            container.decoded_total.saturating_add(len),
            limits.max_total_len
        )));
    }
    check_padding(source, &block, container.len)?;
    if block.storage == Storage::Stored {
        copy_range(
            source,
            block.offset,
            block.content_len,
            container.len,
            cancel,
            &mut sink,
        )?;
        container.decoded_total += len;
        return Ok(Decoded {
            len,
            stored_len: block.stored_len,
            trailing: u64::from(block.padding),
        });
    }
    let end = block
        .offset
        .checked_add(block.content_len)
        .ok_or_else(|| invalid(format!("the range of block {index} overflows")))?;
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
                if zlib.total_out() != len {
                    return Err(invalid(format!(
                        "the zlib stream of block {index} produced {} bytes, not the {} it declares",
                        zlib.total_out(),
                        len
                    )));
                }
                container.decoded_total += len;
                return Ok(Decoded {
                    len,
                    stored_len: block.stored_len,
                    trailing: u64::from(block.padding),
                });
            }
            return Err(invalid(format!(
                "the zlib stream of block {index} ends before its {} stored bytes do",
                block.content_len
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
                if pos != end {
                    return Err(invalid(format!(
                        "the zlib stream of block {index} ends after {} of its {} content bytes",
                        pos - block.offset,
                        block.content_len
                    )));
                }
                if zlib.total_out() != len {
                    return Err(invalid(format!(
                        "the zlib stream of block {index} produced {} bytes, not the {} it declares",
                        zlib.total_out(),
                        len
                    )));
                }
                container.decoded_total += len;
                return Ok(Decoded {
                    len,
                    stored_len: block.stored_len,
                    trailing: u64::from(block.padding),
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

/// Checks that the declared padding of `block` is present and zero.
fn check_padding<R: Read + Seek>(source: &mut R, block: &Block, len: u64) -> Result<(), Error> {
    if block.padding == 0 {
        return Ok(());
    }
    let at = block
        .offset
        .checked_add(block.content_len)
        .ok_or_else(|| invalid("the padding offset overflows"))?;
    let padding = read_at(source, at, block.padding as usize, len)?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(invalid(format!(
            "block {} declares {} padding bytes that are not zero",
            block.index, block.padding
        )));
    }
    Ok(())
}

/// Copies `len` stored bytes from `at` to `sink`.
fn copy_range<R: Read + Seek>(
    source: &mut R,
    at: u64,
    len: u64,
    file_len: u64,
    cancel: &AtomicBool,
    sink: &mut impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<(), Error> {
    if at.checked_add(len).is_none_or(|end| end > file_len) {
        return Err(invalid(format!(
            "the range of {len} bytes at 0x{at:X} ends after the container (0x{file_len:X})"
        )));
    }
    source.seek(SeekFrom::Start(at))?;
    let mut reader = source.take(len);
    let mut buf = vec![0u8; DECODE_INPUT];
    loop {
        check(cancel)?;
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sink(&buf[..read]).map_err(Error::Io)?;
    }
    Ok(())
}

/// One component of the byte chain, reported separately so one success does
/// not imply another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Component {
    pub name: &'static str,
    /// `supported`, `unsupported` or `not established`.
    pub status: &'static str,
    pub note: &'static str,
}

/// The byte-level chain from one descriptor to its reconstructed bytes.
///
/// Only the relations the research established are reported: the descriptor
/// fields, the referenced virtual range, the blocks it covers, the decoded
/// byte count and, when the count divides evenly, the bytes per texel. No
/// pixel format, tile layout or mip meaning is claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureReport {
    pub descriptor: u32,
    pub width: u32,
    pub height: u32,
    pub mip: u8,
    pub format_id: u8,
    pub kind: u8,
    pub tile_mode: u8,
    pub first_page: u32,
    pub first_block: u32,
    pub block_count: u32,
    pub virtual_start: u64,
    pub virtual_end: u64,
    /// Stored bytes the selected blocks occupy, padding excluded.
    pub stored_len: u64,
    /// Trailing zero bytes of the selected blocks' stored spans.
    pub padding: u64,
    pub decoded_len: u64,
    pub classes: Vec<u8>,
    /// `decoded_len / (width * height)` when it divides evenly. A size
    /// relation, not a pixel-format interpretation.
    pub bytes_per_texel: Option<u32>,
    /// Whether the decoded bytes and the virtual range agree.
    pub complete: bool,
    pub components: Vec<Component>,
    pub notes: Vec<String>,
}

/// The block range one descriptor references, computed without decoding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorRange {
    /// The descriptor's first page.
    pub first_page: u32,
    /// The index of the first block in [`Container::blocks`].
    pub first_block: u32,
    pub block_count: u32,
    pub virtual_start: u64,
    pub virtual_end: u64,
    /// The virtual length of the range: the reconstructed byte count.
    pub virtual_len: u64,
    /// The stored bytes the selected blocks occupy, padding excluded.
    pub stored_len: u64,
    /// Trailing zero bytes of the selected blocks' stored spans.
    pub padding: u64,
}

/// Finds the block range of `descriptor` without decoding any block.
pub fn descriptor_range<R: Read + Seek>(
    source: &mut R,
    container: &Container,
    descriptor: u32,
) -> Result<DescriptorRange, Error> {
    if descriptor >= container.entry_count {
        return Err(invalid(format!(
            "descriptor {descriptor} does not exist; the chunk holds {}",
            container.entry_count
        )));
    }
    let entry = container
        .entries(source, descriptor, 1)?
        .pop()
        .ok_or_else(|| invalid(format!("descriptor {descriptor} cannot be read")))?;
    let first_page = entry.locator_page();
    if first_page == 0 {
        return Err(invalid(format!(
            "descriptor {descriptor} has no locator page"
        )));
    }
    let first_block = container
        .blocks
        .iter()
        .position(|block| block.virtual_position / 0x1000 == u64::from(first_page))
        .ok_or_else(|| {
            invalid(format!(
                "the locator page {first_page} of descriptor {descriptor} is not a block start"
            ))
        })?;
    // The range runs to the next descriptor's first page, or to the end
    // record for the last descriptor. The last end is not page-rounded, so a
    // small final texture that shares a page is still included.
    let end =
        if usize::try_from(descriptor).unwrap_or(usize::MAX) + 1 < container.entry_count as usize {
            let next = container
                .entries(source, descriptor + 1, 1)?
                .pop()
                .map(|entry| entry.locator_page());
            match next {
                Some(page) if page > first_page => u64::from(page) * 0x1000,
                _ => {
                    return Err(invalid(format!(
                        "descriptor {} does not start after descriptor {descriptor}",
                        descriptor + 1
                    )));
                }
            }
        } else {
            container
                .records
                .last()
                .map(Record::virtual_position)
                .unwrap_or(0)
        };
    let mut block_count = 0u32;
    for block in &container.blocks[first_block..] {
        if block.virtual_position >= end {
            break;
        }
        block_count += 1;
    }
    if block_count == 0 {
        // The last record's virtual position is page-granular. A final block
        // shorter than a page therefore ends where it starts in that encoding,
        // but the block itself still belongs to the descriptor.
        let is_last =
            usize::try_from(descriptor).unwrap_or(usize::MAX) + 1 >= container.entry_count as usize;
        if is_last && first_block < container.blocks.len() {
            block_count = 1;
        } else {
            return Err(invalid(format!("descriptor {descriptor} covers no block")));
        }
    }
    let virtual_start = container.blocks[first_block].virtual_position;
    let mut stored_len = 0u64;
    let mut padding = 0u64;
    for block in &container.blocks[first_block..first_block + block_count as usize] {
        stored_len += block.content_len;
        padding += u64::from(block.padding);
    }
    let last = &container.blocks[first_block + block_count as usize - 1];
    let virtual_end = last.virtual_position + last.virtual_len;
    Ok(DescriptorRange {
        first_page,
        first_block: first_block as u32,
        block_count,
        virtual_start,
        virtual_end,
        virtual_len: virtual_end.saturating_sub(virtual_start),
        stored_len,
        padding,
    })
}

/// Reconstructs one descriptor's bytes, streams them to `sink`, and reports
/// the chain. Blocks are decoded by class; a block of an undecoded class
/// refuses the whole chain rather than returning partial bytes.
pub fn reconstruct_texture<R: Read + Seek>(
    source: &mut R,
    container: &mut Container,
    descriptor: u32,
    limits: &Limits,
    cancel: &AtomicBool,
    mut sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<TextureReport, Error> {
    let range = descriptor_range(source, container, descriptor)?;
    let entry = container
        .entries(source, descriptor, 1)?
        .pop()
        .ok_or_else(|| invalid(format!("descriptor {descriptor} cannot be read")))?;
    let first_page = range.first_page;
    let first_block = range.first_block as usize;
    let block_count = range.block_count;

    // Classify the descriptor's blocks once; decode_block refuses an
    // unclassified one.
    container.classify_range(source, first_block, block_count as usize, cancel)?;
    let mut decoded_len = 0u64;
    let mut stored_len = 0u64;
    let mut padding = 0u64;
    let mut classes = Vec::with_capacity(block_count as usize);
    for offset in 0..block_count {
        let index = first_block as u32 + offset;
        let before = container.decoded_total;
        decode_block(source, container, index, limits, cancel, &mut sink)?;
        decoded_len += container.decoded_total - before;
        let block = &container.blocks[index as usize];
        stored_len += block.content_len;
        padding += u64::from(block.padding);
        classes.push(block.class_id);
    }

    let (virtual_start, virtual_end) = (range.virtual_start, range.virtual_end);
    let texels = u64::from(entry.width()) * u64::from(entry.height());
    let bytes_per_texel = (texels > 0 && decoded_len.is_multiple_of(texels))
        .then(|| u32::try_from(decoded_len / texels).ok())
        .flatten();
    let complete = decoded_len == range.virtual_len;

    let mut notes = Vec::new();
    if bytes_per_texel != Some(1) {
        notes.push(
            "the only measured size relation is one byte per texel for the sampled descriptor"
                .to_string(),
        );
    }
    if entry.mip() != 0 {
        notes.push("mip semantics for multi-level textures are not established".to_string());
    }
    if entry.kind() != 2 {
        notes.push("only the 2D kind was followed end to end".to_string());
    }
    if entry.tile_mode() != 0 {
        notes.push("the tile mode has no established meaning".to_string());
    }
    if !complete {
        notes.push(format!(
            "decoded {decoded_len} bytes for a virtual range of {}",
            virtual_end.saturating_sub(virtual_start)
        ));
    }
    Ok(TextureReport {
        descriptor,
        width: entry.width(),
        height: entry.height(),
        mip: entry.mip(),
        format_id: entry.format_id(),
        kind: entry.kind(),
        tile_mode: entry.tile_mode(),
        first_page,
        first_block: first_block as u32,
        block_count,
        virtual_start,
        virtual_end,
        stored_len,
        padding,
        decoded_len,
        classes,
        bytes_per_texel,
        complete,
        components: components(entry.mip()),
        notes,
    })
}

/// The component table the research reports: the first five components have
/// a supported byte-level path, the last three are not established.
fn components(mip: u8) -> Vec<Component> {
    let mip_note = if mip == 0 {
        "one level; no mip comparison covers this sample"
    } else {
        "mip selection is not implemented"
    };
    vec![
        Component {
            name: "descriptor",
            status: "supported",
            note: "fields read at confirmed positions",
        },
        Component {
            name: "block_selection",
            status: "supported",
            note: "the range runs to the next descriptor's first page",
        },
        Component {
            name: "storage_class",
            status: "supported",
            note: "only 0x20 and 0x00 are decoded; the other classes are refused",
        },
        Component {
            name: "decompression",
            status: "supported",
            note: "zlib or stored bytes, with the content length checked",
        },
        Component {
            name: "virtual_reconstruction",
            status: "supported",
            note: "virtual positions come from the record counter and page term",
        },
        Component {
            name: "pixel_format",
            status: "not established",
            note: "no format id has a validated pixel interpretation",
        },
        Component {
            name: "element_order",
            status: "not established",
            note: "linear layout is rejected only for format 98 at tile mode 3",
        },
        Component {
            name: "mip_selection",
            status: "not established",
            note: mip_note,
        },
    ]
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
