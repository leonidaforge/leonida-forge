//! ADAT audio containers: header, per-stream tables, chunk records and the
//! packet framing of the encoded stream.
//!
//! The grammar is the one the research established (ADAT-F16 to ADAT-F29):
//! `ADAT`, a version and variant word at `+0x04`, a stream count at `+0x08`,
//! a data offset at `+0x0C`, a per-stream table selected by the variant, and
//! a run of eight-byte chunk records that ends at the data offset. Records
//! whose type byte is `0x55` hold the encoded stream.
//!
//! Streams are handled by class: a `0x0B` stream must be a multiple of 2,048
//! bytes and is walked as `[u16 length][packet]` blocks with a zero
//! terminator; a `0x02` stream receives only the `size == 4 * declared`
//! relation. Every other class is unclassified and refused. No codec is
//! named and nothing is decoded.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

pub const MAGIC: [u8; 4] = *b"ADAT";
/// The common header.
pub const HEADER_LEN: usize = 0x10;
/// Bytes of one encoded block.
pub const BLOCK_LEN: usize = 2_048;
/// Bytes of one chunk record.
pub const RECORD_LEN: u64 = 8;
/// Record types this reader reads.
pub const TYPE_PHRASE: u8 = 0x76;
pub const TYPE_PAGE: u8 = 0x48;
pub const TYPE_POSITION: u8 = 0xA3;
pub const TYPE_STREAM: u8 = 0x55;
/// Codec byte whose streams carry the 2,048-byte framing.
pub const CODEC_FRAMED: u8 = 0x0B;
/// Codec byte whose streams carry only the size relation.
pub const CODEC_SIZE_ONLY: u8 = 0x02;
/// Failures listed in a report.
pub const MAX_FAILURES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotAdat,
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAdat => f.write_str("not an ADAT payload"),
            Error::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}

pub fn is_adat(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// Reader limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_len: u64,
    pub max_streams: u32,
    pub max_records: u32,
    /// Chunk records kept in the report.
    pub max_kept: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // The largest observed payload is 51,693,440 bytes.
            max_len: 96 << 20,
            max_streams: 1 << 12,
            max_records: 1 << 14,
            max_kept: 64,
        }
    }
}

/// One chunk record: a type byte, a size and a payload-relative offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub index: u32,
    pub kind: u8,
    pub size: u32,
    pub offset: u32,
}

/// One `0x76` descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Phrase {
    pub offset: u32,
    pub declared: u32,
    pub rate: u16,
    pub rate_flags: u16,
    pub codec: u8,
}

/// One `0x48` sub-stream entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageEntry {
    pub decoded: u32,
    pub rate: u16,
    pub rate_flags: u16,
    pub codec: u8,
}

/// One `0x48` page descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub offset: u32,
    pub pages: u32,
    pub stride: u32,
    pub entries: Vec<PageEntry>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockCounts {
    pub data: u64,
    pub sentinel: u64,
    pub metadata: u64,
    pub zero: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecSummary {
    pub codec: u8,
    pub streams: u32,
    /// `framed`, `size-only` or `unclassified`.
    pub support: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositionTable {
    /// Tables read; the non-page families carry one per stream.
    pub tables: u32,
    pub entries: u32,
    /// Every table starts at zero.
    pub starts_at_zero: bool,
    /// Every table is non-decreasing.
    pub non_decreasing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSummary {
    pub declared_pages: u32,
    pub stride: u32,
    pub sentinel_pages: u64,
    pub pages_with_metadata: u64,
    pub page_count_matches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub version: u16,
    pub variant: u16,
    pub streams: u32,
    pub data_offset: u32,
    /// Records read, kept in the report up to the limit and counted beyond.
    pub records: Vec<Record>,
    pub record_count: u32,
    pub type_counts: BTreeMap<u8, u32>,
    pub phrases: Vec<Phrase>,
    pub pages: Vec<Page>,
    pub codecs: Vec<CodecSummary>,
    pub blocks: BlockCounts,
    pub packets: u64,
    pub packet_bytes: u64,
    pub padding: u64,
    pub framing_violations: u64,
    pub failures: Vec<String>,
    pub positions: Option<PositionTable>,
    /// `Some` for a row whose stream is divided into `0x48` pages.
    pub page_summary: Option<PageSummary>,
    /// The observed rate values and how often each occurred.
    pub rates: Vec<(u32, u32)>,
    /// Whether the stream framing walk ran for every stream.
    pub framing_checked: bool,
    pub stored_len: u64,
    pub issues: Vec<String>,
}

/// Splits an eight-byte record word.
pub fn split_record(word: u64) -> (u8, u32, u32) {
    let kind = (word >> 56) as u8;
    let size = ((word >> 28) & 0x0FFF_FFFF) as u32;
    let offset = (word & 0x0FFF_FFFF) as u32;
    (kind, size, offset)
}

/// Parses one ADAT payload.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Report, Error> {
    if !is_adat(bytes) {
        return Err(Error::NotAdat);
    }
    if bytes.len() as u64 > limits.max_len {
        return Err(invalid(format!(
            "the payload is {} bytes, more than the {} byte limit",
            bytes.len(),
            limits.max_len
        )));
    }
    let flags = le_u32(bytes, 4).ok_or_else(|| invalid("the header is truncated"))?;
    let version = (flags & 0xFFFF) as u16;
    let variant = (flags >> 16) as u16;
    let streams = le_u32(bytes, 8).ok_or_else(|| invalid("the header is truncated"))?;
    let data_offset = le_u32(bytes, 0x0C).ok_or_else(|| invalid("the header is truncated"))?;
    if version != 1 {
        return Err(invalid(format!(
            "version {version} is not the observed version 1"
        )));
    }
    if streams == 0 || streams > limits.max_streams {
        return Err(invalid(format!(
            "the header declares {streams} streams, outside 1..={}",
            limits.max_streams
        )));
    }
    if data_offset as usize > bytes.len() || data_offset < HEADER_LEN as u32 {
        return Err(invalid(format!(
            "the data offset {data_offset:#x} is outside the payload"
        )));
    }
    let record_start = record_start(variant, streams, bytes)?;
    if record_start > data_offset as u64 {
        return Err(invalid(format!(
            "the record run would start at {record_start:#x}, after the data offset {data_offset:#x}"
        )));
    }
    let run = data_offset as u64 - record_start;
    if !run.is_multiple_of(RECORD_LEN) {
        return Err(invalid(format!(
            "the record run is {run} bytes, not a whole number of records"
        )));
    }
    let record_count = (run / RECORD_LEN) as u32;
    if record_count > limits.max_records {
        return Err(invalid(format!(
            "the payload declares {record_count} chunk records, more than the {} limit",
            limits.max_records
        )));
    }

    let mut report = Report {
        version,
        variant,
        streams,
        data_offset,
        records: Vec::new(),
        record_count,
        type_counts: BTreeMap::new(),
        phrases: Vec::new(),
        pages: Vec::new(),
        codecs: Vec::new(),
        blocks: BlockCounts::default(),
        packets: 0,
        packet_bytes: 0,
        padding: 0,
        framing_violations: 0,
        failures: Vec::new(),
        positions: None,
        page_summary: None,
        rates: Vec::new(),
        framing_checked: false,
        stored_len: bytes.len() as u64,
        issues: Vec::new(),
    };

    // Read the records.
    let mut words = Vec::with_capacity(record_count as usize);
    for ix in 0..record_count as usize {
        let at = record_start as usize + ix * RECORD_LEN as usize;
        let word = le_u64(bytes, at).ok_or_else(|| invalid("a chunk record is truncated"))?;
        let (kind, size, offset) = split_record(word);
        if size == 0 {
            return Err(invalid(format!("chunk record {ix} declares size 0")));
        }
        if offset < data_offset || (offset as u64) + u64::from(size) > bytes.len() as u64 {
            return Err(invalid(format!(
                "chunk record {ix} spans {offset:#x}..{:#x}, outside the data area {data_offset:#x}..{:#x}",
                u64::from(offset) + u64::from(size),
                bytes.len()
            )));
        }
        *report.type_counts.entry(kind).or_insert(0) += 1;
        if report.records.len() < limits.max_kept {
            report.records.push(Record {
                index: ix as u32,
                kind,
                size,
                offset,
            });
        }
        words.push((kind, size, offset));
    }
    // The byte before the data offset is the last record's type byte.
    let last_type =
        le_u64(bytes, data_offset as usize - RECORD_LEN as usize).map(|word| split_record(word).0);
    if let Some(&(kind, _, _)) = words.last()
        && last_type != Some(kind)
    {
        report.issues.push(format!(
            "the last record type {kind:#04x} differs from the byte before the data offset"
        ));
    }

    // Descriptors and streams are paired by index in record order: a stored
    // stream can precede the descriptor that describes it.
    let mut descriptors: Vec<Descriptor> = Vec::new();
    let mut streams: Vec<(u32, u32)> = Vec::new();
    let mut position_tables: Vec<(u32, u32)> = Vec::new();
    for &(kind, size, offset) in &words {
        let start = offset as usize;
        let end = start + size as usize;
        let record = &bytes[start..end];
        match kind {
            TYPE_PHRASE => match phrase(offset, size, record) {
                Some(phrase) => {
                    report.phrases.push(phrase);
                    descriptors.push(Descriptor {
                        codec: phrase.codec,
                        declared: phrase.declared,
                        pages: None,
                    });
                }
                None => report.issues.push(format!(
                    "the 0x76 record at {offset:#x} is shorter than 32 bytes"
                )),
            },
            TYPE_PAGE => match page(offset, size, record) {
                Some(page) => {
                    let geometry = Some((page.pages, page.stride));
                    if page.entries.is_empty() {
                        report.issues.push(format!(
                            "the 0x48 record at {offset:#x} has no sub-stream entry"
                        ));
                    }
                    let mut codecs: Vec<u8> =
                        page.entries.iter().map(|entry| entry.codec).collect();
                    codecs.sort_unstable();
                    codecs.dedup();
                    if codecs.len() > 1 {
                        report.issues.push(format!(
                            "the 0x48 record at {offset:#x} mixes codec bytes {codecs:?}"
                        ));
                    }
                    for entry in &page.entries {
                        descriptors.push(Descriptor {
                            codec: entry.codec,
                            declared: entry.decoded,
                            pages: geometry,
                        });
                    }
                    report.pages.push(page);
                }
                None => report.issues.push(format!(
                    "the 0x48 record at {offset:#x} does not match its sub-stream count"
                )),
            },
            TYPE_POSITION => position_tables.push((offset, size)),
            TYPE_STREAM => streams.push((offset, size)),
            _ => {}
        }
    }
    if streams.is_empty() {
        report
            .issues
            .push("the payload has no 0x55 stream records".to_string());
    }
    if streams.len() != descriptors.len() {
        report.issues.push(format!(
            "the payload holds {} stream records and {} descriptors",
            streams.len(),
            descriptors.len()
        ));
    }
    let mut codec_counts: BTreeMap<u8, u32> = BTreeMap::new();
    let mut framing_allowed = true;
    for (ix, &(offset, size)) in streams.iter().enumerate() {
        let Some(descriptor) = descriptors.get(ix).copied() else {
            break;
        };
        *codec_counts.entry(descriptor.codec).or_insert(0) += 1;
        let record = &bytes[offset as usize..(offset + size) as usize];
        match descriptor.codec {
            CODEC_FRAMED => {
                if !(size as usize).is_multiple_of(BLOCK_LEN) {
                    report.framing_violations += 1;
                    report.failures.push(format!(
                        "the 0x0B stream at {offset:#x} is {size} bytes, not a multiple of {BLOCK_LEN}"
                    ));
                    continue;
                }
                if framing_allowed {
                    frame_stream(record, descriptor.pages, &mut report);
                }
            }
            CODEC_SIZE_ONLY => {
                if u64::from(size) != 4 * u64::from(descriptor.declared) {
                    report.framing_violations += 1;
                    report.failures.push(format!(
                        "the 0x02 stream at {offset:#x} is {size} bytes, not 4 × {} declared",
                        descriptor.declared
                    ));
                }
            }
            codec => {
                framing_allowed = false;
                report.issues.push(format!(
                    "codec byte {codec:#04x} at {offset:#x} is unclassified; its framing is not walked"
                ));
            }
        }
    }
    report.codecs = codec_counts
        .into_iter()
        .map(|(codec, streams)| CodecSummary {
            codec,
            streams,
            support: match codec {
                CODEC_FRAMED => "framed",
                CODEC_SIZE_ONLY => "size-only",
                _ => "unclassified",
            },
        })
        .collect();
    if report
        .codecs
        .iter()
        .filter(|codec| codec.streams > 0)
        .count()
        > 1
    {
        report
            .issues
            .push("the row carries more than one codec class".to_string());
    }
    report.framing_checked = framing_allowed
        && report
            .codecs
            .iter()
            .all(|codec| codec.support != "unclassified");
    let tables: Vec<PositionTable> = position_tables
        .iter()
        .filter_map(|&(offset, size)| positions(bytes, offset, size))
        .collect();
    if !tables.is_empty() {
        report.positions = Some(PositionTable {
            tables: tables.len() as u32,
            entries: tables.iter().map(|table| table.entries).sum(),
            starts_at_zero: tables.iter().all(|table| table.starts_at_zero),
            non_decreasing: tables.iter().all(|table| table.non_decreasing),
        });
    }
    report.rates = rate_values(&report);
    if let Some(page) = report.pages.first() {
        report.page_summary = Some(PageSummary {
            declared_pages: page.pages,
            stride: page.stride,
            sentinel_pages: report.blocks.sentinel,
            pages_with_metadata: report.blocks.metadata,
            page_count_matches: report.blocks.sentinel == u64::from(page.pages),
        });
    }
    Ok(report)
}

/// One stream descriptor, read from a `0x76` record or a `0x48` entry.
#[derive(Debug, Clone, Copy)]
struct Descriptor {
    codec: u8,
    declared: u32,
    /// Page geometry, for a `0x48` entry.
    pages: Option<(u32, u32)>,
}

/// The record-run start of a variant, validated against the declared size.
fn record_start(variant: u16, streams: u32, bytes: &[u8]) -> Result<u64, Error> {
    let streams = u64::from(streams);
    let start = match variant {
        0xFF02 => HEADER_LEN as u64 + 4 * streams,
        0xFF21 | 0xFF25 => 0x14 + 10 * streams,
        0xFF61 => 0x18 + 10 * streams,
        other => {
            return Err(invalid(format!(
                "the variant word {other:#06x} has no supported per-stream table"
            )));
        }
    };
    if start > bytes.len() as u64 {
        return Err(invalid(format!(
            "the per-stream table ends at {start:#x}, past the payload"
        )));
    }
    Ok(start)
}

fn phrase(offset: u32, size: u32, record: &[u8]) -> Option<Phrase> {
    if size < 32 || record.len() < 32 {
        return None;
    }
    let declared = le_u32(record, 0)?;
    let rate = le_u16(record, 8)?;
    let rate_flags = le_u16(record, 10)?;
    let codec = record.get(0x1C).copied()?;
    Some(Phrase {
        offset,
        declared,
        rate,
        rate_flags,
        codec,
    })
}

fn page(offset: u32, size: u32, record: &[u8]) -> Option<Page> {
    let pages = le_u32(record, 0)?;
    let stride = le_u32(record, 4)?;
    let count = le_u32(record, 8)?;
    let expected = 12u64.checked_add(16 * u64::from(count))?;
    if expected != u64::from(size) {
        return None;
    }
    let mut entries = Vec::with_capacity(count as usize);
    for ix in 0..count as usize {
        let at = 12 + 16 * ix;
        let decoded = le_u32(record, at + 4)?;
        let rate_flags = le_u32(record, at + 8)?;
        let codec_word = le_u16(record, at + 12)?;
        entries.push(PageEntry {
            decoded,
            rate: (rate_flags >> 16) as u16,
            rate_flags: (rate_flags & 0xFFFF) as u16,
            codec: codec_word as u8,
        });
    }
    Some(Page {
        offset,
        pages,
        stride,
        entries,
    })
}

/// One position table as read.
fn positions(bytes: &[u8], offset: u32, size: u32) -> Option<PositionTable> {
    let entries = size / 4;
    let start = offset as usize;
    let mut values = Vec::with_capacity(entries as usize);
    for ix in 0..entries as usize {
        values.push(le_u32(bytes, start + 4 * ix)?);
    }
    Some(PositionTable {
        tables: 1,
        entries,
        starts_at_zero: values.first() == Some(&0),
        non_decreasing: values.windows(2).all(|pair| pair[0] <= pair[1]),
    })
}

fn rate_values(report: &Report) -> Vec<(u32, u32)> {
    let mut counts: BTreeMap<u32, u32> = BTreeMap::new();
    for phrase in &report.phrases {
        *counts.entry(u32::from(phrase.rate)).or_insert(0) += 1;
    }
    for page in &report.pages {
        for entry in &page.entries {
            *counts.entry(u32::from(entry.rate)).or_insert(0) += 1;
        }
    }
    counts.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Classified {
    Data {
        packets: u32,
        payload: u64,
        padding: u64,
    },
    Sentinel,
    Zero,
    Metadata,
    Violation(String),
}

/// Classifies one 2,048-byte block.
fn classify_block(block: &[u8], allow_metadata: bool) -> Classified {
    if block.len() >= 4 && block[..4] == [0xFF; 4] {
        return Classified::Sentinel;
    }
    if block.iter().all(|&byte| byte == 0) {
        return Classified::Zero;
    }
    let mut pos = 0usize;
    let mut packets = 0u32;
    let mut payload = 0u64;
    loop {
        if pos == block.len() {
            return Classified::Data {
                packets,
                payload,
                padding: 0,
            };
        }
        if pos + 2 > block.len() {
            break;
        }
        let len = usize::from(u16::from_le_bytes(
            block[pos..pos + 2].try_into().expect("two bytes"),
        ));
        if len == 0 {
            let rest = &block[pos + 2..];
            if rest.iter().any(|&byte| byte != 0) {
                return Classified::Violation(format!(
                    "non-zero bytes follow the terminator at block offset {pos:#x}"
                ));
            }
            return Classified::Data {
                packets,
                payload,
                padding: rest.len() as u64,
            };
        }
        let end = pos + 2 + len;
        if end > block.len() {
            break;
        }
        packets += 1;
        payload += len as u64;
        pos = end;
    }
    if allow_metadata {
        Classified::Metadata
    } else {
        Classified::Violation(format!(
            "a packet at block offset {pos:#x} crosses the {:#x}-byte block end",
            block.len()
        ))
    }
}

fn frame_stream(stream: &[u8], pages: Option<(u32, u32)>, report: &mut Report) {
    match pages {
        Some((pages, stride)) => {
            if stride == 0 || !(stride as usize).is_multiple_of(BLOCK_LEN) {
                report.issues.push(format!(
                    "the page stride {stride} is not a multiple of {BLOCK_LEN}; the page walk is skipped"
                ));
                return;
            }
            if u64::from(stride) * u64::from(pages) < stream.len() as u64 {
                report.issues.push(format!(
                    "{pages} pages of {stride} bytes do not cover the {} byte stream",
                    stream.len()
                ));
                return;
            }
            for page in 0..pages as usize {
                let start = page * stride as usize;
                if start >= stream.len() {
                    report.issues.push(format!(
                        "page {page} starts at {start:#x}, past the {} byte stream",
                        stream.len()
                    ));
                    break;
                }
                // A trailing page can be shorter than the stride.
                let end = (start + stride as usize).min(stream.len());
                if end - start < stride as usize {
                    report.issues.push(format!(
                        "page {page} is {} bytes, shorter than the {stride} byte stride",
                        end - start
                    ));
                }
                let bytes = &stream[start..end];
                let blocks = bytes.chunks(BLOCK_LEN);
                let mut data_started = false;
                let mut metadata_seen = false;
                for (ix, block) in blocks.enumerate() {
                    let first = ix == 0;
                    let classified =
                        classify_block(block, !data_started && !metadata_seen && !first);
                    match classified {
                        Classified::Sentinel => {
                            report.blocks.sentinel += 1;
                            if !first {
                                report
                                    .issues
                                    .push(format!("page {page} carries a sentinel at block {ix}"));
                            }
                        }
                        Classified::Data {
                            packets,
                            payload,
                            padding,
                        } => {
                            report.blocks.data += 1;
                            report.packets += u64::from(packets);
                            report.packet_bytes += payload;
                            report.padding += padding;
                            data_started = true;
                        }
                        Classified::Zero => report.blocks.zero += 1,
                        Classified::Metadata => {
                            report.blocks.metadata += 1;
                            metadata_seen = true;
                        }
                        Classified::Violation(reason) => {
                            report.framing_violations += 1;
                            if report.failures.len() < MAX_FAILURES {
                                report
                                    .failures
                                    .push(format!("page {page} block {ix}: {reason}"));
                            }
                        }
                    }
                }
            }
        }
        None => {
            for (ix, block) in stream.chunks(BLOCK_LEN).enumerate() {
                match classify_block(block, false) {
                    Classified::Data {
                        packets,
                        payload,
                        padding,
                    } => {
                        report.blocks.data += 1;
                        report.packets += u64::from(packets);
                        report.packet_bytes += payload;
                        report.padding += padding;
                    }
                    Classified::Zero => report.blocks.zero += 1,
                    Classified::Sentinel => report.blocks.sentinel += 1,
                    Classified::Metadata => report.blocks.metadata += 1,
                    Classified::Violation(reason) => {
                        report.framing_violations += 1;
                        if report.failures.len() < MAX_FAILURES {
                            report.failures.push(format!("block {ix}: {reason}"));
                        }
                    }
                }
            }
        }
    }
}
