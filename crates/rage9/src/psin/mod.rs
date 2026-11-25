//! PSIN payloads: framed containers with two pre-section grammars.
//!
//! The framing is the one the research established (PSIN-F01 to PSIN-F21):
//! `PSIN`, a big-endian first-section offset at `+0x04`, a walk of
//! `tag + big-endian length` sections that ends exactly at the payload size,
//! and a `CHKS` integrity section. The first section tag splits the
//! population into the `LSCH` and `PMAP` families. They share a tag
//! vocabulary, not a grammar, so every path and every message keeps them
//! apart.
//!
//! No tag, field, block or value gets a semantic name here. Value bodies and
//! block contents stay opaque and bounded, and the checksum is reported
//! separately from the structural parse.

#[cfg(test)]
mod tests;

use std::fmt;

pub const MAGIC: [u8; 4] = *b"PSIN";
/// Header before the pre-section area.
pub const HEADER_LEN: usize = 8;
/// Longest section walk accepted.
pub const MAX_SECTIONS: usize = 96;
/// Longest pre-section descriptor table accepted.
pub const MAX_DESCRIPTORS: usize = 1 << 14;
/// Longest `PMAP` block directory accepted.
pub const MAX_BLOCKS: usize = 1 << 14;
/// Longest `PSCH` table accepted.
pub const MAX_VALUES: usize = 1 << 16;
/// The checksum seed the research documents.
pub const CHECKSUM_SEED: u32 = 0x3FAC_7125;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotPsin,
    /// The framing or a family grammar is broken.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotPsin => f.write_str("not a PSIN payload"),
            Error::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}

pub fn is_psin(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

fn be_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn tag_at(bytes: &[u8], at: usize) -> Option<[u8; 4]> {
    bytes.get(at..at + 4)?.try_into().ok()
}

/// Rounds `len` up to the next multiple of 16.
fn align16(len: u32) -> Option<u32> {
    len.checked_add(15).map(|sum| sum & !15)
}

/// One tagged section. `len` includes the eight-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub tag: [u8; 4],
    pub offset: u32,
    pub len: u32,
}

impl Section {
    pub fn body_len(&self) -> u32 {
        self.len.saturating_sub(8)
    }

    pub fn tag_text(self) -> String {
        String::from_utf8_lossy(&self.tag).into_owned()
    }
}

/// Which pre-section grammar the first section tag selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Lsch,
    Pmap,
    /// Any other tag. Its grammar is not supported.
    Other,
}

impl Family {
    pub fn name(self) -> &'static str {
        match self {
            Family::Lsch => "LSCH",
            Family::Pmap => "PMAP",
            Family::Other => "other",
        }
    }
}

/// One `LSCH` descriptor: an uninterpreted word and a block length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    pub word: u32,
    pub len: u32,
}

/// The solved `LSCH` descriptor table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorTable {
    pub count: u16,
    pub descriptors: Vec<Descriptor>,
    /// Every count that satisfies the relation. One entry means unique.
    pub candidates: Vec<u16>,
}

/// One `PMAP` block record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub id: u32,
    pub offset: u32,
    pub zero: u32,
    pub len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTable {
    pub mode: u32,
    pub second: u32,
    pub blocks: Vec<Block>,
    /// The first-section offset the block lengths predict.
    pub predicted_first_offset: u32,
    pub offset_matches: bool,
    pub padding_ok: bool,
}

/// One `PSCH` id and the value range its offset delimits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Value {
    pub id: u32,
    pub offset: u32,
    pub len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionTable {
    pub count: u32,
    pub values: Vec<Value>,
    pub tiling_ok: bool,
    /// Why the tiling failed, when it did.
    pub tiling_error: Option<String>,
}

/// A bounded structural description of an `LSCH` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LschBody {
    pub len: u32,
    pub header_word: u32,
    pub header_zero: bool,
    pub marker_records: u32,
    pub tail_len: u32,
    pub aligned: bool,
}

/// A bounded structural description of a `LENM` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LenmBody {
    /// `None` for an empty body.
    pub len: Option<u32>,
    pub count: Option<u32>,
    /// `16 * count - 8` for a count of at least one.
    pub chain_len: Option<u32>,
    /// Bytes after the chain: `length - (0x18 + 16 * count)`.
    pub extra: Option<u32>,
    /// Whether the count delimits the body exactly.
    pub count_delimits_body: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    Verified,
    Mismatch {
        stored: u32,
        computed: u32,
    },
    /// No `CHKS` section, or one whose body has another shape.
    Unsupported,
}

impl Checksum {
    pub fn name(self) -> &'static str {
        match self {
            Checksum::Verified => "verified",
            Checksum::Mismatch { .. } => "mismatched",
            Checksum::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The first-section offset from `+0x04`.
    pub first_offset: u32,
    pub sections: Vec<Section>,
    pub family: Family,
    pub first_tag: [u8; 4],
    pub descriptors: Option<DescriptorTable>,
    pub blocks: Option<BlockTable>,
    pub section_table: Option<SectionTable>,
    pub lsch: Option<LschBody>,
    pub lenm: Option<LenmBody>,
    /// The `PMAP` block with id 1, when present: its range and whether its
    /// last byte is a NUL. The contents stay opaque.
    pub id1_block: Option<Id1Block>,
    pub checksum: Checksum,
    pub issues: Vec<String>,
}

/// The bounds of the id-1 block, with one observation and no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Id1Block {
    pub offset: u32,
    pub len: u32,
    pub nul_terminated: bool,
}

/// The one-at-a-time checksum over signed bytes, seeded with
/// [`CHECKSUM_SEED`]. The two words at `+0x04` and `+0x08` of the `CHKS`
/// body are zeroed before hashing.
pub fn checksum_with_zeroed(payload: &[u8], zero_at: usize) -> u32 {
    let mut hash = CHECKSUM_SEED;
    for (ix, &byte) in payload.iter().enumerate() {
        let byte = if (zero_at..zero_at.saturating_add(8)).contains(&ix) {
            0
        } else {
            byte
        };
        hash = hash.wrapping_add(byte as i8 as i32 as u32);
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash.wrapping_add(hash << 15)
}

/// Parses one PSIN payload.
pub fn parse(payload: &[u8]) -> Result<Report, Error> {
    if !is_psin(payload) {
        return Err(Error::NotPsin);
    }
    let first_offset = be_u32(payload, 4).ok_or(Error::NotPsin)?;
    if first_offset < HEADER_LEN as u32 {
        return Err(invalid(format!(
            "the first-section offset {first_offset} is inside the header"
        )));
    }
    let sections = walk(payload, first_offset)?;
    let first_tag = tag_at(payload, first_offset as usize).ok_or_else(|| {
        invalid(format!(
            "the first section at {first_offset:#x} is past the end of the payload"
        ))
    })?;
    let family = match &first_tag {
        b"LSCH" => Family::Lsch,
        b"PMAP" => Family::Pmap,
        _ => Family::Other,
    };
    let mut report = Report {
        first_offset,
        sections,
        family,
        first_tag,
        descriptors: None,
        blocks: None,
        section_table: None,
        lsch: None,
        lenm: None,
        id1_block: None,
        checksum: Checksum::Unsupported,
        issues: Vec::new(),
    };
    match family {
        Family::Lsch => lsch_family(payload, &mut report)?,
        Family::Pmap => pmap_family(payload, &mut report)?,
        Family::Other => {
            report.issues.push(format!(
                "the first section tag {} has no supported grammar",
                report.sections[0].tag_text()
            ));
        }
    }
    for section in &report.sections {
        match &section.tag {
            b"LSCH" => report.lsch = Some(lsch_body(payload, *section)),
            b"LENM" => report.lenm = Some(lenm_body(payload, *section)),
            _ => {}
        }
    }
    report.checksum = verify_checksum(payload, &report.sections);
    Ok(report)
}

/// Walks the tagged sections. The walk must end exactly at the payload size.
fn walk(payload: &[u8], first_offset: u32) -> Result<Vec<Section>, Error> {
    let mut sections = Vec::new();
    let mut at = first_offset as usize;
    while at < payload.len() {
        if sections.len() >= MAX_SECTIONS {
            return Err(invalid(format!(
                "the payload holds more than {MAX_SECTIONS} sections"
            )));
        }
        let tag = tag_at(payload, at)
            .ok_or_else(|| invalid(format!("a section tag at {at:#x} is truncated")))?;
        let len = be_u32(payload, at + 4)
            .ok_or_else(|| invalid(format!("the section length at {at:#x} is truncated")))?;
        if len < 8 {
            return Err(invalid(format!(
                "the section at {at:#x} declares {len} bytes, shorter than its header"
            )));
        }
        let end = (at as u64) + u64::from(len);
        if end > payload.len() as u64 {
            return Err(invalid(format!(
                "the section at {at:#x} ends at {end:#x}, past the {} byte payload",
                payload.len()
            )));
        }
        sections.push(Section {
            tag,
            offset: at as u32,
            len,
        });
        at = end as usize;
    }
    if at != payload.len() {
        return Err(invalid(format!(
            "the section walk ends at {at:#x}, not at the payload size {:#x}",
            payload.len()
        )));
    }
    if sections.is_empty() {
        return Err(invalid("the payload has no sections"));
    }
    Ok(sections)
}

fn body(payload: &[u8], section: Section) -> &[u8] {
    let start = section.offset as usize + 8;
    &payload[start..start + section.body_len() as usize]
}

fn lsch_family(payload: &[u8], report: &mut Report) -> Result<(), Error> {
    let first = report.first_offset;
    if first < 0x10 {
        return Err(invalid(
            "an LSCH payload needs a 0x10-byte prefix before its descriptor table",
        ));
    }
    let mut candidates = Vec::new();
    let mut tables: Vec<Vec<Descriptor>> = Vec::new();
    let max_count = ((first as usize).saturating_sub(0x10) / 16).min(MAX_DESCRIPTORS);
    for count in 0..=max_count {
        let Some(table) = descriptor_table(payload, count, first) else {
            // Counts above the first length that does not fit cannot solve.
            break;
        };
        if let Some(table) = table {
            candidates.push(count as u16);
            tables.push(table);
        }
    }
    match candidates.len() {
        0 => {
            report
                .issues
                .push("no descriptor count satisfies the LSCH relation".to_string());
            Ok(())
        }
        1 => {
            report.descriptors = Some(DescriptorTable {
                count: candidates[0],
                descriptors: tables.pop().unwrap_or_default(),
                candidates,
            });
            Ok(())
        }
        _ => {
            report.issues.push(format!(
                "{} descriptor counts satisfy the LSCH relation: {}",
                candidates.len(),
                candidates
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            report.descriptors = Some(DescriptorTable {
                count: 0,
                descriptors: Vec::new(),
                candidates: candidates.clone(),
            });
            Ok(())
        }
    }
}

/// Returns `Some(None)` when `count` descriptors fit but do not solve the
/// relation, `Some(Some(table))` when they solve it, and `None` when the
/// table cannot be read at all.
fn descriptor_table(payload: &[u8], count: usize, first: u32) -> Option<Option<Vec<Descriptor>>> {
    let start = HEADER_LEN;
    let end = start + 16 * count;
    if end > first as usize || end > payload.len() {
        return None;
    }
    let mut descriptors = Vec::with_capacity(count);
    let mut sum = 0u64;
    for ix in 0..count {
        let at = start + 16 * ix;
        let marker = payload.get(at + 8..at + 16)?;
        if marker != [0xAA; 8] {
            return Some(None);
        }
        let word = le_u32(payload, at)?;
        let len = le_u32(payload, at + 4)?;
        let aligned = u64::from(align16(len)?);
        sum = sum.checked_add(aligned)?;
        descriptors.push(Descriptor { word, len });
    }
    let predicted = 0x10u64.checked_add(16 * count as u64)?.checked_add(sum)?;
    Some((predicted == u64::from(first)).then_some(descriptors))
}

fn pmap_family(payload: &[u8], report: &mut Report) -> Result<(), Error> {
    let section = report.sections[0];
    let bytes = body(payload, section);
    if bytes.len() < 0x10 {
        return Err(invalid(
            "the PMAP section body is shorter than its directory",
        ));
    }
    let mode = be_u32(bytes, 0).unwrap_or(0);
    let second = be_u32(bytes, 4).unwrap_or(0);
    let count = be_u16(bytes, 8).unwrap_or(0) as usize;
    if count > MAX_BLOCKS {
        return Err(invalid(format!(
            "the PMAP directory declares {count} blocks, more than the {MAX_BLOCKS} limit"
        )));
    }
    let records_end = 0x10usize
        .checked_add(
            count
                .checked_mul(16)
                .ok_or_else(|| invalid("block count overflows"))?,
        )
        .ok_or_else(|| invalid("block count overflows"))?;
    if bytes.len() < records_end {
        return Err(invalid(format!(
            "the PMAP directory needs {records_end} bytes, but the body holds {}",
            bytes.len()
        )));
    }
    let padding = bytes.get(0x0A..0x10).unwrap_or_default();
    let mut blocks: Vec<Block> = Vec::with_capacity(count);
    let mut sum = 0u64;
    let mut offset_matches = true;
    let mut padding_ok = true;
    for ix in 0..count {
        let at = 0x10 + 16 * ix;
        let block = Block {
            id: be_u32(bytes, at).unwrap_or(0),
            offset: be_u32(bytes, at + 4).unwrap_or(0),
            zero: be_u32(bytes, at + 8).unwrap_or(0),
            len: be_u32(bytes, at + 12).unwrap_or(0),
        };
        if !(block.offset as usize).is_multiple_of(16) {
            report.issues.push(format!(
                "block {ix} starts at {:#x}, which is not 16-byte aligned",
                block.offset
            ));
        }
        let expected = 0x10u64.checked_add(sum);
        if expected != Some(u64::from(block.offset)) {
            offset_matches = false;
            report.issues.push(format!(
                "block {ix} starts at {:#x}; the block lengths predict {:#x}",
                block.offset,
                expected.unwrap_or(0)
            ));
        }
        // Padding between blocks is the 0x70 byte.
        if ix > 0 {
            let previous_end =
                (blocks[ix - 1].offset as u64).saturating_add(u64::from(blocks[ix - 1].len));
            let gap_end = block.offset as u64;
            let mut gap = previous_end.min(payload.len() as u64);
            while gap < gap_end.min(payload.len() as u64) {
                if payload.get(gap as usize).copied() != Some(0x70) {
                    padding_ok = false;
                }
                gap += 1;
            }
        }
        if block.offset as usize >= payload.len()
            || (block.offset as u64) + u64::from(block.len) > payload.len() as u64
        {
            report.issues.push(format!(
                "block {ix} spans {:#x}..{:#x}, past the payload end",
                block.offset,
                u64::from(block.offset) + u64::from(block.len)
            ));
        }
        sum = sum
            .checked_add(u64::from(align16(block.len).unwrap_or(block.len)))
            .ok_or_else(|| invalid("the block lengths overflow"))?;
        blocks.push(block);
    }
    if padding != [0x70; 6] {
        padding_ok = false;
    }
    // The last block is not padded when the first-section offset is set.
    let predicted = blocks
        .last()
        .and_then(|last| {
            let before = sum.checked_sub(u64::from(align16(last.len).unwrap_or(last.len)))?;
            0x10u64
                .checked_add(before)?
                .checked_add(u64::from(last.len))
        })
        .unwrap_or(0x10);
    let first = report.first_offset;
    if predicted != u64::from(first) {
        report.issues.push(format!(
            "the block lengths predict the first section at {predicted:#x}, not {first:#x}"
        ));
    }
    if let Some(block) = blocks.iter().find(|block| block.id == 1) {
        let start = block.offset as usize;
        let end = start.saturating_add(block.len as usize);
        if end <= payload.len() {
            report.id1_block = Some(Id1Block {
                offset: block.offset,
                len: block.len,
                nul_terminated: payload.get(end.saturating_sub(1)) == Some(&0),
            });
        }
    }
    report.blocks = Some(BlockTable {
        mode,
        second,
        blocks,
        predicted_first_offset: predicted as u32,
        offset_matches,
        padding_ok,
    });

    // The PSCH table is the second section of this family.
    if let Some(section) = report
        .sections
        .iter()
        .find(|section| &section.tag == b"PSCH")
        .copied()
    {
        report.section_table = Some(psch(payload, section, report)?);
    } else {
        report
            .issues
            .push("the PMAP family has no PSCH section".to_string());
    }
    Ok(())
}

fn psch(payload: &[u8], section: Section, report: &mut Report) -> Result<SectionTable, Error> {
    let bytes = body(payload, section);
    let count = be_u32(bytes, 0).ok_or_else(|| invalid("the PSCH count is truncated"))?;
    if count as usize > MAX_VALUES {
        return Err(invalid(format!(
            "the PSCH table declares {count} values, more than the {MAX_VALUES} limit"
        )));
    }
    let table_end = 4usize
        .checked_add(count as usize * 8)
        .ok_or_else(|| invalid("the PSCH count overflows"))?;
    if bytes.len() < table_end {
        return Err(invalid(format!(
            "the PSCH table needs {table_end} bytes, but the body holds {}",
            bytes.len()
        )));
    }
    let mut pairs = Vec::with_capacity(count as usize);
    for ix in 0..count as usize {
        let at = 4 + 8 * ix;
        pairs.push((
            be_u32(bytes, at).unwrap_or(0),
            be_u32(bytes, at + 4).unwrap_or(0),
        ));
    }
    let values_start = table_end + 8;
    let mut tiling_error = None;
    if values_start > bytes.len() {
        tiling_error = Some(format!(
            "the value region starts at {values_start:#x}, past the {:#x}-byte body",
            bytes.len()
        ));
    }
    let mut values = Vec::with_capacity(pairs.len());
    for (ix, (id, offset)) in pairs.iter().enumerate() {
        let end = pairs
            .get(ix + 1)
            .map(|(_, next)| *next as u64)
            .unwrap_or(bytes.len() as u64);
        let start = u64::from(*offset);
        if start < values_start as u64 || end < start || end > bytes.len() as u64 {
            tiling_error.get_or_insert_with(|| {
                format!(
                    "value {ix} spans {start:#x}..{end:#x}, outside the value region {values_start:#x}..{:#x}",
                    bytes.len()
                )
            });
        }
        values.push(Value {
            id: *id,
            offset: *offset,
            len: end.saturating_sub(start).min(u32::MAX as u64) as u32,
        });
    }
    if let Some((_, first)) = pairs.first()
        && *first as usize != values_start
    {
        tiling_error.get_or_insert_with(|| {
            format!("the first value starts at {first:#x}, not at the table end {values_start:#x}")
        });
    }
    if pairs.windows(2).any(|pair| pair[1].1 < pair[0].1) {
        tiling_error.get_or_insert_with(|| "the value offsets decrease".to_string());
    }
    if let (Some(last), Some(value)) = (pairs.last(), values.last()) {
        let last_start = u64::from(last.1);
        if last_start + u64::from(value.len) != bytes.len() as u64 {
            tiling_error.get_or_insert_with(|| {
                format!(
                    "the last value ends at {:#x}, not at the body end {:#x}",
                    last_start + u64::from(value.len),
                    bytes.len()
                )
            });
        }
    }
    // Every other block id at or above 0x100 must appear in the table.
    if let Some(table) = &report.blocks {
        for block in &table.blocks {
            if block.id >= 0x100 && !pairs.iter().any(|(id, _)| *id == block.id) {
                report.issues.push(format!(
                    "block id {:#x} does not occur in the PSCH table",
                    block.id
                ));
            }
        }
    }
    Ok(SectionTable {
        count,
        values,
        tiling_ok: tiling_error.is_none(),
        tiling_error,
    })
}

fn lsch_body(payload: &[u8], section: Section) -> LschBody {
    let bytes = body(payload, section);
    let mut body = LschBody {
        len: bytes.len() as u32,
        header_word: le_u32(bytes, 8).unwrap_or(0),
        header_zero: bytes.get(0x0C..0x10).map(|b| b == [0; 4]).unwrap_or(false),
        marker_records: 0,
        tail_len: 0,
        aligned: bytes.len().is_multiple_of(16),
    };
    if bytes.len() < 0x10 {
        body.tail_len = bytes.len() as u32;
        return body;
    }
    let mut at = 0x10;
    while at + 32 <= bytes.len() && bytes[at..at + 8] == [0xAA; 8] {
        body.marker_records += 1;
        at += 32;
    }
    body.tail_len = (bytes.len() - at) as u32;
    body
}

fn lenm_body(payload: &[u8], section: Section) -> LenmBody {
    let bytes = body(payload, section);
    if bytes.is_empty() {
        return LenmBody {
            len: None,
            count: None,
            chain_len: None,
            extra: None,
            count_delimits_body: true,
        };
    }
    let count = le_u32(bytes, 0x10);
    let chain_len =
        count.and_then(|count| count.checked_mul(16).and_then(|value| value.checked_sub(8)));
    let extra = chain_len.map(|chain| (bytes.len() as u32).saturating_sub(0x18 + chain));
    LenmBody {
        len: Some(bytes.len() as u32),
        count,
        chain_len,
        extra,
        count_delimits_body: extra == Some(0),
    }
}

fn verify_checksum(payload: &[u8], sections: &[Section]) -> Checksum {
    let Some(section) = sections.iter().find(|section| &section.tag == b"CHKS") else {
        return Checksum::Unsupported;
    };
    if section.body_len() != 12 {
        return Checksum::Unsupported;
    }
    let bytes = body(payload, *section);
    let (Some(total), Some(stored)) = (be_u32(bytes, 0), be_u32(bytes, 4)) else {
        return Checksum::Unsupported;
    };
    if total != payload.len() as u32 || bytes.get(8..12) != Some(b"zppp") {
        return Checksum::Unsupported;
    }
    let computed = checksum_with_zeroed(payload, section.offset as usize + 8);
    if computed == stored {
        Checksum::Verified
    } else {
        Checksum::Mismatch { stored, computed }
    }
}
