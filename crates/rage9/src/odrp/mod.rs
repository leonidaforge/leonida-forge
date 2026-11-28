//! The `0DRP` metadata resource form.
//!
//! A metadata resource stores the self-describing tables a `PSIN` container
//! holds in its `LSCH`, `LENM` and `LRSC` sections, but inside a RAGE resource:
//! a system segment of addressed tables and a graphics segment. The four bytes
//! `0DRP` at system `+0x10` are the observed marker; the name is a signature,
//! not an established format name.
//!
//! Everything below was read from GTA VI resources and checked against them:
//!
//! - The system segment starts with a zero `u64`, a system pointer to the page
//!   map at `+0x08`, the tag at `+0x10`, the object type at `+0x14`, a zero
//!   `u64` at `+0x18` and the root block at `+0x20`.
//! - `+0x28` addresses the structure table of 32-byte records, `+0x30` the
//!   enumeration table of 24-byte records (zero when there are none), `+0x38`
//!   the block table of 16-byte records and `+0x40` a system pointer the
//!   population does not explain. The four `u16` at `+0x48` are the structure,
//!   enumeration and block counts, then a word of unknown meaning.
//! - A structure record is `{u32 name, u32 signature, u32 flags, u32 zero,
//!   u64 member pointer, u32 size, u16 zero, u16 field count}`. Where the
//!   `PSIN` form stores eight `0xAA` bytes, the resource form stores the
//!   pointer to the structure's field records.
//! - A field record is `{u32 name, u32 offset, u32 type word, u32 auxiliary}`,
//!   the same 16 bytes the `PSIN` form uses.
//! - An enumeration record is `{u32 name, u32 signature, u64 value pointer,
//!   u32 count, u32 zero}` followed by `count` value records of
//!   `{u64 value, u32 name, u32 zero}`.
//! - A block record is `{u32 type word, u32 byte length, u64 pointer}`. The
//!   pointer names the segment and the offset of the block's bytes. A block
//!   whose type word is one structure's name holds that structure's records; a
//!   block of any other type is a pool.
//! - A reference is a `u64` of `(byte offset << 20) | block`, the block counted
//!   from one, zero being null. The same word names either segment through its
//!   block, never directly.
//! - A `0x5c` array and a `0x75` map store `{u32 length, u32 capacity, u64
//!   reference}`; a `0x52` array stores `{u64 reference, u16 length, u16
//!   capacity, u32 zero}`, as the `PSIN` form does. A map's two words are the
//!   number of bucket records and the number of entries those buckets hold.
//! - A `0x42` field is an eight-byte reference into a text block (`type
//!   0x10`), whose elements are NUL-terminated strings.
//!
//! Types this decoder does not claim to understand keep the bytes their schema
//! extent covers and are reported as unresolved. A stored hash is never
//! replaced by a name; a name table is applied beside it.

#[cfg(test)]
mod tests;

use std::collections::HashMap;

use crate::psin::pso::{
    ArrayElements, ArrayValue, Bitset, Content, EnumValue, EnumValueMatch, Enumeration, Field,
    FieldValue, Limits, Location, MapValue, PoolEntry, PoolKind, Record, RecordLink, Reference,
    ReferenceFault, Resolution, Scalar, Span, Structure, Target, TextValue, Value,
};
use crate::resource::{self, PageMap, Pointer, Segment};

/// The tag offset in the system segment.
pub const TAG_OFFSET: usize = 0x10;
/// The bytes some metadata resources carry at [`TAG_OFFSET`].
pub const TAG: [u8; 4] = *b"0DRP";
/// The header extends at least to the four counts at `+0x48`.
pub const HEADER_LEN: usize = 0x50;

/// The most structures a resource may declare.
pub const MAX_STRUCTURES: usize = 1 << 14;
/// The most enumerations a resource may declare.
pub const MAX_ENUMS: usize = 1 << 14;
/// The most blocks a resource may declare.
pub const MAX_BLOCKS: usize = 1 << 14;

const STRUCTURE_LEN: usize = 32;
const FIELD_LEN: usize = 16;
const ENUM_LEN: usize = 24;
const ENUM_VALUE_LEN: usize = 16;
const BLOCK_LEN: usize = 16;
const DESCRIPTOR_NAME: u32 = 0x100;

const TYPE_STRUCTURE: u16 = 0x05;
const TYPE_REFERENCE: u16 = 0x07;
const TYPE_TEXT_REFERENCE: u16 = 0x42;
const TYPE_TEXT_SLOT: u16 = 0x44;
const TYPE_INLINE_ARRAY: u16 = 0x50;
const TYPE_ARRAY: u16 = 0x52;
const TYPE_ARRAY_LENGTH_FIRST: u16 = 0x5c;
const TYPE_ENUM8: u16 = 0x60;
const TYPE_ENUM32: u16 = 0x62;
const TYPE_BITSET: u16 = 0x65;
const TYPE_MAP_LENGTH_FIRST: u16 = 0x75;

/// The bytes a `0x42` text reference occupies.
const TEXT_REFERENCE_WIDTH: u32 = 8;
/// The bytes a `0x65` bit set occupies in the resource form.
const BITSET_WIDTH: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The system segment does not carry the tag and the header shape.
    NotOdrp,
    /// A table, block or record is inconsistent with the resource.
    Malformed(String),
    /// A read limit was reached.
    Limit(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotOdrp => f.write_str("not a 0DRP metadata resource"),
            Error::Malformed(reason) => f.write_str(reason),
            Error::Limit(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

fn malformed(reason: impl Into<String>) -> Error {
    Error::Malformed(reason.into())
}

/// Whether `system` starts like a `0DRP` metadata resource: a zero `u64`, a
/// system page-map pointer at `+0x08` and the tag at `+0x10`.
pub fn is_odrp(system: &[u8]) -> bool {
    resource::page_map_offset(system).is_some()
        && system.get(TAG_OFFSET..TAG_OFFSET + TAG.len()) == Some(TAG.as_slice())
}

/// The stored header of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The object type byte after the tag. `0x7A` in every observed resource;
    /// its meaning is not established.
    pub object_type: u8,
    /// The block the header names as the document's root, counted from one.
    /// Every one of the 15,768 decoded resources stores the number of the block
    /// the derived roots hold, so the word reads as a root block rather than a
    /// count. Zero means the header names no root.
    pub root_block: u32,
    pub structures: u16,
    pub enums: u16,
    pub blocks: u16,
    /// The fourth `u16` at `+0x4E`. Meaning not established.
    pub unknown: u16,
    pub system_pages: u8,
    pub graphics_pages: u8,
    /// The page map's offset in the system segment.
    pub page_map: u32,
    /// The pointer at `+0x40`, whose target the population does not explain.
    pub extra_pointer: Option<u32>,
}

/// One block and what it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    /// The block number a reference stores: counted from one.
    pub index: u32,
    /// The type word from the block table.
    pub id: u32,
    /// The block's byte offset in its segment.
    pub offset: u32,
    pub len: u32,
    pub segment: Segment,
    pub content: Content,
}

/// A decoded metadata resource.
#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub header: Header,
    pub structures: Vec<Structure>,
    pub enums: Vec<Enumeration>,
    pub blocks: Vec<Block>,
    /// Structure blocks no decoded reference reaches, in block order. Derived
    /// from the decoded references, independently of [`Header::root_block`], so
    /// the two readings can be compared.
    pub roots: Vec<u32>,
    /// What does not add up and what was not decoded.
    pub issues: Vec<String>,
    /// Blocks that could not be decoded to their full extent.
    pub unsupported_blocks: u32,
    /// References that name no record, or text references that name no string.
    pub unresolved_references: u32,
    /// Whether a read limit cut the document short.
    pub truncated: bool,
}

impl Document {
    /// The structure the schema defines once under `name`.
    pub fn structure(&self, name: u32) -> Option<&Structure> {
        unique(&self.structures, name, |structure| structure.name)
    }

    /// The enumeration the table defines once under `name`.
    pub fn enumeration(&self, name: u32) -> Option<&Enumeration> {
        unique(&self.enums, name, |enumeration| enumeration.name)
    }

    /// Records across every structure block.
    pub fn record_count(&self) -> usize {
        self.blocks
            .iter()
            .map(|block| match &block.content {
                Content::Records { records, .. } => records.len(),
                _ => 0,
            })
            .sum()
    }

    /// The text values whose reference resolved to a string.
    pub fn text_count(&self) -> usize {
        let mut total = 0;
        for block in &self.blocks {
            if let Content::Records { records, .. } = &block.content {
                for record in records {
                    for value in &record.fields {
                        if let Value::Text(text) = &value.value
                            && text.text.is_ok()
                        {
                            total += 1;
                        }
                    }
                }
            }
        }
        total
    }

    /// The depth of the deepest embedded structure.
    pub fn depth(&self) -> usize {
        fn record_depth(record: &Record, depth: usize) -> usize {
            let mut deepest = depth;
            for value in &record.fields {
                let nested = match &value.value {
                    Value::Structure(record) => record_depth(record, depth + 1),
                    Value::Array(array) => match &array.elements {
                        Ok(ArrayElements::Records { records }) => records
                            .iter()
                            .map(|record| record_depth(record, depth + 1))
                            .max()
                            .unwrap_or(depth),
                        _ => depth,
                    },
                    Value::Map(map) => match &map.entries {
                        Ok((_, records)) => records
                            .iter()
                            .map(|record| record_depth(record, depth + 1))
                            .max()
                            .unwrap_or(depth),
                        _ => depth,
                    },
                    _ => depth,
                };
                deepest = deepest.max(nested);
            }
            deepest
        }
        self.blocks
            .iter()
            .filter_map(|block| match &block.content {
                Content::Records { records, .. } => Some(
                    records
                        .iter()
                        .map(|record| record_depth(record, 1))
                        .max()
                        .unwrap_or(0),
                ),
                _ => None,
            })
            .max()
            .unwrap_or(0)
    }

    /// Whether every block decoded, every reference bound and nothing was
    /// truncated.
    pub fn complete(&self) -> bool {
        self.unsupported_blocks == 0 && self.unresolved_references == 0 && !self.truncated
    }

    /// `decoded`, `partial` or `failed`.
    ///
    /// A document is `decoded` when every block the header declares was read
    /// to its full extent — as whole records of a structure the schema defines
    /// or as a pool of established element width — every reference it stores
    /// bound to its target, and no read limit cut it short. A field whose type
    /// is not decoded keeps the bytes its extent covers and does not by itself
    /// make a document partial: its storage is accounted for. A block that
    /// cannot be divided into records, or a reference that binds nowhere, does.
    pub fn status(&self) -> &'static str {
        if self.blocks.is_empty() && self.header.blocks != 0 {
            return "failed";
        }
        if self.complete() {
            "decoded"
        } else {
            "partial"
        }
    }
}

fn unique<T>(items: &[T], name: u32, key: impl Fn(&T) -> u32) -> Option<&T> {
    let mut found = items.iter().filter(|item| key(item) == name);
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

/// Reads a `0DRP` resource from its two reconstructed segments.
pub fn decode(system: &[u8], graphics: &[u8], limits: &Limits) -> Result<Document, Error> {
    decode_with(system, graphics, limits)
}

fn decode_with(system: &[u8], graphics: &[u8], limits: &Limits) -> Result<Document, Error> {
    if !is_odrp(system) {
        return Err(Error::NotOdrp);
    }
    let segments = Segments { system, graphics };
    let header = read_header(system)?;
    let mut reader = Reader {
        segments,
        structures: Vec::new(),
        enums: Vec::new(),
        blocks: Vec::new(),
        issues: Vec::new(),
        limits: *limits,
        nodes: 0,
        truncated: false,
        unsupported: 0,
        unresolved: 0,
        inbound: Vec::new(),
    };
    reader.read_schema(header)?;
    reader.read_blocks(header)?;
    let mut document = reader.finish(header);
    document.roots = derive_roots(&document);
    check_root(&mut document);
    Ok(document)
}

/// Reports a header root block the derived roots do not hold and the block
/// table does not name. Both readings agree across the observed population, so
/// a disagreement is worth a note rather than a silent choice of one of them.
fn check_root(document: &mut Document) {
    let root = document.header.root_block;
    if root == 0 {
        document
            .issues
            .push("the header names no root block".to_string());
        return;
    }
    if document.roots.contains(&root) {
        return;
    }
    let reason = if document.blocks.iter().any(|block| block.index == root) {
        "a reference reaches it"
    } else {
        "the block table does not name it"
    };
    document.issues.push(format!(
        "the header names block {root} as the root, and {reason}"
    ));
}

/// The two reconstructed segments of a resource.
#[derive(Debug, Clone, Copy)]
pub struct Segments<'a> {
    pub system: &'a [u8],
    pub graphics: &'a [u8],
}

impl<'a> Segments<'a> {
    fn bytes(&self, segment: Segment) -> &'a [u8] {
        match segment {
            Segment::System => self.system,
            Segment::Graphics => self.graphics,
        }
    }

    fn at(&self, segment: Segment, offset: u32, len: u32) -> Option<&'a [u8]> {
        let bytes = self.bytes(segment);
        let start = offset as usize;
        let end = start.checked_add(len as usize)?;
        bytes.get(start..end)
    }
}

fn read_header(system: &[u8]) -> Result<Header, Error> {
    let head = system.get(..HEADER_LEN).ok_or_else(|| {
        malformed(format!(
            "the system segment is {} bytes, shorter than the {HEADER_LEN}-byte header",
            system.len()
        ))
    })?;
    let page_map = resource::page_map_offset(head)
        .ok_or_else(|| malformed("the header holds no system page-map pointer"))?;
    let map = PageMap::parse(
        page_map,
        system
            .get(page_map as usize..)
            .ok_or_else(|| malformed("the page map lies outside the system segment"))?,
    )
    .map_err(|err| malformed(err.describe()))?;
    let extra_pointer = match u64_at(head, 0x40) {
        Some(value) if value != 0 => match Pointer::decode(value) {
            Some(Pointer::System(offset)) if (offset as usize) < system.len() => Some(offset),
            _ => None,
        },
        _ => None,
    };
    Ok(Header {
        object_type: head[0x14],
        root_block: u32_at(head, 0x20).expect("0x20 fits the header"),
        structures: u16_at(head, 0x48).expect("0x48 fits the header"),
        enums: u16_at(head, 0x4a).expect("0x4a fits the header"),
        blocks: u16_at(head, 0x4c).expect("0x4c fits the header"),
        unknown: u16_at(head, 0x4e).expect("0x4e fits the header"),
        system_pages: map.system_pages,
        graphics_pages: map.graphics_pages,
        page_map,
        extra_pointer,
    })
}

struct Reader<'a> {
    segments: Segments<'a>,
    structures: Vec<Structure>,
    enums: Vec<Enumeration>,
    blocks: Vec<Block>,
    issues: Vec<String>,
    limits: Limits,
    nodes: usize,
    truncated: bool,
    unsupported: u32,
    unresolved: u32,
    /// Block numbers some decoded reference reaches.
    inbound: Vec<bool>,
}

impl Reader<'_> {
    fn read_schema(&mut self, header: Header) -> Result<(), Error> {
        if usize::from(header.structures) > MAX_STRUCTURES {
            return Err(Error::Limit(format!(
                "the resource declares {} structures, more than {MAX_STRUCTURES}",
                header.structures
            )));
        }
        let table = self.table_pointer(0x28, "structure")?;
        let count = usize::from(header.structures);
        let bytes = self
            .segments
            .at(Segment::System, table, (count * STRUCTURE_LEN) as u32)
            .ok_or_else(|| malformed("the structure table runs past the system segment"))?;
        let mut layout = Vec::with_capacity(count);
        for index in 0..count {
            let at = index * STRUCTURE_LEN;
            let member = match u64_at(bytes, at + 16).expect("a record holds it") {
                0 => None,
                value => Some(
                    pointer_offset(value, Segment::System, self.segments.system.len()).ok_or_else(
                        || {
                            malformed(format!(
                                "structure {index} names a member list outside the system segment"
                            ))
                        },
                    )?,
                ),
            };
            layout.push((
                u32_at(bytes, at).expect("a record holds it"),
                u32_at(bytes, at + 4).expect("a record holds it"),
                u32_at(bytes, at + 8).expect("a record holds it"),
                u32_at(bytes, at + 24).expect("a record holds it"),
                member,
                u16_at(bytes, at + 30).expect("a record holds it"),
            ));
        }
        for (name, signature, flags, size, member, count) in layout {
            let mut fields = Vec::with_capacity(usize::from(count));
            if let Some(member) = member {
                let width = usize::from(count) * FIELD_LEN;
                if width > 0 {
                    let bytes = self
                        .segments
                        .at(Segment::System, member, width as u32)
                        .ok_or_else(|| {
                            malformed(format!(
                                "the field list of structure {name:#010x} runs past the system segment"
                            ))
                        })?;
                    for index in 0..usize::from(count) {
                        let at = index * FIELD_LEN;
                        fields.push(Field {
                            name: u32_at(bytes, at).expect("a field record holds it"),
                            offset: u32_at(bytes, at + 4).expect("a field record holds it"),
                            type_word: u32_at(bytes, at + 8).expect("a field record holds it"),
                            auxiliary: u32_at(bytes, at + 12).expect("a field record holds it"),
                        });
                    }
                }
            } else if count != 0 {
                self.issues.push(format!(
                    "structure {name:#010x} declares {count} fields but names no member list"
                ));
            }
            self.structures.push(Structure {
                name,
                signature,
                flags,
                size,
                fields,
            });
        }
        if usize::from(header.enums) > MAX_ENUMS {
            return Err(Error::Limit(format!(
                "the resource declares {} enumerations, more than {MAX_ENUMS}",
                header.enums
            )));
        }
        if header.enums > 0 {
            let table = self.table_pointer(0x30, "enumeration")?;
            let count = usize::from(header.enums);
            let bytes = self
                .segments
                .at(Segment::System, table, (count * ENUM_LEN) as u32)
                .ok_or_else(|| malformed("the enumeration table runs past the system segment"))?;
            let mut layout = Vec::with_capacity(count);
            for index in 0..count {
                let at = index * ENUM_LEN;
                let values = match u64_at(bytes, at + 8).expect("a record holds it") {
                    0 => None,
                    value => Some(
                        pointer_offset(value, Segment::System, self.segments.system.len())
                            .ok_or_else(|| {
                                malformed(format!(
                                    "enumeration {index} names a value list outside the system segment"
                                ))
                            })?,
                    ),
                };
                layout.push((
                    u32_at(bytes, at).expect("a record holds it"),
                    u32_at(bytes, at + 4).expect("a record holds it"),
                    values,
                    u32_at(bytes, at + 16).expect("a record holds it"),
                ));
            }
            for (name, signature, values, count) in layout {
                let mut members = Vec::new();
                if let Some(values) = values {
                    let width = (count as usize)
                        .checked_mul(ENUM_VALUE_LEN)
                        .ok_or_else(|| malformed("an enumeration's value count overflows"))?;
                    if width > 0 {
                        let bytes = self
                            .segments
                            .at(Segment::System, values, width as u32)
                            .ok_or_else(|| {
                                malformed(format!(
                                    "the value list of enumeration {name:#010x} runs past the system segment"
                                ))
                            })?;
                        for index in 0..count as usize {
                            let at = index * ENUM_VALUE_LEN;
                            members.push(EnumValue {
                                value: u64_at(bytes, at).expect("a value record holds it"),
                                name: u32_at(bytes, at + 8).expect("a value record holds it"),
                            });
                        }
                    }
                } else if count != 0 {
                    self.issues.push(format!(
                        "enumeration {name:#010x} declares {count} values but names no value list"
                    ));
                }
                self.enums.push(Enumeration {
                    name,
                    signature,
                    values: members,
                });
            }
        }
        Ok(())
    }

    fn table_pointer(&self, at: usize, what: &str) -> Result<u32, Error> {
        match u64_at(self.segments.system, at) {
            Some(value) if value != 0 => {
                pointer_offset(value, Segment::System, self.segments.system.len()).ok_or_else(
                    || malformed(format!("the {what} table pointer is not a system pointer")),
                )
            }
            _ => Err(malformed(format!(
                "the header holds no {what} table pointer"
            ))),
        }
    }

    fn read_blocks(&mut self, header: Header) -> Result<(), Error> {
        if usize::from(header.blocks) > MAX_BLOCKS {
            return Err(Error::Limit(format!(
                "the resource declares {} blocks, more than {MAX_BLOCKS}",
                header.blocks
            )));
        }
        let table = self.table_pointer(0x38, "block")?;
        let count = usize::from(header.blocks);
        let bytes = self
            .segments
            .at(Segment::System, table, (count * BLOCK_LEN) as u32)
            .ok_or_else(|| malformed("the block table runs past the system segment"))?;
        let mut layout = Vec::with_capacity(count);
        for index in 0..count {
            let at = index * BLOCK_LEN;
            let id = u32_at(bytes, at).expect("a record holds it");
            let len = u32_at(bytes, at + 4).expect("a record holds it");
            let (segment, offset) =
                match Pointer::decode(u64_at(bytes, at + 8).expect("a record holds it")) {
                    Some(Pointer::System(offset)) => (Segment::System, offset),
                    Some(Pointer::Graphics(offset)) => (Segment::Graphics, offset),
                    None => {
                        return Err(malformed(format!(
                            "block {} names no segment pointer",
                            index + 1
                        )));
                    }
                };
            if self.segments.at(segment, offset, len).is_none() {
                return Err(malformed(format!(
                    "block {} spans {offset:#x}..{:#x} in the {} segment, past its {} bytes",
                    index + 1,
                    u64::from(offset) + u64::from(len),
                    segment.name(),
                    self.segments.bytes(segment).len()
                )));
            }
            layout.push((index as u32 + 1, id, offset, len, segment));
        }
        self.inbound = vec![false; layout.len()];
        let mut blocks = Vec::with_capacity(layout.len());
        for (index, id, offset, len, segment) in layout {
            blocks.push(Block {
                index,
                id,
                offset,
                len,
                segment,
                content: Content::Unsupported("not decoded".into()),
            });
        }
        self.blocks = blocks;
        let mut contents = Vec::with_capacity(self.blocks.len());
        for index in 0..self.blocks.len() {
            let (id, offset, len, segment) = {
                let block = &self.blocks[index];
                (block.id, block.offset, block.len, block.segment)
            };
            contents.push(self.read_block(id, offset, len, segment)?);
        }
        for (block, content) in self.blocks.iter_mut().zip(contents) {
            block.content = content;
        }
        Ok(())
    }

    fn read_block(
        &mut self,
        id: u32,
        offset: u32,
        len: u32,
        segment: Segment,
    ) -> Result<Content, Error> {
        let bytes = self
            .segments
            .at(segment, offset, len)
            .ok_or_else(|| malformed("a block lies outside its segment"))?;
        if let Some(structure) = unique(&self.structures, id, |item| item.name).cloned() {
            return self.read_records(&structure, offset, len, segment);
        }
        let Some(kind) = PoolKind::of(id) else {
            if let Some(content) = self.read_typed_pool(id, bytes) {
                return Ok(content);
            }
            self.unsupported += 1;
            return Ok(Content::Unsupported(format!(
                "no structure, no known pool and no established element width has the type {id:#010x}"
            )));
        };
        if kind == PoolKind::Reference64 {
            let mut words = Vec::new();
            for chunk in bytes.as_chunks::<8>().0.iter().take(self.limits.elements) {
                let word = u64::from_le_bytes(*chunk);
                if word != 0 {
                    words.push(word);
                }
            }
            for word in words {
                match self.resolve(word) {
                    Some((number, _)) => self.note_inbound(number),
                    None => self.unresolved += 1,
                }
            }
        }
        // A pool whose bytes do not divide into its elements is kept as it is
        // stored: reported as unsupported rather than read as an empty pool.
        if let Some(reason) = pool_shape_problem(kind, bytes) {
            self.unsupported += 1;
            return Ok(Content::Unsupported(reason));
        }
        let (total, entries) = self.read_pool(bytes, kind)?;
        Ok(Content::Pool {
            kind,
            total,
            entries,
        })
    }

    /// A block typed by a field code whose width the type table establishes.
    /// Its elements are read as scalars; a type whose elements cannot all be
    /// read is not a pool this decoder claims to understand.
    fn read_typed_pool(&mut self, id: u32, bytes: &[u8]) -> Option<Content> {
        let code = u16::try_from(id & 0xffff).ok()?;
        let width = element_width(code, (id >> 16) as u16)?;
        if width == 0 || !bytes.len().is_multiple_of(width as usize) {
            return None;
        }
        let total = bytes.len() / width as usize;
        let count = total.min(self.limits.elements);
        let mut entries = Vec::with_capacity(count);
        for chunk in bytes.chunks_exact(width as usize).take(count) {
            entries.push(read_scalar(chunk, code, (id >> 16) as u16)?);
        }
        if count < total {
            self.truncated = true;
            self.issues.push(format!(
                "block {id:#010x} holds {total} elements; the first {count} were decoded"
            ));
        }
        Some(Content::Elements {
            code,
            width,
            total: total as u32,
            entries,
        })
    }

    fn read_records(
        &mut self,
        structure: &Structure,
        offset: u32,
        len: u32,
        segment: Segment,
    ) -> Result<Content, Error> {
        if structure.size == 0 {
            self.unsupported += 1;
            return Ok(Content::Unsupported(
                "the structure's record size is zero".into(),
            ));
        }
        if !len.is_multiple_of(structure.size) {
            self.unsupported += 1;
            return Ok(Content::Unsupported(format!(
                "the block's {len} bytes are not a whole number of {} byte records",
                structure.size
            )));
        }
        let total = len / structure.size;
        let decoded = total.min(self.limits.records as u32);
        if decoded < total {
            self.truncated = true;
            self.issues.push(format!(
                "block {:#010x} holds {total} records; the first {decoded} were decoded",
                structure.name
            ));
        }
        self.spend(decoded as usize)?;
        let mut records = Vec::with_capacity(decoded as usize);
        for index in 0..decoded {
            let at = offset + index * structure.size;
            records.push(self.read_record(structure, at, segment, 0, &mut Vec::new())?);
        }
        Ok(Content::Records {
            structure: structure.name,
            stride: structure.size,
            total,
            records,
        })
    }

    fn read_pool(&mut self, bytes: &[u8], kind: PoolKind) -> Result<(u32, Vec<PoolEntry>), Error> {
        if kind == PoolKind::Text {
            if bytes.is_empty() {
                return Ok((0, Vec::new()));
            }
            let pieces: Vec<&[u8]> = bytes.split(|&byte| byte == 0).collect();
            let total = pieces.len() - 1;
            let count = total.min(self.limits.elements);
            if count < total {
                self.truncated = true;
                self.issues.push(format!(
                    "a text pool holds {total} entries; the first {count} were decoded"
                ));
            }
            self.spend(count)?;
            let entries = pieces
                .iter()
                .take(count)
                .map(|piece| match std::str::from_utf8(piece) {
                    Ok(text) => PoolEntry::Text(text.to_string()),
                    Err(_) => PoolEntry::Bytes(piece.to_vec()),
                })
                .collect();
            return Ok((total as u32, entries));
        }
        let stride = kind.stride().expect("a sized pool has a stride");
        let total = bytes.len() / stride;
        let count = total.min(self.limits.elements);
        if count < total {
            self.truncated = true;
            self.issues.push(format!(
                "a {} pool holds {total} entries; the first {count} were decoded",
                kind.name()
            ));
        }
        self.spend(count)?;
        let mut entries = Vec::with_capacity(count);
        for chunk in bytes.chunks_exact(stride).take(count) {
            entries.push(match kind {
                PoolKind::Hash32 => {
                    PoolEntry::Hash32(u32::from_le_bytes(chunk.try_into().expect("4 bytes")))
                }
                PoolKind::Word32 => {
                    PoolEntry::Word32(u32::from_le_bytes(chunk.try_into().expect("4 bytes")))
                }
                PoolKind::Reference64 | PoolKind::Word64 => {
                    PoolEntry::Word64(u64::from_le_bytes(chunk.try_into().expect("8 bytes")))
                }
                PoolKind::Word128 => PoolEntry::Word128(chunk.try_into().expect("16 bytes")),
                PoolKind::Text => unreachable!("handled above"),
            });
        }
        Ok((total as u32, entries))
    }

    fn read_record(
        &mut self,
        structure: &Structure,
        at: u32,
        segment: Segment,
        depth: usize,
        active: &mut Vec<(u32, u32)>,
    ) -> Result<Record, Error> {
        if depth > self.limits.depth {
            return Err(Error::Limit(format!(
                "structures nest deeper than {} levels",
                self.limits.depth
            )));
        }
        // An embedded record costs the same as a block's record, so one record
        // that embeds the same structures many times cannot multiply the work
        // past the document's budget.
        if depth > 0 {
            self.spend(1)?;
        }
        if active.contains(&(structure.name, at)) {
            return Err(malformed(format!(
                "the structure {:#010x} at {at:#x} embeds itself",
                structure.name
            )));
        }
        if self.segments.at(segment, at, structure.size).is_none() {
            return Err(malformed(format!(
                "the record at {at:#x} runs past the {} segment",
                segment.name()
            )));
        }
        active.push((structure.name, at));
        let mut fields = Vec::with_capacity(structure.fields.len());
        for field in &structure.fields {
            let extent = structure.extent(field);
            let value = self.read_value(structure, field, at, segment, depth, active)?;
            fields.push(FieldValue {
                field: *field,
                extent,
                value,
            });
        }
        active.pop();
        Ok(Record {
            offset: at,
            structure: structure.name,
            fields,
        })
    }

    fn read_value(
        &mut self,
        structure: &Structure,
        field: &Field,
        record_at: u32,
        segment: Segment,
        depth: usize,
        active: &mut Vec<(u32, u32)>,
    ) -> Result<Value, Error> {
        let start = record_at
            .checked_add(field.offset)
            .ok_or_else(|| malformed("a field offset overflows"))?;
        let code = field.code();
        if field.name == DESCRIPTOR_NAME {
            return Ok(Value::Descriptor {
                code,
                upper: field.upper(),
                auxiliary: field.auxiliary,
            });
        }
        if field.offset >= structure.size {
            self.issues.push(format!(
                "field {:#010x} of structure {:#010x} lies past its record",
                field.name, structure.name
            ));
            return Ok(self.unresolved(structure, field, segment, start, 0));
        }
        let extent = structure
            .extent(field)
            .unwrap_or_else(|| structure.size - field.offset);
        match code {
            TYPE_STRUCTURE => {
                let target = unique(&self.structures, field.auxiliary, |item| item.name)
                    .cloned()
                    .filter(|target| {
                        target.size > 0
                            && field
                                .offset
                                .checked_add(target.size)
                                .is_some_and(|end| end <= structure.size)
                    });
                match target {
                    Some(target) => {
                        let record =
                            self.read_record(&target, start, segment, depth + 1, active)?;
                        Ok(Value::Structure(Box::new(record)))
                    }
                    None => Ok(self.unresolved(structure, field, segment, start, extent)),
                }
            }
            TYPE_REFERENCE => match self.segments.at(segment, start, 8) {
                Some(bytes) => Ok(Value::Reference(
                    self.bind(u64_at(bytes, 0).expect("8 bytes")),
                )),
                None => Ok(self.unresolved(structure, field, segment, start, 8)),
            },
            TYPE_TEXT_REFERENCE => match self.segments.at(segment, start, TEXT_REFERENCE_WIDTH) {
                Some(bytes) => {
                    let word = u64_at(bytes, 0).expect("8 bytes");
                    Ok(Value::Text(self.read_text(word)))
                }
                None => Ok(self.unresolved(structure, field, segment, start, TEXT_REFERENCE_WIDTH)),
            },
            TYPE_TEXT_SLOT => match self.segments.at(segment, start, 16) {
                Some(bytes) => Ok(Value::TextSlot {
                    raw: bytes.try_into().expect("16 bytes"),
                }),
                None => Ok(self.unresolved(structure, field, segment, start, 16)),
            },
            TYPE_ARRAY | TYPE_ARRAY_LENGTH_FIRST | TYPE_MAP_LENGTH_FIRST => {
                match self.read_span(segment, start, code) {
                    Some(words) if code != TYPE_MAP_LENGTH_FIRST => Ok(Value::Array(
                        self.read_array(structure, field, words, depth)?,
                    )),
                    Some(words) => Ok(Value::Map(Box::new(self.read_map(field, words)?))),
                    None => Ok(self.unresolved(structure, field, segment, start, 16)),
                }
            }
            TYPE_INLINE_ARRAY => {
                Ok(self.read_inline(structure, field, segment, start, depth, active))
            }
            TYPE_BITSET => match self.segments.at(segment, start, BITSET_WIDTH) {
                Some(bytes) => Ok(Value::Bitset(Bitset {
                    bits: u64_at(bytes, 0).expect("8 bytes"),
                    bit_count: match field.upper() {
                        0 => None,
                        count => Some(count),
                    },
                    enumeration: field.auxiliary,
                })),
                None => Ok(self.unresolved(structure, field, segment, start, BITSET_WIDTH)),
            },
            TYPE_ENUM8 | TYPE_ENUM32 => {
                let width = crate::psin::pso::type_width(code, field.upper()).unwrap_or(4);
                match self.segments.at(segment, start, width) {
                    Some(bytes) => {
                        let value = if width == 1 {
                            u32::from(bytes[0])
                        } else {
                            u32::from_le_bytes(bytes.try_into().expect("4 bytes"))
                        };
                        Ok(Value::Enum(self.enum_match(field.auxiliary, value)))
                    }
                    None => Ok(self.unresolved(structure, field, segment, start, width)),
                }
            }
            _ => match element_width(code, field.upper()) {
                Some(width) if width <= extent => {
                    match self
                        .segments
                        .at(segment, start, width)
                        .and_then(|bytes| read_scalar(bytes, code, field.upper()))
                    {
                        Some(scalar) => Ok(Value::Scalar(scalar)),
                        None => Ok(self.unresolved(structure, field, segment, start, extent)),
                    }
                }
                _ => Ok(self.unresolved(structure, field, segment, start, extent)),
            },
        }
    }

    /// The bytes a field's type does not let this decoder read, kept as they
    /// are stored.
    fn unresolved(
        &self,
        structure: &Structure,
        field: &Field,
        segment: Segment,
        start: u32,
        width: u32,
    ) -> Value {
        let width = width.min(structure.size.saturating_sub(field.offset));
        Value::Unresolved {
            code: field.code(),
            upper: field.upper(),
            auxiliary: field.auxiliary,
            raw: self
                .segments
                .at(segment, start, width)
                .unwrap_or_default()
                .to_vec(),
        }
    }

    fn read_inline(
        &mut self,
        structure: &Structure,
        field: &Field,
        segment: Segment,
        start: u32,
        depth: usize,
        active: &mut Vec<(u32, u32)>,
    ) -> Value {
        let count = field.auxiliary;
        let descriptor = structure
            .fields
            .get(usize::from(field.upper()))
            .filter(|descriptor| descriptor.name == DESCRIPTOR_NAME);
        let extent = structure
            .extent(field)
            .unwrap_or_else(|| structure.size - field.offset);
        let Some(descriptor) = descriptor else {
            return self.unresolved(structure, field, segment, start, extent);
        };
        if descriptor.code() == TYPE_STRUCTURE {
            let Some(element) = unique(&self.structures, descriptor.auxiliary, |item| item.name)
                .cloned()
                .filter(|element| element.size > 0)
            else {
                return self.unresolved(structure, field, segment, start, extent);
            };
            if count
                .checked_mul(element.size)
                .is_none_or(|total| total > extent)
            {
                return self.unresolved(structure, field, segment, start, extent);
            }
            let mut records = Vec::with_capacity(count as usize);
            for index in 0..count {
                let at = start + index * element.size;
                match self.read_record(&element, at, segment, depth + 1, active) {
                    Ok(record) => records.push(record),
                    Err(err) => {
                        self.issues.push(err.to_string());
                        return self.unresolved(structure, field, segment, start, extent);
                    }
                }
            }
            return Value::Array(ArrayValue {
                span: Span {
                    word: 0,
                    resolution: Resolution::Null,
                    count,
                    capacity: count,
                    tail: 0,
                },
                descriptor: field.upper(),
                elements: Ok(ArrayElements::Records { records }),
            });
        }
        let Some(width) = element_width(descriptor.code(), descriptor.upper()) else {
            return self.unresolved(structure, field, segment, start, extent);
        };
        if width == 0 || count.checked_mul(width).is_none_or(|total| total > extent) {
            return self.unresolved(structure, field, segment, start, extent);
        }
        let Some(bytes) = self.segments.at(segment, start, count * width) else {
            return self.unresolved(structure, field, segment, start, extent);
        };
        let mut values = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            let at = index * width as usize;
            match read_scalar(
                &bytes[at..at + width as usize],
                descriptor.code(),
                descriptor.upper(),
            ) {
                Some(scalar) => values.push(scalar),
                None => return self.unresolved(structure, field, segment, start, extent),
            }
        }
        Value::Array(ArrayValue {
            span: Span {
                word: 0,
                resolution: Resolution::Null,
                count,
                capacity: count,
                tail: 0,
            },
            descriptor: field.upper(),
            elements: Ok(ArrayElements::Scalars {
                code: descriptor.code(),
                values,
            }),
        })
    }

    /// The 16-byte array or map header of the type code.
    fn read_span(&self, segment: Segment, at: u32, code: u16) -> Option<HeaderWords> {
        let bytes = self.segments.at(segment, at, 16)?;
        Some(if code == TYPE_ARRAY {
            HeaderWords {
                reference: u64_at(bytes, 0)?,
                count: u32::from(u16_at(bytes, 8)?),
                capacity: u32::from(u16_at(bytes, 10)?),
                tail: u32_at(bytes, 12)?,
            }
        } else {
            HeaderWords {
                count: u32_at(bytes, 0)?,
                capacity: u32_at(bytes, 4)?,
                reference: u64_at(bytes, 8)?,
                tail: 0,
            }
        })
    }

    fn read_array(
        &mut self,
        structure: &Structure,
        field: &Field,
        words: HeaderWords,
        depth: usize,
    ) -> Result<ArrayValue, Error> {
        let span = Span {
            word: words.reference,
            resolution: self.resolution(words.reference),
            count: words.count,
            capacity: words.capacity,
            tail: words.tail,
        };
        let elements = self.resolve_array(structure, field, words, depth);
        Ok(ArrayValue {
            span,
            descriptor: field.upper(),
            elements,
        })
    }

    fn resolve_array(
        &mut self,
        structure: &Structure,
        field: &Field,
        words: HeaderWords,
        _depth: usize,
    ) -> Result<ArrayElements, String> {
        if words.count != words.capacity {
            return Err(format!(
                "the array's {} length and {} capacity words differ",
                words.count, words.capacity
            ));
        }
        if words.tail != 0 {
            return Err(format!("the array's trailing word is {:#x}", words.tail));
        }
        let descriptor = structure
            .fields
            .get(usize::from(field.upper()))
            .filter(|descriptor| descriptor.name == DESCRIPTOR_NAME)
            .ok_or_else(|| format!("field {} is not an element descriptor", field.upper()))?;
        let descriptor = *descriptor;
        let code = descriptor.code();
        if words.count == 0 {
            return Ok(match code {
                TYPE_STRUCTURE => ArrayElements::Structure {
                    structure: descriptor.auxiliary,
                    stride: self
                        .structure(descriptor.auxiliary)
                        .map_or(0, |target| target.size),
                    links: Vec::new(),
                },
                TYPE_REFERENCE => ArrayElements::Reference { links: Vec::new() },
                0x4a => ArrayElements::Hash32 { values: Vec::new() },
                TYPE_ENUM32 => ArrayElements::Enum32 {
                    enumeration: descriptor.auxiliary,
                    values: Vec::new(),
                },
                code if element_width(code, descriptor.upper()).is_some() => {
                    ArrayElements::Scalars {
                        code,
                        values: Vec::new(),
                    }
                }
                code => return Err(format!("the element type {code:#x} is not decoded")),
            });
        }
        let Some((number, offset)) = self.resolve(words.reference) else {
            return Err("the array's reference names no block".into());
        };
        self.note_inbound(number);
        let block = self
            .blocks
            .iter()
            .find(|block| block.index == number)
            .cloned()
            .ok_or_else(|| "the array's block does not exist".to_string())?;
        let bytes = self
            .segments
            .at(
                block.segment,
                block.offset + offset,
                block.len.saturating_sub(offset),
            )
            .ok_or_else(|| "the array's bytes leave the segment".to_string())?;
        let wanted = words.count as usize;
        match code {
            TYPE_STRUCTURE => {
                let element = unique(&self.structures, descriptor.auxiliary, |item| item.name)
                    .cloned()
                    .ok_or_else(|| {
                        "the element descriptor names no single structure".to_string()
                    })?;
                if element.size == 0 {
                    return Err("the element structure's record size is zero".into());
                }
                if element.name != block.id {
                    return Err(format!(
                        "the target block holds {:#010x}, not the element structure {:#010x}",
                        block.id, element.name
                    ));
                }
                if !offset.is_multiple_of(element.size) {
                    return Err("the array's offset is not a whole record multiple".into());
                }
                let available = bytes.len() / element.size as usize;
                let count = wanted.min(available).min(self.limits.elements);
                if count < wanted {
                    self.truncated = true;
                    self.issues.push(format!(
                        "a structure array names {wanted} records; the first {count} were decoded"
                    ));
                }
                self.spend(count).map_err(|err| err.to_string())?;
                let first = offset / element.size;
                let mut links = Vec::with_capacity(count);
                for index in 0..count as u32 {
                    links.push(RecordLink {
                        index: first + index,
                        target: Target {
                            block: number,
                            record: first + index,
                            offset: offset + index * element.size,
                            structure: element.name,
                        },
                    });
                }
                Ok(ArrayElements::Structure {
                    structure: element.name,
                    stride: element.size,
                    links,
                })
            }
            TYPE_REFERENCE => {
                if block.id != 0x07 {
                    return Err("the target block is not a reference pool".into());
                }
                let count = wanted.min(bytes.len() / 8).min(self.limits.elements);
                if count < wanted {
                    self.truncated = true;
                }
                self.spend(count).map_err(|err| err.to_string())?;
                let mut links = Vec::with_capacity(count);
                for chunk in bytes.as_chunks::<8>().0.iter().take(count) {
                    let reference = self.bind(u64::from_le_bytes(*chunk));
                    if reference.fault.is_some() {
                        self.unresolved += 1;
                    }
                    links.push(reference);
                }
                Ok(ArrayElements::Reference { links })
            }
            0x4a => {
                if block.id != 0x4a {
                    return Err("the target block is not a hash pool".into());
                }
                let count = wanted.min(bytes.len() / 4).min(self.limits.elements);
                self.spend(count).map_err(|err| err.to_string())?;
                Ok(ArrayElements::Hash32 {
                    values: bytes
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .take(count)
                        .map(|chunk| u32::from_le_bytes(*chunk))
                        .collect(),
                })
            }
            TYPE_ENUM32 => {
                let count = wanted.min(bytes.len() / 4).min(self.limits.elements);
                self.spend(count).map_err(|err| err.to_string())?;
                Ok(ArrayElements::Enum32 {
                    enumeration: descriptor.auxiliary,
                    values: bytes
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .take(count)
                        .map(|chunk| u32::from_le_bytes(*chunk))
                        .collect(),
                })
            }
            code => {
                let width = element_width(code, descriptor.upper())
                    .ok_or_else(|| format!("the element type {code:#x} is not decoded"))?;
                if width == 0 || !bytes.len().is_multiple_of(width as usize) {
                    return Err(format!(
                        "the target block's {} bytes are not whole {width}-byte elements",
                        bytes.len()
                    ));
                }
                let count = wanted
                    .min(bytes.len() / width as usize)
                    .min(self.limits.elements);
                if count < wanted {
                    self.truncated = true;
                    self.issues.push(format!(
                        "an array names {wanted} elements; the first {count} were decoded"
                    ));
                }
                self.spend(count).map_err(|err| err.to_string())?;
                let mut values = Vec::with_capacity(count);
                for index in 0..count {
                    let at = index * width as usize;
                    match read_scalar(&bytes[at..at + width as usize], code, descriptor.upper()) {
                        Some(scalar) => values.push(scalar),
                        None => return Err(format!("the element type {code:#x} is not decoded")),
                    }
                }
                Ok(ArrayElements::Scalars { code, values })
            }
        }
    }

    fn read_map(&mut self, field: &Field, words: HeaderWords) -> Result<MapValue, Error> {
        let span = Span {
            word: words.reference,
            resolution: self.resolution(words.reference),
            count: words.count,
            capacity: words.capacity,
            tail: words.tail,
        };
        let entries = self.resolve_map(words);
        Ok(MapValue {
            span,
            key_descriptor: (field.auxiliary & 0xffff) as u16,
            value_descriptor: (field.auxiliary >> 16) as u16,
            entries,
        })
    }

    fn resolve_map(&mut self, words: HeaderWords) -> Result<(u32, Vec<Record>), String> {
        if words.count == 0 {
            return Ok((0, Vec::new()));
        }
        let Some((number, offset)) = self.resolve(words.reference) else {
            return Err("the map's reference names no block".into());
        };
        self.note_inbound(number);
        let block = self
            .blocks
            .iter()
            .find(|block| block.index == number)
            .cloned()
            .ok_or_else(|| "the map's block does not exist".to_string())?;
        let structure = unique(&self.structures, block.id, |item| item.name)
            .cloned()
            .ok_or_else(|| "the map's target names no single structure".to_string())?;
        if structure.size == 0 {
            return Err("the entry structure's record size is zero".into());
        }
        if !offset.is_multiple_of(structure.size) {
            return Err("the map's offset is not a whole record multiple".into());
        }
        let available = block.len.saturating_sub(offset) / structure.size;
        let count = words.count.min(available).min(self.limits.elements as u32);
        if count < words.count {
            self.truncated = true;
            self.issues.push(format!(
                "a map names {} buckets; the first {count} were decoded",
                words.count
            ));
        }
        self.spend(count as usize).map_err(|err| err.to_string())?;
        let mut records = Vec::with_capacity(count as usize);
        for index in 0..count {
            let at = block.offset + offset + index * structure.size;
            records.push(
                self.read_record(&structure, at, block.segment, 0, &mut Vec::new())
                    .map_err(|err| err.to_string())?,
            );
        }
        Ok((structure.name, records))
    }

    fn structure(&self, name: u32) -> Option<&Structure> {
        unique(&self.structures, name, |structure| structure.name)
    }

    fn enum_match(&self, enumeration: u32, value: u32) -> EnumValueMatch {
        let Some(table) = self.enumeration(enumeration) else {
            return EnumValueMatch {
                value,
                enumeration,
                matches: Vec::new(),
                defined: false,
            };
        };
        EnumValueMatch {
            value,
            enumeration,
            matches: table.matches(value).copied().collect(),
            defined: true,
        }
    }

    fn enumeration(&self, name: u32) -> Option<&Enumeration> {
        unique(&self.enums, name, |enumeration| enumeration.name)
    }

    /// The block and offset a reference word names.
    fn resolve(&self, word: u64) -> Option<(u32, u32)> {
        if word == 0 {
            return None;
        }
        let number = (word & 0xf_ffff) as u32;
        // The offset field is 44 bits wide; one that does not fit a `u32` names
        // no location this decoder can address, which is a fault rather than a
        // wrapped offset.
        let offset = u32::try_from(word >> 20).ok()?;
        let block = self.blocks.iter().find(|block| block.index == number)?;
        (offset <= block.len).then_some((number, offset))
    }

    fn resolution(&self, word: u64) -> Resolution {
        if word == 0 {
            return Resolution::Null;
        }
        match self.resolve(word) {
            Some((number, offset)) => Resolution::Located(Location {
                block: number,
                offset,
                len: self
                    .blocks
                    .iter()
                    .find(|block| block.index == number)
                    .map_or(0, |block| block.len),
            }),
            None => Resolution::Fault(ReferenceFault::BlockOutside),
        }
    }

    fn bind(&mut self, word: u64) -> Reference {
        if word == 0 {
            return Reference {
                word,
                target: None,
                fault: None,
            };
        }
        let fault = |fault| Reference {
            word,
            target: None,
            fault: Some(fault),
        };
        let Some((number, offset)) = self.resolve(word) else {
            self.unresolved += 1;
            return fault(ReferenceFault::BlockOutside);
        };
        let block = self
            .blocks
            .iter()
            .find(|block| block.index == number)
            .cloned()
            .expect("resolved");
        let Some(structure) = unique(&self.structures, block.id, |item| item.name).cloned() else {
            self.note_inbound(number);
            self.unresolved += 1;
            return fault(ReferenceFault::NoStructure);
        };
        if structure.size == 0
            || !offset.is_multiple_of(structure.size)
            || offset
                .checked_add(structure.size)
                .is_none_or(|end| end > block.len)
        {
            self.unresolved += 1;
            return fault(ReferenceFault::NotARecord);
        }
        self.note_inbound(number);
        Reference {
            word,
            target: Some(Target {
                block: number,
                record: offset / structure.size,
                offset,
                structure: structure.name,
            }),
            fault: None,
        }
    }

    /// The text a `0x42` word names, when its block is a text block.
    fn read_text(&mut self, word: u64) -> TextValue {
        let resolution = self.resolution(word);
        let text = match resolution {
            Resolution::Null => Err("the reference is null".to_string()),
            Resolution::Fault(_) => Err("the reference names no block".to_string()),
            Resolution::Located(location) => {
                self.note_inbound(location.block);
                let block = self
                    .blocks
                    .iter()
                    .find(|block| block.index == location.block)
                    .cloned()
                    .expect("resolved");
                if block.id != 0x10 {
                    Err(format!(
                        "the reference names block {:#010x}, not a text block",
                        block.id
                    ))
                } else {
                    let offset = location.offset.min(block.len);
                    match self
                        .segments
                        .at(block.segment, block.offset + offset, block.len - offset)
                    {
                        Some(bytes) => match bytes.iter().position(|&byte| byte == 0) {
                            Some(end) => std::str::from_utf8(&bytes[..end])
                                .map(str::to_string)
                                .map_err(|_| "the text is not UTF-8".to_string()),
                            None => Err("the text is not NUL-terminated".to_string()),
                        },
                        None => Err("the text leaves its segment".to_string()),
                    }
                }
            }
        };
        if text.is_err() {
            self.unresolved += 1;
        }
        TextValue {
            word,
            resolution,
            text,
        }
    }

    fn spend(&mut self, amount: usize) -> Result<(), Error> {
        self.nodes = self
            .nodes
            .checked_add(amount)
            .ok_or_else(|| Error::Limit("the value count overflows".into()))?;
        if self.nodes > self.limits.nodes {
            return Err(Error::Limit(format!(
                "the resource needs more than {} values",
                self.limits.nodes
            )));
        }
        Ok(())
    }

    fn note_inbound(&mut self, block: u32) {
        if let Some(slot) = block
            .checked_sub(1)
            .and_then(|index| self.inbound.get_mut(index as usize))
        {
            *slot = true;
        }
    }

    fn finish(self, header: Header) -> Document {
        Document {
            header,
            structures: self.structures,
            enums: self.enums,
            blocks: self.blocks,
            roots: Vec::new(),
            issues: self.issues,
            unsupported_blocks: self.unsupported,
            unresolved_references: self.unresolved,
            truncated: self.truncated,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HeaderWords {
    reference: u64,
    count: u32,
    capacity: u32,
    tail: u32,
}

/// The structure blocks no decoded reference reaches, in block order.
fn derive_roots(document: &Document) -> Vec<u32> {
    let mut inbound = vec![false; document.blocks.len()];
    for block in &document.blocks {
        match &block.content {
            Content::Records { records, .. } => {
                for record in records {
                    mark_inbound(record, &mut inbound);
                }
            }
            Content::Pool {
                kind: PoolKind::Reference64,
                entries,
                ..
            } => {
                for entry in entries {
                    if let PoolEntry::Word64(word) = entry
                        && let Some(number) = reference_block(*word)
                    {
                        mark_block(&mut inbound, number);
                    }
                }
            }
            _ => {}
        }
    }
    document
        .blocks
        .iter()
        .filter(|block| document.structure(block.id).is_some())
        .filter(|block| !inbound[block.index as usize - 1])
        .map(|block| block.index)
        .collect()
}

fn mark_block(inbound: &mut [bool], block: u32) {
    if let Some(slot) = block
        .checked_sub(1)
        .and_then(|index| inbound.get_mut(index as usize))
    {
        *slot = true;
    }
}

fn mark_inbound(record: &Record, inbound: &mut [bool]) {
    for value in &record.fields {
        match &value.value {
            Value::Reference(reference) => {
                if let Some(target) = reference.target {
                    mark_block(inbound, target.block);
                }
            }
            Value::Text(text) => {
                if let Resolution::Located(location) = text.resolution {
                    mark_block(inbound, location.block);
                }
            }
            Value::Array(array) => {
                if let Resolution::Located(location) = array.span.resolution {
                    mark_block(inbound, location.block);
                }
                match &array.elements {
                    Ok(ArrayElements::Reference { links }) => {
                        for link in links {
                            if let Some(target) = link.target {
                                mark_block(inbound, target.block);
                            }
                        }
                    }
                    Ok(ArrayElements::Records { records }) => {
                        for record in records {
                            mark_inbound(record, inbound);
                        }
                    }
                    _ => {}
                }
            }
            Value::Map(map) => {
                if let Resolution::Located(location) = map.span.resolution {
                    mark_block(inbound, location.block);
                }
                if let Ok((_, records)) = &map.entries {
                    for record in records {
                        mark_inbound(record, inbound);
                    }
                }
            }
            Value::Structure(record) => mark_inbound(record, inbound),
            _ => {}
        }
    }
}

fn reference_block(word: u64) -> Option<u32> {
    if word == 0 {
        return None;
    }
    Some((word & 0xf_ffff) as u32)
}

/// The offset a pointer names, checked against the segment it selects.
fn pointer_offset(value: u64, segment: Segment, len: usize) -> Option<u32> {
    let (selected, offset) = match Pointer::decode(value)? {
        Pointer::System(offset) => (Segment::System, offset),
        Pointer::Graphics(offset) => (Segment::Graphics, offset),
    };
    (selected == segment && (offset as usize) <= len).then_some(offset)
}

/// The stored width of a type code, when the schema establishes one.
/// Why a pool's bytes cannot be divided into the elements its type establishes:
/// a sized pool whose length is not a whole number of elements, or a text pool
/// whose last string has no terminator. `None` when the bytes divide.
fn pool_shape_problem(kind: PoolKind, bytes: &[u8]) -> Option<String> {
    let len = bytes.len();
    match kind.stride() {
        None if bytes.last().is_some_and(|byte| *byte != 0) => Some(format!(
            "the text block's {len} bytes do not end with a NUL"
        )),
        None => None,
        Some(stride) if !len.is_multiple_of(stride) => Some(format!(
            "the block's {len} bytes are not whole {stride}-byte {} elements",
            kind.name()
        )),
        Some(_) => None,
    }
}

fn element_width(code: u16, upper: u16) -> Option<u32> {
    match code {
        TYPE_TEXT_REFERENCE => Some(TEXT_REFERENCE_WIDTH),
        TYPE_BITSET => Some(BITSET_WIDTH),
        _ => crate::psin::pso::type_width(code, upper),
    }
}

fn read_scalar(bytes: &[u8], code: u16, upper: u16) -> Option<Scalar> {
    let read4 = |at: usize| -> Option<[u8; 4]> { bytes.get(at..at + 4)?.try_into().ok() };
    let read8 = |at: usize| -> Option<[u8; 8]> { bytes.get(at..at + 8)?.try_into().ok() };
    Some(match code {
        0x01 => Scalar::Bool(match *bytes.first()? {
            0 => false,
            1 => true,
            _ => return None,
        }),
        0x10 => Scalar::I8(*bytes.first()? as i8),
        0x11 => Scalar::U8(*bytes.first()?),
        0x12 => Scalar::I16(i16::from_le_bytes(bytes.get(..2)?.try_into().ok()?)),
        0x13 => Scalar::U16(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?)),
        0x15 => Scalar::U32(u32::from_le_bytes(read4(0)?)),
        0x16 => Scalar::I32(i32::from_le_bytes(read4(0)?)),
        0x08 => Scalar::U64(u64::from_le_bytes(read8(0)?)),
        0x20 => Scalar::F16(crate::psin::pso::half_to_f32(u16::from_le_bytes(
            bytes.get(..2)?.try_into().ok()?,
        ))),
        0x21 => Scalar::F32(f32::from_le_bytes(read4(0)?)),
        0x4a => Scalar::Hash32(u32::from_le_bytes(read4(0)?)),
        0x4d => Scalar::Hash64(u64::from_le_bytes(read8(0)?)),
        0x4f if upper == 5 => Scalar::Hash64(u64::from_le_bytes(read8(0)?)),
        0x31 | 0x32 => Scalar::Vector {
            values: [
                f32::from_le_bytes(read4(0)?),
                f32::from_le_bytes(read4(4)?),
                f32::from_le_bytes(read4(8)?),
                0.0,
            ],
            count: 3,
        },
        0x33 | 0x34 => Scalar::Vector {
            values: [
                f32::from_le_bytes(read4(0)?),
                f32::from_le_bytes(read4(4)?),
                f32::from_le_bytes(read4(8)?),
                f32::from_le_bytes(read4(12)?),
            ],
            count: 4,
        },
        _ => return None,
    })
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// The field type words of a document, by count. A diagnostic helper for
/// population surveys; it does not interpret them.
pub fn field_type_words(document: &Document) -> HashMap<u32, usize> {
    let mut words = HashMap::new();
    for structure in &document.structures {
        for field in &structure.fields {
            *words.entry(field.type_word).or_insert(0) += 1;
        }
    }
    words
}
