//! Typed decoding of the `PSIN` containers the `LSCH` family describes.
//!
//! A GTA VI `.zmt` row holds one of these containers: a `PSIN` section with an
//! instance block table, an `LSCH` schema, a `LENM` enum table and an `LRSC`
//! copy of the metadata resource header. [`super`] walks the framing; this
//! module reads what the sections hold.
//!
//! The layout, and the evidence for it:
//!
//! - The block table is the `LSCH` descriptor table [`super`] already solves,
//!   read as `(type word, byte length)` pairs. The first block follows the
//!   table on a 16-byte boundary, and every block is padded to one.
//! - A structure record is `{u32 name, u32 signature, u32 flags, u32 zero,
//!   8 × 0xAA, u32 size, u16 zero, u16 field count}`. All structure records
//!   come first, then every field record in table order:
//!   `{u32 name, u32 offset, u32 type, u32 auxiliary}`.
//! - An enum record is `{u32 name, u32 signature, 8 × 0xEE, u32 count, u32
//!   zero}`, then `{u64 value, u32 name, u32 zero}` per value.
//! - A block whose type is one structure's name holds that structure's
//!   records, `size` bytes each. Any other block is a value pool.
//! - A reference is a `u64` of `(byte offset within the block << 20) | block`,
//!   the block counted from one. Zero is null.
//! - An array is `{u64 reference, u16 length, u16 capacity, u32 zero}` and a
//!   map is `{u64 one, u64 reference, u16 length, u16 capacity, u32 zero}`.
//!   Both name their element, or their key and value, by index into the owning
//!   structure's field list, and the referenced block holds the elements.
//!
//! Only type codes with an established width are read as values. Every other
//! field keeps its name, offset, type word, auxiliary word, storage extent and
//! bytes, and is reported as unresolved. A stored hash is never replaced by a
//! name: an enum value is reported beside the members it matched, and a field
//! name stays the hash the schema stores.
//!
//! Read limits, bounds checks and cycle checks apply to the whole document, so
//! hostile input cannot make the decoder allocate more than [`Limits::nodes`]
//! values or nest deeper than [`Limits::depth`] levels.

use std::collections::HashMap;
use std::fmt;

use super::{Error as FramingError, Family, Section, parse as parse_framing};

pub use names::Names;

pub mod names;

/// A structure record is this many bytes.
const STRUCTURE_LEN: usize = 32;
/// A field record is this many bytes.
const FIELD_LEN: usize = 16;
/// An enum record is this many bytes.
const ENUM_LEN: usize = 24;
/// An enum value record is this many bytes.
const ENUM_VALUE_LEN: usize = 16;
/// A block record is `(type, length)` followed by eight `0xAA` bytes.
const BLOCK_RECORD_LEN: usize = 16;
/// The block area starts this many bytes after the `PSIN` header, before the
/// block lengths are counted.
const DATA_AREA_START: usize = 16;
/// The marker every structure record carries where the resource form stores a
/// pointer.
const STRUCTURE_MARKER: [u8; 8] = [0xAA; 8];
/// The marker every enum record carries.
const ENUM_MARKER: [u8; 8] = [0xEE; 8];
/// A field named this describes an array or map element rather than storage.
const DESCRIPTOR_NAME: u32 = 0x100;

/// The largest structure table a container may declare.
pub const MAX_STRUCTURES: usize = 1 << 14;
/// The largest field count a schema may declare.
pub const MAX_FIELDS: usize = 1 << 18;
/// The largest enum table a container may declare.
pub const MAX_ENUMS: usize = 1 << 14;
/// The largest enum value count a table may declare.
pub const MAX_ENUM_VALUES: usize = 1 << 20;

// Type codes with an established width. Anything else is reported, not read.
const TYPE_BOOL: u16 = 0x01;
const TYPE_STRUCTURE: u16 = 0x05;
const TYPE_REFERENCE: u16 = 0x07;
const TYPE_U64: u16 = 0x08;
const TYPE_I8: u16 = 0x10;
const TYPE_U8: u16 = 0x11;
const TYPE_I16: u16 = 0x12;
const TYPE_U16: u16 = 0x13;
const TYPE_U32: u16 = 0x15;
const TYPE_I32: u16 = 0x16;
const TYPE_F16: u16 = 0x20;
const TYPE_F32: u16 = 0x21;
const TYPE_VEC3_12: u16 = 0x32;
const TYPE_VEC3_16: u16 = 0x33;
const TYPE_VEC4: u16 = 0x34;
const TYPE_STRING: u16 = 0x44;
const TYPE_HASH32: u16 = 0x4a;
const TYPE_HASH64: u16 = 0x4d;
const TYPE_ID64: u16 = 0x4f;
const TYPE_INLINE_ARRAY: u16 = 0x50;
const TYPE_ARRAY: u16 = 0x52;
const TYPE_ARRAY_LENGTH_FIRST: u16 = 0x5c;
const TYPE_ENUM8: u16 = 0x60;
const TYPE_ENUM32: u16 = 0x62;
const TYPE_BITSET: u16 = 0x65;
const TYPE_MAP: u16 = 0x71;
const TYPE_MAP_LENGTH_FIRST: u16 = 0x75;

/// The stored width of a type code, when it is established. `upper` is the
/// type word's qualifier.
pub fn type_width(code: u16, upper: u16) -> Option<u32> {
    Some(match code {
        TYPE_BOOL | TYPE_I8 | TYPE_U8 | TYPE_ENUM8 => 1,
        TYPE_I16 | TYPE_U16 | TYPE_F16 => 2,
        TYPE_U32 | TYPE_I32 | TYPE_F32 | TYPE_HASH32 | TYPE_ENUM32 => 4,
        TYPE_U64 | TYPE_HASH64 | TYPE_REFERENCE => 8,
        TYPE_ID64 => match upper {
            0x0f => 16,
            0x05 => 8,
            _ => return None,
        },
        TYPE_VEC3_12 => 12,
        TYPE_VEC3_16 | TYPE_VEC4 | TYPE_STRING | TYPE_BITSET | TYPE_INLINE_ARRAY
        | TYPE_ARRAY | TYPE_ARRAY_LENGTH_FIRST | TYPE_MAP_LENGTH_FIRST => 16,
        TYPE_MAP => 24,
        _ => return None,
    })
}

/// The default read limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Values emitted across the whole document.
    pub nodes: usize,
    /// Structure and container nesting.
    pub depth: usize,
    /// Records decoded from one block.
    pub records: usize,
    /// Elements decoded from one pool, array or map.
    pub elements: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            nodes: 1 << 20,
            depth: 16,
            records: 1 << 18,
            elements: 1 << 18,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The bytes do not start with `PSIN`.
    NotPsin,
    /// The section framing or a pre-section grammar is broken.
    Framing(String),
    /// The container is a family this decoder does not read.
    Unsupported {
        family: &'static str,
        first_tag: String,
    },
    /// The schema, the block table or a value is inconsistent.
    Malformed(String),
    /// A read limit was reached.
    Limit(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotPsin => f.write_str("not a PSIN payload"),
            Error::Framing(reason) => write!(f, "PSIN framing: {reason}"),
            Error::Unsupported { family, first_tag } => write!(
                f,
                "the {family} family ({first_tag}) has no decoded structure here"
            ),
            Error::Malformed(reason) => f.write_str(reason),
            Error::Limit(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

impl From<FramingError> for Error {
    fn from(err: FramingError) -> Self {
        match err {
            FramingError::NotPsin => Error::NotPsin,
            FramingError::Invalid(reason) => Error::Framing(reason),
        }
    }
}

fn malformed(reason: impl Into<String>) -> Error {
    Error::Malformed(reason.into())
}

/// What a value pool holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolKind {
    /// `0x10`: NUL-terminated ASCII.
    Text,
    /// `0x4a`: 32-bit hashes.
    Hash32,
    /// `7`: 64-bit reference words, not followed.
    Reference64,
    /// `0x14`: 32-bit words of no established meaning.
    Word32,
    /// `0x16`: 64-bit words of no established meaning.
    Word64,
    /// `0x33`: 16-byte words of no established meaning.
    Word128,
}

impl PoolKind {
    pub fn of(id: u32) -> Option<Self> {
        Some(match id {
            0x10 => PoolKind::Text,
            0x4a => PoolKind::Hash32,
            7 => PoolKind::Reference64,
            0x14 => PoolKind::Word32,
            0x16 => PoolKind::Word64,
            0x33 => PoolKind::Word128,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            PoolKind::Text => "text",
            PoolKind::Hash32 => "hash32",
            PoolKind::Reference64 => "reference64",
            PoolKind::Word32 => "word32",
            PoolKind::Word64 => "word64",
            PoolKind::Word128 => "word128",
        }
    }

    /// The element width; `None` for the variable-width text pool.
    pub fn stride(self) -> Option<usize> {
        Some(match self {
            PoolKind::Text => return None,
            PoolKind::Hash32 | PoolKind::Word32 => 4,
            PoolKind::Reference64 | PoolKind::Word64 => 8,
            PoolKind::Word128 => 16,
        })
    }

    /// Whether every element of this pool has an established meaning.
    pub fn decoded(self) -> bool {
        matches!(self, PoolKind::Text | PoolKind::Hash32)
    }
}

/// One stored value as the schema declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// The field-name hash.
    pub name: u32,
    /// The byte offset in the owning structure.
    pub offset: u32,
    /// The type code in the low 16 bits, its qualifier in the high 16.
    pub type_word: u32,
    /// An embedded structure's name, an enum's hash, or array and map
    /// descriptor indices.
    pub auxiliary: u32,
}

impl Field {
    pub fn code(&self) -> u16 {
        self.type_word as u16
    }

    pub fn upper(&self) -> u16 {
        (self.type_word >> 16) as u16
    }

    /// Whether this field describes an array or map element instead of storage.
    pub fn is_descriptor(&self) -> bool {
        self.name == DESCRIPTOR_NAME
    }

    /// The established width of the field's type.
    pub fn width(&self) -> Option<u32> {
        type_width(self.code(), self.upper())
    }
}

/// One structure of the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structure {
    /// The structure's name hash. Generated helper structures are numbered
    /// from `0x100` instead of hashed.
    pub name: u32,
    /// A word stored beside the name that is not established as a length or a
    /// hash.
    pub signature: u32,
    /// `0x200`, `0x300` or `0x400`. The low byte marks generated helper types.
    pub flags: u32,
    /// The size of one record.
    pub size: u32,
    pub fields: Vec<Field>,
}

impl Structure {
    /// The end of `field`'s storage: the next named field's offset, or the end
    /// of the record. `None` when the offset lies outside the record, and for
    /// a descriptor, which occupies no storage of its own.
    pub fn extent(&self, field: &Field) -> Option<u32> {
        if field.is_descriptor() || field.offset >= self.size {
            return None;
        }
        let next = self
            .fields
            .iter()
            .filter(|other| !other.is_descriptor() && other.offset > field.offset)
            .map(|other| other.offset)
            .min()
            .unwrap_or(self.size);
        Some(next - field.offset)
    }

    /// The fields that occupy storage, in table order.
    pub fn stored_fields(&self) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(|field| !field.is_descriptor())
    }
}

/// One enum value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumValue {
    pub value: u64,
    pub name: u32,
}

/// One enumeration of the `LENM` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumeration {
    pub name: u32,
    /// A word stored beside the name of no established meaning.
    pub signature: u32,
    pub values: Vec<EnumValue>,
}

impl Enumeration {
    /// The members whose stored value equals `value`. A member stored as a
    /// sign-extended 32-bit value matches too.
    pub fn matches(&self, value: u32) -> impl Iterator<Item = &EnumValue> {
        let unsigned = u64::from(value);
        let signed = u64::from(value) | 0xffff_ffff_0000_0000;
        self.values
            .iter()
            .filter(move |member| member.value == unsigned || member.value == signed)
    }
}

/// A scalar with an established width and meaning.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scalar {
    Bool(bool),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    U32(u32),
    I32(i32),
    U64(u64),
    F16(f32),
    F32(f32),
    /// A field or identifier hash stored as a 32-bit word.
    Hash32(u32),
    /// A 64-bit hash or identifier.
    Hash64(u64),
    /// Three or four single-precision components.
    Vector { values: [f32; 4], count: u8 },
}

impl Scalar {
    pub fn type_name(&self) -> &'static str {
        match self {
            Scalar::Bool(_) => "bool",
            Scalar::I8(_) => "i8",
            Scalar::U8(_) => "u8",
            Scalar::I16(_) => "i16",
            Scalar::U16(_) => "u16",
            Scalar::U32(_) => "u32",
            Scalar::I32(_) => "i32",
            Scalar::U64(_) => "u64",
            Scalar::F16(_) => "f16",
            Scalar::F32(_) => "f32",
            Scalar::Hash32(_) => "hash32",
            Scalar::Hash64(_) => "hash64",
            Scalar::Vector { count: 3, .. } => "vec3",
            Scalar::Vector { .. } => "vec4",
        }
    }

    /// The 32-bit word behind a hash value.
    pub fn hash32(&self) -> Option<u32> {
        match *self {
            Scalar::Hash32(value) => Some(value),
            _ => None,
        }
    }
}

/// Where a reference points, when the target is a whole record of a block
/// whose type is one structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// The block, counted from one as the reference stores it.
    pub block: u32,
    /// The record's index in that block.
    pub record: u32,
    /// The record's byte offset in the block.
    pub offset: u32,
    /// The structure the target block holds.
    pub structure: u32,
}

/// Why a reference could not be bound to a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceFault {
    /// The block number is outside the block table.
    BlockOutside,
    /// The target block's type names no single structure.
    NoStructure,
    /// The offset is not a whole multiple of the structure's size, or the
    /// record it names runs past the block.
    NotARecord,
}

impl ReferenceFault {
    pub fn text(self) -> &'static str {
        match self {
            ReferenceFault::BlockOutside => "the reference names a block that does not exist",
            ReferenceFault::NoStructure => "the target block's type names no single structure",
            ReferenceFault::NotARecord => "the reference names no whole record of the target block",
        }
    }
}

/// One 64-bit reference word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reference {
    pub word: u64,
    /// `None` for the null reference and for a word that binds to no record.
    pub target: Option<Target>,
    pub fault: Option<ReferenceFault>,
}

impl Reference {
    pub fn is_null(&self) -> bool {
        self.word == 0
    }
}

/// A block and a byte range in it, without requiring the block to hold records.
/// Arrays, maps and pools name their target this way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    /// The block, counted from one as the reference stores it.
    pub block: u32,
    /// The byte offset in the block.
    pub offset: u32,
    /// The block's byte length.
    pub len: u32,
}

/// Where a `u64` word points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The word is zero.
    Null,
    Located(Location),
    Fault(ReferenceFault),
}

/// The header of an array or a map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub word: u64,
    pub resolution: Resolution,
    pub count: u32,
    /// The second length word. Equal to `count` in every observed container.
    pub capacity: u32,
    /// The word after the lengths. Zero in every observed container.
    pub tail: u32,
}

/// One element of a structure array: a whole record, not expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordLink {
    pub index: u32,
    pub target: Target,
}

/// What an array's elements are.
#[derive(Debug, Clone, PartialEq)]
pub enum ArrayElements {
    Structure {
        structure: u32,
        stride: u32,
        links: Vec<RecordLink>,
    },
    Reference {
        links: Vec<Reference>,
    },
    Hash32 {
        values: Vec<u32>,
    },
    Enum32 {
        enumeration: u32,
        values: Vec<u32>,
    },
}

/// One array and what it resolved to.
#[derive(Debug, Clone, PartialEq)]
pub struct ArrayValue {
    pub span: Span,
    /// The index of the element descriptor in the owning structure's fields.
    pub descriptor: u16,
    pub elements: Result<ArrayElements, String>,
}

/// A map and the entry records its reference points at.
#[derive(Debug, Clone, PartialEq)]
pub struct MapValue {
    pub span: Span,
    /// The index of the key descriptor in the owning structure's fields.
    pub key_descriptor: u16,
    /// The index of the value descriptor.
    pub value_descriptor: u16,
    /// The entry structure and its records, or why they could not be read.
    pub entries: Result<(u32, Vec<Record>), String>,
}

/// One bit set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bitset {
    /// The first 8 bytes, which hold the bits.
    pub bits: u64,
    /// The declared bit count, when the type word states one.
    pub bit_count: Option<u16>,
    pub enumeration: u32,
}

/// A value whose type names an enum the table defines.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumValueMatch {
    pub value: u32,
    pub enumeration: u32,
    /// The members whose stored value equals `value`.
    pub matches: Vec<EnumValue>,
    /// Whether the table defines the enum at all.
    pub defined: bool,
}

/// A field's value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Scalar(Scalar),
    Enum(EnumValueMatch),
    Structure(Box<Record>),
    Reference(Reference),
    Array(ArrayValue),
    Map(Box<MapValue>),
    Bitset(Bitset),
    /// A text field: 16 bytes whose text storage is not established.
    TextSlot { raw: [u8; 16] },
    /// An array or map element, key or value descriptor. It describes the
    /// element's type and occupies no storage.
    Descriptor {
        code: u16,
        upper: u16,
        auxiliary: u32,
    },
    /// A field whose type has no established width. The bytes of the storage
    /// the schema implies are kept.
    Unresolved {
        code: u16,
        upper: u16,
        auxiliary: u32,
        raw: Vec<u8>,
    },
}

impl Value {
    /// `scalar`, `enum`, `structure`, `reference`, `array`, `map`, `bitset`,
    /// `text_slot`, `descriptor` or `unresolved`.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Scalar(_) => "scalar",
            Value::Enum(_) => "enum",
            Value::Structure(_) => "structure",
            Value::Reference(_) => "reference",
            Value::Array(_) => "array",
            Value::Map(_) => "map",
            Value::Bitset(_) => "bitset",
            Value::TextSlot { .. } => "text_slot",
            Value::Descriptor { .. } => "descriptor",
            Value::Unresolved { .. } => "unresolved",
        }
    }
}

/// One field of one record.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldValue {
    pub field: Field,
    /// The storage the schema implies: from this field's offset to the next
    /// named field's.
    pub extent: Option<u32>,
    pub value: Value,
}

/// One record of a structure block.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// The record's byte offset in the container.
    pub offset: u32,
    pub structure: u32,
    pub fields: Vec<FieldValue>,
}

impl Record {
    /// The field with `name`, if the record has one.
    pub fn field(&self, name: u32) -> Option<&FieldValue> {
        self.fields.iter().find(|value| value.field.name == name)
    }
}

/// One element of a value pool.
#[derive(Debug, Clone, PartialEq)]
pub enum PoolEntry {
    Text(String),
    Hash32(u32),
    Reference(u64),
    Word64(u64),
    Word128([u8; 16]),
}

/// A block's contents.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// Records of the structure the block's type names.
    Records {
        structure: u32,
        stride: u32,
        /// The records the block holds, and the ones that were decoded.
        total: u32,
        records: Vec<Record>,
    },
    Pool {
        kind: PoolKind,
        /// The elements the block holds, and the ones that were decoded.
        total: u32,
        entries: Vec<PoolEntry>,
    },
    /// The type names no structure and no known pool, or the block cannot be
    /// divided into records of its structure.
    Unsupported(String),
}

/// One instance block.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    /// The block number a reference stores: counted from one.
    pub index: u32,
    /// The type word from the block table.
    pub id: u32,
    /// The block's byte offset in the container.
    pub offset: u32,
    pub len: u32,
    pub content: Content,
}

/// The metadata resource header the `LRSC` section copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The object type byte after `0DRP`. `0x7a` in every observed container.
    pub object_type: u8,
    /// The number of root objects the resource declares.
    pub roots: u32,
    pub structures: u16,
    pub enums: u16,
    pub blocks: u16,
}

/// A decoded container.
#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    pub structures: Vec<Structure>,
    pub enums: Vec<Enumeration>,
    pub blocks: Vec<Block>,
    pub header: Option<Header>,
    /// What does not add up and what was not decoded.
    pub issues: Vec<String>,
}

impl Document {
    /// The structures no other structure embeds, in table order.
    pub fn roots(&self) -> Vec<u32> {
        let embedded: HashMap<u32, ()> = self
            .structures
            .iter()
            .flat_map(|structure| structure.fields.iter())
            .filter(|field| field.code() == TYPE_STRUCTURE)
            .map(|field| (field.auxiliary, ()))
            .collect();
        self.structures
            .iter()
            .map(|structure| structure.name)
            .filter(|name| !embedded.contains_key(name))
            .collect()
    }

    /// The structure the schema defines once under `name`, if it does.
    pub fn structure(&self, name: u32) -> Option<&Structure> {
        unique(&self.structures, name, |structure| structure.name)
    }

    /// The enumeration the table defines once under `name`, if it does.
    pub fn enumeration(&self, name: u32) -> Option<&Enumeration> {
        unique(&self.enums, name, |enumeration| enumeration.name)
    }

    /// Every structure defined under `name`.
    pub fn structures_named(&self, name: u32) -> impl Iterator<Item = &Structure> {
        self.structures
            .iter()
            .filter(move |structure| structure.name == name)
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

    /// Whether the copied header's counts match the decoded tables.
    pub fn header_matches(&self) -> Option<bool> {
        let header = self.header?;
        Some(
            usize::from(header.structures) == self.structures.len()
                && usize::from(header.enums) == self.enums.len()
                && usize::from(header.blocks) == self.blocks.len(),
        )
    }

    fn block(&self, number: u32) -> Option<&Block> {
        self.blocks.get(number.checked_sub(1)? as usize)
    }
}

fn unique<T>(items: &[T], name: u32, key: impl Fn(&T) -> u32) -> Option<&T> {
    let mut found = items.iter().filter(|item| key(item) == name);
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

/// Reads `payload` as an `LSCH`-family container.
pub fn decode(payload: &[u8]) -> Result<Document, Error> {
    decode_with(payload, Limits::default())
}

/// Reads `payload` under explicit read limits.
pub fn decode_with(payload: &[u8], limits: Limits) -> Result<Document, Error> {
    if !super::is_psin(payload) {
        return Err(Error::NotPsin);
    }
    let report = parse_framing(payload)?;
    if report.family != Family::Lsch {
        return Err(Error::Unsupported {
            family: report.family.name(),
            first_tag: report
                .sections
                .first()
                .map(|section| section.tag_text())
                .unwrap_or_default(),
        });
    }
    let body_len = report.first_offset as usize;
    if body_len > payload.len() {
        return Err(malformed("the PSIN section runs past the payload"));
    }
    let table = report
        .descriptors
        .as_ref()
        .ok_or_else(|| malformed("the block table does not solve"))?;
    if usize::from(table.count) == 0 || table.descriptors.len() != usize::from(table.count) {
        return Err(malformed(format!(
            "{} block counts fit the table, so the block layout is ambiguous",
            table.candidates.len()
        )));
    }

    let structures = read_section(&report.sections, b"LSCH")
        .map(|section| read_structures(payload, section))
        .transpose()?
        .unwrap_or_default();
    let enums = read_section(&report.sections, b"LENM")
        .map(|section| read_enumerations(payload, section))
        .transpose()?
        .unwrap_or_default();
    let header = read_section(&report.sections, b"LRSC")
        .map(|section| read_header(payload, section))
        .transpose()?
        .flatten();

    let mut issues = Vec::new();
    let mut layout = Vec::with_capacity(table.descriptors.len());
    let mut at = DATA_AREA_START
        .checked_add(table.descriptors.len() * BLOCK_RECORD_LEN)
        .ok_or_else(|| malformed("the block table is too long"))?;
    for (position, descriptor) in table.descriptors.iter().enumerate() {
        let len = descriptor.len as usize;
        let end = at
            .checked_add(len)
            .ok_or_else(|| malformed("a block length overflows"))?;
        if end > body_len {
            return Err(malformed(format!(
                "block {} spans {at:#x}..{end:#x}, past the PSIN section's {body_len:#x} bytes",
                position + 1
            )));
        }
        let padded = end
            .checked_add(15)
            .map(|value| value & !15)
            .ok_or_else(|| malformed("a block offset overflows"))?;
        if padded > body_len {
            return Err(malformed(format!(
                "block {} ends at {end:#x} and its alignment padding passes the section",
                position + 1
            )));
        }
        if payload[end..padded].iter().any(|&byte| byte != 0) {
            issues.push(format!(
                "the alignment padding after block {} is not zero",
                position + 1
            ));
        }
        layout.push((position as u32 + 1, descriptor.word, at as u32, descriptor.len));
        at = padded;
    }
    if at != body_len {
        return Err(malformed(format!(
            "the blocks end at {at:#x}, not at the PSIN section's {body_len:#x} bytes"
        )));
    }

    let mut document = Document {
        structures,
        enums,
        // Every block is described before any of them is decoded, because a
        // reference may name a block that comes later.
        blocks: layout
            .iter()
            .map(|&(index, id, offset, len)| Block {
                index,
                id,
                offset,
                len,
                content: Content::Unsupported("not decoded".into()),
            })
            .collect(),
        header,
        issues,
    };
    let mut budget = Budget {
        limits,
        nodes: 0,
        truncated: Vec::new(),
    };
    let mut contents = Vec::with_capacity(document.blocks.len());
    for block in &document.blocks {
        contents.push(read_block(
            payload,
            &document,
            block.id,
            block.offset,
            block.len,
            &mut budget,
        )?);
    }
    for (block, content) in document.blocks.iter_mut().zip(contents) {
        block.content = content;
    }
    document.issues.append(&mut budget.truncated);
    if document.header_matches() == Some(false) {
        let header = document.header.expect("checked");
        document.issues.push(format!(
            "the copied resource header counts {} structures, {} enums and {} blocks; the container holds {} structures, {} enums and {} blocks",
            header.structures,
            header.enums,
            header.blocks,
            document.structures.len(),
            document.enums.len(),
            document.blocks.len()
        ));
    }
    Ok(document)
}

fn read_section(sections: &[Section], tag: &[u8; 4]) -> Option<Section> {
    sections.iter().find(|section| &section.tag == tag).copied()
}

fn body(payload: &[u8], section: Section) -> Result<&[u8], Error> {
    let start = section.offset as usize + 8;
    let end = start
        .checked_add(section.body_len() as usize)
        .ok_or_else(|| malformed("a section length overflows"))?;
    payload.get(start..end).ok_or_else(|| {
        malformed(format!(
            "the {} section runs past the payload",
            section.tag_text()
        ))
    })
}

fn read_structures(payload: &[u8], section: Section) -> Result<Vec<Structure>, Error> {
    let body = body(payload, section)?;
    let mut headers = Vec::new();
    let mut at = 0usize;
    let mut accounted = 0usize;
    while accounted < body.len() {
        let record = body
            .get(at..at + STRUCTURE_LEN)
            .ok_or_else(|| malformed(format!("the structure record at {at:#x} is truncated")))?;
        if record[16..24] != STRUCTURE_MARKER {
            return Err(malformed(format!(
                "the structure record at {at:#x} has no 0xAA marker"
            )));
        }
        let count = u16::from_le_bytes(record[30..32].try_into().expect("2 bytes"));
        accounted = accounted
            .checked_add(STRUCTURE_LEN + FIELD_LEN * usize::from(count))
            .ok_or_else(|| malformed("the field counts overflow"))?;
        if accounted > body.len() {
            return Err(malformed(format!(
                "the structure at {at:#x} declares {count} fields, past the schema's {} bytes",
                body.len()
            )));
        }
        if headers.len() >= MAX_STRUCTURES {
            return Err(Error::Limit(format!(
                "the schema declares more than {MAX_STRUCTURES} structures"
            )));
        }
        headers.push((
            u32::from_le_bytes(record[0..4].try_into().expect("4 bytes")),
            u32::from_le_bytes(record[4..8].try_into().expect("4 bytes")),
            u32::from_le_bytes(record[8..12].try_into().expect("4 bytes")),
            u32::from_le_bytes(record[24..28].try_into().expect("4 bytes")),
            count,
        ));
        at += STRUCTURE_LEN;
    }
    if accounted != body.len() {
        return Err(malformed("the structure records do not cover the schema"));
    }
    let mut structures = Vec::with_capacity(headers.len());
    let mut total = 0usize;
    for (name, signature, flags, size, count) in headers {
        total = total
            .checked_add(usize::from(count))
            .ok_or_else(|| malformed("the field counts overflow"))?;
        if total > MAX_FIELDS {
            return Err(Error::Limit(format!(
                "the schema declares more than {MAX_FIELDS} fields"
            )));
        }
        let mut fields = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let record = body
                .get(at..at + FIELD_LEN)
                .ok_or_else(|| malformed(format!("the field record at {at:#x} is truncated")))?;
            fields.push(Field {
                name: u32::from_le_bytes(record[0..4].try_into().expect("4 bytes")),
                offset: u32::from_le_bytes(record[4..8].try_into().expect("4 bytes")),
                type_word: u32::from_le_bytes(record[8..12].try_into().expect("4 bytes")),
                auxiliary: u32::from_le_bytes(record[12..16].try_into().expect("4 bytes")),
            });
            at += FIELD_LEN;
        }
        structures.push(Structure {
            name,
            signature,
            flags,
            size,
            fields,
        });
    }
    if at != body.len() {
        return Err(malformed("bytes follow the field records"));
    }
    Ok(structures)
}

fn read_enumerations(payload: &[u8], section: Section) -> Result<Vec<Enumeration>, Error> {
    let body = body(payload, section)?;
    let mut headers = Vec::new();
    let mut at = 0usize;
    let mut accounted = 0usize;
    while accounted < body.len() {
        let record = body
            .get(at..at + ENUM_LEN)
            .ok_or_else(|| malformed(format!("the enum record at {at:#x} is truncated")))?;
        if record[8..16] != ENUM_MARKER {
            return Err(malformed(format!(
                "the enum record at {at:#x} has no 0xEE marker"
            )));
        }
        let count = u32::from_le_bytes(record[16..20].try_into().expect("4 bytes"));
        accounted = accounted
            .checked_add(ENUM_LEN + ENUM_VALUE_LEN * count as usize)
            .ok_or_else(|| malformed("the enum value counts overflow"))?;
        if accounted > body.len() {
            return Err(malformed(format!(
                "the enum at {at:#x} declares {count} values, past the table's {} bytes",
                body.len()
            )));
        }
        if headers.len() >= MAX_ENUMS {
            return Err(Error::Limit(format!(
                "the table declares more than {MAX_ENUMS} enums"
            )));
        }
        headers.push((
            u32::from_le_bytes(record[0..4].try_into().expect("4 bytes")),
            u32::from_le_bytes(record[4..8].try_into().expect("4 bytes")),
            count,
        ));
        at += ENUM_LEN;
    }
    if accounted != body.len() {
        return Err(malformed("the enum records do not cover the table"));
    }
    let mut enums = Vec::with_capacity(headers.len());
    let mut total = 0usize;
    for (name, signature, count) in headers {
        total = total
            .checked_add(count as usize)
            .ok_or_else(|| malformed("the enum value counts overflow"))?;
        if total > MAX_ENUM_VALUES {
            return Err(Error::Limit(format!(
                "the table declares more than {MAX_ENUM_VALUES} enum values"
            )));
        }
        let mut values = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let record = body
                .get(at..at + ENUM_VALUE_LEN)
                .ok_or_else(|| malformed(format!("the enum value at {at:#x} is truncated")))?;
            values.push(EnumValue {
                value: u64::from_le_bytes(record[0..8].try_into().expect("8 bytes")),
                name: u32::from_le_bytes(record[8..12].try_into().expect("4 bytes")),
            });
            at += ENUM_VALUE_LEN;
        }
        enums.push(Enumeration {
            name,
            signature,
            values,
        });
    }
    if at != body.len() {
        return Err(malformed("bytes follow the enum values"));
    }
    Ok(enums)
}

fn read_header(payload: &[u8], section: Section) -> Result<Option<Header>, Error> {
    let body = body(payload, section)?;
    if body.len() < 0x40 || &body[0..4] != b"0DRP" {
        return Ok(None);
    }
    Ok(Some(Header {
        object_type: body[4],
        roots: u32::from_le_bytes(body[0x10..0x14].try_into().expect("4 bytes")),
        structures: u16::from_le_bytes(body[0x38..0x3a].try_into().expect("2 bytes")),
        enums: u16::from_le_bytes(body[0x3a..0x3c].try_into().expect("2 bytes")),
        blocks: u16::from_le_bytes(body[0x3c..0x3e].try_into().expect("2 bytes")),
    }))
}

/// Counts the values emitted so far and stops a document that would exceed its
/// limits.
struct Budget {
    limits: Limits,
    nodes: usize,
    truncated: Vec<String>,
}

impl Budget {
    fn spend(&mut self, amount: usize) -> Result<(), Error> {
        self.nodes = self
            .nodes
            .checked_add(amount)
            .ok_or_else(|| Error::Limit("the value count overflows".into()))?;
        if self.nodes > self.limits.nodes {
            return Err(Error::Limit(format!(
                "the container needs more than {} values",
                self.limits.nodes
            )));
        }
        Ok(())
    }

    fn note_truncated(&mut self, what: String) {
        self.truncated.push(what);
    }
}

fn read_block(
    payload: &[u8],
    document: &Document,
    id: u32,
    offset: u32,
    len: u32,
    budget: &mut Budget,
) -> Result<Content, Error> {
    let start = offset as usize;
    let bytes = payload
        .get(start..start + len as usize)
        .ok_or_else(|| malformed(format!("the block at {offset:#x} runs past the payload")))?;
    if let Some(structure) = document.structure(id) {
        if structure.size == 0 {
            return Ok(Content::Unsupported(
                "the structure's record size is zero".into(),
            ));
        }
        if !len.is_multiple_of(structure.size) {
            return Ok(Content::Unsupported(format!(
                "the block's {len} bytes are not a whole number of {} byte records",
                structure.size
            )));
        }
        let total = len / structure.size;
        let decoded = total.min(budget.limits.records as u32);
        budget.spend(decoded as usize)?;
        if decoded < total {
            budget.note_truncated(format!(
                "block {id:#010x} holds {total} records; the first {decoded} were decoded"
            ));
        }
        let mut records = Vec::with_capacity(decoded as usize);
        for index in 0..decoded {
            let record_at = offset + index * structure.size;
            records.push(read_record(
                payload,
                document,
                structure,
                record_at,
                budget,
                &mut Vec::new(),
                0,
            )?);
        }
        return Ok(Content::Records {
            structure: structure.name,
            stride: structure.size,
            total,
            records,
        });
    }
    let Some(kind) = PoolKind::of(id) else {
        return Ok(Content::Unsupported(format!(
            "no structure and no known pool has the type {id:#010x}"
        )));
    };
    reader_pool(bytes, kind, budget).map(|(total, entries)| Content::Pool {
        kind,
        total,
        entries,
    })
}

fn reader_pool(
    bytes: &[u8],
    kind: PoolKind,
    budget: &mut Budget,
) -> Result<(u32, Vec<PoolEntry>), Error> {
    if kind == PoolKind::Text {
        if bytes.is_empty() {
            return Ok((0, Vec::new()));
        }
        let text = bytes[bytes.len() - 1] == 0
            && bytes
                .iter()
                .all(|&byte| byte == 0 || (0x20..0x7f).contains(&byte));
        if !text {
            return Ok((0, Vec::new()));
        }
        let pieces: Vec<&[u8]> = bytes.split(|&byte| byte == 0).collect();
        // The final NUL leaves one empty piece.
        let total = pieces.len() - 1;
        let count = total.min(budget.limits.elements);
        budget.spend(count)?;
        if count < total {
            budget.note_truncated(format!(
                "a text pool holds {total} entries; the first {count} were decoded"
            ));
        }
        let entries = pieces
            .iter()
            .take(count)
            .map(|piece| PoolEntry::Text(String::from_utf8_lossy(piece).into_owned()))
            .collect();
        return Ok((total as u32, entries));
    }
    let stride = kind.stride().expect("a sized pool has a stride");
    if !bytes.len().is_multiple_of(stride) {
        return Ok((0, Vec::new()));
    }
    let total = bytes.len() / stride;
    let count = total.min(budget.limits.elements);
    budget.spend(count)?;
    if count < total {
        budget.note_truncated(format!(
            "a {} pool holds {total} entries; the first {count} were decoded",
            kind.name()
        ));
    }
    let mut entries = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(stride).take(count) {
        entries.push(match kind {
            PoolKind::Hash32 => {
                PoolEntry::Hash32(u32::from_le_bytes(chunk.try_into().expect("4 bytes")))
            }
            PoolKind::Word32 => PoolEntry::Word64(u64::from(u32::from_le_bytes(
                chunk.try_into().expect("4 bytes"),
            ))),
            PoolKind::Reference64 => {
                PoolEntry::Reference(u64::from_le_bytes(chunk.try_into().expect("8 bytes")))
            }
            PoolKind::Word64 => {
                PoolEntry::Word64(u64::from_le_bytes(chunk.try_into().expect("8 bytes")))
            }
            PoolKind::Word128 => PoolEntry::Word128(chunk.try_into().expect("16 bytes")),
            PoolKind::Text => unreachable!("handled above"),
        });
    }
    Ok((total as u32, entries))
}

fn read_record(
    payload: &[u8],
    document: &Document,
    structure: &Structure,
    at: u32,
    budget: &mut Budget,
    active: &mut Vec<(u32, u32)>,
    depth: usize,
) -> Result<Record, Error> {
    let end = at
        .checked_add(structure.size)
        .ok_or_else(|| malformed("a record offset overflows"))?;
    if payload.get(at as usize..end as usize).is_none() {
        return Err(malformed(format!(
            "the record at {at:#x} runs past the container"
        )));
    }
    if depth > budget.limits.depth {
        return Err(Error::Limit(format!(
            "structures nest deeper than {} levels",
            budget.limits.depth
        )));
    }
    if active.contains(&(structure.name, at)) {
        return Err(malformed(format!(
            "the structure at {at:#x} embeds itself"
        )));
    }
    active.push((structure.name, at));
    let mut fields = Vec::with_capacity(structure.fields.len());
    for field in &structure.fields {
        let extent = structure.extent(field);
        let value = read_value(payload, document, structure, field, at, budget, active, depth)?;
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

#[allow(clippy::too_many_arguments)]
fn read_value(
    payload: &[u8],
    document: &Document,
    structure: &Structure,
    field: &Field,
    record_at: u32,
    budget: &mut Budget,
    active: &mut Vec<(u32, u32)>,
    depth: usize,
) -> Result<Value, Error> {
    let start = record_at
        .checked_add(field.offset)
        .ok_or_else(|| malformed("a field offset overflows"))?;
    let code = field.code();
    let unresolved = |width: usize| -> Value {
        let end = (start as usize).saturating_add(width.min(structure.size as usize));
        Value::Unresolved {
            code,
            upper: field.upper(),
            auxiliary: field.auxiliary,
            raw: payload.get(start as usize..end).unwrap_or_default().to_vec(),
        }
    };
    if field.is_descriptor() {
        return Ok(Value::Descriptor {
            code,
            upper: field.upper(),
            auxiliary: field.auxiliary,
        });
    }
    // A type with no established width still reports the bytes its extent
    // implies.
    let unknown_type = || {
        let width = field
            .width()
            .or_else(|| structure.extent(field))
            .unwrap_or(0) as usize;
        unresolved(width)
    };
    match code {
        TYPE_STRUCTURE => {
            let Some(target) = document.structure(field.auxiliary) else {
                return Ok(unknown_type());
            };
            if target.size == 0 {
                return Ok(unknown_type());
            }
            let record = read_record(payload, document, target, start, budget, active, depth + 1)?;
            Ok(Value::Structure(Box::new(record)))
        }
        TYPE_REFERENCE => match read_u64(payload, start) {
            Some(raw) => Ok(Value::Reference(bind_reference(document, raw))),
            None => Ok(unresolved(8)),
        },
        TYPE_ARRAY | TYPE_ARRAY_LENGTH_FIRST | TYPE_MAP | TYPE_MAP_LENGTH_FIRST => {
            match read_span(payload, start, code) {
                Some(words) if matches!(code, TYPE_ARRAY | TYPE_ARRAY_LENGTH_FIRST) => Ok(
                    Value::Array(read_array(payload, document, structure, field, words, budget)),
                ),
                Some(words) => Ok(Value::Map(Box::new(read_map(
                    payload, document, field, words, budget,
                )))),
                None => Ok(unresolved(field.width().unwrap_or(0) as usize)),
            }
        }
        TYPE_BITSET => match read_u64(payload, start) {
            Some(bits) => Ok(Value::Bitset(Bitset {
                bits,
                bit_count: match field.upper() {
                    0 => None,
                    count => Some(count),
                },
                enumeration: field.auxiliary,
            })),
            None => Ok(unresolved(16)),
        },
        TYPE_STRING => match payload.get(start as usize..start as usize + 16) {
            Some(bytes) => Ok(Value::TextSlot {
                raw: bytes.try_into().expect("16 bytes"),
            }),
            None => Ok(unresolved(16)),
        },
        TYPE_INLINE_ARRAY => read_inline_array(payload, document, structure, field, start, budget),
        TYPE_ENUM8 | TYPE_ENUM32 => {
            let width = type_width(code, field.upper()).expect("enum width") as usize;
            match payload.get(start as usize..start as usize + width) {
                Some(bytes) => {
                    let value = if width == 1 {
                        u32::from(bytes[0])
                    } else {
                        u32::from_le_bytes(bytes.try_into().expect("4 bytes"))
                    };
                    Ok(Value::Enum(enum_match(document, field.auxiliary, value)))
                }
                None => Ok(unresolved(width)),
            }
        }
        _ => match read_scalar(payload, start, code, field.upper()) {
            Some(scalar) => Ok(Value::Scalar(scalar)),
            None => Ok(unknown_type()),
        },
    }
}

fn enum_match(document: &Document, enumeration: u32, value: u32) -> EnumValueMatch {
    let Some(table) = document.enumeration(enumeration) else {
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

fn read_u64(payload: &[u8], at: u32) -> Option<u64> {
    let bytes = payload.get(at as usize..at as usize + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn read_scalar(payload: &[u8], at: u32, code: u16, upper: u16) -> Option<Scalar> {
    let start = at as usize;
    Some(match code {
        TYPE_BOOL => Scalar::Bool(match *payload.get(start)? {
            0 => false,
            1 => true,
            _ => return None,
        }),
        TYPE_I8 => Scalar::I8(*payload.get(start)? as i8),
        TYPE_U8 => Scalar::U8(*payload.get(start)?),
        TYPE_I16 => Scalar::I16(i16::from_le_bytes(read(payload, start)?)),
        TYPE_U16 => Scalar::U16(u16::from_le_bytes(read(payload, start)?)),
        TYPE_U32 => Scalar::U32(u32::from_le_bytes(read(payload, start)?)),
        TYPE_I32 => Scalar::I32(i32::from_le_bytes(read(payload, start)?)),
        TYPE_U64 => Scalar::U64(u64::from_le_bytes(read(payload, start)?)),
        TYPE_F16 => Scalar::F16(half_to_f32(u16::from_le_bytes(read(payload, start)?))),
        TYPE_F32 => Scalar::F32(f32::from_le_bytes(read(payload, start)?)),
        TYPE_HASH32 => Scalar::Hash32(u32::from_le_bytes(read(payload, start)?)),
        TYPE_HASH64 => Scalar::Hash64(u64::from_le_bytes(read(payload, start)?)),
        // Only the sub-type the research establishes as 64-bit is read.
        TYPE_ID64 if upper == 5 => Scalar::Hash64(u64::from_le_bytes(read(payload, start)?)),
        TYPE_VEC3_12 => Scalar::Vector {
            values: [
                f32::from_le_bytes(read(payload, start)?),
                f32::from_le_bytes(read(payload, start + 4)?),
                f32::from_le_bytes(read(payload, start + 8)?),
                0.0,
            ],
            count: 3,
        },
        TYPE_VEC3_16 | TYPE_VEC4 => Scalar::Vector {
            values: [
                f32::from_le_bytes(read(payload, start)?),
                f32::from_le_bytes(read(payload, start + 4)?),
                f32::from_le_bytes(read(payload, start + 8)?),
                f32::from_le_bytes(read(payload, start + 12)?),
            ],
            count: 4,
        },
        _ => return None,
    })
}

fn read<const N: usize>(payload: &[u8], at: usize) -> Option<[u8; N]> {
    payload.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// IEEE 754 binary16 to binary32.
pub fn half_to_f32(bits: u16) -> f32 {
    let sign = u32::from(bits >> 15) << 31;
    let exponent = u32::from((bits >> 10) & 0x1f);
    let mantissa = u32::from(bits & 0x3ff);
    let value = match exponent {
        0 if mantissa == 0 => sign,
        // Subnormal: normalize the mantissa.
        0 => {
            let mut mantissa = mantissa;
            let mut shift = 0u32;
            while mantissa & 0x400 == 0 {
                mantissa <<= 1;
                shift += 1;
            }
            let exponent = 127u32.saturating_sub(14 + shift);
            sign | (exponent << 23) | ((mantissa & 0x3ff) << 13)
        }
        0x1f => sign | 0x7f80_0000 | (mantissa << 13),
        _ => sign | ((exponent + 127 - 15) << 23) | (mantissa << 13),
    };
    f32::from_bits(value)
}

fn bind_reference(document: &Document, word: u64) -> Reference {
    let fault = |fault| Reference {
        word,
        target: None,
        fault: Some(fault),
    };
    if word == 0 {
        return Reference {
            word,
            target: None,
            fault: None,
        };
    }
    let number = (word & 0xf_ffff) as u32;
    let offset = (word >> 20) as u32;
    let Some(block) = document.block(number) else {
        return fault(ReferenceFault::BlockOutside);
    };
    let Some(structure) = document.structure(block.id) else {
        return fault(ReferenceFault::NoStructure);
    };
    if structure.size == 0
        || !offset.is_multiple_of(structure.size)
        || offset
            .checked_add(structure.size)
            .is_none_or(|end| end > block.len)
    {
        return fault(ReferenceFault::NotARecord);
    }
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

#[derive(Debug, Clone, Copy)]
struct HeaderWords {
    reference: u64,
    count: u16,
    capacity: u16,
    tail: u32,
}

fn read_span(payload: &[u8], at: u32, code: u16) -> Option<HeaderWords> {
    let start = at as usize;
    let width = type_width(code, 0)? as usize;
    let bytes = payload.get(start..start + width)?;
    Some(match code {
        TYPE_MAP_LENGTH_FIRST | TYPE_ARRAY_LENGTH_FIRST => HeaderWords {
            count: u16::from_le_bytes(bytes[0..2].try_into().ok()?),
            capacity: u16::from_le_bytes(bytes[2..4].try_into().ok()?),
            reference: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
            tail: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
        },
        TYPE_MAP => {
            if u64::from_le_bytes(bytes[0..8].try_into().ok()?) != 1 {
                return None;
            }
            HeaderWords {
                reference: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
                count: u16::from_le_bytes(bytes[16..18].try_into().ok()?),
                capacity: u16::from_le_bytes(bytes[18..20].try_into().ok()?),
                tail: u32::from_le_bytes(bytes[20..24].try_into().ok()?),
            }
        }
        _ => HeaderWords {
            reference: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            count: u16::from_le_bytes(bytes[8..10].try_into().ok()?),
            capacity: u16::from_le_bytes(bytes[10..12].try_into().ok()?),
            tail: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
        },
    })
}

/// Resolves a word to a block and a byte offset, whatever the block holds.
fn resolve_location(document: &Document, word: u64) -> Resolution {
    if word == 0 {
        return Resolution::Null;
    }
    let number = (word & 0xf_ffff) as u32;
    let offset = (word >> 20) as u32;
    let Some(block) = document.block(number) else {
        return Resolution::Fault(ReferenceFault::BlockOutside);
    };
    if offset > block.len {
        return Resolution::Fault(ReferenceFault::NotARecord);
    }
    Resolution::Located(Location {
        block: number,
        offset,
        len: block.len,
    })
}

fn span(document: &Document, words: HeaderWords) -> Span {
    Span {
        word: words.reference,
        resolution: resolve_location(document, words.reference),
        count: u32::from(words.count),
        capacity: u32::from(words.capacity),
        tail: words.tail,
    }
}

/// The target a span names, or why it names none.
fn spanned(span: Span) -> Result<Location, String> {
    match span.resolution {
        Resolution::Null => Err("the reference is null".to_string()),
        Resolution::Fault(fault) => Err(fault.text().to_string()),
        Resolution::Located(location) => Ok(location),
    }
}

fn read_array(
    payload: &[u8],
    document: &Document,
    structure: &Structure,
    field: &Field,
    words: HeaderWords,
    budget: &mut Budget,
) -> ArrayValue {
    let header = span(document, words);
    let elements = resolve_array(payload, document, structure, field, header, budget);
    ArrayValue {
        span: header,
        descriptor: field.upper(),
        elements,
    }
}

fn resolve_array(
    payload: &[u8],
    document: &Document,
    structure: &Structure,
    field: &Field,
    header: Span,
    budget: &mut Budget,
) -> Result<ArrayElements, String> {
    if header.count != header.capacity {
        return Err(format!(
            "the array's {} length and {} capacity words differ",
            header.count, header.capacity
        ));
    }
    if header.tail != 0 {
        return Err(format!("the array's trailing word is {:#x}", header.tail));
    }
    let descriptor = structure
        .fields
        .get(usize::from(field.upper()))
        .filter(|descriptor| descriptor.is_descriptor())
        .ok_or_else(|| format!("field {} is not an element descriptor", field.upper()))?;
    let code = descriptor.code();
    if header.count == 0 {
        return Ok(match code {
            TYPE_STRUCTURE => ArrayElements::Structure {
                structure: descriptor.auxiliary,
                stride: document
                    .structure(descriptor.auxiliary)
                    .map_or(0, |target| target.size),
                links: Vec::new(),
            },
            TYPE_REFERENCE => ArrayElements::Reference { links: Vec::new() },
            TYPE_HASH32 => ArrayElements::Hash32 { values: Vec::new() },
            TYPE_ENUM32 => ArrayElements::Enum32 {
                enumeration: descriptor.auxiliary,
                values: Vec::new(),
            },
            code => {
                return Err(format!(
                    "the element descriptor's type {code:#x} is not decoded"
                ));
            }
        });
    }
    let location = spanned(header)?;
    let block = document
        .block(location.block)
        .ok_or_else(|| "the array's block does not exist".to_string())?;
    let bytes = payload
        .get(block.offset as usize..block.offset as usize + block.len as usize)
        .ok_or_else(|| "the array's block runs past the container".to_string())?;
    let start = location.offset as usize;
    let wanted = header.count as usize;
    // The element descriptor must name the type the target block holds, and
    // the target must be long enough for the elements it names.
    match code {
        TYPE_STRUCTURE => {
            let element = document
                .structure(descriptor.auxiliary)
                .ok_or_else(|| "the element descriptor names no single structure".to_string())?;
            if element.size == 0 {
                return Err("the element structure's record size is zero".to_string());
            }
            if element.name != block.id {
                return Err(format!(
                    "the target block holds {:#010x}, not the element structure {:#010x}",
                    block.id, element.name
                ));
            }
            if !start.is_multiple_of(element.size as usize) {
                return Err("the array's offset is not a whole record multiple".to_string());
            }
            let available = (bytes.len() - start) / element.size as usize;
            let count = wanted.min(available).min(budget.limits.elements);
            budget.spend(count).map_err(|err| err.to_string())?;
            if count < wanted {
                budget.note_truncated(format!(
                    "a structure array names {wanted} records; the first {count} were decoded"
                ));
            }
            let first = (start as u32) / element.size;
            let mut links = Vec::with_capacity(count);
            for index in 0..count as u32 {
                links.push(RecordLink {
                    index: first + index,
                    target: Target {
                        block: location.block,
                        record: first + index,
                        offset: (start as u32) + index * element.size,
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
            if PoolKind::of(block.id) != Some(PoolKind::Reference64) {
                return Err("the target block is not a reference pool".to_string());
            }
            if !start.is_multiple_of(8) {
                return Err("the array's offset is not eight-byte aligned".to_string());
            }
            let available = (bytes.len() - start) / 8;
            let count = wanted.min(available).min(budget.limits.elements);
            budget.spend(count).map_err(|err| err.to_string())?;
            let mut links = Vec::with_capacity(count);
            for index in 0..count {
                let at = start + index * 8;
                let word = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
                links.push(bind_reference(document, word));
            }
            Ok(ArrayElements::Reference { links })
        }
        TYPE_HASH32 => {
            if PoolKind::of(block.id) != Some(PoolKind::Hash32) {
                return Err("the target block is not a hash pool".to_string());
            }
            if !start.is_multiple_of(4) {
                return Err("the array's offset is not four-byte aligned".to_string());
            }
            let available = (bytes.len() - start) / 4;
            let count = wanted.min(available).min(budget.limits.elements);
            budget.spend(count).map_err(|err| err.to_string())?;
            Ok(ArrayElements::Hash32 {
                values: read_words(bytes, start, count),
            })
        }
        TYPE_ENUM32 => {
            if PoolKind::of(block.id) != Some(PoolKind::Word32) {
                return Err("the target block is not a 32-bit value pool".to_string());
            }
            if !start.is_multiple_of(4) {
                return Err("the array's offset is not four-byte aligned".to_string());
            }
            let available = (bytes.len() - start) / 4;
            let count = wanted.min(available).min(budget.limits.elements);
            budget.spend(count).map_err(|err| err.to_string())?;
            Ok(ArrayElements::Enum32 {
                enumeration: descriptor.auxiliary,
                values: read_words(bytes, start, count),
            })
        }
        code => Err(format!(
            "the element descriptor's type {code:#x} is not decoded"
        )),
    }
}

fn read_words(bytes: &[u8], start: usize, count: usize) -> Vec<u32> {
    (0..count)
        .map(|index| {
            let at = start + index * 4;
            u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
        })
        .collect()
}

fn read_map(
    payload: &[u8],
    document: &Document,
    field: &Field,
    words: HeaderWords,
    budget: &mut Budget,
) -> MapValue {
    let header = span(document, words);
    let entries = resolve_map(payload, document, header, budget);
    MapValue {
        span: header,
        key_descriptor: (field.auxiliary & 0xffff) as u16,
        value_descriptor: (field.auxiliary >> 16) as u16,
        entries,
    }
}

fn resolve_map(
    payload: &[u8],
    document: &Document,
    header: Span,
    budget: &mut Budget,
) -> Result<(u32, Vec<Record>), String> {
    if header.count != header.capacity {
        return Err(format!(
            "the map's {} length and {} capacity words differ",
            header.count, header.capacity
        ));
    }
    if header.tail != 0 {
        return Err(format!("the map's trailing word is {:#x}", header.tail));
    }
    if header.count == 0 {
        return Ok((0, Vec::new()));
    }
    let location = spanned(header)?;
    let block = document
        .block(location.block)
        .ok_or_else(|| "the map's block does not exist".to_string())?;
    let Some(structure) = document.structure(block.id) else {
        return Err("the map's target names no single structure".to_string());
    };
    if structure.size == 0 {
        return Err("the entry structure's record size is zero".to_string());
    }
    let start = location.offset as usize;
    if !start.is_multiple_of(structure.size as usize) {
        return Err("the map's offset is not a whole record multiple".to_string());
    }
    let wanted = header.count as usize;
    let available = (block.len as usize - start) / structure.size as usize;
    let count = wanted.min(available).min(budget.limits.elements);
    budget.spend(count).map_err(|err| err.to_string())?;
    if count < wanted {
        budget.note_truncated(format!(
            "a map names {wanted} entries; the first {count} were decoded"
        ));
    }
    let mut records = Vec::with_capacity(count);
    for index in 0..count as u32 {
        let record_at = block
            .offset
            .checked_add(location.offset)
            .and_then(|base| base.checked_add(index * structure.size))
            .ok_or_else(|| "the map's record offset overflows".to_string())?;
        records.push(
            read_record(
                payload,
                document,
                structure,
                record_at,
                budget,
                &mut Vec::new(),
                0,
            )
            .map_err(|err| err.to_string())?,
        );
    }
    Ok((structure.name, records))
}

fn read_inline_array(
    payload: &[u8],
    document: &Document,
    structure: &Structure,
    field: &Field,
    start: u32,
    budget: &mut Budget,
) -> Result<Value, Error> {
    let unresolved = |raw: Vec<u8>| Value::Unresolved {
        code: field.code(),
        upper: field.upper(),
        auxiliary: field.auxiliary,
        raw,
    };
    let Some(element) = structure
        .fields
        .get(usize::from(field.upper()))
        .filter(|element| element.is_descriptor())
    else {
        return Ok(unresolved(Vec::new()));
    };
    // The count is the auxiliary word; the stride is the element type's width.
    let Some(stride) = element.width() else {
        return Ok(unresolved(Vec::new()));
    };
    let count = field.auxiliary as usize;
    let Some(bytes) = (stride as usize)
        .checked_mul(count)
        .and_then(|total| payload.get(start as usize..(start as usize).checked_add(total)?))
    else {
        return Ok(unresolved(Vec::new()));
    };
    if element.code() != TYPE_REFERENCE {
        return Ok(unresolved(bytes.to_vec()));
    }
    let count = count.min(budget.limits.elements);
    budget.spend(count)?;
    let mut links = Vec::with_capacity(count);
    for chunk in bytes.as_chunks::<8>().0.iter().take(count) {
        links.push(bind_reference(
            document,
            u64::from_le_bytes(*chunk),
        ));
    }
    Ok(Value::Array(ArrayValue {
        span: Span {
            word: 0,
            resolution: Resolution::Null,
            count: count as u32,
            capacity: count as u32,
            tail: 0,
        },
        descriptor: field.upper(),
        elements: Ok(ArrayElements::Reference { links }),
    }))
}

#[cfg(test)]
mod tests;
