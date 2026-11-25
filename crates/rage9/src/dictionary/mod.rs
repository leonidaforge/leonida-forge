//! Texture dictionaries in a reconstructed resource.
//!
//! The grammar is the one the research read in the type-5 rows of the nested
//! texture archives (RES-F36 to RES-F41): a system segment with a sorted
//! `u32` name-hash array, a parallel value array of record pointers, and
//! `0x70`-byte records. The graphics segment is not parsed; only the
//! allocation extents that the record starts describe.
//!
//! Recognition is structural, so it fails closed: a resource that does not
//! satisfy every step is not a dictionary and the failing step is reported.
//! There is no type ID in the test.
//!
//! Nothing here decodes pixels. Width, height, format id and the mip word are
//! read at confirmed positions and exposed as values; their meanings are
//! probable at best. No texture reference is resolved: a matching name hash
//! only shares a namespace.

#[cfg(test)]
mod tests;

use std::fmt;

use super::resource::Pointer;
use super::rpf::names::joaat;

/// Bytes of the root header the grammar reads.
pub const ROOT_LEN: usize = 0x60;
/// Bytes of one texture record.
pub const RECORD_LEN: u64 = 0x70;
/// Longest name text the hash check reads.
pub const NAME_WINDOW: usize = 64;
/// The name-record `+0x10` value that identifies the hash-carrying variant.
pub const NAME_HASH_VARIANT: u64 = 6;
/// Bits of the mip word that hold the level count.
const MIP_LEVEL_MASK: u16 = 0x7FFF;

/// The structural step a resource failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    HeaderLen,
    ZeroQword,
    PageMapPointer,
    HashPointer,
    HashCounts,
    ValuePointer,
    ValueCounts,
    CountsDiffer,
    Capacity,
    HashArray,
    HashOrder,
    ValuePointerOutOfRange,
    RecordOutOfRange,
}

impl Step {
    pub fn describe(self) -> &'static str {
        match self {
            Step::HeaderLen => "the system segment is shorter than the root header",
            Step::ZeroQword => "the first qword is not zero",
            Step::PageMapPointer => "the page-map pointer is not a system pointer",
            Step::HashPointer => "the hash-array pointer is not a system pointer",
            Step::HashCounts => "the hash count and capacity are not readable",
            Step::ValuePointer => "the value-array pointer is not a system pointer",
            Step::ValueCounts => "the value count and capacity are not readable",
            Step::CountsDiffer => "the hash count differs from the value count",
            Step::Capacity => "a capacity is smaller than its count",
            Step::HashArray => "the hash array is outside the system segment",
            Step::HashOrder => "the hash array is not ascending and duplicate-free",
            Step::ValuePointerOutOfRange => {
                "a value is not a system pointer inside the system segment"
            }
            Step::RecordOutOfRange => "a record does not fit inside the system segment",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A resource that fails a recognition step is not a dictionary.
    NotADictionary(Step),
    /// An identified dictionary whose arrays or records are inconsistent.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotADictionary(step) => f.write_str(step.describe()),
            Error::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

/// Reader limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_records: usize,
    pub max_hashes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 1 << 16,
            max_hashes: 1 << 16,
        }
    }
}

/// Which variant the name record at `+0x10` identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameVariant {
    /// `+0x10` is [`NAME_HASH_VARIANT`], so `+0x18` holds the name hash.
    Hash,
    /// Any other variant; no hash is read.
    Pointer,
}

impl NameVariant {
    pub fn name(self) -> &'static str {
        match self {
            NameVariant::Hash => "hash",
            NameVariant::Pointer => "pointer",
        }
    }
}

/// The result of the folded one-at-a-time check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCheck {
    Matched,
    Mismatched {
        stored: u32,
        computed: u32,
    },
    /// The text was not reachable, unterminated or longer than the window.
    NotChecked(&'static str),
}

impl NameCheck {
    pub fn name(self) -> &'static str {
        match self {
            NameCheck::Matched => "matched",
            NameCheck::Mismatched { .. } => "mismatched",
            NameCheck::NotChecked(_) => "not checked",
        }
    }

    pub fn reason(self) -> Option<&'static str> {
        match self {
            NameCheck::NotChecked(reason) => Some(reason),
            _ => None,
        }
    }
}

/// One `0x70`-byte record. Fields whose meaning is unknown keep neutral
/// names; widths and the format id are positions only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub index: u32,
    /// Offset of the record in the system segment.
    pub at: u32,
    /// `+0x08`: allocation unit count. Its byte scale is not established.
    pub units: u32,
    /// `+0x0C`: two uninterpreted `u16`.
    pub word_0c: u32,
    /// `+0x10`: `2432` or `2434` in the sample; uninterpreted.
    pub word_10: u64,
    /// `+0x18`: graphics pointer to the allocation start.
    pub graphics_at: Option<u32>,
    /// The extent to the next distinct allocation start, or the graphics end.
    pub extent: Option<u64>,
    /// `+0x30`: system pointer to the name record.
    pub name_at: Option<u32>,
    pub width: u16,
    pub height: u16,
    /// `+0x3F`: format id, not mapped to an enum.
    pub format_id: u8,
    /// `+0x42`: the raw mip word.
    pub mip_word: u16,
    /// Low 15 bits of the mip word.
    pub mip_levels: u16,
    /// `+0x3C`, `+0x3E`, `+0x40`, `+0x46`, `+0x48`, `+0x60`: read, neutral.
    pub neutral: [u64; 6],
    pub name_variant: NameVariant,
    /// The `u32` at name record `+0x18`, only for the hash variant.
    pub name_hash: Option<u32>,
    pub name_check: NameCheck,
}

/// The checks the research records as fields of the census.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checks {
    pub counts_equal: bool,
    pub capacities_ok: bool,
    pub hash_sorted_unique: bool,
    /// The value array is already in ascending order, which is how the
    /// census compares it with the sorted record addresses.
    pub value_order_matches_index: bool,
    pub starts_at_zero: bool,
    pub allocation_duplicate: bool,
    pub allocation_front_gap: bool,
    pub allocations_in_bounds: bool,
    /// The extents sum to the graphics size.
    pub partition_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub hash_count: u16,
    pub hash_capacity: u16,
    pub value_count: u16,
    pub value_capacity: u16,
    /// A dictionary with no arrays and no records.
    pub empty: bool,
    pub hashes: Vec<u32>,
    pub values: Vec<u32>,
    pub records: Vec<Record>,
    pub system_len: u64,
    pub graphics_len: u64,
    pub checks: Checks,
}

impl Report {
    /// Records whose name hash matches a hash in this dictionary.
    ///
    /// A hash can occur more than once, so this returns every candidate; it
    /// does not select one.
    pub fn hash_candidates(&self, hash: u32) -> Vec<(u32, u32)> {
        self.records
            .iter()
            .filter(|record| record.name_hash == Some(hash))
            .map(|record| (record.index, record.at))
            .collect()
    }
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

fn system_at(value: u64) -> Option<u32> {
    match Pointer::decode(value) {
        Some(Pointer::System(offset)) => Some(offset),
        _ => None,
    }
}

fn graphics_at(value: u64) -> Option<u32> {
    match Pointer::decode(value) {
        Some(Pointer::Graphics(offset)) => Some(offset),
        _ => None,
    }
}

/// Whether `system` has the structural shape of a dictionary. The graphics
/// segment plays no part.
pub fn is_dictionary(system: &[u8]) -> bool {
    parse(system, 0, &Limits::default()).is_ok()
}

/// Parses a dictionary. `graphics_len` is the length of the graphics
/// segment; allocation bounds are checked against it but no graphics byte is
/// read.
pub fn parse(system: &[u8], graphics_len: u64, limits: &Limits) -> Result<Report, Error> {
    if system.len() < ROOT_LEN {
        return Err(Error::NotADictionary(Step::HeaderLen));
    }
    if u64_at(system, 0) != Some(0) {
        return Err(Error::NotADictionary(Step::ZeroQword));
    }
    // The page-map pointer is required by the header shape even though the
    // map itself is read during reconstruction.
    system_at(u64_at(system, 0x08).unwrap_or(0))
        .ok_or(Error::NotADictionary(Step::PageMapPointer))
        .map(|_| ())?;

    let hash_value = u64_at(system, 0x20).ok_or(Error::NotADictionary(Step::HashCounts))?;
    let (hash_count, hash_capacity) = (
        u16_at(system, 0x28).ok_or(Error::NotADictionary(Step::HashCounts))?,
        u16_at(system, 0x2A).ok_or(Error::NotADictionary(Step::HashCounts))?,
    );
    let value_value = u64_at(system, 0x30).ok_or(Error::NotADictionary(Step::ValueCounts))?;
    let (value_count, value_capacity) = (
        u16_at(system, 0x38).ok_or(Error::NotADictionary(Step::ValueCounts))?,
        u16_at(system, 0x3A).ok_or(Error::NotADictionary(Step::ValueCounts))?,
    );

    let empty = hash_value == 0 && value_value == 0 && hash_count == 0 && value_count == 0;
    if empty {
        return Ok(Report {
            hash_count,
            hash_capacity,
            value_count,
            value_capacity,
            empty: true,
            hashes: Vec::new(),
            values: Vec::new(),
            records: Vec::new(),
            system_len: system.len() as u64,
            graphics_len,
            checks: Checks {
                counts_equal: true,
                capacities_ok: hash_capacity >= hash_count && value_capacity >= value_count,
                hash_sorted_unique: true,
                value_order_matches_index: true,
                starts_at_zero: true,
                allocation_duplicate: false,
                allocation_front_gap: false,
                allocations_in_bounds: true,
                partition_ok: true,
            },
        });
    }

    let hash_at = system_at(hash_value).ok_or(Error::NotADictionary(Step::HashPointer))?;
    let value_at = system_at(value_value).ok_or(Error::NotADictionary(Step::ValuePointer))?;
    if hash_count != value_count {
        return Err(Error::NotADictionary(Step::CountsDiffer));
    }
    if hash_capacity < hash_count || value_capacity < value_count {
        return Err(Error::NotADictionary(Step::Capacity));
    }

    // Neither count is clamped: an array that does not fit is an error.
    let hashes = read_array::<4>(system, hash_at, hash_count, Step::HashArray)?
        .into_iter()
        .map(u32::from_le_bytes)
        .collect::<Vec<u32>>();
    let values = read_array::<8>(system, value_at, value_count, Step::HashArray)?
        .into_iter()
        .map(u64::from_le_bytes)
        .collect::<Vec<u64>>();
    let hash_sorted_unique = hashes.windows(2).all(|pair| pair[0] < pair[1]);
    if !hash_sorted_unique {
        return Err(Error::NotADictionary(Step::HashOrder));
    }
    if usize::from(value_count) > limits.max_hashes {
        return Err(Error::Invalid(format!(
            "the dictionary declares {value_count} records, more than the {} record limit",
            limits.max_records
        )));
    }

    let mut pointers = Vec::with_capacity(values.len());
    for (ix, &value) in values.iter().enumerate() {
        let at = system_at(value).ok_or_else(|| {
            Error::Invalid(format!(
                "value {ix} holds {value:#018X}, which is not a system pointer"
            ))
        })?;
        let end = u64::from(at)
            .checked_add(RECORD_LEN)
            .ok_or_else(|| Error::Invalid(format!("record {ix} overflows")))?;
        if end > system.len() as u64 {
            return Err(Error::Invalid(format!(
                "record {ix} at system +{at:#x} needs {RECORD_LEN} bytes, past the {} byte system segment",
                system.len()
            )));
        }
        pointers.push(at);
    }

    let value_order_matches_index = values.windows(2).all(|pair| pair[0] <= pair[1]);
    let mut starts: Vec<u32> = Vec::with_capacity(pointers.len());
    for &at in &pointers {
        let value = u64_at(system, at as usize + 0x18)
            .ok_or(Error::NotADictionary(Step::RecordOutOfRange))?;
        starts.push(graphics_at(value).unwrap_or(u32::MAX));
    }
    let mut distinct: Vec<u64> = starts
        .iter()
        .filter(|&&start| start != u32::MAX)
        .map(|&start| u64::from(start))
        .collect();
    distinct.sort_unstable();
    let duplicate = distinct.windows(2).any(|pair| pair[0] == pair[1]);
    distinct.dedup();
    let starts_at_zero = distinct.first() == Some(&0);
    let front_gap = distinct.first().is_some_and(|&start| start > 0);
    let in_bounds = starts
        .iter()
        .all(|&start| start != u32::MAX && u64::from(start) < graphics_len.max(1))
        && graphics_len > 0;
    let mut sum = 0u64;
    for (ix, &start) in distinct.iter().enumerate() {
        let extent = match distinct.get(ix + 1) {
            Some(&next) => next - start,
            None => graphics_len.saturating_sub(start),
        };
        sum = sum.saturating_add(extent);
    }
    let partition_ok = !duplicate && starts_at_zero && in_bounds && sum == graphics_len;

    let mut records = Vec::with_capacity(pointers.len());
    for (ix, &at) in pointers.iter().enumerate() {
        let base = at as usize;
        let extent = (starts[ix] != u32::MAX).then(|| {
            let start = u64::from(starts[ix]);
            let next = distinct
                .iter()
                .find(|&&candidate| candidate > start)
                .copied()
                .unwrap_or(graphics_len);
            next.saturating_sub(start)
        });
        let name_at = system_at(u64_at(system, base + 0x30).unwrap_or(0));
        let (name_variant, name_hash, name_check) = match name_at {
            Some(name) => read_name(system, name),
            None => (
                NameVariant::Pointer,
                None,
                NameCheck::NotChecked("no name record"),
            ),
        };
        records.push(Record {
            index: ix as u32,
            at,
            units: u32_at(system, base + 0x08).unwrap_or(0),
            word_0c: u32_at(system, base + 0x0C).unwrap_or(0),
            word_10: u64_at(system, base + 0x10).unwrap_or(0),
            graphics_at: (starts[ix] != u32::MAX).then_some(starts[ix]),
            extent,
            name_at,
            width: u16_at(system, base + 0x38).unwrap_or(0),
            height: u16_at(system, base + 0x3A).unwrap_or(0),
            format_id: system.get(base + 0x3F).copied().unwrap_or(0),
            mip_word: u16_at(system, base + 0x42).unwrap_or(0),
            mip_levels: u16_at(system, base + 0x42).unwrap_or(0) & MIP_LEVEL_MASK,
            neutral: [
                u64::from(u16_at(system, base + 0x3C).unwrap_or(0)),
                u64::from(system.get(base + 0x3E).copied().unwrap_or(0)),
                u64::from(u16_at(system, base + 0x40).unwrap_or(0)),
                u64::from(u16_at(system, base + 0x46).unwrap_or(0)),
                u64_at(system, base + 0x48).unwrap_or(0),
                u64_at(system, base + 0x60).unwrap_or(0),
            ],
            name_variant,
            name_hash,
            name_check,
        });
    }

    Ok(Report {
        hash_count,
        hash_capacity,
        value_count,
        value_capacity,
        empty: false,
        hashes,
        values: pointers,
        records,
        system_len: system.len() as u64,
        graphics_len,
        checks: Checks {
            counts_equal: hash_count == value_count,
            capacities_ok: hash_capacity >= hash_count && value_capacity >= value_count,
            hash_sorted_unique,
            value_order_matches_index,
            starts_at_zero,
            allocation_duplicate: duplicate,
            allocation_front_gap: front_gap,
            allocations_in_bounds: in_bounds,
            partition_ok,
        },
    })
}

/// Reads `count` `N`-byte entries at `at` without clamping the count.
fn read_array<const N: usize>(
    system: &[u8],
    at: u32,
    count: u16,
    step: Step,
) -> Result<Vec<[u8; N]>, Error> {
    let len = usize::from(count) * N;
    let start = at as usize;
    let end = start.checked_add(len).ok_or(Error::NotADictionary(step))?;
    let bytes = system.get(start..end).ok_or(Error::NotADictionary(step))?;
    Ok(bytes.as_chunks::<N>().0.to_vec())
}

/// Reads a name record and checks its hash when the variant carries one.
fn read_name(system: &[u8], at: u32) -> (NameVariant, Option<u32>, NameCheck) {
    let base = at as usize;
    let discriminator = u64_at(system, base + 0x10).unwrap_or(0);
    if discriminator != NAME_HASH_VARIANT {
        return (
            NameVariant::Pointer,
            None,
            NameCheck::NotChecked("the name record is not the hash variant"),
        );
    }
    let stored = u32_at(system, base + 0x18).unwrap_or(0);
    let Some(text_base) = system_at(u64_at(system, base).unwrap_or(0)) else {
        return (
            NameVariant::Hash,
            Some(stored),
            NameCheck::NotChecked("no text pointer"),
        );
    };
    let Some(text_start) = (text_base as usize).checked_add(8) else {
        return (
            NameVariant::Hash,
            Some(stored),
            NameCheck::NotChecked("the text pointer overflows"),
        );
    };
    let Some(window) = system.get(text_start..text_start.saturating_add(NAME_WINDOW)) else {
        return (
            NameVariant::Hash,
            Some(stored),
            NameCheck::NotChecked("the text is unreachable"),
        );
    };
    let Some(len) = window.iter().position(|&byte| byte == 0) else {
        return (
            NameVariant::Hash,
            Some(stored),
            NameCheck::NotChecked("the text is not terminated inside the 64-byte window"),
        );
    };
    let computed = joaat(&window[..len]);
    let check = if computed == stored {
        NameCheck::Matched
    } else {
        NameCheck::Mismatched { stored, computed }
    };
    (NameVariant::Hash, Some(stored), check)
}

/// The texture parameter word a drawable shader carries at entry `+0x04`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextureParameter {
    /// Low two bits.
    pub class: u8,
    /// Bits 2..31.
    pub slot: u32,
}

impl TextureParameter {
    /// Splits `value` into its parameter class and slot index.
    pub fn split(value: u32) -> Self {
        Self {
            class: (value & 0x3) as u8,
            slot: value >> 2,
        }
    }

    /// Class zero is the texture-entry class the research observed.
    pub fn is_texture(self) -> bool {
        self.class == 0
    }
}

/// What a drawable slot holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// The slot index is below the declared texture count and holds a record.
    Bound,
    /// The slot index is below the declared texture count and is null.
    Unbound,
    /// The slot index is at or above the declared texture count.
    Invalid,
}

impl SlotState {
    pub fn name(self) -> &'static str {
        match self {
            SlotState::Bound => "bound",
            SlotState::Unbound => "unbound",
            SlotState::Invalid => "invalid",
        }
    }
}

/// Classifies a texture parameter's slot against the declared texture count.
///
/// A non-texture class has no slot, so it is reported as `None` and must not
/// be counted as a bound, unbound or invalid slot.
pub fn slot_state(
    parameter: TextureParameter,
    texture_count: u32,
    bound: bool,
) -> Option<SlotState> {
    if !parameter.is_texture() {
        return None;
    }
    Some(if parameter.slot >= texture_count {
        SlotState::Invalid
    } else if bound {
        SlotState::Bound
    } else {
        SlotState::Unbound
    })
}
