//! Drawable dictionaries.
//!
//! A drawable dictionary is a resource whose system segment starts with a
//! `pgDictionary`-shaped root and whose values are member drawables. The
//! layout below is the one observed in 20 type-4 rows of five archives
//! (DDICT-F01 to DDICT-F06). Every member name hash was checked against
//! `joaat` of the member drawable's own name.
//!
//! Observed root, system-relative:
//!
//! | Offset | Size | Observation |
//! | -----: | ---: | ----------- |
//! | `+0x00` | 8 | Zero in every sample; a parser MUST require it |
//! | `+0x08` | 8 | Page-map pointer, the same word [`super::resource::page_map_offset`] reads |
//! | `+0x10` | 8 | Zero in every sample; meaning not established |
//! | `+0x18` | 8 | `1` in every sample; meaning not established, and not the member count |
//! | `+0x20` | 8 | System pointer to a sorted `u32` name-hash array |
//! | `+0x28` | 2 + 2 | Hash count, then capacity |
//! | `+0x30` | 8 | System pointer to a `u64` member-pointer array |
//! | `+0x38` | 2 + 2 | Value count, then capacity |
//!
//! The two arrays are positional: entry `i` of the value array is the member
//! whose name hash is entry `i` of the hash array. The hash array is ascending
//! and duplicate-free in every sample. A member value is a system pointer to
//! an `rmcDrawable` whose own page-map word is zero and whose `+0xB8` word is
//! `0x103`; that is the same embedded-drawable form a fragment holds, so
//! [`super::drawable::inspect_member_at`] reads it.
//!
//! Nothing here decodes geometry. A member that does not resolve is reported
//! and does not invalidate the other members.

#[cfg(test)]
mod tests;

use std::fmt;

use super::drawable;
use super::resource::Pointer;

/// Bytes of the root the grammar reads.
pub const ROOT_LEN: usize = 0x40;
/// Largest member count accepted.
pub const MAX_MEMBERS: usize = 1 << 12;
/// The word at `+0x18` observed in every sample.
pub const WORD_18: u64 = 1;

/// The structural step a resource failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The system segment is shorter than the root.
    HeaderLen,
    /// The first word is not zero.
    ZeroWord,
    /// The page-map slot is not the resource page map.
    PageMap,
    /// The hash-array slot is neither zero nor a system pointer.
    HashPointer,
    /// The value-array slot is neither zero nor a system pointer.
    ValuePointer,
    /// A count is unreadable, or counts differ, or a count exceeds its capacity.
    Counts,
    /// A count exceeds [`MAX_MEMBERS`].
    Capacity,
    /// An array does not fit inside the system segment.
    Array,
}

impl Step {
    pub fn describe(self) -> &'static str {
        match self {
            Step::HeaderLen => "the system segment is shorter than the dictionary root",
            Step::ZeroWord => "the dictionary root does not start with a zero word",
            Step::PageMap => "the dictionary page-map slot is not the resource page map",
            Step::HashPointer => "the hash-array slot is not a system pointer",
            Step::ValuePointer => "the value-array slot is not a system pointer",
            Step::Counts => "the dictionary counts and capacities are inconsistent",
            Step::Capacity => "the dictionary declares more members than the reader accepts",
            Step::Array => "a dictionary array does not fit inside the system segment",
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotADictionary(Step),
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

/// What one member value turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberState {
    /// The value resolves to a member drawable whose LOD chain walks.
    Drawable,
    /// The value is null.
    Null,
    /// The value is not a system pointer.
    NotAPointer,
    /// The value points at system data that does not have the member form.
    NotADrawable,
}

impl MemberState {
    pub fn name(&self) -> &'static str {
        match self {
            MemberState::Drawable => "drawable",
            MemberState::Null => "null",
            MemberState::NotAPointer => "not a pointer",
            MemberState::NotADrawable => "not a drawable",
        }
    }
}

/// One member entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub index: u32,
    /// The stored name hash. It equals `joaat` of the member drawable's name
    /// in every observed sample; it is not a resolved file name.
    pub hash: u32,
    /// The stored value, as written.
    pub value: u64,
    /// The member drawable's system offset, when the value is a system pointer.
    pub drawable: Option<u32>,
    /// The member drawable's stored name, when it has one.
    pub name: Option<String>,
    pub state: MemberState,
}

/// The root fields the grammar reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub page_map: u32,
    /// The words at `+0x10` and `+0x18`. Their meanings are not established.
    pub word_10: u64,
    pub word_18: u64,
    pub hash_array: Option<u32>,
    pub value_array: Option<u32>,
    pub count: u16,
    pub capacity: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub header: Header,
    pub members: Vec<Member>,
    /// The hash array is ascending and duplicate-free.
    pub hash_sorted: bool,
    /// A root with no members.
    pub empty: bool,
}

impl Report {
    /// Members whose value resolved to a member drawable.
    pub fn drawable_members(&self) -> impl Iterator<Item = &Member> {
        self.members
            .iter()
            .filter(|member| member.state == MemberState::Drawable)
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

/// Reads the root and every member entry. `graphics` is used to decide whether
/// a member value resolves to a member drawable.
///
/// An empty dictionary is valid: the two counts are zero and no array is read.
pub fn parse(system: &[u8], graphics: &[u8]) -> Result<Report, Error> {
    if system.len() < ROOT_LEN {
        return Err(Error::NotADictionary(Step::HeaderLen));
    }
    if u64_at(system, 0) != Some(0) {
        return Err(Error::NotADictionary(Step::ZeroWord));
    }
    let page_map_value = u64_at(system, 0x08).unwrap_or(0);
    let page_map = system_at(page_map_value).ok_or(Error::NotADictionary(Step::PageMap))?;
    // The root's page-map word is the resource's page map by definition; a
    // zero there would not be a pointer, which the check above rejects.

    let hash_value = u64_at(system, 0x20).ok_or(Error::NotADictionary(Step::Counts))?;
    let value_value = u64_at(system, 0x30).ok_or(Error::NotADictionary(Step::Counts))?;
    let hash_count = u16_at(system, 0x28).ok_or(Error::NotADictionary(Step::Counts))?;
    let hash_capacity = u16_at(system, 0x2A).ok_or(Error::NotADictionary(Step::Counts))?;
    let value_count = u16_at(system, 0x38).ok_or(Error::NotADictionary(Step::Counts))?;
    let value_capacity = u16_at(system, 0x3A).ok_or(Error::NotADictionary(Step::Counts))?;

    if hash_count != value_count || hash_capacity < hash_count || value_capacity < value_count {
        return Err(Error::NotADictionary(Step::Counts));
    }
    if usize::from(hash_count) > MAX_MEMBERS {
        return Err(Error::NotADictionary(Step::Capacity));
    }

    let hash_array = match system_at(hash_value) {
        Some(offset) => Some(offset),
        None if hash_value == 0 => None,
        None => return Err(Error::NotADictionary(Step::HashPointer)),
    };
    let value_array = match system_at(value_value) {
        Some(offset) => Some(offset),
        None if value_value == 0 => None,
        None => return Err(Error::NotADictionary(Step::ValuePointer)),
    };

    if hash_count == 0 {
        // An empty dictionary stores no arrays. A non-zero pointer with a zero
        // count is still checked for bounds, so a malformed empty root fails.
        if let Some(at) = value_array {
            check_array(system, at as usize, 0, 8)?;
        }
        if let Some(at) = hash_array {
            check_array(system, at as usize, 0, 4)?;
        }
        return Ok(Report {
            header: Header {
                page_map,
                word_10: u64_at(system, 0x10).unwrap_or(0),
                word_18: u64_at(system, 0x18).unwrap_or(0),
                hash_array,
                value_array,
                count: 0,
                capacity: hash_capacity.min(value_capacity),
            },
            members: Vec::new(),
            hash_sorted: true,
            empty: true,
        });
    }

    let hash_array = hash_array.ok_or(Error::NotADictionary(Step::HashPointer))?;
    let value_array = value_array.ok_or(Error::NotADictionary(Step::ValuePointer))?;
    check_array(system, hash_array as usize, usize::from(hash_count), 4)?;
    check_array(system, value_array as usize, usize::from(value_count), 8)?;

    let mut members = Vec::with_capacity(usize::from(hash_count));
    let mut previous: Option<u32> = None;
    let mut hash_sorted = true;
    for index in 0..u32::from(hash_count) {
        let hash = u32_at(system, hash_array as usize + index as usize * 4)
            .ok_or(Error::NotADictionary(Step::Array))?;
        let value = u64_at(system, value_array as usize + index as usize * 8)
            .ok_or(Error::NotADictionary(Step::Array))?;
        if previous.is_some_and(|previous| hash <= previous) {
            hash_sorted = false;
        }
        previous = Some(hash);
        let mut member = Member {
            index,
            hash,
            value,
            drawable: None,
            name: None,
            state: MemberState::NotAPointer,
        };
        if value == 0 {
            member.state = MemberState::Null;
        } else if let Some(at) = system_at(value) {
            member.drawable = Some(at);
            let root = at as usize;
            if drawable::is_member_drawable_at(system, graphics, root) {
                member.state = MemberState::Drawable;
                member.name = drawable::member_name_at(system, root);
            } else {
                member.state = MemberState::NotADrawable;
            }
        }
        members.push(member);
    }

    Ok(Report {
        header: Header {
            page_map,
            word_10: u64_at(system, 0x10).unwrap_or(0),
            word_18: u64_at(system, 0x18).unwrap_or(0),
            hash_array: Some(hash_array),
            value_array: Some(value_array),
            count: hash_count,
            capacity: hash_capacity.max(value_capacity),
        },
        members,
        hash_sorted,
        empty: false,
    })
}

fn check_array(system: &[u8], at: usize, count: usize, stride: usize) -> Result<(), Error> {
    let needed = at
        .checked_add(count.saturating_mul(stride))
        .ok_or(Error::NotADictionary(Step::Array))?;
    if needed > system.len() {
        return Err(Error::NotADictionary(Step::Array));
    }
    Ok(())
}

/// Whether `system` has the root of a drawable dictionary.
///
/// The test is structural. A populated dictionary must hold at least one
/// member whose value resolves to a member drawable; an empty dictionary is
/// accepted only when the counts are zero and the `+0x18` word is the observed
/// [`WORD_18`], because an empty root has no member to confirm the form.
pub fn is_drawable_dictionary(system: &[u8], graphics: &[u8]) -> bool {
    match parse(system, graphics) {
        Ok(report) if report.empty => report.header.word_18 == WORD_18,
        Ok(report) => {
            report.hash_sorted
                && report
                    .members
                    .iter()
                    .any(|m| m.state == MemberState::Drawable)
        }
        Err(_) => false,
    }
}
