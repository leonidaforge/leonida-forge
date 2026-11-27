//! Fragment resources.
//!
//! A fragment is a resource whose system data starts with a root header and
//! that holds a member drawable. The layout below was read on 40 rows of one
//! nested archive and confirmed on all 5,553 type-3 rows of 27 nested archives
//! (FRAG-F01 to FRAG-F08): every row holds exactly one member drawable and only
//! `+0x18` reaches one. Every other field the root stores is reported as a slot
//! whose meaning is not established.
//!
//! Observed root header, system-relative:
//!
//! | Offset | Size | Observation |
//! | -----: | ---: | ----------- |
//! | `+0x00` | 8 | Zero in every sample; a parser MUST require it |
//! | `+0x08` | 8 | Page-map pointer, exactly as a resource-level drawable holds |
//! | `+0x10` | 8 | System pointer; an unestablished record, never a drawable in the samples |
//! | `+0x18` | 8 | System pointer to the member drawable in every sample |
//! | `+0x20` | 8 | System pointer; an unestablished record, never a drawable in the samples |
//! | `+0x28` | 8 | System pointer; an unestablished record, never a drawable in the samples |
//! | `+0x30` | 8 | Four `u16`; `+0x30` is `1` in every sample, the others vary |
//!
//! Only `+0x18` is followed. The other pointers are not scanned for further
//! drawables: 5,553 rows never reach one, so treating them as component tables
//! would be an invention. A fragment is reported as a single-drawable
//! representation and says so.
//!
//! The member drawable holds zero in its own page-map word (`drawable +0x08`)
//! and `3` in the word at `drawable +0xB8` where a resource-level drawable
//! holds `0x103`. Neither value is interpreted.

use std::fmt;

use super::drawable;

#[cfg(test)]
mod tests;

/// Bytes of the root header this module reads.
pub const ROOT_PREFIX_LEN: usize = 0x38;
/// The root word that is zero in every observed fragment.
pub const ROOT_ZERO: u64 = 0;
/// The `u16` counts the root stores at `+0x30`.
pub const COUNT_SLOTS: usize = 4;
/// The suffix a fragment member drawable carries in every observed sample.
pub const FRAGMENT_SUFFIX: &str = "#ft";
/// Why a resource is not a supported fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The system segment is shorter than the root header.
    HeaderLen,
    /// The first word is not zero.
    ZeroWord,
    /// The page-map slot is not a system pointer.
    PageMap,
    /// The member-drawable slot is not a system pointer.
    Drawable,
    /// The drawable slot resolves but the target is not a member drawable.
    DrawableShape,
}

impl Step {
    pub fn describe(self) -> &'static str {
        match self {
            Step::HeaderLen => "the system segment is shorter than the fragment root header",
            Step::ZeroWord => "the fragment root does not start with a zero word",
            Step::PageMap => "the fragment root page-map slot is not a system pointer",
            Step::Drawable => "the fragment root drawable slot is not a system pointer",
            Step::DrawableShape => {
                "the fragment drawable slot does not resolve to a member drawable"
            }
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

/// The root header fields this module reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub page_map: u32,
    pub drawable: u32,
    /// The pointers at `+0x10`, `+0x20` and `+0x28`. Their targets are not
    /// identified; they are not drawables in any observed sample.
    pub unexplained: [Option<u32>; 3],
    /// The four `u16` at `+0x30`, as stored.
    pub counts: [u16; COUNT_SLOTS],
}

impl Header {
    /// How many unexplained slots the root populates.
    pub fn unexplained_present(&self) -> usize {
        self.unexplained
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub header: Header,
    /// The member drawable's structural walk.
    pub drawable: drawable::Report,
    /// Whether the member drawable's name carries the fragment suffix.
    pub named_fragment: bool,
    /// Why the walk of the member drawable was not clean, when it was not.
    pub issues: Vec<String>,
}

impl Report {
    pub fn name(&self) -> Option<&str> {
        self.drawable.header.name_text.as_deref()
    }
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn system_pointer(value: u64) -> Option<u32> {
    match super::resource::Pointer::decode(value) {
        Some(super::resource::Pointer::System(offset)) => Some(offset),
        _ => None,
    }
}

/// Reads the root header. `Err` names the step that failed.
pub fn header(system: &[u8]) -> Result<Header, Step> {
    if system.len() < ROOT_PREFIX_LEN {
        return Err(Step::HeaderLen);
    }
    if u64_at(system, 0) != Some(ROOT_ZERO) {
        return Err(Step::ZeroWord);
    }
    let page_map = u64_at(system, 0x08)
        .and_then(system_pointer)
        .ok_or(Step::PageMap)?;
    let drawable = u64_at(system, 0x18)
        .and_then(system_pointer)
        .ok_or(Step::Drawable)?;
    let mut counts = [0u16; COUNT_SLOTS];
    for (index, count) in counts.iter_mut().enumerate() {
        *count = u16_at(system, 0x30 + index * 2).unwrap_or(0);
    }
    Ok(Header {
        page_map,
        drawable,
        unexplained: [
            u64_at(system, 0x10).and_then(system_pointer),
            u64_at(system, 0x20).and_then(system_pointer),
            u64_at(system, 0x28).and_then(system_pointer),
        ],
        counts,
    })
}

/// Whether a member drawable's name carries the fragment suffix.
pub fn is_fragment_name(report: &drawable::Report) -> bool {
    report
        .header
        .name_text
        .as_deref()
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(FRAGMENT_SUFFIX))
}

/// Inspects a fragment. `None` when the resource does not have the root shape,
/// when it is a resource-level drawable itself, or when the member-drawable
/// slot does not resolve to a member drawable.
///
/// Recognition is structural. The member name's `#ft` suffix is reported in
/// [`Report::named_fragment`] but is not required: the declared resource type
/// selects the candidate and the structure decides, so a fragment whose member
/// carries another suffix is still the fragment its structure says it is.
pub fn inspect(system: &[u8], graphics: &[u8]) -> Option<Report> {
    let header = header(system).ok()?;
    // A resource-level drawable also starts with a zero word and a page map;
    // its `+0x18` is the skeleton slot. A drawable is not a fragment.
    if drawable::is_drawable_at(system, graphics, 0) {
        return None;
    }
    let at = header.drawable as usize;
    if at.checked_add(0xC0).is_none_or(|end| end > system.len()) {
        return None;
    }
    let drawable = drawable::inspect_member_at(system, graphics, at)?;
    Some(Report {
        header,
        named_fragment: is_fragment_name(&drawable),
        issues: drawable
            .issues
            .iter()
            .map(|issue| issue.to_string())
            .collect(),
        drawable,
    })
}
