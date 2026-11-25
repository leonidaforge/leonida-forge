//! EDUP: a count, a table of two eight-byte fields and an opaque trailing
//! blob.
//!
//! The framing is the one the research established (EDUP rows of
//! `evidence/edup/INDEX.md`): `EDUP`, a little-endian `u32` entry count, that
//! many 16-byte entries, a little-endian `u32` blob length, then the blob.
//! The payload size is `12 + 16 * count + length` exactly.
//!
//! In the one large table the research reached, the second field matched a
//! stored texture key for every entry and the first field matched none. That
//! establishes the direction for that population only. A match is reported as
//! a candidate relation, never as a resolved texture, and the store set is
//! supplied by the caller: this reader never scans a store on its own.

#[cfg(test)]
mod tests;

use std::fmt;

pub const MAGIC: [u8; 4] = *b"EDUP";
/// Bytes before the entries.
pub const HEADER_LEN: usize = 8;
/// Bytes of one entry.
pub const ENTRY_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotEdup,
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotEdup => f.write_str("not an EDUP payload"),
            Error::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}

pub fn is_edup(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// One entry, as two little-endian 64-bit fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub first: u64,
    pub second: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Every first-field key matched and no second-field key did.
    FirstField,
    /// Every second-field key matched and no first-field key did.
    SecondField,
    /// Both fields match on at least one entry.
    Ambiguous,
    /// Neither field matched the supplied keys.
    Unresolved,
    /// No comparison was run.
    NotEvaluated,
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Direction::FirstField => "first-field",
            Direction::SecondField => "second-field",
            Direction::Ambiguous => "ambiguous",
            Direction::Unresolved => "unresolved",
            Direction::NotEvaluated => "not evaluated",
        }
    }
}

/// The counts that decide the key direction of one table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    pub entries: usize,
    pub first_distinct: usize,
    pub second_distinct: usize,
    pub first_matches: usize,
    pub second_matches: usize,
    pub both_matches: usize,
    pub first_keys: Vec<u64>,
    pub second_keys: Vec<u64>,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blob {
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub count: u32,
    pub entries: Vec<Entry>,
    pub first_distinct: usize,
    pub second_distinct: usize,
    /// No entry repeats a first-field value.
    pub first_unique: bool,
    /// No first-field value occurs as a second-field value.
    pub fields_disjoint: bool,
    pub blob: Blob,
    pub size: u64,
}

/// Parses an EDUP payload. `max_entries` bounds the table the caller accepts.
pub fn parse(bytes: &[u8], max_entries: usize) -> Result<Report, Error> {
    if !is_edup(bytes) {
        return Err(Error::NotEdup);
    }
    let count = le_u32(bytes, 4).ok_or_else(|| invalid("the entry count is truncated"))?;
    if count as usize > max_entries {
        return Err(invalid(format!(
            "the payload declares {count} entries, more than the {max_entries} limit"
        )));
    }
    let entries_end = HEADER_LEN
        .checked_add(count as usize * ENTRY_LEN)
        .ok_or_else(|| invalid("the entry count overflows"))?;
    let length = le_u32(bytes, entries_end)
        .ok_or_else(|| invalid("the trailing-blob length is truncated"))?;
    let blob_end = entries_end
        .checked_add(4)
        .and_then(|at| at.checked_add(length as usize))
        .ok_or_else(|| invalid("the trailing-blob length overflows"))?;
    if blob_end != bytes.len() {
        return Err(invalid(format!(
            "the payload is {} bytes; the count and blob length give {blob_end}",
            bytes.len()
        )));
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut firsts = Vec::with_capacity(count as usize);
    let mut seconds = Vec::with_capacity(count as usize);
    for ix in 0..count as usize {
        let at = HEADER_LEN + ix * ENTRY_LEN;
        let first = le_u64(bytes, at).ok_or_else(|| invalid("an entry is truncated"))?;
        let second = le_u64(bytes, at + 8).ok_or_else(|| invalid("an entry is truncated"))?;
        entries.push(Entry { first, second });
        firsts.push(first);
        seconds.push(second);
    }
    let mut sorted_first = firsts.clone();
    sorted_first.sort_unstable();
    sorted_first.dedup();
    let mut sorted_second = seconds.clone();
    sorted_second.sort_unstable();
    sorted_second.dedup();
    let first_unique = sorted_first.len() == firsts.len();
    let fields_disjoint = !firsts.iter().any(|first| seconds.contains(first))
        && !seconds.iter().any(|second| firsts.contains(second));
    Ok(Report {
        count,
        entries,
        first_distinct: sorted_first.len(),
        second_distinct: sorted_second.len(),
        first_unique,
        fields_disjoint,
        blob: Blob {
            offset: (entries_end + 4) as u64,
            len: length,
        },
        size: bytes.len() as u64,
    })
}

/// Compares the two entry fields with a caller-supplied key set.
///
/// The result distinguishes a direction from an unresolved table and from a
/// comparison that was not run. A key match is reported as a candidate
/// association only.
pub fn compare(report: &Report, keys: &[u64], max_detail: usize) -> Comparison {
    let mut first_matches = 0usize;
    let mut second_matches = 0usize;
    let mut both_matches = 0usize;
    let mut first_keys = Vec::new();
    let mut second_keys = Vec::new();
    for entry in &report.entries {
        let first = keys.contains(&entry.first);
        let second = keys.contains(&entry.second);
        if first {
            first_matches += 1;
            if first_keys.len() < max_detail {
                first_keys.push(entry.first);
            }
        }
        if second {
            second_matches += 1;
            if second_keys.len() < max_detail {
                second_keys.push(entry.second);
            }
        }
        if first && second {
            both_matches += 1;
        }
    }
    let direction = if report.entries.is_empty() {
        Direction::NotEvaluated
    } else if both_matches > 0 {
        Direction::Ambiguous
    } else if first_matches > 0 && second_matches == 0 {
        Direction::FirstField
    } else if second_matches > 0 && first_matches == 0 {
        Direction::SecondField
    } else {
        Direction::Unresolved
    };
    Comparison {
        entries: report.entries.len(),
        first_distinct: report.first_distinct,
        second_distinct: report.second_distinct,
        first_matches,
        second_matches,
        both_matches,
        first_keys,
        second_keys,
        direction,
    }
}
