//! Local name tables: text supplied by the user that maps stored keys to
//! names.
//!
//! The format is line based and UTF-8. A blank line and a line whose first
//! byte is `#` are ignored. Every other line is one of:
//!
//! - a candidate path, relative to the archive or including the mount prefix;
//! - `hash64:HASH<TAB>NAME` or `key32:HASH<TAB>NAME`, an explicitly declared
//!   stored key and the name claimed for it.
//!
//! A declared key is verified by hashing the normalized name where the
//! algorithm is known. A line that cannot be parsed is skipped and counted,
//! never guessed at.
//!
//! Plain candidate lines are the original `.names.txt` format and keep
//! working unchanged. A line that contains a tab is always a mapping, so a
//! path with a tab cannot be written.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use super::{Key, fold};

/// Larger tables are not read.
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Longer lines are skipped.
pub const MAX_LINE: usize = 4096;
/// At most this many entries are kept.
pub const MAX_ENTRIES: usize = 1 << 20;

/// Where a name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provenance {
    /// A candidate path, tested against the rows by hashing.
    CandidatePath,
    /// A name declared next to a stored key in the table.
    UserMapping,
}

impl Provenance {
    pub fn text(self) -> &'static str {
        match self {
            Provenance::CandidatePath => "candidate_path",
            Provenance::UserMapping => "user_mapping",
        }
    }
}

/// One parsed line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableEntry {
    pub name: String,
    pub provenance: Provenance,
    /// The key the name is claimed for. `None` for a candidate path, which is
    /// hashed instead.
    pub declared: Option<Key>,
}

/// A parsed table and what was not accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringTable {
    entries: Vec<TableEntry>,
    skipped: usize,
    duplicates: usize,
    truncated: bool,
}

impl StringTable {
    /// Reads at most [`MAX_BYTES`] from `path`. The file is only read, never
    /// written.
    pub fn read(path: &Path) -> io::Result<Self> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let truncated = bytes.len() as u64 > MAX_BYTES;
        if truncated {
            bytes.truncate(MAX_BYTES as usize);
        }
        Ok(Self::parse(&bytes, truncated))
    }

    /// Parses `bytes`. `truncated` says that they are only the start of a
    /// larger file, so a final line without a newline is incomplete and is
    /// dropped.
    pub fn parse(bytes: &[u8], truncated: bool) -> Self {
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let mut table = Self {
            truncated,
            ..Self::default()
        };
        let mut seen: HashSet<TableEntry> = HashSet::new();
        let mut parts: Vec<&[u8]> = bytes.split(|&byte| byte == b'\n').collect();
        if truncated && parts.last().is_some_and(|line| !line.is_empty()) {
            parts.pop();
        }
        for raw in parts {
            let line = raw.strip_suffix(b"\r").unwrap_or(raw);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            if line.len() > MAX_LINE {
                table.skipped += 1;
                continue;
            }
            let Ok(text) = std::str::from_utf8(line) else {
                table.skipped += 1;
                continue;
            };
            let Some(entry) = parse_entry(text) else {
                table.skipped += 1;
                continue;
            };
            if !seen.insert(entry.clone()) {
                table.duplicates += 1;
                continue;
            }
            if table.entries.len() >= MAX_ENTRIES {
                table.truncated = true;
                break;
            }
            table.entries.push(entry);
        }
        table
    }

    pub fn entries(&self) -> &[TableEntry] {
        &self.entries
    }

    /// Lines that were not valid entries: malformed, too long, not UTF-8 or
    /// controlled bytes.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Valid lines dropped because the same entry appeared earlier.
    pub fn duplicates(&self) -> usize {
        self.duplicates
    }

    /// Whether the byte or entry limit cut the input short.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn candidates(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.provenance == Provenance::CandidatePath)
            .count()
    }

    pub fn mappings(&self) -> usize {
        self.entries.len() - self.candidates()
    }
}

fn parse_entry(line: &str) -> Option<TableEntry> {
    match line.split_once('\t') {
        Some((key, name)) => {
            // A second tab means the line is not a two-field mapping.
            if name.contains('\t') {
                return None;
            }
            Some(TableEntry {
                name: checked_name(name)?,
                provenance: Provenance::UserMapping,
                declared: Some(parse_key(key)?),
            })
        }
        None => Some(TableEntry {
            name: checked_name(line)?,
            provenance: Provenance::CandidatePath,
            declared: None,
        }),
    }
}

/// `hash64:HEX` or `key32:HEX`, with an optional `0x` prefix.
fn parse_key(text: &str) -> Option<Key> {
    let (namespace, value) = text.split_once(':')?;
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) || value.len() > 16 {
        return None;
    }
    let digits = u64::from_str_radix(value, 16).ok()?;
    match namespace {
        "hash64" => Some(Key::Hash64(digits)),
        "key32" if value.len() <= 8 => Some(Key::Key32(digits as u32)),
        _ => None,
    }
}

/// A name is display data: it must be UTF-8 without control characters or
/// bidi overrides, so it cannot carry terminal escapes, a NUL that the engine
/// would stop at, or text that displays as a different name.
fn checked_name(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    let invalid = bytes.is_empty()
        || bytes.len() > MAX_LINE
        || name.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
                )
        });
    (!invalid).then(|| name.to_string())
}

/// The normalized bytes two spellings are compared by.
pub(crate) fn normalized(name: &str) -> Vec<u8> {
    name.as_bytes().iter().copied().map(fold).collect()
}

#[cfg(test)]
mod tests;
