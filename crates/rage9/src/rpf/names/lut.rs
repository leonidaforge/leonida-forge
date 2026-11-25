//! Leonida Forge LUT v1: a versioned, namespace-specific text file of
//! hash-to-name mappings.
//!
//! The first records are declarations:
//!
//! ```text
//! # leonida-forge-lut: 1
//! # namespace: hash64
//! ```
//!
//! Every other non-comment line is `HASH<TAB>NAME`. Hashes use a `0x` prefix,
//! exactly 16 digits for `hash64` and exactly 8 for `key32`, and are written
//! in uppercase. Names are UTF-8 display strings without control characters
//! and keep their internal spaces. Records are sorted by hash and then name,
//! so serialization is deterministic. Exact duplicates are dropped; different
//! names for one hash are kept as separate candidates.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

use super::resolve::verifies;
use super::table::{MAX_ENTRIES, MAX_LINE, checked_name};
use super::{Class, Key};

/// The only supported format version.
pub const VERSION: u32 = 1;
/// Larger LUT files are rejected.
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;

const VERSION_MARKER: &str = "# leonida-forge-lut:";
const NAMESPACE_MARKER: &str = "# namespace:";

#[derive(Debug)]
pub enum LutError {
    Io(io::Error),
    TooLarge { len: u64, limit: u64 },
    Invalid { line: usize, message: String },
}

impl fmt::Display for LutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LutError::Io(err) => err.fmt(f),
            LutError::TooLarge { len, limit } => write!(
                f,
                "the LUT is {len} bytes, larger than the {limit}-byte limit"
            ),
            LutError::Invalid { line, message } => write!(f, "line {line}: {message}"),
        }
    }
}

impl std::error::Error for LutError {}

impl From<io::Error> for LutError {
    fn from(err: io::Error) -> Self {
        LutError::Io(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LutEntry {
    pub hash: Key,
    pub name: String,
    /// Whether hashing the name or its stem reproduces `hash`.
    pub verified: bool,
}

/// One namespace and its mappings, in canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lut {
    namespace: Class,
    entries: Vec<LutEntry>,
    duplicates: usize,
}

impl Lut {
    /// Reads a LUT. Oversized files, malformed records and missing or
    /// conflicting declarations are errors.
    pub fn read(path: &Path) -> Result<Self, LutError> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(LutError::TooLarge {
                len: bytes.len() as u64,
                limit: MAX_BYTES,
            });
        }
        Self::parse(&bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, LutError> {
        let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
        let mut version = None;
        let mut namespace = None;
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        let mut duplicates = 0;
        for (number, raw) in bytes.split(|&byte| byte == b'\n').enumerate() {
            let line_number = number + 1;
            let line = raw.strip_suffix(b"\r").unwrap_or(raw);
            let text = std::str::from_utf8(line).map_err(|_| invalid(line_number, "not UTF-8"))?;
            let trimmed = text.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix(VERSION_MARKER) {
                let declared: u32 = rest
                    .trim()
                    .parse()
                    .map_err(|_| invalid(line_number, "the format version is not a number"))?;
                if declared != VERSION {
                    return Err(invalid(
                        line_number,
                        &format!("unsupported format version {declared}; expected {VERSION}"),
                    ));
                }
                version = Some(declared);
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix(NAMESPACE_MARKER) {
                let declared = Class::parse_namespace(rest.trim())
                    .ok_or_else(|| invalid(line_number, "the namespace is not hash64 or key32"))?;
                match namespace {
                    Some(previous) if previous != declared => {
                        return Err(invalid(line_number, "the namespace is declared twice"));
                    }
                    _ => namespace = Some(declared),
                }
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
            let namespace = namespace
                .ok_or_else(|| invalid(line_number, "a record appears before the namespace"))?;
            version.ok_or_else(|| {
                invalid(line_number, "a record appears before the format version")
            })?;
            let (hash, name) = text
                .split_once('\t')
                .ok_or_else(|| invalid(line_number, "the record has no tab"))?;
            if name.contains('\t') {
                return Err(invalid(line_number, "the name contains a tab"));
            }
            let hash = parse_hash(hash.trim(), namespace, line_number)?;
            let name = checked_name(name)
                .ok_or_else(|| invalid(line_number, "the name is empty or contains controls"))?;
            if line.len() > MAX_LINE {
                return Err(invalid(line_number, "the line is too long"));
            }
            let entry = LutEntry {
                verified: verifies(&name, hash),
                hash,
                name,
            };
            if !seen.insert(entry.clone()) {
                duplicates += 1;
                continue;
            }
            if entries.len() >= MAX_ENTRIES {
                return Err(invalid(
                    line_number,
                    &format!("more than {MAX_ENTRIES} entries"),
                ));
            }
            entries.push(entry);
        }
        let version_ok = version.ok_or_else(|| invalid(0, "the format version is missing"))?;
        if version_ok != VERSION {
            return Err(invalid(0, "unsupported format version"));
        }
        let namespace = namespace.ok_or_else(|| invalid(0, "the namespace is missing"))?;
        entries.sort_by(|a, b| {
            a.hash
                .value()
                .cmp(&b.hash.value())
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(Self {
            namespace,
            entries,
            duplicates,
        })
    }

    /// Builds a canonical LUT from mappings. Every key must belong to
    /// `namespace`; names are validated and exact duplicates are dropped.
    pub fn new(
        namespace: Class,
        mappings: impl IntoIterator<Item = (Key, String)>,
    ) -> Result<Self, LutError> {
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        let mut duplicates = 0;
        for (hash, name) in mappings {
            if hash.class() != namespace {
                return Err(invalid(
                    0,
                    &format!(
                        "{} is not a {} key",
                        hash.canonical(),
                        namespace.namespace()
                    ),
                ));
            }
            let name = checked_name(&name)
                .ok_or_else(|| invalid(0, "a name is empty or contains controls"))?;
            let entry = LutEntry {
                verified: verifies(&name, hash),
                hash,
                name,
            };
            if !seen.insert(entry.clone()) {
                duplicates += 1;
                continue;
            }
            if entries.len() >= MAX_ENTRIES {
                return Err(invalid(0, &format!("more than {MAX_ENTRIES} entries")));
            }
            entries.push(entry);
        }
        entries.sort_by(|a, b| {
            a.hash
                .value()
                .cmp(&b.hash.value())
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(Self {
            namespace,
            entries,
            duplicates,
        })
    }

    pub fn namespace(&self) -> Class {
        self.namespace
    }

    pub fn entries(&self) -> &[LutEntry] {
        &self.entries
    }

    pub fn duplicates(&self) -> usize {
        self.duplicates
    }

    pub fn verified(&self) -> usize {
        self.entries.iter().filter(|entry| entry.verified).count()
    }

    /// Canonical text: declarations, a blank line, then sorted records.
    pub fn to_text(&self) -> String {
        let mut text = format!(
            "{VERSION_MARKER} {VERSION}\n{NAMESPACE_MARKER} {}\n\n",
            self.namespace.namespace()
        );
        for entry in &self.entries {
            text.push_str(&entry.hash.canonical());
            text.push('\t');
            text.push_str(&entry.name);
            text.push('\n');
        }
        text
    }
}

fn parse_hash(text: &str, namespace: Class, line: usize) -> Result<Key, LutError> {
    let hex = text
        .strip_prefix("0x")
        .ok_or_else(|| invalid(line, "the hash has no 0x prefix"))?;
    let width = namespace.width();
    if hex.len() != width {
        return Err(invalid(
            line,
            &format!(
                "a {} hash needs exactly {width} hexadecimal digits",
                namespace.namespace()
            ),
        ));
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(line, "the hash is not hexadecimal"));
    }
    let value = u64::from_str_radix(hex, 16).map_err(|_| invalid(line, "the hash is invalid"))?;
    Ok(match namespace {
        Class::Hash64 => Key::Hash64(value),
        Class::Key32 => Key::Key32(value as u32),
    })
}

fn invalid(line: usize, message: &str) -> LutError {
    LutError::Invalid {
        line,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests;
