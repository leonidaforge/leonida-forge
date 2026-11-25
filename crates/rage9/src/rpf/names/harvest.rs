//! Candidate strings from payloads and executables, and the bounded variants
//! that are hashed against an index.
//!
//! Extraction is deliberately conservative: only printable ASCII, valid
//! non-control UTF-8 and ASCII-only UTF-16LE runs, and only strings that look
//! like paths or file names. A match still proves only that the text hashes to
//! a stored key, not that the game used that text as a filename.

use std::collections::HashSet;

use super::table::checked_name;
use super::{Class, Key, hash64, joaat};

/// Shortest accepted candidate.
pub const MIN_STRING: usize = 4;
/// Longest accepted candidate.
pub const MAX_STRING: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub min_len: usize,
    pub max_len: usize,
    pub max_strings: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            min_len: MIN_STRING,
            max_len: MAX_STRING,
            max_strings: 100_000,
        }
    }
}

/// How a variant relates to the extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VariantKind {
    Exact,
    Stem,
    AfterScheme,
    AfterSchemeStem,
    Trimmed,
    TrimmedStem,
}

impl VariantKind {
    pub fn text(self) -> &'static str {
        match self {
            VariantKind::Exact => "exact",
            VariantKind::Stem => "stem",
            VariantKind::AfterScheme => "after_scheme",
            VariantKind::AfterSchemeStem => "after_scheme_stem",
            VariantKind::Trimmed => "trimmed",
            VariantKind::TrimmedStem => "trimmed_stem",
        }
    }
}

/// Text to hash plus the filename that should be shown if it matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Variant {
    /// The text whose engine hash is calculated.
    pub text: String,
    /// A relative candidate filename with its extension, for display and LUT
    /// export.
    pub display: String,
    pub kind: VariantKind,
}

/// Extracts candidate path-like strings from `bytes`.
pub fn extract_strings(bytes: &[u8], limits: Limits) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    scan_utf8(bytes, limits, &mut seen, &mut out);
    scan_utf16le(bytes, limits, &mut seen, &mut out);
    out
}

fn push_candidate(
    candidate: &str,
    limits: Limits,
    seen: &mut HashSet<String>,
    out: &mut Vec<String>,
) {
    let trimmed = candidate.trim_matches([' ', '\t']);
    push_one(trimmed, limits, seen, out);
    if trimmed.contains(' ') {
        for token in trimmed.split_whitespace() {
            push_one(token, limits, seen, out);
        }
    }
}

fn push_one(candidate: &str, limits: Limits, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    if out.len() >= limits.max_strings {
        return;
    }
    if candidate.len() < limits.min_len || candidate.len() > limits.max_len {
        return;
    }
    if checked_name(candidate).is_none() || !looks_like_name(candidate) {
        return;
    }
    if seen.insert(candidate.to_string()) {
        out.push(candidate.to_string());
    }
}

fn scan_utf8(bytes: &[u8], limits: Limits, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    let mut current = String::new();
    let mut overflowed = false;
    let mut i = 0;
    while i < bytes.len() {
        if out.len() >= limits.max_strings {
            return;
        }
        match decode_char(&bytes[i..]) {
            Some((character, len)) if is_name_char(character) => {
                if !overflowed {
                    current.push(character);
                    if current.len() > limits.max_len {
                        current.clear();
                        overflowed = true;
                    }
                }
                i += len;
            }
            Some((_, len)) => {
                if !overflowed && !current.is_empty() {
                    push_candidate(&current, limits, seen, out);
                }
                current.clear();
                overflowed = false;
                i += len;
            }
            None => {
                if !overflowed && !current.is_empty() {
                    push_candidate(&current, limits, seen, out);
                }
                current.clear();
                overflowed = false;
                i += 1;
            }
        }
    }
    if !overflowed && !current.is_empty() {
        push_candidate(&current, limits, seen, out);
    }
}

fn scan_utf16le(bytes: &[u8], limits: Limits, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    let mut current = String::new();
    let mut overflowed = false;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if out.len() >= limits.max_strings {
            return;
        }
        let low = bytes[i];
        let high = bytes[i + 1];
        if high == 0 && low.is_ascii() && is_name_char(char::from(low)) {
            if !overflowed {
                current.push(char::from(low));
                if current.len() > limits.max_len {
                    current.clear();
                    overflowed = true;
                }
            }
            i += 2;
        } else {
            if !overflowed && !current.is_empty() {
                push_candidate(&current, limits, seen, out);
            }
            current.clear();
            overflowed = false;
            i += 1;
        }
    }
    if !overflowed && !current.is_empty() {
        push_candidate(&current, limits, seen, out);
    }
}

fn decode_char(bytes: &[u8]) -> Option<(char, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        let character = char::from(first);
        return (!character.is_control()).then_some((character, 1));
    }
    let len = match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    let end = len.min(bytes.len());
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    let character = text.chars().next()?;
    (!character.is_control()).then_some((character, character.len_utf8()))
}

fn is_name_char(character: char) -> bool {
    character.is_alphanumeric()
        || matches!(
            character,
            '_' | '-'
                | '.'
                | '/'
                | '\\'
                | ' '
                | ':'
                | '@'
                | '+'
                | '~'
                | '$'
                | '%'
                | '&'
                | '\''
                | '('
                | ')'
                | '['
                | ']'
                | ','
                | '#'
                | '!'
        )
}

fn looks_like_name(text: &str) -> bool {
    if text.starts_with("http://") || text.starts_with("https://") {
        return false;
    }
    if text.starts_with(['/', '\\', '.']) || text.ends_with(['/', '\\', '.']) {
        return false;
    }
    if text.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    text.chars().any(|c| c.is_ascii_alphanumeric())
        && text.chars().any(|c| matches!(c, '.' | '/' | '\\'))
}

/// A small, evidence-bounded set of variants. Absolute scheme prefixes and
/// leading separators are removed; a stem is the text before the last `.`, as
/// the engine splits it.
pub fn candidate_variants(name: &str) -> Vec<Variant> {
    let mut bases: Vec<(String, VariantKind, VariantKind)> =
        vec![(name.to_string(), VariantKind::Exact, VariantKind::Stem)];
    if let Some(relative) = after_scheme(name)
        && relative != name
    {
        bases.push((
            relative.to_string(),
            VariantKind::AfterScheme,
            VariantKind::AfterSchemeStem,
        ));
    }
    let trimmed = name.trim_start_matches(['/', '\\']);
    if trimmed != name {
        bases.push((
            trimmed.to_string(),
            VariantKind::Trimmed,
            VariantKind::TrimmedStem,
        ));
    }

    let mut variants = Vec::new();
    let mut seen = HashSet::new();
    for (base, exact_kind, stem_kind) in bases {
        let mut push = |text: &str, display: &str, kind| {
            let variant = Variant {
                text: text.to_string(),
                display: display.to_string(),
                kind,
            };
            if seen.insert((variant.text.clone(), variant.kind)) {
                variants.push(variant);
            }
        };
        push(&base, &base, exact_kind);
        if let Some(dot) = base.rfind('.') {
            let stem = &base[..dot];
            if !stem.is_empty() && stem != base {
                push(stem, &base, stem_kind);
            }
        }
        if variants.len() >= 6 {
            break;
        }
    }
    variants
}

fn after_scheme(name: &str) -> Option<&str> {
    let colon = name.find(':')?;
    let rest = name.get(colon + 1..)?;
    let rest = rest.strip_prefix('/').or_else(|| rest.strip_prefix('\\'))?;
    // Do not treat a drive letter such as `D:` as a scheme.
    if colon == 1 && name.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }
    (!rest.is_empty()).then_some(rest)
}

/// The keys to query for `variant` in `class`.
///
/// A 64-bit key is always the stem, or the whole text when there is no dot.
/// A 32-bit key is the engine's fallback for an extension that maps to no
/// type, so both the whole text and its stem are queried. The variant list
/// already contains both, so each variant yields one key.
pub fn hash_variant(variant: &Variant, class: Class) -> Option<Key> {
    match class {
        Class::Hash64 => {
            let text = variant.text.as_str();
            if text.rfind('.').is_some() {
                None
            } else {
                Some(Key::Hash64(hash64(text.as_bytes())))
            }
        }
        Class::Key32 => Some(Key::Key32(joaat(variant.text.as_bytes()))),
    }
}

#[cfg(test)]
mod tests;
