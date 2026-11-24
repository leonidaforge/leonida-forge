//! RPF9 entry names. An archive stores hashes of entry paths, not the paths.
//! [`match_candidates`] finds the rows that candidate paths from outside the
//! archive address, following the engine's resolver.
//!
//! The engine's extension and type class tables are executable data and are
//! not included. Only `rpf`, type 0 and its 64-bit class are built in; the
//! caller supplies anything else through [`Types`].
//!
//! Hashes and resolver rules follow the research documentation for
//! executable build e95020b2.

use std::collections::HashMap;

use super::metadata::{Entry, Error, Metadata};

/// The type ID of nested archives, extension `rpf`.
pub const RPF_TYPE: u8 = 0;
/// The type the resolver uses when the extension maps to no type, or the
/// path has no extension.
pub const NO_TYPE: u8 = 0xFF;
/// The limit of a prefix derived from an archive path.
pub const MAX_PREFIX_LEN: usize = 255;
/// The limit of an explicit mount prefix.
pub const MAX_MOUNT_PREFIX_LEN: usize = 253;

/// The byte mapping both hashes apply: ASCII upper case to lower case and `\`
/// to `/`. No other byte changes.
pub fn fold(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte + 0x20,
        b'\\' => b'/',
        _ => byte,
    }
}

const C1: u64 = 0x87C3_7B91_1142_53D5;
const C2: u64 = 0x4CF5_AD43_2745_937F;

fn mix_k1(k1: u64) -> u64 {
    k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2)
}

fn mix_k2(k2: u64) -> u64 {
    k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1)
}

fn fmix(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    k ^= k >> 33;
    k = k.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    k ^ (k >> 33)
}

fn words(block: [u8; 16]) -> (u64, u64) {
    let value = u128::from_le_bytes(block);
    (value as u64, (value >> 64) as u64)
}

/// The 64-bit path hash: the first word of MurmurHash3 x64-128 with seed 0
/// over the folded bytes. The engine mixes only the low byte of the length
/// into the final state, so from 256 bytes on the result differs from the
/// standard algorithm.
pub fn hash64(path: &[u8]) -> u64 {
    let (blocks, tail) = path.as_chunks::<16>();
    let (mut h1, mut h2) = (0u64, 0u64);
    for block in blocks {
        let (k1, k2) = words(block.map(fold));
        h1 ^= mix_k1(k1);
        h1 = h1.rotate_left(27).wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52DC_E729);
        h2 ^= mix_k2(k2);
        h2 = h2.rotate_left(31).wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x3849_5AB5);
    }
    if !tail.is_empty() {
        let mut block = [0; 16];
        for (to, &from) in block.iter_mut().zip(tail) {
            *to = fold(from);
        }
        let (k1, k2) = words(block);
        if tail.len() > 8 {
            h2 ^= mix_k2(k2);
        }
        h1 ^= mix_k1(k1);
    }
    let len = (path.len() & 0xFF) as u64;
    h1 ^= len;
    h2 ^= len;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    fmix(h1).wrapping_add(fmix(h2))
}

/// The 32-bit key: Jenkins one-at-a-time with seed 0 over the folded bytes.
/// Like the engine, it stops at a NUL byte. Input that starts with `"` is
/// hashed from the next byte up to the next `"`.
pub fn joaat(text: &[u8]) -> u32 {
    let (body, quoted) = match text {
        [b'"', rest @ ..] => (rest, true),
        _ => (text, false),
    };
    let mut h = 0u32;
    for &byte in body {
        if byte == 0 || (quoted && byte == b'"') {
            break;
        }
        h = h.wrapping_add(u32::from(fold(byte)));
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
    }
    h = h.wrapping_add(h << 3);
    h ^= h >> 11;
    h.wrapping_add(h << 15)
}

/// The part of a request path the engine compares as a whole, by its folded
/// hash, before it resolves the rest.
///
/// An archive starts with the prefix [`MountPrefix::from_archive_path`]
/// derives. Mounting it replaces that with the mount prefix
/// ([`MountPrefix::mounted`]). Which prefix applies is engine runtime state
/// that the archive does not record, so the caller chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountPrefix {
    pub len: usize,
    pub hash: u64,
}

impl MountPrefix {
    /// Matches every path. Candidates are then relative to the archive.
    pub const EMPTY: Self = Self { len: 0, hash: 0 };

    /// The default prefix the engine derives from an archive's resolved path: up to
    /// and including the last `/` or `\`, or for a `memory:` path up to and
    /// including the next `:`, at most 255 bytes. The archive's file name is
    /// not part of it. `None` for a `memory:` path without a further `:`, whose
    /// handling is not established, and for a path with a NUL byte.
    pub fn from_archive_path(path: &[u8]) -> Option<Self> {
        if path.contains(&0) {
            return None;
        }
        let end = match path.strip_prefix(b"memory:") {
            Some(rest) => b"memory:".len() + rest.iter().position(|&b| b == b':')? + 1,
            None => path
                .iter()
                .rposition(|&b| b == b'/' || b == b'\\')
                .map_or(0, |separator| separator + 1),
        };
        let prefix = &path[..end.min(MAX_PREFIX_LEN)];
        Some(Self {
            len: prefix.len(),
            hash: hash64(prefix),
        })
    }

    /// An explicit mount prefix, which replaces the default when the engine
    /// mounts the archive. `None` unless the prefix is non-empty, ends in `/`
    /// or `\`, has at most 253 bytes and no NUL byte, as the engine's mount
    /// requires.
    pub fn mounted(prefix: &[u8]) -> Option<Self> {
        let valid = matches!(prefix.last(), Some(b'/' | b'\\'))
            && prefix.len() <= MAX_MOUNT_PREFIX_LEN
            && !prefix.contains(&0);
        valid.then(|| Self {
            len: prefix.len(),
            hash: hash64(prefix),
        })
    }

    fn strip<'p>(&self, path: &'p [u8]) -> Option<&'p [u8]> {
        let (head, rest) = path.split_at_checked(self.len)?;
        (hash64(head) == self.hash).then_some(rest)
    }
}

/// Which row field holds the key of a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// [`hash64`] of the stem, in the name hash column.
    Hash64,
    /// [`joaat`] of the stem, in the 32-bit key column.
    Key32,
}

/// Extension to type ID and type ID to class mappings.
#[derive(Debug, Clone)]
pub struct Types {
    extensions: Vec<(Vec<u8>, u8)>,
    classes: [Option<Class>; 256],
}

impl Default for Types {
    /// Only `rpf` to type 0, of the 64-bit class.
    fn default() -> Self {
        let mut classes = [None; 256];
        classes[usize::from(RPF_TYPE)] = Some(Class::Hash64);
        Self {
            extensions: vec![(b"rpf".to_vec(), RPF_TYPE)],
            classes,
        }
    }
}

impl Types {
    /// Maps `extension`, compared case-sensitively like the engine, to
    /// `type_id`. [`NO_TYPE`] records that the engine maps the extension to no
    /// type.
    pub fn insert_extension(&mut self, extension: &[u8], type_id: u8) {
        match self.extensions.iter_mut().find(|(e, _)| e == extension) {
            Some((_, existing)) => *existing = type_id,
            None => self.extensions.push((extension.to_vec(), type_id)),
        }
    }

    /// Type [`NO_TYPE`] always uses the 32-bit class, as in the resolver.
    pub fn insert_class(&mut self, type_id: u8, class: Class) {
        self.classes[usize::from(type_id)] = Some(class);
    }

    pub fn extension_type(&self, extension: &[u8]) -> Option<u8> {
        self.extensions
            .iter()
            .find(|(e, _)| e == extension)
            .map(|&(_, type_id)| type_id)
    }

    pub fn class(&self, type_id: u8) -> Option<Class> {
        if type_id == NO_TYPE {
            return Some(Class::Key32);
        }
        self.classes[usize::from(type_id)]
    }

    /// The row key and type a candidate addresses.
    pub fn resolve(
        &self,
        prefix: &MountPrefix,
        candidate: &Candidate,
    ) -> Result<Address, Unresolved> {
        match *candidate {
            Candidate::Path(path) => {
                if path.contains(&0) {
                    return Err(Unresolved::Nul);
                }
                let rest = prefix.strip(path).ok_or(Unresolved::OutsidePrefix)?;
                let Some(dot) = rest.iter().rposition(|&b| b == b'.') else {
                    return self.address(rest, NO_TYPE);
                };
                let extension = &rest[dot + 1..];
                match self.extension_type(extension) {
                    Some(NO_TYPE) => self.address(rest, NO_TYPE),
                    Some(type_id) => self.address(&rest[..dot], type_id),
                    None => Err(Unresolved::UnknownExtension(extension.to_vec())),
                }
            }
            Candidate::Stem { stem, type_id } => {
                if stem.contains(&0) {
                    return Err(Unresolved::Nul);
                }
                self.address(stem, type_id)
            }
        }
    }

    fn address(&self, stem: &[u8], type_id: u8) -> Result<Address, Unresolved> {
        let key = match self.class(type_id) {
            Some(Class::Hash64) => Key::Hash64(hash64(stem)),
            Some(Class::Key32) => Key::Key32(joaat(stem)),
            None => return Err(Unresolved::UnknownClass(type_id)),
        };
        Ok(Address {
            key,
            type_id,
            stem: stem.to_vec(),
        })
    }
}

/// A name to test against the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate<'a> {
    /// A request path, including the mount prefix if there is one. The engine
    /// splits the rest at its last `.` into stem and extension.
    Path(&'a [u8]),
    /// A stem relative to the mount prefix, without extension.
    Stem { stem: &'a [u8], type_id: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Hash64(u64),
    Key32(u32),
}

/// What a candidate resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub key: Key,
    pub type_id: u8,
    /// The hashed bytes. For [`NO_TYPE`] that is the whole rest, extension
    /// included.
    pub stem: Vec<u8>,
}

/// Why a candidate addresses no row key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolved {
    /// The engine reads paths as C strings.
    Nul,
    OutsidePrefix,
    /// The extension's type is not known. It is not assumed to be
    /// [`NO_TYPE`], because the engine may map it to a type.
    UnknownExtension(Vec<u8>),
    /// The class of the type is not known.
    UnknownClass(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateMatch {
    pub address: Address,
    /// Every row with the candidate's key and type, in row order. Empty if
    /// none has. The engine's linear scan returns the first.
    pub rows: Vec<u32>,
}

/// A row with the candidates that address it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub index: u32,
    pub type_id: u8,
    pub name_hash: Option<u64>,
    pub name_key: Option<u32>,
    /// Indices into the candidate list, in candidate order. Duplicates are
    /// kept.
    pub candidates: Vec<usize>,
    /// Whether candidates with different folded stems address this row, so
    /// that the hashes cannot tell which name is right.
    pub ambiguous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matches {
    /// Every row, in row order, matched or not.
    pub rows: Vec<Row>,
    /// One result per candidate, in candidate order.
    pub candidates: Vec<Result<CandidateMatch, Unresolved>>,
}

impl Matches {
    /// The match result of the entry in row `row`.
    pub fn row(&self, row: u32) -> Option<&Row> {
        self.rows.iter().find(|r| r.index == row)
    }
}

/// Matches candidates against the rows of decoded metadata. `prefix` is the
/// effective prefix of the archive. Rows are searched exhaustively, without
/// the engine's sorted lookup.
pub fn match_candidates(
    metadata: &Metadata,
    prefix: &MountPrefix,
    types: &Types,
    candidates: &[Candidate],
) -> Result<Matches, Error> {
    let entries: Vec<Entry> = metadata.entries().collect();
    match_entries(&entries, prefix, types, candidates)
}

/// [`match_candidates`] over entries that were already read. Every entry
/// needs a location record and well-formed name fields.
pub fn match_entries(
    entries: &[Entry],
    prefix: &MountPrefix,
    types: &Types,
    candidates: &[Candidate],
) -> Result<Matches, Error> {
    let mut rows = Vec::with_capacity(entries.len());
    let mut index: HashMap<(Key, u8), Vec<usize>> = HashMap::new();
    for (position, entry) in entries.iter().enumerate() {
        let type_id = match &entry.location {
            Ok(Some(location)) => location.type_id,
            Ok(None) => {
                return Err(Error::Invalid(format!(
                    "row {} has no location record",
                    entry.row
                )));
            }
            Err(reason) => return Err(Error::Invalid(reason.clone())),
        };
        let name_hash = entry.name_hash.clone().map_err(Error::Invalid)?;
        let name_key = entry.name_key.clone().map_err(Error::Invalid)?;
        let keys = [name_hash.map(Key::Hash64), name_key.map(Key::Key32)];
        for key in keys.into_iter().flatten() {
            index.entry((key, type_id)).or_default().push(position);
        }
        rows.push(Row {
            index: entry.row,
            type_id,
            name_hash,
            name_key,
            candidates: Vec::new(),
            ambiguous: false,
        });
    }

    let mut first_stem: Vec<Option<Vec<u8>>> = vec![None; rows.len()];
    let results = candidates
        .iter()
        .enumerate()
        .map(|(number, candidate)| {
            let address = types.resolve(prefix, candidate)?;
            let matched = index
                .get(&(address.key, address.type_id))
                .map(Vec::as_slice)
                .unwrap_or_default();
            let folded: Vec<u8> = address.stem.iter().copied().map(fold).collect();
            for &position in matched {
                let row = &mut rows[position];
                row.candidates.push(number);
                match &first_stem[position] {
                    Some(stem) => row.ambiguous |= *stem != folded,
                    None => first_stem[position] = Some(folded.clone()),
                }
            }
            Ok(CandidateMatch {
                address,
                rows: matched
                    .iter()
                    .map(|&position| rows[position].index)
                    .collect(),
            })
        })
        .collect();
    Ok(Matches {
        rows,
        candidates: results,
    })
}

#[cfg(test)]
mod tests;
