//! Resolving stored name hashes to candidate names from a local table.
//!
//! A hash is one way: several names can have it and most stored hashes have
//! no name. A candidate is therefore a suggestion with provenance and a
//! verification state, never a replacement for the stored key.
//!
//! A candidate path is tested the way the engine addresses a row: normalized,
//! split into stem and extension, hashed with the type's class and compared
//! with the row's key and type ID. It is verified by construction.
//!
//! A declared mapping names a stored key directly. It is verified only when
//! the normalized name, or its stem before the last `.`, hashes to the
//! declared key with the declared class. Otherwise it stays an unconfirmed
//! suggestion.

use std::collections::HashMap;

use super::table::{Provenance, StringTable, normalized};
use super::{Candidate, Class, Key, MountPrefix, Types, Unresolved, hash64, joaat};
use crate::rpf::metadata::Entry;

/// What a row's stored keys and type say about the hash namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Hash64,
    Key32,
    /// Candidates from both classes address the row.
    Mixed,
    /// The type's class is unknown and the row stores both keys or none.
    Unknown,
}

impl Namespace {
    pub fn text(self) -> Option<&'static str> {
        match self {
            Namespace::Hash64 => Some("hash64"),
            Namespace::Key32 => Some("key32"),
            Namespace::Mixed => Some("mixed"),
            Namespace::Unknown => None,
        }
    }
}

impl From<Class> for Namespace {
    fn from(class: Class) -> Self {
        match class {
            Class::Hash64 => Namespace::Hash64,
            Class::Key32 => Namespace::Key32,
        }
    }
}

/// One name that addresses a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub text: String,
    pub provenance: Provenance,
    pub algorithm: Class,
    /// Whether hashing the normalized name reproduces the stored key.
    pub verified: bool,
}

/// The resolution of one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Unresolved,
    /// One normalized name, possibly written in several spellings.
    Resolved(Vec<Name>),
    /// Different normalized names share the row's key.
    Ambiguous(Vec<Name>),
}

impl Resolution {
    pub fn names(&self) -> &[Name] {
        match self {
            Resolution::Unresolved => &[],
            Resolution::Resolved(names) | Resolution::Ambiguous(names) => names,
        }
    }

    pub fn is_resolved(&self) -> bool {
        matches!(self, Resolution::Resolved(_))
    }

    pub fn is_ambiguous(&self) -> bool {
        matches!(self, Resolution::Ambiguous(_))
    }

    pub fn is_unresolved(&self) -> bool {
        matches!(self, Resolution::Unresolved)
    }
}

/// A row with its resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowNames {
    pub row: u32,
    pub namespace: Namespace,
    pub resolution: Resolution,
}

/// What became of one table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateOutcome {
    /// The key and type matched these rows, in row order.
    Matched(Vec<u32>),
    /// The key is well defined but no row has it.
    NoRow,
    /// The entry does not address a row at all.
    Unresolved(Unresolved),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateResult {
    /// Index into the table's entries.
    pub index: usize,
    pub name: String,
    pub provenance: Provenance,
    pub verified: bool,
    pub outcome: CandidateOutcome,
}

/// Every row, in table order, and every table entry's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionSet {
    pub rows: Vec<RowNames>,
    pub candidates: Vec<CandidateResult>,
    /// Rows whose name fields did not parse. They are never matched.
    pub unusable_rows: usize,
}

impl ResolutionSet {
    pub fn row(&self, row: u32) -> Option<&RowNames> {
        self.rows.iter().find(|names| names.row == row)
    }
}

/// Resolves table entries against entries that were already read.
pub struct Resolver<'a> {
    table: &'a StringTable,
    types: &'a Types,
    prefix: MountPrefix,
}

/// The stored keys of one valid row.
struct RowKey {
    row: u32,
    type_id: Option<u8>,
    hash: Option<u64>,
    key: Option<u32>,
}

impl<'a> Resolver<'a> {
    pub fn new(table: &'a StringTable, types: &'a Types, prefix: MountPrefix) -> Self {
        Self {
            table,
            types,
            prefix,
        }
    }

    pub fn resolve(&self, entries: &[Entry]) -> ResolutionSet {
        let mut rows: Vec<RowNames> = Vec::with_capacity(entries.len());
        let mut keys: Vec<RowKey> = Vec::with_capacity(entries.len());
        let mut index: HashMap<(Class, u64), Vec<usize>> = HashMap::new();
        let mut position_by_row: HashMap<u32, usize> = HashMap::new();
        let mut unusable_rows = 0;
        for entry in entries {
            let mut unusable = false;
            let hash = match &entry.name_hash {
                Ok(value) => *value,
                Err(_) => {
                    unusable = true;
                    None
                }
            };
            let key = match &entry.name_key {
                Ok(value) => *value,
                Err(_) => {
                    unusable = true;
                    None
                }
            };
            if unusable {
                unusable_rows += 1;
            }
            let position = rows.len();
            position_by_row.insert(entry.row, position);
            if let Some(hash) = hash {
                index
                    .entry((Class::Hash64, hash))
                    .or_default()
                    .push(position);
            }
            if let Some(key) = key {
                index
                    .entry((Class::Key32, u64::from(key)))
                    .or_default()
                    .push(position);
            }
            keys.push(RowKey {
                row: entry.row,
                type_id: entry.type_id(),
                hash,
                key,
            });
            rows.push(RowNames {
                row: entry.row,
                namespace: Namespace::Unknown,
                resolution: Resolution::Unresolved,
            });
        }

        let mut found: Vec<Vec<Name>> = vec![Vec::new(); entries.len()];
        let candidate_results = self
            .table
            .entries()
            .iter()
            .enumerate()
            .map(|(number, entry)| {
                let (outcome, name, verified) = match entry.declared {
                    None => self.path_candidate(entry.name.as_bytes(), &keys, &index),
                    Some(key) => self.user_mapping(&entry.name, key, &keys, &index),
                };
                if let CandidateOutcome::Matched(rows) = &outcome
                    && let Some(name) = name
                {
                    for row in rows {
                        if let Some(&position) = position_by_row.get(row) {
                            add_name(&mut found[position], name.clone());
                        }
                    }
                }
                CandidateResult {
                    index: number,
                    name: entry.name.clone(),
                    provenance: entry.provenance,
                    verified,
                    outcome,
                }
            })
            .collect();

        for (position, names) in found.into_iter().enumerate() {
            rows[position].namespace = namespace(&keys[position], &names, self.types);
            rows[position].resolution = classify(names);
        }
        ResolutionSet {
            rows,
            candidates: candidate_results,
            unusable_rows,
        }
    }

    fn path_candidate(
        &self,
        name: &[u8],
        keys: &[RowKey],
        index: &HashMap<(Class, u64), Vec<usize>>,
    ) -> (CandidateOutcome, Option<Name>, bool) {
        let address = match self.types.resolve(&self.prefix, &Candidate::Path(name)) {
            Ok(address) => address,
            Err(err) => return (CandidateOutcome::Unresolved(err), None, false),
        };
        let (class, value) = match address.key {
            Key::Hash64(hash) => (Class::Hash64, hash),
            Key::Key32(key) => (Class::Key32, u64::from(key)),
        };
        let rows: Vec<u32> = index
            .get(&(class, value))
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|&&position| keys[position].type_id == Some(address.type_id))
            .map(|&position| keys[position].row)
            .collect();
        let name = (!rows.is_empty()).then(|| Name {
            text: String::from_utf8_lossy(name).into_owned(),
            provenance: Provenance::CandidatePath,
            algorithm: class,
            verified: true,
        });
        (outcome(rows), name, true)
    }

    fn user_mapping(
        &self,
        name: &str,
        declared: Key,
        keys: &[RowKey],
        index: &HashMap<(Class, u64), Vec<usize>>,
    ) -> (CandidateOutcome, Option<Name>, bool) {
        let (class, value) = match declared {
            Key::Hash64(hash) => (Class::Hash64, hash),
            Key::Key32(key) => (Class::Key32, u64::from(key)),
        };
        let verified = verifies(name, declared);
        let rows: Vec<u32> = index
            .get(&(class, value))
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            // A type whose class is known only matches its own class, so the
            // 32-bit and 64-bit namespaces stay apart.
            .filter(|&&position| match keys[position].type_id {
                Some(type_id) => match self.types.class(type_id) {
                    Some(row_class) => row_class == class,
                    None => true,
                },
                None => true,
            })
            .map(|&position| keys[position].row)
            .collect();
        let name = (!rows.is_empty()).then(|| Name {
            text: name.to_string(),
            provenance: Provenance::UserMapping,
            algorithm: class,
            verified,
        });
        (outcome(rows), name, verified)
    }
}

fn outcome(rows: Vec<u32>) -> CandidateOutcome {
    if rows.is_empty() {
        CandidateOutcome::NoRow
    } else {
        CandidateOutcome::Matched(rows)
    }
}

/// Keeps one entry per spelling, preferring a verified candidate path over a
/// verified mapping over an unconfirmed mapping.
fn add_name(names: &mut Vec<Name>, name: Name) {
    match names.iter_mut().find(|known| known.text == name.text) {
        Some(known) if strength(&name) > strength(known) => *known = name,
        Some(_) => {}
        None => names.push(name),
    }
}

fn strength(name: &Name) -> u8 {
    match (name.provenance, name.verified) {
        (Provenance::CandidatePath, _) => 3,
        (Provenance::UserMapping, true) => 2,
        (Provenance::UserMapping, false) => 1,
    }
}

/// Whether the engine's hashes of the name, or of its stem, reproduce the
/// declared key. This proves the name is a preimage, not that the archive
/// named the entry.
pub(crate) fn verifies(name: &str, declared: Key) -> bool {
    let bytes = name.as_bytes();
    let stem = match bytes.iter().rposition(|&byte| byte == b'.') {
        Some(dot) => &bytes[..dot],
        None => bytes,
    };
    [bytes, stem].into_iter().any(|candidate| match declared {
        Key::Hash64(hash) => hash64(candidate) == hash,
        Key::Key32(key) => joaat(candidate) == key,
    })
}

fn classify(names: Vec<Name>) -> Resolution {
    if names.is_empty() {
        return Resolution::Unresolved;
    }
    let mut folded = names.iter().map(|name| normalized(&name.text));
    let first = folded.next().unwrap_or_default();
    if folded.all(|other| other == first) {
        Resolution::Resolved(names)
    } else {
        Resolution::Ambiguous(names)
    }
}

fn namespace(row: &RowKey, names: &[Name], types: &Types) -> Namespace {
    let mut hash64 = false;
    let mut key32 = false;
    for name in names {
        match name.algorithm {
            Class::Hash64 => hash64 = true,
            Class::Key32 => key32 = true,
        }
    }
    match (hash64, key32) {
        (true, true) => return Namespace::Mixed,
        (true, false) => return Namespace::Hash64,
        (false, true) => return Namespace::Key32,
        (false, false) => {}
    }
    if let Some(class) = row.type_id.and_then(|type_id| types.class(type_id)) {
        return class.into();
    }
    match (row.hash.is_some(), row.key.is_some()) {
        (true, false) => Namespace::Hash64,
        (false, true) => Namespace::Key32,
        _ => Namespace::Unknown,
    }
}

#[cfg(test)]
mod tests;
