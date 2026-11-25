//! An in-memory index of stored name keys, with archive and row identity.
//!
//! A row contributes both of its stored keys when they are present. The
//! namespace is part of the map key, so 32-bit and 64-bit values never mix.
//! Callers keep the archive table; occurrences store only an index into it.

use std::collections::HashMap;

use super::{Class, Key};

/// One row that stores a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Occurrence {
    /// Index into the caller's archive list.
    pub archive: usize,
    pub row: u32,
    pub type_id: Option<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct HashIndex {
    entries: HashMap<(Class, u64), Vec<Occurrence>>,
    rows: usize,
    inserted: usize,
}

impl HashIndex {
    /// Adds one key occurrence. The same occurrence for one key is ignored.
    pub fn insert(&mut self, key: Key, occurrence: Occurrence) {
        let list = self.entries.entry((key.class(), key.value())).or_default();
        if !list.contains(&occurrence) {
            list.push(occurrence);
            self.inserted += 1;
        }
    }

    /// Adds both stored keys of a row and counts the row once.
    pub fn insert_row(
        &mut self,
        archive: usize,
        row: u32,
        type_id: Option<u8>,
        hash: Option<u64>,
        key: Option<u32>,
    ) {
        self.rows += 1;
        let occurrence = Occurrence {
            archive,
            row,
            type_id,
        };
        if let Some(hash) = hash {
            self.insert(Key::Hash64(hash), occurrence);
        }
        if let Some(key) = key {
            self.insert(Key::Key32(key), occurrence);
        }
    }

    pub fn lookup(&self, key: Key) -> &[Occurrence] {
        self.entries
            .get(&(key.class(), key.value()))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of distinct keys, summed over both namespaces.
    pub fn unique_keys(&self) -> usize {
        self.entries.len()
    }

    pub fn unique_keys_in(&self, class: Class) -> usize {
        self.entries
            .keys()
            .filter(|(kind, _)| *kind == class)
            .count()
    }

    pub fn occurrences(&self) -> usize {
        self.inserted
    }

    pub fn keys_in(&self, class: Class) -> impl Iterator<Item = (Key, &[Occurrence])> {
        self.entries
            .iter()
            .filter(move |((kind, _), _)| *kind == class)
            .map(|((kind, value), rows)| {
                let key = match kind {
                    Class::Hash64 => Key::Hash64(*value),
                    Class::Key32 => Key::Key32(*value as u32),
                };
                (key, rows.as_slice())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_namespaces_apart() {
        let mut index = HashIndex::default();
        index.insert_row(0, 1, Some(0), Some(0x1234), None);
        index.insert_row(0, 2, Some(255), None, Some(0x1234));
        assert_eq!(index.lookup(Key::Hash64(0x1234)).len(), 1);
        assert_eq!(index.lookup(Key::Key32(0x1234)).len(), 1);
        assert_eq!(index.rows(), 2);
        assert_eq!(index.unique_keys(), 2);
        assert_eq!(index.unique_keys_in(Class::Hash64), 1);
        assert_eq!(index.unique_keys_in(Class::Key32), 1);
    }

    #[test]
    fn records_multiple_archive_occurrences() {
        let mut index = HashIndex::default();
        index.insert_row(0, 7, Some(0), Some(9), None);
        index.insert_row(1, 3, Some(0), Some(9), None);
        index.insert_row(1, 3, Some(0), Some(9), None);
        let rows = index.lookup(Key::Hash64(9));
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            Occurrence {
                archive: 0,
                row: 7,
                type_id: Some(0)
            }
        );
        assert_eq!(rows[1].archive, 1);
        assert_eq!(index.occurrences(), 2);
    }
}
