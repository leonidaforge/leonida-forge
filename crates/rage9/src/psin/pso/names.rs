//! Candidate names for the 32-bit hashes a metadata schema stores.
//!
//! A field or structure name in a `PSIN` container is a case-sensitive
//! `joaat` of the name as written, so the only names this index holds are the
//! ones whose hash it reproduces. A hash is one way: a lookup returns
//! candidates, the stored hash stays the identity, and a hash with no
//! candidate stays unresolved.
//!
//! The index is built from a [`StringTable`], the same table the archive
//! commands read. Each entry contributes its own name and each path component
//! of it, so a table of archive paths can still name a field such as `fMass`.

use std::collections::HashMap;

use crate::rpf::names::StringTable;

/// The most distinct hashes an index holds.
pub const MAX_NAMES: usize = 1 << 20;

/// The hash a metadata schema stores for a name: Jenkins one-at-a-time over
/// the bytes as written.
///
/// This is not [`crate::rpf::names::joaat`], which folds case for archive
/// paths. A schema name is case-sensitive: `Position` hashes to `0x0C928991`
/// and `position` does not.
pub fn metadata_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &byte in name {
        if byte == 0 {
            break;
        }
        hash = hash.wrapping_add(u32::from(byte));
        hash = hash.wrapping_add(hash << 10);
        hash ^= hash >> 6;
    }
    hash = hash.wrapping_add(hash << 3);
    hash ^= hash >> 11;
    hash.wrapping_add(hash << 15)
}

/// Candidate names, indexed by the hash they reproduce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    by_hash: HashMap<u32, Vec<String>>,
    count: usize,
}

impl Names {
    /// An index with no names. Every lookup is unresolved.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Indexes every name and every `/`- or `\`-separated component of it.
    pub fn from_table(table: &StringTable) -> Self {
        let mut names = Self::default();
        for entry in table.entries() {
            names.insert(&entry.name);
            for component in entry.name.split(['/', '\\']) {
                names.insert(component);
            }
        }
        names
    }

    /// Indexes one name, with the extension dropped as well, so
    /// `data/effects/vfxglassinfo.zmt` also offers `vfxglassinfo`.
    pub fn insert(&mut self, name: &str) {
        if name.is_empty() {
            return;
        }
        self.add(name);
        if let Some((stem, _)) = name.rsplit_once('.')
            && !stem.is_empty()
        {
            self.add(stem);
        }
    }

    fn add(&mut self, name: &str) {
        let hash = metadata_hash(name.as_bytes());
        match self.by_hash.get_mut(&hash) {
            Some(candidates) => {
                if !candidates.iter().any(|candidate| candidate == name) {
                    candidates.push(name.to_string());
                }
            }
            None => {
                if self.by_hash.len() >= MAX_NAMES {
                    return;
                }
                self.by_hash.insert(hash, vec![name.to_string()]);
                self.count += 1;
            }
        }
    }

    /// The distinct hashes the index names.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The names whose case-sensitive `joaat` is `hash`, sorted.
    pub fn lookup(&self, hash: u32) -> &[String] {
        self.by_hash
            .get(&hash)
            .map_or(&[], |candidates| candidates.as_slice())
    }

    /// Whether the index names `hash`.
    pub fn resolves(&self, hash: u32) -> bool {
        self.by_hash.contains_key(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(lines: &str) -> StringTable {
        StringTable::parse(lines.as_bytes(), false)
    }

    #[test]
    fn the_metadata_hash_is_case_sensitive() {
        // Hashes the research states for the metadata schema.
        assert_eq!(metadata_hash(b"Key"), 0x6098_a50e);
        assert_eq!(metadata_hash(b"Item"), 0x063f_a3f2);
        assert_eq!(metadata_hash(b"Position"), 0x0c92_8991);
        assert_eq!(metadata_hash(b"Flags"), 0x4b62_1302);
        assert_eq!(metadata_hash(b"CMloRoomDef"), 0x0b18_11f1);
        assert_ne!(metadata_hash(b"Position"), metadata_hash(b"position"));
    }

    #[test]
    fn a_name_resolves_by_its_own_hash() {
        let names = Names::from_table(&table("fMass\n"));
        assert_eq!(names.lookup(metadata_hash(b"fMass")), ["fMass".to_string()]);
        assert!(!names.resolves(metadata_hash(b"fmass")));
    }

    #[test]
    fn a_path_component_resolves() {
        let names = Names::from_table(&table("data/effects/vfxglassinfo.zmt\n"));
        assert_eq!(
            names.lookup(metadata_hash(b"vfxglassinfo")),
            ["vfxglassinfo".to_string()]
        );
        assert!(names.resolves(metadata_hash(b"data/effects/vfxglassinfo.zmt")));
    }

    #[test]
    fn an_unknown_hash_is_unresolved() {
        let names = Names::empty();
        assert!(names.lookup(0x1234_5678).is_empty());
        assert!(!names.resolves(0x1234_5678));
        assert!(names.is_empty());
    }

    #[test]
    fn a_declared_mapping_is_indexed_by_the_name_it_carries() {
        // The declared key is not used: a metadata name resolves only when the
        // name itself hashes to the stored hash.
        let names = Names::from_table(&table("key32:0x0E8F4A11\tfInitialDragCoeff\n"));
        assert_eq!(
            names.lookup(metadata_hash(b"fInitialDragCoeff")),
            ["fInitialDragCoeff".to_string()]
        );
        assert!(!names.resolves(0x0E8F_4A11));
    }

    #[test]
    fn several_names_for_one_hash_are_all_kept() {
        let mut names = Names::empty();
        names.insert("aB");
        names.insert("aB");
        assert_eq!(names.lookup(metadata_hash(b"aB")), ["aB".to_string()]);
        assert_eq!(names.len(), 1);
    }
}
