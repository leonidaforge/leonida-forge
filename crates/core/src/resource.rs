//! Canonical resource paths.
//!
//! An archive entry is addressed by the stored hash of its name, not by a
//! display name, and a row index addresses an entry only within one archive.
//! This module joins the archive hierarchy, the stored keys and the verified
//! names into two strings:
//!
//! - [`ResourcePath::identity`] is stable. It uses the root file name, the
//!   stored keys and, where keys repeat, the occurrence number. It never uses
//!   a resolved name, so adding a name mapping cannot change it.
//! - [`ResourcePath::display`] is for people. It uses the verified resolved
//!   path of each entry when exactly one verified name folds to its key, and
//!   the stored key at its namespace width otherwise.
//!
//! Components are separated by [`SEPARATOR`]. The first component is the root
//! file, each further archive-entered component is a nested archive, and the
//! last component is the entry itself. `!` and `~` in a name are doubled, so a
//! name can never spell a separator or an occurrence marker.
//!
//! Two entries of one archive that would show the same label take an
//! occurrence number in archive order (`~1`, `~2`, ...), so a label always
//! names exactly one entry. An entry without a stored key is labelled
//! `unidentified`; it takes no occurrence number in its identity, because its
//! locator already identifies it.
//!
//! A row index is diagnostic metadata. It is retained as the identity of an
//! entry that has no stored key, and reported as a limitation; it is never
//! used in place of an available key.

use std::collections::HashMap;

use lforge_rage9::rpf::metadata::Entry;
use lforge_rage9::rpf::names::table::normalized;
use lforge_rage9::rpf::names::{Class, Key, Resolution, RowNames, Types};

/// Separates the root file, the nested archives and the entry.
pub const SEPARATOR: char = '!';

/// Why a resource path is incomplete, as text for a report.
pub const NO_KEY: &str = "the entry stores no name key; its row index is retained as a \
    technical locator and is not a resource identifier";
pub const AMBIGUOUS: &str = "more than one verified name folds differently to the stored key, so \
    the key is shown instead of choosing a name";
pub const DUPLICATE: &str = "more than one entry in this archive shows this label; the \
    occurrence number distinguishes them in archive order";
pub const UNPLACED: &str = "the verified name is not a safe relative archive path, so the \
    stored key is shown instead and the name stays in the details";

/// A technical locator of an entry inside one archive. Never a filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locator {
    /// A native RPF9 row index.
    Row(u32),
    /// A ZIP central-directory index.
    Zip(usize),
}

impl Locator {
    /// The locator as a stable identity component, e.g. `row:9`.
    pub fn identity(self) -> String {
        match self {
            Locator::Row(row) => format!("row:{row}"),
            Locator::Zip(index) => format!("zip:{index}"),
        }
    }

    /// The locator as a short human label, e.g. `row 9`.
    pub fn text(self) -> String {
        match self {
            Locator::Row(row) => format!("row {row}"),
            Locator::Zip(index) => format!("zip entry {index}"),
        }
    }
}

/// One entry of an archive: its key, the name evidence and its technical
/// locator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryId {
    /// The stored key of the entry, when it has one.
    pub key: Option<Key>,
    /// The type that declares the display extension.
    pub type_id: Option<u8>,
    /// The single verified name that resolves the key.
    pub name: Option<String>,
    /// Verified names that fold differently, so the key cannot choose one.
    pub ambiguous: Vec<String>,
    /// The technical locator, retained for reports and for entries without a
    /// key.
    pub locator: Option<Locator>,
    /// 1-based position among entries of the same archive with this key.
    pub duplicate: usize,
    /// Number of entries in the same archive with this key.
    pub duplicates: usize,
}

impl EntryId {
    /// An entry with a single verified name or with a key.
    pub fn new(key: Option<Key>, type_id: Option<u8>, name: Option<String>) -> Self {
        Self {
            key,
            type_id,
            name,
            ambiguous: Vec::new(),
            locator: None,
            duplicate: 1,
            duplicates: 1,
        }
    }

    /// An entry whose name comes from the archive itself, as a ZIP entry's
    /// name does. The name is authoritative; there is no hash to verify it.
    pub fn named(name: impl Into<String>, type_id: Option<u8>, locator: Locator) -> Self {
        Self {
            key: None,
            type_id,
            name: Some(name.into()),
            ambiguous: Vec::new(),
            locator: Some(locator),
            duplicate: 1,
            duplicates: 1,
        }
    }

    /// An entry identified only by the stored key columns a producer recorded,
    /// for a consumer that has no table of contents. The 64-bit column wins
    /// when both hold a value, as it does for a row of unknown type.
    pub fn from_stored(
        hash64: Option<u64>,
        key32: Option<u32>,
        type_id: Option<u8>,
        name: Option<String>,
    ) -> Self {
        let key = match (hash64, key32) {
            (Some(hash), _) => Some(Key::Hash64(hash)),
            (None, Some(key)) => Some(Key::Key32(key)),
            _ => None,
        };
        Self::new(key, type_id, name)
    }

    /// A native RPF9 row with its resolution.
    pub fn from_row(entry: &Entry, names: Option<&RowNames>, types: &Types) -> Self {
        let (name, ambiguous) = name_evidence(names);
        Self {
            key: stored_key(entry, types),
            type_id: entry.type_id(),
            name,
            ambiguous,
            locator: Some(Locator::Row(entry.row)),
            duplicate: 1,
            duplicates: 1,
        }
    }

    /// Whether the entry has neither a key nor a verified name.
    pub fn is_unidentified(&self) -> bool {
        self.key.is_none() && self.name.is_none()
    }

    /// The stable identity component. It never depends on a resolved name.
    ///
    /// An entry without a key is identified by its locator, which is already
    /// unique in the archive, so it takes no occurrence marker.
    pub fn identity(&self) -> String {
        match self.key {
            Some(key) => {
                let value = format!("{}:{}", key.class().namespace(), key.canonical());
                match self.duplicates {
                    0 | 1 => value,
                    _ => format!("{value}~{}", self.duplicate),
                }
            }
            None => self
                .locator
                .map_or_else(|| "unidentified".to_string(), |locator| locator.identity()),
        }
    }

    /// The user-facing component: a verified name, otherwise the stored key,
    /// otherwise an explicit unidentified label.
    pub fn display(&self) -> String {
        let escaped = escape(&self.display_base());
        match self.duplicates {
            0 | 1 => escaped,
            _ => format!("{escaped}~{}", self.duplicate),
        }
    }

    /// The component before the occurrence marker. Two entries of one archive
    /// that share it get an occurrence number, so a label always names exactly
    /// one entry.
    ///
    /// A verified name is used only when it is a safe relative archive path;
    /// an unsafe one would let a label escape the archive it names.
    pub fn display_base(&self) -> String {
        if let Some(name) = self.placed_name() {
            registry_name(name, self.type_id)
        } else if let Some(key) = self.key {
            registry_name(&key.canonical(), self.type_id)
        } else {
            "unidentified".to_string()
        }
    }

    /// The verified name, when it is a safe relative archive path.
    fn placed_name(&self) -> Option<&str> {
        let name = self.name.as_deref()?;
        lforge_rage9::rpf::names::relative_path(name).map(|_| name)
    }

    /// The last component of [`EntryId::display`], with the occurrence marker
    /// kept beside the file name rather than after a folder.
    pub fn file_label(&self) -> String {
        let display = self.display();
        let (_, last) = split_last_component(&display);
        last.to_string()
    }

    /// The folder components a verified name describes, when it is a safe
    /// relative archive path.
    pub fn folder(&self) -> Option<Vec<String>> {
        let name = self.placed_name()?;
        let parts = lforge_rage9::rpf::names::relative_path(name)?;
        let (_, folder) = parts.split_last()?;
        Some(folder.iter().map(|part| (*part).to_string()).collect())
    }

    /// Why the component cannot state a key or a single name.
    pub fn limitation(&self) -> Option<&'static str> {
        if self.name.is_none() && !self.ambiguous.is_empty() {
            Some(AMBIGUOUS)
        } else if self.is_unidentified() {
            Some(NO_KEY)
        } else if self.duplicates > 1 {
            Some(DUPLICATE)
        } else if self.name.is_some() && self.folder().is_none() {
            Some(UNPLACED)
        } else {
            None
        }
    }
}

/// The stored key in the authoritative column of the entry's type.
///
/// A type of a known class uses only that class's column, so the 32-bit and
/// 64-bit namespaces stay apart. A type of unknown class takes whichever
/// column holds a key, preferring the 64-bit one, as earlier reports did.
pub fn stored_key(entry: &Entry, types: &Types) -> Option<Key> {
    let hash = entry.name_hash.as_ref().ok().and_then(|value| *value);
    let key = entry.name_key.as_ref().ok().and_then(|value| *value);
    match entry.type_id().and_then(|type_id| types.class(type_id)) {
        Some(Class::Hash64) => hash.map(Key::Hash64),
        Some(Class::Key32) => key.map(Key::Key32),
        _ => match (hash, key) {
            (Some(hash), _) => Some(Key::Hash64(hash)),
            (None, Some(key)) => Some(Key::Key32(key)),
            _ => None,
        },
    }
}

/// The single verified name of a row, or every verified name that folds
/// differently. Unverified mappings are never returned.
pub fn name_evidence(row: Option<&RowNames>) -> (Option<String>, Vec<String>) {
    let Some(row) = row else {
        return (None, Vec::new());
    };
    let names: Vec<&str> = match &row.resolution {
        Resolution::Resolved(names) | Resolution::Ambiguous(names) => names
            .iter()
            .filter(|name| name.verified)
            .map(|name| name.text.as_str())
            .collect(),
        Resolution::Unresolved => Vec::new(),
    };
    let mut unique: Vec<&str> = Vec::with_capacity(names.len());
    for name in names {
        if !unique
            .iter()
            .any(|known| normalized(known) == normalized(name))
        {
            unique.push(name);
        }
    }
    match unique.len() {
        0 => (None, Vec::new()),
        1 => (Some(unique[0].to_string()), Vec::new()),
        _ => (
            None,
            unique.iter().map(|name| (*name).to_string()).collect(),
        ),
    }
}

/// Assigns the occurrence number of every entry whose label another entry of
/// the same archive shares, in slice order. Entries are ordered by archive
/// position, so the numbering is deterministic and a new name mapping can only
/// move an entry to a label of its own.
pub fn assign_occurrences(entries: &mut [EntryId]) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (position, entry) in entries.iter().enumerate() {
        groups
            .entry(entry.display_base())
            .or_default()
            .push(position);
    }
    let mut groups: Vec<Vec<usize>> = groups.into_values().filter(|g| g.len() > 1).collect();
    groups.sort_by_key(|positions| positions[0]);
    for positions in groups {
        let total = positions.len();
        for (ordinal, position) in positions.into_iter().enumerate() {
            entries[position].duplicate = ordinal + 1;
            entries[position].duplicates = total;
        }
    }
}

/// A root file, the nested archives entered and, optionally, the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePath {
    root: String,
    ancestors: Vec<EntryId>,
    entry: Option<EntryId>,
}

impl ResourcePath {
    /// The path of a file on disk: only the file name, never a directory.
    pub fn root(name: impl Into<String>) -> Self {
        Self {
            root: name.into(),
            ancestors: Vec::new(),
            entry: None,
        }
    }

    /// The same path with one more archive entered.
    pub fn push(&self, archive: EntryId) -> Self {
        let mut next = self.clone();
        next.ancestors.push(archive);
        next.entry = None;
        next
    }

    /// The same archive path with its final entry.
    pub fn with_entry(&self, entry: EntryId) -> Self {
        let mut next = self.clone();
        next.entry = Some(entry);
        next
    }

    /// The entry, when this path names one.
    pub fn entry(&self) -> Option<&EntryId> {
        self.entry.as_ref()
    }

    /// The root file name.
    pub fn root_name(&self) -> &str {
        &self.root
    }

    /// The path of the archive that holds the entry, or of the last archive
    /// when the path names no entry.
    pub fn archive_display(&self) -> String {
        let mut value = escape(&self.root);
        for ancestor in &self.ancestors {
            value.push(SEPARATOR);
            value.push_str(&ancestor.display());
        }
        value
    }

    /// The user-facing path.
    pub fn display(&self) -> String {
        let mut value = self.archive_display();
        if let Some(entry) = &self.entry {
            value.push(SEPARATOR);
            value.push_str(&entry.display());
        }
        value
    }

    /// The stable identity.
    pub fn identity(&self) -> String {
        let mut value = self.root.clone();
        for ancestor in &self.ancestors {
            value.push(SEPARATOR);
            value.push_str(&ancestor.identity());
        }
        if let Some(entry) = &self.entry {
            value.push(SEPARATOR);
            value.push_str(&entry.identity());
        }
        value
    }

    /// Every limitation of this path, without repeats.
    pub fn limitations(&self) -> Vec<&'static str> {
        let mut limits: Vec<&'static str> = Vec::new();
        for entry in self.ancestors.iter().chain(self.entry.iter()) {
            if let Some(limit) = entry.limitation()
                && !limits.contains(&limit)
            {
                limits.push(limit);
            }
        }
        limits
    }
}

/// The name to show with the extension the type registry declares, if any.
fn registry_name(name: &str, type_id: Option<u8>) -> String {
    crate::registry::file_name(name, type_id).text
}

/// Doubles the separator and the occurrence marker, so a name cannot spell
/// either.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character == SEPARATOR || character == '~' {
            escaped.push(character);
        }
        escaped.push(character);
    }
    escaped
}

/// Splits at the last `/` or `\`, keeping the separator with the folder.
fn split_last_component(text: &str) -> (&str, &str) {
    match text.rfind(['/', '\\']) {
        Some(at) => (&text[..=at], &text[at + 1..]),
        None => ("", text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lforge_rage9::rpf::names::{Name, Namespace, Provenance, hash64, joaat};

    fn resolved(names: &[(&str, bool)]) -> RowNames {
        RowNames {
            row: 0,
            namespace: Namespace::Hash64,
            resolution: Resolution::Resolved(
                names
                    .iter()
                    .map(|(text, verified)| Name {
                        text: (*text).to_string(),
                        provenance: Provenance::CandidatePath,
                        algorithm: Class::Hash64,
                        verified: *verified,
                    })
                    .collect(),
            ),
        }
    }

    #[test]
    fn a_verified_name_wins_and_keeps_the_declared_extension() {
        let row = resolved(&[("packs/inner", true)]);
        let (name, ambiguous) = name_evidence(Some(&row));
        assert_eq!(name.as_deref(), Some("packs/inner"));
        assert!(ambiguous.is_empty());
        let entry = EntryId::new(Some(Key::Hash64(hash64(b"packs/inner"))), Some(0), name);
        assert_eq!(entry.display(), "packs/inner.rpf");
        assert_eq!(entry.folder(), Some(vec!["packs".to_string()]));
        assert_eq!(entry.file_label(), "inner.rpf");
    }

    #[test]
    fn the_stored_key_is_used_when_no_verified_name_exists() {
        let row = resolved(&[("readme", false)]);
        let (name, ambiguous) = name_evidence(Some(&row));
        assert!(name.is_none());
        assert!(ambiguous.is_empty());
        let key = Key::Key32(joaat(b"readme"));
        let entry = EntryId::new(Some(key), Some(6), name);
        assert_eq!(entry.display(), format!("{}.zbn", key.canonical()));
        assert_eq!(entry.identity(), format!("key32:{}", key.canonical()));
        assert_eq!(entry.limitation(), None);
    }

    #[test]
    fn an_ambiguous_key_is_shown_as_the_actual_hash_not_as_a_candidate() {
        let row = resolved(&[("readme", true), ("README", false), ("read_me", true)]);
        let (name, ambiguous) = name_evidence(Some(&row));
        assert!(name.is_none());
        assert_eq!(ambiguous, ["readme", "read_me"]);
        let key = Key::Key32(joaat(b"readme"));
        let entry = EntryId {
            ambiguous,
            ..EntryId::new(Some(key), None, name)
        };
        assert!(!entry.display().contains("readme"));
        assert!(entry.display().starts_with(&key.canonical()));
        assert_eq!(entry.limitation(), Some(AMBIGUOUS));
    }

    #[test]
    fn a_key_keeps_its_namespace_width() {
        assert_eq!(
            EntryId::new(Some(Key::Hash64(0x542ABDCA39C4C)), Some(0), None).display(),
            "0x000542ABDCA39C4C.rpf"
        );
        assert_eq!(
            EntryId::new(Some(Key::Key32(0x2B99746)), None, None).display(),
            "0x02B99746"
        );
    }

    #[test]
    fn the_identity_does_not_change_when_a_name_is_added() {
        let before = EntryId::new(Some(Key::Hash64(hash64(b"packs/inner"))), Some(0), None);
        let after = EntryId::new(
            Some(Key::Hash64(hash64(b"packs/inner"))),
            Some(0),
            Some("packs/inner".to_string()),
        );
        assert_eq!(before.identity(), after.identity());
        assert_ne!(before.display(), after.display());
    }

    #[test]
    fn duplicates_get_a_deterministic_occurrence_marker() {
        let key = Key::Hash64(hash64(b"shared/name"));
        let mut entries = vec![
            EntryId::new(Some(key), Some(0), Some("shared/name".to_string())),
            EntryId::new(Some(key), Some(0), Some("shared/name".to_string())),
            EntryId::new(Some(Key::Hash64(hash64(b"other"))), Some(0), None),
        ];
        assign_occurrences(&mut entries);
        assert_eq!(entries[0].display(), "shared/name.rpf~1");
        assert_eq!(entries[1].display(), "shared/name.rpf~2");
        assert_eq!(
            entries[0].identity(),
            format!("hash64:{}~1", key.canonical())
        );
        let other = Key::Hash64(hash64(b"other"));
        assert_eq!(entries[2].display(), format!("{}.rpf", other.canonical()));
        assert_eq!(entries[0].limitation(), Some(DUPLICATE));
        assert_eq!(entries[2].limitation(), None);
    }

    #[test]
    fn a_name_cannot_spell_a_separator_or_the_occurrence_marker() {
        let entry = EntryId::new(
            Some(Key::Hash64(hash64(b"a!b~2"))),
            None,
            Some("a!b~2".to_string()),
        );
        assert_eq!(entry.display(), "a!!b~~2");
        assert_eq!(
            entry.identity(),
            format!("hash64:{}", Key::Hash64(hash64(b"a!b~2")).canonical())
        );
    }

    #[test]
    fn nested_archives_keep_their_hierarchy() {
        let root = ResourcePath::root("data.rpf");
        let pack = root.push(EntryId::new(
            Some(Key::Hash64(hash64(b"packs/inner"))),
            Some(0),
            Some("packs/inner".to_string()),
        ));
        let entry = pack.with_entry(EntryId::new(
            Some(Key::Hash64(hash64(b"packs/inner/leaf"))),
            Some(5),
            Some("packs/inner/leaf".to_string()),
        ));
        assert_eq!(
            entry.display(),
            "data.rpf!packs/inner.rpf!packs/inner/leaf.ztd"
        );
        assert_eq!(entry.archive_display(), "data.rpf!packs/inner.rpf");
    }

    #[test]
    fn a_zip_name_is_authoritative_and_has_a_technical_identity() {
        let entry = EntryId::named("scripts/main.gfx", Some(66), Locator::Zip(3));
        assert_eq!(entry.display(), "scripts/main.gfx");
        assert_eq!(entry.identity(), "zip:3");
        assert!(entry.limitation().is_none());
    }

    #[test]
    fn an_entry_without_a_key_retains_its_locator_as_identity() {
        let entry = EntryId {
            key: None,
            type_id: Some(5),
            name: None,
            ambiguous: Vec::new(),
            locator: Some(Locator::Row(42)),
            duplicate: 1,
            duplicates: 1,
        };
        assert_eq!(entry.identity(), "row:42");
        assert_eq!(entry.display(), "unidentified");
        assert_eq!(entry.limitation(), Some(NO_KEY));
    }

    #[test]
    fn entries_without_a_key_keep_distinct_labels_and_their_own_locator() {
        let mut entries = vec![
            EntryId {
                locator: Some(Locator::Row(3)),
                ..EntryId::new(None, Some(0), None)
            },
            EntryId {
                locator: Some(Locator::Row(7)),
                ..EntryId::new(None, Some(0), None)
            },
            EntryId::new(
                Some(Key::Hash64(hash64(b"named"))),
                Some(0),
                Some("named".to_string()),
            ),
        ];
        assign_occurrences(&mut entries);
        assert_eq!(entries[0].display(), "unidentified~1");
        assert_eq!(entries[1].display(), "unidentified~2");
        assert_eq!(entries[0].identity(), "row:3");
        assert_eq!(entries[1].identity(), "row:7");
        assert_eq!(entries[0].limitation(), Some(NO_KEY));
        assert_eq!(entries[2].display(), "named.rpf");
    }
}
