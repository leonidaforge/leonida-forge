//! Explorer tests on synthetic archives with an unencrypted table of
//! contents.

use std::cell::Cell;
use std::fs;
use std::sync::atomic::AtomicBool;

use lforge_rage9::rpf::Progress;
use lforge_rage9::rpf::metadata::keys;
use lforge_rage9::rpf::names::{Builtin, NO_TYPE, RPF_TYPE, hash64, joaat};

use super::*;
use crate::files;
use crate::files::archive::{self, Location, locate, prepare_required};
use crate::files::rpf::tests::{rpf_bytes, zlib};
use crate::files::zip::tests::{zip_bytes, zip_bytes_with};

thread_local! {
    /// Full reads of a metadata area on this thread.
    pub(crate) static FULL_READS: Cell<usize> = const { Cell::new(0) };
}

fn full_reads() -> usize {
    FULL_READS.with(Cell::get)
}

pub(crate) struct Spec {
    pub payload: Vec<u8>,
    pub type_id: u8,
    pub mode: u8,
    pub hash: Option<u64>,
    pub key: Option<u32>,
    /// Without one, the row has no location record.
    pub location: bool,
    /// Points the name hash cell past its pool.
    pub bad_hash: bool,
    /// Overrides the logical size, which is the payload's length otherwise.
    pub logical: Option<u64>,
    /// The chunk table value.
    pub chunks: Option<Vec<u8>>,
    pub source: Option<u32>,
}

pub(crate) fn spec(payload: &[u8], type_id: u8) -> Spec {
    Spec {
        payload: payload.to_vec(),
        type_id,
        mode: 0,
        hash: None,
        key: None,
        location: true,
        bad_hash: false,
        logical: None,
        chunks: None,
        source: None,
    }
}

/// An archive whose table of contents is stored unencrypted.
pub(crate) fn native_rpf(rows: &[Spec]) -> Vec<u8> {
    native_rpf_with(rows, &[])
}

/// [`native_rpf`] with `B` sub-block 3 listing `companions`, names and
/// identifiers. Columns: name hash, name key, A location record, chunk table
/// and read source, then the payloads.
pub(crate) fn native_rpf_with(rows: &[Spec], companions: &[(&[u8], u64)]) -> Vec<u8> {
    let n = rows.len();
    assert!(n < 0xFE);
    let chunk_width = rows
        .iter()
        .filter_map(|row| row.chunks.as_ref().map(Vec::len))
        .max()
        .unwrap_or(8);
    let columns = [
        (keys::NAME_HASH, 0, 8),
        (keys::NAME_KEY, 8 * n, 4),
        (keys::LOCATION_A, 12 * n, 16),
        (keys::CHUNK_TABLE, 28 * n, chunk_width),
        (keys::READ_SOURCE, (28 + chunk_width) * n, 4),
    ];
    // One A record, for sub-block 2 or, with companions, sub-block 3.
    let b = 0x50;
    let b_len = (8 + companions.len() * 0x108).next_multiple_of(16);
    let descriptors = b + b_len;
    let cells = descriptors + columns.len() * 24;
    let pool = (cells + columns.len() * n).next_multiple_of(8);
    // The empty secondary area starts 8-aligned after the primary one.
    let end = (pool + (32 + chunk_width) * n).next_multiple_of(8);
    let payloads = end.next_multiple_of(16);
    let mut bytes = vec![0u8; payloads];
    let put = |bytes: &mut Vec<u8>, at: usize, value: &[u8]| {
        bytes[at..at + value.len()].copy_from_slice(value);
    };
    put(&mut bytes, 0, b"9FPR");
    put(&mut bytes, 0x04, &(end as u32).to_le_bytes());
    put(&mut bytes, 0x08, &(end as u32).to_le_bytes());
    put(&mut bytes, 0x1A, &1u16.to_le_bytes());
    put(&mut bytes, 0x1C, &(b_len as u32).to_le_bytes());
    put(&mut bytes, 0x20, &(columns.len() as u16).to_le_bytes());
    put(&mut bytes, 0x24, &(n as u32).to_le_bytes());
    bytes[0x2C] = 1;
    bytes[0x2D] = 1;
    let sub_block: u16 = if companions.is_empty() { 2 } else { 3 };
    put(&mut bytes, 0x40, &sub_block.to_le_bytes());
    if !companions.is_empty() {
        put(&mut bytes, b, &(companions.len() as u32).to_le_bytes());
        for (i, (name, identifier)) in companions.iter().enumerate() {
            let record = b + 8 + i * 0x108;
            put(&mut bytes, record, name);
            put(&mut bytes, record + 0x100, &identifier.to_le_bytes());
        }
    }
    for (column, (key, offset, width)) in columns.into_iter().enumerate() {
        let at = descriptors + column * 24;
        put(&mut bytes, at, &key.to_le_bytes());
        put(&mut bytes, at + 0x0C, &(offset as u32).to_le_bytes());
        put(&mut bytes, at + 0x10, &(width as u16).to_le_bytes());
    }
    let mut data = Vec::new();
    for (r, row) in rows.iter().enumerate() {
        let cell = |present: bool| if present { r as u8 } else { 0xFF };
        let hash_cell = if row.bad_hash {
            0xFE
        } else {
            cell(row.hash.is_some())
        };
        put(
            &mut bytes,
            cells + r * columns.len(),
            &[
                hash_cell,
                cell(row.key.is_some()),
                cell(row.location),
                cell(row.chunks.is_some()),
                cell(row.source.is_some()),
            ],
        );
        put(
            &mut bytes,
            pool + 8 * r,
            &row.hash.unwrap_or(0).to_le_bytes(),
        );
        put(
            &mut bytes,
            pool + 8 * n + 4 * r,
            &row.key.unwrap_or(0).to_le_bytes(),
        );
        let offset = payloads + data.len();
        let logical = row.logical.unwrap_or(row.payload.len() as u64);
        let packed = logical | (u64::from(row.type_id) << 48) | (u64::from(row.mode) << 56);
        let record = pool + 12 * n + 16 * r;
        put(
            &mut bytes,
            record,
            &(row.payload.len().div_ceil(16) as u32).to_le_bytes(),
        );
        put(
            &mut bytes,
            record + 4,
            &((offset / 16) as u32).to_le_bytes(),
        );
        put(&mut bytes, record + 8, &packed.to_le_bytes());
        if let Some(table) = &row.chunks {
            put(&mut bytes, pool + 28 * n + chunk_width * r, table);
        }
        put(
            &mut bytes,
            pool + (28 + chunk_width) * n + 4 * r,
            &row.source.unwrap_or(u32::MAX).to_le_bytes(),
        );
        data.extend_from_slice(&row.payload);
        data.resize(data.len().next_multiple_of(16), 0);
    }
    bytes.extend_from_slice(&data);
    bytes
}

/// A chunk table value in encoding 4 and its stored chunks: one zlib stream
/// per element of `chunks`, padded with nonzero bytes.
pub(crate) fn zlib_chunks(chunks: &[&[u8]]) -> (Vec<u8>, Vec<u8>, u64) {
    let mut stored = Vec::new();
    let mut table = vec![8, 0, 0, 0];
    table.extend_from_slice(&(chunks.len() as u16).to_le_bytes());
    table.extend_from_slice(&[0, 4]);
    let mut logical = 0;
    for data in chunks {
        let compressed = zlib(data);
        let stored_len = compressed.len().next_multiple_of(16);
        let padding = (stored_len - compressed.len()) as u64;
        stored.extend_from_slice(&compressed);
        stored.resize(stored.len() + padding as usize, 0xA5);
        let entry = data.len() as u64 | ((stored_len / 16) as u64) << 28 | padding << 52 | 3 << 56;
        table.extend_from_slice(&entry.to_le_bytes());
        logical += data.len() as u64;
    }
    (stored, table, logical)
}

fn names_of(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.name.as_str()).collect()
}

fn detail<'a>(entry: &'a Entry, label: &str) -> &'a str {
    entry
        .details
        .iter()
        .find(|(l, _)| *l == label)
        .map(|(_, value)| value.as_str())
        .unwrap_or_else(|| panic!("no {label} in {:?}", entry.details))
}

/// Lists `path`, opening the archives it needs first, as the explorer does.
/// What was opened may be evicted before the listing, so it is opened again
/// then.
fn list_opened(path: &Path) -> Vec<Entry> {
    for _ in 0..10 {
        match files::list(path) {
            Err(err) if prepare_required(&err).is_some() => {
                archive::prepare(path, &Progress::default(), &AtomicBool::new(false)).unwrap();
            }
            result => return result.unwrap(),
        }
    }
    panic!("{} could not be listed", path.display());
}

fn opened(path: &Path) -> Archive {
    list_opened(path);
    match locate(path).unwrap() {
        Location::Archive(archive) => archive,
        other => panic!("expected an opened archive, got {other:?}"),
    }
}

#[test]
fn lists_entries_from_the_table_of_contents() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("native.rpf");
    let raw = b"plain raw payload".to_vec();
    fs::write(
        &path,
        native_rpf(&[
            Spec {
                hash: Some(hash64(b"packs/inner")),
                ..spec(&zip_bytes(&[("leaf.txt", b"leaf")]), RPF_TYPE)
            },
            Spec {
                hash: Some(hash64(b"data")),
                ..spec(&raw, 5)
            },
            Spec {
                mode: 2,
                hash: Some(hash64(b"packed")),
                ..spec(b"stored with mode 2", RPF_TYPE)
            },
            Spec {
                location: false,
                ..spec(b"", RPF_TYPE)
            },
            Spec {
                bad_hash: true,
                ..spec(&[4; 16], RPF_TYPE)
            },
        ]),
    )
    .unwrap();

    // No scan is needed.
    let entries = files::list(&path).unwrap();
    let expected = [
        format!("0x{:016X}.rpf", hash64(b"packs/inner")),
        format!("0x{:016X}", hash64(b"data")),
        format!("0x{:016X}.rpf", hash64(b"packed")),
        "Row 00003".to_string(),
        "Row 00004".to_string(),
    ];
    assert_eq!(names_of(&entries).join("\n"), expected.join("\n"));
    let kinds: Vec<EntryKind> = entries.iter().map(|e| e.kind).collect();
    use EntryKind::{File, Unavailable};
    assert_eq!(kinds, [File, File, File, Unavailable, File]);
    assert_eq!(entries[0].type_name, "RPF9 entry, type 0 (rpf)");
    assert_eq!(entries[1].type_name, "RPF9 entry, type 5");
    assert_eq!(entries[1].size, Some(raw.len() as u64));
    assert_eq!(
        detail(&entries[1], "Names"),
        "Unknown: no candidate path or declared name has this entry's hash"
    );
    assert_eq!(
        detail(&entries[1], "Name hash"),
        format!("0x{:016X}", hash64(b"data"))
    );
    assert_eq!(detail(&entries[1], "Compression"), "None");
    assert_eq!(detail(&entries[1], "Read source"), "Main");
    assert_eq!(detail(&entries[1], "Contents"), "Readable as stored");
    assert_eq!(detail(&entries[2], "Compression"), "Mode 2, not supported");
    assert!(detail(&entries[2], "Contents").starts_with("Not readable"));
    assert_eq!(detail(&entries[3], "Location record"), "Missing");
    assert_eq!(entries[3].type_name, "RPF9 entry, unreadable");
    assert!(detail(&entries[4], "Name hash").starts_with("Malformed"));
    assert_eq!(
        detail(&entries[4], "Names"),
        "Unknown: the row is malformed"
    );
    assert_eq!(detail(&entries[4], "Contents"), "Readable as stored");

    let note = files::describe(&path).unwrap();
    assert!(note.contains("table of contents"), "{note}");
    assert!(note.contains("5 entries"), "{note}");
    assert!(note.contains("2 of them have malformed fields"), "{note}");
    assert!(note.contains("built-in name mappings"), "{note}");

    // Raw entries read and open in the Binary Inspector.
    assert_eq!(files::read(&entries[1].path).unwrap(), raw);
    let mut inspected = files::open_binary(&entries[1].path).unwrap();
    assert_eq!(
        lforge_binary::read_at(&mut inspected.source, 0, 100).unwrap(),
        raw
    );
    assert_eq!(files::read(&entries[4].path).unwrap(), [4; 16]);
    // Unsupported and unreadable entries are refused with the reason.
    let err = files::read(&entries[2].path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("mode 2"), "{err}");
    assert!(files::open_binary(&entries[2].path).is_err());
    let err = files::read(&entries[3].path).unwrap_err();
    assert!(err.to_string().contains("no location record"), "{err}");

    // Each entry has exactly one path.
    for alias in ["Row 0", "Row 000000", "row 00001", "Row 00005", "Row 1"] {
        assert!(files::read(&path.join(alias)).is_err(), "{alias}");
    }
    assert!(files::list(&entries[1].path).is_err());
    assert!(files::list(&path.join("Recovered Entries")).is_err());
}

#[test]
fn duplicate_visible_labels_keep_distinct_entry_paths() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("duplicates.rpf");
    let hash = hash64(b"shared/name");
    fs::write(
        &path,
        native_rpf(&[
            Spec {
                hash: Some(hash),
                ..spec(b"first payload", RPF_TYPE)
            },
            Spec {
                hash: Some(hash),
                ..spec(b"second payload", RPF_TYPE)
            },
        ]),
    )
    .unwrap();
    let entries = files::list(&path).unwrap();
    assert_eq!(entries[0].name, entries[1].name);
    assert_ne!(entries[0].path, entries[1].path);
    assert_eq!(files::read(&entries[0].path).unwrap(), b"first payload");
    assert_eq!(files::read(&entries[1].path).unwrap(), b"second payload");
    assert_eq!(detail(&entries[0], "Name hash"), format!("0x{hash:016X}"));
}

#[test]
fn verified_paths_become_folders_and_unnamed_rows_come_last() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("named.rpf");
    fs::write(
        &path,
        native_rpf(&[
            Spec {
                hash: Some(hash64(b"packs/inner")),
                ..spec(&[1; 16], RPF_TYPE)
            },
            Spec {
                key: Some(joaat(b"readme")),
                ..spec(&[2; 16], NO_TYPE)
            },
            Spec {
                hash: Some(hash64(b"other")),
                ..spec(&[3; 16], RPF_TYPE)
            },
            Spec {
                hash: Some(hash64(b"packs/inner/leaf")),
                ..spec(&[4; 16], RPF_TYPE)
            },
        ]),
    )
    .unwrap();
    let candidates = temp.path().join("named.rpf.names.txt");
    fs::write(
        &candidates,
        "packs/inner.rpf\r\nPACKS\\INNER.rpf\n\npacks/inner/leaf.rpf\nreadme\n\"readme\"x\n\
         missing.rpf\nmodel.ydr\n",
    )
    .unwrap();

    // The verified relative paths are folders; the unnamed group is last.
    let root = files::list(&path).unwrap();
    assert_eq!(names_of(&root), ["packs", "Unnamed Entries"]);
    assert!(root[0].is_dir());
    assert!(root[1].is_dir());
    let note = files::describe(&path).unwrap();
    assert!(note.contains("shown as folders"), "{note}");
    assert!(
        note.contains("2 rows without one are at the end in Unnamed Entries"),
        "{note}"
    );

    let packs = files::list(&root[0].path).unwrap();
    assert_eq!(names_of(&packs), ["inner", "inner.rpf"]);
    assert_eq!(
        detail(&packs[1], "Names"),
        "packs/inner.rpf, PACKS\\INNER.rpf"
    );
    // The entry path stays the row number, under the folder it was placed in.
    assert_eq!(packs[1].path, path.join("packs").join("Row 00000"));
    assert_eq!(files::read(&packs[1].path).unwrap(), [1; 16]);
    let nested = files::list(&packs[0].path).unwrap();
    assert_eq!(names_of(&nested), ["leaf.rpf"]);
    assert_eq!(files::read(&nested[0].path).unwrap(), [4; 16]);
    assert!(files::list(&packs[1].path).is_err());

    let unnamed = files::list(&root[1].path).unwrap();
    let expected = [
        format!("0x{:08X}", joaat(b"readme")),
        format!("0x{:016X}.rpf", hash64(b"other")),
    ];
    assert_eq!(names_of(&unnamed).join("\n"), expected.join("\n"));
    assert!(detail(&unnamed[0], "Names").starts_with("Ambiguous: readme, \"readme\"x"));
    assert_eq!(
        detail(&unnamed[1], "Names"),
        "Unknown: no candidate path or declared name has this entry's hash"
    );
    let note = files::describe(&path).unwrap();
    assert!(
        note.contains("3 of 4 entries are named by the 7 candidate paths"),
        "{note}"
    );
    assert!(note.contains("1 ambiguously"), "{note}");
    assert!(
        note.contains("1 candidates could not be resolved"),
        "{note}"
    );

    // Only one path names a row: an alias is refused.
    assert!(files::read(&path.join("Row 00000")).is_err());
    assert!(files::read(&path.join("Packs").join("Row 00000")).is_err());
    assert!(files::read(&path.join("packs").join("Row 00002")).is_err());
    assert!(files::read(&path.join("Unnamed Entries").join("Row 00000")).is_err());

    // A changed candidate file is read again.
    fs::write(&candidates, "other.rpf\n").unwrap();
    let root = files::list(&path).unwrap();
    assert_eq!(names_of(&root), ["other.rpf", "Unnamed Entries"]);
    assert_eq!(files::read(&root[0].path).unwrap(), [3; 16]);
    let unnamed = files::list(&root[1].path).unwrap();
    assert_eq!(names_of(&unnamed).len(), 3);
    assert!(detail(&unnamed[2], "Names").starts_with("Unknown"));
    fs::remove_file(&candidates).unwrap();
    let root = files::list(&path).unwrap();
    assert_eq!(names_of(&root).len(), 4);
}

#[test]
fn names_come_from_a_lut_beside_the_executable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("lut.rpf");
    let item = hash64(b"props/item");
    let other = hash64(b"other");
    fs::write(
        &path,
        native_rpf(&[
            Spec {
                hash: Some(item),
                ..spec(&[1; 16], RPF_TYPE)
            },
            Spec {
                hash: Some(other),
                ..spec(&[2; 16], RPF_TYPE)
            },
        ]),
    )
    .unwrap();
    let directory = temp.path().join("bin");
    fs::create_dir(&directory).unwrap();
    fs::write(
        directory.join("rpf9-hash64.lut"),
        format!("# leonida-forge-lut: 1\n# namespace: hash64\n\n0x{item:016X}\tProps/Item.ydr\n"),
    )
    .unwrap();

    let archive = opened(&path);
    let builtin = Builtin::load(Some(&directory));
    let mut native = Native::read(&archive).unwrap();
    native.names = Names::read_with(&archive, &native.rows, &native.types, &builtin);
    native.layout = Layout::build(&native.rows, native.names.as_ref());
    let root = native.list(&archive, Path::new("")).unwrap();
    assert_eq!(names_of(&root), ["Props", "Unnamed Entries"]);
    let props = native.list(&archive, Path::new("Props")).unwrap();
    assert_eq!(names_of(&props), ["Item.ydr"]);
    assert_eq!(
        detail(&props[0], "Name source"),
        "User mapping, verified by hash"
    );
    assert_eq!(detail(&props[0], "Name hash"), format!("0x{item:016X}"));
    assert_eq!(props[0].path, archive.path.join("Props").join("Row 00000"));
    let unnamed = native.list(&archive, Path::new("Unnamed Entries")).unwrap();
    let labels: Vec<String> = unnamed.iter().map(|entry| entry.name.clone()).collect();
    assert_eq!(labels, [format!("0x{other:016X}.rpf")]);
}

#[test]
fn lut_content_next_to_the_archive_is_not_used() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("lut.rpf");
    let item = hash64(b"props/item");
    fs::write(
        &path,
        native_rpf(&[Spec {
            hash: Some(item),
            ..spec(&[1; 16], RPF_TYPE)
        }]),
    )
    .unwrap();
    let lut =
        format!("# leonida-forge-lut: 1\n# namespace: hash64\n\n0x{item:016X}\tProps/Item.ydr\n");
    // A `.lut` beside an archive is not read at all.
    fs::write(temp.path().join("lut.rpf.lut"), &lut).unwrap();
    // LUT content in the name table is refused with a reason.
    fs::write(temp.path().join("lut.rpf.names.txt"), &lut).unwrap();

    let entries = files::list(&path).unwrap();
    assert_eq!(entries[0].name, format!("0x{item:016X}.rpf"));
    let note = files::describe(&path).unwrap();
    assert!(note.contains("lut.rpf.names.txt was not used"), "{note}");
    assert!(note.contains("a LUT is only read from"), "{note}");
    assert!(note.contains("built-in name mappings"), "{note}");
}

#[test]
fn names_can_be_declared_for_stored_keys() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("mapped.rpf");
    let item = hash64(b"props/item");
    let readme = joaat(b"readme");
    fs::write(
        &path,
        native_rpf(&[
            Spec {
                hash: Some(item),
                ..spec(&[1; 16], RPF_TYPE)
            },
            Spec {
                key: Some(readme),
                ..spec(&[2; 16], NO_TYPE)
            },
        ]),
    )
    .unwrap();
    let names = temp.path().join("mapped.rpf.names.txt");
    fs::write(
        &names,
        format!(
            "# declared keys\n\
             hash64:{item:016X}\tProps/Item.ydr\n\
             key32:{readme:08X}\tReadme.txt\n\
             hash64:nothex\tignored\n"
        ),
    )
    .unwrap();

    let root = files::list(&path).unwrap();
    // The entry remains its row; a name only decides where it is listed.
    assert_eq!(names_of(&root), ["Props", "Readme.txt"]);
    let props = files::list(&root[0].path).unwrap();
    assert_eq!(names_of(&props), ["Item.ydr"]);
    assert_eq!(
        props[0].path.file_name().unwrap().to_str().unwrap(),
        "Row 00000"
    );
    assert_eq!(props[0].path, path.join("Props").join("Row 00000"));
    assert_eq!(detail(&props[0], "Names"), "Props/Item.ydr");
    assert_eq!(
        detail(&props[0], "Name source"),
        "User mapping, verified by hash"
    );
    assert_eq!(detail(&root[1], "Names"), "Readme.txt");
    // The stored key is still shown unchanged.
    assert_eq!(detail(&props[0], "Name hash"), format!("0x{item:016X}"));
    assert_eq!(detail(&root[1], "Name key"), format!("0x{readme:08X}"));
    let note = files::describe(&path).unwrap();
    assert!(
        note.contains("2 of 2 entries are named by the 2 name mappings"),
        "{note}"
    );
    assert!(note.contains("2 of 2 name mappings are verified"), "{note}");
    assert!(note.contains("1 line was not a valid entry"), "{note}");

    // A name that does not hash to the declared key stays a suggestion, so it
    // is neither a label nor a folder.
    fs::write(&names, format!("hash64:{item:016X}\tnot/that/item\n")).unwrap();
    let entries = files::list(&path).unwrap();
    assert_eq!(
        names_of(&entries).join("\n"),
        format!("0x{item:016X}.rpf\n0x{readme:08X}")
    );
    assert_eq!(detail(&entries[0], "Names"), "not/that/item");
    assert_eq!(
        detail(&entries[0], "Name source"),
        "User mapping, unconfirmed"
    );
    let note = files::describe(&path).unwrap();
    assert!(note.contains("0 of 1 name mappings are verified"), "{note}");
    assert!(note.contains("1 is unconfirmed"), "{note}");
    assert_eq!(detail(&entries[0], "Name hash"), format!("0x{item:016X}"));
}

#[test]
fn folder_spellings_that_fold_alike_are_one_folder() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("folded.rpf");
    fs::write(
        &path,
        native_rpf(&[
            Spec {
                hash: Some(hash64(b"packs/a")),
                ..spec(&[1; 16], RPF_TYPE)
            },
            Spec {
                hash: Some(hash64(b"packs/b")),
                ..spec(&[2; 16], RPF_TYPE)
            },
        ]),
    )
    .unwrap();
    // The engine folds case, so both paths are in one folder, spelled as the
    // first placed name spells it.
    fs::write(
        temp.path().join("folded.rpf.names.txt"),
        "PACKS/A.rpf\npacks/B.rpf\n",
    )
    .unwrap();

    let root = files::list(&path).unwrap();
    assert_eq!(names_of(&root), ["PACKS"]);
    let children = files::list(&root[0].path).unwrap();
    assert_eq!(names_of(&children), ["A.rpf", "B.rpf"]);
    assert_eq!(
        files::read(&path.join("PACKS").join("Row 00001")).unwrap(),
        [2; 16]
    );
    assert!(files::read(&path.join("packs").join("Row 00000")).is_err());
}

#[test]
fn unsafe_names_are_not_used_for_folders() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("unsafe.rpf");
    let names = [
        (hash64(b"../../escape"), "../../escape.bin"),
        (hash64(b"/abs/x"), "/abs/x.bin"),
        (hash64(b"C:/x"), "C:/x.bin"),
        (hash64(b"a/./b"), "a/./b.bin"),
        (hash64(b"a//b"), "a//b.bin"),
        (hash64(b"a/.."), "a/.."),
    ];
    let rows: Vec<Spec> = names
        .iter()
        .map(|(hash, _)| Spec {
            hash: Some(*hash),
            ..spec(&[7; 16], RPF_TYPE)
        })
        .collect();
    fs::write(&path, native_rpf(&rows)).unwrap();
    let table: String = names
        .iter()
        .map(|(hash, name)| format!("hash64:{hash:016X}\t{name}\n"))
        .collect();
    fs::write(temp.path().join("unsafe.rpf.names.txt"), table).unwrap();

    // None of the names can place a row, so they are verified suggestions in
    // the details, and every row keeps its key as the label.
    let entries = files::list(&path).unwrap();
    assert_eq!(entries.len(), names.len());
    for (entry, (hash, name)) in entries.iter().zip(&names) {
        assert_eq!(entry.name, format!("0x{hash:016X}.rpf"));
        assert_eq!(detail(entry, "Names"), *name);
        assert_eq!(
            detail(entry, "Name source"),
            "User mapping, verified by hash"
        );
    }
    let note = files::describe(&path).unwrap();
    assert!(!note.contains("shown as folders"), "{note}");
    assert!(!note.contains("Unnamed Entries"), "{note}");
    assert!(files::read(&path.join("Row 00000")).is_ok());
}

#[test]
fn unusable_tables_fall_back_to_recovery() {
    let temp = tempfile::tempdir().unwrap();
    // Encrypted, as in real archives.
    let encrypted = temp.path().join("encrypted.rpf");
    fs::write(
        &encrypted,
        rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")]),
    )
    .unwrap();
    // A table whose primary area ends inside the header.
    let mut broken = rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")]);
    broken[8..12].copy_from_slice(&0x20u32.to_le_bytes());
    let malformed = temp.path().join("malformed.rpf");
    fs::write(&malformed, broken).unwrap();

    for (path, reason) in [
        (
            &encrypted,
            "The table of contents is processed before use: it is encrypted: the static pass \
             decrypts it with cipher type 16",
        ),
        (&malformed, "The table of contents could not be read:"),
    ] {
        assert!(prepare_required(&files::list(path).unwrap_err()).is_some());
        assert_eq!(names_of(&list_opened(path)), [files::rpf::RECOVERED]);
        let note = files::describe(path).unwrap();
        assert!(note.starts_with(reason), "{note}");
        assert!(note.contains("recovered from zlib streams"), "{note}");
    }
    assert!(
        files::describe(&malformed)
            .unwrap()
            .contains("primary area ends inside the header")
    );
}

#[test]
fn raw_entries_open_as_nested_archives() {
    let temp = tempfile::tempdir().unwrap();
    let zip = zip_bytes(&[("leaf.txt", b"leaf")]);
    let inner_native = native_rpf(&[spec(b"deep leaf", 3)]);
    let encrypted = rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")]);
    let path = temp.path().join("outer.rpf");
    fs::write(
        &path,
        native_rpf(&[
            spec(&zip, RPF_TYPE),
            spec(&inner_native, RPF_TYPE),
            spec(&encrypted, RPF_TYPE),
            Spec {
                mode: 2,
                ..spec(&zip, RPF_TYPE)
            },
        ]),
    )
    .unwrap();

    // ZIP in RPF9, as a view.
    let row = |n: u32| path.join(row_name(n));
    let nested = opened(&row(0));
    assert_eq!(
        (nested.format, nested.depth, nested.decompressed),
        (archive::Format::Zip, 2, 0)
    );
    assert_eq!(files::read(&row(0).join("leaf.txt")).unwrap(), b"leaf");
    // RPF9 in RPF9, native in native and encrypted in native.
    let nested = opened(&row(1));
    assert_eq!(
        (nested.format, nested.decompressed),
        (archive::Format::Rpf9, 0)
    );
    assert_eq!(
        files::read(&row(1).join("Row 00000")).unwrap(),
        b"deep leaf"
    );
    assert_eq!(names_of(&list_opened(&row(2))), [files::rpf::RECOVERED]);
    // Recognised by content, then listed as an archive.
    let listed = files::list(&path).unwrap();
    assert_eq!(listed[0].kind, EntryKind::Archive);
    assert_eq!(listed[1].kind, EntryKind::Archive);
    // An entry with an unsupported mode is not opened.
    let err = archive::prepare(&row(3), &Progress::default(), &AtomicBool::new(false)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("mode 2"), "{err}");
    assert!(prepare_required(&files::list(&row(3)).unwrap_err()).is_some());
}

#[test]
fn native_archives_open_inside_zip_archives() {
    let temp = tempfile::tempdir().unwrap();
    let inner = native_rpf(&[spec(b"inside", 9)]);
    let files_in_zip: [(&str, &[u8]); 1] = [("data.bin", &inner)];
    let stored = temp.path().join("stored.zip");
    fs::write(
        &stored,
        zip_bytes_with(&files_in_zip, ::zip::CompressionMethod::Stored),
    )
    .unwrap();
    let deflated = temp.path().join("deflated.zip");
    fs::write(&deflated, zip_bytes(&files_in_zip)).unwrap();
    for (outer, decompressed) in [(&stored, 0), (&deflated, inner.len() as u64)] {
        let path = outer.join("data.bin");
        let nested = opened(&path);
        assert_eq!(nested.decompressed, decompressed);
        assert_eq!(names_of(&files::list(&path).unwrap()), ["Row 00000"]);
        assert_eq!(files::read(&path.join("Row 00000")).unwrap(), b"inside");
    }
}

#[test]
fn encrypted_tables_are_never_read_in_full() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("encrypted.rpf");
    fs::write(&path, rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")])).unwrap();
    let before = full_reads();
    // Listing before the scan, preparing, listing and describing.
    assert!(prepare_required(&files::list(&path).unwrap_err()).is_some());
    assert!(prepare_required(&files::list(&path).unwrap_err()).is_some());
    assert_eq!(names_of(&list_opened(&path)), [files::rpf::RECOVERED]);
    assert!(files::describe(&path).unwrap().contains("encrypted"));
    // A changed archive is probed again, still without a full read.
    fs::write(
        &path,
        rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><b/>"), zlib(b"x")]),
    )
    .unwrap();
    assert!(prepare_required(&files::list(&path).unwrap_err()).is_some());
    assert_eq!(full_reads(), before);
}

/// Counts reads, so it relies on its archive staying in memory. Tests get
/// enough room in the cache for that.
#[test]
fn usable_tables_are_read_once_until_something_changes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("native.rpf");
    fs::write(&path, native_rpf(&[spec(b"one", 1)])).unwrap();
    let before = full_reads();
    for _ in 0..3 {
        assert_eq!(names_of(&files::list(&path).unwrap()), ["Row 00000"]);
        files::describe(&path).unwrap();
    }
    assert_eq!(full_reads(), before + 1);
    // A new candidate file, then a changed archive.
    fs::write(temp.path().join("native.rpf.names.txt"), "x\n").unwrap();
    files::list(&path).unwrap();
    assert_eq!(full_reads(), before + 2);
    fs::write(&path, native_rpf(&[spec(b"one", 1), spec(b"two", 1)])).unwrap();
    assert_eq!(files::list(&path).unwrap().len(), 2);
    assert_eq!(full_reads(), before + 3);
}

#[test]
fn passes_other_than_decryption_are_named_as_such() {
    let temp = tempfile::tempdir().unwrap();
    // Static descriptor 0, a no-op cipher.
    let mut no_op = rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")]);
    no_op[0x2E] = 1;
    // Selector 0 with B sub-block 1, whose cipher type is stored as 0.
    let mut archive_pass = native_rpf(&[spec(b"one", 1)]);
    archive_pass[0x40..0x42].copy_from_slice(&1u16.to_le_bytes());
    let before = full_reads();
    for (name, bytes, expected) in [
        (
            "no_op.rpf",
            no_op,
            "the static pass processes it with cipher type 0, a no-op cipher",
        ),
        (
            "archive_pass.rpf",
            archive_pass,
            "the archive pass processes it with cipher type 0, a no-op cipher",
        ),
    ] {
        let path = temp.path().join(name);
        fs::write(&path, bytes).unwrap();
        list_opened(&path);
        let note = files::describe(&path).unwrap();
        assert!(note.contains(expected), "{note}");
        assert!(!note.contains("encrypted"), "{note}");
    }
    assert_eq!(full_reads(), before);
}

pub(crate) fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    io::Write::write_all(&mut encoder, data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn decoded_entries_read_and_hold_archives() {
    let temp = tempfile::tempdir().unwrap();
    let text: Vec<u8> = (0..100_000u32).map(|i| b'a' + (i / 9 % 26) as u8).collect();
    let zip = zip_bytes(&[("leaf.txt", b"leaf")]);
    let inner_native = native_rpf(&[spec(b"deep leaf", 3)]);
    let (zip_chunks, zip_table, zip_len) = zlib_chunks(&[&zip[..20], &zip[20..]]);
    let (rpf_chunks, rpf_table, rpf_len) = zlib_chunks(&[&inner_native]);
    let (text_chunks, text_table, text_len) = zlib_chunks(&[&text[..60_000], &text[60_000..]]);
    let mut bad_chunks = text_chunks.clone();
    // The Adler-32 trailer of the second zlib stream.
    let second_end = zlib(&text[..60_000]).len().next_multiple_of(16) + zlib(&text[60_000..]).len();
    bad_chunks[second_end - 1] ^= 1;
    let path = temp.path().join("decoded.rpf");
    fs::write(
        &path,
        native_rpf(&[
            Spec {
                mode: 1,
                logical: Some(text.len() as u64),
                ..spec(&deflate(&text), 0)
            },
            Spec {
                chunks: Some(text_table.clone()),
                logical: Some(text_len),
                ..spec(&text_chunks, 0)
            },
            Spec {
                chunks: Some(zip_table),
                logical: Some(zip_len),
                ..spec(&zip_chunks, RPF_TYPE)
            },
            Spec {
                mode: 1,
                logical: Some(inner_native.len() as u64),
                ..spec(&deflate(&inner_native), RPF_TYPE)
            },
            Spec {
                chunks: Some(rpf_table),
                logical: Some(rpf_len),
                ..spec(&rpf_chunks, RPF_TYPE)
            },
            Spec {
                chunks: Some(text_table),
                logical: Some(text_len),
                ..spec(&bad_chunks, 0)
            },
        ]),
    )
    .unwrap();

    let entries = files::list(&path).unwrap();
    assert_eq!(detail(&entries[0], "Compression"), "Raw DEFLATE");
    assert_eq!(
        detail(&entries[0], "Contents"),
        "Readable, decoded when read"
    );
    assert!(detail(&entries[1], "Compression").starts_with("In chunks"));
    assert_eq!(
        detail(&entries[1], "Chunks"),
        "2 in encoding 4: 2 zlib, 0 copied"
    );
    // Read in full, and in the Binary Inspector.
    for n in [0, 1] {
        assert_eq!(entries[n].size, Some(text.len() as u64));
        assert_eq!(files::read(&entries[n].path).unwrap(), text);
        let mut inspected = files::open_binary(&entries[n].path).unwrap();
        assert_eq!(
            lforge_binary::read_at(&mut inspected.source, 59_990, 20).unwrap(),
            text[59_990..60_010]
        );
    }
    // Archives in decoded entries are recognised by content and decompressed
    // within the chain's budget.
    let row = |n: u32| path.join(row_name(n));
    let nested = opened(&row(2));
    assert_eq!(nested.format, archive::Format::Zip);
    assert_eq!(nested.decompressed, zip.len() as u64);
    assert_eq!(files::read(&row(2).join("leaf.txt")).unwrap(), b"leaf");
    for n in [3, 4] {
        let nested = opened(&row(n));
        assert_eq!(nested.format, archive::Format::Rpf9);
        assert_eq!(nested.decompressed, inner_native.len() as u64);
        assert_eq!(
            files::read(&row(n).join("Row 00000")).unwrap(),
            b"deep leaf"
        );
    }
    // A damaged chunk is reported, not returned.
    let err = files::read(&entries[5].path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(files::open_binary(&entries[5].path).is_err());
    // Decompressing a nested archive can be cancelled.
    let cancelled = temp.path().join("cancelled.rpf");
    fs::write(
        &cancelled,
        native_rpf(&[Spec {
            mode: 1,
            logical: Some(inner_native.len() as u64),
            ..spec(&deflate(&inner_native), RPF_TYPE)
        }]),
    )
    .unwrap();
    let err = archive::prepare(
        &cancelled.join("Row 00000"),
        &Progress::default(),
        &AtomicBool::new(true),
    )
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
}

const COMPANION_MAGIC: [u8; 8] = [0, 0, 0, 0x39, 0x56, 0x46, 0x50, 0x52];

/// `archive` with a companion header: the payloads at the same offsets.
pub(crate) fn companion_of(archive: &[u8], identifier: u64) -> Vec<u8> {
    let mut bytes = archive.to_vec();
    bytes[..8].copy_from_slice(&COMPANION_MAGIC);
    bytes[8..16].copy_from_slice(&identifier.to_le_bytes());
    bytes
}

/// Rows read through companions, with sub-block 3 listing `missing.dat`,
/// `data.dat` and `bad.dat`. Returns the archive with zeros where the
/// companion rows' payloads are, the archive with them, and the text.
fn companion_archive() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let text: Vec<u8> = (0..30_000u32).map(|i| b'a' + (i / 5 % 26) as u8).collect();
    let rows = [
        Spec {
            source: Some(1),
            ..spec(&text, 0)
        },
        Spec {
            source: Some(1),
            mode: 1,
            logical: Some(text.len() as u64),
            ..spec(&deflate(&text), 0)
        },
        Spec {
            source: Some(0),
            ..spec(&text, 0)
        },
        Spec {
            source: Some(2),
            ..spec(&text, 0)
        },
        Spec {
            source: Some(5),
            ..spec(&text, 0)
        },
        spec(b"in the main file", 0),
    ];
    let companions: [(&[u8], u64); 3] = [(b"missing.dat", 1), (b"data.dat", 2), (b"bad.dat", 3)];
    let full = native_rpf_with(&rows, &companions);
    let mut main = full.clone();
    // The main row's payload is last; everything before it is zeroed.
    let last = full
        .windows(16)
        .rposition(|w| w == b"in the main file")
        .unwrap();
    let first = u32::from_le_bytes(full[4..8].try_into().unwrap()) as usize;
    main[first.next_multiple_of(16)..last].fill(0);
    (main, full, text)
}

#[test]
fn companions_are_found_next_to_the_archive() {
    let temp = tempfile::tempdir().unwrap();
    let (main, full, text) = companion_archive();
    let path = temp.path().join("main.rpf");
    fs::write(&path, &main).unwrap();
    fs::write(temp.path().join("data.dat"), companion_of(&full, 2)).unwrap();
    fs::write(temp.path().join("bad.dat"), companion_of(&full, 9)).unwrap();

    let entries = files::list(&path).unwrap();
    assert_eq!(
        detail(&entries[0], "Read source"),
        "Companion 1 (data.dat), available"
    );
    assert!(detail(&entries[2], "Read source").starts_with("Companion 0 (missing.dat), missing"));
    assert!(detail(&entries[3], "Read source").starts_with("Companion 2 (bad.dat), invalid"));
    assert!(detail(&entries[3], "Read source").contains("identifier"));
    assert_eq!(
        detail(&entries[4], "Read source"),
        "Companion 5, not listed by the archive"
    );
    assert_eq!(detail(&entries[5], "Read source"), "Main");
    assert_eq!(detail(&entries[0], "Contents"), "Readable as stored");
    assert_eq!(
        detail(&entries[1], "Contents"),
        "Readable, decoded when read"
    );
    assert!(detail(&entries[2], "Contents").starts_with("Not readable"));
    let note = files::describe(&path).unwrap();
    assert!(
        note.contains("3 companion files: 1 available, 1 missing, 1 invalid, 0 not supported"),
        "{note}"
    );

    // Stored and raw DEFLATE rows come from the companion, at the same
    // offsets as in the main file.
    for n in [0, 1] {
        assert_eq!(files::read(&entries[n].path).unwrap(), text, "row {n}");
    }
    let mut inspected = files::open_binary(&entries[0].path).unwrap();
    assert_eq!(
        lforge_binary::read_at(&mut inspected.source, 100, 10).unwrap(),
        text[100..110]
    );
    assert_eq!(files::read(&entries[5].path).unwrap(), b"in the main file");
    // Unavailable companions do not fall back to the main file.
    for n in [2, 3, 4] {
        let err = files::read(&entries[n].path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "row {n}");
        assert!(err.to_string().contains("alternate source"), "{err}");
    }
}

#[test]
fn changed_companions_are_checked_again() {
    let temp = tempfile::tempdir().unwrap();
    let (main, full, text) = companion_archive();
    let path = temp.path().join("main.rpf");
    fs::write(&path, &main).unwrap();
    let data = temp.path().join("data.dat");
    fs::write(&data, companion_of(&full, 2)).unwrap();
    let row = |n: u32| path.join(row_name(n));
    assert_eq!(files::read(&row(0)).unwrap(), text);

    // A wrong identifier makes the cached companion unusable.
    let mut wrong = companion_of(&full, 7);
    wrong.push(0);
    fs::write(&data, &wrong).unwrap();
    assert!(files::read(&row(0)).is_err());
    let entries = files::list(&path).unwrap();
    assert!(detail(&entries[0], "Read source").contains("invalid"));
    // A companion that appears later is used.
    fs::write(&data, companion_of(&full, 2)).unwrap();
    fs::write(temp.path().join("missing.dat"), companion_of(&full, 1)).unwrap();
    assert_eq!(files::read(&row(0)).unwrap(), text);
    assert_eq!(files::read(&row(2)).unwrap(), text);
    // A removed companion is noticed.
    fs::remove_file(&data).unwrap();
    assert!(files::read(&row(0)).is_err());
}

#[test]
fn archives_in_archives_have_no_companion_directory() {
    let temp = tempfile::tempdir().unwrap();
    let (main, full, _) = companion_archive();
    let outer = temp.path().join("outer.zip");
    let data = companion_of(&full, 2);
    fs::write(
        &outer,
        zip_bytes_with(
            &[("main.rpf", &main), ("data.dat", &data)],
            ::zip::CompressionMethod::Stored,
        ),
    )
    .unwrap();
    // A data.dat next to the outer file is not used either.
    fs::write(temp.path().join("data.dat"), &data).unwrap();
    let path = outer.join("main.rpf");
    opened(&path);
    let entries = files::list(&path).unwrap();
    let source = detail(&entries[0], "Read source");
    assert!(source.contains("not supported"), "{source}");
    assert!(source.contains("stored in another archive"), "{source}");
    let err = files::read(&entries[0].path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert_eq!(files::read(&entries[5].path).unwrap(), b"in the main file");
    assert!(files::describe(&path).unwrap().contains("0 available"));
}

/// A main archive whose rows are read from companion `data.dat`: a stored
/// ZIP holding `leaf.txt` with `leaf`, a native RPF9, and the ZIP again as
/// raw DEFLATE.
fn companion_nesting(leaf: &[u8]) -> Vec<u8> {
    let zip = zip_bytes_with(&[("leaf.txt", leaf)], ::zip::CompressionMethod::Stored);
    let inner = native_rpf(&[spec(b"deep leaf", 3)]);
    native_rpf_with(
        &[
            Spec {
                source: Some(0),
                ..spec(&zip, RPF_TYPE)
            },
            Spec {
                source: Some(0),
                ..spec(&inner, RPF_TYPE)
            },
            Spec {
                source: Some(0),
                mode: 1,
                logical: Some(zip.len() as u64),
                ..spec(&deflate(&zip), RPF_TYPE)
            },
        ],
        &[(b"data.dat", 2)],
    )
}

#[test]
fn archives_in_companions_open_and_follow_the_companion() {
    let temp = tempfile::tempdir().unwrap();
    let full = companion_nesting(b"leaf");
    let path = temp.path().join("main.rpf");
    fs::write(&path, &full).unwrap();
    let data = temp.path().join("data.dat");
    fs::write(&data, companion_of(&full, 2)).unwrap();
    let row = |n: u32| path.join(row_name(n));

    // ZIP and RPF9 in companion rows, recognised by content.
    let nested = opened(&row(0));
    assert_eq!(
        (nested.format, nested.decompressed),
        (archive::Format::Zip, 0)
    );
    assert_eq!(nested.dependencies.len(), 1);
    assert_eq!(nested.dependencies[0].0, data);
    assert_eq!(files::read(&row(0).join("leaf.txt")).unwrap(), b"leaf");
    let nested = opened(&row(1));
    assert_eq!(nested.format, archive::Format::Rpf9);
    assert_eq!(
        files::read(&row(1).join("Row 00000")).unwrap(),
        b"deep leaf"
    );
    let nested = opened(&row(2));
    assert_eq!(nested.format, archive::Format::Zip);
    assert!(nested.decompressed > 0);
    assert_eq!(files::read(&row(2).join("leaf.txt")).unwrap(), b"leaf");
    assert_eq!(files::list(&path).unwrap()[0].kind, EntryKind::Archive);

    // A replaced companion, with the main archive unchanged.
    let changed = companion_nesting(b"LEAF");
    let mut replacement = companion_of(&changed, 2);
    replacement.push(0);
    fs::write(&data, &replacement).unwrap();
    assert_eq!(fs::read(&path).unwrap(), full);
    for n in [0, 2] {
        assert!(prepare_required(&files::list(&row(n)).unwrap_err()).is_some());
        assert_eq!(files::read(&row(n).join("leaf.txt")).unwrap(), b"LEAF");
    }

    // A removed companion, then one that reappears.
    fs::remove_file(&data).unwrap();
    let err = files::read(&row(0).join("leaf.txt")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{err}");
    let entries = files::list(&path).unwrap();
    assert!(detail(&entries[0], "Read source").contains("missing"));
    assert!(detail(&entries[0], "Contents").starts_with("Not readable"));
    fs::write(&data, companion_of(&full, 2)).unwrap();
    assert_eq!(files::read(&row(0).join("leaf.txt")).unwrap(), b"leaf");
    assert_eq!(
        files::read(&row(1).join("Row 00000")).unwrap(),
        b"deep leaf"
    );
}
