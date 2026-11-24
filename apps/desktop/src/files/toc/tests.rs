//! Explorer tests on synthetic archives with an unencrypted table of
//! contents.

use std::cell::Cell;
use std::sync::atomic::AtomicBool;

use lforge_rage9::rpf::Progress;
use lforge_rage9::rpf::metadata::keys;
use lforge_rage9::rpf::names::{NO_TYPE, RPF_TYPE, hash64, joaat};

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
    }
}

/// An archive whose table of contents is stored unencrypted: columns name
/// hash, name key and A location record, then the payloads.
pub(crate) fn native_rpf(rows: &[Spec]) -> Vec<u8> {
    let n = rows.len();
    assert!(n < 0xFE);
    let cells = 0xA8;
    let pool = (cells + 3 * n).next_multiple_of(8);
    // The empty secondary area starts 8-aligned after the primary one.
    let end = (pool + 28 * n).next_multiple_of(8);
    let payloads = end.next_multiple_of(16);
    let mut bytes = vec![0u8; payloads];
    let put = |bytes: &mut Vec<u8>, at: usize, value: &[u8]| {
        bytes[at..at + value.len()].copy_from_slice(value);
    };
    put(&mut bytes, 0, b"9FPR");
    put(&mut bytes, 0x04, &(end as u32).to_le_bytes());
    put(&mut bytes, 0x08, &(end as u32).to_le_bytes());
    put(&mut bytes, 0x1A, &1u16.to_le_bytes());
    put(&mut bytes, 0x1C, &0x10u32.to_le_bytes());
    put(&mut bytes, 0x20, &3u16.to_le_bytes());
    put(&mut bytes, 0x24, &(n as u32).to_le_bytes());
    bytes[0x2C] = 1;
    bytes[0x2D] = 1;
    put(&mut bytes, 0x40, &2u16.to_le_bytes());
    let columns = [
        (keys::NAME_HASH, 0, 8u16),
        (keys::NAME_KEY, 8 * n, 4),
        (keys::LOCATION_A, 12 * n, 16),
    ];
    for (column, (key, offset, width)) in columns.into_iter().enumerate() {
        let at = 0x60 + column * 24;
        put(&mut bytes, at, &key.to_le_bytes());
        put(&mut bytes, at + 0x0C, &(offset as u32).to_le_bytes());
        put(&mut bytes, at + 0x10, &width.to_le_bytes());
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
            cells + r * 3,
            &[hash_cell, cell(row.key.is_some()), cell(row.location)],
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
        let packed =
            row.payload.len() as u64 | (u64::from(row.type_id) << 48) | (u64::from(row.mode) << 56);
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
        data.extend_from_slice(&row.payload);
        data.resize(data.len().next_multiple_of(16), 0);
    }
    bytes.extend_from_slice(&data);
    bytes
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
fn list_opened(path: &Path) -> Vec<Entry> {
    match files::list(path) {
        Err(err) if prepare_required(&err).is_some() => {
            archive::prepare(path, &Progress::default(), &AtomicBool::new(false)).unwrap();
            files::list(path).unwrap()
        }
        result => result.unwrap(),
    }
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
                mode: 1,
                hash: Some(hash64(b"packed")),
                ..spec(&zlib(b"compressed"), RPF_TYPE)
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
    assert_eq!(
        names_of(&entries),
        [
            "Row 00000",
            "Row 00001",
            "Row 00002",
            "Row 00003",
            "Row 00004"
        ]
    );
    let kinds: Vec<EntryKind> = entries.iter().map(|e| e.kind).collect();
    use EntryKind::{File, Unavailable};
    assert_eq!(kinds, [File, File, File, Unavailable, File]);
    assert_eq!(entries[0].type_name, "RPF9 entry, type 0 (rpf)");
    assert_eq!(entries[1].type_name, "RPF9 entry, type 5");
    assert_eq!(entries[1].size, Some(raw.len() as u64));
    assert_eq!(detail(&entries[1], "Names"), "Unknown");
    assert_eq!(
        detail(&entries[1], "Name hash"),
        format!("0x{:016X}", hash64(b"data"))
    );
    assert_eq!(detail(&entries[1], "Compression"), "None");
    assert_eq!(detail(&entries[1], "Read source"), "Main");
    assert_eq!(detail(&entries[1], "Raw bytes"), "Available");
    assert_eq!(detail(&entries[2], "Compression"), "Mode 1, not supported");
    assert!(detail(&entries[2], "Raw bytes").starts_with("Not available"));
    assert_eq!(detail(&entries[3], "Location record"), "Missing");
    assert_eq!(entries[3].type_name, "RPF9 entry, unreadable");
    assert!(detail(&entries[4], "Name hash").starts_with("Malformed"));
    assert_eq!(
        detail(&entries[4], "Names"),
        "Unknown: the row is malformed"
    );
    assert_eq!(detail(&entries[4], "Raw bytes"), "Available");

    let note = files::describe(&path).unwrap();
    assert!(note.contains("table of contents"), "{note}");
    assert!(note.contains("5 entries"), "{note}");
    assert!(note.contains("2 of them have malformed fields"), "{note}");
    assert!(note.contains("native.rpf.names.txt"), "{note}");

    // Raw entries read and open in the Binary Inspector.
    assert_eq!(files::read(&entries[1].path).unwrap(), raw);
    let mut inspected = files::open_binary(&entries[1].path).unwrap();
    assert_eq!(
        lforge_binary::read_at(&mut inspected.source, 0, 100).unwrap(),
        raw
    );
    assert_eq!(files::read(&entries[4].path).unwrap(), [4; 16]);
    // Encoded and unreadable entries are refused with the reason.
    let err = files::read(&entries[2].path).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("compressed"), "{err}");
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
fn names_come_from_candidate_paths() {
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
        ]),
    )
    .unwrap();
    let candidates = temp.path().join("named.rpf.names.txt");
    fs::write(
        &candidates,
        "packs/inner.rpf\r\nPACKS\\INNER.rpf\n\nreadme\n\"readme\"x\nmissing.rpf\nmodel.ydr\n",
    )
    .unwrap();

    let entries = files::list(&path).unwrap();
    // The row stays the name; candidates are details.
    assert_eq!(names_of(&entries), ["Row 00000", "Row 00001", "Row 00002"]);
    assert_eq!(
        detail(&entries[0], "Names"),
        "packs/inner.rpf, PACKS\\INNER.rpf"
    );
    assert!(detail(&entries[1], "Names").starts_with("Ambiguous: readme, \"readme\"x"));
    assert_eq!(
        detail(&entries[2], "Names"),
        "Unknown: no candidate path has this entry's hash"
    );
    let note = files::describe(&path).unwrap();
    assert!(
        note.contains("2 of 3 entries are named by the 6 candidate paths"),
        "{note}"
    );
    assert!(note.contains("1 ambiguously"), "{note}");
    assert!(
        note.contains("1 candidates could not be resolved"),
        "{note}"
    );

    // A changed candidate file is read again.
    fs::write(&candidates, "other.rpf\n").unwrap();
    let entries = files::list(&path).unwrap();
    assert_eq!(detail(&entries[2], "Names"), "other.rpf");
    assert!(detail(&entries[0], "Names").starts_with("Unknown"));
    fs::remove_file(&candidates).unwrap();
    assert_eq!(detail(&files::list(&path).unwrap()[2], "Names"), "Unknown");
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
            "The table of contents is not read: it is encrypted: the static pass decrypts it \
             with cipher type 16",
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
                mode: 1,
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
    // A compressed entry is not opened as raw bytes.
    let err = archive::prepare(&row(3), &Progress::default(), &AtomicBool::new(false)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("compressed"), "{err}");
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
