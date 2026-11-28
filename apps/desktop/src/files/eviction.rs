//! Archives whose cached state is evicted between operations.
//!
//! Each test evicts only the archives under its own temporary directory, so
//! tests running at the same time do not affect it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use lforge_rage9::rpf::Progress;
use lforge_rage9::rpf::names::RPF_TYPE;

use super::archive::{self, Location, forget_kept, locate, prepare, prepare_required};
use super::rpf::tests::{rpf_bytes, zlib};
use super::rpf::{self, RECOVERED, forget};
use super::toc::tests::{Spec, companion_of, deflate, native_rpf, native_rpf_with, spec};
use super::zip::tests::{zip_bytes, zip_bytes_with};
use super::{Entry, list, read};

/// Evicts what is cached for `paths`, as pressure from other archives would.
fn evict(paths: &[PathBuf]) {
    for path in paths {
        forget(path);
        forget_kept(path);
    }
}

fn names(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.name.as_str()).collect()
}

fn prepare_path(path: &Path) -> io::Result<()> {
    prepare(path, &Progress::default(), &AtomicBool::new(false))
}

fn stored_zip(leaf: &[u8]) -> Vec<u8> {
    zip_bytes_with(&[("leaf.txt", leaf)], ::zip::CompressionMethod::Stored)
}

/// The recovered XML entry of an archive written by [`rpf_bytes`] with one
/// part.
fn recovered_xml(archive: &Path) -> PathBuf {
    archive
        .join(RECOVERED)
        .join("XML")
        .join(format!("0x{:010X}.xml", 0x100))
}

const XML: &[u8] = b"<?xml version=\"1.0\"?><a/>";

#[test]
fn evicted_archives_are_prepared_again() {
    let temp = tempfile::tempdir().unwrap();
    // Recovered by scanning: after eviction it needs a scan again, as no
    // cache directory is used in tests.
    let scanned = temp.path().join("scanned.rpf");
    fs::write(&scanned, rpf_bytes(&[zlib(XML)])).unwrap();
    prepare_path(&scanned).unwrap();
    forget(&scanned);
    let err = list(&scanned).unwrap_err();
    assert_eq!(prepare_required(&err), Some(scanned.as_path()));
    prepare_path(&scanned).unwrap();
    assert_eq!(names(&list(&scanned).unwrap()), [RECOVERED]);
    // Reading prepares on its own.
    forget(&scanned);
    assert_eq!(read(&recovered_xml(&scanned)).unwrap(), XML);

    // A native table is read again without preparing.
    let native = temp.path().join("native.rpf");
    fs::write(&native, native_rpf(&[spec(b"row", 1)])).unwrap();
    assert_eq!(names(&list(&native).unwrap()), ["unidentified"]);
    forget(&native);
    assert_eq!(names(&list(&native).unwrap()), ["unidentified"]);

    // A nested archive is opened again from its parent.
    let outer = temp.path().join("outer.zip");
    fs::write(&outer, zip_bytes(&[("inner.zip", &stored_zip(b"leaf"))])).unwrap();
    let nested = outer.join("inner.zip");
    prepare_path(&nested).unwrap();
    assert_eq!(names(&list(&nested).unwrap()), ["leaf.txt"]);
    forget_kept(&nested);
    assert_eq!(
        prepare_required(&list(&nested).unwrap_err()),
        Some(nested.as_path())
    );
    prepare_path(&nested).unwrap();
    assert_eq!(names(&list(&nested).unwrap()), ["leaf.txt"]);
}

/// ZIP, holding native RPF9, holding encrypted RPF9 and a ZIP.
fn mixed_chain(dir: &Path) -> (Vec<PathBuf>, PathBuf, PathBuf) {
    let native = native_rpf(&[
        spec(&rpf_bytes(&[zlib(XML)]), RPF_TYPE),
        Spec {
            mode: 1,
            logical: Some(stored_zip(b"deep").len() as u64),
            ..spec(&deflate(&stored_zip(b"deep")), RPF_TYPE)
        },
    ]);
    let outer = dir.join("chain.zip");
    fs::write(&outer, zip_bytes(&[("native.rpf", &native)])).unwrap();
    let native = outer.join("native.rpf");
    // Both rows store no key, so their labels carry the occurrence number.
    let encrypted = native.join("unidentified~1");
    let zip = native.join("unidentified~2");
    let paths = vec![native.clone(), encrypted.clone(), zip.clone()];
    (paths, recovered_xml(&encrypted), zip.join("leaf.txt"))
}

#[test]
fn repeated_misses_reload_every_level() {
    let temp = tempfile::tempdir().unwrap();
    let (paths, xml, leaf) = mixed_chain(temp.path());
    for round in 0..20 {
        // Each level, all levels, or none.
        match round % 3 {
            0 => evict(&paths[round % paths.len()..=round % paths.len()]),
            1 => evict(&paths),
            _ => {}
        }
        assert_eq!(read(&xml).unwrap(), XML, "round {round}");
        assert_eq!(read(&leaf).unwrap(), b"deep", "round {round}");
    }
}

/// Reads `path`. Under eviction a read may give up after its attempts, but
/// it never returns other bytes.
fn read_checked(path: &Path, expected: &[u8]) -> bool {
    match read(path) {
        Ok(bytes) => {
            assert_eq!(bytes, expected, "{}", path.display());
            true
        }
        Err(err) => {
            let message = err.to_string();
            assert!(
                prepare_required(&err).is_some() || message.contains("could not be opened"),
                "{}: {message}",
                path.display()
            );
            false
        }
    }
}

#[test]
fn concurrent_readers_survive_eviction() {
    let temp = tempfile::tempdir().unwrap();
    let chains: Vec<_> = (0..4)
        .map(|n| {
            let dir = temp.path().join(format!("chain{n}"));
            fs::create_dir(&dir).unwrap();
            mixed_chain(&dir)
        })
        .collect();
    let all: Vec<PathBuf> = chains
        .iter()
        .flat_map(|(paths, ..)| paths.clone())
        .collect();
    let files: Vec<(PathBuf, PathBuf)> = chains
        .iter()
        .map(|(_, xml, leaf)| (xml.clone(), leaf.clone()))
        .collect();

    // In lock step: readers in parallel, then everything is evicted. Every
    // read must find its way back.
    let rounds = 8;
    let barrier = Arc::new(Barrier::new(files.len() + 1));
    let readers: Vec<_> = files
        .iter()
        .cloned()
        .map(|(xml, leaf)| {
            let barrier = barrier.clone();
            thread::spawn(move || {
                for _ in 0..rounds {
                    barrier.wait();
                    assert_eq!(read(&xml).unwrap(), XML);
                    assert_eq!(read(&leaf).unwrap(), b"deep");
                    barrier.wait();
                }
            })
        })
        .collect();
    for _ in 0..rounds {
        barrier.wait();
        barrier.wait();
        evict(&all);
    }
    for reader in readers {
        reader.join().unwrap();
    }

    // Freely: eviction runs while the readers read.
    let done = Arc::new(AtomicBool::new(false));
    let evictor = {
        let (done, all) = (done.clone(), all.clone());
        thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                evict(&all);
                thread::yield_now();
            }
        })
    };
    let readers: Vec<_> = files
        .iter()
        .cloned()
        .map(|(xml, leaf)| {
            thread::spawn(move || {
                for _ in 0..20 {
                    read_checked(&xml, XML);
                    read_checked(&leaf, b"deep");
                }
            })
        })
        .collect();
    for reader in readers {
        reader.join().unwrap();
    }
    done.store(true, Ordering::Relaxed);
    evictor.join().unwrap();
    // Once eviction stops, everything reads.
    for (xml, leaf) in &files {
        assert_eq!(read(xml).unwrap(), XML);
        assert_eq!(read(leaf).unwrap(), b"deep");
    }
}

#[test]
fn an_opened_archive_outlives_its_cache_entry() {
    let temp = tempfile::tempdir().unwrap();
    let inner = stored_zip(b"leaf");
    let outer = temp.path().join("outer.zip");
    fs::write(&outer, zip_bytes(&[("inner.zip", &inner)])).unwrap();
    let nested = outer.join("inner.zip");
    prepare_path(&nested).unwrap();
    let Location::Archive(opened) = locate(&nested).unwrap() else {
        panic!("expected the opened archive");
    };
    forget_kept(&nested);
    // Its source stays readable after eviction.
    assert_eq!(archive::read_all(&opened).unwrap(), inner);
    assert_eq!(
        prepare_required(&list(&nested).unwrap_err()),
        Some(nested.as_path())
    );

    // A located file of an evicted scanned archive reports that it has to be
    // prepared again.
    let scanned = temp.path().join("scanned.rpf");
    fs::write(&scanned, rpf_bytes(&[zlib(XML)])).unwrap();
    prepare_path(&scanned).unwrap();
    let Location::Inside(parent, inner) = locate(&recovered_xml(&scanned)).unwrap() else {
        panic!("expected a file inside the archive");
    };
    forget(&scanned);
    let err = archive::copy(&parent, &inner, &mut Vec::new(), archive::MAX_READ).unwrap_err();
    assert!(prepare_required(&err).is_some(), "{err}");
    assert!(rpf::raw_source(&parent, &inner).is_err());
}

/// `main.rpf`, whose row 0 is read from companion `data.dat` and holds a
/// native RPF9 whose row 0 is a ZIP with `leaf.txt`.
fn companion_chain(leaf: &[u8]) -> Vec<u8> {
    let inner = native_rpf(&[spec(&stored_zip(leaf), RPF_TYPE)]);
    native_rpf_with(
        &[Spec {
            source: Some(0),
            ..spec(&inner, RPF_TYPE)
        }],
        &[(b"data.dat", 2)],
    )
}

#[test]
fn companion_changes_reach_every_level() {
    let temp = tempfile::tempdir().unwrap();
    let main = temp.path().join("main.rpf");
    let full = companion_chain(b"leaf");
    fs::write(&main, &full).unwrap();
    let data = temp.path().join("data.dat");
    fs::write(&data, companion_of(&full, 2)).unwrap();
    let level1 = main.join("unidentified");
    let level2 = level1.join("unidentified");
    let leaf = level2.join("leaf.txt");
    let levels = [main.clone(), level1.clone(), level2.clone()];
    assert_eq!(read(&leaf).unwrap(), b"leaf");

    // A replaced companion, with and without eviction in between.
    for (round, text) in [&b"LEAF"[..], b"Leaf", b"lEAF"].iter().enumerate() {
        let mut replacement = companion_of(&companion_chain(text), 2);
        replacement.resize(replacement.len() + round + 1, 0);
        fs::write(&data, &replacement).unwrap();
        if round == 1 {
            evict(&levels);
        }
        assert_eq!(read(&leaf).unwrap(), *text, "round {round}");
        // The deeper archives depend on the companion too.
        let Location::Archive(deep) = archive::locate_prepared(&level2).unwrap() else {
            panic!("expected the opened archive");
        };
        assert_eq!(deep.dependencies.len(), 1);
    }

    // Removed: every level below it is gone. Back: it reads again.
    fs::remove_file(&data).unwrap();
    assert_eq!(read(&leaf).unwrap_err().kind(), io::ErrorKind::Unsupported);
    assert!(list(&level2).is_err());
    fs::write(&data, companion_of(&full, 2)).unwrap();
    evict(&levels);
    assert_eq!(read(&leaf).unwrap(), b"leaf");
}

#[test]
fn cancelled_loading_leaves_nothing_behind() {
    let temp = tempfile::tempdir().unwrap();
    let noise: Vec<u8> = (0..400_000u32).map(|i| (i * 7919 % 251) as u8).collect();
    let big = zip_bytes(&[("noise.bin", &noise)]);
    let native = temp.path().join("native.rpf");
    fs::write(
        &native,
        native_rpf(&[Spec {
            mode: 1,
            logical: Some(big.len() as u64),
            ..spec(&deflate(&big), RPF_TYPE)
        }]),
    )
    .unwrap();
    let outer = temp.path().join("outer.zip");
    fs::write(&outer, zip_bytes(&[("big.zip", &big)])).unwrap();
    for nested in [native.join("unidentified"), outer.join("big.zip")] {
        let err = prepare(&nested, &Progress::default(), &AtomicBool::new(true)).unwrap_err();
        assert_eq!(
            err.kind(),
            io::ErrorKind::Interrupted,
            "{}",
            nested.display()
        );
        assert!(prepare_required(&list(&nested).unwrap_err()).is_some());
        prepare_path(&nested).unwrap();
        assert_eq!(names(&list(&nested).unwrap()), ["noise.bin"]);
    }
}
