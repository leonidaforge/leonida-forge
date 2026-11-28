//! ZIP archives, browsed like folders.
//!
//! Each call reads the archive's table of contents again, so changes on disk
//! show up on the next listing.

use std::collections::BTreeMap;
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use chrono::{Local, NaiveDate, TimeZone};
use lforge_binary::Source;
use lforge_core::resource::{EntryId, Locator};
use zip::{CompressionMethod, ZipArchive};

use super::archive::{Archive, check_size};
use super::{Entry, EntryKind};

type Zip = ZipArchive<BufReader<Source>>;

/// Lists the direct children of `inner`. Folders that the archive only
/// implies through the paths of their files are listed as well.
pub fn list(archive: &Archive, inner: &Path) -> io::Result<Vec<Entry>> {
    let mut zip = open(archive)?;
    let dir = archive.path.join(inner);
    let mut children: BTreeMap<String, Entry> = BTreeMap::new();
    let mut found = inner.as_os_str().is_empty();

    for index in 0..zip.len() {
        let file = zip.by_index_raw(index).map_err(io::Error::other)?;
        // Names that escape the archive root, like `../x`, are skipped.
        let Some(name) = file.enclosed_name() else {
            continue;
        };
        let Ok(rest) = name.strip_prefix(inner) else {
            continue;
        };
        found = true;
        let mut components = rest.components();
        let Some(Component::Normal(first)) = components.next() else {
            continue;
        };
        let child = first.to_string_lossy().into_owned();
        let path = dir.join(&child);
        if components.next().is_some() || file.is_dir() {
            children
                .entry(child.clone())
                .or_insert_with(|| Entry::new(child, path, EntryKind::Directory, None, None));
        } else {
            let modified = file.last_modified().and_then(to_system_time);
            let mut entry = Entry::new(
                child.clone(),
                path,
                EntryKind::File,
                Some(file.size()),
                modified,
            );
            let id = EntryId::named(
                name.to_string_lossy().replace('\\', "/"),
                None,
                Locator::Zip(index),
            );
            entry.resource = Some(archive.resource.with_entry(id));
            entry.resource_row = u32::try_from(index).ok();
            children.insert(child.clone(), entry);
        }
    }

    if !found {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the folder does not exist in the archive",
        ));
    }
    Ok(children.into_values().collect())
}

/// The shortest leading part of `inner` that names a file in the archive.
pub fn file_prefix(archive: &Archive, inner: &Path) -> io::Result<Option<PathBuf>> {
    let mut zip = open(archive)?;
    let mut shortest: Option<PathBuf> = None;
    for index in 0..zip.len() {
        let file = zip.by_index_raw(index).map_err(io::Error::other)?;
        if file.is_dir() {
            continue;
        }
        let Some(name) = file.enclosed_name() else {
            continue;
        };
        if inner.starts_with(&name)
            && shortest
                .as_ref()
                .is_none_or(|s| name.components().count() < s.components().count())
        {
            shortest = Some(name);
        }
    }
    Ok(shortest)
}

pub fn file_len(archive: &Archive, inner: &Path) -> io::Result<u64> {
    let mut zip = open(archive)?;
    let index = find(&mut zip, inner)?;
    Ok(zip.by_index_raw(index).map_err(io::Error::other)?.size())
}

/// The canonical identity of the ZIP entry at `inner`, for the path of an
/// archive entered from it.
pub fn entry_id(archive: &Archive, inner: &Path) -> Option<EntryId> {
    let mut zip = open(archive).ok()?;
    let index = find(&mut zip, inner).ok()?;
    Some(EntryId::named(
        inner.to_string_lossy().replace('\\', "/"),
        None,
        Locator::Zip(index),
    ))
}

/// Decompresses one file into `out`, within `limit` bytes.
pub fn copy(
    archive: &Archive,
    inner: &Path,
    out: &mut dyn Write,
    limit: u64,
) -> io::Result<Option<SystemTime>> {
    let mut zip = open(archive)?;
    let index = find(&mut zip, inner)?;
    let file = zip.by_index(index).map_err(io::Error::other)?;
    check_size(file.size(), limit)?;
    let modified = file.last_modified().and_then(to_system_time);
    // The declared size may be wrong, so the copy is capped as well.
    let copied = io::copy(&mut file.take(limit.saturating_add(1)), out)?;
    check_size(copied, limit)?;
    Ok(modified)
}

/// A file stored without compression or encryption, as a view of the
/// archive's source. Its bytes have not been checked against its CRC-32.
pub struct Unverified {
    pub source: Source,
    crc32: u32,
}

/// Bytes read per step when checking a CRC-32.
const VERIFY_CHUNK: usize = 64 * 1024;

impl Unverified {
    /// Reads the bytes once, in bounded pieces, and returns the view if they
    /// match the recorded CRC-32.
    pub fn verify(self, cancel: &AtomicBool) -> io::Result<Source> {
        let mut reader = self.source.clone();
        let mut crc = flate2::Crc::new();
        let mut buf = vec![0; VERIFY_CHUNK];
        let mut read = 0u64;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            crc.update(&buf[..n]);
            read += n as u64;
        }
        if read != self.source.len() || crc.sum() != self.crc32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored file does not match its CRC-32",
            ));
        }
        Ok(self.source)
    }
}

/// A file stored without compression or encryption. `None` for any other
/// file, which has to be decoded instead.
pub fn stored_file(archive: &Archive, inner: &Path) -> io::Result<Option<Unverified>> {
    let mut zip = open(archive)?;
    let index = find(&mut zip, inner)?;
    let file = zip.by_index_raw(index).map_err(io::Error::other)?;
    if file.compression() != CompressionMethod::Stored
        || file.encrypted()
        || file.compressed_size() != file.size()
    {
        return Ok(None);
    }
    // Set by `by_index_raw`, relative to the archive's source.
    let Some(start) = file.data_start() else {
        return Ok(None);
    };
    Ok(Some(Unverified {
        source: archive.source.slice(start, file.size())?,
        crc32: file.crc32(),
    }))
}

fn find(zip: &mut Zip, inner: &Path) -> io::Result<usize> {
    (0..zip.len())
        .find(|&index| {
            zip.by_index_raw(index)
                .ok()
                .filter(|file| !file.is_dir())
                .and_then(|file| file.enclosed_name())
                .is_some_and(|name| name == inner)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the file does not exist in the archive",
            )
        })
}

fn open(archive: &Archive) -> io::Result<Zip> {
    ZipArchive::new(BufReader::new(archive.source.clone())).map_err(io::Error::other)
}

/// ZIP timestamps carry no time zone; by convention they are local time.
fn to_system_time(time: zip::DateTime) -> Option<SystemTime> {
    let naive =
        NaiveDate::from_ymd_opt(time.year().into(), time.month().into(), time.day().into())?
            .and_hms_opt(
                time.hour().into(),
                time.minute().into(),
                time.second().into(),
            )?;
    Some(Local.from_local_datetime(&naive).earliest()?.into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::files::{self, archive};
    use std::fs;
    use zip::write::SimpleFileOptions;

    pub(crate) fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
        zip_bytes_with(files, CompressionMethod::Deflated)
    }

    pub(crate) fn zip_bytes_with(files: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
        let mut out = io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut out);
        let options = SimpleFileOptions::default().compression_method(method);
        for (name, data) in files {
            if name.ends_with('/') {
                zip.add_directory(*name, options).unwrap();
            } else {
                zip.start_file(*name, options).unwrap();
                zip.write_all(data).unwrap();
            }
        }
        zip.finish().unwrap();
        out.into_inner()
    }

    pub(crate) fn write_zip(path: &Path, files: &[(&str, &[u8])]) {
        fs::write(path, zip_bytes(files)).unwrap();
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn opened(path: &Path) -> Archive {
        match archive::locate(path).unwrap() {
            archive::Location::Archive(archive) => archive,
            other => panic!("not an archive: {other:?}"),
        }
    }

    fn verified(archive: &Archive, name: &str) -> io::Result<Source> {
        stored_file(archive, Path::new(name))?
            .expect("a stored file")
            .verify(&AtomicBool::new(false))
    }

    #[test]
    fn stored_files_are_verified_views() {
        let temp = tempfile::tempdir().unwrap();
        // Larger than one verification step.
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let files: [(&str, &[u8]); 3] = [("a.bin", &data), ("b.bin", b"tail"), ("empty.bin", b"")];
        let bytes = zip_bytes_with(&files, CompressionMethod::Stored);
        let stored = temp.path().join("stored.zip");
        fs::write(&stored, &bytes).unwrap();
        let archive = opened(&stored);

        let mut view = verified(&archive, "a.bin").unwrap();
        assert_eq!(view.len(), data.len() as u64);
        assert_eq!(
            lforge_binary::read_at(&mut view, 0, data.len()).unwrap(),
            data
        );
        let mut tail = verified(&archive, "b.bin").unwrap();
        assert_eq!(lforge_binary::read_at(&mut tail, 0, 100).unwrap(), b"tail");
        assert!(verified(&archive, "empty.bin").unwrap().is_empty());
        assert!(stored_file(&archive, Path::new("missing.bin")).is_err());

        let unverified = stored_file(&archive, Path::new("a.bin")).unwrap().unwrap();
        let err = unverified.verify(&AtomicBool::new(true)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);

        // One changed byte in the middle of the stored data.
        let at = bytes
            .windows(4)
            .position(|w| w == &data[1000..1004])
            .unwrap();
        let mut corrupt = bytes.clone();
        corrupt[at] ^= 0xFF;
        let damaged = temp.path().join("damaged.zip");
        fs::write(&damaged, corrupt).unwrap();
        let err = verified(&opened(&damaged), "a.bin").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("CRC-32"), "{err}");
        assert!(verified(&opened(&damaged), "b.bin").is_ok());

        let deflated = temp.path().join("deflated.zip");
        write_zip(&deflated, &[("a.bin", &data)]);
        let archive = opened(&deflated);
        assert!(stored_file(&archive, Path::new("a.bin")).unwrap().is_none());
    }

    #[test]
    fn lists_explicit_and_implied_folders() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("pack.zip");
        write_zip(
            &archive,
            &[
                ("readme.txt", b"hi"),
                ("empty/", b""),
                ("cars/models/car.bin", b"12345"),
                ("cars/テクスチャ.png", b"png"),
            ],
        );

        let root = files::list(&archive).unwrap();
        assert_eq!(names(&root), ["cars", "empty", "readme.txt"]);
        assert_eq!(root[0].kind, EntryKind::Directory);
        assert_eq!(root[0].path, archive.join("cars"));
        assert_eq!(root[2].size, Some(2));
        assert!(root[2].modified.is_some());

        let cars = files::list(&archive.join("cars")).unwrap();
        assert_eq!(names(&cars), ["models", "テクスチャ.png"]);
        assert!(files::list(&archive.join("empty")).unwrap().is_empty());
        assert!(files::list(&archive.join("missing")).is_err());
    }

    #[test]
    fn reads_files_and_resolves_paths_inside_archives() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("Pack.Zip");
        write_zip(&archive, &[("cars/models/car.bin", b"12345")]);
        let inside = archive.join("cars").join("models");

        match archive::locate(&inside).unwrap() {
            archive::Location::Inside(found, inner) => {
                assert_eq!(found.path, archive);
                assert_eq!(inner, Path::new(r"cars\models"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            archive::locate(temp.path()).unwrap(),
            archive::Location::Plain
        ));
        assert_eq!(files::read(&inside.join("car.bin")).unwrap(), b"12345");
        assert!(files::read(&archive.join("cars/missing.bin")).is_err());
        assert_eq!(names(&files::list(&inside).unwrap()), ["car.bin"]);
    }

    #[test]
    fn skips_names_that_escape_the_archive() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("evil.zip");
        write_zip(&archive, &[("../outside.txt", b"x"), ("inside.txt", b"y")]);
        assert_eq!(names(&files::list(&archive).unwrap()), ["inside.txt"]);
    }

    #[test]
    fn extracts_entries_for_random_access() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("pack.zip");
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 7) as u8).collect();
        write_zip(&archive, &[("a/data.bin", &data), ("other.bin", b"x")]);

        let mut file = files::open_binary(&archive.join("a/data.bin")).unwrap();
        assert!(file.modified.is_some());
        assert_eq!(file.source.len(), data.len() as u64);
        assert_eq!(
            lforge_binary::read_at(&mut file.source, 99_998, 16).unwrap(),
            &data[99_998..]
        );
        assert!(files::open_binary(&archive.join("a/missing.bin")).is_err());
        assert!(files::open_binary(&archive.join("a")).is_err());
    }

    #[test]
    fn rejects_entries_over_the_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bomb.zip");
        write_zip(&path, &[("zeros.bin", &[0u8; 4096])]);
        let archive = opened(&path);
        let inner = Path::new("zeros.bin");
        let err = copy(&archive, inner, &mut io::sink(), 4095).unwrap_err();
        assert!(err.to_string().contains("too large"));
        assert!(copy(&archive, inner, &mut io::sink(), 4096).is_ok());
    }

    #[test]
    fn rejects_corrupt_and_truncated_archives() {
        let temp = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..50_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let bytes = zip_bytes(&[("data.bin", &data)]);

        let truncated = temp.path().join("truncated.zip");
        fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
        assert!(files::read(&truncated.join("data.bin")).is_err());

        // Damage the compressed data but keep the directory intact.
        let mut damaged = bytes.clone();
        for byte in &mut damaged[100..200] {
            *byte ^= 0x5A;
        }
        let corrupt = temp.path().join("corrupt.zip");
        fs::write(&corrupt, &damaged).unwrap();
        assert!(files::list(&corrupt).is_ok());
        assert!(files::open_binary(&corrupt.join("data.bin")).is_err());
    }

    #[test]
    fn files_with_an_archive_name_but_other_contents_are_plain() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("broken.zip");
        fs::write(&archive, b"not a zip").unwrap();
        assert!(files::list(&archive).is_err());
        assert!(files::read(&archive.join("x")).is_err());
        assert_eq!(files::read(&archive).unwrap(), b"not a zip");
    }
}
