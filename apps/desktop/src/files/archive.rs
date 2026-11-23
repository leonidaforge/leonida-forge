//! ZIP archives, browsed like folders.
//!
//! Each call reads the archive's table of contents again, so changes on disk
//! show up on the next listing.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Component, Path};
use std::time::SystemTime;

use chrono::{Local, NaiveDate, TimeZone};
use zip::ZipArchive;

use super::{Entry, EntryKind};

/// Files inside archives are read into memory, so cap what one read may allocate.
const MAX_READ: u64 = 512 * 1024 * 1024;

pub fn is_archive(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
}

/// Splits a path that continues inside an archive file into the archive and
/// the path within it. Returns `None` for plain filesystem paths.
pub fn locate(path: &Path) -> Option<(&Path, &Path)> {
    let archive = path
        .ancestors()
        .find(|ancestor| is_archive(ancestor) && ancestor.is_file())?;
    Some((archive, path.strip_prefix(archive).ok()?))
}

/// Lists the direct children of `inner`. Folders that the archive only
/// implies through the paths of their files are listed as well.
pub fn list(archive: &Path, inner: &Path) -> io::Result<Vec<Entry>> {
    let mut zip = open(archive)?;
    let dir = archive.join(inner);
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
            children.insert(
                child.clone(),
                Entry::new(child, path, EntryKind::File, Some(file.size()), modified),
            );
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

/// Reads one file from the archive into memory.
pub fn read(archive: &Path, inner: &Path) -> io::Result<Vec<u8>> {
    let mut zip = open(archive)?;
    let index = (0..zip.len())
        .find(|&index| {
            zip.by_index_raw(index)
                .ok()
                .and_then(|file| file.enclosed_name())
                .is_some_and(|name| name == inner)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the file does not exist in the archive",
            )
        })?;
    let file = zip.by_index(index).map_err(io::Error::other)?;
    if file.size() > MAX_READ {
        return Err(io::Error::other(
            "the file is too large to read from the archive",
        ));
    }
    let mut bytes = Vec::with_capacity(file.size() as usize);
    file.take(MAX_READ).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn open(archive: &Path) -> io::Result<ZipArchive<BufReader<File>>> {
    let file = File::open(archive)?;
    ZipArchive::new(BufReader::new(file)).map_err(io::Error::other)
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
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use zip::write::SimpleFileOptions;

    fn write_zip(path: &Path, files: &[(&str, &[u8])]) {
        let mut zip = zip::ZipWriter::new(File::create(path).unwrap());
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in files {
            if name.ends_with('/') {
                zip.add_directory(*name, options).unwrap();
            } else {
                zip.start_file(*name, options).unwrap();
                zip.write_all(data).unwrap();
            }
        }
        zip.finish().unwrap();
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
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

        let root = list(&archive, Path::new("")).unwrap();
        assert_eq!(names(&root), ["cars", "empty", "readme.txt"]);
        assert_eq!(root[0].kind, EntryKind::Directory);
        assert_eq!(root[0].path, archive.join("cars"));
        assert_eq!(root[2].size, Some(2));
        assert!(root[2].modified.is_some());

        let cars = list(&archive, Path::new("cars")).unwrap();
        assert_eq!(names(&cars), ["models", "テクスチャ.png"]);
        assert!(list(&archive, Path::new("empty")).unwrap().is_empty());
        assert!(list(&archive, Path::new("missing")).is_err());
    }

    #[test]
    fn reads_files_and_resolves_paths_inside_archives() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("Pack.Zip");
        write_zip(&archive, &[("cars/models/car.bin", b"12345")]);
        let inside = archive.join("cars").join("models");

        assert_eq!(
            locate(&inside),
            Some((archive.as_path(), Path::new(r"cars\models")))
        );
        assert_eq!(locate(temp.path()), None);
        assert_eq!(
            super::super::read(&inside.join("car.bin")).unwrap(),
            b"12345"
        );
        assert!(read(&archive, Path::new("cars/missing.bin")).is_err());

        let entries = super::super::list(&inside).unwrap();
        assert_eq!(names(&entries), ["car.bin"]);
    }

    #[test]
    fn skips_names_that_escape_the_archive() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("evil.zip");
        write_zip(&archive, &[("../outside.txt", b"x"), ("inside.txt", b"y")]);
        assert_eq!(
            names(&list(&archive, Path::new("")).unwrap()),
            ["inside.txt"]
        );
    }

    #[test]
    fn rejects_files_that_are_not_archives() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("broken.zip");
        std::fs::write(&archive, b"not a zip").unwrap();
        assert!(list(&archive, Path::new("")).is_err());
        assert_eq!(
            locate(&archive.join("x")).map(|(a, _)| a.to_path_buf()),
            Some(PathBuf::from(&archive))
        );
    }
}
