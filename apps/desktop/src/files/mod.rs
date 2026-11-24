//! Read-only access to directories and archives.
//!
//! A path may continue inside an archive file, and inside archives stored in
//! it, e.g. `mods\pack.zip\cars\data.rpf\Recovered Entries`. [`list`] and
//! [`read`] resolve such paths, so callers treat archives like folders.

pub mod archive;
#[cfg(test)]
mod eviction;
pub mod images;
pub mod rpf;
pub mod shell;
mod toc;
mod zip;

use std::cmp::Ordering;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use archive::{Identified, Location};
use lforge_binary::Source;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    /// An archive file that can be browsed like a directory.
    Archive,
    File,
    /// The entry exists but its metadata cannot be read, e.g. a broken link.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub modified: Option<SystemTime>,
    pub type_name: String,
    /// Format-specific properties for the preview pane. Entries that have
    /// them also bring their own type name.
    pub details: Vec<(&'static str, String)>,
    /// Sorted by this instead of the name, for names that encode a number
    /// natural order cannot see, such as hexadecimal offsets.
    pub order: Option<u64>,
}

impl Entry {
    pub fn new(
        name: String,
        path: PathBuf,
        kind: EntryKind,
        size: Option<u64>,
        modified: Option<SystemTime>,
    ) -> Self {
        let type_name = fallback_type_name(kind, extension(&path).as_deref());
        Self {
            name,
            path,
            kind,
            size,
            modified,
            type_name,
            details: Vec::new(),
            order: None,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.kind == EntryKind::Directory
    }

    /// Directories and archives, which can be opened like folders.
    pub fn is_container(&self) -> bool {
        matches!(self.kind, EntryKind::Directory | EntryKind::Archive)
    }

    pub fn extension(&self) -> Option<String> {
        if self.is_dir() {
            return None;
        }
        extension(&self.path)
    }

    pub fn is_supported_image(&self) -> bool {
        self.kind == EntryKind::File && is_supported_image(&self.path)
    }

    /// Regular files, including archives, can be opened as raw bytes.
    pub fn is_inspectable(&self) -> bool {
        matches!(self.kind, EntryKind::File | EntryKind::Archive)
    }
}

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_lowercase())
}

/// The type name used when Windows does not know the file type.
fn fallback_type_name(kind: EntryKind, extension: Option<&str>) -> String {
    match kind {
        EntryKind::Directory => "File folder".to_string(),
        EntryKind::Unavailable => "Unavailable".to_string(),
        EntryKind::Archive | EntryKind::File => match extension {
            Some("png") => "PNG image".to_string(),
            Some("jpg" | "jpeg") => "JPEG image".to_string(),
            Some(ext) => format!("{} file", ext.to_uppercase()),
            None => "File".to_string(),
        },
    }
}

pub fn is_supported_image(path: &Path) -> bool {
    extension(path).is_some_and(|ext| matches!(ext.as_str(), "png" | "jpg" | "jpeg"))
}

/// Lists the direct children of a directory, or of a folder inside an archive.
/// Type names come from Windows where it knows the file type.
pub fn list(path: &Path) -> io::Result<Vec<Entry>> {
    let mut entries = match archive::locate(path)? {
        Location::Archive(archive) => archive::list(&archive, Path::new(""))?,
        Location::Inside(archive, inner) => {
            if archive::is_file(&archive, &inner)? {
                // Possibly an archive that has not been decompressed yet.
                return Err(archive::needs_prepare(path.to_path_buf()));
            }
            archive::list(&archive, &inner)?
        }
        Location::Plain if path.is_file() => {
            return Err(archive::not_an_archive(
                path,
                &archive::identify_file(path)?,
            ));
        }
        Location::Plain => list_directory(path)?,
    };
    for entry in entries.iter_mut().filter(|entry| entry.details.is_empty()) {
        if let Some(name) = shell::type_name(entry) {
            entry.type_name = name;
        }
    }
    Ok(entries)
}

/// Explains where the contents of a folder come from, when that is not
/// obvious, e.g. for entries recovered from an RPF archive.
pub fn describe(path: &Path) -> Option<String> {
    match archive::locate(path).ok()? {
        Location::Archive(archive) => archive::describe(&archive, Path::new("")),
        Location::Inside(archive, inner) => archive::describe(&archive, &inner),
        Location::Plain => None,
    }
}

/// Identifies a file by its contents, wherever it is stored. Files inside
/// archives are identified from their first bytes, so archives among them
/// are only fully checked when they are opened.
pub fn identify(path: &Path) -> io::Result<Identified> {
    match archive::locate_prepared(path)? {
        Location::Archive(archive) => Ok(Identified::Archive(archive.format)),
        Location::Inside(archive, inner) if archive::is_file(&archive, &inner)? => {
            archive::sniff(&archive, &inner)
        }
        Location::Plain if path.is_file() => archive::identify_file(path),
        Location::Inside(..) | Location::Plain => Ok(Identified::Unknown),
    }
}

/// The file on disk that `path` is stored in, and the path inside it, for
/// paths inside archives. Does not read any file.
pub fn split_location(path: &Path) -> Option<(&Path, &Path)> {
    let file = path.ancestors().find(|ancestor| ancestor.is_file())?;
    let inner = path.strip_prefix(file).ok()?;
    (!inner.as_os_str().is_empty()).then_some((file, inner))
}

/// Reads a whole file, which may be inside an archive.
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    match archive::locate_prepared(path)? {
        Location::Plain => fs::read(path),
        Location::Archive(archive) => archive::read_all(&archive),
        Location::Inside(archive, inner) => {
            let mut bytes = Vec::new();
            archive::copy(&archive, &inner, &mut bytes, archive::MAX_READ)?;
            Ok(bytes)
        }
    }
}

/// A file opened for random access, possibly extracted from an archive.
pub struct BinaryFile {
    pub source: Source,
    pub modified: Option<SystemTime>,
}

/// Opens a file for random access. Files inside archives are extracted to a
/// temporary file first, within the archive size limit. Windows deletes the
/// temporary file when its last handle closes, also when the process exits
/// abnormally.
pub fn open_binary(path: &Path) -> io::Result<BinaryFile> {
    let location = archive::locate_prepared(path)?;
    if let Location::Archive(archive) = &location
        && archive.depth > 1
    {
        return Ok(BinaryFile {
            source: archive.source.clone(),
            modified: None,
        });
    }
    let (file, modified) = match location {
        Location::Inside(archive, inner) => {
            let mut out = io::BufWriter::new(tempfile::tempfile()?);
            let modified = archive::copy(&archive, &inner, &mut out, archive::MAX_READ)?;
            (out.into_inner().map_err(|err| err.into_error())?, modified)
        }
        Location::Plain | Location::Archive(_) => {
            let file = fs::File::open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(io::Error::other("not a regular file"));
            }
            (file, metadata.modified().ok())
        }
    };
    Ok(BinaryFile {
        source: Source::from_file(file)?,
        modified,
    })
}

/// Lists the direct children of a directory on disk. Never recurses.
fn list_directory(dir: &Path) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let items: Vec<_> = fs::read_dir(dir)?.collect();
    let many = archive::too_many_to_identify(items.len());
    for item in items {
        let item = match item {
            Ok(item) => item,
            Err(err) => {
                log::warn!("skipping unreadable entry in {}: {err}", dir.display());
                continue;
            }
        };
        let path = item.path();
        let name = item.file_name().to_string_lossy().into_owned();
        // `DirEntry::metadata` is free on Windows but does not follow links.
        let metadata = match item.file_type() {
            Ok(file_type) if file_type.is_symlink() => fs::metadata(&path),
            _ => item.metadata(),
        };
        entries.push(entry_from_metadata(path, name, metadata, many));
    }
    Ok(entries)
}

fn entry_from_metadata(
    path: PathBuf,
    name: String,
    metadata: io::Result<fs::Metadata>,
    many: bool,
) -> Entry {
    let Ok(metadata) = metadata else {
        return Entry::new(name, path, EntryKind::Unavailable, None, None);
    };
    let kind = if metadata.is_dir() {
        EntryKind::Directory
    } else if metadata.is_file() && archive::is_archive_on_disk(&path, many) {
        EntryKind::Archive
    } else {
        EntryKind::File
    };
    let size = metadata.is_file().then_some(metadata.len());
    Entry::new(name, path, kind, size, metadata.modified().ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SortKey {
    #[default]
    Name,
    Type,
    Size,
    Modified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Sort {
    pub key: SortKey,
    pub descending: bool,
}

/// Sorts folders before files, then by `sort`. Ties are broken by name in
/// ascending order, whatever the sort direction.
pub fn sort_entries(entries: &mut [Entry], sort: Sort) {
    entries.sort_by(|a, b| {
        let ordering = match sort.key {
            SortKey::Name => match (a.order, b.order) {
                (Some(a), Some(b)) => a.cmp(&b),
                _ => natural_cmp(&a.name, &b.name),
            },
            SortKey::Type => a.type_name.cmp(&b.type_name),
            SortKey::Size => a.size.cmp(&b.size),
            SortKey::Modified => a.modified.cmp(&b.modified),
        };
        let ordering = if sort.descending {
            ordering.reverse()
        } else {
            ordering
        };
        b.is_dir()
            .cmp(&a.is_dir())
            .then(ordering)
            .then_with(|| natural_cmp(&a.name, &b.name))
    });
}

/// Case-insensitive comparison that orders digit runs by value ("2" < "10").
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut a_chars = a.chars().peekable();
    let mut b_chars = b.chars().peekable();
    loop {
        match (a_chars.peek().copied(), b_chars.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let a_digits = take_digits(&mut a_chars);
                let b_digits = take_digits(&mut b_chars);
                let a_value = a_digits.trim_start_matches('0');
                let b_value = b_digits.trim_start_matches('0');
                let ordering = a_value
                    .len()
                    .cmp(&b_value.len())
                    .then_with(|| a_value.cmp(b_value));
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(x), Some(y)) => {
                let ordering = x.to_lowercase().cmp(y.to_lowercase());
                if ordering != Ordering::Equal {
                    return ordering;
                }
                a_chars.next();
                b_chars.next();
            }
        }
    }
}

fn take_digits(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut digits = String::new();
    while let Some(c) = chars.next_if(char::is_ascii_digit) {
        digits.push(c);
    }
    digits
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Formats with thousands separators, e.g. `19,312,640`.
pub fn format_bytes_exact(bytes: u64) -> String {
    let digits = bytes.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn format_modified(time: SystemTime) -> String {
    let local: chrono::DateTime<chrono::Local> = time.into();
    local.format("%d.%m.%Y %H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn file(name: &str, size: u64) -> Entry {
        Entry::new(
            name.into(),
            PathBuf::from(name),
            EntryKind::File,
            Some(size),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(size)),
        )
    }

    fn dir(name: &str) -> Entry {
        Entry::new(
            name.into(),
            PathBuf::from(name),
            EntryKind::Directory,
            None,
            None,
        )
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn natural_order_ignores_case_and_compares_numbers_by_value() {
        let mut names = vec!["file10", "File2", "file1", "file02b", "alpha"];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(names, ["alpha", "file1", "File2", "file02b", "file10"]);
    }

    #[test]
    fn folders_come_first_in_every_sort() {
        let mut entries = vec![file("b.bin", 10), dir("z"), file("a.png", 30), dir("a")];
        for key in [
            SortKey::Name,
            SortKey::Type,
            SortKey::Size,
            SortKey::Modified,
        ] {
            for descending in [false, true] {
                sort_entries(&mut entries, Sort { key, descending });
                assert!(entries[0].is_dir() && entries[1].is_dir());
            }
        }
    }

    #[test]
    fn sorts_by_each_column() {
        let mut entries = vec![file("b.bin", 10), file("a.png", 30), file("c.dds", 20)];

        sort_entries(&mut entries, Sort::default());
        assert_eq!(names(&entries), ["a.png", "b.bin", "c.dds"]);

        let by_size = Sort {
            key: SortKey::Size,
            descending: true,
        };
        sort_entries(&mut entries, by_size);
        assert_eq!(names(&entries), ["a.png", "c.dds", "b.bin"]);

        let mut with_folders = vec![dir("b"), dir("a"), file("x", 1)];
        sort_entries(&mut with_folders, by_size);
        assert_eq!(names(&with_folders), ["a", "b", "x"]);

        let by_type = Sort {
            key: SortKey::Type,
            descending: false,
        };
        sort_entries(&mut entries, by_type);
        assert_eq!(names(&entries), ["b.bin", "c.dds", "a.png"]);

        let by_modified = Sort {
            key: SortKey::Modified,
            descending: false,
        };
        sort_entries(&mut entries, by_modified);
        assert_eq!(names(&entries), ["b.bin", "c.dds", "a.png"]);
    }

    #[test]
    fn names_with_an_order_sort_by_it() {
        let mut entries: Vec<Entry> = ["0x000A000000", "0x00000A0000", "0x00000B0000"]
            .into_iter()
            .map(|name| {
                let mut entry = file(name, 1);
                entry.order = u64::from_str_radix(&name[2..], 16).ok();
                entry
            })
            .collect();
        sort_entries(&mut entries, Sort::default());
        assert_eq!(
            names(&entries),
            ["0x00000A0000", "0x00000B0000", "0x000A000000"]
        );
    }

    #[test]
    fn lists_files_and_folders_with_unicode_names() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("Ordner ä")).unwrap();
        fs::write(temp.path().join("テクスチャ.png"), [0u8; 3]).unwrap();
        fs::write(temp.path().join("vehicles.rpf"), [0u8; 5]).unwrap();
        zip::tests::write_zip(&temp.path().join("Pack.ZIP"), &[("a.txt", b"a")]);
        // An archive extension alone does not make an archive.
        fs::write(temp.path().join("fake.zip"), [0u8; 1]).unwrap();

        // `list_directory` keeps the fallback type names; `list` adds Windows names.
        let mut entries = list_directory(temp.path()).unwrap();
        sort_entries(&mut entries, Sort::default());

        assert_eq!(
            names(&entries),
            [
                "Ordner ä",
                "fake.zip",
                "Pack.ZIP",
                "vehicles.rpf",
                "テクスチャ.png"
            ]
        );
        assert_eq!(entries[1].kind, EntryKind::File);
        entries.remove(1);
        assert_eq!(entries[0].kind, EntryKind::Directory);
        assert_eq!(entries[0].size, None);
        assert_eq!(entries[1].kind, EntryKind::Archive);
        assert!(entries[1].is_container());
        assert_eq!(entries[2].type_name, "RPF file");
        assert_eq!(entries[2].size, Some(5));
        assert!(entries[3].is_supported_image());
        assert!(entries[3].modified.is_some());
    }

    #[test]
    fn listing_a_missing_directory_fails() {
        let temp = tempfile::tempdir().unwrap();
        assert!(list_directory(&temp.path().join("missing")).is_err());
    }

    #[test]
    fn listing_does_not_recurse() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("a/b/c")).unwrap();
        let entries = list_directory(temp.path()).unwrap();
        assert_eq!(names(&entries), ["a"]);
    }

    #[cfg(windows)]
    #[test]
    fn broken_symlink_is_listed_as_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let link = temp.path().join("dangling");
        // Creating symlinks needs Developer Mode or elevation on Windows.
        if std::os::windows::fs::symlink_file(temp.path().join("missing"), &link).is_err() {
            return;
        }
        let entries = list_directory(temp.path()).unwrap();
        assert_eq!(entries[0].kind, EntryKind::Unavailable);
    }

    #[test]
    fn opens_plain_and_archived_files_for_inspection() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("plain.bin"), b"LFG\0").unwrap();
        let plain = open_binary(&temp.path().join("plain.bin")).unwrap();
        assert_eq!(plain.source.len(), 4);
        assert!(plain.modified.is_some());
        assert!(open_binary(temp.path()).is_err());
        assert!(open_binary(&temp.path().join("missing.bin")).is_err());

        let archive = temp.path().join("pack.zip");
        let mut zip = ::zip::ZipWriter::new(fs::File::create(&archive).unwrap());
        zip.start_file("dir/inner.bin", ::zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut zip, b"inside").unwrap();
        zip.finish().unwrap();

        let mut inner = open_binary(&archive.join("dir").join("inner.bin")).unwrap();
        assert_eq!(
            lforge_binary::read_at(&mut inner.source, 0, 64).unwrap(),
            b"inside"
        );
        assert!(open_binary(&archive.join("dir")).is_err());

        let raw = open_binary(&archive).unwrap();
        assert_eq!(raw.source.len(), fs::metadata(&archive).unwrap().len());
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(19_312_640), "18.4 MB");
        assert_eq!(format_bytes_exact(19_312_640), "19,312,640");
        assert_eq!(format_bytes_exact(999), "999");
        assert_eq!(format_bytes_exact(1000), "1,000");
    }
}
