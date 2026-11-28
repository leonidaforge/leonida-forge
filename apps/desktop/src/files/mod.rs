//! Read-only access to directories and archives.
//!
//! A path may continue inside an archive file, and inside archives stored in
//! it, e.g. `mods\pack.zip\cars\data.rpf\Recovered Entries`. [`list`] and
//! [`read`] resolve such paths, so callers treat archives like folders.

pub mod archive;
#[cfg(test)]
mod eviction;
pub mod executable;
pub mod images;
pub mod model;
pub mod rpf;
pub mod shell;
mod toc;
mod zip;

use std::cmp::Ordering;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

use archive::{Identified, Location};
pub use executable::{Access, Executable};
use lforge_binary::Source;
use lforge_core::resource::ResourcePath;
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
    /// The native RPF row type, when the entry comes from a native archive.
    pub resource_type: Option<u8>,
    /// The canonical resource path, when the entry comes from an archive.
    /// The path is display data; `resource_row` and the path's identity are
    /// the technical record.
    pub resource: Option<ResourcePath>,
    /// The native RPF row index or ZIP central-directory index. Diagnostic
    /// metadata, never a resource identifier.
    pub resource_row: Option<u32>,
    /// Format-specific properties for the preview pane. Entries that have
    /// them also bring their own type name.
    pub details: Vec<(&'static str, String)>,
    /// Sorted by this instead of the name, for names that encode a number
    /// natural order cannot see, such as hexadecimal offsets.
    pub order: Option<u64>,
    /// Sorted after every other entry of its folder, whatever the sort.
    pub last: bool,
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
            resource_type: None,
            resource: None,
            resource_row: None,
            details: Vec::new(),
            order: None,
            last: false,
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

/// A folder an archive does not store, made from what its entries describe.
pub(crate) fn folder(dir: &Path, name: &str, contents: String) -> Entry {
    let mut entry = Entry::new(
        name.to_string(),
        dir.join(name),
        EntryKind::Directory,
        None,
        None,
    );
    entry.type_name = "Virtual folder".to_string();
    entry.details = vec![("Contents", contents)];
    entry
}

pub(crate) fn count(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        _ => format!("{n} {many}"),
    }
}

pub fn is_supported_image(path: &Path) -> bool {
    extension(path).is_some_and(|ext| matches!(ext.as_str(), "png" | "jpg" | "jpeg"))
}

/// Lists the direct children of a directory, or of a folder inside an archive,
/// without an executable. Type names come from Windows where it knows the file
/// type.
#[cfg(test)]
pub fn list(path: &Path) -> io::Result<Vec<Entry>> {
    list_with(path, &Access::none())
}

/// [`list`] with the executable that may authenticate a stored table of
/// contents. Archives whose metadata needs it and have none fail with an
/// error that [`archive::executable_required`] or
/// [`archive::authentication_failure`] recognises.
pub fn list_with(path: &Path, access: &Access) -> io::Result<Vec<Entry>> {
    let mut entries = match archive::locate_with(path, access)? {
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
#[cfg(test)]
pub fn describe(path: &Path) -> Option<String> {
    describe_with(path, &Access::none())
}

pub fn describe_with(path: &Path, access: &Access) -> Option<String> {
    match archive::locate_with(path, access).ok()? {
        Location::Archive(archive) => archive::describe(&archive, Path::new("")),
        Location::Inside(archive, inner) => archive::describe(&archive, &inner),
        Location::Plain => None,
    }
}

/// Identifies a file by its contents, wherever it is stored. Files inside
/// archives are identified from their first bytes, so archives among them
/// are only fully checked when they are opened.
#[cfg(test)]
pub fn identify(path: &Path) -> io::Result<Identified> {
    identify_with(path, &Access::none())
}

pub fn identify_with(path: &Path, access: &Access) -> io::Result<Identified> {
    match archive::locate_prepared_with(path, access)? {
        Location::Archive(archive) => Ok(Identified::Archive(archive.format)),
        Location::Inside(archive, inner) if archive::is_file(&archive, &inner)? => {
            archive::sniff(&archive, &inner)
        }
        Location::Plain if path.is_file() => archive::identify_file(path),
        Location::Inside(..) | Location::Plain => Ok(Identified::Unknown),
    }
}

/// Classifies a file wherever it is stored, from a bounded head of its bytes.
/// `entry_type` is the native row type when the entry has one. Returns nothing
/// when the bytes cannot be read, so a caller keeps its own fallback.
pub fn classify_with(
    path: &Path,
    access: &Access,
    entry_type: Option<u8>,
) -> Option<lforge_core::classify::Classification> {
    match archive::locate_prepared_with(path, access).ok()? {
        Location::Archive(..) => None,
        Location::Inside(archive, inner) if archive::is_file(&archive, &inner).ok()? => {
            archive::classify(&archive, &inner, entry_type).ok()
        }
        Location::Plain if path.is_file() => {
            let mut head = [0u8; lforge_core::classify::HEAD_LEN];
            let read = std::fs::File::open(path)
                .and_then(|mut file| io::Read::read(&mut file, &mut head))
                .ok()?;
            Some(archive::classify_head(
                &head[..read],
                entry_type,
                path.extension(),
            ))
        }
        Location::Inside(..) | Location::Plain => None,
    }
}

/// The file on disk that `path` is stored in, and the path inside it, for
/// paths inside archives. Does not read any file.
pub fn split_location(path: &Path) -> Option<(&Path, &Path)> {
    let file = path.ancestors().find(|ancestor| ancestor.is_file())?;
    let inner = path.strip_prefix(file).ok()?;
    (!inner.as_os_str().is_empty()).then_some((file, inner))
}

/// Reads a whole file, which may be inside an archive, without an executable.
#[cfg(test)]
pub fn read(path: &Path) -> io::Result<Vec<u8>> {
    read_with(path, &Access::none())
}

pub fn read_with(path: &Path, access: &Access) -> io::Result<Vec<u8>> {
    match archive::locate_prepared_with(path, access)? {
        Location::Plain => {
            archive::check_size(fs::metadata(path)?.len(), archive::MAX_MATERIALIZE)?;
            fs::read(path)
        }
        Location::Archive(archive) => archive::read_all(&archive),
        Location::Inside(archive, inner) => {
            let mut bytes = Vec::new();
            archive::copy(&archive, &inner, &mut bytes, archive::MAX_MATERIALIZE)?;
            Ok(bytes)
        }
    }
}

/// The system/graphics split of a decoded native RAGE resource.
pub use lforge_rage9::rpf::resource::PageSplit;

/// Finds the page split of the decoded native resource at `path`. `source` is
/// the decoded payload returned by [`open_binary_with`]. `None` when the entry
/// is not a chunked native RAGE resource.
pub fn resource_split_with(
    path: &Path,
    access: &Access,
    source: &Source,
) -> io::Result<Option<PageSplit>> {
    let Location::Inside(container, inner) = archive::locate_prepared_with(path, access)? else {
        return Ok(None);
    };
    if container.format != archive::Format::Rpf9 {
        return Ok(None);
    }
    let Some(chunks) = rpf::chunks(&container, &inner)? else {
        return Ok(None);
    };
    let mut source = source.clone();
    let len = source.len();
    lforge_rage9::rpf::resource::page_split(
        &mut source,
        len,
        &chunks,
        lforge_rage9::rpf::RESOURCE_SYSTEM_LIMIT,
    )
    .map(Some)
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

/// A file opened for random access, possibly extracted from an archive.
pub struct BinaryFile {
    pub source: Source,
    pub modified: Option<SystemTime>,
}

/// Opens a file for random access, without an executable. Files inside
/// archives are extracted to a temporary file first, within the archive size
/// limit. Windows deletes the temporary file when its last handle closes, also
/// when the process exits abnormally.
#[cfg(test)]
pub fn open_binary(path: &Path) -> io::Result<BinaryFile> {
    open_binary_with(path, &Access::none())
}

pub fn open_binary_with(path: &Path, access: &Access) -> io::Result<BinaryFile> {
    let location = archive::locate_prepared_with(path, access)?;
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

/// Streams the decoded contents of the file at `source` into a temporary file
/// in `dest`'s directory, then moves it onto `dest` once the whole payload has
/// been written. Returns the number of bytes written.
///
/// A failed or cancelled export removes the temporary file and leaves `dest`
/// untouched, so no partial final file remains. An existing `dest` is replaced
/// only after a complete export; the caller is expected to have confirmed the
/// overwrite through the save dialog. Reuses the archive readers, so native,
/// scan-recovered and ZIP contents are decoded through their existing paths
/// (see [`archive::export_to`]).
/// [`export_with`] without an executable.
#[cfg(test)]
pub fn export(source: &Path, dest: &Path, cancel: &AtomicBool) -> io::Result<u64> {
    export_with(source, dest, &Access::none(), cancel)
}

/// [`export`] with the executable that may authenticate the stored table of
/// contents the entry is listed from.
pub fn export_with(
    source: &Path,
    dest: &Path,
    access: &Access,
    cancel: &AtomicBool,
) -> io::Result<u64> {
    let dir = match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut temp = tempfile::NamedTempFile::new_in(&dir)?;
    let written = {
        let mut out = io::BufWriter::new(temp.as_file_mut());
        let written = archive::export_to_with(source, access, &mut out, cancel)?;
        out.flush()?;
        written
    };
    temp.persist(dest).map_err(|err| err.error)?;
    Ok(written)
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

/// How the rows of an RPF9 archive are listed. The two modes never change a
/// row's identity: its path stays `<folder>/Row NNNNN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ListingLayout {
    /// Verified relative paths become virtual folders.
    #[default]
    Folders,
    /// Every row of the archive is listed in one list at its root.
    Flat,
}

impl ListingLayout {
    pub const ALL: [ListingLayout; 2] = [ListingLayout::Folders, ListingLayout::Flat];

    pub fn label(self) -> &'static str {
        match self {
            ListingLayout::Folders => "Folders",
            ListingLayout::Flat => "Flat list",
        }
    }
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
            .then_with(|| a.last.cmp(&b.last))
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
mod export_tests {
    use super::*;
    use crate::files::rpf::tests::{rpf_bytes, zlib};
    use crate::files::toc::tests::{
        Spec, companion_of, deflate, native_rpf, native_rpf_with, spec,
    };
    use crate::files::zip::tests::zip_bytes;
    use lforge_rage9::rpf::names::RPF_TYPE;

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    /// The offset-named path of the single recovered entry of an RPF9 archive
    /// written by `rpf_bytes` with one part, which lands at offset 0x100.
    fn recovered(archive: &Path, folder: &str, ext: &str) -> PathBuf {
        archive
            .join(rpf::RECOVERED)
            .join(folder)
            .join(format!("0x{:010X}.{ext}", 0x100))
    }

    /// Entries in `dir` that are neither the archive nor the destination: a
    /// temporary file left behind is one of these.
    fn stray_entries(dir: &Path, keep: &[&Path]) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| !keep.iter().any(|kept| *kept == entry.path()))
            .count()
    }

    #[test]
    fn exports_a_recovered_entry() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("data.rpf");
        let xml = b"<?xml version=\"1.0\"?><root/>";
        fs::write(&archive, rpf_bytes(&[zlib(xml)])).unwrap();
        let dest = temp.path().join("out.xml");
        let written = export(&recovered(&archive, "XML", "xml"), &dest, &no_cancel()).unwrap();
        assert_eq!(written, xml.len() as u64);
        assert_eq!(fs::read(&dest).unwrap(), xml);
    }

    #[test]
    fn exports_native_stored_and_nested_entries() {
        let temp = tempfile::tempdir().unwrap();
        // A native table-of-contents entry, stored.
        let native = temp.path().join("native.rpf");
        fs::write(&native, native_rpf(&[spec(b"stored payload", 0)])).unwrap();
        let dest = temp.path().join("row.bin");
        export(&native.join("Row 00000"), &dest, &no_cancel()).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"stored payload");

        // A recovered entry of an RPF9 archive stored inside a ZIP.
        let xml = b"<?xml version=\"1.0\"?><nested/>";
        let outer = temp.path().join("outer.zip");
        fs::write(
            &outer,
            zip_bytes(&[("inner.rpf", &rpf_bytes(&[zlib(xml)]))]),
        )
        .unwrap();
        let entry = recovered(&outer.join("inner.rpf"), "XML", "xml");
        let nested = temp.path().join("nested.xml");
        export(&entry, &nested, &no_cancel()).unwrap();
        assert_eq!(fs::read(&nested).unwrap(), xml);
    }

    #[test]
    fn a_failed_export_keeps_the_destination_and_leaves_no_temporary() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("unsupported.rpf");
        fs::write(
            &archive,
            native_rpf(&[Spec {
                mode: 2,
                ..spec(b"cannot decode this", RPF_TYPE)
            }]),
        )
        .unwrap();
        let dest = temp.path().join("out.bin");
        fs::write(&dest, b"existing").unwrap();
        let err = export(&archive.join("Row 00000"), &dest, &no_cancel()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(fs::read(&dest).unwrap(), b"existing");
        assert_eq!(stray_entries(temp.path(), &[&archive, &dest]), 0);
    }

    #[test]
    fn a_cancelled_export_writes_no_file() {
        let temp = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 256) as u8).collect();
        let archive = temp.path().join("deflate.rpf");
        fs::write(
            &archive,
            native_rpf(&[Spec {
                mode: 1,
                logical: Some(data.len() as u64),
                ..spec(&deflate(&data), 0)
            }]),
        )
        .unwrap();
        let dest = temp.path().join("out.bin");
        let err = export(&archive.join("Row 00000"), &dest, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(!dest.exists());
        assert_eq!(stray_entries(temp.path(), &[&archive]), 0);
    }

    #[test]
    fn export_replaces_an_existing_destination() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("native.rpf");
        fs::write(&archive, native_rpf(&[spec(b"fresh bytes", 0)])).unwrap();
        let dest = temp.path().join("out.bin");
        fs::write(&dest, b"old and longer content").unwrap();
        export(&archive.join("Row 00000"), &dest, &no_cancel()).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"fresh bytes");
    }

    #[test]
    fn a_missing_companion_refuses_export() {
        let temp = tempfile::tempdir().unwrap();
        let text = b"companion-sourced payload".to_vec();
        let full = native_rpf_with(
            &[Spec {
                source: Some(0),
                ..spec(&text, 0)
            }],
            &[(b"data.dat", 7)],
        );
        let archive = temp.path().join("main.rpf");
        fs::write(&archive, &full).unwrap();
        let companion = temp.path().join("data.dat");
        fs::write(&companion, companion_of(&full, 7)).unwrap();

        let dest = temp.path().join("out.bin");
        export(&archive.join("Row 00000"), &dest, &no_cancel()).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), text);

        // With the companion gone, the source can no longer be validated.
        fs::remove_file(&companion).unwrap();
        let stale = temp.path().join("stale.bin");
        let err = export(&archive.join("Row 00000"), &stale, &no_cancel()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(!stale.exists());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn read_refuses_a_file_above_the_materialization_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("large.bin");
        let file = fs::File::create(&path).unwrap();
        file.set_len(archive::MAX_MATERIALIZE + 1).unwrap();
        let err = read(&path).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

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
