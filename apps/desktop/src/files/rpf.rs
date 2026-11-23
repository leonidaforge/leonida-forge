//! RPF9 archives, browsed through the entries recovered from their data.
//!
//! Listing needs an index, which takes a scan of the whole archive. Until
//! [`build_index`] has run, listings fail with an error that
//! [`index_required`] recognises, so the explorer can show progress and offer
//! cancellation instead of blocking.
//!
//! The archive's own names and folders are unknown. Inside an archive,
//! `Recovered Entries` holds one virtual folder per kind of entry, and
//! `Unrecovered Regions` holds byte ranges that could not be decoded. Files are
//! named after their archive offset, which stays the same across scans.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::SystemTime;

use lforge_binary::Source;
use lforge_rpf::{Index, Kind, Progress, Region, Status};

use super::archive::{MAX_READ, check_size};
use super::{Entry, EntryKind, format_bytes_exact, format_size};

pub const RECOVERED: &str = "Recovered Entries";
pub const UNRECOVERED: &str = "Unrecovered Regions";
/// Indexes kept in memory; older ones are reloaded from the cache file.
const MAX_IN_MEMORY: usize = 8;

const SOURCE_NOTE: &str = "Recovered from a zlib stream in the archive data. The name is the \
     archive offset; the original name and folder are unknown.";

/// The archive has to be indexed before its contents can be listed.
#[derive(Debug)]
struct IndexRequired {
    archive: PathBuf,
}

impl fmt::Display for IndexRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} has not been indexed yet", self.archive.display())
    }
}

impl std::error::Error for IndexRequired {}

/// The archive that has to be indexed before the listing that failed with
/// `err` can succeed.
pub fn index_required(err: &io::Error) -> Option<&Path> {
    let inner = err.get_ref()?.downcast_ref::<IndexRequired>()?;
    Some(&inner.archive)
}

type Stamp = (u64, Option<SystemTime>);

struct Cached {
    stamp: Stamp,
    index: Arc<Index>,
    last_used: u64,
}

#[derive(Default)]
struct Indexes {
    clock: u64,
    by_archive: HashMap<PathBuf, Cached>,
}

static INDEXES: LazyLock<Mutex<Indexes>> = LazyLock::new(Default::default);

fn indexes() -> std::sync::MutexGuard<'static, Indexes> {
    INDEXES.lock().unwrap_or_else(|err| err.into_inner())
}

fn stamp(archive: &Path) -> io::Result<Stamp> {
    let metadata = fs::metadata(archive)?;
    Ok((metadata.len(), metadata.modified().ok()))
}

fn cache_dir() -> Option<PathBuf> {
    // Tests must not write to the user profile.
    if cfg!(test) {
        return None;
    }
    lforge_core::data_dir().map(|dir| dir.join("cache").join("rpf"))
}

fn remember(archive: &Path, stamp: Stamp, index: Index) -> Arc<Index> {
    let index = Arc::new(index);
    let mut indexes = indexes();
    indexes.clock += 1;
    let last_used = indexes.clock;
    indexes.by_archive.insert(
        archive.to_path_buf(),
        Cached {
            stamp,
            index: index.clone(),
            last_used,
        },
    );
    if indexes.by_archive.len() > MAX_IN_MEMORY
        && let Some(oldest) = indexes
            .by_archive
            .iter()
            .min_by_key(|(_, cached)| cached.last_used)
            .map(|(path, _)| path.clone())
    {
        indexes.by_archive.remove(&oldest);
    }
    index
}

/// The index of `archive` from memory or the cache file, if it still matches
/// the archive. Never scans.
fn index(archive: &Path) -> io::Result<Arc<Index>> {
    let stamp = stamp(archive)?;
    {
        let mut indexes = indexes();
        indexes.clock += 1;
        let now = indexes.clock;
        if let Some(cached) = indexes.by_archive.get_mut(archive)
            && cached.stamp == stamp
        {
            cached.last_used = now;
            return Ok(cached.index.clone());
        }
    }
    if let Some(dir) = cache_dir()
        && let Some(index) = lforge_rpf::load_cached(&dir, archive)
    {
        return Ok(remember(archive, stamp, index));
    }
    Err(io::Error::other(IndexRequired {
        archive: archive.to_path_buf(),
    }))
}

/// Scans `archive`, or loads its cache file, and keeps the index in memory.
pub fn build_index(archive: &Path, progress: &Progress, cancel: &AtomicBool) -> io::Result<()> {
    let stamp = stamp(archive)?;
    let (index, _) = lforge_rpf::open(archive, cache_dir().as_deref(), progress, cancel)?;
    remember(archive, stamp, index);
    Ok(())
}

fn folder_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Xml => "XML",
        Kind::Pso => "PSO",
        Kind::Rbf => "RBF",
        Kind::Png => "PNG",
        Kind::Dds => "DDS",
        Kind::Resource => "Resources",
        Kind::Text => "Text",
        Kind::Binary => "Unidentified",
    }
}

fn type_name(kind: Kind, status: Status) -> String {
    let name = match kind {
        Kind::Xml => "XML document",
        Kind::Pso => "PSO data",
        Kind::Rbf => "RBF data",
        Kind::Png => "PNG image",
        Kind::Dds => "DDS texture",
        Kind::Resource => "Resource system data",
        Kind::Text => "Text",
        Kind::Binary => "Binary data",
    };
    match (kind, status) {
        (Kind::Resource, _) | (_, Status::Complete) => name.to_string(),
        (_, Status::Partial) => format!("{name} (partial)"),
        (_, Status::Unverified) => format!("{name} (unverified)"),
    }
}

fn status_text(kind: Kind, status: Status) -> &'static str {
    match (kind, status) {
        (_, Status::Complete) => {
            "Complete: starts with a file signature and ends with a short chunk"
        }
        (Kind::Resource, _) => {
            "Partial: system data only; the other pages of the resource are not reconstructed"
        }
        (_, Status::Partial) => {
            "Partial: starts with a file signature, but the end could not be verified"
        }
        (_, Status::Unverified) => {
            "Unverified: no known file signature; this may be a whole file or a part of one"
        }
    }
}

/// `0x000000B000.xml`: the offset, padded so names sort by offset.
fn file_name(offset: u64, extension: &str) -> String {
    format!("0x{offset:010X}.{extension}")
}

/// The offset of a name made by [`file_name`]. Other spellings are rejected,
/// so each entry has exactly one path.
fn parse_file_name(name: &str, extension: &str) -> Option<u64> {
    let hex = name
        .strip_prefix("0x")?
        .strip_suffix(extension)?
        .strip_suffix('.')?;
    let offset = u64::from_str_radix(hex, 16).ok()?;
    (file_name(offset, extension) == name).then_some(offset)
}

enum Node<'a> {
    Root,
    Recovered,
    Kind(Kind),
    Regions,
    Entry(&'a lforge_rpf::Entry),
    Region(&'a Region),
}

fn resolve<'a>(index: &'a Index, inner: &Path) -> Option<Node<'a>> {
    let parts = inner
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<&str>>>()?;
    let kind_of = |folder: &str| {
        Kind::ALL
            .into_iter()
            .find(|kind| folder_name(*kind) == folder)
    };
    match parts.as_slice() {
        [] => Some(Node::Root),
        [RECOVERED] => Some(Node::Recovered),
        [UNRECOVERED] => Some(Node::Regions),
        [RECOVERED, folder] => kind_of(folder).map(Node::Kind),
        [RECOVERED, folder, name] => {
            let kind = kind_of(folder)?;
            let entry = index.entry_at(parse_file_name(name, kind.extension())?)?;
            (entry.kind == kind).then_some(Node::Entry(entry))
        }
        [UNRECOVERED, name] => index
            .region_at(parse_file_name(name, "bin")?)
            .map(Node::Region),
        _ => None,
    }
}

fn not_found() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "the path does not exist in the archive",
    )
}

fn folder(dir: &Path, name: &str, contents: String) -> Entry {
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

fn count(n: usize, one: &str, many: &str) -> String {
    match n {
        1 => format!("1 {one}"),
        _ => format!("{n} {many}"),
    }
}

fn compressed(len: u64) -> String {
    format!("{} ({} bytes)", format_size(len), format_bytes_exact(len))
}

fn entry_file(dir: &Path, entry: &lforge_rpf::Entry) -> Entry {
    let name = file_name(entry.offset, entry.kind.extension());
    let mut file = Entry::new(
        name.clone(),
        dir.join(&name),
        EntryKind::File,
        Some(entry.len),
        None,
    );
    file.type_name = type_name(entry.kind, entry.status);
    file.order = Some(entry.offset);
    file.details = vec![
        ("Status", status_text(entry.kind, entry.status).to_string()),
        ("Offset", format!("{:#x}", entry.offset)),
        ("Compressed", compressed(entry.stored_len)),
        ("Streams", entry.stream_count().to_string()),
        ("Source", SOURCE_NOTE.to_string()),
    ];
    file
}

fn region_file(dir: &Path, region: &Region) -> Entry {
    let name = file_name(region.offset, "bin");
    let mut file = Entry::new(
        name.clone(),
        dir.join(&name),
        EntryKind::File,
        Some(region.len),
        None,
    );
    file.type_name = "Unrecovered region".to_string();
    file.order = Some(region.offset);
    file.details = vec![
        (
            "Status",
            "Not decoded: these bytes are not zlib streams. They are shown as stored.".to_string(),
        ),
        ("Offset", format!("{:#x}", region.offset)),
    ];
    file
}

pub fn list(archive: &Path, inner: &Path) -> io::Result<Vec<Entry>> {
    let index = index(archive)?;
    let dir = archive.join(inner);
    let entries = match resolve(&index, inner).ok_or_else(not_found)? {
        Node::Root => {
            let mut folders = Vec::new();
            if !index.entries.is_empty() {
                let contents = count(index.entries.len(), "recovered entry", "recovered entries");
                folders.push(folder(&dir, RECOVERED, contents));
            }
            if !index.regions.is_empty() {
                let contents = count(index.regions.len(), "region", "regions");
                folders.push(folder(&dir, UNRECOVERED, contents));
            }
            folders
        }
        Node::Recovered => Kind::ALL
            .into_iter()
            .filter_map(|kind| {
                let n = index.entries.iter().filter(|e| e.kind == kind).count();
                (n > 0).then(|| folder(&dir, folder_name(kind), count(n, "entry", "entries")))
            })
            .collect(),
        Node::Kind(kind) => index
            .entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .map(|entry| entry_file(&dir, entry))
            .collect(),
        Node::Regions => index
            .regions
            .iter()
            .map(|region| region_file(&dir, region))
            .collect(),
        Node::Entry(_) | Node::Region(_) => {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "not a folder"));
        }
    };
    Ok(entries)
}

/// Writes one recovered entry or region to `out`, within [`MAX_READ`].
fn copy(archive: &Path, inner: &Path, out: &mut dyn Write) -> io::Result<()> {
    let index = index(archive)?;
    let source = Source::open(archive)?;
    match resolve(&index, inner).ok_or_else(not_found)? {
        Node::Entry(entry) => {
            check_size(entry.len, MAX_READ)?;
            lforge_rpf::read_entry(source, &index, entry, MAX_READ, out)?;
        }
        Node::Region(region) => {
            check_size(region.len, MAX_READ)?;
            lforge_rpf::read_region(source, region, MAX_READ, out)?;
        }
        _ => return Err(io::Error::other("not a file")),
    }
    Ok(())
}

pub fn read(archive: &Path, inner: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    copy(archive, inner, &mut bytes)?;
    Ok(bytes)
}

pub fn extract(archive: &Path, inner: &Path) -> io::Result<File> {
    let mut out = BufWriter::new(tempfile::tempfile()?);
    copy(archive, inner, &mut out)?;
    out.into_inner().map_err(|err| err.into_error())
}

/// Explains where the contents of an archive folder come from. Returns
/// `None` until the archive is indexed.
pub fn describe(archive: &Path, inner: &Path) -> Option<String> {
    let index = index(archive).ok()?;
    let percent = |part: u64| match index.data_len() {
        0 => 0.0,
        total => part as f64 * 100.0 / total as f64,
    };
    let note = match resolve(&index, inner)? {
        Node::Root if index.entries.is_empty() => {
            "No entries could be recovered: the table of contents is encrypted, and no zlib \
             streams were found in the archive data. The archive is not necessarily empty."
                .to_string()
        }
        Node::Root | Node::Recovered | Node::Kind(_) => format!(
            "The table of contents is encrypted and is not read. {} were recovered from zlib \
             streams covering {:.1}% of the archive data. Folders and names are not original: \
             entries are grouped by kind and named after their archive offset.",
            count(index.entries.len(), "entry", "entries"),
            percent(index.recovered_len()),
        ),
        Node::Regions => format!(
            "Bytes outside the recovered streams that are not zero padding ({:.1}% of the archive \
             data). They are not zlib streams and are shown as stored, without decoding.",
            percent(index.unrecovered_len()),
        ),
        Node::Entry(_) | Node::Region(_) => return None,
    };
    Some(note)
}

#[cfg(test)]
mod tests {
    use super::*;

    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use crate::files;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// A header, a table of contents of 0x60 bytes, then `parts` at aligned
    /// offsets starting at 0x100.
    fn write_rpf(path: &Path, parts: &[Vec<u8>]) -> Vec<u64> {
        let mut bytes = vec![0u8; 0x40];
        bytes[..4].copy_from_slice(b"9FPR");
        bytes[4..8].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes.resize(0xA0, 0x5A);
        bytes.resize(0x100, 0);
        let mut offsets = Vec::new();
        for part in parts {
            offsets.push(bytes.len() as u64);
            bytes.extend_from_slice(part);
            bytes.resize(bytes.len().next_multiple_of(16), 0);
        }
        fs::write(path, bytes).unwrap();
        offsets
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn build(path: &Path) {
        build_index(path, &Progress::default(), &AtomicBool::new(false)).unwrap();
    }

    #[test]
    fn lists_recovered_entries_by_kind_after_indexing() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("data.rpf");
        let xml = b"<?xml version=\"1.0\"?><root/>".to_vec();
        let offsets = write_rpf(
            &archive,
            &[zlib(&xml), vec![0x77; 40], zlib(&[1, 2, 3, 0, 9])],
        );

        let err = files::list(&archive).unwrap_err();
        assert_eq!(index_required(&err), Some(archive.as_path()));
        assert!(files::describe(&archive).is_none());
        build(&archive);

        let root = files::list(&archive).unwrap();
        assert_eq!(names(&root), [RECOVERED, UNRECOVERED]);
        assert!(root.iter().all(Entry::is_dir));
        assert!(files::describe(&archive).unwrap().contains("encrypted"));

        let kinds = files::list(&archive.join(RECOVERED)).unwrap();
        assert_eq!(names(&kinds), ["XML", "Unidentified"]);

        let xml_dir = archive.join(RECOVERED).join("XML");
        let files_in_dir = files::list(&xml_dir).unwrap();
        let name = format!("0x{:010X}.xml", offsets[0]);
        assert_eq!(names(&files_in_dir), [name.as_str()]);
        let file = &files_in_dir[0];
        assert_eq!(file.kind, EntryKind::File);
        assert_eq!(file.size, Some(xml.len() as u64));
        assert_eq!(file.modified, None);
        assert_eq!(file.type_name, "XML document");
        assert!(file.details.iter().any(|(label, _)| *label == "Compressed"));
        assert_eq!(files::read(&file.path).unwrap(), xml);

        let mut inspected = files::open_binary(&file.path).unwrap();
        assert_eq!(
            lforge_binary::read_at(&mut inspected.source, 0, 1024).unwrap(),
            xml
        );

        let regions = files::list(&archive.join(UNRECOVERED)).unwrap();
        assert_eq!(regions.len(), 1);
        // Regions cover whole 16-byte blocks.
        let mut raw = vec![0x77; 40];
        raw.resize(48, 0);
        assert_eq!(files::read(&regions[0].path).unwrap(), raw);
        assert_eq!(regions[0].type_name, "Unrecovered region");
    }

    #[test]
    fn the_archive_itself_opens_as_raw_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("raw.rpf");
        write_rpf(&archive, &[zlib(b"abc")]);
        let expected = fs::read(&archive).unwrap();
        assert_eq!(files::read(&archive).unwrap(), expected);
        let mut raw = files::open_binary(&archive).unwrap();
        assert_eq!(raw.source.len(), expected.len() as u64);
        assert_eq!(
            lforge_binary::read_at(&mut raw.source, 0, 4).unwrap(),
            b"9FPR"
        );
    }

    #[test]
    fn recognises_archives_by_signature() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real.RPF");
        write_rpf(&real, &[]);
        fs::write(temp.path().join("fake.rpf"), b"RPF7....").unwrap();
        fs::write(temp.path().join("short.rpf"), b"9F").unwrap();
        let mut entries = files::list(temp.path()).unwrap();
        files::sort_entries(&mut entries, files::Sort::default());
        let kinds: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(
            kinds,
            [
                ("fake.rpf", EntryKind::File),
                ("real.RPF", EntryKind::Archive),
                ("short.rpf", EntryKind::File),
            ]
        );
    }

    #[test]
    fn an_archive_without_streams_is_not_shown_as_empty() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("opaque.rpf");
        write_rpf(&archive, &[vec![0xC3; 500]]);
        build(&archive);
        assert_eq!(names(&files::list(&archive).unwrap()), [UNRECOVERED]);
        let note = files::describe(&archive).unwrap();
        assert!(note.contains("No entries could be recovered"));
        assert!(note.contains("not necessarily empty"));
    }

    #[test]
    fn each_entry_has_exactly_one_path() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("ids.rpf");
        let offsets = write_rpf(&archive, &[zlib(b"<?xml version=\"1.0\"?><a/>")]);
        build(&archive);
        let xml = archive.join(RECOVERED).join("XML");
        assert!(files::read(&xml.join(format!("0x{:010X}.xml", offsets[0]))).is_ok());
        for alias in [
            format!("0x{:X}.xml", offsets[0]),
            format!("0x{:010x}.xml", offsets[0] + 0xA),
            format!("0x{:010X}.bin", offsets[0]),
            format!("0x{:010X}.xml", offsets[0] + 16),
            "..".to_string(),
        ] {
            assert!(files::read(&xml.join(&alias)).is_err(), "{alias}");
        }
        assert!(
            files::read(
                &archive
                    .join(RECOVERED)
                    .join("Text")
                    .join(format!("0x{:010X}.xml", offsets[0]))
            )
            .is_err()
        );
        assert!(files::list(&archive.join("Missing")).is_err());
        assert!(files::list(&xml.join(format!("0x{:010X}.xml", offsets[0]))).is_err());
        assert_eq!(parse_file_name("0x0000000100.xml", "xml"), Some(0x100));
        assert_eq!(parse_file_name("0x0000000100xml", "xml"), None);
    }

    #[test]
    fn a_changed_archive_needs_a_new_index() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("changing.rpf");
        write_rpf(&archive, &[zlib(b"first")]);
        build(&archive);
        assert!(files::list(&archive).is_ok());
        write_rpf(&archive, &[zlib(b"first"), zlib(b"second, longer")]);
        let err = files::list(&archive).unwrap_err();
        assert_eq!(index_required(&err), Some(archive.as_path()));
    }

    #[test]
    fn cancelled_indexing_leaves_the_archive_unindexed() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("cancel.rpf");
        let noise: Vec<u8> = (0..3_000_000u64).map(|i| (i * 7919 % 251) as u8).collect();
        let parts: Vec<Vec<u8>> = noise.chunks(0x10000).map(zlib).collect();
        write_rpf(&archive, &parts);
        let err = build_index(&archive, &Progress::default(), &AtomicBool::new(true)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(index_required(&files::list(&archive).unwrap_err()).is_some());
    }
}
