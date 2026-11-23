//! RPF9 archives, browsed through the entries recovered from their data.
//!
//! Listing needs an index, which takes a scan of the whole archive. Until
//! [`build_index`] has run, listings fail with an error that
//! [`super::archive::prepare_required`] recognises, so the explorer can show progress and offer
//! cancellation instead of blocking.
//!
//! The archive's own names and folders are unknown. Inside an archive,
//! `Recovered Entries` holds one virtual folder per kind of entry,
//! `Resource Pages` holds the page streams of reconstructed resources one by
//! one, and `Unrecovered Regions` holds byte ranges that could not be
//! decoded. Files are named after their archive offset, which stays the same
//! across scans.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock, Mutex};

use lforge_rage9::resource::{Page, Segment};
use lforge_rage9::rpf::{self, CacheKey, Index, Kind, Progress, Region, Resource, Status, Stream};

use super::archive::{Archive, Stamp, check_size, needs_prepare};
use super::{Entry, EntryKind, format_bytes_exact, format_size};

pub const RECOVERED: &str = "Recovered Entries";
pub const PAGES: &str = "Resource Pages";
pub const UNRECOVERED: &str = "Unrecovered Regions";
/// Indexes kept in memory; older ones are reloaded from the cache file.
const MAX_IN_MEMORY: usize = 8;

const SOURCE_NOTE: &str = "Recovered from a zlib stream in the archive data. The name is the \
     archive offset; the original name and folder are unknown.";

const RESOURCE_SOURCE_NOTE: &str = "Reconstructed from consecutive zlib streams in the archive \
     data: the system pages, then the graphics pages, as pointers in the resource address them. \
     The name is the archive offset; the original name and folder are unknown.";

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

fn cache_dir() -> Option<PathBuf> {
    // Tests must not write to the user profile.
    if cfg!(test) {
        return None;
    }
    lforge_core::data_dir().map(|dir| dir.join("cache").join("rpf"))
}

/// Identifies an archive by its full path through the archives it is
/// stored in, and versions it by the file on disk they all come from.
fn cache_key(archive: &Archive) -> io::Result<CacheKey> {
    let mut location = rpf::file_location(&archive.root);
    let nested = archive.nested_path();
    if !nested.as_os_str().is_empty() {
        // Names inside archives may differ only in case.
        location.push('|');
        location.push_str(&nested.to_string_lossy());
    }
    Ok(CacheKey {
        location,
        version: rpf::file_version(&fs::metadata(&archive.root)?)?,
    })
}

fn remember(archive: &Archive, index: Index) -> Arc<Index> {
    let index = Arc::new(index);
    let mut indexes = indexes();
    indexes.clock += 1;
    let last_used = indexes.clock;
    indexes.by_archive.insert(
        archive.path.clone(),
        Cached {
            stamp: archive.stamp,
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
fn index(archive: &Archive) -> io::Result<Arc<Index>> {
    let len = archive.source.len();
    {
        let mut indexes = indexes();
        indexes.clock += 1;
        let now = indexes.clock;
        if let Some(cached) = indexes.by_archive.get_mut(&archive.path)
            && cached.stamp == archive.stamp
            && cached.index.archive_len == len
        {
            cached.last_used = now;
            return Ok(cached.index.clone());
        }
    }
    if let Some(dir) = cache_dir()
        && let Some(index) = rpf::load(&dir, &cache_key(archive)?, len)
    {
        return Ok(remember(archive, index));
    }
    Err(needs_prepare(archive.path.clone()))
}

/// Scans `archive`, unless its index is in memory or in the cache, and keeps
/// the index in memory.
pub fn build_index(archive: &Archive, progress: &Progress, cancel: &AtomicBool) -> io::Result<()> {
    if index(archive).is_ok() {
        return Ok(());
    }
    let key = cache_key(archive)?;
    let index = rpf::scan(archive.source.clone(), progress, cancel)?;
    if let Some(dir) = cache_dir()
        && cache_key(archive).is_ok_and(|after| after == key)
    {
        let _ = rpf::store(&dir, &key, &index);
    }
    remember(archive, index);
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
        Kind::Resource => "RAGE resource",
        Kind::Text => "Text",
        Kind::Binary => "Binary data",
    };
    match status {
        Status::Complete => name.to_string(),
        Status::Partial => format!("{name} (partial)"),
        Status::Unverified => format!("{name} (unverified)"),
    }
}

fn status_text(kind: Kind, status: Status) -> &'static str {
    match (kind, status) {
        (Kind::Resource, Status::Complete) => {
            "Complete: the page map is valid, every declared page was found and the page sizes fit \
             the observed pattern"
        }
        (Kind::Resource, Status::Partial) => {
            "Partial: the page map declares pages that were not found next to the resource"
        }
        (Kind::Resource, Status::Unverified) => {
            "Unverified: the page map could not be validated, or the page sizes do not fit the \
             observed pattern"
        }
        (_, Status::Complete) => {
            "Complete: starts with a file signature and ends with a short chunk"
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
    Pages,
    Regions,
    Entry(&'a rpf::Entry),
    /// A resource and the position of the page among its pages.
    Page(&'a Resource, usize),
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
        [PAGES] => Some(Node::Pages),
        [UNRECOVERED] => Some(Node::Regions),
        [RECOVERED, folder] => kind_of(folder).map(Node::Kind),
        [RECOVERED, folder, name] => {
            let kind = kind_of(folder)?;
            let entry = index.entry_at(parse_file_name(name, kind.extension())?)?;
            (entry.kind == kind).then_some(Node::Entry(entry))
        }
        [PAGES, name] => index
            .page_at(parse_file_name(name, "bin")?)
            .map(|(resource, position, ..)| Node::Page(resource, position)),
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

fn segment_text(resource: &Resource, segment: Segment) -> String {
    let layout = &resource.layout;
    let len = layout.segment_len(segment);
    let pages = layout.segment_pages(segment).count();
    format!(
        "{} ({} bytes) in {}",
        format_size(len),
        format_bytes_exact(len),
        count(pages, "page", "pages")
    )
}

fn resource_details(index: &Index, resource: &Resource) -> Vec<(&'static str, String)> {
    let layout = &resource.layout;
    let mut details = vec![
        ("System data", segment_text(resource, Segment::System)),
        ("Graphics data", segment_text(resource, Segment::Graphics)),
        (
            "Page map",
            match layout.page_map {
                Ok(map) => format!(
                    "At {:#x} in the system data; declares {} and {}",
                    map.offset,
                    count(map.system_pages.into(), "system page", "system pages"),
                    count(map.graphics_pages.into(), "graphics page", "graphics pages"),
                ),
                Err(err) => format!("Not validated: {}", err.describe()),
            },
        ),
        (
            "Pages",
            index
                .resource_pages(resource)
                .map(|(page, streams)| {
                    format!("{:#x} ({})", streams[0].offset, page.segment.name())
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
    ];
    if let Some(tag) = layout.tag {
        details.push(("Marker", format!("0DRP {tag:#04x} (meaning unknown)")));
    }
    let pointers = layout.pointers;
    details.push((
        "Pointer-like values",
        format!(
            "{} system, {} graphics; {} and {} point outside{}",
            pointers.system,
            pointers.graphics,
            pointers.system_outside,
            pointers.graphics_outside,
            if pointers.checked {
                ""
            } else {
                " (not all checked)"
            }
        ),
    ));
    let issues: Vec<String> = layout
        .issues()
        .iter()
        .map(|issue| issue.describe())
        .collect();
    if !issues.is_empty() {
        details.push(("Warnings", issues.join("; ")));
    }
    details
}

fn entry_file(dir: &Path, index: &Index, entry: &rpf::Entry) -> Entry {
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
    ];
    let source = match index.resource_at(entry.offset) {
        Some(resource) => {
            file.details.extend(resource_details(index, resource));
            RESOURCE_SOURCE_NOTE
        }
        None => SOURCE_NOTE,
    };
    file.details.extend([
        ("Compressed", compressed(entry.stored_len)),
        ("Streams", entry.stream_count().to_string()),
        ("Source", source.to_string()),
    ]);
    file
}

fn page_file(
    dir: &Path,
    resource: &Resource,
    position: usize,
    page: &Page,
    streams: &[Stream],
) -> Entry {
    let offset = streams[0].offset;
    let name = file_name(offset, "bin");
    let mut file = Entry::new(
        name.clone(),
        dir.join(&name),
        EntryKind::File,
        Some(page.len),
        None,
    );
    let (segment, number) = rpf::page_label(&resource.layout, position);
    let of = resource.layout.segment_pages(segment).count();
    file.type_name = match segment {
        Segment::System => "Resource system page",
        Segment::Graphics => "Resource graphics page",
    }
    .to_string();
    file.order = Some(offset);
    let stored: u64 = streams.iter().map(|s| u64::from(s.stored_len)).sum();
    file.details = vec![
        (
            "Resource",
            format!(
                "{} ({})",
                file_name(resource.offset, Kind::Resource.extension()),
                resource.status().name()
            ),
        ),
        ("Page", format!("{} page {number} of {of}", segment.name())),
        ("Offset", format!("{offset:#x}")),
        ("Compressed", compressed(stored)),
        ("Streams", page.stream_count.to_string()),
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

pub fn list(archive: &Archive, inner: &Path) -> io::Result<Vec<Entry>> {
    let index = index(archive)?;
    let dir = archive.path.join(inner);
    let entries = match resolve(&index, inner).ok_or_else(not_found)? {
        Node::Root => {
            let mut folders = Vec::new();
            if !index.entries.is_empty() {
                let contents = count(index.entries.len(), "recovered entry", "recovered entries");
                folders.push(folder(&dir, RECOVERED, contents));
            }
            let pages: usize = index.resources.iter().map(|r| r.layout.pages.len()).sum();
            if pages > 0 {
                folders.push(folder(&dir, PAGES, count(pages, "page", "pages")));
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
            .map(|entry| entry_file(&dir, &index, entry))
            .collect(),
        Node::Pages => index
            .resources
            .iter()
            .flat_map(|resource| {
                index
                    .resource_pages(resource)
                    .enumerate()
                    .map(move |(position, (page, streams))| (resource, position, page, streams))
            })
            .map(|(resource, position, page, streams)| {
                page_file(&dir, resource, position, page, streams)
            })
            .collect(),
        Node::Regions => index
            .regions
            .iter()
            .map(|region| region_file(&dir, region))
            .collect(),
        Node::Entry(_) | Node::Page(..) | Node::Region(_) => {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "not a folder"));
        }
    };
    Ok(entries)
}

/// Writes one recovered entry, page or region to `out`, within `limit`.
pub fn copy(archive: &Archive, inner: &Path, out: &mut dyn Write, limit: u64) -> io::Result<()> {
    let index = index(archive)?;
    let source = archive.source.clone();
    match resolve(&index, inner).ok_or_else(not_found)? {
        Node::Entry(entry) => {
            check_size(entry.len, limit)?;
            rpf::read_entry(source, &index, entry, limit, out)?;
        }
        Node::Page(resource, position) => {
            let (page, streams) = index
                .resource_pages(resource)
                .nth(position)
                .ok_or_else(not_found)?;
            check_size(page.len, limit)?;
            rpf::read_streams(source, &index, streams, limit, out)?;
        }
        Node::Region(region) => {
            check_size(region.len, limit)?;
            rpf::read_region(source, region, limit, out)?;
        }
        _ => return Err(io::Error::other("not a file")),
    }
    Ok(())
}

fn file_node_len(node: &Node, index: &Index) -> Option<u64> {
    match node {
        Node::Entry(entry) => Some(entry.len),
        Node::Page(resource, position) => index
            .resource_pages(resource)
            .nth(*position)
            .map(|(page, _)| page.len),
        Node::Region(region) => Some(region.len),
        _ => None,
    }
}

/// The shortest leading part of `inner` that names a file in the archive.
pub fn file_prefix(archive: &Archive, inner: &Path) -> io::Result<Option<PathBuf>> {
    let index = index(archive)?;
    let mut prefix = PathBuf::new();
    for component in inner.components() {
        prefix.push(component);
        let Some(node) = resolve(&index, &prefix) else {
            return Ok(None);
        };
        if file_node_len(&node, &index).is_some() {
            return Ok(Some(prefix));
        }
    }
    Ok(None)
}

pub fn file_len(archive: &Archive, inner: &Path) -> io::Result<u64> {
    let index = index(archive)?;
    let node = resolve(&index, inner).ok_or_else(not_found)?;
    file_node_len(&node, &index).ok_or_else(|| io::Error::other("not a file"))
}

/// Why an archive recovered from the entry at `inner` may be incomplete.
pub fn caveat(archive: &Archive, inner: &Path) -> Option<String> {
    let index = index(archive).ok()?;
    let Node::Entry(entry) = resolve(&index, inner)? else {
        return None;
    };
    let why = match entry.status {
        Status::Complete => return None,
        Status::Partial => "its last chunk was not found",
        Status::Unverified => "its streams cannot be verified to form one whole file",
    };
    Some(format!(
        "This archive was recovered from an RPF9 entry that is {}: {why}. Parts of it may be \
         missing.",
        entry.status.name()
    ))
}

/// Explains where the contents of an archive folder come from. Returns
/// `None` until the archive is indexed.
pub fn describe(archive: &Archive, inner: &Path) -> Option<String> {
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
        Node::Pages => format!(
            "The page streams of {}, one file per page, in archive order. Each resource in \
             Recovered Entries holds its system pages followed by its graphics pages; here they \
             can be inspected separately.",
            count(
                index.resources.len(),
                "reconstructed resource",
                "reconstructed resources"
            ),
        ),
        Node::Regions => format!(
            "Bytes outside the recovered streams that are not zero padding ({:.1}% of the archive \
             data). They are not zlib streams and are shown as stored, without decoding.",
            percent(index.unrecovered_len()),
        ),
        Node::Entry(_) | Node::Page(..) | Node::Region(_) => return None,
    };
    Some(note)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use crate::files;
    use crate::files::archive::{self, prepare_required};

    pub(crate) fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// A header, a table of contents of 0x60 bytes, then `parts` at aligned
    /// offsets starting at 0x100.
    pub(crate) fn rpf_bytes(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x40];
        bytes[..4].copy_from_slice(b"9FPR");
        bytes[4..8].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes.resize(0xA0, 0x5A);
        bytes.resize(0x100, 0);
        for part in parts {
            bytes.extend_from_slice(part);
            bytes.resize(bytes.len().next_multiple_of(16), 0);
        }
        bytes
    }

    /// Writes [`rpf_bytes`] and returns the offset of each part.
    fn write_rpf(path: &Path, parts: &[Vec<u8>]) -> Vec<u64> {
        let mut offsets = Vec::new();
        let mut offset = 0x100u64;
        for part in parts {
            offsets.push(offset);
            offset = (offset + part.len() as u64).next_multiple_of(16);
        }
        fs::write(path, rpf_bytes(parts)).unwrap();
        offsets
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn build(path: &Path) {
        archive::prepare(path, &Progress::default(), &AtomicBool::new(false)).unwrap();
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
        assert_eq!(prepare_required(&err), Some(archive.as_path()));
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
        assert_eq!(prepare_required(&err), Some(archive.as_path()));
    }

    #[test]
    fn cancelled_indexing_leaves_the_archive_unindexed() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("cancel.rpf");
        let noise: Vec<u8> = (0..3_000_000u64).map(|i| (i * 7919 % 251) as u8).collect();
        let parts: Vec<Vec<u8>> = noise.chunks(0x10000).map(zlib).collect();
        write_rpf(&archive, &parts);
        let err =
            archive::prepare(&archive, &Progress::default(), &AtomicBool::new(true)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(prepare_required(&files::list(&archive).unwrap_err()).is_some());
    }

    #[test]
    fn resources_and_their_pages_can_be_browsed_and_read() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("textures.rpf");
        let mut system = vec![0u8; 0x100];
        system[8..16].copy_from_slice(&0x5000_00C0u64.to_le_bytes());
        system[0xC8] = 1;
        system[0xC9] = 1;
        let graphics: Vec<u8> = (0..0x3000u32).map(|i| (i % 251) as u8).collect();
        let mut bytes = vec![0u8; 0x40];
        bytes[..4].copy_from_slice(b"9FPR");
        bytes[4..8].copy_from_slice(&0x40u32.to_le_bytes());
        // 16 zero bytes in front of the first system stream.
        bytes.resize(0x1010, 0);
        let mut offsets = Vec::new();
        for page in [&system, &graphics] {
            bytes.resize(bytes.len().next_multiple_of(16), 0);
            offsets.push(bytes.len() as u64);
            bytes.extend_from_slice(&zlib(page));
        }
        bytes.resize(bytes.len().next_multiple_of(16), 0);
        fs::write(&archive, bytes).unwrap();
        build(&archive);

        assert_eq!(names(&files::list(&archive).unwrap()), [RECOVERED, PAGES]);
        assert_eq!(
            names(&files::list(&archive.join(RECOVERED)).unwrap()),
            ["Resources"]
        );
        let resources = files::list(&archive.join(RECOVERED).join("Resources")).unwrap();
        assert_eq!(resources.len(), 1);
        let resource = &resources[0];
        assert_eq!(resource.type_name, "RAGE resource");
        assert_eq!(resource.size, Some(0x3100));
        let detail = |entry: &Entry, label: &str| {
            entry
                .details
                .iter()
                .find(|(l, _)| *l == label)
                .map(|(_, value)| value.clone())
        };
        assert!(detail(resource, "Status").unwrap().starts_with("Complete"));
        assert!(
            detail(resource, "Graphics data")
                .unwrap()
                .contains("1 page")
        );
        assert_eq!(
            files::read(&resource.path).unwrap(),
            [system.clone(), graphics.clone()].concat()
        );

        let pages = files::list(&archive.join(PAGES)).unwrap();
        assert_eq!(
            names(&pages),
            [
                format!("0x{:010X}.bin", offsets[0]),
                format!("0x{:010X}.bin", offsets[1])
            ]
        );
        assert_eq!(pages[1].type_name, "Resource graphics page");
        assert_eq!(detail(&pages[1], "Page").unwrap(), "graphics page 1 of 1");
        assert_eq!(files::read(&pages[1].path).unwrap(), graphics);
        let mut inspected = files::open_binary(&pages[0].path).unwrap();
        assert_eq!(
            lforge_binary::read_at(&mut inspected.source, 0, 0x100).unwrap(),
            system
        );
        assert!(
            files::describe(&archive.join(PAGES))
                .unwrap()
                .contains("1 reconstructed resource")
        );
        assert!(
            files::read(
                &archive
                    .join(PAGES)
                    .join(format!("0x{:010X}.bin", offsets[1] + 16))
            )
            .is_err()
        );
    }
}
