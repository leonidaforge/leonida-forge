//! RPF9 archives, browsed through their own table of contents (see
//! [`super::toc`]) and otherwise through the entries recovered from their
//! data.
//!
//! A table of contents that the engine processes before reading is used only
//! after it authenticated against a local executable ([`build_index`] with an
//! [`super::executable::Access`]). Without one, or when authentication fails,
//! the archive data can be scanned instead. Until that has happened, listings
//! fail with an error that [`super::archive::prepare_required`],
//! [`super::archive::executable_required`] or
//! [`super::archive::authentication_failure`] recognises, so the explorer can
//! show progress, ask which way to go and offer cancellation instead of
//! blocking.
//!
//! Recovered entries have no names or folders. Inside an archive,
//! `Recovered Entries` holds one virtual folder per kind of entry,
//! `Resource Pages` holds the page streams of reconstructed resources one by
//! one, and `Unrecovered Regions` holds byte ranges that could not be
//! decoded. Files are named after their archive offset, which stays the same
//! across scans.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use lforge_rage9::resource::{Page, Segment};
use lforge_rage9::rpf::metadata::verify;
use lforge_rage9::rpf::{self, CacheKey, Index, Kind, Progress, Region, Resource, Status, Stream};

use super::archive::{
    Archive, Dependency, Stage, Stamp, authentication_failed, check_size, needs_executable,
    needs_prepare,
};
use super::executable::Executable;
use super::toc;
use super::{Entry, EntryKind, format_bytes_exact, format_size};

pub const RECOVERED: &str = "Recovered Entries";
pub const PAGES: &str = "Resource Pages";
pub const UNRECOVERED: &str = "Unrecovered Regions";
/// Indexes kept in memory; older ones are reloaded from the cache file.
/// Tests run at the same time and share this cache, so they get room enough
/// not to push out each other's indexes. Eviction is tested on purpose in
/// `files::eviction` and with small limits in this module's tests.
const MAX_IN_MEMORY: usize = if cfg!(test) { 4096 } else { 8 };

const SOURCE_NOTE: &str = "Recovered from a zlib stream in the archive data. The name is the \
     archive offset; the original name and folder are unknown.";

const RESOURCE_SOURCE_NOTE: &str = "Reconstructed from consecutive zlib streams in the archive \
     data: the system pages, then the graphics pages, as pointers in the resource address them. \
     The name is the archive offset; the original name and folder are unknown.";

/// What an archive is listed from.
#[derive(Clone)]
enum Contents {
    Native(Arc<toc::Native>),
    /// Entries recovered from the data, and why the table of contents was
    /// not used.
    Recovered(Arc<Index>, Arc<str>),
}

/// Why the contents of an archive are not available yet.
#[derive(Debug, Clone)]
enum Unavailable {
    /// The stored metadata needs processing, and no executable is configured.
    Executable(Arc<str>),
    /// The configured executable did not authenticate the stored metadata, or
    /// is no longer the file that was selected.
    Authentication(Arc<str>),
    /// The stored metadata is not usable; the data can be scanned.
    Recoverable(Arc<str>),
    /// The stored metadata needs processing and an executable is configured.
    /// Only [`build_index`] spends the time to authenticate it, so a cached
    /// recovery index is not used in its place.
    Deferred,
}

struct Cached {
    stamp: Stamp,
    /// Of the archive, as it was opened.
    dependencies: Vec<Dependency>,
    /// The executable the contents were obtained with, so a different one is
    /// never mixed into what was read with another.
    executable: Option<(PathBuf, Stamp)>,
    contents: Contents,
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
    let mut version = rpf::file_version(&fs::metadata(&archive.root)?)?;
    // The bytes may also come from companion files.
    for dependency in &archive.dependencies {
        version.extend_from_slice(format!("|{dependency:?}").as_bytes());
    }
    Ok(CacheKey { location, version })
}

impl Indexes {
    /// Keeps `cached`, then drops the least recently used other entry if more
    /// than `max` remain. The new entry itself is never dropped.
    fn insert(&mut self, path: PathBuf, mut cached: Cached, max: usize) {
        self.clock += 1;
        cached.last_used = self.clock;
        self.by_archive.insert(path.clone(), cached);
        if self.by_archive.len() > max
            && let Some(oldest) = self
                .by_archive
                .iter()
                .filter(|(other, _)| **other != path)
                .min_by_key(|(_, cached)| cached.last_used)
                .map(|(path, _)| path.clone())
        {
            self.by_archive.remove(&oldest);
        }
    }
}

fn remember(archive: &Archive, contents: Contents) -> Contents {
    let cached = Cached {
        stamp: archive.stamp,
        dependencies: archive.dependencies.clone(),
        executable: archive.access.identity(),
        contents: contents.clone(),
        last_used: 0,
    };
    indexes().insert(archive.path.clone(), cached, MAX_IN_MEMORY);
    contents
}

/// Drops what is kept in memory for the archive at `path`, as eviction
/// would.
#[cfg(test)]
pub(crate) fn forget(path: &Path) {
    indexes().by_archive.remove(path);
}

fn in_memory(archive: &Archive) -> Option<Contents> {
    let mut indexes = indexes();
    indexes.clock += 1;
    let now = indexes.clock;
    let cached = indexes.by_archive.get_mut(&archive.path)?;
    let current = cached.stamp == archive.stamp
        && cached.dependencies == archive.dependencies
        && cached.executable == archive.access.identity()
        && match &cached.contents {
            Contents::Native(native) => native.is_current(archive),
            Contents::Recovered(index, _) => index.archive_len == archive.source.len(),
        };
    if !current {
        return None;
    }
    cached.last_used = now;
    Some(cached.contents.clone())
}

/// Authenticates the stored table of contents with `executable` and returns
/// it. Only a passing signature check yields native entries.
fn authenticate(
    archive: &Archive,
    executable: &Executable,
    cancel: &AtomicBool,
) -> Result<toc::Native, Arc<str>> {
    let mut source = archive.source.clone();
    let open = verify::open_authenticated(&mut source, executable.view(), cancel)
        .map_err(|err| Arc::from(format!("The metadata could not be read: {err}.")))?;
    let report = open.report;
    let Some(authenticated) = open.authenticated else {
        return Err(Arc::from(format!(
            "{} did not authenticate the metadata: {} (stage {}).",
            executable.name(),
            report.outcome,
            report.stage
        )));
    };
    Ok(toc::Native::from_authenticated(
        archive,
        authenticated.into_metadata(),
        report,
    ))
}

/// The contents of `archive` from memory, its table of contents, a local
/// executable or the cache file, or why they are not available. `allow_auth`
/// decides whether the stored metadata may be authenticated here; only
/// [`build_index`] does that, so a listing never spends that time and cannot
/// preempt the progress and cancellation the explorer offers. Never scans.
fn lookup(
    archive: &Archive,
    allow_auth: bool,
    cancel: &AtomicBool,
) -> io::Result<Result<Contents, Unavailable>> {
    if let Some(contents) = in_memory(archive) {
        return Ok(Ok(contents));
    }
    let unreadable = match toc::Native::read(archive) {
        Ok(native) => return Ok(Ok(remember(archive, Contents::Native(Arc::new(native))))),
        Err(unreadable) => unreadable,
    };
    let unreadable_reason = unreadable.reason().clone();
    let mut failed: Option<Arc<str>> = None;
    // Whether a recovery index kept for this archive may stand in for the
    // table of contents. Not while an executable that could authenticate it
    // is selected: the prepare step decides, and authenticating is preferred
    // over recovery.
    let mut may_scan = true;
    match archive.access.executable() {
        // A changed executable says nothing about this archive, so it is not
        // used; the selection has to be repeated.
        Some(executable) if !executable.is_current() => {
            failed = Some(Arc::from(format!(
                "{} changed since it was selected, so it was not used. Select it again, or \
                 scan the archive data.",
                executable.name()
            )));
        }
        Some(executable) if allow_auth => match authenticate(archive, executable, cancel) {
            Ok(native) => return Ok(Ok(remember(archive, Contents::Native(Arc::new(native))))),
            Err(reason) => failed = Some(reason),
        },
        Some(_) => may_scan = false,
        None => {}
    }
    // Recovery stays available whatever the table of contents did: an index
    // kept for this archive is used, and carries the reason it was needed.
    let reason = failed.clone().unwrap_or(unreadable_reason);
    if may_scan
        && let Some(dir) = cache_dir()
        && let Some(index) = rpf::load(&dir, &cache_key(archive)?, archive.source.len())
    {
        let recovered = Contents::Recovered(Arc::new(index), reason);
        return Ok(Ok(remember(archive, recovered)));
    }
    Ok(Err(match failed {
        Some(reason) => Unavailable::Authentication(reason),
        None if !may_scan => Unavailable::Deferred,
        None => match unreadable {
            toc::Unreadable::Processed(reason) => Unavailable::Executable(reason),
            toc::Unreadable::Malformed(reason) => Unavailable::Recoverable(reason),
        },
    }))
}

fn contents(archive: &Archive) -> io::Result<Contents> {
    lookup(archive, false, &AtomicBool::new(false))?
        .map_err(|_| needs_prepare(archive.path.clone()))
}

/// Reads the table of contents or, where it cannot be used, scans `archive`,
/// unless its contents are in memory or in the cache. Keeps the result in
/// memory.
///
/// With an executable configured, the stored metadata is authenticated first.
/// `allow_scan` decides whether scanning may stand in for a table of contents
/// that no executable authenticated; without it, the call fails with an error
/// the explorer recognises and turns into a choice for the user.
pub fn build_index(
    archive: &Archive,
    allow_scan: bool,
    stage: &Stage,
    progress: &Progress,
    cancel: &AtomicBool,
) -> io::Result<()> {
    stage.set(Stage::VERIFYING);
    let unavailable = match lookup(archive, true, cancel)? {
        Ok(_) => return Ok(()),
        Err(unavailable) => unavailable,
    };
    if cancel.load(Ordering::Relaxed) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
    }
    match &unavailable {
        Unavailable::Authentication(reason) if !allow_scan => {
            return Err(authentication_failed(
                archive.path.clone(),
                reason.to_string(),
            ));
        }
        Unavailable::Executable(reason) if !allow_scan => {
            return Err(needs_executable(archive.path.clone(), reason.to_string()));
        }
        _ => {}
    }
    let reason = match unavailable {
        Unavailable::Executable(reason)
        | Unavailable::Authentication(reason)
        | Unavailable::Recoverable(reason) => reason,
        // Only reachable without an authentication attempt, which this
        // function always makes.
        Unavailable::Deferred => Arc::from("The table of contents is processed before use."),
    };
    stage.set(Stage::SCANNING);
    let key = cache_key(archive)?;
    let index = rpf::scan(archive.source.clone(), progress, cancel)?;
    if let Some(dir) = cache_dir()
        && cache_key(archive).is_ok_and(|after| after == key)
    {
        let _ = rpf::store(&dir, &key, &index);
    }
    remember(archive, Contents::Recovered(Arc::new(index), reason));
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
    match contents(archive)? {
        Contents::Native(native) => native.list(archive, inner),
        Contents::Recovered(index, _) => list_recovered(archive, &index, inner),
    }
}

fn list_recovered(archive: &Archive, index: &Index, inner: &Path) -> io::Result<Vec<Entry>> {
    let dir = archive.path.join(inner);
    let entries = match resolve(index, inner).ok_or_else(not_found)? {
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
            .map(|entry| entry_file(&dir, index, entry))
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

/// Writes one entry, page or region to `out`, within `limit`.
pub fn copy(
    archive: &Archive,
    inner: &Path,
    out: &mut dyn Write,
    limit: u64,
    cancel: &AtomicBool,
) -> io::Result<()> {
    let index = match contents(archive)? {
        Contents::Native(native) => return native.copy(archive, inner, out, limit, cancel),
        Contents::Recovered(index, _) => index,
    };
    let source = archive.source.clone();
    match resolve(&index, inner).ok_or_else(not_found)? {
        Node::Entry(entry) => {
            check_size(entry.len, limit)?;
            rpf::read_entry(source, &index, entry, limit, out, cancel)?;
        }
        Node::Page(resource, position) => {
            let (page, streams) = index
                .resource_pages(resource)
                .nth(position)
                .ok_or_else(not_found)?;
            check_size(page.len, limit)?;
            rpf::read_streams(source, &index, streams, limit, out, cancel)?;
        }
        Node::Region(region) => {
            check_size(region.len, limit)?;
            rpf::read_region(source, region, limit, out, cancel)?;
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
    let index = match contents(archive)? {
        Contents::Native(native) => return Ok(native.file_prefix(inner)),
        Contents::Recovered(index, _) => index,
    };
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
    let index = match contents(archive)? {
        Contents::Native(native) => return native.file_len(inner),
        Contents::Recovered(index, _) => index,
    };
    let node = resolve(&index, inner).ok_or_else(not_found)?;
    file_node_len(&node, &index).ok_or_else(|| io::Error::other("not a file"))
}

/// Why an archive recovered from the entry at `inner` may be incomplete.
pub fn caveat(archive: &Archive, inner: &Path) -> Option<String> {
    let Contents::Recovered(index, _) = contents(archive).ok()? else {
        return None;
    };
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

/// The bytes of a file stored as it is, as a view of the archive's source.
/// `None` for anything else, which [`copy`] decodes or reports.
/// The further files the bytes of the file at `inner` come from: its
/// companion file, if it is read through one.
pub fn dependencies(archive: &Archive, inner: &Path) -> io::Result<Vec<Dependency>> {
    Ok(match contents(archive)? {
        Contents::Native(native) => native.dependencies(archive, inner),
        Contents::Recovered(..) => Vec::new(),
    })
}

pub fn raw_source(archive: &Archive, inner: &Path) -> io::Result<Option<lforge_binary::Source>> {
    match contents(archive)? {
        Contents::Native(native) => Ok(native.raw_source(archive, inner)),
        // Recovered entries are zlib streams.
        Contents::Recovered(..) => Ok(None),
    }
}

/// Explains where the contents of an archive folder come from. Returns
/// `None` until the archive is indexed.
pub fn describe(archive: &Archive, inner: &Path) -> Option<String> {
    let (index, reason) = match contents(archive).ok()? {
        Contents::Native(native) => return native.describe(archive, inner),
        Contents::Recovered(index, reason) => (index, reason),
    };
    let percent = |part: u64| match index.data_len() {
        0 => 0.0,
        total => part as f64 * 100.0 / total as f64,
    };
    let note = match resolve(&index, inner)? {
        Node::Root if index.entries.is_empty() => format!(
            "{reason} No entries could be recovered: no zlib streams were found in the archive \
             data. The archive is not necessarily empty."
        ),
        Node::Root | Node::Recovered | Node::Kind(_) => format!(
            "{reason} {} were recovered from zlib streams covering {:.1}% of the archive data. \
             Folders and names are not original: entries are grouped by kind and named after \
             their archive offset.",
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
    use crate::files::{Access, Executable};

    pub(crate) fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// A header, a table of contents of 0x60 bytes that the static pass
    /// processes, as in real archives, then `parts` at aligned offsets
    /// starting at 0x100.
    pub(crate) fn rpf_bytes(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x40];
        bytes[..4].copy_from_slice(b"9FPR");
        bytes[4..8].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes[0x2C] = 1;
        bytes[0x2D] = 1;
        bytes[0x2E] = 9;
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

    fn recovered_contents() -> Contents {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&rpf_bytes(&[zlib(b"text")])).unwrap();
        let source = lforge_binary::Source::from_file(file).unwrap();
        let index = rpf::scan(source, &Progress::default(), &AtomicBool::new(false)).unwrap();
        Contents::Recovered(Arc::new(index), Arc::from("reason"))
    }
    fn cached(contents: &Contents) -> Cached {
        Cached {
            stamp: (0, None),
            dependencies: Vec::new(),
            executable: None,
            contents: contents.clone(),
            last_used: 0,
        }
    }

    #[test]
    fn indexes_drop_the_least_recently_used() {
        let contents = recovered_contents();
        let mut indexes = Indexes::default();
        for name in ["a", "b", "c"] {
            indexes.insert(PathBuf::from(name), cached(&contents), 2);
        }
        let mut names: Vec<_> = indexes.by_archive.keys().cloned().collect();
        names.sort();
        assert_eq!(names, [PathBuf::from("b"), PathBuf::from("c")]);
        indexes.clock += 1;
        indexes
            .by_archive
            .get_mut(Path::new("b"))
            .unwrap()
            .last_used = indexes.clock;
        indexes.insert(PathBuf::from("d"), cached(&contents), 2);
        let mut names: Vec<_> = indexes.by_archive.keys().cloned().collect();
        names.sort();
        assert_eq!(names, [PathBuf::from("b"), PathBuf::from("d")]);
        // The new entry stays; the least recently used other one goes.
        indexes.insert(PathBuf::from("e"), cached(&contents), 2);
        let mut names: Vec<_> = indexes.by_archive.keys().cloned().collect();
        names.sort();
        assert_eq!(names, [PathBuf::from("d"), PathBuf::from("e")]);
    }

    fn detail<'a>(entry: &'a Entry, label: &str) -> Option<&'a str> {
        entry
            .details
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, value)| value.as_str())
    }

    /// An RPF9 archive whose table of contents the engine processes, with two
    /// payloads in its data.
    fn processed_archive(dir: &Path) -> PathBuf {
        let archive = dir.join("data.rpf");
        write_rpf(
            &archive,
            &[zlib(b"<?xml version=\"1.0\"?><a/>"), zlib(b"plain text")],
        );
        archive
    }

    fn prepare_with(archive: &Path, access: &Access, allow_scan: bool) -> io::Result<()> {
        archive::prepare_with(
            archive,
            access,
            allow_scan,
            &Stage::default(),
            &Progress::default(),
            &AtomicBool::new(false),
        )
    }

    /// An executable that opens as an image but holds no compatible metadata
    /// state, as a game build this tool does not recognise would.
    fn unrelated_executable(dir: &Path) -> Access {
        let path = dir.join("other.exe");
        fs::write(&path, crate::files::executable::tests::pe_bytes()).unwrap();
        Access::with(Arc::new(Executable::open(&path).unwrap()))
    }

    #[test]
    fn a_processed_archive_without_an_executable_asks_for_one() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        let err = prepare_with(&archive, &Access::none(), false).unwrap_err();
        let (path, reason) = archive::executable_required(&err).unwrap();
        assert_eq!(path, archive.as_path());
        assert!(reason.contains("processed"), "{reason}");
        // Neither an authentication failure nor a scan request.
        assert!(archive::authentication_failure(&err).is_none());
        assert!(prepare_required(&err).is_none());
        // Nothing was scanned, so the listing still cannot be produced.
        let err = files::list(&archive).unwrap_err();
        assert_eq!(prepare_required(&err), Some(archive.as_path()));
    }

    #[test]
    fn an_unrelated_executable_fails_authentication_not_the_payload() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        let access = unrelated_executable(temp.path());
        let err = prepare_with(&archive, &access, false).unwrap_err();
        let (path, reason) = archive::authentication_failure(&err).unwrap();
        assert_eq!(path, archive.as_path());
        assert!(reason.contains("did not authenticate"), "{reason}");
        // A failed authentication is not reported as a missing executable.
        assert!(archive::executable_required(&err).is_none());
    }

    #[test]
    fn recovery_stays_available_without_an_executable() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        prepare_with(&archive, &Access::none(), true).unwrap();
        assert_eq!(names(&files::list(&archive).unwrap()), [RECOVERED]);
    }

    #[test]
    fn choosing_to_scan_keeps_recovered_entries_and_says_why() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        let access = unrelated_executable(temp.path());
        prepare_with(&archive, &access, true).unwrap();
        assert_eq!(
            names(&files::list_with(&archive, &access).unwrap()),
            [RECOVERED]
        );
        let note = files::describe_with(&archive, &access).unwrap();
        assert!(note.contains("did not authenticate"), "{note}");
        assert!(!note.contains("stored unencrypted"), "{note}");
    }

    #[test]
    fn selecting_an_executable_invalidates_contents_read_without_one() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        prepare_with(&archive, &Access::none(), true).unwrap();
        assert!(files::list(&archive).is_ok());
        let access = unrelated_executable(temp.path());
        let err = files::list_with(&archive, &access).unwrap_err();
        assert_eq!(prepare_required(&err), Some(archive.as_path()));
    }

    #[test]
    fn a_changed_executable_is_not_used() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        let path = temp.path().join("other.exe");
        fs::write(&path, crate::files::executable::tests::pe_bytes()).unwrap();
        let executable = Arc::new(Executable::open(&path).unwrap());
        fs::write(&path, b"changed after it was opened").unwrap();
        let access = Access::with(executable);
        let err = prepare_with(&archive, &access, false).unwrap_err();
        let (_, reason) = archive::authentication_failure(&err).unwrap();
        assert!(reason.contains("changed"), "{reason}");
    }

    #[test]
    fn cancellation_stops_before_any_scan_starts() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        let err = archive::prepare_with(
            &archive,
            &Access::none(),
            false,
            &Stage::default(),
            &Progress::default(),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn overlapping_opens_of_one_archive_both_finish() {
        let temp = tempfile::tempdir().unwrap();
        let archive = processed_archive(temp.path());
        let (one, two) = std::thread::scope(|scope| {
            let other = scope.spawn(|| prepare_with(&archive, &Access::none(), true));
            let one = prepare_with(&archive, &Access::none(), true);
            (one, other.join().unwrap())
        });
        assert!(one.is_ok(), "{:?}", one.err());
        assert!(two.is_ok(), "{:?}", two.err());
        assert_eq!(names(&files::list(&archive).unwrap()), [RECOVERED]);
    }

    #[test]
    fn an_executable_context_reaches_archives_stored_in_archives() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().join("outer.rpf");
        // The inner archive is stored as one zlib stream in the outer
        // archive, so scanning recovers it as a whole entry.
        let inner = rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><inner/>")]);
        write_rpf(&outer, &[zlib(&inner)]);
        let access = unrelated_executable(temp.path());
        prepare_with(&outer, &access, true).unwrap();

        let root = files::list_with(&outer, &access).unwrap();
        let recovered = root.iter().find(|entry| entry.name == RECOVERED).unwrap();
        let kinds = files::list_with(&recovered.path, &access).unwrap();
        let entries = files::list_with(&kinds[0].path, &access).unwrap();
        let stored = &entries[0];

        // The outer archive's context is carried into what is stored in it.
        let archive::Location::Inside(outer_archive, _) =
            archive::locate_with(&stored.path, &access).unwrap()
        else {
            panic!("expected an entry inside the outer archive");
        };
        assert_eq!(outer_archive.access.identity(), access.identity());

        // Once it is opened, the nested archive keeps the same context.
        prepare_with(&stored.path, &access, true).unwrap();
        let archive::Location::Archive(nested) =
            archive::locate_with(&stored.path, &access).unwrap()
        else {
            panic!("expected the stored entry to be an archive");
        };
        assert_eq!(nested.access.identity(), access.identity());
    }

    #[test]
    fn native_rows_show_grounded_fields_and_their_metadata_status() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("native.rpf");
        fs::write(
            &path,
            crate::files::toc::tests::native_rpf(&[crate::files::toc::tests::Spec {
                hash: Some(lforge_rage9::rpf::names::hash64(b"data")),
                ..crate::files::toc::tests::spec(b"five bytes", 11)
            }]),
        )
        .unwrap();
        let rows = files::list(&path).unwrap();
        let row = &rows[0];
        let hash = format!("0x{:016X}", lforge_rage9::rpf::names::hash64(b"data"));
        assert_eq!(row.name, hash.as_str());
        assert_eq!(detail(row, "Name hash"), Some(hash.as_str()));
        assert_eq!(detail(row, "Type ID"), Some("11 (meaning not established)"));
        assert!(detail(row, "Metadata").unwrap().starts_with("Unencrypted"));
        assert!(detail(row, "Contents").is_some());
    }

    /// Opens a copy of a local archive with a LUT sidecar, read-only. Set
    /// `LEONIDA_FORGE_EXECUTABLE`, `LEONIDA_FORGE_ARCHIVE` and
    /// `LEONIDA_FORGE_LUT`.
    #[test]
    #[ignore = "set the three environment variables to local files to run"]
    fn local_lut_labels_smoke_test() {
        let Some(executable) = std::env::var_os("LEONIDA_FORGE_EXECUTABLE") else {
            panic!("set LEONIDA_FORGE_EXECUTABLE to a local executable");
        };
        let Some(archive) = std::env::var_os("LEONIDA_FORGE_ARCHIVE") else {
            panic!("set LEONIDA_FORGE_ARCHIVE to a local archive");
        };
        let Some(lut) = std::env::var_os("LEONIDA_FORGE_LUT") else {
            panic!("set LEONIDA_FORGE_LUT to a local LUT");
        };
        let executable = Arc::new(Executable::open(Path::new(&executable)).unwrap());
        let access = Access::with(executable);
        let temp = tempfile::tempdir().unwrap();
        let source = PathBuf::from(archive);
        let name = source.file_name().unwrap();
        let archive = temp.path().join(name);
        std::fs::copy(&source, &archive).unwrap();
        let mut sidecar = name.to_os_string();
        sidecar.push(".lut");
        std::fs::copy(PathBuf::from(lut), temp.path().join(sidecar)).unwrap();

        prepare_with(&archive, &access, false).unwrap();
        let rows = files::list_with(&archive, &access).unwrap();
        let named = rows
            .iter()
            .filter(|row| detail(row, "Names").is_some_and(|text| !text.starts_with("Unknown")))
            .count();
        assert!(named > 0, "the LUT resolved no names");
        assert!(
            rows.iter()
                .any(|row| !row.name.starts_with("0x") && !row.name.starts_with("Row "))
        );
    }

    /// Reads a real archive through the desktop layer, read-only. Set the
    /// environment variables to a local executable and one of its archives.
    #[test]
    #[ignore = "set LEONIDA_FORGE_EXECUTABLE and LEONIDA_FORGE_ARCHIVE to local files to run"]
    fn local_authenticated_archive_smoke_test() {
        let Some(executable) = std::env::var_os("LEONIDA_FORGE_EXECUTABLE") else {
            panic!("set LEONIDA_FORGE_EXECUTABLE to a local executable to run this test");
        };
        let Some(archive) = std::env::var_os("LEONIDA_FORGE_ARCHIVE") else {
            panic!("set LEONIDA_FORGE_ARCHIVE to a local archive to run this test");
        };
        let executable = Arc::new(Executable::open(Path::new(&executable)).unwrap());
        let access = Access::with(executable);
        let archive = PathBuf::from(archive);

        prepare_with(&archive, &access, false).unwrap();
        let rows = files::list_with(&archive, &access).unwrap();
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|row| row.name.starts_with("Row ")));
        let note = files::describe_with(&archive, &access).unwrap();
        assert!(note.contains("signature verified"), "{note}");

        let readable = rows.iter().find(|row| {
            row.kind == EntryKind::File
                && detail(row, "Contents").is_some_and(|text| !text.starts_with("Not readable"))
        });
        match readable {
            Some(row) => {
                // The preview and export readers return exactly the logical size.
                let bytes = files::read_with(&row.path, &access).unwrap();
                assert_eq!(Some(bytes.len() as u64), row.size);
            }
            // A sample whose rows all need a transform this tool refuses.
            None => assert!(
                rows.iter()
                    .filter(|row| row.kind == EntryKind::File)
                    .all(|row| detail(row, "Contents")
                        .is_some_and(|text| text.starts_with("Not readable")))
            ),
        }
    }
}
