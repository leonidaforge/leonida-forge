//! Archives browsed like folders, wherever they are stored.
//!
//! A path continues inside an archive file, and inside archives stored in
//! that archive, e.g. `pack.rpf\Recovered Entries\Unidentified\
//! 0x0000001000.bin\Recovered Entries`. [`locate`] walks such a path one
//! archive at a time. Archives are recognised by their contents, not by
//! their names.
//!
//! An archive stored in another archive is opened once, by [`prepare`]: as a
//! view of its parent's bytes if it is stored as it is, otherwise
//! decompressed into an anonymous temporary file. It is reused while the
//! file on disk that holds the outermost archive is unchanged. Until then,
//! and until an RPF9 archive is indexed, operations fail with an error that
//! [`prepare_required`] recognises, so the explorer can show progress and
//! offer cancellation instead of blocking.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::SystemTime;

use lforge_binary::Source;
use lforge_core::archive::{self as identify, HEAD_LEN};
pub use lforge_core::archive::{Format, Identified};
use lforge_core::classify::{self, Classification};
use lforge_core::resource::{EntryId, ResourcePath};
use lforge_rage9::rpf::Progress;

use super::executable::Access;
use super::{Entry, EntryKind, format_size, rpf, zip};

/// Caps what reading one file from an archive may allocate in memory or on disk.
pub const MAX_READ: u64 = 512 * 1024 * 1024;
/// Largest resource materialized into memory by the generic read helpers.
/// Larger files must be opened for random access or exported instead.
pub const MAX_MATERIALIZE: u64 = 64 * 1024 * 1024;
/// Archives in a chain, counting the one on disk.
pub const MAX_DEPTH: usize = 8;
/// Caps the bytes decompressed for an archive and the archives it is stored in.
pub const MAX_CHAIN: u64 = 2 * 1024 * 1024 * 1024;
/// Caps the decompressed archives kept for reuse. Archives still in use stay
/// alive until they are no longer used.
const MAX_KEPT: u64 = 2 * 1024 * 1024 * 1024;
/// Tests run at the same time and share this cache, so they get room enough
/// not to push out each other's archives. Eviction is tested on purpose in
/// `files::eviction` and with small limits in this module's tests.
const MAX_KEPT_COUNT: usize = if cfg!(test) { 4096 } else { 32 };
/// In folders with more files, only files with an archive extension are
/// checked, so listing them does not open every file. Opening any file still
/// checks its contents.
const MAX_IDENTIFIED: usize = 4096;
/// Bounds [`prepare`] in case kept archives are dropped as soon as they are
/// decompressed.
const MAX_ATTEMPTS: usize = 2 * MAX_DEPTH + 2;

/// Size and modification time of a file on disk.
pub type Stamp = (u64, Option<SystemTime>);

/// A file other than the one the chain starts at that an archive's bytes
/// come from, with its stamp when they were read. `None` for a file that did
/// not exist.
pub type Dependency = (PathBuf, Option<Stamp>);

/// The stamp of a regular file, or `None` if there is none.
pub fn file_stamp(path: &Path) -> Option<Stamp> {
    let metadata = fs::metadata(path).ok()?;
    metadata
        .is_file()
        .then(|| (metadata.len(), metadata.modified().ok()))
}

/// Whether every file in `dependencies` is unchanged.
pub fn dependencies_current(dependencies: &[Dependency]) -> bool {
    dependencies
        .iter()
        .all(|(path, stamp)| file_stamp(path) == *stamp)
}

/// An archive opened for reading.
#[derive(Debug, Clone)]
pub struct Archive {
    /// Where the archive is. Paths inside it continue from here.
    pub path: PathBuf,
    pub format: Format,
    pub source: Source,
    /// The file on disk that holds the outermost archive.
    pub root: PathBuf,
    pub stamp: Stamp,
    /// 1 for an archive on disk.
    pub depth: usize,
    /// Bytes decompressed for this archive and the archives it is stored in.
    pub decompressed: u64,
    /// Why the contents may be incomplete, for archives recovered from
    /// another archive.
    pub caveat: Option<String>,
    /// Further files this archive's bytes come from, such as RPF9 companion
    /// files, for archives opened from another archive.
    pub dependencies: Vec<Dependency>,
    /// The executable that may authenticate the stored table of contents.
    /// Carried along so no reader has to look one up globally.
    pub access: Access,
    /// The canonical path of this archive: the root file name and every
    /// nested archive it was entered through. It names no entry itself.
    pub resource: ResourcePath,
}

impl Archive {
    fn on_disk(path: &Path, access: &Access) -> io::Result<Result<Self, Identified>> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Ok(Err(Identified::Unknown));
        }
        let mut source = Source::from_file(file)?;
        Ok(match identify::identify(&mut source)? {
            Identified::Archive(format) => Ok(Self {
                path: path.to_path_buf(),
                format,
                source,
                root: path.to_path_buf(),
                stamp: (metadata.len(), metadata.modified().ok()),
                depth: 1,
                decompressed: 0,
                caveat: None,
                dependencies: Vec::new(),
                access: access.clone(),
                resource: ResourcePath::root(file_name(path)),
            }),
            other => Err(other),
        })
    }

    /// The path below the file on disk, empty for an archive on disk.
    pub fn nested_path(&self) -> &Path {
        self.path.strip_prefix(&self.root).unwrap_or(Path::new(""))
    }
}

/// An archive that has to be decompressed or indexed first.
#[derive(Debug)]
struct PrepareRequired {
    path: PathBuf,
}

impl fmt::Display for PrepareRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} has not been opened yet", self.path.display())
    }
}

impl std::error::Error for PrepareRequired {}

pub(super) fn needs_prepare(path: PathBuf) -> io::Error {
    io::Error::other(PrepareRequired { path })
}

/// The archive that [`prepare`] has to open before the operation that failed
/// with `err` can succeed.
pub fn prepare_required(err: &io::Error) -> Option<&Path> {
    let inner = err.get_ref()?.downcast_ref::<PrepareRequired>()?;
    Some(&inner.path)
}

/// An RPF9 archive whose stored table of contents needs processing, opened
/// without an executable to authenticate it. The caller chooses between
/// selecting an executable and scanning the archive data.
#[derive(Debug)]
struct NeedsExecutable {
    path: PathBuf,
    reason: String,
}

impl fmt::Display for NeedsExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} has a processed table of contents and no compatible executable was supplied: {}",
            file_name(&self.path),
            self.reason
        )
    }
}

impl std::error::Error for NeedsExecutable {}

pub(super) fn needs_executable(path: PathBuf, reason: impl Into<String>) -> io::Error {
    io::Error::other(NeedsExecutable {
        path,
        reason: reason.into(),
    })
}

/// The archive, and why, that needs an executable before its native table of
/// contents can be read.
pub fn executable_required(err: &io::Error) -> Option<(&Path, &str)> {
    let inner = err.get_ref()?.downcast_ref::<NeedsExecutable>()?;
    Some((&inner.path, &inner.reason))
}

/// The stored table of contents was not accepted with the supplied
/// executable: the authentication attempt failed, or the executable is no
/// longer the one that was selected. The archive data can still be scanned.
#[derive(Debug)]
struct AuthenticationFailed {
    path: PathBuf,
    reason: String,
}

impl fmt::Display for AuthenticationFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the table of contents of {} could not be authenticated: {}",
            file_name(&self.path),
            self.reason
        )
    }
}

impl std::error::Error for AuthenticationFailed {}

pub(super) fn authentication_failed(path: PathBuf, reason: impl Into<String>) -> io::Error {
    io::Error::other(AuthenticationFailed {
        path,
        reason: reason.into(),
    })
}

/// The archive, and why, whose stored table of contents failed
/// authentication.
pub fn authentication_failure(err: &io::Error) -> Option<(&Path, &str)> {
    let inner = err.get_ref()?.downcast_ref::<AuthenticationFailed>()?;
    Some((&inner.path, &inner.reason))
}

/// What opening an archive is doing, for the explorer's progress view.
#[derive(Debug, Default)]
pub struct Stage(AtomicU8);

impl Stage {
    /// The archive is decompressed, read or awaited.
    pub const OPENING: u8 = 0;
    /// The stored table of contents is authenticated with the selected
    /// executable.
    pub const VERIFYING: u8 = 1;
    /// The archive data is scanned for recovery.
    pub const SCANNING: u8 = 2;

    pub fn set(&self, stage: u8) {
        self.0.store(stage, Ordering::Relaxed);
    }

    pub fn get(&self) -> u8 {
        self.0.load(Ordering::Relaxed)
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

/// Why `path` cannot be opened as an archive.
pub fn not_an_archive(path: &Path, identified: &Identified) -> io::Error {
    let name = file_name(path);
    match identified {
        Identified::Invalid { format, reason } => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} is not a valid {format} archive: {reason}"),
        ),
        _ => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} is not an archive in a supported format"),
        ),
    }
}

/// What a path names.
#[derive(Debug)]
pub enum Location {
    /// A directory or file on disk that is not an archive or inside one.
    Plain,
    /// An archive, on disk or opened from another archive.
    Archive(Archive),
    /// A folder or file inside an archive. The path is not empty.
    Inside(Archive, PathBuf),
}

/// Resolves `path` through every archive it continues into, without an
/// executable to authenticate stored metadata with.
#[cfg(test)]
pub fn locate(path: &Path) -> io::Result<Location> {
    locate_with(path, &Access::none())
}

/// Resolves `path` through every archive it continues into. `access` is
/// carried into the archives, so their tables of contents can be
/// authenticated later.
pub fn locate_with(path: &Path, access: &Access) -> io::Result<Location> {
    let Some(root) = path.ancestors().find(|ancestor| ancestor.is_file()) else {
        return Ok(Location::Plain);
    };
    let mut archive = match Archive::on_disk(root, access)? {
        Ok(archive) => archive,
        Err(_) if root == path => return Ok(Location::Plain),
        Err(identified) => return Err(not_an_archive(root, &identified)),
    };
    loop {
        let inner = path
            .strip_prefix(&archive.path)
            .map_err(io::Error::other)?
            .to_path_buf();
        if inner.as_os_str().is_empty() {
            return Ok(Location::Archive(archive));
        }
        match file_prefix(&archive, &inner)? {
            Some(file) if file != inner => archive = open_nested(&archive, &file)?,
            Some(_) => {
                return Ok(match kept(&archive, &inner) {
                    Some(nested) => Location::Archive(nested),
                    None => Location::Inside(archive, inner),
                });
            }
            None => return Ok(Location::Inside(archive, inner)),
        }
    }
}

/// Like [`locate`], but opens the archives on the way without cancellation.
/// For reading single files, where the explorer has opened them before.
#[cfg(test)]
pub fn locate_prepared(path: &Path) -> io::Result<Location> {
    locate_prepared_with(path, &Access::none())
}

/// [`locate_prepared`] with the executable that may authenticate stored
/// metadata.
pub fn locate_prepared_with(path: &Path, access: &Access) -> io::Result<Location> {
    for _ in 0..MAX_ATTEMPTS {
        match locate_with(path, access) {
            Err(err) => match prepare_required(&err) {
                Some(archive) => {
                    let archive = archive.to_path_buf();
                    prepare_with(
                        &archive,
                        access,
                        true,
                        &Stage::default(),
                        &Progress::default(),
                        &AtomicBool::new(false),
                    )?;
                }
                None => return Err(err),
            },
            location => return location,
        }
    }
    Err(io::Error::other("the archive could not be opened"))
}

/// Decompresses and indexes what `path` needs before it can be listed: the
/// archives it continues into and, if it names an archive, that archive.
/// Recovery is allowed, as for callers that have already chosen it.
#[cfg(test)]
pub fn prepare(path: &Path, progress: &Progress, cancel: &AtomicBool) -> io::Result<()> {
    prepare_with(
        path,
        &Access::none(),
        true,
        &Stage::default(),
        progress,
        cancel,
    )
}

/// [`prepare`] with the executable that may authenticate stored metadata.
///
/// `allow_scan` decides what happens when the table of contents needs a
/// processed pass that no executable can authenticate: with it set, the
/// archive data is scanned; without it, the call fails with
/// [`executable_required`] or [`authentication_failure`] so the explorer can
/// ask the user which way to go.
pub fn prepare_with(
    path: &Path,
    access: &Access,
    allow_scan: bool,
    stage: &Stage,
    progress: &Progress,
    cancel: &AtomicBool,
) -> io::Result<()> {
    for _ in 0..MAX_ATTEMPTS {
        let location = match locate_with(path, access) {
            Ok(location) => location,
            Err(err) => match prepare_required(&err) {
                // Always an archive that `path` continues into.
                Some(outer) if outer != path => {
                    let outer = outer.to_path_buf();
                    prepare_with(&outer, access, allow_scan, stage, progress, cancel)?;
                    continue;
                }
                _ => return Err(err),
            },
        };
        match location {
            Location::Archive(archive) => {
                return match archive.format {
                    Format::Rpf9 => rpf::build_index(&archive, allow_scan, stage, progress, cancel),
                    Format::Zip => Ok(()),
                };
            }
            Location::Inside(archive, inner) if is_file(&archive, &inner)? => {
                stage.set(Stage::OPENING);
                decompress(&archive, &inner, cancel)?;
            }
            Location::Inside(..) | Location::Plain => return Ok(()),
        }
    }
    Err(io::Error::other("the archive could not be opened"))
}

/// The shortest leading part of `inner` that names a file.
fn file_prefix(archive: &Archive, inner: &Path) -> io::Result<Option<PathBuf>> {
    match archive.format {
        Format::Zip => zip::file_prefix(archive, inner),
        Format::Rpf9 => rpf::file_prefix(archive, inner),
    }
}

pub fn is_file(archive: &Archive, inner: &Path) -> io::Result<bool> {
    Ok(file_prefix(archive, inner)?.as_deref() == Some(inner))
}

/// The size of a file in the archive, as its index declares it.
fn file_len(archive: &Archive, inner: &Path) -> io::Result<u64> {
    match archive.format {
        Format::Zip => zip::file_len(archive, inner),
        Format::Rpf9 => rpf::file_len(archive, inner),
    }
}

/// Writes one file from the archive to `out`, within `limit` bytes. Returns
/// its modification time, if the archive records one.
pub fn copy(
    archive: &Archive,
    inner: &Path,
    out: &mut dyn Write,
    limit: u64,
) -> io::Result<Option<SystemTime>> {
    copy_cancellable(archive, inner, out, limit, &AtomicBool::new(false))
}

/// [`copy`] that also stops while decoding once `cancel` is set. Writes to
/// `out` should check it too.
fn copy_cancellable(
    archive: &Archive,
    inner: &Path,
    out: &mut dyn Write,
    limit: u64,
    cancel: &AtomicBool,
) -> io::Result<Option<SystemTime>> {
    match archive.format {
        Format::Zip => zip::copy(archive, inner, out, limit),
        Format::Rpf9 => rpf::copy(archive, inner, out, limit, cancel).map(|()| None),
    }
}

/// Lists the direct children of `inner`. Files known to be archives are
/// listed as such.
pub fn list(archive: &Archive, inner: &Path) -> io::Result<Vec<Entry>> {
    let mut entries = match archive.format {
        Format::Zip => zip::list(archive, inner)?,
        Format::Rpf9 => rpf::list(archive, inner)?,
    };
    let kept = kept_archives();
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.kind == EntryKind::File)
    {
        if kept
            .by_path
            .get(&entry.path)
            .is_some_and(|nested| nested.is_current(archive))
        {
            entry.kind = EntryKind::Archive;
        }
    }
    Ok(entries)
}

/// Explains where the contents of an archive folder come from.
pub fn describe(archive: &Archive, inner: &Path) -> Option<String> {
    let note = match archive.format {
        Format::Rpf9 => rpf::describe(archive, inner),
        Format::Zip => None,
    };
    let caveat = archive
        .caveat
        .clone()
        .filter(|_| inner.as_os_str().is_empty());
    match (caveat, note) {
        (Some(caveat), Some(note)) => Some(format!("{caveat} {note}")),
        (caveat, note) => caveat.or(note),
    }
}

/// Identifies a file on disk by its contents.
pub fn identify_file(path: &Path) -> io::Result<Identified> {
    identify::identify(&mut Source::open(path)?)
}

/// Whether a file listed on disk is an archive. Only the contents count;
/// the extension decides whether to look in large folders.
pub(super) fn is_archive_on_disk(path: &Path, many: bool) -> bool {
    let hinted = || {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("zip") || ext.eq_ignore_ascii_case("rpf"))
    };
    (!many || hinted())
        && identify_file(path).is_ok_and(|identified| matches!(identified, Identified::Archive(_)))
}

pub(super) fn too_many_to_identify(count: usize) -> bool {
    count > MAX_IDENTIFIED
}

/// What the start of a file in an archive tells about it, without
/// decompressing all of it.
pub fn sniff(archive: &Archive, inner: &Path) -> io::Result<Identified> {
    let len = file_len(archive, inner)?;
    let mut head = Head(Vec::with_capacity(HEAD_LEN));
    match copy(archive, inner, &mut head, MAX_READ) {
        Ok(_) => {}
        Err(err) if err.get_ref().is_some_and(|inner| inner.is::<HeadFull>()) => {}
        Err(err) => return Err(err),
    }
    Ok(identify::sniff(&head.0, len))
}

/// Classifies a file in an archive from a bounded head of its decoded bytes.
/// `entry_type` is the native row type when the entry has one, and never
/// decides the format on its own.
pub fn classify(
    archive: &Archive,
    inner: &Path,
    entry_type: Option<u8>,
) -> io::Result<Classification> {
    let mut head = Head(Vec::with_capacity(HEAD_LEN));
    match copy(archive, inner, &mut head, MAX_READ) {
        Ok(_) => {}
        Err(err) if err.get_ref().is_some_and(|inner| inner.is::<HeadFull>()) => {}
        Err(err) => return Err(err),
    }
    Ok(classify_head(&head.0, entry_type, inner.extension()))
}

/// The first `limit` decoded bytes of a file in an archive, for callers that
/// inspect a head larger than [`HEAD_LEN`], such as the text check.
pub fn read_head(archive: &Archive, inner: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut head = Bounded {
        bytes: Vec::with_capacity(usize::try_from(limit.min(64 * 1024)).unwrap_or(0)),
        limit,
    };
    match copy(archive, inner, &mut head, MAX_READ) {
        Ok(_) => {}
        Err(err) if err.get_ref().is_some_and(|inner| inner.is::<HeadFull>()) => {}
        Err(err) => return Err(err),
    }
    Ok(head.bytes)
}

/// [`classify`] for the first bytes of a file, wherever they were read.
pub fn classify_head(
    head: &[u8],
    entry_type: Option<u8>,
    extension: Option<&std::ffi::OsStr>,
) -> Classification {
    let extension = extension
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase());
    classify::classify(classify::Inputs {
        entry_type,
        original_extension: extension.as_deref(),
        storage: None,
        payload: classify::PayloadState::Decoded,
        head: Some(head),
    })
}

#[derive(Debug)]
struct HeadFull;

impl fmt::Display for HeadFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("enough bytes were read")
    }
}

impl std::error::Error for HeadFull {}

/// Collects the first [`HEAD_LEN`] bytes, then stops the copy.
struct Head(Vec<u8>);
impl Write for Head {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let room = HEAD_LEN - self.0.len();
        if room == 0 {
            return Err(io::Error::other(HeadFull));
        }
        let n = buf.len().min(room);
        self.0.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Collects at most `limit` bytes, then stops the copy the same way.
struct Bounded {
    bytes: Vec<u8>,
    limit: u64,
}

impl Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let room = self.limit - self.bytes.len() as u64;
        if room == 0 {
            return Err(io::Error::other(HeadFull));
        }
        let n = buf.len().min(usize::try_from(room).unwrap_or(usize::MAX));
        self.bytes.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for Cancelled {}

/// Stops writing once `cancel` is set.
struct Cancellable<'a, W> {
    out: W,
    cancel: &'a AtomicBool,
}

impl<W: Write> Write for Cancellable<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Not `Interrupted`, which `io::copy` and `write_all` retry forever.
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::other(Cancelled));
        }
        self.out.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Counts the bytes passed through to `out`.
struct Counting<'a> {
    out: &'a mut dyn Write,
    written: u64,
}

impl Write for Counting<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

pub fn check_size(size: u64, limit: u64) -> io::Result<()> {
    if size > limit {
        return Err(io::Error::other(format!(
            "the file is too large to read from the archive (limit {})",
            format_size(limit)
        )));
    }
    Ok(())
}

/// Opens a file of `parent` that is an archive itself and keeps it.
fn decompress(parent: &Archive, inner: &Path, cancel: &AtomicBool) -> io::Result<()> {
    decompress_limited(parent, inner, cancel, MAX_READ, MAX_CHAIN)
}

/// `read_limit` caps the size of the nested archive, also when it is a view,
/// because opening it scans its contents like those of a copy. `chain_limit`
/// caps the bytes decompressed along the chain, which a view adds nothing to.
fn decompress_limited(
    parent: &Archive,
    inner: &Path,
    cancel: &AtomicBool,
    read_limit: u64,
    chain_limit: u64,
) -> io::Result<()> {
    let path = parent.path.join(inner);
    if parent.depth >= MAX_DEPTH {
        return Err(io::Error::other(format!(
            "{} is nested too deeply: at most {MAX_DEPTH} archives inside each other can be opened",
            file_name(&path)
        )));
    }
    let mut dependencies = parent.dependencies.clone();
    if parent.format == Format::Rpf9 {
        dependencies.extend(rpf::dependencies(parent, inner)?);
    }
    if let Some(source) = stored_view(parent, inner, read_limit, cancel)? {
        return keep_identified(parent, inner, path, source, 0, dependencies);
    }
    let len = file_len(parent, inner)?;
    check_size(len, read_limit)?;
    let room = chain_limit.saturating_sub(parent.decompressed);
    if len > room {
        return Err(io::Error::other(format!(
            "{} cannot be opened: together with the archives it is stored in, it would \
             decompress to more than {}",
            file_name(&path),
            format_size(chain_limit)
        )));
    }
    let mut temp = tempfile::tempfile()?;
    {
        let mut out = Cancellable {
            out: BufWriter::new(&mut temp),
            cancel,
        };
        // The declared size may be wrong, so the copy is capped as well.
        copy_cancellable(parent, inner, &mut out, len.min(read_limit), cancel)
            .and_then(|_| out.flush())
            .map_err(
                |err| match err.get_ref().is_some_and(|e| e.is::<Cancelled>()) {
                    true => io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
                    false => err,
                },
            )?;
    }
    let source = Source::from_file(temp)?;
    let decompressed = source.len();
    keep_identified(parent, inner, path, source, decompressed, dependencies)
}

/// A file of `parent` stored as it is, as a view of the parent's source,
/// within `read_limit`. ZIP files are checked against their CRC-32 first;
/// RPF9 records no checksum. Other files have to be decoded, which a view
/// must not stand in for.
fn stored_view(
    parent: &Archive,
    inner: &Path,
    read_limit: u64,
    cancel: &AtomicBool,
) -> io::Result<Option<Source>> {
    match parent.format {
        Format::Zip => {
            let Some(stored) = zip::stored_file(parent, inner)? else {
                return Ok(None);
            };
            check_size(stored.source.len(), read_limit)?;
            stored.verify(cancel).map(Some)
        }
        Format::Rpf9 => {
            let Some(source) = rpf::raw_source(parent, inner)? else {
                return Ok(None);
            };
            check_size(source.len(), read_limit)?;
            Ok(Some(source))
        }
    }
}

fn keep_identified(
    parent: &Archive,
    inner: &Path,
    path: PathBuf,
    mut source: Source,
    decompressed: u64,
    dependencies: Vec<Dependency>,
) -> io::Result<()> {
    let format = match identify::identify(&mut source)? {
        Identified::Archive(format) => format,
        other => return Err(not_an_archive(&path, &other)),
    };
    let caveat = match parent.format {
        Format::Rpf9 => rpf::caveat(parent, inner),
        Format::Zip => None,
    };
    keep(
        path,
        Kept {
            stamp: parent.stamp,
            format,
            source,
            decompressed,
            caveat,
            dependencies,
            last_used: 0,
        },
    );
    Ok(())
}

struct Kept {
    /// Of the file on disk the chain starts at.
    stamp: Stamp,
    format: Format,
    source: Source,
    /// The size of the temporary file holding the archive, 0 for a view of
    /// its parent.
    decompressed: u64,
    caveat: Option<String>,
    /// Of the archive and the archives it is stored in.
    dependencies: Vec<Dependency>,
    last_used: u64,
}

impl Kept {
    /// Whether this was opened from `parent` as it is now: the file on disk
    /// and every further file the bytes come from are unchanged.
    fn is_current(&self, parent: &Archive) -> bool {
        self.stamp == parent.stamp && dependencies_current(&self.dependencies)
    }
}

#[derive(Default)]
struct KeptArchives {
    clock: u64,
    by_path: HashMap<PathBuf, Kept>,
}

static KEPT: LazyLock<Mutex<KeptArchives>> = LazyLock::new(Default::default);

fn kept_archives() -> MutexGuard<'static, KeptArchives> {
    KEPT.lock().unwrap_or_else(|err| err.into_inner())
}

impl KeptArchives {
    /// Keeps `archive`, then drops the least recently used other archives
    /// until at most `max_count` remain and their temporary files take at
    /// most `max_bytes`. The new archive itself is never dropped.
    fn insert(&mut self, path: PathBuf, mut archive: Kept, max_bytes: u64, max_count: usize) {
        self.clock += 1;
        archive.last_used = self.clock;
        self.by_path.insert(path.clone(), archive);
        loop {
            let total: u64 = self.by_path.values().map(|kept| kept.decompressed).sum();
            if total <= max_bytes && self.by_path.len() <= max_count {
                break;
            }
            let Some(oldest) = self
                .by_path
                .iter()
                .filter(|(other, _)| **other != path)
                .min_by_key(|(_, kept)| kept.last_used)
                .map(|(path, _)| path.clone())
            else {
                break;
            };
            self.by_path.remove(&oldest);
        }
    }
}

fn keep(path: PathBuf, archive: Kept) {
    kept_archives().insert(path, archive, MAX_KEPT, MAX_KEPT_COUNT);
}

/// Drops the kept archive at `path`, as eviction would.
#[cfg(test)]
pub(crate) fn forget_kept(path: &Path) {
    kept_archives().by_path.remove(path);
}

/// The canonical identity of the nested archive at `inner`, for the path of
/// the archive opened from it.
fn nested_entry_id(parent: &Archive, inner: &Path) -> Option<EntryId> {
    let entry = match parent.format {
        Format::Zip => zip::entry_id(parent, inner),
        Format::Rpf9 => rpf::entry_id(parent, inner),
    }?;
    Some(entry)
}

/// The kept archive at `inner` in `parent`, if it was opened from the same
/// file on disk and the files it depends on are unchanged.
fn kept(parent: &Archive, inner: &Path) -> Option<Archive> {
    let path = parent.path.join(inner);
    let mut kept = kept_archives();
    kept.clock += 1;
    let now = kept.clock;
    let entry = kept.by_path.get_mut(&path)?;
    if !entry.is_current(parent) {
        kept.by_path.remove(&path);
        return None;
    }
    entry.last_used = now;
    let resource = match nested_entry_id(parent, inner) {
        Some(entry) => parent.resource.push(entry),
        None => parent.resource.clone(),
    };
    Some(Archive {
        path,
        format: entry.format,
        source: entry.source.clone(),
        root: parent.root.clone(),
        stamp: parent.stamp,
        depth: parent.depth + 1,
        decompressed: parent.decompressed.saturating_add(entry.decompressed),
        caveat: entry.caveat.clone(),
        dependencies: entry.dependencies.clone(),
        access: parent.access.clone(),
        resource,
    })
}

fn open_nested(parent: &Archive, inner: &Path) -> io::Result<Archive> {
    kept(parent, inner).ok_or_else(|| needs_prepare(parent.path.join(inner)))
}

/// Reads a whole archive into memory.
pub fn read_all(archive: &Archive) -> io::Result<Vec<u8>> {
    if archive.depth == 1 {
        check_size(fs::metadata(&archive.path)?.len(), MAX_MATERIALIZE)?;
        return fs::read(&archive.path);
    }
    check_size(archive.source.len(), MAX_MATERIALIZE)?;
    let mut source = archive.source.clone();
    source.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    io::copy(&mut source, &mut bytes)?;
    Ok(bytes)
}

/// Streams the decoded contents of the file at `path` into `out`, opening the
/// archives it is stored in first and revalidating their sources. Stops with
/// [`io::ErrorKind::Interrupted`] once `cancel` is set. Returns the number of
/// bytes written.
///
/// Reuses the readers [`copy`] uses, so native table-of-contents entries,
/// scan-recovered entries, resource pages and regions, and ZIP entries are all
/// decoded through their existing paths, honouring companion read sources and
/// the read limit. Only the file at `path` is read; no unrelated entry is
/// decoded.
/// [`export_to_with`] without an executable.
#[cfg(test)]
pub fn export_to(path: &Path, out: &mut dyn Write, cancel: &AtomicBool) -> io::Result<u64> {
    export_to_with(path, &Access::none(), out, cancel)
}

/// [`export_to`] with the executable that may authenticate the stored table of
/// contents the file is listed from.
pub fn export_to_with(
    path: &Path,
    access: &Access,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> io::Result<u64> {
    export_to_within(path, access, out, MAX_READ, cancel)
}

fn export_to_within(
    path: &Path,
    access: &Access,
    out: &mut dyn Write,
    limit: u64,
    cancel: &AtomicBool,
) -> io::Result<u64> {
    for _ in 0..MAX_ATTEMPTS {
        let location = match locate_with(path, access) {
            Ok(location) => location,
            Err(err) => match prepare_required(&err) {
                Some(archive) => {
                    let archive = archive.to_path_buf();
                    prepare_with(
                        &archive,
                        access,
                        true,
                        &Stage::default(),
                        &Progress::default(),
                        cancel,
                    )?;
                    continue;
                }
                None => return Err(err),
            },
        };
        let mut counting = Counting { out, written: 0 };
        match location {
            Location::Inside(archive, inner) => {
                copy_cancellable(&archive, &inner, &mut counting, limit, cancel)?;
            }
            // A file that is itself an archive: its own bytes, not its contents.
            Location::Archive(archive) => {
                check_size(archive.source.len(), limit)?;
                let mut source = archive.source.clone();
                source.seek(SeekFrom::Start(0))?;
                copy_reader(&mut source, &mut counting, cancel)?;
            }
            Location::Plain => {
                let mut file = File::open(path)?;
                copy_reader(&mut file, &mut counting, cancel)?;
            }
        }
        return Ok(counting.written);
    }
    Err(io::Error::other("the archive could not be opened"))
}

/// Copies all of `reader` into `out`, stopping with
/// [`io::ErrorKind::Interrupted`] once `cancel` is set.
fn copy_reader(
    reader: &mut dyn io::Read,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> io::Result<()> {
    let mut sink = Cancellable { out, cancel };
    match io::copy(reader, &mut sink) {
        Ok(_) => Ok(()),
        Err(err) if err.get_ref().is_some_and(|e| e.is::<Cancelled>()) => {
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::files;
    use crate::files::rpf::tests::{rpf_bytes, zlib};
    use crate::files::zip::tests::{zip_bytes, zip_bytes_with};
    use ::zip::CompressionMethod;

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn open(path: &Path) {
        prepare(path, &Progress::default(), &AtomicBool::new(false)).unwrap();
    }

    /// Lists `path`, opening the archives it needs first, as the explorer does.
    /// What was opened may be evicted before the listing, so it is opened
    /// again then.
    fn list_opened(path: &Path) -> Vec<Entry> {
        for _ in 0..MAX_ATTEMPTS {
            match files::list(path) {
                Err(err) if prepare_required(&err).is_some() => open(path),
                result => return result.unwrap(),
            }
        }
        panic!("{} could not be listed", path.display());
    }

    fn identified(path: &Path) -> Identified {
        files::identify(path).unwrap()
    }

    /// The offset-named path of the single recovered entry of an RPF9
    /// archive written by [`rpf_bytes`] with one part.
    fn recovered(archive: &Path, folder: &str, extension: &str) -> PathBuf {
        archive
            .join(rpf::RECOVERED)
            .join(folder)
            .join(format!("0x{:010X}.{extension}", 0x100))
    }

    #[test]
    fn archives_are_recognised_by_contents_not_extension() {
        let temp = tempfile::tempdir().unwrap();
        let rpf = rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")]);
        let zip = zip_bytes(&[("inside.txt", b"hi")]);
        let cases: [(&str, &[u8], Identified); 7] = [
            ("a.rpf", &rpf, Identified::Archive(Format::Rpf9)),
            ("a.bin", &rpf, Identified::Archive(Format::Rpf9)),
            ("b.zip", &zip, Identified::Archive(Format::Zip)),
            ("b.dat", &zip, Identified::Archive(Format::Zip)),
            ("zip.rpf", &zip, Identified::Archive(Format::Zip)),
            ("rpf.zip", &rpf, Identified::Archive(Format::Rpf9)),
            ("plain.bin", b"just some bytes", Identified::Unknown),
        ];
        for (name, bytes, expected) in &cases {
            let path = temp.path().join(name);
            fs::write(&path, bytes).unwrap();
            assert_eq!(&identified(&path), expected, "{name}");
        }

        let mut entries = files::list(temp.path()).unwrap();
        files::sort_entries(&mut entries, files::Sort::default());
        for entry in &entries {
            let archive = entry.name != "plain.bin";
            assert_eq!(entry.kind == EntryKind::Archive, archive, "{}", entry.name);
        }

        // Each opens with the reader of its actual format.
        assert_eq!(
            names(&list_opened(&temp.path().join("zip.rpf"))),
            ["inside.txt"]
        );
        assert_eq!(
            names(&list_opened(&temp.path().join("rpf.zip"))),
            [rpf::RECOVERED]
        );
        let err = files::list(&temp.path().join("plain.bin")).unwrap_err();
        assert!(err.to_string().contains("not an archive"), "{err}");
    }

    #[test]
    fn broken_archives_report_why_instead_of_listing_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let zip = zip_bytes(&[("a.txt", &[1; 3000])]);
        let truncated = temp.path().join("truncated.bin");
        fs::write(&truncated, &zip[..zip.len() / 2]).unwrap();
        let header = temp.path().join("header.rpf");
        fs::write(&header, b"9FPR\x00\x10\x00\x00").unwrap();
        for path in [&truncated, &header] {
            assert!(matches!(identified(path), Identified::Invalid { .. }));
            let err = files::list(path).unwrap_err();
            assert!(err.to_string().contains("is not a valid"), "{err}");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            // The bytes can still be inspected.
            assert!(files::open_binary(path).is_ok());
        }
    }

    /// Writes `formats[0]` to disk. Each archive holds the next one, and
    /// the innermost holds an XML file. Returns the path of each archive and
    /// of the XML file.
    fn write_chain(dir: &Path, formats: &[Format], leaf: &[u8]) -> Vec<PathBuf> {
        let child_name = |i: usize| match i + 1 == formats.len() {
            true => "leaf.xml".to_string(),
            false => format!("level{}.bin", i + 1),
        };
        let mut bytes = leaf.to_vec();
        for (i, format) in formats.iter().enumerate().rev() {
            bytes = match format {
                Format::Zip => zip_bytes(&[(&child_name(i), &bytes), ("other.txt", b"x")]),
                Format::Rpf9 => rpf_bytes(&[zlib(&bytes)]),
            };
        }
        let outer = dir.join("outer.dat");
        fs::write(&outer, bytes).unwrap();
        let mut paths = vec![outer];
        for (i, format) in formats.iter().enumerate() {
            let next = match format {
                Format::Zip => paths[i].join(child_name(i)),
                Format::Rpf9 if i + 1 == formats.len() => recovered(&paths[i], "XML", "xml"),
                // Archives are not a kind the scan recognises.
                Format::Rpf9 => recovered(&paths[i], "Unidentified", "bin"),
            };
            paths.push(next);
        }
        paths
    }

    fn check_chain(formats: &[Format]) {
        let temp = tempfile::tempdir().unwrap();
        let leaf = b"<?xml version=\"1.0\"?><leaf/>";
        let paths = write_chain(temp.path(), formats, leaf);

        for (depth, path) in paths[..formats.len()].iter().enumerate() {
            let context = format!("{formats:?} level {depth}");
            assert_eq!(
                identified(path),
                Identified::Archive(formats[depth]),
                "{context}"
            );
            assert!(!list_opened(path).is_empty(), "{context}");
            if depth > 0 {
                // Once opened, the archive is listed as one in its folder.
                let folder = files::list(path.parent().unwrap()).unwrap();
                let listed = folder.iter().find(|entry| &entry.path == path).unwrap();
                assert_eq!(listed.kind, EntryKind::Archive, "{context}");
                assert!(listed.is_container());
            }
        }
        let leaf_path = paths.last().unwrap();
        assert_eq!(files::read(leaf_path).unwrap(), leaf);
        assert_eq!(identified(leaf_path), Identified::Unknown);

        // The inspector gets the bytes of each nested archive, not its parent's.
        for (depth, path) in paths[..formats.len()].iter().enumerate() {
            let mut inspected = files::open_binary(path).unwrap();
            let head = lforge_binary::read_at(&mut inspected.source, 0, HEAD_LEN).unwrap();
            assert_eq!(identify::signature(&head), Some(formats[depth]));
            assert_eq!(
                inspected.source.len(),
                files::read(path).unwrap().len() as u64
            );
        }
    }

    #[test]
    fn opens_archives_nested_in_any_combination() {
        use Format::{Rpf9, Zip};
        for chain in [
            &[Zip, Zip][..],
            &[Rpf9, Zip],
            &[Zip, Rpf9],
            &[Rpf9, Rpf9],
            &[Rpf9, Zip, Rpf9, Zip],
            &[Zip, Rpf9, Zip, Rpf9],
        ] {
            check_chain(chain);
        }
    }

    fn nested(path: &Path) -> Archive {
        list_opened(path);
        match locate(path).unwrap() {
            Location::Archive(archive) => archive,
            other => panic!("expected an opened archive, got {other:?}"),
        }
    }

    #[test]
    fn stored_archives_are_views_and_compressed_ones_are_decoded() {
        let temp = tempfile::tempdir().unwrap();
        let inner_zip = zip_bytes(&[("leaf.txt", b"leaf")]);
        let inner_rpf = rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")]);
        let files: [(&str, &[u8]); 2] = [("inner.zip", &inner_zip), ("inner.rpf", &inner_rpf)];
        let stored = temp.path().join("stored.zip");
        fs::write(&stored, zip_bytes_with(&files, CompressionMethod::Stored)).unwrap();
        let deflated = temp.path().join("deflated.zip");
        fs::write(&deflated, zip_bytes(&files)).unwrap();

        for (outer, viewed) in [(&stored, true), (&deflated, false)] {
            for (name, bytes) in files {
                let path = outer.join(name);
                let archive = nested(&path);
                let expected = if viewed { 0 } else { bytes.len() as u64 };
                assert_eq!(archive.decompressed, expected, "{}", path.display());
                assert_eq!(archive.source.len(), bytes.len() as u64);
                assert_eq!(files::read(&path).unwrap(), bytes);
                let mut inspected = files::open_binary(&path).unwrap();
                assert_eq!(
                    lforge_binary::read_at(&mut inspected.source, 0, bytes.len()).unwrap(),
                    bytes
                );
            }
            assert_eq!(
                files::read(&outer.join("inner.zip").join("leaf.txt")).unwrap(),
                b"leaf"
            );
            assert_eq!(
                names(&list_opened(&outer.join("inner.rpf"))),
                [rpf::RECOVERED]
            );
        }

        // A view is dropped like a decompressed archive when the file changes.
        fs::write(
            &stored,
            zip_bytes_with(
                &[("inner.zip", &inner_zip), ("new.txt", b"n")],
                CompressionMethod::Stored,
            ),
        )
        .unwrap();
        let path = stored.join("inner.zip");
        assert_eq!(
            prepare_required(&files::list(&path).unwrap_err()),
            Some(path.as_path())
        );
        assert_eq!(names(&list_opened(&path)), ["leaf.txt"]);
    }

    /// An outer archive that stores `inner.zip` uncompressed, last.
    fn stored_outer(dir: &Path, edit: impl FnOnce(&mut Vec<u8>, &[u8])) -> PathBuf {
        let inner = zip_bytes(&[("leaf.txt", b"leaf contents")]);
        let mut bytes = zip_bytes_with(
            &[("first.txt", b"x"), ("inner.zip", &inner)],
            CompressionMethod::Stored,
        );
        edit(&mut bytes, &inner);
        let outer = dir.join("outer.zip");
        fs::write(&outer, bytes).unwrap();
        outer
    }

    /// Adds `delta` to both sizes in the central header of `name`.
    fn grow_declared_size(bytes: &mut [u8], name: &str, delta: u32) {
        let at = (0..bytes.len() - 46)
            .find(|&i| {
                let name_len = u16::from_le_bytes([bytes[i + 28], bytes[i + 29]]) as usize;
                bytes[i..].starts_with(b"PK")
                    && bytes.get(i + 46..i + 46 + name_len) == Some(name.as_bytes())
            })
            .unwrap();
        for field in [at + 20, at + 24] {
            let size = u32::from_le_bytes(bytes[field..field + 4].try_into().unwrap());
            bytes[field..field + 4].copy_from_slice(&(size + delta).to_le_bytes());
        }
    }

    fn assert_not_opened(path: &Path, cancel: bool) -> io::Error {
        let err = prepare(path, &Progress::default(), &AtomicBool::new(cancel)).unwrap_err();
        assert!(prepare_required(&files::list(path).unwrap_err()).is_some());
        err
    }

    #[test]
    fn stored_archives_must_match_their_crc() {
        let temp = tempfile::tempdir().unwrap();
        let outer = stored_outer(temp.path(), |bytes, inner| {
            // A byte in the middle of the stored inner archive.
            let at = bytes.windows(inner.len()).position(|w| w == inner).unwrap();
            bytes[at + inner.len() / 2] ^= 0x55;
        });
        let err = assert_not_opened(&outer.join("inner.zip"), false);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("CRC-32"), "{err}");
        // The file can still be inspected as bytes.
        assert!(files::open_binary(&outer.join("first.txt")).is_ok());
    }

    #[test]
    fn stored_archives_with_wrong_sizes_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        // The declared size runs into the central directory.
        let dir = temp.path().join("into_directory");
        fs::create_dir(&dir).unwrap();
        let outer = stored_outer(&dir, |bytes, _| grow_declared_size(bytes, "inner.zip", 16));
        let err = assert_not_opened(&outer.join("inner.zip"), false);
        assert!(err.to_string().contains("CRC-32"), "{err}");
        // The declared size runs past the end of the file.
        let dir = temp.path().join("past_end");
        fs::create_dir(&dir).unwrap();
        let outer = stored_outer(&dir, |bytes, _| {
            grow_declared_size(bytes, "inner.zip", 0x100_0000);
        });
        assert_not_opened(&outer.join("inner.zip"), false);
    }

    #[test]
    fn verifying_a_stored_archive_can_be_cancelled() {
        let temp = tempfile::tempdir().unwrap();
        let outer = stored_outer(temp.path(), |_, _| {});
        let err = assert_not_opened(&outer.join("inner.zip"), true);
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(!list_opened(&outer.join("inner.zip")).is_empty());
    }

    #[test]
    fn views_are_capped_in_size_but_decompress_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let outer = stored_outer(temp.path(), |_, _| {});
        let Location::Inside(parent, name) = locate(&outer.join("inner.zip")).unwrap() else {
            panic!("expected a file inside the archive");
        };
        let cancel = AtomicBool::new(false);
        let len = file_len(&parent, &name).unwrap();
        let err = decompress_limited(&parent, &name, &cancel, len - 1, MAX_CHAIN).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        assert!(prepare_required(&files::list(&outer.join("inner.zip")).unwrap_err()).is_some());
        // No decompression budget is needed for a view.
        decompress_limited(&parent, &name, &cancel, len, 0).unwrap();
        let Location::Archive(nested) = locate(&outer.join("inner.zip")).unwrap() else {
            panic!("expected the kept archive");
        };
        assert_eq!((nested.decompressed, nested.source.len()), (0, len));
    }

    #[test]
    fn stored_archives_nest_as_views_of_views() {
        let temp = tempfile::tempdir().unwrap();
        let leaf = b"<?xml version=\"1.0\"?><leaf/>";
        let rpf = rpf_bytes(&[zlib(leaf)]);
        let middle = zip_bytes_with(
            &[("pad.txt", b"padding"), ("inner.rpf", &rpf)],
            CompressionMethod::Stored,
        );
        let outer = temp.path().join("outer.zip");
        fs::write(
            &outer,
            zip_bytes_with(
                &[("first.txt", b"x"), ("middle.zip", &middle)],
                CompressionMethod::Stored,
            ),
        )
        .unwrap();

        let middle_path = outer.join("middle.zip");
        let rpf_path = middle_path.join("inner.rpf");
        let middle_archive = nested(&middle_path);
        let rpf_archive = nested(&rpf_path);
        assert_eq!((middle_archive.depth, middle_archive.decompressed), (2, 0));
        assert_eq!((rpf_archive.depth, rpf_archive.decompressed), (3, 0));
        let mut head = rpf_archive.source.clone();
        assert_eq!(
            lforge_binary::read_at(&mut head, 0, rpf.len()).unwrap(),
            rpf
        );
        assert_eq!(
            files::read(&recovered(&rpf_path, "XML", "xml")).unwrap(),
            leaf
        );
    }

    #[test]
    fn a_changed_outer_archive_drops_what_was_opened_from_it() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().join("outer.zip");
        let inner_rpf = |text: &[u8]| rpf_bytes(&[zlib(text)]);
        fs::write(
            &outer,
            zip_bytes(&[("inner.bin", &inner_rpf(b"<?xml?><a/>"))]),
        )
        .unwrap();
        let nested = outer.join("inner.bin");
        assert!(list_opened(&nested).len() == 1);
        assert_eq!(files::list(&outer).unwrap()[0].kind, EntryKind::Archive);

        let changed = inner_rpf(b"plain text that is long enough to differ");
        fs::write(
            &outer,
            zip_bytes(&[("inner.bin", &changed), ("new.txt", b"n")]),
        )
        .unwrap();
        let err = files::list(&nested).unwrap_err();
        assert_eq!(prepare_required(&err), Some(nested.as_path()));
        let reopened = list_opened(&nested.join(rpf::RECOVERED));
        assert_eq!(names(&reopened), ["Text"]);
    }

    #[test]
    fn nested_archives_with_the_same_name_are_kept_apart() {
        let temp = tempfile::tempdir().unwrap();
        let outer = temp.path().join("outer.zip");
        let xml = rpf_bytes(&[zlib(b"<?xml version=\"1.0\"?><a/>")]);
        let text = rpf_bytes(&[zlib(b"some readable text in here")]);
        fs::write(
            &outer,
            zip_bytes(&[("a/same.bin", &xml), ("b/same.bin", &text)]),
        )
        .unwrap();
        let a = list_opened(&outer.join("a").join("same.bin").join(rpf::RECOVERED));
        let b = list_opened(&outer.join("b").join("same.bin").join(rpf::RECOVERED));
        assert_eq!(names(&a), ["XML"]);
        assert_eq!(names(&b), ["Text"]);
    }

    #[test]
    fn nesting_is_limited_in_depth() {
        let temp = tempfile::tempdir().unwrap();
        let mut bytes = zip_bytes(&[("leaf.txt", b"x")]);
        for _ in 0..MAX_DEPTH {
            bytes = zip_bytes(&[("n.zip", &bytes)]);
        }
        let mut path = temp.path().join("deep.zip");
        fs::write(&path, bytes).unwrap();
        for _ in 1..MAX_DEPTH {
            path = path.join("n.zip");
            assert_eq!(names(&list_opened(&path)), ["n.zip"]);
        }
        let too_deep = path.join("n.zip");
        let err = prepare(&too_deep, &Progress::default(), &AtomicBool::new(false)).unwrap_err();
        assert!(err.to_string().contains("nested too deeply"), "{err}");
        // Its bytes can still be inspected.
        assert!(files::open_binary(&too_deep).is_ok());
    }

    #[test]
    fn decompression_is_limited_across_the_chain() {
        let temp = tempfile::tempdir().unwrap();
        let inner = zip_bytes(&[("zeros.bin", &[0; 10_000])]);
        let outer = temp.path().join("outer.zip");
        fs::write(&outer, zip_bytes(&[("inner.zip", &inner)])).unwrap();
        let Location::Inside(parent, name) = locate(&outer.join("inner.zip")).unwrap() else {
            panic!("expected a file inside the archive");
        };
        let cancel = AtomicBool::new(false);
        let len = inner.len() as u64;
        let err = decompress_limited(&parent, &name, &cancel, MAX_READ, len - 1).unwrap_err();
        assert!(err.to_string().contains("decompress to more than"), "{err}");
        decompress_limited(&parent, &name, &cancel, MAX_READ, len).unwrap();
        let Location::Archive(nested) = locate(&outer.join("inner.zip")).unwrap() else {
            panic!("expected the kept archive");
        };
        assert_eq!(nested.depth, 2);
        assert_eq!(nested.decompressed, len);
    }

    #[test]
    fn corrupt_nested_archives_and_cancellation_fail_cleanly() {
        let temp = tempfile::tempdir().unwrap();
        let mut broken = zip_bytes(&[("a.txt", &[5; 4000])]);
        broken.truncate(broken.len() - 30);
        let noise: Vec<u8> = (0..400_000u32).map(|i| (i * 7919 % 251) as u8).collect();
        let big = zip_bytes(&[("noise.bin", &noise)]);
        let outer = temp.path().join("outer.zip");
        fs::write(
            &outer,
            zip_bytes(&[("broken.bin", &broken), ("big.zip", &big)]),
        )
        .unwrap();

        let broken = outer.join("broken.bin");
        assert!(matches!(
            identified(&broken),
            Identified::Archive(Format::Zip)
        ));
        let err = prepare(&broken, &Progress::default(), &AtomicBool::new(false)).unwrap_err();
        assert!(
            err.to_string().contains("is not a valid ZIP archive"),
            "{err}"
        );

        let big = outer.join("big.zip");
        let err = prepare(&big, &Progress::default(), &AtomicBool::new(true)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        assert!(prepare_required(&files::list(&big).unwrap_err()).is_some());
    }

    fn kept_entry(decompressed: u64) -> Kept {
        Kept {
            stamp: (0, None),
            format: Format::Zip,
            source: Source::from_file(tempfile::tempfile().unwrap()).unwrap(),
            decompressed,
            caveat: None,
            dependencies: Vec::new(),
            last_used: 0,
        }
    }

    fn kept_paths(kept: &KeptArchives) -> Vec<String> {
        let mut paths: Vec<String> = kept
            .by_path
            .keys()
            .map(|path| path.display().to_string())
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn kept_archives_drop_the_least_recently_used() {
        let mut kept = KeptArchives::default();
        for name in ["a", "b", "c"] {
            kept.insert(PathBuf::from(name), kept_entry(0), u64::MAX, 2);
        }
        assert_eq!(kept_paths(&kept), ["b", "c"]);
        // Using an archive makes it recent, as `kept` does.
        kept.clock += 1;
        kept.by_path.get_mut(Path::new("b")).unwrap().last_used = kept.clock;
        kept.insert(PathBuf::from("d"), kept_entry(0), u64::MAX, 2);
        assert_eq!(kept_paths(&kept), ["b", "d"]);
        // A replaced archive is not counted twice.
        kept.insert(PathBuf::from("d"), kept_entry(0), u64::MAX, 2);
        assert_eq!(kept_paths(&kept), ["b", "d"]);
    }

    #[test]
    fn export_to_enforces_the_read_limit() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("data.rpf");
        let xml = b"<?xml version=\"1.0\"?><root-with-enough-bytes/>";
        fs::write(&archive, rpf_bytes(&[zlib(xml)])).unwrap();
        open(&archive);
        let entry = archive
            .join(rpf::RECOVERED)
            .join("XML")
            .join(format!("0x{:010X}.xml", 0x100));
        let cancel = AtomicBool::new(false);
        let mut out = Vec::new();
        let err = export_to_within(
            &entry,
            &Access::none(),
            &mut out,
            (xml.len() - 1) as u64,
            &cancel,
        )
        .unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        out.clear();
        let written =
            export_to_within(&entry, &Access::none(), &mut out, xml.len() as u64, &cancel).unwrap();
        assert_eq!(written, xml.len() as u64);
        assert_eq!(out, xml);
    }

    #[test]
    fn export_to_copies_a_plain_file() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("plain.bin");
        fs::write(&file, b"plain bytes on disk").unwrap();
        let mut out = Vec::new();
        let written = export_to(&file, &mut out, &AtomicBool::new(false)).unwrap();
        assert_eq!(written, 19);
        assert_eq!(out, b"plain bytes on disk");
    }

    #[test]
    fn kept_archives_are_limited_by_size() {
        let mut kept = KeptArchives::default();
        kept.insert(PathBuf::from("view"), kept_entry(0), 100, 10);
        kept.insert(PathBuf::from("a"), kept_entry(60), 100, 10);
        kept.insert(PathBuf::from("b"), kept_entry(30), 100, 10);
        assert_eq!(kept_paths(&kept), ["a", "b", "view"]);
        kept.insert(PathBuf::from("c"), kept_entry(30), 100, 10);
        // The oldest go first, the view too, until the temporary files fit.
        assert_eq!(kept_paths(&kept), ["b", "c"]);
        // An archive larger than the limit is kept alone.
        kept.insert(PathBuf::from("huge"), kept_entry(500), 100, 10);
        assert_eq!(kept_paths(&kept), ["huge"]);
    }
}
