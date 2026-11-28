//! Shared helpers for the archive commands that read the native table of
//! contents directly, rather than the scan-recovered index.
//!
//! Companion resolution reuses the rage9 primitives the desktop uses, without
//! a dependency on desktop UI code: [`Metadata::companions`] parses `B`
//! sub-block 3 and [`Companions::open`] opens each record in the archive's
//! directory with its path-traversal, symlink and header checks.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::Source;
use lforge_binary::pe::ExecutableView;
use lforge_rage9::rpf;
use lforge_rage9::rpf::metadata::provider::RecognizedSource;
use lforge_rage9::rpf::metadata::transform::Algorithm;
use lforge_rage9::rpf::metadata::verify::{
    OpenReport, VerifyOutcome, VerifyReport, open_authenticated,
};
use lforge_rage9::rpf::metadata::{
    Companion, CompanionStatus, Entry, Error, Metadata, Payload, Stored,
};
use lforge_rage9::rpf::names::{Builtin, Lut, StringTable};

/// How the native table of contents was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// The archive has no processing pass, so its stored metadata is the
    /// table the engine reads.
    NotApplicable,
    /// The signature verified and steps 4 and 5 decoded the metadata.
    Authenticated(VerifyReport),
}

impl Authentication {
    pub fn status(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Authenticated(_) => "authenticated",
        }
    }

    pub fn report(&self) -> Option<&VerifyReport> {
        match self {
            Self::NotApplicable => None,
            Self::Authenticated(report) => Some(report),
        }
    }
}

/// An opened archive and the native table of contents the engine would read.
pub struct Opened {
    pub source: Source,
    pub metadata: Metadata,
    pub authentication: Authentication,
    /// Present when the executable authenticated the metadata; it can build
    /// payload-transform blocks.
    pub stream: Option<lforge_rage9::rpf::metadata::provider::RecognizedSource>,
}

/// One name table that was read, and what became of it.
#[derive(Debug, Clone)]
pub struct NameTableSource {
    pub path: PathBuf,
    pub kind: &'static str,
    pub namespace: Option<&'static str>,
    pub entries: usize,
    pub verified: usize,
    pub added: usize,
}

/// The local name tables of one archive and the built-in ones. A local table
/// is an explicit `--name-file`, or `<archive>.names.txt` next to the archive
/// when none is given.
#[derive(Debug, Clone)]
pub struct NameTables {
    /// Local entries first, then the built-in ones.
    pub table: StringTable,
    /// Entries `table` holds from the local files.
    pub local: usize,
    pub sources: Vec<NameTableSource>,
    pub sidecar: bool,
    pub builtin: Builtin,
}

fn sidecar_path(archive: &Path) -> PathBuf {
    let mut name = archive.file_name().unwrap_or_default().to_os_string();
    name.push(".names.txt");
    archive.with_file_name(name)
}

fn is_lut(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8_lossy(bytes)
        .trim_start()
        .starts_with("# leonida-forge-lut:")
}

fn read_bounded(path: &Path) -> Result<(Vec<u8>, bool), String> {
    let limit =
        lforge_rage9::rpf::names::table::MAX_BYTES.max(lforge_rage9::rpf::names::lut::MAX_BYTES);
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let truncated = bytes.len() as u64 > limit;
    if truncated {
        bytes.truncate(limit as usize);
    }
    Ok((bytes, truncated))
}

/// Reads the local tables, then merges the built-in LUTs. The table next to
/// an archive is a `.names.txt` candidate table; a LUT there is refused.
pub fn load_name_tables(archive: &Path, files: &[PathBuf]) -> Result<NameTables, String> {
    let (paths, sidecar) = if files.is_empty() {
        let path = sidecar_path(archive);
        if path.is_file() {
            (vec![path], true)
        } else {
            (Vec::new(), false)
        }
    } else {
        (files.to_vec(), false)
    };
    let mut table = StringTable::default();
    let mut sources = Vec::new();
    for path in paths {
        let (bytes, truncated) = read_bounded(&path)?;
        if is_lut(&bytes) {
            if sidecar {
                return Err(format!(
                    "{} is a LUT; a LUT is only read from the built-in tables and from beside \
                     the executable, and the table next to an archive is a .names.txt name table",
                    path.display()
                ));
            }
            if truncated {
                return Err(format!(
                    "{} is larger than the LUT size limit",
                    path.display()
                ));
            }
            let lut = Lut::parse(&bytes).map_err(|err| format!("{}: {err}", path.display()))?;
            let entries = lut.entries().len();
            let verified = lut.verified();
            let namespace = Some(lut.namespace().namespace());
            let added = table.merge_lut(&lut);
            sources.push(NameTableSource {
                path,
                kind: "lut",
                namespace,
                entries,
                verified,
                added,
            });
        } else {
            let part = StringTable::parse(&bytes, truncated);
            let entries = part.entries().len();
            let added = table.merge(part);
            sources.push(NameTableSource {
                path,
                kind: "names_txt",
                namespace: None,
                entries,
                verified: 0,
                added,
            });
        }
    }
    let local = table.entries().len();
    let builtin = Builtin::beside_executable();
    table.merge(builtin.table().clone());
    Ok(NameTables {
        table,
        local,
        sources,
        sidecar,
        builtin,
    })
}

/// How an entry's contents can be read: one of the readability states. This
/// reports storage and the framing that was validated, not a decode that was
/// not attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentsState {
    /// `None` when the storage is supported but decoding was not attempted.
    /// `true` for `stored` (the stored bytes are the contents) and for
    /// `validated` (the chunk table and its sizes fit the entry; no chunk was
    /// decoded).
    pub readable: Option<bool>,
    /// `stored`, `validated`, `transform_available`, `transform_key_missing`,
    /// `unsupported_transform`, `unsupported_compression`,
    /// `alternate_source` or `malformed`.
    pub state: &'static str,
    pub reason: Option<String>,
}

/// Computes the readability state of `entry` against its read sources.
pub fn contents_state(
    entry: &Entry,
    source: &Source,
    alternates: &[Option<Source>],
    stream: Option<&RecognizedSource>,
) -> ContentsState {
    let state =
        |readable: Option<bool>, state: &'static str, reason: Option<String>| ContentsState {
            readable,
            state,
            reason,
        };
    // A field that did not parse takes precedence: nothing downstream is trustworthy.
    let malformed = [
        entry.location.as_ref().err(),
        entry.chunks.as_ref().err(),
        entry.payload_transform.as_ref().err(),
        entry.read_source.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .next();
    if let Some(reason) = malformed {
        return state(Some(false), "malformed", Some(reason.clone()));
    }
    match entry.payload(source, alternates) {
        Ok(_) if entry.raw_source(source, alternates).is_ok() => state(Some(true), "stored", None),
        // The payload was opened and its chunk table validated, but no chunk
        // was decoded. Reporting `decoded` here promised more than this call
        // established; a corrupt zlib stream still fails extraction.
        Ok(_) => state(Some(true), "validated", None),
        Err(Error::Encoded { .. }) if matches!(entry.payload_transform, Ok(true)) => {
            transform_state(entry, stream)
        }
        Err(Error::Encoded { encoding, .. }) => state(
            Some(false),
            "unsupported_transform",
            Some(format!("stored {encoding}")),
        ),
        Err(Error::Undecodable { reason, .. }) => {
            state(Some(false), "unsupported_compression", Some(reason))
        }
        Err(Error::ReadSource { index, .. }) => state(
            Some(false),
            "alternate_source",
            Some(format!("alternate read source {index} is not available")),
        ),
        Err(err) => state(Some(false), "malformed", Some(err.to_string())),
    }
}

/// The transform's storage is supported when the algorithm is known and the
/// executable has a key state for the descriptor. Decoding is not attempted
/// here, so `readable` is `None` rather than `true`.
fn transform_state(entry: &Entry, stream: Option<&RecognizedSource>) -> ContentsState {
    let cipher = match &entry.payload_cipher {
        Ok(Some(cipher)) => cipher,
        Ok(None) => {
            return ContentsState {
                readable: Some(false),
                state: "unsupported_transform",
                reason: Some("the transform has no cipher descriptor".to_string()),
            };
        }
        Err(reason) => {
            return ContentsState {
                readable: Some(false),
                state: "unsupported_transform",
                reason: Some(format!("malformed cipher descriptor: {reason}")),
            };
        }
    };
    match Algorithm::of(cipher.kind) {
        Ok(Algorithm::Untraced(0x11)) => {}
        Ok(_) => {
            return ContentsState {
                readable: Some(false),
                state: "unsupported_transform",
                reason: Some(format!(
                    "cipher type {:#x} selects an algorithm this build does not decode",
                    cipher.kind
                )),
            };
        }
        Err(reason) => {
            return ContentsState {
                readable: Some(false),
                state: "unsupported_transform",
                reason: Some(reason.to_string()),
            };
        }
    }
    let Some(stream) = stream else {
        return ContentsState {
            readable: Some(false),
            state: "transform_key_missing",
            reason: Some(
                "stored behind the payload transform; no executable key state is available"
                    .to_string(),
            ),
        };
    };
    if stream.stream_blocks(cipher.key_id).is_empty() {
        return ContentsState {
            readable: Some(false),
            state: "transform_key_missing",
            reason: Some(
                "stored behind the payload transform; the executable has no key state for this key identifier"
                    .to_string(),
            ),
        };
    }
    ContentsState {
        readable: None,
        state: "transform_available",
        reason: Some(
            "stored behind the payload transform; the executable key state is available and decoding was not attempted"
                .to_string(),
        ),
    }
}

/// Builds the streaming payload of a row behind the payload transform. The
/// transform is verified against the first zlib chunk from a bounded prefix;
/// the returned payload transforms and decompresses on read.
pub fn transformed_payload(
    entry: &Entry,
    source: &Source,
    alternates: &Alternates,
    stream: &lforge_rage9::rpf::metadata::provider::RecognizedSource,
) -> Result<Payload, String> {
    let transform = stream
        .stream_transform(entry, source, alternates.sources())
        .map_err(|err| format!("row {}: {err}", entry.row))?;
    entry
        .transformed_payload(source, alternates.sources(), transform)
        .map_err(|err| format!("row {}: {err}", entry.row))
}

/// Whether the entry's stored bytes can be read as they are, and why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawState {
    Available { size: u64 },
    Unavailable { reason: String },
}

/// Bytes copied per read while spooling a nested archive.
const COPY_BUFFER: usize = 1024 * 1024;
/// A chunk stored with this method is a zlib stream, so the entry is not
/// contiguous.
const ZLIB_METHOD: u8 = 3;
/// The largest metadata area a nested archive read may take.
const MAX_METADATA: u64 = 256 * 1024 * 1024;

/// What a walk may spend on nested archives.
#[derive(Debug, Clone, Copy)]
pub struct NestedLimits {
    /// The largest archive one row may store.
    pub max_nested_bytes: u64,
    /// The most spooled bytes one run may borrow.
    pub max_spool_bytes: u64,
    /// The bytes this run has spooled so far.
    pub spooled: u64,
}

/// Why an entry that should hold an archive could not be opened as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedError {
    /// The row could not be read as an archive. The message names the row.
    Failed(String),
    /// Opening it needs more temporary storage than the run may use.
    SpoolBudget { size: u64 },
}

impl std::fmt::Display for NestedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NestedError::Failed(reason) => f.write_str(reason),
            NestedError::SpoolBudget { size } => write!(
                f,
                "opening this archive needs {size} more spooled bytes than the run may use"
            ),
        }
    }
}

/// The archive-relative range of an entry whose chunks are all copies, so its
/// bytes can be read where they lie. `None` when any chunk is compressed,
/// padded or shorter than it is stored, and for storage that is not a sequence
/// of chunks.
pub fn contiguous(entry: &Entry) -> Option<(u64, u64)> {
    if matches!(entry.payload_transform, Ok(true)) {
        return None;
    }
    let location = match &entry.location {
        Ok(Some(location)) => *location,
        _ => return None,
    };
    if location.mode != 0 {
        return None;
    }
    let table = match &entry.chunks {
        Ok(Some(table)) => table,
        _ => return None,
    };
    let mut stored = 0u64;
    let mut logical = 0u64;
    for chunk in &table.chunks {
        if chunk.method == ZLIB_METHOD
            || chunk.padding != 0
            || chunk.stored_len != chunk.logical_len
        {
            return None;
        }
        stored = stored.checked_add(u64::from(chunk.stored_len))?;
        logical = logical.checked_add(u64::from(chunk.logical_len))?;
    }
    if logical != location.logical_len {
        return None;
    }
    // Encoding 2 always starts its chunks after a 16-byte prefix. Encoding 4
    // stores the same prefix for resource-page payloads and none otherwise, so
    // the prefix length depends on the entry's stored size.
    let prefix = table.stored_prefix(location.stored_len).ok()?;
    Some((location.payload_offset.checked_add(prefix)?, stored))
}

/// Opens the archive `entry` holds, in place when its bytes are stored as they
/// are and through temporary storage otherwise. Returns the spooled bytes it
/// borrowed, so a caller can account for the run's budget.
pub fn open_nested(
    entry: &Entry,
    opened: &Opened,
    alternates: &[Option<Source>],
    name: &str,
    limits: NestedLimits,
    executable: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<(Opened, u64), NestedError> {
    let failed = NestedError::Failed;
    let in_place = contiguous(entry);
    let mut spooled = 0u64;
    let source = match in_place {
        Some((offset, len)) => opened
            .source
            .slice(offset, len)
            .map_err(|err| failed(format!("row {}: {err}", entry.row)))?,
        None => match entry.raw_source(&opened.source, alternates) {
            Ok(source) => source,
            Err(_) => {
                let mut payload = entry
                    .payload(&opened.source, alternates)
                    .map_err(|err| failed(format!("row {}: {err}", entry.row)))?;
                let size = payload.len();
                if size > limits.max_nested_bytes {
                    return Err(failed(format!(
                        "row {} stores an archive of {size} bytes, over the nested-archive limit",
                        entry.row
                    )));
                }
                if limits.spooled.saturating_add(size) > limits.max_spool_bytes {
                    return Err(NestedError::SpoolBudget { size });
                }
                spooled = size;
                spool(&mut payload, entry.row, cancel, size).map_err(failed)?
            }
        },
    };
    let nested =
        open_metadata_at(source, name, MAX_METADATA, executable, cancel).map_err(failed)?;
    Ok((nested, spooled))
}

/// Copies a decoded payload into temporary storage and opens a source over it.
fn spool(
    payload: &mut Payload,
    row: u32,
    cancel: &AtomicBool,
    size: u64,
) -> Result<Source, String> {
    use std::io::Write;

    let mut file = tempfile::tempfile()
        .map_err(|err| format!("row {row}: cannot create temporary storage: {err}"))?;
    let mut buffer = vec![0u8; COPY_BUFFER];
    let mut copied = 0u64;
    loop {
        let read = payload
            .read_cancellable(&mut buffer, cancel)
            .map_err(|err| format!("row {row}: {err}"))?;
        if read == 0 {
            break;
        }
        file.write_all(&buffer[..read])
            .map_err(|err| format!("row {row}: cannot write temporary storage: {err}"))?;
        copied += read as u64;
    }
    if copied != size {
        return Err(format!(
            "row {row}: the payload is {copied} bytes, not the {size} the table declares"
        ));
    }
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|err| format!("row {row}: {err}"))?;
    Source::from_file(file).map_err(|err| format!("row {row}: {err}"))
}

pub fn raw_state(entry: &Entry, source: &Source, alternates: &[Option<Source>]) -> RawState {
    match entry.raw_source(source, alternates) {
        Ok(view) => RawState::Available { size: view.len() },
        Err(Error::Encoded { encoding, .. }) => RawState::Unavailable {
            reason: format!("stored {encoding}"),
        },
        Err(Error::ReadSource { index, .. }) => RawState::Unavailable {
            reason: format!("alternate read source {index} is not available"),
        },
        Err(err) => RawState::Unavailable {
            reason: err.to_string(),
        },
    }
}

/// Archive discovery limits for directory searches.
#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_archives: usize,
}

/// Every `.rpf` file under `root`, sorted, with whether a limit cut the walk
/// short. A file root is returned as it is. Symbolic links are skipped.
pub fn collect_archives(
    root: &Path,
    limits: ScanLimits,
    cancel: &AtomicBool,
) -> Result<(Vec<PathBuf>, bool), String> {
    if root.is_file() {
        return Ok((vec![root.to_path_buf()], false));
    }
    let mut files = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut truncated = false;
    while let Some((directory, depth)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        if depth > limits.max_depth {
            truncated = true;
            continue;
        }
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        let mut children: Vec<_> = entries.filter_map(Result::ok).collect();
        children.sort_by_key(|entry| entry.path());
        for entry in children {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                stack.push((path, depth + 1));
            } else if file_type.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("rpf"))
            {
                files.push(path);
                if files.len() >= limits.max_archives {
                    truncated = true;
                    break;
                }
            }
        }
        if files.len() >= limits.max_archives {
            break;
        }
    }
    files.sort();
    Ok((files, truncated))
}

/// Opens `path`, reads the RPF9 header and decodes the native table of
/// contents.
///
/// Unprocessed metadata is decoded directly. Encrypted metadata requires an
/// `executable` and is used only after the signature verifies. Malformed or
/// oversized metadata is rejected. `limit` caps the metadata area read into
/// memory.
pub fn open_metadata(path: &Path, limit: u64, executable: Option<&Path>) -> Result<Opened, String> {
    open_metadata_cancellable(path, limit, executable, &AtomicBool::new(false))
}

/// [`open_metadata`] with a cancellation flag. Cancellation is checked before
/// expensive reads and passed to the authentication path.
pub fn open_metadata_cancellable(
    path: &Path,
    limit: u64,
    executable: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<Opened, String> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("cancelled".to_string());
    }
    let source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    open_metadata_at(
        source,
        &path.display().to_string(),
        limit,
        executable,
        cancel,
    )
}

/// [`open_metadata_cancellable`] for a source that is already open, so an
/// archive stored inside another one is read where it lies instead of being
/// copied. `label` names the source in failures.
pub fn open_metadata_at(
    source: Source,
    label: &str,
    limit: u64,
    executable: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<Opened, String> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("cancelled".to_string());
    }
    let mut source = source;
    rpf::read_header(&mut source).map_err(|err| format!("{label}: {err}"))?;
    // The header, and at most the A table, decide whether the stored bytes can
    // be used before all of them are read.
    let probe = Stored::probe(&mut source.clone()).map_err(|err| format!("{label}: {err}"))?;
    if probe.processing.is_none() {
        let metadata = Stored::read(&mut source.clone(), limit)
            .and_then(Stored::decode)
            .map_err(|err| format!("{label}: {err}"))?;
        return Ok(Opened {
            source,
            metadata,
            authentication: Authentication::NotApplicable,
            stream: None,
        });
    }
    let Some(executable) = executable else {
        let reason = probe
            .unsupported()
            .unwrap_or_else(|| "the metadata is processed".to_string());
        return Err(format!(
            "the table of contents of {label} is not read: it is processed and requires --executable: {reason}"
        ));
    };
    let view = ExecutableView::open(executable)
        .map_err(|err| format!("cannot open {}: {err}", executable.display()))?;
    let open: OpenReport = open_authenticated(&mut source.clone(), &view, cancel)
        .map_err(|err| format!("{label}: {err}"))?;
    let report = open.report;
    let Some(authenticated) = open.authenticated else {
        return Err(format!(
            "the table of contents of {label} is not authenticated: {} (stage {})",
            report.outcome, report.stage
        ));
    };
    if report.outcome != VerifyOutcome::MetadataDecodedAuthenticated {
        return Err(format!(
            "the table of contents of {label} is not authenticated: {} (stage {})",
            report.outcome, report.stage
        ));
    }
    Ok(Opened {
        source,
        metadata: authenticated.into_metadata(),
        authentication: Authentication::Authenticated(report),
        stream: open.source,
    })
}

/// The alternate read sources of an archive, resolved from `B` sub-block 3.
/// One entry per companion record, in record order; `None` where the companion
/// is not available, so an entry read through it is refused rather than read
/// from the main archive.
pub struct Alternates {
    pub records: Vec<Companion>,
    pub statuses: Vec<CompanionStatus>,
    sources: Vec<Option<Source>>,
    /// Why sub-block 3 could not be read, if it is malformed.
    pub problem: Option<String>,
}

impl Alternates {
    /// Resolves the companions of `archive`, a file on disk, against its own
    /// directory. The archive is never opened as a companion source.
    pub fn resolve(archive: &Path, metadata: &Metadata) -> Self {
        let list = match metadata.companions() {
            Ok(list) => list,
            Err(err) => {
                return Self {
                    records: Vec::new(),
                    statuses: Vec::new(),
                    sources: Vec::new(),
                    problem: Some(err.to_string()),
                };
            }
        };
        let statuses = list.open(archive);
        let sources = statuses
            .iter()
            .map(|status| status.source().cloned())
            .collect();
        Self {
            records: list.records,
            statuses,
            sources,
            problem: None,
        }
    }

    pub fn sources(&self) -> &[Option<Source>] {
        &self.sources
    }
}
