//! `lforge archive inventory`: a bounded, deterministic inventory of every
//! entry a supported archive exposes, optionally descending into archives
//! stored inside it.
//!
//! The inventory reuses the same readers as the rest of the CLI: the
//! authenticated RPF9 table of contents through [`crate::rows::Listing`], the
//! lossless ZIP central directory in [`lforge_core::zip`], and content
//! recognition from [`lforge_core::archive`] and [`lforge_core::inspect`].
//! Nothing is recognised from a file name: recursion happens only when the
//! decoded payload is a valid archive of a supported format.
//!
//! Two distinctions the research workflow depends on are kept explicit. A
//! payload that cannot be decoded is reported with the stage that stopped it
//! (compression, transform, source, authentication, limit), never as an
//! unknown format. A manifest whose traversal was cut short says so in its
//! summary and is never presented as complete.
//!
//! Records stream: JSONL writes a header, one record per entry and a final
//! summary; JSON writes one document whose entry array is filled as the walk
//! proceeds. Nothing accumulates beyond the counters and the open archives.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{self, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::Source;
use lforge_core::archive::{self, Format, Identified};
use lforge_core::inspect as recognition;
use lforge_core::zip as zip_archive;
use lforge_rage9::rpf::metadata::Payload;
use lforge_rage9::rpf::names::Key;
use serde_json::{Value, json};

use crate::native;
use crate::nested::Selector;
use crate::rows::{self, Listing};

/// The schema of every document and record this command writes.
pub const SCHEMA: &str = "leonida-forge.archive-inventory/1";

/// As in the other archive commands.
const MAX_METADATA: u64 = 256 * 1024 * 1024;
/// Bytes copied per step while decoding.
const COPY_LEN: usize = 64 * 1024;
/// Bytes read for signature recognition before a full decode.
const RECOGNITION_BYTES: usize = archive::HEAD_LEN;
/// Caps the entries one archive may expose. The inventory's own entry limit is
/// a traversal-wide limit and must not make an archive unopenable.
const MAX_ARCHIVE_ENTRIES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Jsonl,
}

impl OutputFormat {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "json" => Ok(OutputFormat::Json),
            "jsonl" => Ok(OutputFormat::Jsonl),
            other => Err(format!(
                "'{other}' is not an output format; use json or jsonl"
            )),
        }
    }
}

/// Caps one inventory. Every counter describes the whole traversal, not one
/// branch, so no combination of branches can exceed them.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Archives in a chain, counting the root.
    pub max_depth: usize,
    /// Archives opened, roots included.
    pub max_archives: u64,
    /// Entries recorded, all archives included.
    pub max_entries: u64,
    /// Largest payload decoded into temporary storage.
    pub max_entry_bytes: u64,
    /// Total payload bytes decoded into temporary storage.
    pub max_decoded_bytes: u64,
    /// Temporary storage held by the archives on the current chain.
    pub max_temp_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_archives: 64,
            max_entries: 1 << 20,
            max_entry_bytes: 512 * 1024 * 1024,
            max_decoded_bytes: 8 * 1024 * 1024 * 1024,
            max_temp_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Narrows what is written. Traversal is not pruned: a filter decides which
/// entry records are emitted, so a skipped archive still explains itself.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    pub content_format: Option<String>,
    pub type_id: Option<u8>,
    pub name: Option<String>,
    pub hash: Option<Key>,
    pub readable: Option<bool>,
    pub failure_stage: Option<String>,
    pub depth: Option<usize>,
}

impl Filters {
    fn matches(&self, record: &EntryRecord) -> bool {
        if let Some(format) = &self.content_format
            && !record
                .content
                .format_id
                .as_deref()
                .is_some_and(|id| id.eq_ignore_ascii_case(format))
        {
            return false;
        }
        if let Some(type_id) = self.type_id
            && record.entry.type_id != Some(type_id)
        {
            return false;
        }
        if let Some(name) = &self.name {
            let needle = name.to_ascii_lowercase();
            let found = record
                .entry
                .resolved_name
                .as_deref()
                .into_iter()
                .chain(record.entry.name.as_deref())
                .any(|candidate| candidate.to_ascii_lowercase().contains(&needle));
            if !found {
                return false;
            }
        }
        if let Some(hash) = self.hash {
            let matches = match hash {
                Key::Hash64(value) => record.entry.hash64 == Some(value),
                Key::Key32(value) => record.entry.key32 == Some(value),
            };
            if !matches {
                return false;
            }
        }
        if let Some(readable) = self.readable
            && record.payload.readable != readable
        {
            return false;
        }
        if let Some(stage) = &self.failure_stage {
            let found = record
                .content
                .failure_stage
                .or_else(|| record.skipped.as_ref().map(|skip| skip.stage));
            if !found.is_some_and(|found| found.eq_ignore_ascii_case(stage)) {
                return false;
            }
        }
        if let Some(depth) = self.depth
            && record.path.len() != depth
        {
            return false;
        }
        true
    }
}

pub struct Options {
    pub path: PathBuf,
    pub executable: Option<PathBuf>,
    pub candidates: Vec<PathBuf>,
    pub recursive: bool,
    pub format: OutputFormat,
    pub output: Option<PathBuf>,
    pub overwrite: bool,
    pub limits: Limits,
    pub filters: Filters,
}

/// How a traversal ended. Only `Complete` and `CompleteWithSkips` describe a
/// traversal that reached every entry the limits allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Complete,
    CompleteWithSkips,
    Truncated,
    Cancelled,
    Failed,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Status::Complete => "complete",
            Status::CompleteWithSkips => "complete_with_skips",
            Status::Truncated => "truncated",
            Status::Cancelled => "cancelled",
            Status::Failed => "failed",
        }
    }

    fn is_complete(self) -> bool {
        matches!(self, Status::Complete | Status::CompleteWithSkips)
    }
}

#[derive(Debug, Clone)]
struct SkipInfo {
    stage: &'static str,
    reason: String,
}

#[derive(Debug, Clone)]
struct PayloadInfo {
    readable: bool,
    status: &'static str,
    reason: Option<String>,
}

impl PayloadInfo {
    fn new(readable: bool, status: &'static str, reason: Option<String>) -> Self {
        Self {
            readable,
            status,
            reason,
        }
    }
}

#[derive(Debug, Clone)]
struct ContentInfo {
    status: &'static str,
    format: Option<Value>,
    format_id: Option<String>,
    /// The format if the payload is a valid archive that may be entered.
    archive_format: Option<Format>,
    failure_stage: Option<&'static str>,
    failure: Option<String>,
    display_extension: Option<Value>,
}

impl ContentInfo {
    fn not_inspected() -> Self {
        Self {
            status: "not_inspected",
            format: None,
            format_id: None,
            archive_format: None,
            failure_stage: None,
            failure: None,
            display_extension: None,
        }
    }

    fn stopped(stage: &'static str, reason: impl Into<String>) -> Self {
        let mut content = Self::not_inspected();
        content.failure_stage = Some(stage);
        content.failure = Some(reason.into());
        content
    }
}

#[derive(Debug, Clone)]
struct EntryInfo {
    selector: Selector,
    kind: &'static str,
    name: Option<String>,
    resolved_name: Option<String>,
    name_status: &'static str,
    namespace: Option<String>,
    hash64: Option<u64>,
    key32: Option<u32>,
    type_id: Option<u8>,
    extension: Option<String>,
    extension_synthetic: bool,
    stored_size: Option<u64>,
    logical_size: Option<u64>,
    is_directory: bool,
    encoding: Value,
}

#[derive(Debug, Clone)]
struct EntryRecord {
    root: String,
    path: Vec<Selector>,
    archive_format: Format,
    archive_entries: usize,
    zip64: bool,
    duplicate_names: usize,
    entry: EntryInfo,
    payload: PayloadInfo,
    content: ContentInfo,
    skipped: Option<SkipInfo>,
    authentication: Value,
}

impl EntryRecord {
    /// A command that reproduces this entry with the existing selectors. The
    /// root is a placeholder: an inventory never needs the absolute path the
    /// caller used.
    fn reproduce(&self) -> String {
        let mut command = String::from("lforge archive inspect ROOT");
        for selector in &self.path {
            command.push_str(&format!(" --enter {}", selector.label()));
        }
        match self.entry.selector {
            Selector::Row(_) => {
                command.push_str(&format!(" --row {}", self.entry.selector.selector_index()))
            }
            Selector::Zip(_) => {
                command.push_str(&format!(" --zip {}", self.entry.selector.selector_index()))
            }
        }
        command
    }

    fn json(&self) -> Value {
        let selector_path: Vec<String> = self.path.iter().map(Selector::label).collect();
        let mut value = json!({
            "schema": SCHEMA,
            "kind": "entry",
            "root": self.root,
            "depth": self.path.len(),
            "archive": {
                "format": self.archive_format.name(),
                "format_id": self.archive_format.name().to_lowercase(),
                "entries": self.archive_entries,
                "zip64": self.zip64,
                "duplicate_names": self.duplicate_names,
            },
            "selector_path": selector_path,
            "selector": self.entry.selector.label(),
            "selector_kind": self.entry.selector.selector_kind(),
            "selector_index": self.entry.selector.selector_index(),
            "entry": {
                "kind": self.entry.kind,
                "name": self.entry.name,
                "resolved_name": self.entry.resolved_name,
                "name_status": self.entry.name_status,
                "namespace": self.entry.namespace,
                "hash64": self.entry.hash64.map(|hash| format!("0x{hash:016X}")),
                "key32": self.entry.key32.map(|key| format!("0x{key:08X}")),
                "type_id": self.entry.type_id,
                "extension": self.entry.extension,
                "extension_synthetic": self.entry.extension_synthetic,
                "stored_size": self.entry.stored_size,
                "logical_size": self.entry.logical_size,
                "is_directory": self.entry.is_directory,
                "encoding": self.entry.encoding,
            },
            "payload": {
                "readable": self.payload.readable,
                "status": self.payload.status,
                "reason": self.payload.reason,
            },
            "content": {
                "status": self.content.status,
                "format": self.content.format,
                "failure_stage": self.content.failure_stage,
                "failure": self.content.failure,
                "display_extension": self.content.display_extension,
            },
            "archive_authentication": self.authentication,
            "reproduce": self.reproduce(),
        });
        if let Some(skip) = &self.skipped {
            value["skipped"] = json!({ "stage": skip.stage, "reason": skip.reason });
        }
        value
    }
}

/// One top-level archive the caller named or the directory scan found.
#[derive(Debug, Clone)]
struct Root {
    path: PathBuf,
    /// A display name with no absolute directory, so a shared manifest does
    /// not leak the local layout.
    name: String,
}

#[derive(Default)]
struct Stats {
    by_archive_format: BTreeMap<String, u64>,
    by_depth: BTreeMap<String, u64>,
    by_type_id: BTreeMap<String, u64>,
    by_name_status: BTreeMap<String, u64>,
    by_content_format: BTreeMap<String, u64>,
    by_payload_status: BTreeMap<String, u64>,
    by_failure_stage: BTreeMap<String, u64>,
    unique_hashes: HashSet<(String, u64)>,
    unique_names: HashSet<String>,
}

impl Stats {
    fn count(map: &mut BTreeMap<String, u64>, key: impl Into<String>) {
        *map.entry(key.into()).or_insert(0) += 1;
    }
}

struct Outcome {
    status: Status,
    error: Option<String>,
}

pub fn run(options: Options) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    let (roots, discovery_truncated) = discover(&options.path, &options.limits, &cancel)?;
    let mut outcome = None;
    match &options.output {
        Some(path) => {
            crate::output::write_file(path, options.overwrite, |writer| {
                outcome = Some(run_stream(
                    &options,
                    &roots,
                    discovery_truncated,
                    &cancel,
                    writer,
                )?);
                Ok(0u64)
            })?;
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            outcome = Some(run_stream(
                &options,
                &roots,
                discovery_truncated,
                &cancel,
                &mut lock,
            )?);
        }
    }
    match outcome {
        Some(outcome) if outcome.status.is_complete() => Ok(()),
        Some(outcome) => Err(outcome.error.unwrap_or_else(|| {
            format!(
                "the inventory is {}; see the summary record",
                outcome.status.name()
            )
        })),
        None => Err("the inventory produced no summary".to_string()),
    }
}

/// Discovers the roots and reports whether a limit cut the directory walk.
fn discover(
    root: &Path,
    limits: &Limits,
    cancel: &AtomicBool,
) -> Result<(Vec<Root>, bool), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".to_string());
    }
    if root.is_file() {
        return Ok((
            vec![Root {
                name: display_name(root),
                path: root.to_path_buf(),
            }],
            false,
        ));
    }
    if !root.is_dir() {
        return Err(format!("{} is not a file or a directory", root.display()));
    }
    let mut files = Vec::new();
    let mut truncated = false;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    'walk: while let Some((directory, depth)) = stack.pop() {
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
        for child in children {
            let Ok(file_type) = child.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = child.path();
            if file_type.is_dir() {
                stack.push((path, depth + 1));
            } else if file_type.is_file() && has_archive_extension(&path) {
                files.push(path);
                if files.len() as u64 >= limits.max_archives {
                    truncated = true;
                    break 'walk;
                }
            }
        }
    }
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "no .rpf or .zip archives were found under {}",
            root.display()
        ));
    }
    let roots = files
        .into_iter()
        .map(|path| Root {
            name: relative_name(root, &path),
            path,
        })
        .collect();
    Ok((roots, truncated))
}

fn has_archive_extension(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("rpf") || extension.eq_ignore_ascii_case("zip")
    })
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn relative_name(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let parts: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.is_empty() {
        display_name(path)
    } else {
        parts.join("/")
    }
}

fn run_stream(
    options: &Options,
    roots: &[Root],
    discovery_truncated: bool,
    cancel: &AtomicBool,
    writer: &mut dyn Write,
) -> Result<Outcome, String> {
    let mut emitter = Emitter::new(options.format, writer);
    emitter.header(&header_json(options, roots, discovery_truncated))?;
    let mut engine = Engine::new(options, cancel);
    if discovery_truncated {
        engine.truncate("max_archives");
    }
    for root in roots {
        if matches!(engine.status, Status::Truncated | Status::Cancelled) {
            break;
        }
        if engine.archives >= engine.limits.max_archives {
            engine.truncate("max_archives");
            break;
        }
        engine.enter_root(root, &mut emitter)?;
    }
    if engine.archives == 0 && matches!(engine.status, Status::Complete | Status::CompleteWithSkips)
    {
        engine.status = Status::Failed;
        engine.error = Some("no archive could be opened".to_string());
    }
    let summary = engine.summary(roots.len(), discovery_truncated);
    emitter.finish(&summary)?;
    Ok(Outcome {
        status: engine.status,
        error: engine.error.clone(),
    })
}

fn header_json(options: &Options, roots: &[Root], discovery_truncated: bool) -> Value {
    json!({
        "schema": SCHEMA,
        "kind": "header",
        "tool": { "name": "lforge", "version": env!("CARGO_PKG_VERSION") },
        "roots": roots.iter().map(|root| json!({
            "name": root.name,
            "size": fs::metadata(&root.path).map(|meta| meta.len()).ok(),
        })).collect::<Vec<Value>>(),
        "root_selection": "a directory is searched for .rpf and .zip files; recursion inside an archive is content-based",
        "options": {
            "recursive": options.recursive,
            "format": match options.format { OutputFormat::Json => "json", OutputFormat::Jsonl => "jsonl" },
            "max_depth": options.limits.max_depth,
            "max_archives": options.limits.max_archives,
            "max_entries": options.limits.max_entries,
            "max_entry_bytes": options.limits.max_entry_bytes,
            "max_decoded_bytes": options.limits.max_decoded_bytes,
            "max_temp_bytes": options.limits.max_temp_bytes,
        },
        "filters": {
            "content_format": options.filters.content_format,
            "type_id": options.filters.type_id,
            "name": options.filters.name,
            "hash": options.filters.hash.map(|key| match key {
                Key::Hash64(value) => format!("0x{value:016X}"),
                Key::Key32(value) => format!("0x{value:08X}"),
            }),
            "readable": options.filters.readable,
            "failure_stage": options.filters.failure_stage,
            "depth": options.filters.depth,
        },
        "reconstruction": {
            "placeholder": "ROOT",
            "template": "lforge archive inspect ROOT [--enter SEL]... (--row N | --zip N)",
            "note": "each entry record carries the selector chain and a reproduce string; the root name is relative to the caller's root",
        },
        "path_sanitized": true,
        "discovery_truncated": discovery_truncated,
    })
}

struct Engine<'a> {
    executable: Option<&'a Path>,
    candidates: &'a [PathBuf],
    recursive: bool,
    limits: Limits,
    filters: Filters,
    cancel: &'a AtomicBool,
    status: Status,
    error: Option<String>,
    archives: u64,
    entries_discovered: u64,
    entries_emitted: u64,
    skipped: u64,
    decoded: u64,
    live_temp: u64,
    limits_hit: BTreeSet<&'static str>,
    stats: Stats,
}

impl<'a> Engine<'a> {
    fn new(options: &'a Options, cancel: &'a AtomicBool) -> Self {
        Self {
            executable: options.executable.as_deref(),
            candidates: &options.candidates,
            recursive: options.recursive,
            limits: options.limits,
            filters: options.filters.clone(),
            cancel,
            status: Status::Complete,
            error: None,
            archives: 0,
            entries_discovered: 0,
            entries_emitted: 0,
            skipped: 0,
            decoded: 0,
            live_temp: 0,
            limits_hit: BTreeSet::new(),
            stats: Stats::default(),
        }
    }

    fn truncate(&mut self, limit: &'static str) {
        self.limits_hit.insert(limit);
        self.status = Status::Truncated;
    }

    fn note_skip(&mut self) {
        if self.status == Status::Complete {
            self.status = Status::CompleteWithSkips;
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn note_skipped(&mut self, record: &mut EntryRecord, skip: SkipInfo) {
        record.skipped = Some(skip);
        self.note_skip();
        self.skipped += 1;
    }

    /// Charges `bytes` to the cumulative decode budget.
    fn charge_decoded(&mut self, bytes: u64) -> bool {
        let Some(total) = self.decoded.checked_add(bytes) else {
            return false;
        };
        if total > self.limits.max_decoded_bytes {
            return false;
        }
        self.decoded = total;
        true
    }

    fn enter_root(&mut self, root: &Root, emitter: &mut Emitter<'_>) -> Result<(), String> {
        let format = match identify_path(&root.path) {
            Ok(format) => format,
            Err((stage, reason)) => {
                emitter.record(&json!({
                    "schema": SCHEMA,
                    "kind": "error",
                    "root": root.name,
                    "stage": stage,
                    "error": reason,
                }))?;
                self.note_skip();
                self.skipped += 1;
                return Ok(());
            }
        };
        self.start(
            root.path.clone(),
            root.name.clone(),
            format,
            None,
            &[],
            emitter,
        )
    }

    /// Opens `path`, emits its archive record and walks its entries.
    fn start(
        &mut self,
        path: PathBuf,
        root: String,
        format: Format,
        temp: Option<tempfile::TempPath>,
        chain: &[Selector],
        emitter: &mut Emitter<'_>,
    ) -> Result<(), String> {
        if self.cancelled() {
            self.status = Status::Cancelled;
            drop(temp);
            return Ok(());
        }
        if self.archives >= self.limits.max_archives {
            self.truncate("max_archives");
            drop(temp);
            return Ok(());
        }
        let mut open = match self.open_archive(&path, format, temp) {
            Ok(open) => open,
            Err(skip) => {
                emitter.record(&json!({
                    "schema": SCHEMA,
                    "kind": "error",
                    "root": root,
                    "selector_path": chain.iter().map(Selector::label).collect::<Vec<_>>(),
                    "format": format.name(),
                    "stage": skip.stage,
                    "error": skip.reason,
                }))?;
                self.note_skip();
                self.skipped += 1;
                return Ok(());
            }
        };
        self.archives += 1;
        Stats::count(&mut self.stats.by_archive_format, format.name());
        emitter.record(&open.archive_json(&root, chain))?;
        open.walk(self, &root, chain, emitter)
    }

    fn open_archive(
        &mut self,
        path: &Path,
        format: Format,
        temp: Option<tempfile::TempPath>,
    ) -> Result<Open, SkipInfo> {
        match format {
            Format::Rpf9 => {
                let listing = Listing::open(path, self.executable, self.candidates, self.cancel)
                    .map_err(|reason| SkipInfo {
                        stage: if reason.contains("authenticat") || reason.contains("--executable")
                        {
                            "authentication"
                        } else {
                            "structure"
                        },
                        reason,
                    })?;
                Ok(Open::Rpf9 {
                    listing: Box::new(listing),
                    _temp: temp,
                })
            }
            Format::Zip => {
                let mut source = Source::open(path).map_err(|err| SkipInfo {
                    stage: "structure",
                    reason: format!("cannot open {}: {err}", path.display()),
                })?;
                let archive = zip_archive::Archive::read(
                    &mut source,
                    &zip_archive::Limits {
                        max_entries: MAX_ARCHIVE_ENTRIES,
                        max_metadata: MAX_METADATA,
                    },
                    self.cancel,
                )
                .map_err(|err| SkipInfo {
                    stage: match err.kind {
                        zip_archive::ErrorKind::Limit => "limit",
                        zip_archive::ErrorKind::UnsupportedCompression => "compression",
                        zip_archive::ErrorKind::Encrypted => "transform",
                        _ => "structure",
                    },
                    reason: err.to_string(),
                })?;
                Ok(Open::Zip {
                    archive,
                    source,
                    _temp: temp,
                })
            }
        }
    }

    /// Checks the per-entry and cumulative decode limits before decoding.
    fn reserve_decode(&mut self, size: u64) -> Result<(), SkipInfo> {
        if size > self.limits.max_entry_bytes {
            return Err(SkipInfo {
                stage: "limit",
                reason: format!(
                    "the payload decodes to {size} bytes, more than the {} byte per-entry limit",
                    self.limits.max_entry_bytes
                ),
            });
        }
        if !self.charge_decoded(size) {
            return Err(SkipInfo {
                stage: "limit",
                reason: format!(
                    "the cumulative decode budget of {} bytes is exhausted",
                    self.limits.max_decoded_bytes
                ),
            });
        }
        Ok(())
    }

    /// Decodes a ZIP entry into a temporary file, charging the decode budget.
    fn spool_zip_entry(
        &mut self,
        archive: &zip_archive::Archive,
        source: &mut Source,
        len: u64,
        entry: &zip_archive::Entry,
    ) -> Result<tempfile::TempPath, SkipInfo> {
        let size = entry.uncompressed_size;
        self.reserve_decode(size)?;
        let mut file = tempfile::NamedTempFile::new().map_err(|err| SkipInfo {
            stage: "storage",
            reason: format!("cannot create a temporary file: {err}"),
        })?;
        archive
            .decode_entry(source, len, entry, self.cancel, size, &mut file)
            .map_err(|err| SkipInfo {
                stage: if err.kind == zip_archive::ErrorKind::Limit {
                    "limit"
                } else {
                    "decoding"
                },
                reason: err.to_string(),
            })?;
        let (_file, path) = file.into_parts();
        Ok(path)
    }

    /// Copies an RPF9 row's decoded payload into a temporary file. The row was
    /// already charged to the decode budget when it was inspected, so this
    /// checks only the per-entry size.
    fn spool_payload(
        &mut self,
        payload: &mut Payload,
        size: u64,
    ) -> Result<tempfile::TempPath, SkipInfo> {
        if size > self.limits.max_entry_bytes {
            return Err(SkipInfo {
                stage: "limit",
                reason: format!(
                    "the payload decodes to {size} bytes, more than the {} byte per-entry limit",
                    self.limits.max_entry_bytes
                ),
            });
        }
        let mut file = tempfile::NamedTempFile::new().map_err(|err| SkipInfo {
            stage: "storage",
            reason: format!("cannot create a temporary file: {err}"),
        })?;
        let mut buf = vec![0u8; COPY_LEN];
        let mut written = 0u64;
        loop {
            if self.cancelled() {
                return Err(SkipInfo {
                    stage: "cancel",
                    reason: "cancelled".to_string(),
                });
            }
            let n = payload
                .read_cancellable(&mut buf, self.cancel)
                .map_err(|err| SkipInfo {
                    stage: "decoding",
                    reason: err.to_string(),
                })?;
            if n == 0 {
                break;
            }
            written = written.checked_add(n as u64).ok_or_else(|| SkipInfo {
                stage: "decoding",
                reason: "the decoded size overflowed".to_string(),
            })?;
            if written > size {
                return Err(SkipInfo {
                    stage: "decoding",
                    reason: "the decoded payload is larger than its declared size".to_string(),
                });
            }
            file.write_all(&buf[..n]).map_err(|err| SkipInfo {
                stage: "storage",
                reason: format!("cannot write the temporary file: {err}"),
            })?;
        }
        if written != size {
            return Err(SkipInfo {
                stage: "decoding",
                reason: format!(
                    "the decoded payload holds {written} bytes, not its declared {size}"
                ),
            });
        }
        let (_file, path) = file.into_parts();
        Ok(path)
    }

    fn reserve_temp(&mut self, size: u64) -> bool {
        let Some(total) = self.live_temp.checked_add(size) else {
            return false;
        };
        if total > self.limits.max_temp_bytes {
            return false;
        }
        self.live_temp = total;
        true
    }

    fn release_temp(&mut self, size: u64) {
        self.live_temp = self.live_temp.saturating_sub(size);
    }

    fn summary(&self, roots: usize, discovery_truncated: bool) -> Value {
        json!({
            "schema": SCHEMA,
            "kind": "summary",
            "status": self.status.name(),
            "error": &self.error,
            "roots": roots,
            "archives": self.archives,
            "entries_discovered": self.entries_discovered,
            "entries_emitted": self.entries_emitted,
            "skipped": self.skipped,
            "decoded_bytes": self.decoded,
            "temp_bytes_held": self.live_temp,
            "limits_hit": self.limits_hit.iter().copied().collect::<Vec<_>>(),
            "discovery_truncated": discovery_truncated,
            "unique_hashes": self.stats.unique_hashes.len(),
            "unique_names": self.stats.unique_names.len(),
            "by_archive_format": &self.stats.by_archive_format,
            "by_depth": &self.stats.by_depth,
            "by_type_id": &self.stats.by_type_id,
            "by_name_status": &self.stats.by_name_status,
            "by_content_format": &self.stats.by_content_format,
            "by_payload_status": &self.stats.by_payload_status,
            "by_failure_stage": &self.stats.by_failure_stage,
            "note": "counts describe every discovered entry; entries_emitted is what the filters let through",
        })
    }

    fn emit(&mut self, record: EntryRecord, emitter: &mut Emitter<'_>) -> Result<(), String> {
        self.entries_discovered += 1;
        Stats::count(&mut self.stats.by_depth, record.path.len().to_string());
        Stats::count(&mut self.stats.by_name_status, record.entry.name_status);
        Stats::count(
            &mut self.stats.by_type_id,
            record
                .entry
                .type_id
                .map_or_else(|| "none".to_string(), |type_id| type_id.to_string()),
        );
        Stats::count(
            &mut self.stats.by_content_format,
            record
                .content
                .format_id
                .clone()
                .unwrap_or_else(|| record.content.status.to_string()),
        );
        Stats::count(&mut self.stats.by_payload_status, record.payload.status);
        if let Some(stage) = record
            .content
            .failure_stage
            .or_else(|| record.skipped.as_ref().map(|skip| skip.stage))
        {
            Stats::count(&mut self.stats.by_failure_stage, stage);
        }
        if let Some(hash) = record.entry.hash64 {
            self.stats
                .unique_hashes
                .insert(("hash64".to_string(), hash));
        }
        if let Some(key) = record.entry.key32 {
            self.stats
                .unique_hashes
                .insert(("key32".to_string(), u64::from(key)));
        }
        if let Some(name) = record
            .entry
            .resolved_name
            .as_ref()
            .or(record.entry.name.as_ref())
            && !name.is_empty()
        {
            self.stats.unique_names.insert(name.clone());
        }
        if self.filters.matches(&record) {
            emitter.record(&record.json())?;
            self.entries_emitted += 1;
        }
        Ok(())
    }
}

enum Open {
    Rpf9 {
        listing: Box<Listing>,
        /// Dropped after `listing`, so the temporary file is not deleted while
        /// its reader is still open.
        _temp: Option<tempfile::TempPath>,
    },
    Zip {
        archive: zip_archive::Archive,
        source: Source,
        _temp: Option<tempfile::TempPath>,
    },
}

impl Open {
    fn format(&self) -> Format {
        match self {
            Open::Rpf9 { .. } => Format::Rpf9,
            Open::Zip { .. } => Format::Zip,
        }
    }

    fn archive_json(&self, root: &str, chain: &[Selector]) -> Value {
        let chain: Vec<String> = chain.iter().map(Selector::label).collect();
        match self {
            Open::Rpf9 { listing, .. } => json!({
                "schema": SCHEMA,
                "kind": "archive",
                "root": root,
                "selector_path": chain,
                "depth": chain.len(),
                "format": "RPF9",
                "format_id": "rpf9",
                "entries": listing.entries().len(),
                "zip64": false,
                "duplicate_names": 0,
                "authentication": rows::authentication_json(&listing.opened().authentication),
            }),
            Open::Zip { archive, .. } => json!({
                "schema": SCHEMA,
                "kind": "archive",
                "root": root,
                "selector_path": chain,
                "depth": chain.len(),
                "format": "ZIP",
                "format_id": "zip",
                "entries": archive.len(),
                "zip64": archive.zip64,
                "duplicate_names": archive.duplicate_names,
                "authentication": Value::Null,
            }),
        }
    }

    fn walk(
        &mut self,
        engine: &mut Engine<'_>,
        root: &str,
        chain: &[Selector],
        emitter: &mut Emitter<'_>,
    ) -> Result<(), String> {
        match self {
            Open::Rpf9 { listing, .. } => walk_rpf9(engine, listing, root, chain, emitter),
            Open::Zip {
                archive, source, ..
            } => walk_zip(engine, archive, source, root, chain, emitter),
        }
    }
}

fn walk_rpf9(
    engine: &mut Engine<'_>,
    listing: &Listing,
    root: &str,
    chain: &[Selector],
    emitter: &mut Emitter<'_>,
) -> Result<(), String> {
    let opened = listing.opened();
    let source = opened.source.clone();
    let alternates = listing.alternates();
    let authentication = rows::authentication_json(&opened.authentication);
    let entries = listing.entries();
    let archive_entries = entries.len();
    for entry in entries {
        if engine.cancelled() {
            engine.status = Status::Cancelled;
            return Ok(());
        }
        if engine.entries_discovered >= engine.limits.max_entries {
            engine.truncate("max_entries");
            return Ok(());
        }
        let state = native::contents_state(entry, &source, alternates.sources());
        let payload = PayloadInfo::new(state.readable, state.state, state.reason.clone());
        let mut content = ContentInfo::not_inspected();
        let mut nested: Option<(Format, u64)> = None;
        if state.readable {
            match entry.payload(&source, alternates.sources()) {
                Ok(mut decoded) => {
                    let len = decoded.len();
                    if len > engine.limits.max_entry_bytes {
                        content = ContentInfo::stopped(
                            "limit",
                            format!(
                                "the payload is {len} bytes, more than the {} byte inspection limit",
                                engine.limits.max_entry_bytes
                            ),
                        );
                    } else if !engine.charge_decoded(len) {
                        engine.truncate("max_decoded_bytes");
                        return Ok(());
                    } else {
                        content = classify(&mut decoded, len, engine.cancel);
                        if let Some(format) = content.archive_format {
                            nested = Some((format, len));
                        }
                    }
                }
                Err(err) => {
                    content = ContentInfo::stopped("decoding", err.to_string());
                }
            }
        } else if let Some(reason) = &state.reason {
            content = ContentInfo::stopped(stage_for_state(state.state), reason.clone());
        }

        let location = entry
            .location
            .as_ref()
            .ok()
            .and_then(|value| value.as_ref());
        let chunks = entry.chunks.as_ref().ok().and_then(|value| value.as_ref());
        let encoding = json!({
            "source": "rpf9",
            "mode": location.map(|location| location.mode),
            "chunks": chunks.map(|chunks| json!({
                "encoding": chunks.encoding,
                "count": chunks.chunks.len(),
            })),
            "payload_transform": match &entry.payload_transform {
                Ok(flag) => json!(flag),
                Err(reason) => json!({ "malformed": reason }),
            },
            "read_source": match &entry.read_source {
                Ok(None) => json!("main"),
                Ok(Some(index)) => json!(index),
                Err(reason) => json!({ "malformed": reason }),
            },
        });

        let resolved = listing.row_names(entry.row).map(|names| &names.resolution);
        let (resolved_name, name_status) = match resolved {
            Some(resolution) if resolution.is_resolved() || resolution.is_ambiguous() => (
                resolution
                    .names()
                    .iter()
                    .map(|name| name.text.clone())
                    .collect::<Vec<_>>()
                    .join(", "),
                if resolution.is_ambiguous() {
                    "ambiguous"
                } else {
                    "resolved"
                },
            ),
            Some(_) => (String::new(), "unresolved"),
            None => (String::new(), "none"),
        };
        let resolved_name = (!resolved_name.is_empty()).then_some(resolved_name);
        let type_id = entry.type_id();
        let extension = type_id
            .and_then(|type_id| listing.extension_for(type_id))
            .map(str::to_string);

        let mut record = EntryRecord {
            root: root.to_string(),
            path: chain.to_vec(),
            archive_format: Format::Rpf9,
            archive_entries,
            zip64: false,
            duplicate_names: 0,
            entry: EntryInfo {
                selector: Selector::Row(entry.row),
                kind: "row",
                name: resolved_name.clone(),
                resolved_name,
                name_status,
                namespace: listing
                    .row_names(entry.row)
                    .and_then(|names| names.namespace.text())
                    .map(str::to_string),
                hash64: entry.name_hash.as_ref().ok().copied().flatten(),
                key32: entry.name_key.as_ref().ok().copied().flatten(),
                type_id,
                extension,
                extension_synthetic: false,
                stored_size: location.map(|location| location.stored_len),
                logical_size: location.map(|location| location.logical_len),
                is_directory: false,
                encoding,
            },
            payload,
            content,
            skipped: None,
            authentication: authentication.clone(),
        };

        let mut child = None;
        if let Some((format, size)) = nested
            && engine.recursive
        {
            match entry.payload(&source, alternates.sources()) {
                Ok(mut decoded) => {
                    child = prepare_nested(engine, format, size, &mut record, &mut decoded)?;
                }
                Err(err) => {
                    let skip = SkipInfo {
                        stage: "decoding",
                        reason: err.to_string(),
                    };
                    engine.note_skipped(&mut record, skip);
                }
            }
        }

        let selector = record.entry.selector;
        engine.emit(record, emitter)?;

        if let Some((mut open, size)) = child {
            let mut next = chain.to_vec();
            next.push(selector);
            emitter.record(&open.archive_json(root, &next))?;
            Stats::count(&mut engine.stats.by_archive_format, open.format().name());
            open.walk(engine, root, &next, emitter)?;
            drop(open);
            engine.release_temp(size);
        }
    }
    Ok(())
}

fn walk_zip(
    engine: &mut Engine<'_>,
    archive: &zip_archive::Archive,
    source: &mut Source,
    root: &str,
    chain: &[Selector],
    emitter: &mut Emitter<'_>,
) -> Result<(), String> {
    let len = source.len();
    let archive_entries = archive.len();
    let duplicate_names = archive.duplicate_names;
    let zip64 = archive.zip64;
    for index in 0..archive_entries {
        if engine.cancelled() {
            engine.status = Status::Cancelled;
            return Ok(());
        }
        if engine.entries_discovered >= engine.limits.max_entries {
            engine.truncate("max_entries");
            return Ok(());
        }
        let entry = &archive.entries[index];
        let mut content = ContentInfo::not_inspected();
        let mut nested: Option<(Format, u64)> = None;
        let mut decoded_temp: Option<tempfile::TempPath> = None;
        let payload;
        if entry.is_dir() {
            payload = PayloadInfo::new(false, "directory", None);
        } else if entry.is_encrypted() {
            payload = PayloadInfo::new(
                false,
                "encrypted",
                Some("the entry is encrypted; its payload cannot be decoded".to_string()),
            );
            content = ContentInfo::stopped(
                "transform",
                "the entry is encrypted; its format cannot be recognised",
            );
        } else if !entry.compression.is_supported() {
            let reason = format!(
                "compression method {} is not decoded by this build",
                entry.compression.method()
            );
            payload = PayloadInfo::new(false, "unsupported_compression", Some(reason.clone()));
            content = ContentInfo::stopped("compression", reason);
        } else {
            match archive.read_prefix(source, len, entry, engine.cancel, RECOGNITION_BYTES) {
                Ok(prefix) => {
                    if !engine.charge_decoded(prefix.bytes.len() as u64) {
                        engine.truncate("max_decoded_bytes");
                        return Ok(());
                    }
                    let recognised = recognition::recognise(&prefix.bytes).is_some()
                        || archive::signature(&prefix.bytes).is_some();
                    if !recognised {
                        payload = PayloadInfo::new(
                            true,
                            "prefix_only",
                            Some(format!(
                                "no recognised signature in the first {} bytes; the payload was not decoded",
                                prefix.bytes.len()
                            )),
                        );
                    } else {
                        match engine.spool_zip_entry(archive, source, len, entry) {
                            Ok(path) => {
                                let size = entry.uncompressed_size;
                                match Source::open(&path) {
                                    Ok(mut reader) => {
                                        content = classify(&mut reader, size, engine.cancel);
                                        if let Some(format) = content.archive_format {
                                            nested = Some((format, size));
                                        }
                                        payload = PayloadInfo::new(true, "decoded", None);
                                        decoded_temp = Some(path);
                                    }
                                    Err(err) => {
                                        payload = PayloadInfo::new(true, "decoded", None);
                                        content = ContentInfo::stopped("storage", err.to_string());
                                    }
                                }
                            }
                            Err(skip) => {
                                payload = PayloadInfo::new(
                                    true,
                                    "not_decoded",
                                    Some(skip.reason.clone()),
                                );
                                content = ContentInfo::stopped(skip.stage, skip.reason);
                            }
                        }
                    }
                }
                Err(err) => {
                    let stage = match err.kind {
                        zip_archive::ErrorKind::UnsupportedCompression => "compression",
                        zip_archive::ErrorKind::Encrypted => "transform",
                        zip_archive::ErrorKind::Limit => "limit",
                        _ => "decoding",
                    };
                    payload = PayloadInfo::new(false, "malformed", Some(err.to_string()));
                    content = ContentInfo::stopped(stage, err.to_string());
                }
            }
        }

        let name = (!entry.name.is_empty()).then(|| entry.name.clone());
        let mut record = EntryRecord {
            root: root.to_string(),
            path: chain.to_vec(),
            archive_format: Format::Zip,
            archive_entries,
            zip64,
            duplicate_names,
            entry: EntryInfo {
                selector: Selector::Zip(index),
                kind: "zip",
                name,
                resolved_name: None,
                name_status: "none",
                namespace: None,
                hash64: None,
                key32: None,
                type_id: None,
                extension: None,
                extension_synthetic: false,
                stored_size: Some(entry.compressed_size),
                logical_size: Some(entry.uncompressed_size),
                is_directory: entry.is_dir(),
                encoding: json!({
                    "source": "zip",
                    "method": entry.compression.method(),
                    "compression": entry.compression.name(),
                }),
            },
            payload,
            content,
            skipped: None,
            authentication: Value::Null,
        };

        let mut child = None;
        if let Some((format, size)) = nested
            && engine.recursive
        {
            if chain.len() + 1 >= engine.limits.max_depth {
                let skip = SkipInfo {
                    stage: "depth",
                    reason: format!(
                        "the nesting depth limit of {} archives was reached",
                        engine.limits.max_depth
                    ),
                };
                engine.note_skipped(&mut record, skip);
                decoded_temp = None;
            } else if engine.archives >= engine.limits.max_archives {
                engine.truncate("max_archives");
                decoded_temp = None;
            } else if let Some(path) = decoded_temp.take() {
                if engine.reserve_temp(size) {
                    let temp_path = path.to_path_buf();
                    match engine.open_archive(&temp_path, format, Some(path)) {
                        Ok(open) => {
                            engine.archives += 1;
                            child = Some((open, size));
                        }
                        Err(skip) => {
                            engine.note_skipped(&mut record, skip);
                        }
                    }
                } else {
                    engine.truncate("max_temp_bytes");
                }
            }
        }
        // A decoded payload that is not entered is released here.
        drop(decoded_temp);

        let selector = record.entry.selector;
        engine.emit(record, emitter)?;

        if let Some((mut open, size)) = child {
            let mut next = chain.to_vec();
            next.push(selector);
            emitter.record(&open.archive_json(root, &next))?;
            Stats::count(&mut engine.stats.by_archive_format, open.format().name());
            open.walk(engine, root, &next, emitter)?;
            drop(open);
            engine.release_temp(size);
        }
    }
    Ok(())
}

/// Spools and opens a nested RPF9 or ZIP payload, applying the depth, archive
/// and temporary-storage limits. A refusal becomes `record.skipped`.
fn prepare_nested(
    engine: &mut Engine<'_>,
    format: Format,
    size: u64,
    record: &mut EntryRecord,
    payload: &mut Payload,
) -> Result<Option<(Open, u64)>, String> {
    if record.path.len() + 1 >= engine.limits.max_depth {
        let skip = SkipInfo {
            stage: "depth",
            reason: format!(
                "the nesting depth limit of {} archives was reached",
                engine.limits.max_depth
            ),
        };
        engine.note_skipped(record, skip);
        return Ok(None);
    }
    if engine.archives >= engine.limits.max_archives {
        engine.truncate("max_archives");
        return Ok(None);
    }
    if !engine.reserve_temp(size) {
        engine.truncate("max_temp_bytes");
        return Ok(None);
    }
    let temp = match engine.spool_payload(payload, size) {
        Ok(temp) => temp,
        Err(skip) => {
            engine.release_temp(size);
            engine.note_skipped(record, skip);
            return Ok(None);
        }
    };
    let path = temp.to_path_buf();
    match engine.open_archive(&path, format, Some(temp)) {
        Ok(open) => {
            engine.archives += 1;
            Ok(Some((open, size)))
        }
        Err(skip) => {
            engine.release_temp(size);
            engine.note_skipped(record, skip);
            Ok(None)
        }
    }
}

/// Recognises the contents of a decodable payload. Archive recognition runs
/// first, so an RPF9 or ZIP is reported as an archive and its structure is
/// validated by the same code the archive commands use. Any other format goes
/// through the shared inspection, which also reports structural failures.
fn classify(reader: &mut (impl Read + Seek), len: u64, cancel: &AtomicBool) -> ContentInfo {
    match archive::identify(reader) {
        Ok(Identified::Archive(format)) => ContentInfo {
            status: "parsed",
            format: Some(json!({
                "id": format.name().to_lowercase(),
                "name": format.name(),
                "support": "archive",
                "detail": "an archive; its entries are listed by the archive commands",
            })),
            format_id: Some(format.name().to_lowercase()),
            archive_format: Some(format),
            failure_stage: None,
            failure: None,
            display_extension: None,
        },
        Ok(Identified::Invalid { format, reason }) => ContentInfo {
            status: "invalid_archive",
            format: Some(json!({
                "id": format.name().to_lowercase(),
                "name": format.name(),
                "support": "archive",
                "detail": "the signature matched but the structure did not",
            })),
            format_id: Some(format.name().to_lowercase()),
            archive_format: None,
            failure_stage: Some("structure"),
            failure: Some(reason),
            display_extension: None,
        },
        Ok(Identified::Unknown) => {
            let options = recognition::Options {
                sample: 1,
                ..recognition::Options::default()
            };
            match recognition::inspect(reader, len, &options, cancel) {
                Ok(report) => content_from_report(&report),
                Err(err) => ContentInfo::stopped("recognition", err),
            }
        }
        Err(err) => ContentInfo::stopped("recognition", err.to_string()),
    }
}

fn content_from_report(report: &recognition::Report) -> ContentInfo {
    let Some(format) = report.format else {
        // The bytes were available and decoded, and no signature matched.
        let mut content = ContentInfo::not_inspected();
        content.status = "unknown";
        return content;
    };
    let status = match (&report.failure, format.support) {
        (Some(_), _) => "failed",
        (None, "recognition") => "recognised",
        (None, _) => "parsed",
    };
    let display_extension = (format.id == "psin").then(|| {
        json!({
            "value": "bin",
            "synthetic": true,
            "note": ".bin is a neutral display fallback; no PSIN extension is established",
        })
    });
    ContentInfo {
        status,
        format: Some(format.json()),
        format_id: Some(format.id.to_string()),
        archive_format: None,
        failure_stage: report.failure.as_ref().map(|failure| failure.stage),
        failure: report
            .failure
            .as_ref()
            .map(|failure| failure.message.clone()),
        display_extension,
    }
}

/// The RPF9 readability state mapped to a failure stage, for a payload that
/// could not be decoded.
fn stage_for_state(state: &'static str) -> &'static str {
    match state {
        "unsupported_transform" => "transform",
        "unsupported_compression" => "compression",
        "alternate_source" => "source",
        "malformed" => "structure",
        _ => "decoding",
    }
}

fn identify_path(path: &Path) -> Result<Format, (&'static str, String)> {
    let mut source = Source::open(path).map_err(|err| {
        (
            "structure",
            format!("cannot open {}: {err}", path.display()),
        )
    })?;
    match archive::identify(&mut source) {
        Ok(Identified::Archive(format)) => Ok(format),
        Ok(Identified::Invalid { format, reason }) => Err((
            "structure",
            format!(
                "{} is not a valid {format} archive: {reason}",
                path.display()
            ),
        )),
        Ok(Identified::Unknown) => Err((
            "structure",
            format!("{} is not an archive in a supported format", path.display()),
        )),
        Err(err) => Err((
            "structure",
            format!("cannot read {}: {err}", path.display()),
        )),
    }
}

/// Streams a JSON document or JSONL records. Entry records are never held in
/// memory: the JSON entry array is opened before the walk and closed after it.
struct Emitter<'w> {
    format: OutputFormat,
    out: BufWriter<&'w mut dyn Write>,
    first: bool,
}

impl<'w> Emitter<'w> {
    fn new(format: OutputFormat, out: &'w mut dyn Write) -> Self {
        Self {
            format,
            out: BufWriter::new(out),
            first: true,
        }
    }

    fn write_text(&mut self, text: &str) -> Result<(), String> {
        self.out
            .write_all(text.as_bytes())
            .map_err(|err| format!("cannot write the inventory: {err}"))
    }

    fn header(&mut self, header: &Value) -> Result<(), String> {
        let text = serde_json::to_string(header)
            .map_err(|err| format!("cannot serialize the inventory header: {err}"))?;
        match self.format {
            OutputFormat::Jsonl => self.write_text(&format!("{text}\n")),
            OutputFormat::Json => {
                let open = text.strip_suffix('}').ok_or_else(|| {
                    "the inventory header did not serialize as an object".to_string()
                })?;
                self.write_text(open)?;
                self.write_text(",\"records\":[")
            }
        }
    }

    fn record(&mut self, record: &Value) -> Result<(), String> {
        let text = serde_json::to_string(record)
            .map_err(|err| format!("cannot serialize an inventory record: {err}"))?;
        match self.format {
            OutputFormat::Jsonl => self.write_text(&format!("{text}\n")),
            OutputFormat::Json => {
                if !self.first {
                    self.write_text(",")?;
                }
                self.first = false;
                self.write_text(&text)
            }
        }
    }

    fn finish(&mut self, summary: &Value) -> Result<(), String> {
        let text = serde_json::to_string(summary)
            .map_err(|err| format!("cannot serialize the inventory summary: {err}"))?;
        match self.format {
            OutputFormat::Jsonl => self.write_text(&format!("{text}\n"))?,
            OutputFormat::Json => {
                self.write_text("],\"summary\":")?;
                self.write_text(&text)?;
                self.write_text("}\n")?;
            }
        }
        self.out
            .flush()
            .map_err(|err| format!("cannot write the inventory: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A minimal RBF0 document: header, empty root name and an empty root
    /// object. `flags` is the unknown header value.
    fn rbf0(flags: u32) -> Vec<u8> {
        let mut bytes = b"RBF0".to_vec();
        bytes.extend_from_slice(&0xFFFBu16.to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
        bytes
    }

    #[test]
    fn classify_parses_a_minimal_rbf0_document() {
        let bytes = rbf0(3);
        let len = bytes.len() as u64;
        let mut reader = Cursor::new(bytes);
        let content = classify(&mut reader, len, &AtomicBool::new(false));
        assert_eq!(content.status, "parsed");
        assert_eq!(content.format_id.as_deref(), Some("rbf0"));
        assert_eq!(content.archive_format, None);
    }

    #[test]
    fn classify_reports_unknown_content_without_a_failure() {
        let mut reader = Cursor::new(vec![0xAA; 32]);
        let content = classify(&mut reader, 32, &AtomicBool::new(false));
        assert_eq!(content.status, "unknown");
        assert_eq!(content.format_id, None);
        assert_eq!(content.failure_stage, None);
    }

    #[test]
    fn classify_marks_psin_with_a_synthetic_extension() {
        let mut bytes = b"PSIN".to_vec();
        bytes.extend_from_slice(&[0; 12]);
        let mut reader = Cursor::new(bytes);
        let content = classify(&mut reader, 16, &AtomicBool::new(false));
        assert_eq!(content.format_id.as_deref(), Some("psin"));
        let extension = content.display_extension.expect("display extension");
        assert_eq!(extension["value"], "bin");
        assert_eq!(extension["synthetic"], true);
    }

    #[test]
    fn the_emitter_writes_a_complete_jsonl_stream() {
        let mut bytes = Vec::new();
        {
            let mut emitter = Emitter::new(OutputFormat::Jsonl, &mut bytes);
            emitter.header(&json!({ "kind": "header" })).unwrap();
            emitter.record(&json!({ "kind": "entry", "n": 1 })).unwrap();
            emitter
                .finish(&json!({ "kind": "summary", "status": "complete" }))
                .unwrap();
        }
        let lines: Vec<&str> = std::str::from_utf8(&bytes).unwrap().lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("header"));
        assert!(lines[2].contains("complete"));
    }

    #[test]
    fn the_emitter_writes_one_json_document() {
        let mut bytes = Vec::new();
        {
            let mut emitter = Emitter::new(OutputFormat::Json, &mut bytes);
            emitter.header(&json!({ "kind": "header" })).unwrap();
            emitter.record(&json!({ "kind": "entry" })).unwrap();
            emitter.record(&json!({ "kind": "entry" })).unwrap();
            emitter.finish(&json!({ "kind": "summary" })).unwrap();
        }
        let document: Value = serde_json::from_slice(&bytes).expect("one document");
        assert_eq!(document["kind"], "header");
        assert_eq!(document["records"].as_array().unwrap().len(), 2);
        assert_eq!(document["summary"]["kind"], "summary");
    }

    #[test]
    fn a_cancelled_traversal_says_so_and_keeps_its_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cancel.zip");
        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut out);
            writer
                .start_file("a.bin", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&[0xAA; 32]).unwrap();
            writer.finish().unwrap();
        }
        std::fs::write(&path, out.into_inner()).unwrap();

        let options = Options {
            path: path.clone(),
            executable: None,
            candidates: Vec::new(),
            recursive: false,
            format: OutputFormat::Jsonl,
            output: None,
            overwrite: false,
            limits: Limits::default(),
            filters: Filters::default(),
        };
        let cancel = AtomicBool::new(false);
        let (roots, truncated) = discover(&path, &options.limits, &cancel).unwrap();
        assert!(!truncated);
        cancel.store(true, Ordering::Relaxed);
        let mut bytes = Vec::new();
        let outcome = run_stream(&options, &roots, truncated, &cancel, &mut bytes).unwrap();
        assert_eq!(outcome.status, Status::Cancelled);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"cancelled\""), "{text}");
    }
}
