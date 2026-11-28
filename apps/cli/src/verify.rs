//! `lforge archive verify`: decode every entry of one storage encoding in
//! full, streaming, and report exactly what was established.
//!
//! The command walks the authenticated RPF9 table of contents of every
//! reachable archive and, for each row whose chunk table uses the selected
//! encoding, reads the complete decoded payload through a SHA-256 hasher. It
//! writes the chunk table's decoded fields, the stored prefix, the digest and,
//! on failure, a category and the decoder's message.
//!
//! Nothing is retained but counters, so the pass is bounded by the limits
//! rather than by the installation size. A nested archive is entered in place
//! when its bytes are stored as they are and through a temporary file
//! otherwise.

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::Source;
use lforge_core::classify;
use lforge_core::registry::native_extension;
use lforge_rage9::rpf::metadata::{Entry, Error};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::native::{self, Alternates, Opened};

/// The schema of every record this command writes.
pub const SCHEMA: &str = "leonida-forge.encoding-verification/1";
const MAX_METADATA: u64 = 256 * 1024 * 1024;
const COPY_BUFFER: usize = 1024 * 1024;
const HEAD_LEN: usize = 64;

/// Caps one verification pass.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Archives in a chain, counting the root.
    pub max_depth: usize,
    /// Archives opened, roots included.
    pub max_archives: u64,
    /// Entries examined, all archives included.
    pub max_entries: u64,
    /// Largest nested archive copied to temporary storage.
    pub max_nested_bytes: u64,
    /// Total bytes copied to temporary storage.
    pub max_spool_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_archives: 4096,
            max_entries: 2_000_000,
            max_nested_bytes: 2 * 1024 * 1024 * 1024,
            max_spool_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}

/// Which stored representation a verification pass selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    Chunked(u8),
    RawDeflate,
    Stored,
}

impl Storage {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "chunked-2" => Storage::Chunked(2),
            "chunked-3" => Storage::Chunked(3),
            "chunked-4" => Storage::Chunked(4),
            "raw-deflate" => Storage::RawDeflate,
            "stored" => Storage::Stored,
            _ => return None,
        })
    }

    fn matches(self, entry: &Entry) -> bool {
        let chunks = match &entry.chunks {
            Ok(value) => value.as_ref(),
            Err(_) => return false,
        };
        let mode = match &entry.location {
            Ok(Some(location)) => Some(location.mode),
            Ok(None) => None,
            Err(_) => return false,
        };
        match self {
            Storage::Chunked(encoding) => chunks.is_some_and(|table| table.encoding == encoding),
            Storage::RawDeflate => chunks.is_none() && mode == Some(1),
            Storage::Stored => chunks.is_none() && mode == Some(0),
        }
    }

    pub fn label(self) -> String {
        match self {
            Storage::Chunked(encoding) => format!("chunked-{encoding}"),
            Storage::RawDeflate => "raw-deflate".to_string(),
            Storage::Stored => "stored".to_string(),
        }
    }
}

pub struct Options {
    /// An archive, or a directory searched for `.rpf` files.
    pub path: PathBuf,
    /// The name a single root is reported under.
    pub root_name: Option<String>,
    /// Archives to enter before verifying, as `row:N` selectors.
    pub enters: Vec<crate::nested::Selector>,
    pub executable: Option<PathBuf>,
    /// The chunk encoding whose entries are decoded in full.
    pub encoding: u8,
    /// A stored representation to select instead of `encoding`.
    pub storage: Option<Storage>,
    /// Whether to select only rows with, or only rows without, the payload
    /// transform.
    pub transform: Option<bool>,
    pub recursive: bool,
    pub limits: Limits,
    pub output: Option<PathBuf>,
    pub overwrite: bool,
}

/// One archive that could not be opened, kept as evidence.
#[derive(Debug, Clone)]
struct Failure {
    archive: String,
    depth: usize,
    error: String,
}

struct Tally {
    candidates: u64,
    decoded: u64,
    failed: u64,
    /// Per type, encoding and outcome.
    by_type: BTreeMap<String, u64>,
    by_error: BTreeMap<String, u64>,
    by_prefix: BTreeMap<String, u64>,
    by_methods: BTreeMap<String, u64>,
}

impl Tally {
    fn new() -> Self {
        Self {
            candidates: 0,
            decoded: 0,
            failed: 0,
            by_type: BTreeMap::new(),
            by_error: BTreeMap::new(),
            by_prefix: BTreeMap::new(),
            by_methods: BTreeMap::new(),
        }
    }

    fn count(map: &mut BTreeMap<String, u64>, key: impl Into<String>) {
        *map.entry(key.into()).or_insert(0) += 1;
    }
}

struct Engine<'a> {
    options: &'a Options,
    cancel: &'a AtomicBool,
    writer: Box<dyn Write>,
    /// `(temporary, target)`, present when writing to a file.
    publish: Option<(PathBuf, PathBuf)>,
    storage: Storage,
    archives: u64,
    roots: u64,
    entries: u64,
    spooled: u64,
    tally: Tally,
    failures: Vec<Failure>,
    stopped: Option<&'static str>,
}

impl Drop for Engine<'_> {
    fn drop(&mut self) {
        // A run that ended without publishing leaves no partial target.
        if let Some((temporary, _)) = self.publish.take() {
            let _ = fs::remove_file(temporary);
        }
    }
}

/// Runs a verification pass, writing the record stream to `options.output` or
/// standard output.
pub fn run(options: &Options, cancel: &AtomicBool) -> Result<(), String> {
    if !matches!(options.encoding, 2..=4) {
        return Err(format!(
            "chunk encoding {} is not one of the supported encodings 2, 3 or 4",
            options.encoding
        ));
    }
    let storage = options
        .storage
        .unwrap_or(Storage::Chunked(options.encoding));
    // An entered archive lives in a temporary file, which must outlive the run.
    let mut entered = None;
    let roots = if options.enters.is_empty() {
        discover(&options.path, options.root_name.as_deref(), cancel)?
    } else {
        let resolved = crate::nested::resolve_with(
            &options.path,
            options.executable.as_deref(),
            &options.enters,
            cancel,
            &crate::nested::Limits {
                max_depth: options.limits.max_depth,
                max_archive_bytes: options.limits.max_nested_bytes,
                max_chain_bytes: options.limits.max_spool_bytes,
                max_entries: options.limits.max_entries,
            },
        )?;
        let mut name = options
            .root_name
            .clone()
            .or_else(|| {
                options
                    .path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| options.path.display().to_string());
        for selector in &options.enters {
            name.push('!');
            name.push_str(&selector.selector_index().to_string());
        }
        let path = resolved.path.clone();
        entered = Some(resolved);
        vec![Root { path, name }]
    };
    let _keep_entered = entered;
    let (writer, publish) = open_output(options)?;
    let mut engine = Engine {
        options,
        cancel,
        writer,
        publish,
        storage,
        archives: 0,
        roots: 0,
        entries: 0,
        spooled: 0,
        tally: Tally::new(),
        failures: Vec::new(),
        stopped: None,
    };
    engine.header(&roots)?;
    for root in &roots {
        if engine.cancelled() || engine.stopped.is_some() {
            break;
        }
        if let Err(err) = engine.enter_root(root) {
            engine.failures.push(Failure {
                archive: root.name.clone(),
                depth: 0,
                error: err,
            });
        }
    }
    engine.summary(&roots)?;
    engine.finish()?;
    if let Some(limit) = engine.stopped {
        return Err(format!(
            "the verification stopped at {limit}; the summary records what was verified"
        ));
    }
    if !engine.failures.is_empty() {
        return Err(format!(
            "{} archive(s) could not be read; the summary records which",
            engine.failures.len()
        ));
    }
    if engine.tally.failed != 0 {
        return Err(format!(
            "{} entry/entries of {} could not be decoded; every one is recorded",
            engine.tally.failed,
            engine.storage.label()
        ));
    }
    Ok(())
}

struct Root {
    path: PathBuf,
    name: String,
}

fn discover(
    path: &Path,
    root_name: Option<&str>,
    cancel: &AtomicBool,
) -> Result<Vec<Root>, String> {
    if path.is_file() {
        let name = root_name
            .map(str::to_string)
            .or_else(|| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| path.display().to_string());
        return Ok(vec![Root {
            path: path.to_path_buf(),
            name,
        }]);
    }
    let (files, _) = native::collect_archives(
        path,
        native::ScanLimits {
            max_depth: 32,
            max_archives: 4096,
        },
        cancel,
    )?;
    Ok(files
        .into_iter()
        .map(|file| Root {
            name: relative_name(path, &file),
            path: file,
        })
        .collect())
}

fn relative_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The record stream and, when writing to a file, its temporary and target
/// names.
type Output = (Box<dyn Write>, Option<(PathBuf, PathBuf)>);

fn open_output(options: &Options) -> Result<Output, String> {
    match &options.output {
        Some(path) => {
            if path.exists() && !options.overwrite {
                return Err(format!(
                    "{} already exists; pass --overwrite to replace it",
                    path.display()
                ));
            }
            let mut temporary = path.clone().into_os_string();
            temporary.push(".part");
            let temporary = PathBuf::from(temporary);
            let file = File::create(&temporary)
                .map_err(|err| format!("cannot write {}: {err}", temporary.display()))?;
            Ok((
                Box::new(BufWriter::new(file)),
                Some((temporary, path.clone())),
            ))
        }
        None => Ok((Box::new(std::io::stdout()), None)),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Renames `temporary` to `target`. Windows refuses to replace an existing
/// file with `rename`, so an overwrite removes the target first; elsewhere the
/// rename itself is atomic.
fn publish(temporary: &Path, target: &Path, overwrite: bool) -> Result<(), String> {
    match fs::rename(temporary, target) {
        Ok(()) => Ok(()),
        Err(err) if overwrite && err.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(target)
                .map_err(|err| format!("cannot replace {}: {err}", target.display()))?;
            fs::rename(temporary, target).map_err(|err| {
                format!(
                    "cannot publish {} as {}: {err}",
                    temporary.display(),
                    target.display()
                )
            })
        }
        Err(err) => Err(format!(
            "cannot publish {} as {}: {err}",
            temporary.display(),
            target.display()
        )),
    }
}

impl Engine<'_> {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Whether `entry` belongs to the selected storage and transform state.
    fn selected(&self, entry: &Entry) -> bool {
        if !self.storage.matches(entry) {
            return false;
        }
        match self.options.transform {
            None => true,
            Some(want) => matches!(&entry.payload_transform, Ok(have) if *have == want),
        }
    }

    /// Flushes the stream and publishes the temporary file under its target.
    fn finish(&mut self) -> Result<(), String> {
        self.writer.flush().map_err(|err| err.to_string())?;
        let Some((temporary, target)) = self.publish.take() else {
            return Ok(());
        };
        drop(std::mem::replace(
            &mut self.writer,
            Box::new(std::io::sink()),
        ));
        let published = publish(&temporary, &target, self.options.overwrite);
        if published.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        published
    }

    fn stop(&mut self, limit: &'static str) {
        if self.stopped.is_none() {
            self.stopped = Some(limit);
        }
    }

    fn record(&mut self, value: &Value) -> Result<(), String> {
        let line = serde_json::to_string(value).map_err(|err| err.to_string())?;
        writeln!(self.writer, "{line}").map_err(|err| err.to_string())?;
        // A record is evidence. A run that is interrupted must not lose the
        // entries it already verified.
        self.writer.flush().map_err(|err| err.to_string())
    }

    fn header(&mut self, roots: &[Root]) -> Result<(), String> {
        self.record(&json!({
            "record": "header",
            "schema": SCHEMA,
            "root": self.options.path.display().to_string(),
            "archives": roots.iter().map(|root| root.name.clone()).collect::<Vec<_>>(),
            "encoding": self.options.encoding,
            "storage": self.storage.label(),
            "transform": self.options.transform,
            "recursive": self.options.recursive,
            "limits": {
                "max_depth": self.options.limits.max_depth,
                "max_archives": self.options.limits.max_archives,
                "max_entries": self.options.limits.max_entries,
                "max_nested_bytes": self.options.limits.max_nested_bytes,
                "max_spool_bytes": self.options.limits.max_spool_bytes,
            },
        }))
    }

    fn summary(&mut self, roots: &[Root]) -> Result<(), String> {
        self.record(&json!({
            "record": "summary",
            "schema": SCHEMA,
            "root": self.options.path.display().to_string(),
            "roots": roots.len(),
            "roots_opened": self.roots,
            "archives": self.archives,
            "entries_examined": self.entries,
            "candidates": self.tally.candidates,
            "decoded": self.tally.decoded,
            "failed": self.tally.failed,
            "spooled_bytes": self.spooled,
            "stopped": self.stopped,
            "by_type": self.tally.by_type,
            "by_error": self.tally.by_error,
            "by_prefix": self.tally.by_prefix,
            "by_methods": self.tally.by_methods,
            "failures": self.failures.iter().map(|failure| json!({
                "archive": failure.archive,
                "depth": failure.depth,
                "error": failure.error,
            })).collect::<Vec<_>>(),
        }))
    }

    fn enter_root(&mut self, root: &Root) -> Result<(), String> {
        let source = Source::open(&root.path)
            .map_err(|err| format!("cannot open {}: {err}", root.path.display()))?;
        let opened = native::open_metadata_at(
            source,
            &root.path.display().to_string(),
            MAX_METADATA,
            self.options.executable.as_deref(),
            self.cancel,
        )?;
        self.archives += 1;
        self.roots += 1;
        let alternates = Alternates::resolve(&root.path, &opened.metadata);
        let alternates = alternates.sources().to_vec();
        self.walk(&opened, &alternates, &[], &root.name, 0)
    }

    fn walk(
        &mut self,
        opened: &Opened,
        alternates: &[Option<Source>],
        chain: &[u32],
        name: &str,
        depth: usize,
    ) -> Result<(), String> {
        if self.cancelled() {
            self.stop("cancelled");
            return Ok(());
        }
        let rows: Vec<Entry> = opened.metadata.entries().collect();
        for entry in &rows {
            if self.entries >= self.options.limits.max_entries {
                self.stop("max_entries");
                return Ok(());
            }
            self.entries += 1;
            if self.cancelled() {
                self.stop("cancelled");
                return Ok(());
            }
            let mut nested_chain = chain.to_vec();
            nested_chain.push(entry.row);
            let selector = selector(name, &nested_chain);
            if self.selected(entry) {
                self.verify(opened, alternates, entry, &selector, depth)?;
            }
            if !self.options.recursive || depth + 1 >= self.options.limits.max_depth {
                continue;
            }
            if entry.type_id() != Some(0) {
                continue;
            }
            if self.archives >= self.options.limits.max_archives {
                self.stop("max_archives");
                return Ok(());
            }
            match self.enter_nested(entry, opened, alternates, &selector) {
                Ok(nested) => {
                    self.archives += 1;
                    let result = self.walk(&nested, &[], &[], &selector, depth + 1);
                    if let Err(err) = result {
                        self.failures.push(Failure {
                            archive: selector,
                            depth: depth + 1,
                            error: err,
                        });
                    }
                }
                Err(err) => self.failures.push(Failure {
                    archive: selector,
                    depth: depth + 1,
                    error: err,
                }),
            }
        }
        Ok(())
    }

    /// Opens an archive stored inside `entry`, in place when its bytes are
    /// stored as they are, and through temporary storage otherwise.
    fn enter_nested(
        &mut self,
        entry: &Entry,
        opened: &Opened,
        alternates: &[Option<Source>],
        selector: &str,
    ) -> Result<Opened, String> {
        let limits = native::NestedLimits {
            max_nested_bytes: self.options.limits.max_nested_bytes,
            max_spool_bytes: self.options.limits.max_spool_bytes,
            spooled: self.spooled,
        };
        match native::open_nested(
            entry,
            opened,
            alternates,
            selector,
            limits,
            self.options.executable.as_deref(),
            self.cancel,
        ) {
            Ok((nested, spooled)) => {
                self.spooled += spooled;
                Ok(nested)
            }
            Err(native::NestedError::SpoolBudget { .. }) => {
                self.stop("max_spool_bytes");
                Err(format!(
                    "row {} would exceed the --max-spool-bytes limit",
                    entry.row
                ))
            }
            Err(err) => Err(err.to_string()),
        }
    }

    /// Decodes one entry in full and records what happened.
    fn verify(
        &mut self,
        opened: &Opened,
        alternates: &[Option<Source>],
        entry: &Entry,
        selector: &str,
        depth: usize,
    ) -> Result<(), String> {
        self.tally.candidates += 1;
        let type_key = entry
            .type_id()
            .map_or_else(|| "none".to_string(), |id| id.to_string());
        Tally::count(&mut self.tally.by_type, &type_key);

        let location = entry
            .location
            .as_ref()
            .ok()
            .and_then(|value| value.as_ref());
        let chunks = entry.chunks.as_ref().ok().and_then(|value| value.as_ref());
        let (stored_size, logical_size, mode) = match location {
            Some(location) => (
                Some(location.stored_len),
                Some(location.logical_len),
                Some(location.mode),
            ),
            None => (None, None, None),
        };
        let stored_sum: u64 = chunks
            .map(|chunks| {
                chunks
                    .chunks
                    .iter()
                    .map(|chunk| u64::from(chunk.stored_len))
                    .sum()
            })
            .unwrap_or(0);
        // The stored-prefix rule is the decoder's, so the report cannot drift
        // from what a read does with the same row. Without a chunk table the
        // stored bytes are one stream and there is no prefix.
        let prefix_len = match (stored_size, chunks) {
            (Some(stored), Some(table)) => table.stored_prefix(stored).unwrap_or(0),
            _ => 0,
        };
        let prefix = self.read_prefix(entry, opened, alternates, prefix_len);
        let methods: Vec<u8> = chunks
            .map(|chunks| chunks.chunks.iter().map(|chunk| chunk.method).collect())
            .unwrap_or_default();
        Tally::count(&mut self.tally.by_prefix, prefix_len.to_string());
        if methods.is_empty() {
            Tally::count(&mut self.tally.by_methods, "none");
        } else {
            Tally::count(
                &mut self.tally.by_methods,
                methods
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }

        let mut head = Vec::new();
        let mut hasher = Sha256::new();
        let mut decoded_bytes = 0u64;
        let mut status = "decoded";
        let mut error_category = None;
        let mut error_message = None;
        let opened_payload = || -> Result<_, (String, &'static str)> {
            if matches!(entry.payload_transform, Ok(true))
                && let Some(stream) = opened.stream.as_ref()
            {
                let transform = stream
                    .stream_transform(entry, &opened.source, alternates)
                    .map_err(|err| (format!("row {}: {err}", entry.row), "transform"))?;
                return entry
                    .transformed_payload(&opened.source, alternates, transform)
                    .map_err(|err| (err.to_string(), payload_category(&err)));
            }
            entry
                .payload(&opened.source, alternates)
                .map_err(|err| (err.to_string(), payload_category(&err)))
        };
        match opened_payload() {
            Ok(mut payload) => {
                let mut buffer = vec![0u8; COPY_BUFFER];
                loop {
                    if self.cancelled() {
                        self.stop("cancelled");
                        status = "failed";
                        error_category = Some("cancelled");
                        break;
                    }
                    match payload.read_cancellable(&mut buffer, self.cancel) {
                        Ok(0) => break,
                        Ok(read) => {
                            if head.len() < HEAD_LEN {
                                let want = (HEAD_LEN - head.len()).min(read);
                                head.extend_from_slice(&buffer[..want]);
                            }
                            hasher.update(&buffer[..read]);
                            decoded_bytes += read as u64;
                        }
                        Err(err) => {
                            status = "failed";
                            error_category = Some(category(&err));
                            error_message = Some(err.to_string());
                            break;
                        }
                    }
                }
                if status == "decoded" && decoded_bytes != payload.len() {
                    status = "failed";
                    error_category = Some("logical-size");
                    error_message = Some(format!(
                        "the decoded payload holds {decoded_bytes} bytes, not its declared {}",
                        payload.len()
                    ));
                }
            }
            Err((message, category)) => {
                status = "failed";
                error_category = Some(category);
                error_message = Some(message);
            }
        }
        if status == "decoded" {
            self.tally.decoded += 1;
        } else {
            self.tally.failed += 1;
            if let Some(category) = error_category {
                Tally::count(&mut self.tally.by_error, category);
            }
        }
        let classification = classify::classify(classify::Inputs {
            entry_type: entry.type_id(),
            original_extension: None,
            storage: classify::storage_of(entry),
            payload: if status == "decoded" {
                classify::PayloadState::Decoded
            } else {
                classify::PayloadState::Undecodable(error_message.clone().unwrap_or_default())
            },
            head: Some(&head),
        });
        let digest = (status == "decoded").then(|| hex(&hasher.finalize()));
        let record = json!({
            "record": "entry",
            "schema": SCHEMA,
            "archive": selector,
            "selector_path": depth_chain(selector),
            "depth": depth,
            "row": entry.row,
            "type": entry.type_id(),
            "extension": entry.type_id().and_then(native_extension).map(|native| native.extension),
            "hash64": entry.name_hash.as_ref().ok().copied().flatten().map(|hash| format!("0x{hash:016X}")),
            "key32": entry.name_key.as_ref().ok().copied().flatten().map(|key| format!("0x{key:08X}")),
            "layout": location.map(|location| format!("{:?}", location.layout)),
            "payload_offset": location.map(|location| location.payload_offset),
            "stored_size": stored_size,
            "logical_size": logical_size,
            "mode": mode,
            "transform": matches!(entry.payload_transform, Ok(true)),
            "transform_descriptor": {
                "cipher": match &entry.payload_cipher {
                    Ok(None) => Value::Null,
                    Ok(Some(cipher)) => json!({
                        "key_id": format!("0x{:08X}", cipher.key_id),
                        "type": cipher.kind,
                    }),
                    Err(reason) => json!({ "malformed": reason }),
                },
                "range": match &entry.payload_range {
                    Ok(None) => Value::Null,
                    Ok(Some(range)) => json!({
                        "leading": range.leading(),
                        "gap": range.gap(),
                        "length": range.length(),
                        "step": range.step(),
                        "tail": range.tail(),
                    }),
                    Err(reason) => json!({ "malformed": reason }),
                },
            },
            "read_source": match &entry.read_source {
                Ok(None) => json!("main"),
                Ok(Some(index)) => json!(index),
                Err(reason) => json!({ "malformed": reason }),
            },
            "chunk_table": {
                "parsed": chunks.is_some(),
                "encoding": chunks.map(|chunks| chunks.encoding),
                "count": chunks.map(|chunks| chunks.chunks.len()),
                "methods": methods,
                "stored_sum": stored_sum,
                "stored_prefix": prefix_len,
                "prefix_hex": prefix,
            },
            "verification": {
                "status": status,
                "error_category": error_category,
                "error": error_message,
                "chunk_table_parsed": chunks.is_some(),
                "all_chunks_decoded": status == "decoded",
                "logical_size_matched": status == "decoded" && logical_size == Some(decoded_bytes),
                "integrity": if status != "decoded" {
                    Value::Null
                } else if methods.is_empty() {
                    json!("sizes")
                } else if methods.iter().all(|method| *method == 3) {
                    json!("zlib-adler32")
                } else if methods.contains(&3) {
                    json!("zlib-adler32-and-copy")
                } else {
                    json!("sizes-and-copy")
                },
                "decoded_bytes": decoded_bytes,
                "digest_sha256": digest,
                "payload": classification.payload.name(),
                "identification": identification(&classification),
                "format": classification.format_id(),
                "capability": classification.capability.name(),
                "extension": classification.extension(),
            },
        });
        self.record(&record)
    }

    /// Reads the bytes stored before the first chunk, for the record. They are
    /// not part of the decoded payload.
    fn read_prefix(
        &self,
        entry: &Entry,
        opened: &Opened,
        alternates: &[Option<Source>],
        len: u64,
    ) -> Option<String> {
        let location = entry
            .location
            .as_ref()
            .ok()
            .and_then(|value| value.as_ref())?;
        let source = match entry.read_source.as_ref().ok().copied().flatten() {
            None => &opened.source,
            Some(index) => alternates.get(index as usize)?.as_ref()?,
        };
        let take = len.min(64);
        if take == 0 {
            return Some(String::new());
        }
        let mut slice = source.slice(location.payload_offset, take).ok()?;
        let mut bytes = vec![0u8; take as usize];
        let mut read = 0;
        while read < bytes.len() {
            match slice.read(&mut bytes[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(_) => return None,
            }
        }
        bytes.truncate(read);
        Some(hex(&bytes))
    }
}

fn selector(archive: &str, chain: &[u32]) -> String {
    let mut value = archive.to_string();
    for row in chain {
        value.push('!');
        value.push_str(&row.to_string());
    }
    value
}

fn depth_chain(selector: &str) -> Vec<String> {
    selector
        .split('!')
        .skip(1)
        .map(|row| format!("row:{row}"))
        .collect()
}

/// The failure category of a decode error, as a stable label.
fn category(err: &std::io::Error) -> &'static str {
    let text = err.to_string();
    if text.contains("invalid") && text.contains("compressed data") {
        return "chunk-decode";
    }
    if text.contains("chunk") {
        return "chunk-frame";
    }
    if text.contains("prefix") || text.contains("chunks take") {
        return "chunk-frame";
    }
    if text.contains("logical size") || text.contains("declared") {
        return "logical-size";
    }
    if text.contains("ends early") || text.contains("ends before") {
        return "truncated";
    }
    if text.contains("stored bytes end") || text.contains("after the end") {
        return "stored-range";
    }
    if text.contains("cancelled") {
        return "cancelled";
    }
    "decoding"
}

fn payload_category(err: &Error) -> &'static str {
    match err {
        Error::Undecodable { .. } => "unsupported",
        Error::Encoded { .. } => "transform",
        Error::ReadSource { .. } => "read-source",
        Error::Io(_) => "io",
        Error::Invalid(reason) => {
            if reason.contains("chunk") || reason.contains("prefix") {
                "chunk-frame"
            } else if reason.contains("logical") || reason.contains("stored") {
                "sizes"
            } else {
                "metadata"
            }
        }
        Error::TooLarge { .. } | Error::Transformed(_) | Error::Cipher(_) => "metadata",
    }
}

fn identification(classification: &classify::Classification) -> String {
    use classify::Identification;
    match &classification.identification {
        Identification::Format { format, .. } => format!("format:{}", format.id),
        Identification::Resource { header, .. } => format!("resource:segment-{}", header.segment),
        Identification::Xml { root, .. } => match root {
            Some(root) => format!("xml:{root}"),
            None => "xml:unvalidated".to_string(),
        },
        Identification::Signature { signature, .. } => format!("signature:{signature:?}"),
        Identification::Unrecognised => "none".to_string(),
    }
}
