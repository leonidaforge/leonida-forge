//! A census of every entry of every reachable RPF9 archive, classified by the
//! shared model in [`lforge_core::classify`].
//!
//! The census reads each entry's decoded head only. Combinations of entry type,
//! identification, storage, payload state, confidence, extension and capability
//! are counted, with samples that name the archive and row they came from. A
//! nested archive is entered when its payload is an RPF9 archive, in place when
//! its bytes are stored as they are and through temporary storage otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::Source;
use lforge_core::classify::{self, Classification, Context, Identification, Storage};
use lforge_rage9::rpf::metadata::{Entry, StreamTransform};
use serde_json::{Value, json};

use crate::native::{self, Alternates, Opened};

/// The schema of a census document.
pub const CENSUS_SCHEMA: &str = "leonida-forge.rpf9-census/1";
const MAX_METADATA: u64 = 256 * 1024 * 1024;
/// Bytes of a decoded head a sample records.
const SAMPLE_HEAD: usize = 32;
/// Archive names a combination records before it only counts them.
const SAMPLE_ARCHIVES: usize = 8;
const COPY_BUFFER: usize = 1024 * 1024;

/// What a census is allowed to do.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Archives in a chain, counting the root.
    pub max_depth: usize,
    /// Archives opened, roots included.
    pub max_archives: u64,
    /// Entries classified.
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

/// A census request.
pub struct Options {
    /// An archive, or a directory searched for `.rpf` files.
    pub path: PathBuf,
    /// The executable to recognise the metadata key provider in.
    pub executable: Option<PathBuf>,
    /// Enter archives stored inside an archive.
    pub recursive: bool,
    pub limits: Limits,
    /// Samples kept per combination.
    pub samples: usize,
    /// Also emit one record per entry.
    pub entries: bool,
    /// Where to write the census. Defaults to standard output.
    pub output: Option<PathBuf>,
    pub overwrite: bool,
}

/// One counted combination of entry properties.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    entry_type: Option<u8>,
    identification: String,
    storage: String,
    transform: bool,
    payload: &'static str,
    confidence: &'static str,
    capability: &'static str,
    extension: String,
}

/// What one combination has seen.
#[derive(Debug, Default)]
struct Bucket {
    entries: u64,
    archives: BTreeSet<String>,
    samples: Vec<Value>,
}

struct Engine<'a> {
    options: &'a Options,
    cancel: &'a AtomicBool,
    archives: u64,
    entries: u64,
    spooled: u64,
    buckets: BTreeMap<Key, Bucket>,
    types: BTreeMap<Option<u8>, u64>,
    failures: Vec<Value>,
    stopped: Option<&'static str>,
}

/// Runs a census, writing the result to `options.output` or standard output.
pub fn run(options: &Options, cancel: &AtomicBool) -> Result<(), String> {
    let roots = discover(&options.path, cancel)?;
    let mut out = open_output(options)?;
    let mut engine = Engine {
        options,
        cancel,
        archives: 0,
        entries: 0,
        spooled: 0,
        buckets: BTreeMap::new(),
        types: BTreeMap::new(),
        failures: Vec::new(),
        stopped: None,
    };
    let header = json!({
        "record": "header",
        "schema": CENSUS_SCHEMA,
        "root": options.path.display().to_string(),
        "archives": roots.iter().map(|root| root.name.clone()).collect::<Vec<_>>(),
        "recursive": options.recursive,
        "entries_emitted": options.entries,
        "limits": {
            "max_depth": options.limits.max_depth,
            "max_archives": options.limits.max_archives,
            "max_entries": options.limits.max_entries,
            "max_nested_bytes": options.limits.max_nested_bytes,
            "max_spool_bytes": options.limits.max_spool_bytes,
        },
    });
    writeln!(out, "{header}").map_err(|err| err.to_string())?;
    for root in &roots {
        if engine.cancelled() || engine.stopped.is_some() {
            break;
        }
        if let Err(err) = engine.enter_root(root, &mut out) {
            engine.failures.push(json!({
                "archive": root.name.clone(),
                "depth": 0,
                "error": err,
            }));
        }
    }
    let result = engine.summary(&roots);
    writeln!(out, "{result}").map_err(|err| err.to_string())?;
    if options.output.is_some() {
        out.flush().map_err(|err| err.to_string())?;
    }
    Ok(())
}

struct Root {
    path: PathBuf,
    name: String,
}

fn discover(path: &Path, cancel: &AtomicBool) -> Result<Vec<Root>, String> {
    if path.is_file() {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
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

fn open_output(options: &Options) -> Result<Box<dyn Write>, String> {
    match &options.output {
        Some(path) => {
            if path.exists() && !options.overwrite {
                return Err(format!(
                    "{} already exists; pass --overwrite to replace it",
                    path.display()
                ));
            }
            let file = File::create(path)
                .map_err(|err| format!("cannot write {}: {err}", path.display()))?;
            Ok(Box::new(file))
        }
        None => Ok(Box::new(std::io::stdout())),
    }
}

impl Engine<'_> {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn stop(&mut self, limit: &'static str) {
        if self.stopped.is_none() {
            self.stopped = Some(limit);
        }
    }

    fn enter_root(&mut self, root: &Root, out: &mut dyn Write) -> Result<(), String> {
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
        let alternates = Alternates::resolve(&root.path, &opened.metadata);
        let sources = alternates.sources().to_vec();
        self.walk(&opened, &sources, &[], &root.name, 0, out)
    }

    fn walk(
        &mut self,
        opened: &Opened,
        alternates: &[Option<Source>],
        chain: &[u32],
        name: &str,
        depth: usize,
        out: &mut dyn Write,
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
            if self.cancelled() {
                self.stop("cancelled");
                return Ok(());
            }
            let transform = self.transform(entry, opened, alternates);
            let context = Context {
                main: &opened.source,
                alternates,
                transform: transform.as_ref().ok().and_then(|value| value.as_ref()),
                transform_failure: transform.as_ref().err().map(String::as_str),
            };
            let (classification, evidence) =
                classify::classify_entry_with_evidence(entry, None, &context);
            self.entries += 1;
            let mut nested_chain = chain.to_vec();
            nested_chain.push(entry.row);
            let selector = selector(name, &nested_chain);
            self.count(
                &classification,
                name,
                &selector,
                &evidence.head,
                evidence.payload_len,
            );
            if self.options.entries {
                let record = json!({
                    "record": "entry",
                    "archive": name,
                    "chain": selector,
                    "depth": depth,
                    "row": entry.row,
                    "classification": describe(&classification),
                });
                writeln!(out, "{record}").map_err(|err| err.to_string())?;
            }
            if !self.options.recursive || depth + 1 >= self.options.limits.max_depth {
                continue;
            }
            if classification.format_id() != Some("rpf9") {
                continue;
            }
            if self.archives >= self.options.limits.max_archives {
                self.stop("max_archives");
                return Ok(());
            }
            match self.enter_nested(entry, opened, alternates, &selector) {
                Ok(nested) => {
                    self.archives += 1;
                    let nested_name = selector.clone();
                    // `selector` already carries the rows this archive was
                    // reached through, so the nested walk starts empty.
                    let result = self.walk(&nested, &[], &[], &nested_name, depth + 1, out);
                    if let Err(err) = result {
                        self.failures.push(json!({
                            "archive": nested_name,
                            "depth": depth + 1,
                            "error": err,
                        }));
                    }
                }
                Err(err) => {
                    self.failures.push(json!({
                        "archive": selector,
                        "depth": depth + 1,
                        "error": err,
                    }));
                }
            }
        }
        Ok(())
    }

    fn transform(
        &self,
        entry: &Entry,
        opened: &Opened,
        alternates: &[Option<Source>],
    ) -> Result<Option<StreamTransform>, String> {
        if !matches!(entry.payload_transform, Ok(true)) {
            return Ok(None);
        }
        let Some(stream) = opened.stream.as_ref() else {
            return Ok(None);
        };
        stream
            .stream_transform(entry, &opened.source, alternates)
            .map(Some)
            .map_err(|err| format!("row {}: {err}", entry.row))
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
        let source = match contiguous(entry) {
            Some((offset, len)) => opened
                .source
                .slice(offset, len)
                .map_err(|err| format!("row {}: {err}", entry.row))?,
            None => match entry.raw_source(&opened.source, alternates) {
                Ok(source) => source,
                Err(_) => self.spool(entry, opened, alternates)?,
            },
        };
        native::open_metadata_at(
            source,
            selector,
            MAX_METADATA,
            self.options.executable.as_deref(),
            self.cancel,
        )
    }

    fn spool(
        &mut self,
        entry: &Entry,
        opened: &Opened,
        alternates: &[Option<Source>],
    ) -> Result<Source, String> {
        let mut payload = entry
            .payload(&opened.source, alternates)
            .map_err(|err| format!("row {}: {err}", entry.row))?;
        let size = payload.len();
        if size > self.options.limits.max_nested_bytes {
            return Err(format!(
                "row {} stores an archive of {size} bytes, over the --max-nested-bytes limit",
                entry.row
            ));
        }
        if self.spooled + size > self.options.limits.max_spool_bytes {
            self.stop("max_spool_bytes");
            return Err(format!(
                "row {} would exceed the --max-spool-bytes limit",
                entry.row
            ));
        }
        let mut file = tempfile::tempfile()
            .map_err(|err| format!("row {}: cannot create temporary storage: {err}", entry.row))?;
        let mut buffer = vec![0u8; COPY_BUFFER];
        let mut copied = 0u64;
        loop {
            let read = payload
                .read(&mut buffer)
                .map_err(|err| format!("row {}: {err}", entry.row))?;
            if read == 0 {
                break;
            }
            file.write_all(&buffer[..read]).map_err(|err| {
                format!("row {}: cannot write temporary storage: {err}", entry.row)
            })?;
            copied += read as u64;
        }
        self.spooled += copied;
        file.seek(SeekFrom::Start(0))
            .map_err(|err| format!("row {}: {err}", entry.row))?;
        Source::from_file(file).map_err(|err| format!("row {}: {err}", entry.row))
    }

    fn count(
        &mut self,
        classification: &Classification,
        archive: &str,
        selector: &str,
        head: &[u8],
        payload_len: Option<u64>,
    ) {
        *self.types.entry(classification.entry_type).or_default() += 1;
        let key = Key {
            entry_type: classification.entry_type,
            identification: identification_label(&classification.identification),
            storage: classification
                .storage
                .as_ref()
                .map(Storage::label)
                .unwrap_or("no-location")
                .to_string(),
            transform: classification
                .storage
                .is_some_and(|storage| storage.transform),
            payload: classification.payload.name(),
            confidence: classification.identification.confidence().name(),
            capability: classification.capability.name(),
            extension: classification
                .extension()
                .map(str::to_string)
                .unwrap_or_else(|| "-".to_string()),
        };
        let bucket = self.buckets.entry(key).or_default();
        bucket.entries += 1;
        if bucket.archives.len() < SAMPLE_ARCHIVES {
            bucket.archives.insert(archive.to_string());
        }
        if bucket.samples.len() < self.options.samples {
            bucket.samples.push(json!({
                "archive": archive,
                "chain": selector,
                "size": payload_len,
                "head": hex(&head[..head.len().min(SAMPLE_HEAD)]),
            }));
        }
    }

    fn summary(&self, roots: &[Root]) -> Value {
        let combinations: Vec<Value> = self
            .buckets
            .iter()
            .map(|(key, bucket)| {
                json!({
                    "type": key.entry_type,
                    "identification": key.identification,
                    "storage": key.storage,
                    "transform": key.transform,
                    "payload": key.payload,
                    "confidence": key.confidence,
                    "capability": key.capability,
                    "extension": key.extension,
                    "entries": bucket.entries,
                    "archives": bucket.archives.iter().collect::<Vec<_>>(),
                    "samples": bucket.samples,
                })
            })
            .collect();
        let types: Vec<Value> = self
            .types
            .iter()
            .map(|(type_id, entries)| json!({ "type": type_id, "entries": entries }))
            .collect();
        json!({
            "record": "summary",
            "schema": CENSUS_SCHEMA,
            "root": roots.first().map(|root| root.name.clone()),
            "roots": roots.len(),
            "archives": self.archives,
            "entries": self.entries,
            "spooled_bytes": self.spooled,
            "stopped": self.stopped,
            "types": types,
            "combinations": combinations,
            "failures": self.failures,
        })
    }
}

/// `archive!row!row`: the entries a nested archive was reached through.
fn selector(archive: &str, chain: &[u32]) -> String {
    let mut value = archive.to_string();
    for row in chain {
        value.push('!');
        value.push_str(&row.to_string());
    }
    value
}

fn identification_label(identification: &Identification) -> String {
    match identification {
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

fn describe(classification: &Classification) -> Value {
    let storage = classification.storage;
    json!({
        "type": classification.entry_type,
        "storage": storage.as_ref().map(Storage::label),
        "mode": storage.map(|storage| storage.mode),
        "encoding": storage.and_then(|storage| storage.encoding),
        "transform": storage.map(|storage| storage.transform),
        "payload": classification.payload.name(),
        "identification": identification_label(&classification.identification),
        "format": classification.format_id(),
        "confidence": classification.identification.confidence().name(),
        "capability": classification.capability.name(),
        "capability_reason": classification.capability.reason(),
        "extension": classification.extension(),
        "extension_verified": classification.extension.verified(),
        "reason": classification.reason,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Bytes stored before the first chunk of an encoding-2 entry.
const ENCODING_2_PREFIX: u64 = 16;
/// The chunk method that holds a zlib stream. Every other method copies.
const ZLIB_METHOD: u8 = 3;

/// The archive-relative range of an entry whose chunks are all copies, so its
/// bytes can be read where they lie. `None` when any chunk is compressed,
/// padded or shorter than it is stored, and for storage that is not a sequence
/// of chunks.
fn contiguous(entry: &Entry) -> Option<(u64, u64)> {
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
    let prefix = if table.encoding == 2 {
        ENCODING_2_PREFIX
    } else {
        0
    };
    Some((location.payload_offset.checked_add(prefix)?, stored))
}
