//! A census of every entry of every reachable RPF9 archive, classified by the
//! shared model in [`lforge_core::classify`].
//!
//! The census reads each entry's decoded head only. Combinations of entry type,
//! identification, storage, payload state, confidence, extension and capability
//! are counted, with samples that name the archive and row they came from. A
//! nested archive is entered when its payload is an RPF9 archive, in place when
//! its bytes are stored as they are and through temporary storage otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::io::Write;
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
/// Rejected archive candidates kept as evidence; the rest are counted.
const REJECTION_SAMPLES: usize = 8;

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
    /// The name the root is reported under, when `path` is one archive: the
    /// installation-relative path. Every chain and archive identity starts with
    /// it, so two roots that share a basename stay distinct.
    pub root_name: Option<String>,
    /// The executable to recognise the metadata key provider in.
    pub executable: Option<PathBuf>,
    /// Enter archives stored inside an archive.
    pub recursive: bool,
    /// Classify from metadata only: no payload is read, so no format, structure
    /// or capability is claimed.
    pub metadata_only: bool,
    pub limits: Limits,
    /// Samples kept per combination.
    pub samples: usize,
    /// Also emit one record per entry.
    pub entries: bool,
    /// Where to write the census. Defaults to standard output.
    pub output: Option<PathBuf>,
    pub overwrite: bool,
    /// A journal that records each completed archive, so an interrupted run
    /// resumes without counting an archive twice. The identity string binds the
    /// journal to one build, mode, rule set and set of limits.
    pub journal: Option<PathBuf>,
    pub journal_identity: String,
}

/// One counted combination of entry properties.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    entry_type: Option<u8>,
    identification: String,
    /// A normalised shape of the decoded head, so unrelated payloads are not
    /// merged into one bucket and pointer values are not split into thousands.
    variant: String,
    storage: String,
    transform: bool,
    payload: String,
    structure: String,
    capability: String,
    extension: String,
    /// `original`, `native`, `payload` or `unresolved`: where the extension came
    /// from. Two entries with the same extension but different provenance are
    /// different findings.
    extension_provenance: String,
    /// Where the investigation of this entry ends.
    outcome: String,
}

impl Key {
    fn to_json(&self) -> Value {
        json!({
            "type": self.entry_type,
            "identification": self.identification,
            "variant": self.variant,
            "storage": self.storage,
            "transform": self.transform,
            "payload": self.payload,
            "structure": self.structure,
            "capability": self.capability,
            "extension": self.extension,
            "extension_provenance": self.extension_provenance,
            "outcome": self.outcome,
        })
    }

    fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            entry_type: value["type"].as_u64().and_then(|id| u8::try_from(id).ok()),
            identification: value["identification"].as_str()?.to_string(),
            variant: value["variant"].as_str()?.to_string(),
            storage: value["storage"].as_str()?.to_string(),
            transform: value["transform"].as_bool()?,
            payload: value["payload"].as_str()?.to_string(),
            structure: value["structure"].as_str()?.to_string(),
            capability: value["capability"].as_str()?.to_string(),
            extension: value["extension"].as_str()?.to_string(),
            extension_provenance: value["extension_provenance"].as_str()?.to_string(),
            outcome: value["outcome"].as_str()?.to_string(),
        })
    }
}

/// What one combination has seen.
#[derive(Debug, Clone, Default)]
struct Bucket {
    entries: u64,
    /// Every archive the combination was seen in, for the exact count.
    archive_count: BTreeSet<String>,
    /// A bounded representative set of archive names.
    archives: BTreeSet<String>,
    samples: Vec<Value>,
}

impl Bucket {
    fn to_json(&self) -> Value {
        json!({
            "entries": self.entries,
            "archive_count": self.archive_count.iter().collect::<Vec<_>>(),
            "archives": self.archives.iter().collect::<Vec<_>>(),
            "samples": self.samples,
        })
    }

    fn from_json(value: &Value) -> Option<Self> {
        let list = |key: &str| -> Vec<String> {
            value[key]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        };
        Some(Self {
            entries: value["entries"].as_u64()?,
            archive_count: list("archive_count").into_iter().collect(),
            archives: list("archives").into_iter().collect(),
            samples: value["samples"].as_array().cloned().unwrap_or_default(),
        })
    }
}

/// The per-entry counters of one archive, before they are folded into the run.
#[derive(Debug, Clone, Default)]
struct Tally {
    entries: u64,
    probed: u64,
    decoded: u64,
    undecoded: u64,
    structures: u64,
    containers: u64,
    declared: u64,
    unresolved: u64,
    /// The type ids this archive holds, so the run can count the archives of a
    /// type exactly even when an archive is restored from the journal.
    types: BTreeSet<Option<u8>>,
}

impl Tally {
    fn to_json(&self) -> Value {
        json!({
            "entries": self.entries,
            "probed": self.probed,
            "decoded": self.decoded,
            "undecoded": self.undecoded,
            "structures": self.structures,
            "containers": self.containers,
            "declared": self.declared,
            "unresolved": self.unresolved,
            "types": self.types.iter().collect::<Vec<_>>(),
        })
    }

    fn from_json(value: &Value) -> Self {
        let number = |key: &str| value[key].as_u64().unwrap_or(0);
        Self {
            entries: number("entries"),
            probed: number("probed"),
            decoded: number("decoded"),
            undecoded: number("undecoded"),
            structures: number("structures"),
            containers: number("containers"),
            declared: number("declared"),
            unresolved: number("unresolved"),
            types: value["types"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|item| item.as_u64().and_then(|id| u8::try_from(id).ok()))
                .collect(),
        }
    }
}

/// A journal of completed archives.
///
/// Each line is one archive's contribution, written and flushed before the run
/// moves on, so an interruption loses at most the archive in flight. A line
/// that carries a different identity is ignored: a journal from another build,
/// scan mode, rule set or limit set is not this run's progress.
struct Journal {
    path: PathBuf,
    identity: String,
    done: BTreeMap<String, (Vec<(Key, Bucket)>, Tally)>,
    /// Whether the file ends with a newline. A run that was killed mid-write
    /// leaves a partial line, and appending to it would make the first new
    /// record unreadable, so the next append starts a line of its own.
    ends_with_newline: bool,
}

impl Journal {
    fn open(path: &Path, identity: &str) -> Self {
        let mut done: BTreeMap<String, (Vec<(Key, Bucket)>, Tally)> = BTreeMap::new();
        let mut ends_with_newline = true;
        if let Ok(bytes) = fs::read(path) {
            ends_with_newline = bytes.last().is_none_or(|byte| *byte == b'\n');
            for line in String::from_utf8_lossy(&bytes).lines() {
                let Ok(record) = serde_json::from_str::<Value>(line) else {
                    // A truncated last line is an interrupted write, not a
                    // result.
                    continue;
                };
                if record["identity"].as_str() != Some(identity) {
                    continue;
                }
                let Some(chain) = record["archive"].as_str() else {
                    continue;
                };
                // A record without its tally is unusable: the archive's rows
                // would be counted but its entries would not. A record from a
                // run that stopped mid-archive describes work that did not
                // finish, so the archive is walked again.
                if !record["tally"].is_object() || record["complete"].as_bool() != Some(true) {
                    continue;
                }
                let tally = Tally::from_json(&record["tally"]);
                let mut rows = Vec::new();
                for row in record["rows"].as_array().into_iter().flatten() {
                    let (Some(key), Some(bucket)) =
                        (Key::from_json(&row["key"]), Bucket::from_json(row))
                    else {
                        continue;
                    };
                    rows.push((key, bucket));
                }
                done.insert(chain.to_string(), (rows, tally));
            }
        }
        Self {
            path: path.to_path_buf(),
            identity: identity.to_string(),
            done,
            ends_with_newline,
        }
    }

    fn rows(&self, chain: &str) -> Option<&(Vec<(Key, Bucket)>, Tally)> {
        self.done.get(chain)
    }

    /// Appends and flushes one archive's contribution.
    fn append(
        &self,
        chain: &str,
        buckets: &BTreeMap<Key, Bucket>,
        tally: &Tally,
        complete: bool,
    ) -> Result<(), String> {
        let mut rows = Vec::new();
        for (key, bucket) in buckets {
            let mut row = bucket.to_json();
            row["key"] = key.to_json();
            rows.push(row);
        }
        let record = json!({
            "identity": self.identity,
            "archive": chain,
            "complete": complete,
            "tally": tally.to_json(),
            "rows": rows,
        });
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|err| format!("cannot open the journal: {err}"))?;
        if !self.ends_with_newline {
            // The previous run was killed between a record's bytes and its
            // newline; the partial line is ignored on the next open, so start a
            // fresh one instead of extending it.
            writeln!(file).map_err(|err| format!("cannot write the journal: {err}"))?;
        }
        writeln!(file, "{record}").map_err(|err| format!("cannot write the journal: {err}"))?;
        file.flush()
            .map_err(|err| format!("cannot flush the journal: {err}"))?;
        file.sync_data()
            .map_err(|err| format!("cannot sync the journal: {err}"))
    }
}

struct Engine<'a> {
    options: &'a Options,
    cancel: &'a AtomicBool,
    journal: Option<Journal>,
    archives: u64,
    resumed: u64,
    roots_opened: u64,
    entries: u64,
    spooled: u64,
    probed: u64,
    decoded: u64,
    undecoded: u64,
    structures: u64,
    containers: u64,
    declared: u64,
    unresolved: u64,
    buckets: BTreeMap<Key, Bucket>,
    types: BTreeMap<Option<u8>, TypeCount>,
    failures: Vec<Value>,
    /// Rows the declared type made archive candidates that did not open as an
    /// archive. Not failures: the bytes said otherwise, and the row keeps its
    /// own classification.
    rejected: u64,
    rejections: Vec<Value>,
    stopped: Option<&'static str>,
}

/// What the run has seen of one entry type.
#[derive(Debug, Default)]
struct TypeCount {
    entries: u64,
    /// Every archive that holds an entry of this type, exactly.
    archives: BTreeSet<String>,
}

/// Runs a census, writing the result to `options.output` or standard output.
///
/// The exit status separates three cases a caller must not confuse: a complete
/// census, a census that stopped at a configured limit, and a census in which an
/// archive could not be read. The summary is written in all three, and the
/// status says whether it may be treated as a complete one.
pub fn run(options: &Options, cancel: &AtomicBool) -> Result<(), String> {
    let roots = discover(&options.path, options.root_name.as_deref(), cancel)?;
    let mut out = open_output(options)?;
    let (stopped, failures) = match pass(&roots, options, cancel, &mut out) {
        Ok(result) => result,
        Err(err) => {
            out.abandon();
            return Err(err);
        }
    };
    out.finish()?;
    if let Some(limit) = stopped {
        return Err(format!(
            "the census stopped at {limit}; the summary records what was counted"
        ));
    }
    if failures != 0 {
        return Err(format!(
            "{failures} archive(s) could not be read; the summary records which"
        ));
    }
    Ok(())
}

/// Writes the census. Returns why it stopped, and how many archives failed.
fn pass(
    roots: &[Root],
    options: &Options,
    cancel: &AtomicBool,
    out: &mut Output,
) -> Result<(Option<&'static str>, usize), String> {
    let mut engine = Engine {
        options,
        cancel,
        journal: options
            .journal
            .as_ref()
            .map(|path| Journal::open(path, &options.journal_identity)),
        archives: 0,
        resumed: 0,
        roots_opened: 0,
        entries: 0,
        spooled: 0,
        probed: 0,
        decoded: 0,
        undecoded: 0,
        structures: 0,
        containers: 0,
        declared: 0,
        unresolved: 0,
        buckets: BTreeMap::new(),
        types: BTreeMap::new(),
        failures: Vec::new(),
        rejected: 0,
        rejections: Vec::new(),
        stopped: None,
    };
    let header = json!({
        "record": "header",
        "schema": CENSUS_SCHEMA,
        "root": options.path.display().to_string(),
        "archives": roots.iter().map(|root| root.name.clone()).collect::<Vec<_>>(),
        "recursive": options.recursive,
        "metadata_only": options.metadata_only,
        "entries_emitted": options.entries,
        "limits": {
            "max_depth": options.limits.max_depth,
            "max_archives": options.limits.max_archives,
            "max_entries": options.limits.max_entries,
            "max_nested_bytes": options.limits.max_nested_bytes,
            "max_spool_bytes": options.limits.max_spool_bytes,
        },
    });
    writeln!(out.writer, "{header}").map_err(|err| err.to_string())?;
    for root in roots {
        if engine.cancelled() || engine.stopped.is_some() {
            break;
        }
        if let Err(err) = engine.enter_root(root, &mut out.writer) {
            engine.failures.push(json!({
                "archive": root.name.clone(),
                "depth": 0,
                "error": err,
            }));
        }
    }
    let result = engine.summary(roots);
    writeln!(out.writer, "{result}").map_err(|err| err.to_string())?;
    Ok((engine.stopped, engine.failures.len()))
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

/// Where the census is written, and how it reaches its final name.
///
/// A run writes to a temporary file beside the target and renames it into place
/// only after the summary is written and flushed, so a reader never sees a
/// half-written census and an interrupted run never replaces the previous one.
struct Output {
    writer: Box<dyn Write>,
    /// `(temporary, target)`, present when writing to a file.
    publish: Option<(PathBuf, PathBuf)>,
}

impl Output {
    fn finish(mut self) -> Result<(), String> {
        self.writer.flush().map_err(|err| err.to_string())?;
        let Some((temporary, target)) = self.publish.take() else {
            return Ok(());
        };
        drop(self.writer);
        fs::rename(&temporary, &target).map_err(|err| {
            format!(
                "cannot publish {} as {}: {err}",
                temporary.display(),
                target.display()
            )
        })
    }

    /// Removes the temporary file of a run that did not finish.
    fn abandon(&mut self) {
        if let Some((temporary, _)) = self.publish.take() {
            let _ = fs::remove_file(temporary);
        }
    }
}

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
            Ok(Output {
                writer: Box::new(file),
                publish: Some((temporary, path.clone())),
            })
        }
        None => Ok(Output {
            writer: Box::new(std::io::stdout()),
            publish: None,
        }),
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

    /// Records a declared-archive candidate that the bytes did not open.
    fn reject(&mut self, chain: &str, depth: usize, entry_type: Option<u8>, error: String) {
        self.rejected += 1;
        if self.rejections.len() < REJECTION_SAMPLES {
            self.rejections.push(json!({
                "archive": chain,
                "depth": depth,
                "row_type": entry_type,
                "error": error,
            }));
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
        self.roots_opened += 1;
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
        // An archive already journalled by this run contributes its recorded
        // rows instead of being walked again.
        let recorded = self
            .journal
            .as_ref()
            .and_then(|journal| journal.rows(name))
            .cloned();
        if let Some((rows, tally)) = recorded {
            for (key, bucket) in &rows {
                self.apply(key, bucket);
            }
            self.record_types(name, &tally.types);
            self.fold(&tally);
            self.resumed += 1;
            return Ok(());
        }
        let mut buckets: BTreeMap<Key, Bucket> = BTreeMap::new();
        let mut tally = Tally::default();
        let rows: Vec<Entry> = opened.metadata.entries().collect();
        for entry in &rows {
            if self.entries + tally.entries >= self.options.limits.max_entries {
                self.stop("max_entries");
                break;
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
            let (classification, evidence) = if self.options.metadata_only {
                (
                    classify::classify(classify::Inputs {
                        entry_type: entry.type_id(),
                        original_extension: None,
                        storage: classify::storage_of(entry),
                        payload: classify::PayloadState::NotRead,
                        head: None,
                    }),
                    classify::Evidence::default(),
                )
            } else {
                classify::classify_entry_with_evidence(entry, None, &context)
            };
            let mut nested_chain = chain.to_vec();
            nested_chain.push(entry.row);
            let selector = selector(name, &nested_chain);
            Self::count(
                &mut buckets,
                &mut tally,
                self.options.samples,
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
            // An RPF9 payload is an archive. A row whose declared type is the
            // archive type is a candidate even when no payload was read: a
            // metadata pass must still find archives it has not opened yet.
            let payload_is_archive = classification.format_id() == Some("rpf9");
            let archive_candidate =
                payload_is_archive || classification.declared_asset() == Some("rpf");
            if !archive_candidate {
                continue;
            }
            if self.archives >= self.options.limits.max_archives {
                self.stop("max_archives");
                break;
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
                // The payload's own magic said archive, so not opening it is a
                // failure to read an archive.
                Err(err) if payload_is_archive => {
                    self.failures.push(json!({
                        "archive": selector,
                        "depth": depth + 1,
                        "error": err,
                    }));
                }
                // Only the row's declared type suggested an archive. The bytes
                // did not open as one, which is not a failure to read an
                // archive: it is this census declining to call the entry one.
                // The row keeps its own classification, and the payload pass
                // says what it actually holds.
                Err(err) => self.reject(&selector, depth + 1, classification.entry_type, err),
            }
        }
        self.merge(name, &buckets, &tally);
        if let Some(journal) = self.journal.as_ref() {
            // A stopped archive keeps its rows but is never resumed as done.
            let complete = self.stopped.is_none();
            journal.append(name, &buckets, &tally, complete)?;
        }
        Ok(())
    }

    /// Folds one archive's contribution into the run, exactly once.
    fn merge(&mut self, name: &str, buckets: &BTreeMap<Key, Bucket>, tally: &Tally) {
        for (key, bucket) in buckets {
            self.apply(key, bucket);
        }
        self.record_types(name, &tally.types);
        self.fold(tally);
    }

    /// Remembers that `name` holds each of `types`, so the archives of a type
    /// are counted exactly and never by a representative list.
    fn record_types(&mut self, name: &str, types: &BTreeSet<Option<u8>>) {
        for type_id in types {
            self.types
                .entry(*type_id)
                .or_default()
                .archives
                .insert(name.to_string());
        }
    }

    /// Adds one combination's rows, without its counters.
    fn apply(&mut self, key: &Key, bucket: &Bucket) {
        self.types.entry(key.entry_type).or_default().entries += bucket.entries;
        let samples = self.options.samples;
        let existing = self.buckets.entry(key.clone()).or_default();
        existing.entries += bucket.entries;
        existing
            .archive_count
            .extend(bucket.archive_count.iter().cloned());
        for archive in &bucket.archives {
            if existing.archives.len() < SAMPLE_ARCHIVES {
                existing.archives.insert(archive.clone());
            }
        }
        for sample in &bucket.samples {
            if existing.samples.len() < samples {
                existing.samples.push(sample.clone());
            }
        }
    }

    /// Adds one archive's counters.
    fn fold(&mut self, tally: &Tally) {
        self.entries += tally.entries;
        self.probed += tally.probed;
        self.decoded += tally.decoded;
        self.undecoded += tally.undecoded;
        self.structures += tally.structures;
        self.containers += tally.containers;
        self.declared += tally.declared;
        self.unresolved += tally.unresolved;
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
                Err(format!("row {} would exceed the --max-spool-bytes limit", entry.row))
            }
            Err(err) => Err(err.to_string()),
        }
    }

    /// Adds one entry to an archive's own map and counters, so the archive's
    /// contribution can be folded in and journalled as a unit.
    #[allow(clippy::too_many_arguments)]
    fn count(
        buckets: &mut BTreeMap<Key, Bucket>,
        tally: &mut Tally,
        samples: usize,
        classification: &Classification,
        archive: &str,
        selector: &str,
        head: &[u8],
        payload_len: Option<u64>,
    ) {
        tally.entries += 1;
        tally.types.insert(classification.entry_type);
        match classification.payload.name() {
            "decoded" => {
                tally.probed += 1;
                tally.decoded += 1;
            }
            "not-read" => {}
            _ => {
                tally.probed += 1;
                tally.undecoded += 1;
            }
        }
        let claims = classification.identification.claims();
        if claims.structure == lforge_core::classify::Confidence::Verified {
            tally.structures += 1;
        }
        if matches!(
            classification.identification,
            Identification::Resource { .. }
        ) {
            tally.containers += 1;
        }
        if classification.declared_asset().is_some() {
            tally.declared += 1;
        }
        if matches!(classification.identification, Identification::Unrecognised) {
            tally.unresolved += 1;
        }
        let key = Key {
            entry_type: classification.entry_type,
            identification: identification_label(&classification.identification),
            variant: header_variant(classification, head),
            storage: classification
                .storage
                .as_ref()
                .map(Storage::label)
                .unwrap_or("no-location")
                .to_string(),
            transform: classification
                .storage
                .is_some_and(|storage| storage.transform),
            payload: classification.payload.name().to_string(),
            structure: classification
                .identification
                .claims()
                .structure
                .name()
                .to_string(),
            capability: classification.capability.name().to_string(),
            extension: classification
                .extension()
                .map(str::to_string)
                .unwrap_or_else(|| "-".to_string()),
            extension_provenance: classification.extension.provenance().to_string(),
            outcome: classification.outcome().name().to_string(),
        };
        let bucket = buckets.entry(key).or_default();
        bucket.entries += 1;
        // Exact archive count; the names stay a bounded representative set.
        bucket.archive_count.insert(archive.to_string());
        if bucket.archives.len() < SAMPLE_ARCHIVES {
            bucket.archives.insert(archive.to_string());
        }
        if bucket.samples.len() < samples {
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
                    "variant": key.variant,
                    "storage": key.storage,
                    "transform": key.transform,
                    "payload": key.payload,
                    "structure": key.structure,
                    "capability": key.capability,
                    "extension": key.extension,
                    "extension_provenance": key.extension_provenance,
                    "outcome": key.outcome,
                    "entries": bucket.entries,
                    "archive_count": bucket.archive_count.len(),
                    "archives": bucket.archives.iter().collect::<Vec<_>>(),
                    "samples": bucket.samples,
                })
            })
            .collect();
        let types: Vec<Value> = self
            .types
            .iter()
            .map(|(type_id, count)| {
                json!({
                    "type": type_id,
                    "entries": count.entries,
                    "archives": count.archives.len(),
                })
            })
            .collect();
        // Every entry has exactly one outcome, so these counts add up to the
        // entry count.
        let mut outcomes: BTreeMap<&str, u64> = BTreeMap::new();
        for (key, bucket) in &self.buckets {
            *outcomes.entry(key.outcome.as_str()).or_default() += bucket.entries;
        }
        json!({
            "record": "summary",
            "schema": CENSUS_SCHEMA,
            "root": roots.first().map(|root| root.name.clone()),
            "roots": roots.len(),
            "metadata_only": self.options.metadata_only,
            "archives": self.archives,
            "resumed_archives": self.resumed,
            "entries": self.entries,
            "spooled_bytes": self.spooled,
            "stopped": self.stopped,
            // What a caller needs in order to decide whether this summary may
            // be treated as a complete census of the root. `complete` is about
            // enumeration: an entry whose payload could not be decoded is still
            // an entry that was enumerated, and its outcome says so. A stopped
            // run cannot say how many rows it never reached, so it says that it
            // stopped instead of inventing a count.
            "completion": {
                "complete": self.stopped.is_none() && self.failures.is_empty(),
                "stopped": self.stopped,
                "failed_archives": self.failures.len(),
                "roots_discovered": roots.len(),
                "roots_opened": self.roots_opened,
            },
            "coverage": {
                "roots_discovered": roots.len(),
                "roots_opened": self.roots_opened,
                "archives_opened": self.archives,
                "nested_archives_opened": self.archives.saturating_sub(self.roots_opened),
                "failed_archives": self.failures.len(),
                "rejected_archive_candidates": self.rejected,
                "entries_enumerated": self.entries,
                "entries_probed": self.probed,
                "entries_decoded": self.decoded,
                "entries_undecoded": self.undecoded,
                "structures_verified": self.structures,
                "containers_identified": self.containers,
                "declared_asset_classes": self.declared,
                "unresolved_formats": self.unresolved,
            },
            "types": types,
            "outcomes": outcomes,
            "combinations": combinations,
            "failures": self.failures,
            "rejections": self.rejections,
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

/// A normalised shape of the decoded head.
///
/// The point is to keep unrelated payloads apart without splitting on every
/// pointer, length or count. A format is already discriminated by its
/// recogniser. A resource keeps its segment and the 32-bit word at `+0x10`,
/// which is where observed families differ. Anything else is placed by what the
/// first bytes look like.
fn header_variant(classification: &Classification, head: &[u8]) -> String {
    match &classification.identification {
        Identification::Format { format, .. } => format!("format:{}", format.id),
        Identification::Resource { header, .. } => {
            // A resource pointer's numeric value is an instance, not a format.
            // What can be compared between entries is the shape of the fields
            // around it, so the raw values stay in the samples.
            let word = |offset: usize| {
                head.get(offset..offset + 4)
                    .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            };
            format!(
                "resource:s{}:{}+{}",
                header.segment,
                field_kind(word(0x10)),
                field_kind(word(0x18))
            )
        }
        Identification::Xml { root, .. } => match root {
            Some(root) => format!("xml:{root}"),
            None => "xml:unvalidated".to_string(),
        },
        Identification::Signature { signature, .. } => format!("signature:{signature:?}"),
        Identification::Unrecognised => {
            if classification.payload.name() == "not-read" {
                return "not-read".to_string();
            }
            let first = head.get(..8).unwrap_or(head);
            if first.is_empty() {
                "empty".to_string()
            } else if first.iter().all(|byte| *byte == 0) {
                "zeros".to_string()
            } else if first
                .iter()
                .all(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
            {
                "text".to_string()
            } else {
                let mut label = String::from("binary:");
                for byte in first.iter().take(4) {
                    use std::fmt::Write as _;
                    let _ = write!(label, "{byte:02x}");
                }
                label
            }
        }
    }
}

/// The structural kind of a 32-bit field, for grouping entries without
/// splitting on instance values.
fn field_kind(word: Option<u32>) -> String {
    let Some(word) = word else {
        return "absent".to_string();
    };
    if word == 0 {
        return "zero".to_string();
    }
    // A RAGE pointer carries its segment in the top nibble and an aligned
    // offset below it.
    let segment = (word >> 28) & 0xF;
    let aligned = word & 0xF == 0;
    if matches!(segment, 5 | 6) && aligned {
        return format!("ptr:seg{segment}");
    }
    if word < 0x1_0000 {
        return "small".to_string();
    }
    let bytes = word.to_le_bytes();
    if bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == 0)
    {
        let text: String = bytes
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as char)
            .collect();
        return format!("tag:{text}");
    }
    "other".to_string()
}

fn describe(classification: &Classification) -> Value {
    let storage = classification.storage;
    let claims = classification.identification.claims();
    json!({
        "type": classification.entry_type,
        "native_extension": classification.native_extension(),
        "storage": storage.as_ref().map(Storage::label),
        "mode": storage.map(|storage| storage.mode),
        "encoding": storage.and_then(|storage| storage.encoding),
        "transform": storage.map(|storage| storage.transform),
        "payload": classification.payload.name(),
        "identification": identification_label(&classification.identification),
        "format": classification.format_id(),
        "claims": {
            "signature": claims.signature.name(),
            "structure": claims.structure.name(),
            "asset": claims.asset.name(),
        },
        "capability": classification.capability.name(),
        "capability_reason": classification.capability.reason(),
        "outcome": classification.outcome().name(),
        "extension": classification.extension(),
        "extension_provenance": classification.extension.provenance(),
        "extension_verified": classification.extension.verified(),
        "conflict": classification.conflict,
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

