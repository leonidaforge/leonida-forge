//! `lforge names`: build a native-hash index, harvest candidate strings and
//! export validated LUT mappings.
//!
//! The index and the harvest share one archive pass. Every match is local
//! evidence: it proves that the candidate text hashes to a stored key, not
//! that the game used the text as a filename. Detailed observations go to a
//! user-supplied JSONL file; summaries never contain the strings themselves.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Subcommand;
use lforge_binary::pe::ExecutableView;
use lforge_rage9::rbf0::{self, TextKind};
use lforge_rage9::rpf::metadata::{Entry, Error as MetadataError};
#[cfg(test)]
use lforge_rage9::rpf::names::VariantKind;
use lforge_rage9::rpf::names::{
    Class, HashIndex, Key, Limits as StringLimits, Lut, Occurrence, Types, Variant,
    candidate_variants, extract_strings, hash_variant,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::native::{self, Alternates, Opened};
use crate::output;

const MAX_METADATA: u64 = 256 * 1024 * 1024;
const MAX_JSONL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_JSONL_LINES: usize = 2_000_000;
const MAX_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SECTION_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MATCHES: usize = 100_000;
const MAX_HASHED: usize = 1_000_000;

#[derive(Subcommand)]
pub enum Command {
    /// Build an in-memory hash index of authenticated native RPF9 rows under a
    /// directory
    Index {
        /// Directory searched recursively for .rpf files
        directory: PathBuf,
        /// Executable that authenticates processed metadata
        #[arg(long)]
        executable: PathBuf,
        #[arg(long, default_value_t = 64)]
        max_archives: usize,
        #[arg(long, default_value_t = 32)]
        max_depth: usize,
        #[arg(long, default_value_t = 1_000_000)]
        max_rows: usize,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Harvest candidate strings, match them against the native index and write
    /// local JSONL evidence
    Harvest {
        directory: PathBuf,
        #[arg(long)]
        executable: PathBuf,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "payloads,executable",
            value_name = "SOURCES"
        )]
        sources: Vec<SourceKind>,
        #[arg(long)]
        output: PathBuf,
        /// Replace an existing JSONL file
        #[arg(long)]
        overwrite: bool,
        #[arg(long, default_value_t = 64)]
        max_archives: usize,
        #[arg(long, default_value_t = 32)]
        max_depth: usize,
        #[arg(long, default_value_t = 1_000_000)]
        max_rows: usize,
        #[arg(long, default_value_t = MAX_PAYLOAD_BYTES)]
        max_payload_bytes: u64,
        #[arg(long, default_value_t = MAX_TOTAL_BYTES)]
        max_total_bytes: u64,
        #[arg(long, default_value_t = 200_000)]
        max_strings: usize,
        #[arg(long, default_value_t = MAX_MATCHES)]
        max_matches: usize,
        /// Print a summary as JSON
        #[arg(long)]
        json: bool,
    },
    /// Convert harvest JSONL into validated LUT files
    Export {
        input: PathBuf,
        #[arg(long, default_value = "lut")]
        format: String,
        #[arg(long)]
        output: PathBuf,
        /// Include records that are not hash-verified
        #[arg(long)]
        include_unconfirmed: bool,
        /// Replace existing LUT files
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        json: bool,
    },
    /// Revalidate LUT records and compare the bundled tables with a Research
    /// checkout. Reads only; writes nothing
    Audit {
        /// A directory holding `rpf9-hash64.lut` and `rpf9-key32.lut` to audit
        /// instead of the bundled tables
        #[arg(long)]
        lut: Option<PathBuf>,
        /// A Research checkout's `names` directory to compare with
        #[arg(long)]
        research: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Payloads,
    Executable,
}

impl FromStr for SourceKind {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "payloads" => Ok(SourceKind::Payloads),
            "executable" => Ok(SourceKind::Executable),
            _ => Err(format!("'{text}' is not payloads or executable")),
        }
    }
}

pub fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Index {
            directory,
            executable,
            max_archives,
            max_depth,
            max_rows,
            json,
        } => {
            let cancel = AtomicBool::new(false);
            let discovery = discover(
                &directory,
                &executable,
                ScanLimits {
                    max_depth,
                    max_archives,
                    max_rows,
                },
                &cancel,
            )?;
            let summary = discovery.summary(&directory, &executable);
            if json {
                print_json(&summary)
            } else {
                print_index_text(&summary)
            }
        }
        Command::Harvest {
            directory,
            executable,
            sources,
            output,
            overwrite,
            max_archives,
            max_depth,
            max_rows,
            max_payload_bytes,
            max_total_bytes,
            max_strings,
            max_matches,
            json,
        } => {
            let cancel = AtomicBool::new(false);
            let discovery = discover(
                &directory,
                &executable,
                ScanLimits {
                    max_depth,
                    max_archives,
                    max_rows,
                },
                &cancel,
            )?;
            let mut harvest = Harvester::new(
                &discovery,
                HarvestLimits {
                    payload_bytes: max_payload_bytes,
                    total_bytes: max_total_bytes,
                    strings: max_strings,
                    matches: max_matches,
                },
                &cancel,
            );
            for source in sources {
                match source {
                    SourceKind::Payloads => harvest.payloads()?,
                    SourceKind::Executable => harvest.executable(&executable)?,
                }
            }
            harvest.finish(&output, overwrite)?;
            let summary = harvest.summary(&directory, &executable, &output);
            if json {
                print_json(&summary)
            } else {
                print_harvest_text(&summary)
            }
        }
        Command::Export {
            input,
            format,
            output,
            include_unconfirmed,
            overwrite,
            json,
        } => {
            if format != "lut" {
                return Err(format!("'{format}' is not a supported export format"));
            }
            let summary = export_lut(&input, &output, include_unconfirmed, overwrite)?;
            let value = serde_json::to_value(&summary).map_err(|err| err.to_string())?;
            if json {
                print_json(&value)
            } else {
                println!(
                    "exported {} mappings in {} file(s)",
                    summary.mappings,
                    summary.files.len()
                );
                for file in &summary.files {
                    println!(
                        "  {}: {} mappings, {} unverified, {} ambiguous hashes",
                        file.path, file.mappings, file.unverified, file.ambiguous_hashes
                    );
                }
                Ok(())
            }
        }
        Command::Audit {
            lut,
            research,
            json,
        } => audit(lut.as_deref(), research.as_deref(), json),
    }
}

fn print_json(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|err| err.to_string())?;
    println!("{text}");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_archives: usize,
    pub max_rows: usize,
}

struct IndexedArchive {
    relative: String,
    opened: Opened,
    alternates: Alternates,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize)]
struct Skipped {
    path: String,
    reason: String,
}

struct Discovery {
    archives: Vec<IndexedArchive>,
    index: HashIndex,
    skipped: Vec<Skipped>,
    discovered: usize,
    truncated: bool,
    types: Types,
    namespace_rows: NamespaceRows,
    type_rows: BTreeMap<Option<u8>, TypeRows>,
}

/// One matched row, by archive path and row number.
type RowId = (String, u32);
/// Record count and the distinct rows one source produced.
type SourceStats = (usize, BTreeSet<RowId>);
/// Record count, distinct keys and distinct rows of one source and namespace.
type ProvenanceStats = (usize, BTreeSet<String>, BTreeSet<RowId>);

#[derive(Debug, Clone, Default, Serialize)]
struct NamespaceRows {
    hash64: usize,
    key32: usize,
    unknown: usize,
}

/// How the rows of one type ID populate the two key columns. This is
/// observation, not a class assignment: the namespace a type uses is only
/// established when its class is.
#[derive(Debug, Clone, Default, Serialize)]
struct TypeRows {
    rows: usize,
    hash64_only: usize,
    key32_only: usize,
    both: usize,
    neither: usize,
}

impl TypeRows {
    fn add(&mut self, hash: bool, key: bool) {
        self.rows += 1;
        match (hash, key) {
            (true, true) => self.both += 1,
            (true, false) => self.hash64_only += 1,
            (false, true) => self.key32_only += 1,
            (false, false) => self.neither += 1,
        }
    }
}

impl Discovery {
    fn summary(&self, root: &Path, executable: &Path) -> Value {
        json!({
            "root": root.display().to_string(),
            "executable": executable.display().to_string(),
            "discovered": self.discovered,
            "indexed": self.archives.len(),
            "truncated": self.truncated,
            "rows": self.index.rows(),
            "namespace_rows": self.namespace_rows,
            "type_rows": self
                .type_rows
                .iter()
                .map(|(type_id, rows)| {
                    let mut value = serde_json::to_value(rows).unwrap_or(Value::Null);
                    value["type_id"] = match type_id {
                        Some(type_id) => json!(type_id),
                        None => Value::Null,
                    };
                    value["namespace"] = match type_id.and_then(|t| self.types.class(t)) {
                        Some(Class::Hash64) => json!("hash64"),
                        Some(Class::Key32) => json!("key32"),
                        None => Value::Null,
                    };
                    value
                })
                .collect::<Vec<_>>(),
            "unique_keys": {
                "hash64": self.index.unique_keys_in(Class::Hash64),
                "key32": self.index.unique_keys_in(Class::Key32),
            },
            "occurrences": self.index.occurrences(),
            "skipped": self.skipped,
        })
    }
}

fn print_index_text(summary: &Value) -> Result<(), String> {
    println!(
        "archives:    {} indexed of {} discovered",
        summary["indexed"], summary["discovered"]
    );
    println!("rows:        {}", summary["rows"]);
    println!(
        "namespaces:  {} hash64, {} key32, {} unknown",
        summary["namespace_rows"]["hash64"],
        summary["namespace_rows"]["key32"],
        summary["namespace_rows"]["unknown"]
    );
    for rows in summary["type_rows"].as_array().into_iter().flatten() {
        let type_id = match &rows["type_id"] {
            Value::Null => "none".to_string(),
            other => other.to_string(),
        };
        println!(
            "type {type_id:<4} {:>6} rows: {} hash64-only, {} key32-only, {} both, {} neither, \
             namespace {}",
            rows["rows"],
            rows["hash64_only"],
            rows["key32_only"],
            rows["both"],
            rows["neither"],
            match &rows["namespace"] {
                Value::Null => "unknown",
                Value::String(namespace) => namespace.as_str(),
                _ => "?",
            }
        );
    }
    println!(
        "unique keys: {} hash64, {} key32",
        summary["unique_keys"]["hash64"], summary["unique_keys"]["key32"]
    );
    if summary["truncated"] == json!(true) {
        println!("truncated:   yes");
    }
    for skipped in summary["skipped"].as_array().into_iter().flatten() {
        println!(
            "skipped:     {}: {}",
            skipped["path"].as_str().unwrap_or("?"),
            skipped["reason"].as_str().unwrap_or("?")
        );
    }
    Ok(())
}

fn discover(
    root: &Path,
    executable: &Path,
    limits: ScanLimits,
    cancel: &AtomicBool,
) -> Result<Discovery, String> {
    let (paths, truncated) = collect_archives(root, limits, cancel)?;
    let mut discovery = Discovery {
        archives: Vec::new(),
        index: HashIndex::default(),
        skipped: Vec::new(),
        discovered: paths.len(),
        truncated,
        types: Types::default(),
        namespace_rows: NamespaceRows::default(),
        type_rows: BTreeMap::new(),
    };
    for path in paths {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        if discovery.index.rows() >= limits.max_rows {
            discovery.truncated = true;
            break;
        }
        let opened = match native::open_metadata_cancellable(
            &path,
            MAX_METADATA,
            Some(executable),
            cancel,
        ) {
            Ok(opened) => opened,
            Err(reason) => {
                discovery.skipped.push(Skipped {
                    path: relative(root, &path),
                    reason,
                });
                continue;
            }
        };
        let entries: Vec<Entry> = opened.metadata.entries().collect();
        if discovery.index.rows() + entries.len() > limits.max_rows {
            discovery.truncated = true;
            break;
        }
        let relative_path = relative(root, &path);
        for entry in &entries {
            let (hash, key) = hash_of(entry);
            let type_id = entry.type_id();
            discovery
                .index
                .insert_row(discovery.archives.len(), entry.row, type_id, hash, key);
            match row_namespace(&discovery.types, type_id, hash, key) {
                Some(Class::Hash64) => discovery.namespace_rows.hash64 += 1,
                Some(Class::Key32) => discovery.namespace_rows.key32 += 1,
                None => discovery.namespace_rows.unknown += 1,
            }
            discovery
                .type_rows
                .entry(type_id)
                .or_default()
                .add(hash.is_some(), key.is_some());
        }
        let alternates = Alternates::resolve(&path, &opened.metadata);
        discovery.archives.push(IndexedArchive {
            relative: relative_path,
            opened,
            alternates,
            entries,
        });
    }
    Ok(discovery)
}

fn row_namespace(
    types: &Types,
    type_id: Option<u8>,
    hash: Option<u64>,
    key: Option<u32>,
) -> Option<Class> {
    if let Some(class) = type_id.and_then(|type_id| types.class(type_id)) {
        return Some(class);
    }
    match (hash.is_some(), key.is_some()) {
        (true, false) => Some(Class::Hash64),
        (false, true) => Some(Class::Key32),
        _ => None,
    }
}

fn collect_archives(
    root: &Path,
    limits: ScanLimits,
    cancel: &AtomicBool,
) -> Result<(Vec<PathBuf>, bool), String> {
    native::collect_archives(
        root,
        native::ScanLimits {
            max_depth: limits.max_depth,
            max_archives: limits.max_archives,
        },
        cancel,
    )
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn hash_of(entry: &Entry) -> (Option<u64>, Option<u32>) {
    (
        entry.name_hash.as_ref().ok().and_then(|value| *value),
        entry.name_key.as_ref().ok().and_then(|value| *value),
    )
}

fn metadata_reason(err: &MetadataError) -> String {
    match err {
        MetadataError::Encoded { encoding, .. } => (*encoding).to_string(),
        MetadataError::Undecodable { .. } => "unsupported compression".to_string(),
        MetadataError::ReadSource { .. } => "unavailable read source".to_string(),
        MetadataError::Io(_) => "read error".to_string(),
        _ => "malformed payload metadata".to_string(),
    }
}

#[derive(Debug, Clone, Copy)]
struct HarvestLimits {
    payload_bytes: u64,
    total_bytes: u64,
    strings: usize,
    matches: usize,
}

/// The verified text of one payload: a candidate that matches exactly is a
/// field of the parsed RBF0 document, not an arbitrary binary string. A
/// payload in another format, or one that does not parse, contributes
/// nothing, so every candidate stays unlabelled.
#[derive(Default)]
struct VerifiedText {
    names: HashSet<String>,
    strings: HashSet<String>,
    attributes: HashSet<String>,
}

impl VerifiedText {
    fn of(bytes: &[u8], cancel: &AtomicBool) -> Self {
        let mut verified = Self::default();
        if !rbf0::is_rbf0(bytes) {
            return verified;
        }
        let Ok(document) = rbf0::parse(bytes, &rbf0::Limits::default(), cancel) else {
            return verified;
        };
        verified.names.extend(document.field_names);
        verified.strings.extend(document.string_texts);
        verified.attributes.extend(document.attribute_texts);
        verified
    }

    /// Which verified use the candidate is, by the field it came from.
    fn label(&self, candidate: &str) -> Option<&'static str> {
        if self.names.contains(candidate) {
            Some(TextKind::FieldName.name())
        } else if self.strings.contains(candidate) {
            Some(TextKind::StringValue.name())
        } else if self.attributes.contains(candidate) {
            Some(TextKind::AttributeValue.name())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SourceRecord {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    row: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MatchRow {
    archive: String,
    row: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_id: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MatchRecord {
    kind: String,
    candidate: String,
    name: String,
    variant: String,
    variant_kind: String,
    namespace: String,
    hash: String,
    source: SourceRecord,
    /// The RBF0 field the candidate is, when a parsed document defines it.
    /// Absent for an arbitrary string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_as: Option<String>,
    rows: Vec<MatchRow>,
    verified: bool,
    ambiguous: bool,
}

struct Harvester<'a> {
    discovery: &'a Discovery,
    limits: HarvestLimits,
    archive_bytes: u64,
    cancel: &'a AtomicBool,
    records: Vec<MatchRecord>,
    seen: HashSet<(String, String, String, String, String)>,
    key_names: HashMap<(String, String), BTreeSet<String>>,
    matched_rows: HashSet<(usize, u32)>,
    matched_keys: HashSet<(String, String)>,
    hashed: HashSet<(String, String, String)>,
    payloads_examined: usize,
    payloads_readable: usize,
    payloads_skipped: usize,
    payload_skip_reasons: BTreeMap<String, usize>,
    payload_bytes: u64,
    sections: usize,
    sections_skipped: usize,
    executable_bytes: u64,
    strings: usize,
    sensitive: usize,
    truncated: bool,
}

impl<'a> Harvester<'a> {
    fn new(discovery: &'a Discovery, limits: HarvestLimits, cancel: &'a AtomicBool) -> Self {
        let archive_bytes = (limits.total_bytes / discovery.archives.len().max(1) as u64).max(1);
        Self {
            discovery,
            limits,
            archive_bytes,
            cancel,
            records: Vec::new(),
            seen: HashSet::new(),
            key_names: HashMap::new(),
            matched_rows: HashSet::new(),
            matched_keys: HashSet::new(),
            hashed: HashSet::new(),
            payloads_examined: 0,
            payloads_readable: 0,
            payloads_skipped: 0,
            payload_skip_reasons: BTreeMap::new(),
            payload_bytes: 0,
            sections: 0,
            sections_skipped: 0,
            executable_bytes: 0,
            strings: 0,
            sensitive: 0,
            truncated: false,
        }
    }

    fn check_cancel(&self) -> Result<(), String> {
        if self.cancel.load(Ordering::Relaxed) {
            Err("cancelled".to_string())
        } else {
            Ok(())
        }
    }

    fn payloads(&mut self) -> Result<(), String> {
        for archive in &self.discovery.archives {
            if self.payload_bytes >= self.limits.total_bytes {
                self.truncated = true;
                break;
            }
            let mut archive_bytes = 0u64;
            for entry in &archive.entries {
                self.check_cancel()?;
                if self.payload_bytes >= self.limits.total_bytes {
                    self.truncated = true;
                    break;
                }
                if archive_bytes >= self.archive_bytes {
                    self.truncated = true;
                    break;
                }
                self.payloads_examined += 1;
                let mut payload =
                    match entry.payload(&archive.opened.source, archive.alternates.sources()) {
                        Ok(payload) => payload,
                        Err(err) => {
                            self.payloads_skipped += 1;
                            *self
                                .payload_skip_reasons
                                .entry(metadata_reason(&err))
                                .or_default() += 1;
                            continue;
                        }
                    };
                let mut bytes = Vec::new();
                let mut buffer = vec![0u8; 64 * 1024];
                let mut truncated = false;
                loop {
                    self.check_cancel()?;
                    let remaining = self.limits.payload_bytes.saturating_sub(bytes.len() as u64);
                    if remaining == 0 {
                        truncated = payload.len() > bytes.len() as u64;
                        break;
                    }
                    let take = remaining.min(buffer.len() as u64) as usize;
                    match payload.read_cancellable(&mut buffer[..take], self.cancel) {
                        Ok(0) => break,
                        Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                        Err(err) => {
                            self.payloads_skipped += 1;
                            *self
                                .payload_skip_reasons
                                .entry(err.to_string())
                                .or_default() += 1;
                            bytes.clear();
                            break;
                        }
                    }
                }
                if bytes.is_empty() {
                    continue;
                }
                self.payloads_readable += 1;
                self.payload_bytes += bytes.len() as u64;
                archive_bytes += bytes.len() as u64;
                if truncated {
                    self.truncated = true;
                }
                let source = SourceRecord {
                    kind: "payload".to_string(),
                    archive: Some(archive.relative.clone()),
                    row: Some(entry.row),
                    section: None,
                    authentication: Some(archive.opened.authentication.status().to_string()),
                };
                let verified = VerifiedText::of(&bytes, self.cancel);
                let strings = extract_strings(
                    &bytes,
                    StringLimits {
                        min_len: 4,
                        max_len: 512,
                        max_strings: self.limits.strings.min(20_000),
                    },
                );
                self.strings += strings.len();
                for candidate in strings {
                    if self.strings > self.limits.strings {
                        self.truncated = true;
                        break;
                    }
                    if sensitive_candidate(&candidate) {
                        self.sensitive += 1;
                        continue;
                    }
                    self.process_candidate(&candidate, &source, verified.label(&candidate));
                }
            }
        }
        Ok(())
    }

    fn executable(&mut self, path: &Path) -> Result<(), String> {
        let view = ExecutableView::open(path)
            .map_err(|err| format!("cannot open {}: {err}", path.display()))?;
        for section in view.sections() {
            self.check_cancel()?;
            if self.executable_bytes >= self.limits.total_bytes {
                self.truncated = true;
                break;
            }
            if !section.is_initialized() || !section.is_readable() {
                continue;
            }
            let name = section.name().to_string();
            if skip_section(&name) {
                self.sections_skipped += 1;
                continue;
            }
            let range = section.virtual_range();
            let len = range.end.saturating_sub(range.start);
            if len == 0 {
                continue;
            }
            let take = len.min(MAX_SECTION_BYTES).min(
                self.limits
                    .total_bytes
                    .saturating_sub(self.executable_bytes),
            );
            if take < len {
                self.truncated = true;
            }
            if take == 0 {
                break;
            }
            let Ok(bytes) = view.read_rva(range.start, take as usize) else {
                continue;
            };
            self.sections += 1;
            self.executable_bytes += bytes.len() as u64;
            let source = SourceRecord {
                kind: "executable".to_string(),
                archive: None,
                row: None,
                section: Some(name.clone()),
                authentication: None,
            };
            let strings = extract_strings(
                &bytes,
                StringLimits {
                    min_len: 4,
                    max_len: 512,
                    max_strings: self.limits.strings.min(20_000),
                },
            );
            self.strings += strings.len();
            for candidate in strings {
                if self.strings > self.limits.strings {
                    self.truncated = true;
                    break;
                }
                if sensitive_candidate(&candidate) {
                    self.sensitive += 1;
                    continue;
                }
                self.process_candidate(&candidate, &source, None);
            }
        }
        Ok(())
    }

    fn process_candidate(
        &mut self,
        candidate: &str,
        source: &SourceRecord,
        verified_as: Option<&'static str>,
    ) {
        if self.records.len() >= self.limits.matches {
            self.truncated = true;
            return;
        }
        for variant in candidate_variants(candidate) {
            for class in [Class::Hash64, Class::Key32] {
                let Some(key) = hash_variant(&variant, class) else {
                    continue;
                };
                if self.hashed.len() < MAX_HASHED {
                    self.hashed.insert((
                        candidate.to_string(),
                        variant.text.clone(),
                        class.namespace().to_string(),
                    ));
                } else {
                    self.truncated = true;
                }
                let mut rows: Vec<Occurrence> = self
                    .discovery
                    .index
                    .lookup(key)
                    .iter()
                    .copied()
                    .filter(|occurrence| {
                        occurrence_allows(
                            &self.discovery.types,
                            occurrence.type_id,
                            class,
                            &variant,
                        )
                    })
                    .collect();
                rows.sort_by_key(|occurrence| (occurrence.archive, occurrence.row));
                rows.dedup();
                if rows.is_empty() {
                    continue;
                }
                let namespace = class.namespace().to_string();
                let hash = key.canonical();
                let names = self
                    .key_names
                    .entry((namespace.clone(), hash.clone()))
                    .or_default();
                names.insert(variant.display.clone());
                let ambiguous = names.len() > 1;
                let record_key = (
                    namespace.clone(),
                    hash.clone(),
                    variant.display.clone(),
                    variant.kind.text().to_string(),
                    source_id(source),
                );
                if !self.seen.insert(record_key) {
                    continue;
                }
                for occurrence in &rows {
                    self.matched_rows
                        .insert((occurrence.archive, occurrence.row));
                }
                self.matched_keys.insert((namespace.clone(), hash.clone()));
                let rows = rows
                    .into_iter()
                    .filter_map(|occurrence| {
                        let archive = self.discovery.archives.get(occurrence.archive)?;
                        Some(MatchRow {
                            archive: archive.relative.clone(),
                            row: occurrence.row,
                            type_id: occurrence.type_id,
                        })
                    })
                    .collect();
                self.records.push(MatchRecord {
                    kind: "match".to_string(),
                    candidate: candidate.to_string(),
                    name: variant.display.clone(),
                    variant: variant.text.clone(),
                    variant_kind: variant.kind.text().to_string(),
                    namespace,
                    hash,
                    source: source.clone(),
                    verified_as: verified_as.map(str::to_string),
                    rows,
                    verified: true,
                    ambiguous,
                });
            }
        }
    }

    fn finish(&mut self, output_path: &Path, overwrite: bool) -> Result<(), String> {
        for record in &mut self.records {
            record.ambiguous = self
                .key_names
                .get(&(record.namespace.clone(), record.hash.clone()))
                .is_some_and(|names| names.len() > 1);
        }
        self.records.sort_by(|a, b| {
            (&a.namespace, &a.hash, &a.name, &a.variant, &a.source.kind).cmp(&(
                &b.namespace,
                &b.hash,
                &b.name,
                &b.variant,
                &b.source.kind,
            ))
        });
        output::write_file(output_path, overwrite, |writer| {
            let mut written = 0u64;
            for record in &self.records {
                let line = serde_json::to_string(record).map_err(|err| err.to_string())?;
                writeln!(writer, "{line}").map_err(|err| err.to_string())?;
                written += line.len() as u64 + 1;
            }
            Ok(written)
        })?;
        Ok(())
    }

    fn summary(&self, root: &Path, executable: &Path, output_path: &Path) -> Value {
        let mut by_source: BTreeMap<&str, SourceStats> = BTreeMap::new();
        let mut by_namespace: BTreeMap<&str, usize> = BTreeMap::new();
        let mut by_archive: BTreeMap<&str, usize> = BTreeMap::new();
        let mut by_type: BTreeMap<Option<u8>, usize> = BTreeMap::new();
        for record in &self.records {
            let source = by_source.entry(record.source.kind.as_str()).or_default();
            source.0 += 1;
            *by_namespace.entry(record.namespace.as_str()).or_default() += 1;
            for row in &record.rows {
                source.1.insert((row.archive.clone(), row.row));
                *by_archive.entry(row.archive.as_str()).or_default() += 1;
                *by_type.entry(row.type_id).or_default() += 1;
            }
        }
        let ambiguous_keys = self
            .key_names
            .values()
            .filter(|names| names.len() > 1)
            .count();
        json!({
            "root": root.display().to_string(),
            "executable": executable.display().to_string(),
            "output": output_path.display().to_string(),
            "archives": self.discovery.summary(root, executable),
            "payloads": {
                "examined": self.payloads_examined,
                "readable": self.payloads_readable,
                "skipped": self.payloads_skipped,
                "skip_reasons": self.payload_skip_reasons,
                "bytes": self.payload_bytes,
            },
            "executable_section": {
                "sections": self.sections,
                "sections_skipped": self.sections_skipped,
                "bytes": self.executable_bytes,
            },
            "candidates": {
                "strings": self.strings,
                "hashed": self.hashed.len(),
                "sensitive_skipped": self.sensitive,
            },
            "matches": {
                "records": self.records.len(),
                "unique_keys": self.matched_keys.len(),
                "rows": self.matched_rows.len(),
                "verified_fields": self
                    .records
                    .iter()
                    .filter(|record| record.verified_as.is_some())
                    .count(),
                "ambiguous": self.records.iter().filter(|record| record.ambiguous).count(),
                "ambiguous_keys": ambiguous_keys,
                "by_namespace": by_namespace,
                "by_source": by_source
                    .iter()
                    .map(|(kind, (records, rows))| json!({ "kind": kind, "records": records, "rows": rows.len() }))
                    .collect::<Vec<_>>(),
                "by_archive": by_archive,
                "by_type": by_type
                    .iter()
                    .map(|(type_id, rows)| json!({ "type_id": type_id, "rows": rows }))
                    .collect::<Vec<_>>(),
            },
            "unresolved_rows": self.discovery.index.rows() - self.matched_rows.len(),
            "truncated": self.truncated,
        })
    }
}

fn occurrence_allows(types: &Types, type_id: Option<u8>, class: Class, variant: &Variant) -> bool {
    let Some(type_id) = type_id else {
        return false;
    };
    if let Some(row_class) = types.class(type_id)
        && row_class != class
    {
        return false;
    }
    match class {
        Class::Hash64 => extension_of(&variant.display)
            .is_some_and(|extension| types.extension_type(extension.as_bytes()) == Some(type_id)),
        // The 32-bit class is only established for type 255. Other types have
        // no public class table here, so a coincidental 32-bit match is not
        // promoted.
        Class::Key32 => types.class(type_id) == Some(Class::Key32),
    }
}

fn extension_of(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let dot = base.rfind('.')?;
    (dot + 1 < base.len()).then(|| base[dot + 1..].to_string())
}

fn source_id(source: &SourceRecord) -> String {
    match (&source.archive, source.row, &source.section) {
        (Some(archive), Some(row), _) => format!("{archive}#{row}"),
        (_, _, Some(section)) => format!("exe:{section}"),
        _ => source.kind.clone(),
    }
}

fn skip_section(name: &str) -> bool {
    matches!(
        name.trim(),
        ".reloc" | ".pdata" | ".debug" | ".tls" | ".bss" | ".gfids" | ".00cfg"
    )
}

fn sensitive_candidate(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        return true;
    }
    if [
        "\\users\\",
        "/users/",
        "\\appdata\\",
        "/appdata/",
        "\\programdata\\",
        ":\\program files",
        "begin private key",
        "password",
        "passwd",
        "secret",
        "api_key",
        "api-key",
        "authorization:",
        "access_token",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }
    text.len() >= 128
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-' || byte == b'_')
}

#[derive(Debug, Serialize)]
struct ExportSummary {
    input: String,
    output: String,
    mappings: usize,
    skipped: usize,
    unverified: usize,
    ambiguous_hashes: usize,
    /// Which input source and namespace each accepted record came from, with
    /// distinct keys and rows. Aggregate only: never the strings themselves.
    sources: Vec<Value>,
    files: Vec<ExportedFile>,
}

#[derive(Debug, Serialize)]
struct ExportedFile {
    path: String,
    namespace: String,
    mappings: usize,
    verified: usize,
    unverified: usize,
    ambiguous_hashes: usize,
}

fn export_lut(
    input: &Path,
    output: &Path,
    include_unconfirmed: bool,
    overwrite: bool,
) -> Result<ExportSummary, String> {
    let mut mappings: BTreeMap<Class, BTreeMap<u64, BTreeSet<String>>> = BTreeMap::new();
    let mut provenance: BTreeMap<(String, String), ProvenanceStats> = BTreeMap::new();
    let mut skipped = 0;
    let mut unverified = 0;
    let mut bytes = 0u64;
    let mut lines = 0usize;
    let file =
        fs::File::open(input).map_err(|err| format!("cannot open {}: {err}", input.display()))?;
    for line in BufReader::new(file).lines() {
        lines += 1;
        if lines > MAX_JSONL_LINES {
            return Err(format!(
                "{} has more than {MAX_JSONL_LINES} lines",
                input.display()
            ));
        }
        let line = line.map_err(|err| format!("cannot read {}: {err}", input.display()))?;
        bytes += line.len() as u64 + 1;
        if bytes > MAX_JSONL_BYTES {
            return Err(format!(
                "{} is larger than {MAX_JSONL_BYTES} bytes",
                input.display()
            ));
        }
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if value["kind"] != "match" {
            continue;
        }
        let record: MatchRecord = match serde_json::from_value(value) {
            Ok(record) => record,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if !record.verified && !include_unconfirmed {
            unverified += 1;
            continue;
        }
        let Some(class) = Class::parse_namespace(&record.namespace) else {
            skipped += 1;
            continue;
        };
        let Some(key) = parse_canonical(&record.hash, class) else {
            skipped += 1;
            continue;
        };
        let source = provenance
            .entry((record.source.kind.clone(), record.namespace.clone()))
            .or_default();
        source.0 += 1;
        source.1.insert(record.hash.clone());
        for row in &record.rows {
            source.2.insert((row.archive.clone(), row.row));
        }
        mappings
            .entry(class)
            .or_default()
            .entry(key.value())
            .or_default()
            .insert(record.name);
    }
    if mappings.is_empty() {
        return Err("no verified mappings were found".to_string());
    }
    let multiple = mappings.len() > 1;
    let mut files = Vec::new();
    let mut total_mappings = 0;
    let mut total_unverified = 0;
    let mut total_ambiguous = 0;
    for (class, by_hash) in mappings {
        let ambiguous = by_hash.values().filter(|names| names.len() > 1).count();
        let built = Lut::new(
            class,
            by_hash.into_iter().flat_map(|(hash, names)| {
                names.into_iter().map(move |name| {
                    let key = match class {
                        Class::Hash64 => Key::Hash64(hash),
                        Class::Key32 => Key::Key32(hash as u32),
                    };
                    (key, name)
                })
            }),
        )
        .map_err(|err| err.to_string())?;
        let mut accepted = Vec::new();
        let mut rejected = 0;
        for entry in built.entries() {
            if entry.verified || include_unconfirmed {
                accepted.push((entry.hash, entry.name.clone()));
            } else {
                rejected += 1;
            }
        }
        if accepted.is_empty() {
            total_unverified += rejected;
            continue;
        }
        let lut = Lut::new(class, accepted).map_err(|err| err.to_string())?;
        let verified = lut.verified();
        let unverified = lut.entries().len() - verified;
        let path = namespace_output(output, class, multiple);
        let text = lut.to_text();
        output::write_file(&path, overwrite, |writer| {
            writer
                .write_all(text.as_bytes())
                .map_err(|err| format!("cannot write {}: {err}", path.display()))?;
            Ok(text.len() as u64)
        })?;
        total_mappings += lut.entries().len();
        total_unverified += unverified;
        total_ambiguous += ambiguous;
        files.push(ExportedFile {
            path: path.display().to_string(),
            namespace: class.namespace().to_string(),
            mappings: lut.entries().len(),
            verified,
            unverified,
            ambiguous_hashes: ambiguous,
        });
    }
    if files.is_empty() {
        return Err("no verified mappings were found".to_string());
    }
    Ok(ExportSummary {
        input: input.display().to_string(),
        output: output.display().to_string(),
        mappings: total_mappings,
        skipped,
        unverified: total_unverified + unverified,
        ambiguous_hashes: total_ambiguous,
        sources: provenance
            .into_iter()
            .map(|((kind, namespace), (records, keys, rows))| {
                json!({
                    "kind": kind,
                    "namespace": namespace,
                    "records": records,
                    "keys": keys.len(),
                    "rows": rows.len(),
                })
            })
            .collect(),
        files,
    })
}

fn parse_canonical(text: &str, class: Class) -> Option<Key> {
    let hex = text.strip_prefix("0x")?;
    if hex.len() != class.width() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let value = u64::from_str_radix(hex, 16).ok()?;
    Some(match class {
        Class::Hash64 => Key::Hash64(value),
        Class::Key32 => Key::Key32(value as u32),
    })
}

fn namespace_output(output: &Path, class: Class, multiple: bool) -> PathBuf {
    if !multiple {
        return output.to_path_buf();
    }
    let stem = output
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "resolved".to_string());
    let name = format!("{stem}.{}.lut", class.namespace());
    output.with_file_name(name)
}

fn print_harvest_text(summary: &Value) -> Result<(), String> {
    println!(
        "archives:    {} indexed of {} discovered",
        summary["archives"]["indexed"], summary["archives"]["discovered"]
    );
    println!("rows:        {}", summary["archives"]["rows"]);
    println!(
        "payloads:    {} readable, {} skipped, {} strings",
        summary["payloads"]["readable"],
        summary["payloads"]["skipped"],
        summary["candidates"]["strings"]
    );
    println!(
        "executable:  {} sections, {} skipped, {} bytes",
        summary["executable_section"]["sections"],
        summary["executable_section"]["sections_skipped"],
        summary["executable_section"]["bytes"]
    );
    println!(
        "matches:     {} records, {} keys, {} rows, {} ambiguous ({} ambiguous keys)",
        summary["matches"]["records"],
        summary["matches"]["unique_keys"],
        summary["matches"]["rows"],
        summary["matches"]["ambiguous"],
        summary["matches"]["ambiguous_keys"]
    );
    println!("unresolved:  {} rows", summary["unresolved_rows"]);
    println!("output:      {}", summary["output"].as_str().unwrap_or("?"));
    Ok(())
}

const AUDIT_SCHEMA: &str = "leonida-forge.lut-audit/1";

#[derive(Debug, Default)]
struct LutAudit {
    file: String,
    namespace: Option<String>,
    entries: usize,
    verified: usize,
    unverified: Vec<String>,
    duplicate_records: usize,
    keys: usize,
    ambiguous_keys: usize,
    ambiguous_examples: Vec<String>,
    normalized_duplicates: usize,
    path_unsafe: usize,
    path_unsafe_examples: Vec<String>,
    extensions: BTreeMap<String, usize>,
    problem: Option<String>,
}

impl LutAudit {
    fn ok(&self) -> bool {
        self.problem.is_none() && self.verified == self.entries
    }

    fn json(&self) -> Value {
        json!({
            "file": self.file,
            "namespace": self.namespace,
            "entries": self.entries,
            "verified": self.verified,
            "unverified": self.unverified.len(),
            "unverified_examples": self.unverified,
            "duplicate_records": self.duplicate_records,
            "keys": self.keys,
            "ambiguous_keys": self.ambiguous_keys,
            "ambiguous_examples": self.ambiguous_examples,
            "normalized_duplicates": self.normalized_duplicates,
            "path_unsafe": self.path_unsafe,
            "path_unsafe_examples": self.path_unsafe_examples,
            "extensions": self.extensions,
            "problem": self.problem,
            "ok": self.ok(),
        })
    }
}

fn audit_one(file: &str, lut: &Lut) -> LutAudit {
    let mut audit = LutAudit {
        file: file.to_string(),
        namespace: Some(lut.namespace().namespace().to_string()),
        entries: lut.entries().len(),
        duplicate_records: lut.duplicates(),
        ..LutAudit::default()
    };
    let mut by_key: BTreeMap<(Class, u64), BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut spellings: BTreeMap<(Class, u64, Vec<u8>), usize> = BTreeMap::new();
    for entry in lut.entries() {
        if entry.verified {
            audit.verified += 1;
        } else if audit.unverified.len() < 20 {
            audit
                .unverified
                .push(format!("{} {}", entry.hash.canonical(), entry.name));
        }
        let normalized = lforge_rage9::rpf::names::table::normalized(&entry.name);
        by_key
            .entry((entry.hash.class(), entry.hash.value()))
            .or_default()
            .insert(normalized.clone());
        *spellings
            .entry((entry.hash.class(), entry.hash.value(), normalized))
            .or_default() += 1;
        if lforge_rage9::rpf::names::relative_path(&entry.name).is_none() {
            audit.path_unsafe += 1;
            if audit.path_unsafe_examples.len() < 20 {
                audit.path_unsafe_examples.push(entry.name.clone());
            }
        }
        if let Some(extension) = extension_of(&entry.name) {
            *audit
                .extensions
                .entry(extension.to_ascii_lowercase())
                .or_default() += 1;
        }
    }
    audit.normalized_duplicates = spellings.values().map(|count| count - 1).sum();
    audit.keys = by_key.len();
    audit.ambiguous_keys = by_key.values().filter(|names| names.len() > 1).count();
    for ((class, value), names) in by_key.iter().filter(|(_, names)| names.len() > 1).take(20) {
        let key = match class {
            Class::Hash64 => Key::Hash64(*value).canonical(),
            Class::Key32 => Key::Key32(*value as u32).canonical(),
        };
        let names: Vec<String> = names
            .iter()
            .map(|name| String::from_utf8_lossy(name).into_owned())
            .collect();
        audit
            .ambiguous_examples
            .push(format!("{key}: {}", names.join(", ")));
    }
    audit
}

fn read_lut(path: &Path) -> Result<Lut, String> {
    Lut::read(path).map_err(|err| format!("{}: {err}", path.display()))
}

fn bundled_lut(file: &str, lut_dir: Option<&Path>) -> Result<Lut, String> {
    match lut_dir {
        Some(dir) => read_lut(&dir.join(file)),
        None => lforge_rage9::rpf::names::builtin::embedded()
            .find(|(name, _)| *name == file)
            .map(|(_, bytes)| Lut::parse(bytes).map_err(|err| err.to_string()))
            .unwrap_or_else(|| Err(format!("no bundled table named {file}"))),
    }
}

fn audit(lut_dir: Option<&Path>, research: Option<&Path>, json: bool) -> Result<(), String> {
    let mut audits = Vec::new();
    for file in ["rpf9-hash64.lut", "rpf9-key32.lut"] {
        let audit = match bundled_lut(file, lut_dir) {
            Ok(lut) => audit_one(file, &lut),
            Err(problem) => LutAudit {
                file: file.to_string(),
                problem: Some(problem),
                ..LutAudit::default()
            },
        };
        audits.push(audit);
    }
    let mut research_report = Value::Null;
    let mut research_ok = true;
    if let Some(dir) = research {
        let mut files = Vec::new();
        for file in ["rpf9-hash64.lut", "rpf9-key32.lut"] {
            let mut value = json!({ "file": file });
            let bundled = bundled_lut(file, lut_dir);
            let source = read_lut(&dir.join(file));
            match (bundled, source) {
                (Err(problem), _) | (_, Err(problem)) => {
                    research_ok = false;
                    value["problem"] = json!(problem);
                }
                (Ok(bundled), Ok(source)) => {
                    let identical = bundled.to_text() == source.to_text();
                    research_ok &= identical;
                    let bundled_set: BTreeSet<(Key, &str)> = bundled
                        .entries()
                        .iter()
                        .map(|entry| (entry.hash, entry.name.as_str()))
                        .collect();
                    let source_set: BTreeSet<(Key, &str)> = source
                        .entries()
                        .iter()
                        .map(|entry| (entry.hash, entry.name.as_str()))
                        .collect();
                    value["identical_canonical_text"] = json!(identical);
                    value["bundled_entries"] = json!(bundled.entries().len());
                    value["research_entries"] = json!(source.entries().len());
                    value["missing_from_bundled"] =
                        json!(source_set.difference(&bundled_set).count());
                    value["only_in_bundled"] = json!(bundled_set.difference(&source_set).count());
                }
            }
            files.push(value);
        }
        research_report = json!({
            "directory": dir.display().to_string(),
            "files": files,
            "ok": research_ok,
        });
    }
    let ok = audits.iter().all(LutAudit::ok) && research_ok;
    let document = json!({
        "schema": AUDIT_SCHEMA,
        "luts": audits.iter().map(LutAudit::json).collect::<Vec<_>>(),
        "research": research_report,
        "ok": ok,
    });
    if json {
        print_json(&document)?;
    } else {
        for audit in &audits {
            match &audit.problem {
                Some(problem) => println!("{}: not read: {problem}", audit.file),
                None => {
                    println!(
                        "{}: {} entries ({} verified), {} keys, {} ambiguous keys, {} \
                         normalized duplicates, {} path-unsafe names, {} duplicate records",
                        audit.file,
                        audit.entries,
                        audit.verified,
                        audit.keys,
                        audit.ambiguous_keys,
                        audit.normalized_duplicates,
                        audit.path_unsafe,
                        audit.duplicate_records
                    );
                    for example in &audit.unverified {
                        println!("  unverified: {example}");
                    }
                    for example in &audit.ambiguous_examples {
                        println!("  ambiguous: {example}");
                    }
                    for example in &audit.path_unsafe_examples {
                        println!("  unsafe path: {example}");
                    }
                }
            }
        }
        if !research_report.is_null() {
            println!(
                "research: {}",
                if research_ok {
                    "matches the bundled tables"
                } else {
                    "differs from the bundled tables"
                }
            );
        }
        println!("result: {}", if ok { "ok" } else { "problems found" });
    }
    if ok {
        Ok(())
    } else {
        Err("the LUT audit found problems".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_source_names() {
        assert_eq!(
            "payloads".parse::<SourceKind>().unwrap(),
            SourceKind::Payloads
        );
        assert_eq!(
            "executable".parse::<SourceKind>().unwrap(),
            SourceKind::Executable
        );
        assert!("other".parse::<SourceKind>().is_err());
    }

    #[test]
    fn parses_canonical_hashes_at_the_namespace_width() {
        assert_eq!(
            parse_canonical("0x0000000000000001", Class::Hash64),
            Some(Key::Hash64(1))
        );
        assert_eq!(
            parse_canonical("0x00000001", Class::Key32),
            Some(Key::Key32(1))
        );
        assert_eq!(parse_canonical("0x1", Class::Hash64), None);
        assert_eq!(parse_canonical("0x00000001", Class::Hash64), None);
    }

    #[test]
    fn chooses_namespace_specific_output_paths() {
        let output = Path::new("resolved.lut");
        assert_eq!(
            namespace_output(output, Class::Hash64, false),
            PathBuf::from("resolved.lut")
        );
        assert_eq!(
            namespace_output(output, Class::Hash64, true),
            PathBuf::from("resolved.hash64.lut")
        );
        assert_eq!(
            namespace_output(output, Class::Key32, true),
            PathBuf::from("resolved.key32.lut")
        );
    }

    #[test]
    fn rejects_sensitive_executable_strings() {
        assert!(sensitive_candidate(r"C:\Users\example\file.bin"));
        assert!(sensitive_candidate("password=synthetic"));
        assert!(sensitive_candidate(&"A".repeat(200)));
        assert!(!sensitive_candidate("synthetic/path/file.bin"));
    }

    /// A minimal RBF0 document with one named string field.
    fn rbf0_document() -> Vec<u8> {
        let mut bytes = b"RBF0".to_vec();
        bytes.extend_from_slice(&0xFFFBu16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0x0004u16.to_le_bytes());
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.extend_from_slice(b"field");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0xFFFDu16.to_le_bytes());
        bytes.extend_from_slice(&6u32.to_le_bytes());
        bytes.extend_from_slice(b"value\0");
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
        bytes
    }

    #[test]
    fn labels_verified_rbf0_text_and_leaves_other_strings_alone() {
        let verified = VerifiedText::of(&rbf0_document(), &AtomicBool::new(false));
        assert_eq!(verified.label("field"), Some(TextKind::FieldName.name()));
        assert_eq!(verified.label("value"), Some(TextKind::StringValue.name()));
        assert_eq!(verified.label("unrelated"), None);

        let other = VerifiedText::of(b"nothing to parse here", &AtomicBool::new(false));
        assert_eq!(other.label("field"), None);
    }

    #[test]
    fn only_confirmed_extensions_match_hash64_rows() {
        let types = Types::default();
        let variant = |display: &str| Variant {
            text: "synthetic/x".to_string(),
            display: display.to_string(),
            kind: VariantKind::Stem,
        };
        assert!(occurrence_allows(
            &types,
            Some(0),
            Class::Hash64,
            &variant("synthetic/x.rpf")
        ));
        assert!(!occurrence_allows(
            &types,
            Some(0),
            Class::Hash64,
            &variant("synthetic/x.ityp")
        ));
        assert!(!occurrence_allows(
            &types,
            Some(0),
            Class::Hash64,
            &Variant {
                display: "synthetic/x".to_string(),
                ..variant("synthetic/x")
            }
        ));
        assert!(occurrence_allows(
            &types,
            Some(255),
            Class::Key32,
            &variant("synthetic/x.xml")
        ));
        // Type 11 uses the 32-bit class, established from the executable.
        assert!(occurrence_allows(
            &types,
            Some(11),
            Class::Key32,
            &variant("synthetic/x.xml")
        ));
        // A type with no established class is not promoted.
        assert!(!occurrence_allows(
            &types,
            Some(13),
            Class::Key32,
            &variant("synthetic/x.xml")
        ));
        assert!(!occurrence_allows(
            &types,
            Some(0),
            Class::Key32,
            &variant("synthetic/x.rpf")
        ));
    }

    #[test]
    fn discovery_stops_when_cancelled() {
        let temp = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(true);
        let result = discover(
            temp.path(),
            temp.path(),
            ScanLimits {
                max_depth: 1,
                max_archives: 1,
                max_rows: 1,
            },
            &cancel,
        );
        assert_eq!(result.err().unwrap(), "cancelled");
    }
}
