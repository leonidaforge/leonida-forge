//! Decodes every reachable RBF0 payload and tallies what the decoder found.
//!
//! This is the bounded validation workflow the RBF0 decoder is checked with: it
//! walks archives the way the CLI does, reads each metadata payload, decodes it
//! and counts the outcomes, without writing any document out. Payload names and
//! text are never printed unless `--names` asks for a vocabulary survey, which
//! prints what the documents call their own elements and stays on the terminal.
//!
//! ```text
//! cargo run -p lforge-rage9 --release --example rbf0_population -- \
//!     "<GAME_ROOT>/data.rpf" --executable "<GAME_ROOT>/<game executable>" \
//!     --recursive --values
//! ```
//!
//! Options:
//!
//! - `--recursive`: enter archives stored inside an archive.
//! - `--jsonl <path>`: write one record per decoded payload: digests, counts
//!   and the decoder's own notes. No name or text is written.
//! - `--values`: tally the byte patterns of numeric values, by class.
//! - `--names`: print the element, attribute and field vocabulary by frequency.
//! - `--vocabulary <path>`: write the distinct names to a file, for a local
//!   comparison against another format's name hashes.
//! - `--max-archives`, `--max-entries`, `--max-payload-bytes`: bounds.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_binary::pe::ExecutableView;
use lforge_rage9::rbf0;
use lforge_rage9::rpf;
use lforge_rage9::rpf::metadata::provider::RecognizedSource;
use lforge_rage9::rpf::metadata::verify::{VerifyOutcome, open_authenticated};
use lforge_rage9::rpf::metadata::{CompanionStatus, Entry, Metadata, Payload, Stored};
use sha2::{Digest, Sha256};

/// Bytes read to recognise a payload.
const SIGNATURE: usize = 4;
/// The most distinct length-prefixed texts the survey keeps.
const MAX_TEXT_KEYS: usize = 4096;
/// The most characters of one surveyed text.
const MAX_TEXT_CHARS: usize = 48;

/// What a run may spend.
struct Budget {
    max_archives: u64,
    max_entries: u64,
    max_payload_bytes: u64,
    archives: u64,
    entries: u64,
    spooled: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_archives: 4096,
            max_entries: 4_000_000,
            max_payload_bytes: 64 * 1024 * 1024,
            archives: 0,
            entries: 0,
            spooled: 0,
        }
    }
}

/// One opened archive and the table of contents the engine would read.
struct Opened {
    source: Source,
    metadata: Metadata,
    stream: Option<RecognizedSource>,
    path: Option<PathBuf>,
}

#[derive(Default)]
struct Tally {
    /// Payloads whose first four bytes are the magic.
    discovered: u64,
    /// Payloads whose bytes were read to the end.
    opened: u64,
    /// Payloads that could not be read, and why.
    unreadable: u64,
    unreadable_reasons: BTreeMap<String, u64>,
    /// `decoded`, `partial` or `failed`.
    status: BTreeMap<&'static str, u64>,
    /// Failure kind, for the payloads that stopped early.
    failures: BTreeMap<String, u64>,
    /// Payloads a read limit refused.
    limited: u64,
    /// Bytes of a decoded payload: least and most.
    min_bytes: u64,
    max_bytes: u64,
    /// Elements, depth and names of a decoded document: least and most.
    min_elements: usize,
    max_elements: usize,
    max_depth: usize,
    min_names: usize,
    max_names: usize,
    /// Versioned and versionless headers.
    versioned: u64,
    versionless: u64,
    /// Value tokens per type code.
    types: BTreeMap<u8, u64>,
    /// Text nodes, and how many end with the NUL the format carries.
    text_nodes: u64,
    text_terminated: u64,
    /// Length-prefixed values, and how many end with a NUL.
    byte_values: u64,
    byte_values_terminated: u64,
    /// Payloads that reported at least one note, and the notes.
    with_diagnostics: u64,
    diagnostics: BTreeMap<&'static str, u64>,
    /// Distinct root-name digests, and the digest-to-count tally.
    roots: BTreeMap<String, u64>,
    /// The root element name of each document, by frequency.
    root_names: BTreeMap<String, u64>,
    /// Distinct payload digests, so repeats do not inflate a schema count.
    distinct: HashSet<[u8; 32]>,
    /// The document's own vocabulary, by frequency.
    element_names: BTreeMap<String, u64>,
    attribute_names: BTreeMap<String, u64>,
    field_names: BTreeMap<String, u64>,
    byte_texts: BTreeMap<String, u64>,
    /// Numeric values by class.
    numbers: BTreeMap<u8, NumberTally>,
}

/// What one class of numeric value supports.
#[derive(Default)]
struct NumberTally {
    count: u64,
    /// Byte patterns, keyed by the bytes in hex.
    patterns: BTreeMap<String, u64>,
    /// The integer reading: the range it covers, and how many fit in 32 bits.
    min_int: i64,
    max_int: i64,
    negative: u64,
    fit_i32: u64,
    /// The double reading: the range, how many are finite, and how many are
    /// integral.
    min_float: f64,
    max_float: f64,
    finite: u64,
    not_finite: u64,
    integral: u64,
}

impl NumberTally {
    fn observe(&mut self, bytes: &[u8]) {
        if self.count == 0 {
            self.min_int = i64::MAX;
            self.max_int = i64::MIN;
            self.min_float = f64::INFINITY;
            self.max_float = f64::NEG_INFINITY;
        }
        self.count += 1;
        let (int, float) = match bytes.len() {
            4 => {
                let raw = u32::from_le_bytes(bytes.try_into().expect("four bytes"));
                (i64::from(raw as i32), f64::from(f32::from_bits(raw)))
            }
            8 => {
                let raw = u64::from_le_bytes(bytes.try_into().expect("eight bytes"));
                (raw as i64, f64::from_bits(raw))
            }
            _ => return,
        };
        self.min_int = self.min_int.min(int);
        self.max_int = self.max_int.max(int);
        if int < 0 {
            self.negative += 1;
        }
        if i32::try_from(int).is_ok() {
            self.fit_i32 += 1;
        }
        if float.is_finite() {
            self.finite += 1;
            self.min_float = self.min_float.min(float);
            self.max_float = self.max_float.max(float);
            if float.fract() == 0.0 {
                self.integral += 1;
            }
        } else {
            self.not_finite += 1;
        }
    }
}

impl Tally {
    fn observe(&mut self, bytes: &[u8], document: &rbf0::Document, values: bool, names: bool) {
        self.opened += 1;
        *self.status.entry(document.status()).or_default() += 1;
        if document
            .failure
            .as_ref()
            .is_some_and(|err| err.kind == rbf0::ErrorKind::Limit)
        {
            self.limited += 1;
        }
        if let Some(failure) = &document.failure {
            *self
                .failures
                .entry(format!("{:?}", failure.kind))
                .or_default() += 1;
        }
        let length = bytes.len() as u64;
        let elements = document.elements();
        let depth = document.depth();
        let named = document.names.len();
        if self.opened == 1 {
            self.min_bytes = length;
            self.max_bytes = length;
            self.min_elements = elements;
            self.max_elements = elements;
            self.min_names = named;
            self.max_names = named;
        } else {
            self.min_bytes = self.min_bytes.min(length);
            self.max_bytes = self.max_bytes.max(length);
            self.min_elements = self.min_elements.min(elements);
            self.max_elements = self.max_elements.max(elements);
            self.min_names = self.min_names.min(named);
            self.max_names = self.max_names.max(named);
        }
        self.max_depth = self.max_depth.max(depth);
        if document.header.versioned {
            self.versioned += 1;
        } else {
            self.versionless += 1;
        }
        if let Some(name) = document.root_name() {
            let digest = format!("{:x}", Sha256::digest(name.as_bytes()));
            *self.roots.entry(digest).or_default() += 1;
            if names {
                *self.root_names.entry(name.to_string()).or_default() += 1;
            }
        }
        self.distinct.insert(Sha256::digest(bytes).into());
        if !document.diagnostics.is_empty() {
            self.with_diagnostics += 1;
            for diagnostic in &document.diagnostics {
                *self.diagnostics.entry(diagnostic.message).or_default() += 1;
            }
        }
        for element in document.walk() {
            if names {
                self.count_name(
                    &mut NameKind::Element,
                    document.name(element.index),
                    element.index,
                );
            }
            for attribute in &element.attributes {
                if names {
                    self.count_name(
                        &mut NameKind::Attribute,
                        document.name(attribute.index),
                        attribute.index,
                    );
                }
                self.count_value(&attribute.value, values, names);
            }
            for node in &element.children {
                match node {
                    rbf0::Node::Element(_) => {}
                    rbf0::Node::Field(field) => {
                        if names {
                            self.count_name(
                                &mut NameKind::Field,
                                document.name(field.index),
                                field.index,
                            );
                        }
                        self.count_value(&field.value, values, names);
                    }
                    rbf0::Node::Text(text) => {
                        self.text_nodes += 1;
                        if text.text().is_some_and(|(_, terminated)| terminated) {
                            self.text_terminated += 1;
                        }
                    }
                }
            }
        }
    }

    fn count_name(&mut self, kind: &mut NameKind, name: Option<&str>, index: u16) {
        let name = match name {
            Some(name) => name.to_string(),
            None => format!("#{index}"),
        };
        let tally = match kind {
            NameKind::Element => &mut self.element_names,
            NameKind::Attribute => &mut self.attribute_names,
            NameKind::Field => &mut self.field_names,
        };
        *tally.entry(name).or_default() += 1;
    }

    fn count_value(&mut self, value: &rbf0::Value, values: bool, names: bool) {
        *self.types.entry(value.code()).or_default() += 1;
        match value {
            rbf0::Value::Bytes { .. } => {
                self.byte_values += 1;
                if value.text().is_some_and(|(_, terminated)| terminated) {
                    self.byte_values_terminated += 1;
                }
                if names && let Some((text, _)) = value.text() {
                    let short: String = text.chars().take(MAX_TEXT_CHARS).collect();
                    if self.byte_texts.contains_key(&short) || self.byte_texts.len() < MAX_TEXT_KEYS
                    {
                        *self.byte_texts.entry(short).or_default() += 1;
                    }
                }
            }
            rbf0::Value::Number { code, bytes } => {
                let tally = self.numbers.entry(*code).or_default();
                tally.observe(bytes);
                if values {
                    let key = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
                    *tally.patterns.entry(key).or_default() += 1;
                }
            }
            _ => {}
        }
    }
}

enum NameKind {
    Element,
    Attribute,
    Field,
}

/// One run: the options, the tally and the walk's own bookkeeping.
struct Run {
    recursive: bool,
    values: bool,
    names: bool,
    executable: Option<PathBuf>,
    budget: Budget,
    tally: Tally,
    out: Option<File>,
    vocabulary: Option<File>,
    truncated: bool,
    cancel: AtomicBool,
}

impl Run {
    fn visit(&mut self, opened: Opened, label: &str) {
        let sources = alternates(&opened);
        let rows: Vec<u32> = opened.metadata.entries().map(|entry| entry.row).collect();
        for row in rows {
            if self.budget.entries >= self.budget.max_entries {
                self.truncated = true;
                return;
            }
            self.budget.entries += 1;
            let Ok(entry) = opened.metadata.entry(row) else {
                continue;
            };
            let head = self.read_head(&opened, &entry, &sources);
            if head.as_deref().is_some_and(rbf0::is_rbf0) {
                self.decode_row(&opened, &entry, &sources, label);
                continue;
            }
            let nested = entry.type_id() == Some(0) || head.as_deref().is_some_and(rpf::is_rpf9);
            if self.recursive && nested {
                self.enter(&opened, &entry, &sources, label);
            }
        }
    }

    fn decode_row(
        &mut self,
        opened: &Opened,
        entry: &Entry,
        sources: &[Option<Source>],
        label: &str,
    ) {
        self.tally.discovered += 1;
        let Some(mut payload) = payload_of(opened, entry, sources) else {
            self.tally.unreadable += 1;
            *self
                .tally
                .unreadable_reasons
                .entry(
                    "the payload is behind the transform and no key state is available".to_string(),
                )
                .or_default() += 1;
            return;
        };
        let len = payload.len();
        if len > self.budget.max_payload_bytes {
            self.tally.unreadable += 1;
            *self
                .tally
                .unreadable_reasons
                .entry("over the payload budget".to_string())
                .or_default() += 1;
            return;
        }
        let mut bytes = Vec::with_capacity(len as usize);
        if let Err(err) = payload.read_to_end(&mut bytes) {
            self.tally.unreadable += 1;
            *self
                .tally
                .unreadable_reasons
                .entry(err.to_string())
                .or_default() += 1;
            return;
        }
        let document = match rbf0::decode(&bytes, &rbf0::Limits::default(), &self.cancel) {
            Ok(document) => document,
            Err(err) => {
                self.tally.unreadable += 1;
                *self
                    .tally
                    .unreadable_reasons
                    .entry(err.to_string())
                    .or_default() += 1;
                return;
            }
        };
        self.tally
            .observe(&bytes, &document, self.values, self.names);
        if let Some(file) = &mut self.out {
            let record = serde_json::json!({
                "archive": label,
                "row": entry.row,
                "bytes": bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(&bytes)),
                "status": document.status(),
                "versioned": document.header.versioned,
                "names": document.names.len(),
                "elements": document.elements(),
                "depth": document.depth(),
                "trailing": document.trailing,
                "roots": document.root_name().map(|name| format!("{:x}", Sha256::digest(name.as_bytes()))),
                "failure": document.failure.as_ref().map(|err| serde_json::json!({
                    "kind": format!("{:?}", err.kind),
                    "offset": err.offset,
                    "message": err.message,
                })),
                "diagnostics": document.diagnostics.iter().map(|diagnostic| diagnostic.message).collect::<Vec<_>>(),
            });
            let _ = writeln!(file, "{record}");
        }
    }

    fn enter(&mut self, opened: &Opened, entry: &Entry, sources: &[Option<Source>], label: &str) {
        if self.budget.archives >= self.budget.max_archives {
            self.truncated = true;
            return;
        }
        let nested_label = format!("{label}!{}", entry.row);
        let source = match entry.raw_source(&opened.source, sources) {
            Ok(source) => source,
            Err(_) => {
                let Some(mut payload) = payload_of(opened, entry, sources) else {
                    return;
                };
                let size = payload.len();
                if self.budget.spooled.saturating_add(size) > 8 * 1024 * 1024 * 1024 {
                    self.truncated = true;
                    return;
                }
                let Ok(mut file) = tempfile::tempfile() else {
                    return;
                };
                if std::io::copy(&mut payload, &mut file).is_err() {
                    return;
                }
                if file.seek(std::io::SeekFrom::Start(0)).is_err() {
                    return;
                }
                self.budget.spooled += size;
                match Source::from_file(file) {
                    Ok(source) => source,
                    Err(_) => return,
                }
            }
        };
        let Ok(nested) = open_source(source, None, self.executable.as_deref()) else {
            return;
        };
        self.budget.archives += 1;
        self.visit(nested, &nested_label);
    }

    fn read_head(
        &self,
        opened: &Opened,
        entry: &Entry,
        sources: &[Option<Source>],
    ) -> Option<Vec<u8>> {
        let mut payload = payload_of(opened, entry, sources)?;
        let mut head = vec![0u8; SIGNATURE];
        let mut read = 0;
        while read < SIGNATURE {
            match payload.read(&mut head[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(_) => return None,
            }
        }
        head.truncate(read);
        Some(head)
    }
}

fn main() {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut run = Run {
        recursive: false,
        values: false,
        names: false,
        executable: None,
        budget: Budget::default(),
        tally: Tally::default(),
        out: None,
        vocabulary: None,
        truncated: false,
        cancel: AtomicBool::new(false),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--executable" => run.executable = args.next().map(PathBuf::from),
            "--recursive" => run.recursive = true,
            "--values" => run.values = true,
            "--names" => run.names = true,
            "--vocabulary" => {
                let path = args.next().expect("a path after --vocabulary");
                run.vocabulary = Some(File::create(path).expect("vocabulary output"));
                run.names = true;
            }
            "--jsonl" => {
                let path = args.next().expect("a path after --jsonl");
                run.out = Some(File::create(path).expect("jsonl output"));
            }
            "--max-archives" => {
                run.budget.max_archives = args.next().and_then(|n| n.parse().ok()).unwrap_or(4096)
            }
            "--max-entries" => {
                run.budget.max_entries = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(4_000_000)
            }
            "--max-payload-bytes" => {
                run.budget.max_payload_bytes = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(64 * 1024 * 1024)
            }
            other if other.starts_with("--") => {
                eprintln!("unknown option {other}");
                std::process::exit(2);
            }
            path => roots.push(PathBuf::from(path)),
        }
    }
    if roots.is_empty() {
        eprintln!(
            "usage: rbf0_population <archive-or-directory>... [--executable <exe>] \
             [--recursive] [--jsonl <path>] [--values] [--names] [--vocabulary <path>]"
        );
        std::process::exit(2);
    }
    let mut files = Vec::new();
    for root in &roots {
        collect_archives(root, &mut files);
    }
    let mut roots_walked = 0u64;
    for path in files {
        if run.budget.archives >= run.budget.max_archives {
            run.truncated = true;
            break;
        }
        match open_path(&path, run.executable.as_deref()) {
            Ok(opened) => {
                roots_walked += 1;
                let label = path.display().to_string();
                run.visit(opened, &label);
            }
            Err(err) => eprintln!("{}: {err}", path.display()),
        }
    }
    let names = run.names;
    report(&run.tally, &run.budget, run.truncated, roots_walked, names);
    if let Some(file) = &mut run.vocabulary {
        let mut names: Vec<&String> = Vec::new();
        names.extend(run.tally.element_names.keys());
        names.extend(run.tally.attribute_names.keys());
        names.extend(run.tally.root_names.keys());
        names.extend(run.tally.byte_texts.keys());
        names.sort();
        names.dedup();
        for name in names {
            let _ = writeln!(file, "{name}");
        }
    }
}

fn collect_archives(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        let mut children: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        children.sort();
        for path in children {
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rpf"))
            {
                out.push(path);
            }
        }
    }
}

fn open_path(path: &Path, executable: Option<&Path>) -> Result<Opened, String> {
    let source = Source::open(path).map_err(|err| err.to_string())?;
    open_source(source, Some(path), executable)
}

fn open_source(
    mut source: Source,
    path: Option<&Path>,
    executable: Option<&Path>,
) -> Result<Opened, String> {
    rpf::read_header(&mut source).map_err(|err| err.to_string())?;
    let probe = Stored::probe(&mut source.clone()).map_err(|err| err.to_string())?;
    if probe.processing.is_none() {
        let metadata = Stored::read(&mut source.clone(), 256 * 1024 * 1024)
            .and_then(Stored::decode)
            .map_err(|err| err.to_string())?;
        return Ok(Opened {
            source,
            metadata,
            stream: None,
            path: path.map(Path::to_path_buf),
        });
    }
    let Some(executable) = executable else {
        return Err("the table of contents is processed and needs --executable".to_string());
    };
    let view = ExecutableView::open(executable).map_err(|err| err.to_string())?;
    let open = open_authenticated(&mut source.clone(), &view, &AtomicBool::new(false))
        .map_err(|err| err.to_string())?;
    if open.report.outcome != VerifyOutcome::MetadataDecodedAuthenticated {
        return Err(format!(
            "the table of contents is not authenticated: {} (stage {})",
            open.report.outcome, open.report.stage
        ));
    }
    let authenticated = open.authenticated.expect("a decoded outcome names it");
    Ok(Opened {
        source,
        metadata: authenticated.into_metadata(),
        stream: open.source,
        path: path.map(Path::to_path_buf),
    })
}

/// The companion sources of an archive on disk.
fn alternates(opened: &Opened) -> Vec<Option<Source>> {
    let Some(path) = &opened.path else {
        return Vec::new();
    };
    let Ok(list) = opened.metadata.companions() else {
        return Vec::new();
    };
    list.open(path)
        .iter()
        .map(|status: &CompanionStatus| status.source().cloned())
        .collect()
}

/// The decoded payload of one row, through the engine's transform when the row
/// is stored behind it.
fn payload_of(opened: &Opened, entry: &Entry, sources: &[Option<Source>]) -> Option<Payload> {
    if let Ok(payload) = entry.payload(&opened.source, sources) {
        return Some(payload);
    }
    let stream = opened.stream.as_ref()?;
    let transform = stream
        .stream_transform(entry, &opened.source, sources)
        .ok()?;
    entry
        .transformed_payload(&opened.source, sources, transform)
        .ok()
}

fn report(tally: &Tally, budget: &Budget, truncated: bool, roots: u64, names: bool) {
    let mut out = std::io::stdout().lock();
    let mut line = |text: String| {
        let _ = writeln!(out, "{text}");
    };
    line(format!("root archives walked: {roots}"));
    line(format!("nested archives:      {}", budget.archives));
    line(format!("entries walked:       {}", budget.entries));
    line(format!("rbf0 discovered:      {}", tally.discovered));
    line(format!("payloads opened:      {}", tally.opened));
    line(format!("unreadable payloads:  {}", tally.unreadable));
    for (reason, count) in &tally.unreadable_reasons {
        line(format!("  {count} x {reason}"));
    }
    for (status, count) in &tally.status {
        line(format!("status {status:<15}{count}"));
    }
    for (failure, count) in &tally.failures {
        line(format!("failure {failure:<14}{count}"));
    }
    line(format!("limit refusals:       {}", tally.limited));
    line(format!("distinct payloads:    {}", tally.distinct.len()));
    line(format!(
        "document bytes:       {}..{}",
        tally.min_bytes, tally.max_bytes
    ));
    line(format!(
        "elements per document: {}..{}   depth at most {}   names per document: {}..{}",
        tally.min_elements, tally.max_elements, tally.max_depth, tally.min_names, tally.max_names
    ));
    line(format!(
        "headers:              {} versioned, {} versionless",
        tally.versioned, tally.versionless
    ));
    line(format!(
        "text nodes:           {} ({} end with NUL)",
        tally.text_nodes, tally.text_terminated
    ));
    line(format!(
        "length-prefixed:      {} ({} end with NUL)",
        tally.byte_values, tally.byte_values_terminated
    ));
    line(format!("payloads with notes:  {}", tally.with_diagnostics));
    for (message, count) in &tally.diagnostics {
        line(format!("  note {message:<50} {count}"));
    }
    let types: Vec<String> = tally
        .types
        .iter()
        .map(|(code, count)| format!("{code}:{count}"))
        .collect();
    line(format!("value tokens:         {}", types.join(" ")));
    for (code, numbers) in &tally.numbers {
        line(format!(
            "numbers of class {code}:  {} values, {} distinct byte patterns",
            numbers.count,
            numbers.patterns.len()
        ));
        line(format!(
            "  as integers: {}..{} ({} negative, {} fit in i32)",
            numbers.min_int, numbers.max_int, numbers.negative, numbers.fit_i32
        ));
        line(format!(
            "  as doubles:  {}..{} ({} finite, {} not, {} integral)",
            numbers.min_float,
            numbers.max_float,
            numbers.finite,
            numbers.not_finite,
            numbers.integral
        ));
        let mut patterns: Vec<(&String, &u64)> = numbers.patterns.iter().collect();
        patterns.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (pattern, count) in patterns.iter().take(6) {
            line(format!("  {pattern} x{count}"));
        }
    }
    line(format!(
        "root name digests:    {} distinct",
        tally.roots.len()
    ));
    let mut roots: Vec<(&String, &u64)> = tally.roots.iter().collect();
    roots.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    for (digest, count) in roots.iter().take(40) {
        line(format!("  {digest} x{count}"));
    }
    if names {
        line(format!(
            "root element names: {} distinct",
            tally.root_names.len()
        ));
        let mut roots: Vec<(&String, &u64)> = tally.root_names.iter().collect();
        roots.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
        for (name, count) in roots {
            line(format!("  {count:<8}{name}"));
        }
        for (title, map, take) in [
            ("element names", &tally.element_names, 60),
            ("attribute names", &tally.attribute_names, 40),
            ("field names", &tally.field_names, 60),
            ("length-prefixed texts", &tally.byte_texts, 80),
        ] {
            line(format!("{title}: {} distinct", map.len()));
            let mut entries: Vec<(&String, &u64)> = map.iter().collect();
            entries.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
            for (value, count) in entries.iter().take(take) {
                line(format!("  {count:<8}{value}"));
            }
        }
    }
    if truncated {
        line("a limit stopped the walk; the counts are a floor".to_string());
    }
}
