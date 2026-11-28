//! Decodes every reachable `0DRP` metadata resource and tallies what the
//! decoder found.
//!
//! This is the bounded validation workflow the resource-form decoder is checked
//! with: it walks archives the way the CLI does, reads each metadata payload,
//! splits it into its two segments from the row's page table and the page map,
//! decodes it and counts the outcomes, without writing any document out.
//!
//! ```text
//! cargo run -p lforge-rage9 --release --example odrp_population -- \
//!     "<GAME_ROOT>/data.rpf" --executable "<GAME_ROOT>/<game executable>" \
//!     --recursive
//! ```
//!
//! Options:
//!
//! - `--recursive`: enter archives stored inside an archive.
//! - `--jsonl <path>`: write one record per decoded resource: the counts and
//!   the decoder's own notes. No payload bytes are written.
//! - `--types`: print the stored field and block type words by count.
//! - `--max-archives`, `--max-entries`, `--max-payload-bytes`: bounds.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_binary::pe::ExecutableView;
use lforge_rage9::odrp;
use lforge_rage9::rpf;
use lforge_rage9::rpf::metadata::provider::RecognizedSource;
use lforge_rage9::rpf::metadata::verify::{VerifyOutcome, open_authenticated};
use lforge_rage9::rpf::metadata::{CompanionStatus, Entry, Metadata, Payload, Stored};
use sha2::{Digest, Sha256};

/// Bytes read to recognise the form: the header, the tag and the page map.
const HEAD_LEN: usize = 0x60;

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

struct Opened {
    source: Source,
    metadata: Metadata,
    stream: Option<RecognizedSource>,
    path: Option<PathBuf>,
}

#[derive(Default)]
struct Tally {
    /// Rows whose head carries the tag and the header shape.
    discovered: u64,
    /// Resources whose whole payload was read.
    opened: u64,
    /// Rows whose payload could not be read, and why.
    unreadable: BTreeMap<String, u64>,
    /// Resources a page table and page map could split.
    split: u64,
    /// Resources whose split disagreed with the payload size.
    split_failed: BTreeMap<String, u64>,
    /// `decoded`, `partial` or `failed`.
    status: BTreeMap<&'static str, u64>,
    /// Decoder errors, by kind and message.
    failures: BTreeMap<String, u64>,
    /// The decoder said a read limit stopped it.
    limited: u64,
    /// Resources with at least one note, and the notes.
    noted: u64,
    notes: BTreeMap<String, u64>,
    /// Blocks that were not decoded, by type word.
    unsupported_blocks: u64,
    unsupported_types: BTreeMap<u32, u64>,
    /// References that bound nowhere.
    unresolved_references: u64,
    /// Payload bytes: least and most.
    min_bytes: u64,
    max_bytes: u64,
    /// Structures, blocks and records per resource: least and most.
    min_structures: u16,
    max_structures: u16,
    min_blocks: u16,
    max_blocks: u16,
    min_records: usize,
    max_records: usize,
    /// Depth and text values.
    max_depth: usize,
    texts: u64,
    /// Page shapes: system pages, graphics pages.
    shapes: BTreeMap<(u8, u8), u64>,
    /// Object type bytes.
    object_types: BTreeMap<u8, u64>,
    /// Declared roots words.
    declared_roots: BTreeMap<u32, u64>,
    /// Resources whose roots list is empty.
    without_roots: u64,
    /// Field and block type words, when `--types` asks.
    field_types: BTreeMap<u32, u64>,
    block_types: BTreeMap<u32, u64>,
    /// Distinct payload digests.
    distinct: HashSet<[u8; 32]>,
}

struct Run {
    recursive: bool,
    types: bool,
    executable: Option<PathBuf>,
    budget: Budget,
    tally: Tally,
    out: Option<File>,
    truncated: bool,
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
            if head.as_deref().is_some_and(odrp::is_odrp) {
                self.decode_row(&opened, &entry, &sources, label);
                continue;
            }
            let nested = entry.type_id() == Some(0) || head.as_deref().is_some_and(rpf::is_rpf9);
            if self.recursive && nested && self.budget.archives < self.budget.max_archives {
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
            *self
                .tally
                .unreadable
                .entry("the payload is behind the transform and no key state is available".into())
                .or_default() += 1;
            return;
        };
        let len = payload.len();
        if len > self.budget.max_payload_bytes {
            *self
                .tally
                .unreadable
                .entry("over the payload budget".into())
                .or_default() += 1;
            return;
        }
        let mut bytes = Vec::with_capacity(len as usize);
        if let Err(err) = payload.read_to_end(&mut bytes) {
            *self.tally.unreadable.entry(err.to_string()).or_default() += 1;
            return;
        }
        self.tally.opened += 1;
        self.tally
            .distinct
            .insert(<[u8; 32]>::from(Sha256::digest(&bytes)));
        let chunks = opened.metadata.chunk_table(entry.row).ok().flatten();
        let split = chunks.as_ref().and_then(|table| {
            rpf::resource::page_split(
                &mut std::io::Cursor::new(bytes.as_slice()),
                bytes.len() as u64,
                table,
                rpf::RESOURCE_SYSTEM_LIMIT,
            )
            .ok()
        });
        let (system, graphics) = match &split {
            Some(split) => {
                self.tally.split += 1;
                if split.system_len as usize > bytes.len()
                    || split.system_len.saturating_add(split.graphics_len) != bytes.len() as u64
                {
                    *self
                        .tally
                        .split_failed
                        .entry("the split does not tile the payload".into())
                        .or_default() += 1;
                }
                bytes.split_at((split.system_len as usize).min(bytes.len()))
            }
            None => {
                // Without a page table the graphics segment cannot be located.
                // A resource with no graphics page is all system data.
                let graphics_pages = bytes.get(8).and_then(|_| bytes.get(0x10)).map(|_| 0u8);
                let _ = graphics_pages;
                match graphics_pages_of(&bytes) {
                    Some((_, 0)) => (bytes.as_slice(), &[][..]),
                    other => {
                        *self
                            .tally
                            .split_failed
                            .entry(match other {
                                Some((system, graphics)) => format!(
                                    "no page table: {system} system and {graphics} graphics pages"
                                ),
                                None => "no page table and no readable page map".into(),
                            })
                            .or_default() += 1;
                        return;
                    }
                }
            }
        };
        let document = match odrp::decode(
            system,
            graphics,
            &lforge_rage9::psin::pso::Limits::default(),
        ) {
            Ok(document) => document,
            Err(err) => {
                *self.tally.failures.entry(describe_error(&err)).or_default() += 1;
                return;
            }
        };
        self.tally
            .observe(&document, bytes.len() as u64, self.types);
        if document.truncated {
            self.tally.limited += 1;
        }
        if let Some(file) = &mut self.out {
            let record = serde_json::json!({
                "archive": label,
                "row": entry.row,
                "type": entry.type_id(),
                "bytes": bytes.len(),
                "sha256": format!("{:x}", Sha256::digest(&bytes)),
                "status": document.status(),
                "systemPages": document.header.system_pages,
                "graphicsPages": document.header.graphics_pages,
                "structures": document.header.structures,
                "enums": document.header.enums,
                "blocks": document.header.blocks,
                "unknownWord": document.header.unknown,
                "declaredRoots": document.header.declared_roots,
                "roots": document.roots,
                "records": document.record_count(),
                "depth": document.depth(),
                "texts": document.text_count(),
                "unsupportedBlocks": document.unsupported_blocks,
                "unresolvedReferences": document.unresolved_references,
                "truncated": document.truncated,
                "issues": document.issues,
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
        let mut head = vec![0u8; HEAD_LEN];
        let mut read = 0;
        while read < head.len() {
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

impl Tally {
    fn observe(&mut self, document: &odrp::Document, bytes: u64, types: bool) {
        *self.status.entry(document.status()).or_default() += 1;
        *self
            .shapes
            .entry((document.header.system_pages, document.header.graphics_pages))
            .or_default() += 1;
        *self
            .object_types
            .entry(document.header.object_type)
            .or_default() += 1;
        *self
            .declared_roots
            .entry(document.header.declared_roots)
            .or_default() += 1;
        if document.roots.is_empty() {
            self.without_roots += 1;
        }
        if self.opened == 1 {
            self.min_bytes = bytes;
            self.max_bytes = bytes;
            self.min_structures = document.header.structures;
            self.max_structures = document.header.structures;
            self.min_blocks = document.header.blocks;
            self.max_blocks = document.header.blocks;
        }
        self.min_bytes = self.min_bytes.min(bytes);
        self.max_bytes = self.max_bytes.max(bytes);
        self.min_structures = self.min_structures.min(document.header.structures);
        self.max_structures = self.max_structures.max(document.header.structures);
        self.min_blocks = self.min_blocks.min(document.header.blocks);
        self.max_blocks = self.max_blocks.max(document.header.blocks);
        let records = document.record_count();
        if self.status.values().sum::<u64>() == 1 {
            self.min_records = records;
        }
        self.min_records = self.min_records.min(records);
        self.max_records = self.max_records.max(records);
        self.max_depth = self.max_depth.max(document.depth());
        self.texts += document.text_count() as u64;
        self.unsupported_blocks += u64::from(document.unsupported_blocks);
        self.unresolved_references += u64::from(document.unresolved_references);
        if !document.issues.is_empty() {
            self.noted += 1;
        }
        for issue in &document.issues {
            *self.notes.entry(summarise(issue)).or_default() += 1;
        }
        for block in &document.blocks {
            if let lforge_rage9::psin::pso::Content::Unsupported(_) = block.content {
                *self.unsupported_types.entry(block.id).or_default() += 1;
            }
            if types {
                *self.block_types.entry(block.id).or_default() += 1;
            }
        }
        if types {
            for structure in &document.structures {
                for field in &structure.fields {
                    *self.field_types.entry(field.type_word).or_default() += 1;
                }
            }
        }
    }
}

fn summarise(issue: &str) -> String {
    // Keep the note vocabulary small: a note keeps its first clause.
    issue.split(';').next().unwrap_or(issue).to_string()
}

fn graphics_pages_of(system: &[u8]) -> Option<(u8, u8)> {
    let map = lforge_rage9::resource::page_map_offset(system)? as usize;
    Some((*system.get(map + 8)?, *system.get(map + 9)?))
}

fn describe_error(err: &odrp::Error) -> String {
    match err {
        odrp::Error::NotOdrp => "not 0DRP".to_string(),
        odrp::Error::Malformed(reason) => format!("malformed: {reason}"),
        odrp::Error::Limit(reason) => format!("limit: {reason}"),
    }
}

fn main() {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut run = Run {
        recursive: false,
        types: false,
        executable: None,
        budget: Budget::default(),
        tally: Tally::default(),
        out: None,
        truncated: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--executable" => run.executable = args.next().map(PathBuf::from),
            "--recursive" => run.recursive = true,
            "--types" => run.types = true,
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
            "usage: odrp_population <archive-or-directory>... [--executable <exe>] \
             [--recursive] [--jsonl <path>] [--types]"
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
    let types = run.types;
    report(&run.tally, &run.budget, run.truncated, roots_walked, types);
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

fn report(tally: &Tally, budget: &Budget, truncated: bool, roots: u64, types: bool) {
    let mut out = std::io::stdout().lock();
    let mut line = |text: String| {
        let _ = writeln!(out, "{text}");
    };
    line(format!("root archives walked: {roots}"));
    line(format!("nested archives:      {}", budget.archives));
    line(format!("entries walked:       {}", budget.entries));
    line(format!("resources discovered: {}", tally.discovered));
    line(format!("payloads opened:      {}", tally.opened));
    for (reason, count) in &tally.unreadable {
        line(format!("  unreadable {count} x {reason}"));
    }
    line(format!("splits:               {}", tally.split));
    for (reason, count) in &tally.split_failed {
        line(format!("  not split {count} x {reason}"));
    }
    for (status, count) in &tally.status {
        line(format!("status {status:<15}{count}"));
    }
    for (failure, count) in &tally.failures {
        line(format!("failure {count} x {failure}"));
    }
    line(format!("limit refusals:       {}", tally.limited));
    line(format!("distinct payloads:    {}", tally.distinct.len()));
    line(format!(
        "payload bytes:        {}..{}",
        tally.min_bytes, tally.max_bytes
    ));
    line(format!(
        "structures:           {}..{}",
        tally.min_structures, tally.max_structures
    ));
    line(format!(
        "blocks:               {}..{}",
        tally.min_blocks, tally.max_blocks
    ));
    line(format!(
        "records per resource: {}..{}   depth at most {}",
        tally.min_records, tally.max_records, tally.max_depth
    ));
    line(format!("text values:          {}", tally.texts));
    line(format!(
        "unsupported blocks:   {} ({:?})",
        tally.unsupported_blocks, tally.unsupported_types
    ));
    line(format!(
        "unresolved references:{}",
        tally.unresolved_references
    ));
    line(format!("resources with notes: {}", tally.noted));
    for (note, count) in &tally.notes {
        line(format!("  note {count} x {note}"));
    }
    line(format!("page shapes:          {:?}", tally.shapes));
    line(format!("object type bytes:    {:?}", tally.object_types));
    line(format!("declared root words:  {:?}", tally.declared_roots));
    line(format!(
        "resources without a derived root: {}",
        tally.without_roots
    ));
    if types {
        line(format!("field type words:     {:?}", tally.field_types));
        line(format!("block type words:     {:?}", tally.block_types));
    }
    if truncated {
        line("a bound stopped the walk early".to_string());
    }
}
