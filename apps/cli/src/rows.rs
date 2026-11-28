//! `lforge archive ls`, `search` and `manifest`: authenticated native RPF9
//! rows as stable, machine-readable records.
//!
//! The commands read the archive's own table of contents through
//! [`native::open_metadata`], apply the built-in LUTs and an optional local
//! name table, and print one record per row. They never list a row from
//! unauthenticated metadata, never extract a payload and never write a
//! cryptographic state.
//!
//! 64-bit hashes, keys and payload offsets are strings so no value loses
//! precision. Sizes are numbers. Records and their order are deterministic.

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_core::resource::{self, EntryId, ResourcePath};
use lforge_rage9::rpf::metadata::transform::{Algorithm, CipherDescriptor};
use lforge_rage9::rpf::metadata::{Entry, Field};
use lforge_rage9::rpf::names::{Class, Key, MountPrefix, Resolver, RowNames, Types};
use serde_json::{Value, json};

use crate::native::{self, Alternates, Authentication, Opened};
use crate::output;

/// The schema of one row record, shared by `ls`, `search` and the manifest.
pub const ROW_SCHEMA: &str = "leonida-forge.native-row/1";
/// The schema of a `ls` document.
pub const LIST_SCHEMA: &str = "leonida-forge.native-list/1";
/// The schema of a manifest document.
pub const MANIFEST_SCHEMA: &str = "leonida-forge.native-manifest/1";
/// The schema of a search result document.
pub const SEARCH_SCHEMA: &str = "leonida-forge.native-search/1";

const MAX_METADATA: u64 = 256 * 1024 * 1024;

/// One opened archive with the name tables applied to its rows.
pub struct Listing {
    /// The file on disk the bytes come from: an archive stored inside another
    /// one is still read out of the root file.
    archive: PathBuf,
    /// The canonical path of the archive itself, without its entry.
    path: ResourcePath,
    opened: Opened,
    types: Types,
    resolved: ResolutionSet,
    /// The canonical identity of every row, in row order.
    entry_ids: Vec<EntryId>,
    entries: Vec<Entry>,
}

struct ResolutionSet {
    rows: Vec<RowNames>,
    by_row: std::collections::HashMap<u32, usize>,
}

impl ResolutionSet {
    fn row(&self, row: u32) -> Option<&RowNames> {
        self.by_row.get(&row).map(|&position| &self.rows[position])
    }
}

impl Listing {
    /// Opens `path`, authenticating processed metadata with `executable`, and
    /// resolves its rows with the local tables and the built-in LUTs.
    pub fn open(
        path: &Path,
        executable: Option<&Path>,
        name_files: &[PathBuf],
        cancel: &AtomicBool,
    ) -> Result<Self, String> {
        let opened = native::open_metadata_cancellable(path, MAX_METADATA, executable, cancel)?;
        let root = table_name(path);
        Self::from_opened(path, ResourcePath::root(root), opened, name_files)
    }

    /// Resolves the rows of an archive already read from `origin`, a file on
    /// disk, whose canonical path is `path`. An archive stored inside another
    /// one takes its name table from `origin`, because the table beside a
    /// `.rpf` file describes every archive in that file.
    pub fn from_opened(
        origin: &Path,
        path: ResourcePath,
        opened: Opened,
        name_files: &[PathBuf],
    ) -> Result<Self, String> {
        let tables = native::load_name_tables(origin, name_files)?;
        let types = Types::default();
        let entries: Vec<Entry> = opened.metadata.entries().collect();
        let resolved = Resolver::new(&tables.table, &types, MountPrefix::EMPTY).resolve(&entries);
        let by_row: std::collections::HashMap<u32, usize> = resolved
            .rows
            .iter()
            .enumerate()
            .map(|(position, row)| (row.row, position))
            .collect();
        // One canonical identity per row, shared by every record and message.
        let mut entry_ids: Vec<EntryId> = entries
            .iter()
            .map(|entry| {
                EntryId::from_row(
                    entry,
                    by_row
                        .get(&entry.row)
                        .map(|&position| &resolved.rows[position]),
                    &types,
                )
            })
            .collect();
        resource::assign_occurrences(&mut entry_ids);
        Ok(Self {
            archive: origin.to_path_buf(),
            path,
            opened,
            types,
            resolved: ResolutionSet {
                rows: resolved.rows,
                by_row,
            },
            entry_ids,
            entries,
        })
    }

    /// The canonical path of the row at `position`.
    pub fn resource(&self, position: usize) -> Option<ResourcePath> {
        self.entry_ids
            .get(position)
            .map(|entry| self.path.with_entry(entry.clone()))
    }

    /// The canonical identity of the row at `position`, for a caller that
    /// enters one of its entries as another archive.
    pub fn entry_id(&self, position: usize) -> Option<&EntryId> {
        self.entry_ids.get(position)
    }

    /// The alternate read sources of this archive.
    pub fn alternates(&self) -> Alternates {
        Alternates::resolve(&self.archive, &self.opened.metadata)
    }

    /// The opened archive, its authentication and its source.
    pub fn opened(&self) -> &Opened {
        &self.opened
    }

    /// The rows, in row order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The names resolved for `row`, if the row was resolved at all.
    pub fn row_names(&self, row: u32) -> Option<&RowNames> {
        self.resolved.row(row)
    }

    /// The confirmed extension of a type ID, as text.
    pub fn extension_for(&self, type_id: u8) -> Option<&str> {
        self.extension(type_id)
    }

    /// The extension this build applies to a type: the archive's own type
    /// table when it carries one, otherwise the engine's registry, recovered
    /// from the executable. The same resolution the Explorer shows, so a name
    /// and an extension agree between the two.
    fn extension(&self, type_id: u8) -> Option<&str> {
        if let Some(extension) = self
            .types
            .extension(type_id)
            .and_then(|extension| std::str::from_utf8(extension).ok())
        {
            return Some(extension);
        }
        lforge_core::registry::native_extension(type_id).map(|native| native.extension)
    }

    /// Where the extension came from: `archive` when the archive's own type
    /// table declares it, `declared` when only the engine registry does.
    fn extension_source(&self, type_id: u8) -> Option<&'static str> {
        if self.types.extension(type_id).is_some() {
            return Some("archive");
        }
        lforge_core::registry::is_registered(type_id).then_some("declared")
    }

    fn namespace(&self, type_id: Option<u8>) -> Option<Class> {
        type_id.and_then(|type_id| self.types.class(type_id))
    }

    /// The type IDs and the properties this build establishes for them.
    pub fn types_json(&self) -> Value {
        let mut by_type: std::collections::BTreeMap<Option<u8>, usize> =
            std::collections::BTreeMap::new();
        for entry in &self.entries {
            *by_type.entry(entry.type_id()).or_default() += 1;
        }
        Value::Array(
            by_type
                .into_iter()
                .map(|(type_id, rows)| {
                    json!({
                        "type_id": type_id,
                        "rows": rows,
                        "extension": type_id.and_then(|type_id| self.extension(type_id)),
                        "extension_source": type_id.and_then(|type_id| self.extension_source(type_id)),
                        "namespace": self
                            .namespace(type_id)
                            .map(|class| class.namespace()),
                    })
                })
                .collect(),
        )
    }

    /// One row record. `alternates` is resolved once for the whole listing.
    pub fn row_json(&self, position: usize, source: &Source, alternates: &Alternates) -> Value {
        let entry = &self.entries[position];
        let names = self
            .resolved
            .row(entry.row)
            .expect("every row was resolved");
        let location = &entry.location;
        let type_id = entry.type_id();
        let mut record = json!({
            "schema": ROW_SCHEMA,
            "row": entry.row,
            "type_id": type_id,
            "extension": type_id.and_then(|type_id| self.extension(type_id)),
            "extension_source": type_id.and_then(|type_id| self.extension_source(type_id)),
            "namespace": self
                .namespace(type_id)
                .map(|class| class.namespace()),
            "name_hash": field(&entry.name_hash, |hash| json!(hex(*hash, 16))),
            "name_key": field(&entry.name_key, |key| json!(hex(*key, 8))),
            "name": crate::metadata::resolution_json(names),
            "layout": field(location, |location| json!(format!("{:?}", location.layout))),
            "payload_offset": field(location, |location| json!(hex(location.payload_offset, 16))),
            "stored_size": field(location, |location| json!(location.stored_len)),
            "logical_size": field(location, |location| json!(location.logical_len)),
            "mode": field(location, |location| json!(location.mode)),
            "chunks": field(&entry.chunks, |chunks| {
                json!({ "encoding": chunks.encoding, "count": chunks.chunks.len() })
            }),
            "payload_transform": match &entry.payload_transform {
                Ok(flag) => json!(flag),
                Err(reason) => json!({ "malformed": reason }),
            },
            "payload_cipher": match &entry.payload_cipher {
                Ok(None) => Value::Null,
                Ok(Some(cipher)) => cipher_json(cipher),
                Err(reason) => json!({ "malformed": reason }),
            },
            "read_source": match &entry.read_source {
                Ok(None) => json!("main"),
                Ok(Some(index)) => json!(index),
                Err(reason) => json!({ "malformed": reason }),
            },
            "raw": raw_json(entry, source, alternates.sources()),
            "contents": contents_json(
                entry,
                source,
                alternates.sources(),
                self.opened.stream.as_ref(),
            ),
            "authentication": self.opened.authentication.status(),
        });
        record["archive"] = json!(self.path.archive_display());
        if let Some(resource) = self.resource(position) {
            record["resource"] = json!({
                "display": resource.display(),
                "identity": resource.identity(),
                "limitations": resource.limitations(),
            });
        }
        record
    }

    /// The rows `[offset, offset + limit)` as records, in row order.
    pub fn rows_json(&self, offset: usize, limit: usize) -> Vec<Value> {
        let alternates = self.alternates();
        self.entries
            .iter()
            .enumerate()
            .skip(offset)
            .take(limit)
            .map(|(position, _)| self.row_json(position, &self.opened.source, &alternates))
            .collect()
    }

    pub fn authentication_json(&self) -> Value {
        authentication_json(&self.opened.authentication)
    }
}

/// How a file on disk is named in output: its own file name, so a search over
/// an installation reports the archives the user would name.
fn table_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn field<T>(value: &Field<T>, show: impl Fn(&T) -> Value) -> Value {
    match value {
        Ok(None) => Value::Null,
        Ok(Some(value)) => show(value),
        Err(reason) => json!({ "malformed": reason }),
    }
}

fn hex<T: std::fmt::UpperHex>(value: T, digits: usize) -> String {
    format!("0x{value:0digits$X}")
}

/// The descriptor the engine would use for a row's payload transform. `supported`
/// is false for every descriptor: this build does not decode transformed rows.
pub(crate) fn cipher_json(cipher: &CipherDescriptor) -> Value {
    match Algorithm::of(cipher.kind) {
        Ok(algorithm) => json!({
            "type": cipher.kind,
            "algorithm": format!("{:#x}", algorithm.id()),
            "key_id": format!("0x{:08X}", cipher.key_id),
            "parameter": cipher.parameter.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "supported": matches!(algorithm, Algorithm::Untraced(0x11)),
        }),
        Err(reason) => json!({ "type": cipher.kind, "malformed": reason.to_string() }),
    }
}

fn raw_json(entry: &Entry, source: &Source, alternates: &[Option<Source>]) -> Value {
    match native::raw_state(entry, source, alternates) {
        native::RawState::Available { size } => json!({ "available": true, "size": size }),
        native::RawState::Unavailable { reason } => {
            json!({ "available": false, "reason": reason })
        }
    }
}

fn contents_json(
    entry: &Entry,
    source: &Source,
    alternates: &[Option<Source>],
    stream: Option<&lforge_rage9::rpf::metadata::provider::RecognizedSource>,
) -> Value {
    let state = native::contents_state(entry, source, alternates, stream);
    let mut value = json!({ "readable": state.readable, "state": state.state });
    if let Some(reason) = state.reason {
        value["reason"] = json!(reason);
    }
    value
}

pub fn authentication_json(authentication: &Authentication) -> Value {
    match authentication {
        Authentication::NotApplicable => json!({ "status": authentication.status() }),
        Authentication::Authenticated(report) => json!({
            "status": "authenticated",
            "outcome": report.outcome.to_string(),
            "stage": report.stage,
            "signature": report.signature.to_string(),
            "archive_pass": report.archive_pass,
            "candidates": report.candidates,
            "selected_candidate": report.selected_candidate,
        }),
    }
}

pub struct LsOptions {
    pub file: PathBuf,
    pub executable: Option<PathBuf>,
    pub candidates: Vec<PathBuf>,
    pub offset: usize,
    pub limit: usize,
    pub json: bool,
}

pub fn run_ls(options: LsOptions) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    let listing = Listing::open(
        &options.file,
        options.executable.as_deref(),
        &options.candidates,
        &cancel,
    )?;
    let total = listing.entries.len();
    let offset = options.offset.min(total);
    let limit = options.limit;
    let rows = listing.rows_json(offset, limit);
    if options.json {
        let document = json!({
            "schema": LIST_SCHEMA,
            "archive": listing.archive.display().to_string(),
            "relative": listing.path.archive_display(),
            "authentication": listing.authentication_json(),
            "types": listing.types_json(),
            "total": total,
            "offset": offset,
            "limit": limit,
            "returned": rows.len(),
            "truncated": offset + rows.len() < total,
            "rows": rows,
        });
        print_json(&document)
    } else {
        print_ls_text(&listing, &rows, offset, total);
        Ok(())
    }
}

fn print_json(value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|err| err.to_string())?;
    println!("{text}");
    Ok(())
}

fn print_ls_text(listing: &Listing, rows: &[Value], offset: usize, total: usize) {
    println!(
        "archive:      {} ({} rows, {} authenticated)",
        listing.path.archive_display(),
        total,
        listing.opened.authentication.status()
    );
    if let Some(types) = listing.types_json().as_array() {
        let summary: Vec<String> = types
            .iter()
            .map(|value| {
                format!(
                    "{}={}{}",
                    value["type_id"],
                    value["rows"],
                    value["extension"]
                        .as_str()
                        .map(|extension| format!(" (.{extension}, {})", value["namespace"]))
                        .unwrap_or_default()
                )
            })
            .collect();
        println!("types:        {}", summary.join(", "));
    }
    println!();
    println!(
        "{:>6} {:>4} {:<5} {:<8} {:<20} {:>12} {:>12} {:<12} resource  names",
        "row", "type", "ext", "key", "stored key", "logical", "stored", "contents"
    );
    for row in rows {
        let resource = row["resource"]["display"].as_str().unwrap_or("-");
        let names = names_text(&row["name"]);
        let key = match (&row["name_hash"], &row["name_key"]) {
            (Value::Null, Value::Null) => "-".to_string(),
            (Value::Null, key) => format!("key {}", text(key)),
            (hash, _) => text(hash),
        };
        let location = row["contents"]["state"].as_str().unwrap_or("-");
        println!(
            "{:>6} {:>4} {:<5} {:<8} {:<20} {:>12} {:>12} {:<12} {}  {}",
            row["row"],
            text(&row["type_id"]),
            row["extension"].as_str().unwrap_or("-"),
            row["namespace"].as_str().unwrap_or("-"),
            key,
            text(&row["logical_size"]),
            text(&row["stored_size"]),
            location,
            resource,
            names
        );
    }
    println!();
    println!("showing {} of {} rows from {}", rows.len(), total, offset);
    println!(
        "the row column is the entry's position in this archive's table of contents, not a \
         resource identifier; lines with no name show the stored key"
    );
}

fn names_text(name: &Value) -> String {
    match name["status"].as_str() {
        Some("resolved") | Some("ambiguous") => {
            let candidates: Vec<String> = name["candidates"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|candidate| candidate["name"].as_str().map(str::to_string))
                .collect();
            let suffix = if name["status"] == json!("ambiguous") {
                " (ambiguous)"
            } else {
                ""
            };
            format!("{}{suffix}", candidates.join(", "))
        }
        _ => "-".to_string(),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_string(),
        other => other.to_string(),
    }
}

pub struct SearchOptions {
    pub path: PathBuf,
    pub executable: Option<PathBuf>,
    pub candidates: Vec<PathBuf>,
    pub name: Option<String>,
    pub hash: Option<Key>,
    pub type_id: Option<u8>,
    pub extension: Option<String>,
    pub readable: Option<bool>,
    pub transformed: Option<bool>,
    pub archive: Option<String>,
    pub max_depth: usize,
    pub max_archives: usize,
    pub offset: usize,
    pub limit: usize,
    pub json: bool,
    /// Enter archives stored inside an archive, and search their rows too.
    pub recursive: bool,
    /// The largest archive one row may store, spooled to temporary storage.
    pub max_nested_bytes: u64,
    /// The most temporary storage one search may use for nested archives.
    pub max_spool_bytes: u64,
}

/// Parses `--hash` as `hash64` (16 digits) or `key32` (8 digits), with or
/// without `0x`.
pub fn parse_hash(text: &str) -> Result<Key, String> {
    let hex = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("'{text}' is not a hexadecimal key"));
    }
    let value = u64::from_str_radix(hex, 16).map_err(|_| format!("'{text}' is not a key"))?;
    match hex.len() {
        16 => Ok(Key::Hash64(value)),
        8 => Ok(Key::Key32(value as u32)),
        _ => Err(format!(
            "'{text}' must have 16 hexadecimal digits for hash64 or 8 for key32"
        )),
    }
}

fn matches(
    listing: &Listing,
    position: usize,
    options: &SearchOptions,
    alternates: &Alternates,
) -> bool {
    let entry = &listing.entries[position];
    if let Some(type_id) = options.type_id
        && entry.type_id() != Some(type_id)
    {
        return false;
    }
    if let Some(extension) = &options.extension {
        let confirmed = entry
            .type_id()
            .and_then(|type_id| listing.extension(type_id));
        if !confirmed.is_some_and(|confirmed| confirmed.eq_ignore_ascii_case(extension)) {
            return false;
        }
    }
    if let Some(readable) = options.readable {
        let state = native::contents_state(
            entry,
            &listing.opened.source,
            alternates.sources(),
            listing.opened.stream.as_ref(),
        );
        let matched = state.readable.is_some_and(|value| value == readable);
        if !matched {
            return false;
        }
    }
    if let Some(transformed) = options.transformed
        && matches!(entry.payload_transform, Ok(true)) != transformed
    {
        return false;
    }
    if let Some(name) = &options.name {
        let needle = name.to_ascii_lowercase();
        let resolved = listing.resolved.row(entry.row);
        let found = resolved.is_some_and(|row| {
            row.resolution
                .names()
                .iter()
                .any(|name| name.text.to_ascii_lowercase().contains(&needle))
        });
        if !found {
            return false;
        }
    }
    if let Some(hash) = options.hash {
        // Only the column of the row's established type class may match, the
        // same contract the resolver uses. An unknown class has no
        // authoritative hash column, so it matches neither search width.
        let class = entry
            .type_id()
            .and_then(|type_id| listing.types.class(type_id));
        if !hash_matches(class, entry, hash) {
            return false;
        }
    }
    true
}

/// Whether `entry`, whose type class is `class`, stores `hash` in the column
/// that class makes authoritative. A row of one class never matches the other
/// class's column, even when both columns hold a value; a row of unknown class
/// matches neither.
fn hash_matches(class: Option<Class>, entry: &Entry, hash: Key) -> bool {
    if class != Some(hash.class()) {
        return false;
    }
    match hash {
        Key::Hash64(value) => entry.name_hash.as_ref().ok().copied().flatten() == Some(value),
        Key::Key32(value) => entry.name_key.as_ref().ok().copied().flatten() == Some(value),
    }
}

/// One archive the search still has to look at.
struct Pending {
    /// The file on disk whose bytes the archive is read from.
    origin: PathBuf,
    /// The canonical path of the archive itself.
    path: ResourcePath,
    /// How many archives it was reached through; a file on disk is 0.
    depth: usize,
    /// An archive already opened, or `None` for a file on disk not yet opened.
    opened: Option<Box<Opened>>,
}

/// Whether `entry` declares the archive type, so a search may enter it.
fn is_archive(entry: &Entry, extension: Option<&str>) -> bool {
    entry.type_id().is_some()
        && extension.is_some_and(|extension| extension.eq_ignore_ascii_case("rpf"))
}

pub fn run_search(options: SearchOptions) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    let root = options.path.clone();
    let single = root.is_file();
    let (archives, truncated) = native::collect_archives(
        &root,
        native::ScanLimits {
            max_depth: options.max_depth,
            max_archives: options.max_archives,
        },
        &cancel,
    )?;
    let mut skipped = Vec::new();
    let mut found = Vec::new();
    let mut matched = 0usize;
    // One companion resolution per opened archive, reused for every row.
    let mut companions_resolved = 0usize;
    let mut nested_opened = 0usize;
    let mut spooled = 0u64;
    let mut stopped = None;
    let offset = options.offset;
    let filter = options
        .archive
        .as_ref()
        .map(|filter| filter.to_ascii_lowercase());
    // A file on disk is named by its path under the search root, so `--archive`
    // keeps selecting by directory; a single file is named by its file name.
    let name_of = |archive: &Path| {
        if single {
            table_name(archive)
        } else {
            archive
                .strip_prefix(&root)
                .unwrap_or(archive)
                .to_string_lossy()
                .replace('\\', "/")
        }
    };
    // Files on disk first, in scan order, then the archives inside them in row
    // order, so the output order does not depend on how the walk is scheduled.
    let mut pending: Vec<Pending> = archives
        .iter()
        .rev()
        .map(|archive| Pending {
            origin: archive.clone(),
            path: ResourcePath::root(name_of(archive)),
            depth: 0,
            opened: None,
        })
        .collect();
    while let Some(item) = pending.pop() {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        if let Some(filter) = &filter
            && !item.path.archive_display().to_ascii_lowercase().contains(filter)
        {
            continue;
        }
        if companions_resolved >= options.max_archives {
            stopped = Some("max_archives");
            break;
        }
        let opened = match item.opened {
            Some(opened) => *opened,
            None => {
                match native::open_metadata_cancellable(
                    &item.origin,
                    MAX_METADATA,
                    options.executable.as_deref(),
                    &cancel,
                ) {
                    Ok(opened) => opened,
                    Err(reason) => {
                        skipped.push(json!({
                            "archive": item.path.archive_display(),
                            "identity": item.path.identity(),
                            "reason": reason,
                        }));
                        continue;
                    }
                }
            }
        };
        let listing = match Listing::from_opened(
            &item.origin,
            item.path.clone(),
            opened,
            &options.candidates,
        ) {
            Ok(listing) => listing,
            Err(reason) => {
                skipped.push(json!({
                    "archive": item.path.archive_display(),
                    "identity": item.path.identity(),
                    "reason": reason,
                }));
                continue;
            }
        };
        let alternates = listing.alternates();
        companions_resolved += 1;
        for position in 0..listing.entries.len() {
            if !matches(&listing, position, &options, &alternates) {
                continue;
            }
            matched += 1;
            if matched > offset && found.len() < options.limit {
                found.push(listing.row_json(position, &listing.opened.source, &alternates));
            }
        }
        if !options.recursive || item.depth + 1 >= options.max_depth {
            continue;
        }
        let mut children = Vec::new();
        for position in 0..listing.entries.len() {
            if stopped.is_some() {
                break;
            }
            let entry = &listing.entries[position];
            if !is_archive(
                entry,
                entry.type_id().and_then(|type_id| listing.extension(type_id)),
            ) {
                continue;
            }
            // The budget counts what has been opened, so check it before the
            // next archive is read rather than after the whole listing is done.
            if companions_resolved + children.len() >= options.max_archives {
                stopped = Some("max_archives");
                break;
            }
            let Some(child) = listing.resource(position) else {
                continue;
            };
            let limits = native::NestedLimits {
                max_nested_bytes: options.max_nested_bytes,
                max_spool_bytes: options.max_spool_bytes,
                spooled,
            };
            match native::open_nested(
                entry,
                &listing.opened,
                alternates.sources(),
                &child.archive_display(),
                limits,
                options.executable.as_deref(),
                &cancel,
            ) {
                Ok((nested, spent)) => {
                    spooled += spent;
                    nested_opened += 1;
                    children.push(Pending {
                        origin: item.origin.clone(),
                        path: child,
                        depth: item.depth + 1,
                        opened: Some(Box::new(nested)),
                    });
                }
                Err(native::NestedError::SpoolBudget { .. }) => {
                    stopped = Some("max_spool_bytes");
                }
                Err(err) => {
                    skipped.push(json!({
                        "archive": child.archive_display(),
                        "identity": child.identity(),
                        "reason": err.to_string(),
                    }));
                }
            }
        }
        pending.extend(children.into_iter().rev());
    }
    if options.json {
        let document = json!({
            "schema": SEARCH_SCHEMA,
            "root": root.display().to_string(),
            "archives": archives.len(),
            "nested": nested_opened,
            "spooled_bytes": spooled,
            "matched": matched,
            "offset": offset,
            "limit": options.limit,
            "returned": found.len(),
            "truncated": matched > offset + found.len(),
            "companions_resolved": companions_resolved,
            "archives_truncated": truncated,
            "stopped": stopped,
            "skipped": skipped,
            "rows": found,
        });
        print_json(&document)
    } else {
        println!(
            "{} of {} matched rows shown ({} matched in {} archives)",
            found.len(),
            matched,
            matched,
            companions_resolved
        );
        for row in &found {
            println!(
                "{:<28} {:>6} {:>4} {:<5} {:<8} {}  {}",
                row["archive"].as_str().unwrap_or("-"),
                row["row"],
                text(&row["type_id"]),
                row["extension"].as_str().unwrap_or("-"),
                row["namespace"].as_str().unwrap_or("-"),
                row["resource"]["display"].as_str().unwrap_or("-"),
                names_text(&row["name"])
            );
        }
        for entry in &skipped {
            println!(
                "skipped: {}: {}",
                entry["archive"].as_str().unwrap_or("?"),
                entry["reason"].as_str().unwrap_or("?")
            );
        }
        if let Some(reason) = stopped {
            println!("stopped: {reason}");
        }
        Ok(())
    }
}

pub struct ManifestOptions {
    pub file: PathBuf,
    pub executable: Option<PathBuf>,
    pub candidates: Vec<PathBuf>,
    /// `json` or `jsonl`.
    pub format: String,
    pub output: Option<PathBuf>,
    pub overwrite: bool,
}

pub fn run_manifest(options: ManifestOptions) -> Result<(), String> {
    if options.format != "json" && options.format != "jsonl" {
        return Err(format!(
            "'{}' is not a manifest format; use json or jsonl",
            options.format
        ));
    }
    let cancel = AtomicBool::new(false);
    let listing = Listing::open(
        &options.file,
        options.executable.as_deref(),
        &options.candidates,
        &cancel,
    )?;
    let header = json!({
        "schema": MANIFEST_SCHEMA,
        "archive": listing.archive.display().to_string(),
        "relative": listing.path.archive_display(),
        "authentication": listing.authentication_json(),
        "types": listing.types_json(),
        "rows": listing.entries.len(),
    });
    let produce = |writer: &mut dyn Write| -> Result<u64, String> {
        let mut written = 0u64;
        if options.format == "jsonl" {
            let mut head = header.clone();
            head["kind"] = json!("header");
            written += write_line(writer, &head)?;
            let alternates = listing.alternates();
            for position in 0..listing.entries.len() {
                let mut row = listing.row_json(position, &listing.opened.source, &alternates);
                row["kind"] = json!("row");
                written += write_line(writer, &row)?;
            }
        } else {
            let rows = listing.rows_json(0, listing.entries.len());
            let document = json!({
                "schema": MANIFEST_SCHEMA,
                "archive": header["archive"],
                "relative": header["relative"],
                "authentication": header["authentication"],
                "types": header["types"],
                "rows": rows,
            });
            let mut bytes = serde_json::to_vec(&document).map_err(|err| err.to_string())?;
            bytes.push(b'\n');
            writer.write_all(&bytes).map_err(|err| err.to_string())?;
            written += bytes.len() as u64;
        }
        Ok(written)
    };
    match &options.output {
        Some(path) => {
            let written = output::write_file(path, options.overwrite, produce)?;
            if options.format == "jsonl" {
                println!("wrote {written} bytes to {}", path.display());
            } else {
                println!(
                    "wrote a manifest of {} rows to {}",
                    listing.entries.len(),
                    path.display()
                );
            }
            Ok(())
        }
        None => {
            let out = io::stdout();
            let mut out = BufWriter::new(out.lock());
            produce(&mut out)?;
            out.flush()
                .map_err(|err| format!("cannot write output: {err}"))
        }
    }
}

fn write_line(writer: &mut dyn Write, value: &Value) -> Result<u64, String> {
    let line = serde_json::to_string(value).map_err(|err| err.to_string())?;
    writeln!(writer, "{line}").map_err(|err| err.to_string())?;
    Ok(line.len() as u64 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name_hash: Option<u64>, name_key: Option<u32>) -> Entry {
        Entry {
            row: 0,
            location: Ok(None),
            name_hash: Ok(name_hash),
            name_key: Ok(name_key),
            chunks: Ok(None),
            payload_transform: Ok(false),
            payload_cipher: Ok(None),
            payload_range: Ok(None),
            read_source: Ok(None),
            payload_end: None,
        }
    }

    #[test]
    fn payload_cipher_descriptors_report_type_algorithm_key_and_parameter() {
        let descriptor = CipherDescriptor {
            key_id: 0x1000_002E,
            kind: 0x11,
            parameter: [0xAB; 16],
        };
        let value = cipher_json(&descriptor);
        assert_eq!(value["type"], 0x11);
        assert_eq!(value["algorithm"], "0x11");
        assert_eq!(value["key_id"], "0x1000002E");
        assert_eq!(value["parameter"], "abababababababababababababababab");
        assert_eq!(value["supported"], true);

        // A cipher type that selects CBC reports the algorithm family
        // identifier, not the cipher type.
        let cbc = CipherDescriptor {
            kind: 16,
            ..descriptor
        };
        assert_eq!(cipher_json(&cbc)["algorithm"], "0x10");

        // Cipher types the engine rejects are reported as malformed.
        let invalid = CipherDescriptor {
            kind: 13,
            ..descriptor
        };
        let value = cipher_json(&invalid);
        assert_eq!(value["type"], 13);
        assert!(value["malformed"].is_string());
        assert!(value.get("algorithm").is_none());
    }

    #[test]
    fn hash_search_matches_only_the_class_column() {
        // A row that stores both keys must not match through the column its
        // type class does not make authoritative.
        let both = entry(Some(0x1234), Some(0x5678));
        assert!(hash_matches(
            Some(Class::Hash64),
            &both,
            Key::Hash64(0x1234)
        ));
        assert!(!hash_matches(
            Some(Class::Hash64),
            &both,
            Key::Key32(0x5678)
        ));
        assert!(hash_matches(Some(Class::Key32), &both, Key::Key32(0x5678)));
        assert!(!hash_matches(
            Some(Class::Key32),
            &both,
            Key::Hash64(0x1234)
        ));
        // An unknown class has no authoritative column.
        assert!(!hash_matches(None, &both, Key::Hash64(0x1234)));
        assert!(!hash_matches(None, &both, Key::Key32(0x5678)));
        // A different value does not match.
        assert!(!hash_matches(
            Some(Class::Hash64),
            &both,
            Key::Hash64(0x9999)
        ));
        // A malformed column never matches.
        let mut broken = both.clone();
        broken.name_hash = Err("bad".to_string());
        assert!(!hash_matches(
            Some(Class::Hash64),
            &broken,
            Key::Hash64(0x1234)
        ));
    }

    #[test]
    fn parses_both_hash_widths_exactly() {
        assert_eq!(parse_hash("0x000000000000ABCD"), Ok(Key::Hash64(0xABCD)));
        assert_eq!(parse_hash("0000ABCD"), Ok(Key::Key32(0xABCD)));
        assert!(parse_hash("0x1").is_err());
        assert!(parse_hash("0x00000000000000001").is_err());
        assert!(parse_hash("0x00000000000000ZZ").is_err());
    }

    #[test]
    fn names_text_reports_status() {
        let resolved = json!({
            "status": "resolved",
            "candidates": [{ "name": "packs/inner.rpf" }],
        });
        assert_eq!(names_text(&resolved), "packs/inner.rpf");
        let ambiguous = json!({
            "status": "ambiguous",
            "candidates": [{ "name": "readme" }, { "name": "\"readme\"x" }],
        });
        assert_eq!(names_text(&ambiguous), "readme, \"readme\"x (ambiguous)");
        assert_eq!(names_text(&json!({ "status": "unresolved" })), "-");
    }
}
