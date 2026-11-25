//! `lforge archive metadata`: the RPF9 table of contents as stored, and its
//! entries where it can be read without decryption.

use std::io::{self, BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use lforge_binary::Source;
use lforge_rage9::rpf;
use lforge_rage9::rpf::metadata::transform::{self, Algorithm};
use lforge_rage9::rpf::metadata::{
    CompanionStatus, Entry, Error, Field, Layout, Metadata, Prefix, Processing, Stored,
};
use lforge_rage9::rpf::names::{
    self, CandidateOutcome, Class, MountPrefix, Namespace, Provenance, Resolver, RowNames,
    StringTable, Types,
};
use serde_json::{Value, json};

use crate::native::{self, Alternates, Authentication};

/// Larger metadata areas are not read.
const MAX_METADATA: u64 = 256 * 1024 * 1024;

pub struct Options {
    pub entries: bool,
    pub limit: usize,
    pub candidates: Option<PathBuf>,
    pub archive_path: Option<String>,
    pub mount_prefix: Option<String>,
    pub extensions: Vec<Extension>,
    pub executable: Option<PathBuf>,
    pub json: bool,
}

/// A caller-supplied extension mapping, `EXT=TYPE` or `EXT=TYPE:CLASS`.
#[derive(Debug, Clone)]
pub struct Extension {
    extension: String,
    type_id: u8,
    class: Option<Class>,
}

pub fn parse_extension(text: &str) -> Result<Extension, String> {
    let usage = || format!("'{text}' is not EXT=TYPE or EXT=TYPE:hash64|key32");
    let (extension, rest) = text.split_once('=').ok_or_else(usage)?;
    let (type_id, class) = match rest.split_once(':') {
        Some((type_id, class)) => (type_id, Some(class)),
        None => (rest, None),
    };
    let type_id = lforge_binary::parse_offset(type_id)
        .ok()
        .and_then(|id| u8::try_from(id).ok())
        .ok_or_else(usage)?;
    let class = match class {
        None => None,
        Some("hash64") => Some(Class::Hash64),
        Some("key32") => Some(Class::Key32),
        Some(_) => return Err(usage()),
    };
    Ok(Extension {
        extension: extension.to_string(),
        type_id,
        class,
    })
}

/// The local name table and the address rules it is applied under.
struct Naming {
    path: PathBuf,
    sidecar: bool,
    table: StringTable,
    prefix: MountPrefix,
    types: Types,
}

impl Naming {
    fn read(options: &Options, archive: &Path) -> Result<Option<Self>, String> {
        let (path, sidecar) = match &options.candidates {
            Some(path) => (path.clone(), false),
            None => {
                let path = sidecar_path(archive);
                if path.is_file() {
                    (path, true)
                } else {
                    let addressing = options.archive_path.is_some()
                        || options.mount_prefix.is_some()
                        || !options.extensions.is_empty();
                    if addressing {
                        return Err(format!(
                            "--archive-path, --mount-prefix and --extension need a name table; \
                             pass --name-file or place one at {}",
                            path.display()
                        ));
                    }
                    return Ok(None);
                }
            }
        };
        let table = StringTable::read(&path)
            .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        let prefix = match (&options.mount_prefix, &options.archive_path) {
            (Some(mount), _) => MountPrefix::mounted(mount.as_bytes()).ok_or_else(|| {
                format!(
                    "'{mount}' is not a mount prefix: it must end in / or \\ and have at most {} bytes",
                    names::MAX_MOUNT_PREFIX_LEN
                )
            })?,
            (None, Some(archive)) => MountPrefix::from_archive_path(archive.as_bytes())
                .ok_or_else(|| format!("no mount prefix can be derived from '{archive}'"))?,
            (None, None) => MountPrefix::EMPTY,
        };
        let mut types = Types::default();
        for extension in &options.extensions {
            types.insert_extension(extension.extension.as_bytes(), extension.type_id);
            if let Some(class) = extension.class {
                types.insert_class(extension.type_id, class);
            }
        }
        Ok(Some(Self {
            path,
            sidecar,
            table,
            prefix,
            types,
        }))
    }
}

fn sidecar_path(archive: &Path) -> PathBuf {
    let mut name = archive.file_name().unwrap_or_default().to_os_string();
    name.push(".names.txt");
    archive.with_file_name(name)
}

pub fn run(path: &Path, options: &Options) -> Result<(), String> {
    let naming = Naming::read(options, path)?;
    // Open failures are command failures, not per-archive report states.
    let mut source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    rpf::read_header(&mut source).map_err(|err| format!("{}: {err}", path.display()))?;
    let report = report(path, options, naming.as_ref());
    let out = io::stdout().lock();
    let mut out = BufWriter::new(out);
    let result = if options.json {
        serde_json::to_writer_pretty(&mut out, &report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(out))
    } else {
        write_text(&report, &mut out)
    };
    result
        .and_then(|()| out.flush())
        .or_else(|err| match err.kind() {
            io::ErrorKind::BrokenPipe => Ok(()),
            _ => Err(err),
        })
        .map_err(|err| format!("cannot write output: {err}"))
}

fn range(range: &Range<usize>) -> Value {
    json!({ "start": range.start, "end": range.end })
}

fn prefix_json(prefix: &Prefix) -> Value {
    json!({
        "metadata_end": prefix.metadata_len,
        "primary_end": prefix.primary_len,
        "a_records": prefix.a_records,
        "b_size": prefix.b_len,
        "b_trailer_size": prefix.b_trailer_len,
        "columns": prefix.columns,
        "secondary_columns": prefix.secondary_columns,
        "rows": prefix.rows,
        "cell_width": prefix.cell_width,
        "flags": prefix.flags,
        "selector": prefix.selector,
    })
}

fn layout_json(layout: &Layout) -> Value {
    json!({
        "a_table": range(&layout.a_table),
        "b_block": range(&layout.b_block),
        "descriptors": range(&layout.descriptors),
        "primary_cells": range(&layout.primary_cells),
        "primary_pool": range(&layout.primary_pool),
        "secondary_cells": range(&layout.secondary_cells),
        "secondary_pool": range(&layout.secondary_pool),
    })
}

/// The validation chain's cipher passes, as far as the stored bytes tell.
fn passes_json(prefix: &Prefix, processing: Processing) -> Value {
    let static_pass = (prefix.selector != 0).then(|| {
        let index = prefix.selector >> 1;
        let kind = transform::static_kind(index);
        json!({
            "span_set": if prefix.selector & 1 != 0 { "A and B without the trailer" } else { "A and all of B" },
            "descriptor": index,
            "cipher_type": kind,
            "algorithm": match Algorithm::of(kind) {
                Ok(Algorithm::Identity) => "0 (no-op)".to_string(),
                Ok(Algorithm::Cbc) => "0x10 (CBC)".to_string(),
                Ok(Algorithm::Untraced(id)) => format!("{id:#x} (not analyzed)"),
                Err(err) => err.to_string(),
            },
        })
    });
    let archive_pass = match processing.archive_pass {
        Some(true) => json!("required: B sub-block 1 is present"),
        Some(false) => json!("not required: B sub-block 1 is absent"),
        None => json!("unknown: B sub-block 1 lies inside the static pass"),
    };
    let secondary = prefix.metadata_len > prefix.primary_len;
    json!({
        "static_pass": static_pass,
        "archive_pass": archive_pass,
        "secondary_area": if secondary { "non-empty, processed if the archive pass runs" } else { "empty" },
        "signature": "not checked",
    })
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

/// Whether the entry's stored bytes can be read as they are, and why not.
fn raw_json(entry: &Entry, source: &Source, alternates: &[Option<Source>]) -> Value {
    match entry.raw_source(source, alternates) {
        Ok(view) => json!({ "available": true, "size": view.len() }),
        Err(Error::Encoded { encoding, .. }) => {
            json!({ "available": false, "reason": format!("stored {encoding}") })
        }
        Err(Error::ReadSource { index, .. }) => json!({
            "available": false,
            "reason": format!("alternate read source {index} is not available"),
        }),
        Err(err) => json!({ "available": false, "reason": err.to_string() }),
    }
}

/// How the entry's contents can be obtained: one of the readability states.
/// This reports actual payload readability, not only raw-byte availability.
///
/// - `stored`: readable as the stored bytes are.
/// - `decoded`: readable after supported decoding (raw DEFLATE or chunks).
/// - `unsupported_transform`: behind the unsupported payload transform.
/// - `unsupported_compression`: an unsupported compression mode.
/// - `alternate_source`: read through a companion that is not available.
/// - `malformed`: the payload metadata did not parse or is inconsistent.
fn contents_json(entry: &Entry, source: &Source, alternates: &[Option<Source>]) -> Value {
    let state = |readable: bool, state: &str, reason: Option<String>| {
        let mut value = json!({ "readable": readable, "state": state });
        if let Some(reason) = reason {
            value["reason"] = json!(reason);
        }
        value
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
        return state(false, "malformed", Some(reason.clone()));
    }
    match entry.payload(source, alternates) {
        Ok(_) if entry.raw_source(source, alternates).is_ok() => state(true, "stored", None),
        Ok(_) => state(true, "decoded", None),
        Err(Error::Encoded { encoding, .. }) => state(
            false,
            "unsupported_transform",
            Some(format!("stored {encoding}")),
        ),
        Err(Error::Undecodable { reason, .. }) => {
            state(false, "unsupported_compression", Some(reason))
        }
        Err(Error::ReadSource { index, .. }) => state(
            false,
            "alternate_source",
            Some(format!("alternate read source {index} is not available")),
        ),
        Err(err) => state(false, "malformed", Some(err.to_string())),
    }
}

fn entry_json(
    entry: &Entry,
    source: &Source,
    alternates: &[Option<Source>],
    names: &RowNames,
    show_names: bool,
) -> Value {
    let location = &entry.location;
    let mut value = json!({
        "row": entry.row,
        "layout": field(location, |l| json!(format!("{:?}", l.layout))),
        "type_id": field(location, |l| json!(l.type_id)),
        "payload_offset": field(location, |l| json!(l.payload_offset)),
        "stored_size": field(location, |l| json!(l.stored_len)),
        "logical_size": field(location, |l| json!(l.logical_len)),
        "mode": field(location, |l| json!(l.mode)),
        "name_hash": field(&entry.name_hash, |h| json!(hex(*h, 16))),
        "name_key": field(&entry.name_key, |k| json!(hex(*k, 8))),
        "chunks": field(&entry.chunks, |c| json!({ "encoding": c.encoding, "count": c.chunks.len() })),
        "payload_transform": match &entry.payload_transform {
            Ok(flag) => json!(flag),
            Err(reason) => json!({ "malformed": reason }),
        },
        "read_source": match &entry.read_source {
            Ok(None) => json!("main"),
            Ok(Some(index)) => json!(index),
            Err(reason) => json!({ "malformed": reason }),
        },
        "raw": raw_json(entry, source, alternates),
        "contents": contents_json(entry, source, alternates),
    });
    value["name_resolution"] = resolution_json(names);
    if show_names {
        value["names"] = names
            .resolution
            .names()
            .iter()
            .map(|name| json!(name.text))
            .collect();
        value["ambiguous"] = json!(names.resolution.is_ambiguous());
    }
    value
}

fn resolution_json(row: &RowNames) -> Value {
    let status = if row.resolution.is_ambiguous() {
        "ambiguous"
    } else if row.resolution.is_resolved() {
        "resolved"
    } else {
        "unresolved"
    };
    let namespace = match row.namespace {
        Namespace::Hash64 => json!("hash64"),
        Namespace::Key32 => json!("key32"),
        Namespace::Mixed => json!("mixed"),
        Namespace::Unknown => Value::Null,
    };
    json!({
        "status": status,
        "namespace": namespace,
        "candidates": row
            .resolution
            .names()
            .iter()
            .map(|name| json!({
                "name": name.text,
                "provenance": name.provenance.text(),
                "algorithm": match name.algorithm {
                    Class::Hash64 => "hash64",
                    Class::Key32 => "key32",
                },
                "verified": name.verified,
            }))
            .collect::<Vec<_>>(),
    })
}

fn report(path: &Path, options: &Options, naming: Option<&Naming>) -> Value {
    let unreadable = |reason: String| {
        json!({
            "format": "RPF9",
            "state": "unreadable",
            "authentication": { "status": "unavailable", "reason": reason },
            "entries": { "available": false, "reason": reason },
        })
    };
    let mut source = match Source::open(path) {
        Ok(source) => source,
        Err(err) => return unreadable(format!("cannot open {}: {err}", path.display())),
    };
    if let Err(err) = rpf::read_header(&mut source) {
        return unreadable(format!("{}: {err}", path.display()));
    }
    // The header, and at most the A table, decide whether the whole metadata
    // area is worth reading.
    let probe = match Stored::probe(&mut source.clone()) {
        Ok(probe) => probe,
        Err(err) => return unreadable(format!("{}: {err}", path.display())),
    };
    let prefix = probe.prefix;
    let mut report = json!({
        "format": "RPF9",
        "prefix": prefix_json(&prefix),
        "regions": layout_json(&probe.layout),
        "passes": passes_json(&prefix, probe.processing),
        "transformed": false,
        "verified": false,
        "authentication": { "status": "not_attempted" },
    });
    let (metadata, metadata_source, authentication) = if probe.processing.is_none() {
        match Stored::read(&mut source, MAX_METADATA).and_then(Stored::decode) {
            Ok(metadata) => (metadata, source, Authentication::NotApplicable),
            Err(err) => {
                report["state"] = json!("stored");
                report["entries"] = json!({ "available": false, "reason": err.to_string() });
                return report;
            }
        }
    } else if options.executable.is_some() {
        match native::open_metadata(path, MAX_METADATA, options.executable.as_deref()) {
            Ok(opened) => (opened.metadata, opened.source, opened.authentication),
            Err(reason) => {
                report["state"] = json!("stored");
                report["authentication"] = json!({ "status": "unavailable", "reason": reason });
                report["entries"] = json!({ "available": false, "reason": reason });
                return report;
            }
        }
    } else {
        let reason = probe
            .unsupported()
            .unwrap_or_else(|| "the metadata is processed".to_string());
        report["state"] = json!("stored");
        report["authentication"] = json!({ "status": "unavailable", "reason": reason });
        report["entries"] = json!({
            "available": false,
            "reason": format!("{}; {reason}", Error::Transformed(probe.processing)),
        });
        return report;
    };
    report["state"] = json!("decoded");
    report["authentication"] = authentication_json(&authentication);
    if let Some(verification) = authentication.report() {
        report["transformed"] = json!(true);
        report["verified"] = json!(true);
        report["passes"]["signature"] = json!("verified");
        if let Some(pass) = verification.archive_pass {
            report["passes"]["archive_pass"] = json!(if pass {
                "required: B sub-block 1 is present"
            } else {
                "not required: B sub-block 1 is absent"
            });
        }
    }
    let alternates = Alternates::resolve(path, &metadata);
    report["entries"] = entries_json(&metadata, &metadata_source, &alternates, options, naming);
    report
}

fn authentication_json(authentication: &Authentication) -> Value {
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

/// A summary of the archive's companion files, where it lists any.
fn companions_json(alternates: &Alternates) -> Option<Value> {
    if let Some(problem) = &alternates.problem {
        return Some(json!({ "available": false, "reason": problem }));
    }
    if alternates.records.is_empty() {
        return None;
    }
    let count =
        |kind: fn(&CompanionStatus) -> bool| alternates.statuses.iter().filter(|s| kind(s)).count();
    Some(json!({
        "records": alternates.records.len(),
        "available": count(|s| matches!(s, CompanionStatus::Available(_))),
        "missing": count(|s| matches!(s, CompanionStatus::Missing(_))),
        "invalid": count(|s| matches!(s, CompanionStatus::Invalid(_))),
        "unsupported": count(|s| matches!(s, CompanionStatus::Unsupported(_))),
    }))
}

fn entries_json(
    metadata: &Metadata,
    source: &Source,
    alternates: &Alternates,
    options: &Options,
    naming: Option<&Naming>,
) -> Value {
    let entries: Vec<Entry> = metadata.entries().collect();
    let mut value = json!({
        "available": true,
        "source": "native_toc",
        "rows": entries.len(),
    });
    if let Some(companions) = companions_json(alternates) {
        value["companions"] = companions;
    }
    let empty_table = StringTable::default();
    let default_types = Types::default();
    let (table, types, prefix) = match naming {
        Some(naming) => (&naming.table, &naming.types, naming.prefix),
        None => (&empty_table, &default_types, MountPrefix::EMPTY),
    };
    let resolved = Resolver::new(table, types, prefix).resolve(&entries);
    if let Some(naming) = naming {
        let count = |provenance: Provenance, outcome: fn(&CandidateOutcome) -> bool| {
            resolved
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate.provenance == provenance && outcome(&candidate.outcome)
                })
                .count()
        };
        let unresolved = count(Provenance::CandidatePath, |outcome| {
            matches!(outcome, CandidateOutcome::Unresolved(_))
        });
        let unmatched = count(Provenance::CandidatePath, |outcome| {
            matches!(outcome, CandidateOutcome::NoRow)
        });
        let verified = resolved
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.provenance == Provenance::UserMapping && candidate.verified
            })
            .count();
        let named = resolved
            .rows
            .iter()
            .filter(|row| !row.resolution.names().is_empty())
            .count();
        value["names"] = json!({
            "source": naming.path.to_string_lossy(),
            "sidecar": naming.sidecar,
            "entries": naming.table.entries().len(),
            "candidates": naming.table.candidates(),
            "mappings": naming.table.mappings(),
            "unresolved_candidates": unresolved,
            "unmatched_candidates": unmatched,
            "named_rows": named,
            "resolved_rows": resolved.rows.iter().filter(|row| row.resolution.is_resolved()).count(),
            "ambiguous_rows": resolved.rows.iter().filter(|row| row.resolution.is_ambiguous()).count(),
            "unresolved_rows": resolved.rows.len() - named,
            "verified_mappings": verified,
            "unconfirmed_mappings": naming.table.mappings() - verified,
            "skipped_lines": naming.table.skipped(),
            "duplicate_lines": naming.table.duplicates(),
            "truncated": naming.table.truncated(),
            "unusable_rows": resolved.unusable_rows,
        });
    }
    if options.entries {
        value["listed"] = entries
            .iter()
            .take(options.limit)
            .enumerate()
            .map(|(position, entry)| {
                entry_json(
                    entry,
                    source,
                    alternates.sources(),
                    &resolved.rows[position],
                    naming.is_some(),
                )
            })
            .collect();
    }
    value
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_string(),
        Value::Object(object) if object.contains_key("malformed") => "malformed".to_string(),
        other => other.to_string(),
    }
}

fn write_text(report: &Value, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "format:      RPF9")?;
    writeln!(out, "state:       {}", text(&report["state"]))?;
    if let Value::Object(prefix) = &report["prefix"] {
        let p = |key: &str| prefix[key].as_u64().unwrap_or(0);
        writeln!(
            out,
            "metadata:    ends at {:#x}, primary area ends at {:#x}",
            p("metadata_end"),
            p("primary_end")
        )?;
        writeln!(
            out,
            "table:       {} rows, {} columns ({} secondary), {}-byte cells",
            p("rows"),
            p("columns"),
            p("secondary_columns"),
            p("cell_width")
        )?;
        writeln!(
            out,
            "A, B:        {} records, {} bytes ({} trailer)",
            p("a_records"),
            p("b_size"),
            p("b_trailer_size")
        )?;
        writeln!(
            out,
            "flags:       {:#04x}, selector {:#04x}",
            p("flags"),
            p("selector")
        )?;
    }
    if let Value::Object(regions) = &report["regions"] {
        writeln!(out, "regions:")?;
        for (name, region) in regions {
            writeln!(
                out,
                "  {name:<16} {:#x}..{:#x}",
                region["start"].as_u64().unwrap_or(0),
                region["end"].as_u64().unwrap_or(0)
            )?;
        }
    }
    let passes = &report["passes"];
    if passes.is_object() {
        match passes["static_pass"].as_object() {
            None => writeln!(out, "static pass: not required")?,
            Some(pass) => writeln!(
                out,
                "static pass: required, descriptor {}, cipher type {}, algorithm {}",
                pass["descriptor"],
                pass["cipher_type"],
                text(&pass["algorithm"])
            )?,
        }
        writeln!(out, "archive pass: {}", text(&passes["archive_pass"]))?;
        writeln!(out, "secondary:   {}", text(&passes["secondary_area"]))?;
        writeln!(out, "signature:   {}", text(&passes["signature"]))?;
        writeln!(
            out,
            "transformed: {}",
            if report["transformed"] == json!(true) {
                "yes"
            } else {
                "no"
            }
        )?;
        writeln!(
            out,
            "verified:    {}",
            if report["verified"] == json!(true) {
                "yes"
            } else {
                "no"
            }
        )?;
    }
    writeln!(
        out,
        "authentication: {}",
        text(&report["authentication"]["status"])
    )?;
    let entries = &report["entries"];
    if entries["available"] != json!(true) {
        writeln!(
            out,
            "entries:     unavailable: {}",
            text(&entries["reason"])
        )?;
        return Ok(());
    }
    writeln!(out, "entries:     {} rows", entries["rows"])?;
    if let Some(names) = entries["names"].as_object() {
        match names.get("error") {
            Some(error) => writeln!(out, "names:       not matched: {}", text(error))?,
            None => writeln!(
                out,
                "names:       {} of {} candidates unresolved, {} rows named, {} ambiguous \
                 ({} resolved, {} unresolved), {} unverified mappings, {} skipped lines",
                names["unresolved_candidates"],
                names["candidates"],
                names["named_rows"],
                names["ambiguous_rows"],
                names["resolved_rows"],
                names["unresolved_rows"],
                names["unconfirmed_mappings"],
                names["skipped_lines"]
            )?,
        }
    }
    if let Some(companions) = entries["companions"].as_object() {
        match companions.get("reason") {
            Some(reason) => writeln!(out, "companions:  not read: {}", text(reason))?,
            None => writeln!(
                out,
                "companions:  {} ({} available, {} missing, {} invalid, {} unsupported)",
                companions["records"],
                companions["available"],
                companions["missing"],
                companions["invalid"],
                companions["unsupported"]
            )?,
        }
    }
    let Some(listed) = entries["listed"].as_array() else {
        return Ok(());
    };
    writeln!(out)?;
    writeln!(
        out,
        "{:>6} {:<6} {:>4} {:>14} {:>12} {:>12} {:>4} {:>6} {:<18} {:<11} raw",
        "row",
        "layout",
        "type",
        "offset",
        "stored",
        "logical",
        "mode",
        "source",
        "name",
        "contents"
    )?;
    for entry in listed {
        let name = match (&entry["name_hash"], &entry["name_key"]) {
            (Value::Null, Value::Null) => "-".to_string(),
            (Value::Null, key) => format!("key {}", text(key)),
            (hash, _) => text(hash),
        };
        let raw = match entry["raw"]["available"].as_bool() {
            Some(true) => "yes".to_string(),
            _ => text(&entry["raw"]["reason"]),
        };
        let contents = match entry["contents"]["state"].as_str() {
            Some("unsupported_transform") => "transform",
            Some("unsupported_compression") => "compression",
            Some("alternate_source") => "source",
            Some(state) => state,
            None => "-",
        };
        let number = |key: &str| match &entry[key] {
            Value::Number(n) => n
                .as_u64()
                .map_or_else(|| n.to_string(), |n| format!("{n:#x}")),
            other => text(other),
        };
        write!(
            out,
            "{:>6} {:<6} {:>4} {:>14} {:>12} {:>12} {:>4} {:>6} {:<18} {contents:<11} {raw}",
            entry["row"],
            text(&entry["layout"]),
            text(&entry["type_id"]),
            number("payload_offset"),
            number("stored_size"),
            number("logical_size"),
            text(&entry["mode"]),
            text(&entry["read_source"]),
            name,
        )?;
        if let Some(names) = entry["names"].as_array()
            && !names.is_empty()
        {
            let names: Vec<String> = names.iter().map(text).collect();
            let ambiguous = if entry["ambiguous"] == json!(true) {
                " (ambiguous)"
            } else {
                ""
            };
            write!(out, "  {}{ambiguous}", names.join(", "))?;
        }
        writeln!(out)?;
    }
    let rows = entries["rows"].as_u64().unwrap_or(0);
    if rows > listed.len() as u64 {
        writeln!(
            out,
            "... {} more rows, see --limit",
            rows - listed.len() as u64
        )?;
    }
    Ok(())
}
