//! `lforge archive metadata`: the RPF9 table of contents as stored, and its
//! entries where it can be read without decryption.

use std::fs;
use std::io::{self, BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use lforge_binary::Source;
use lforge_rage9::rpf;
use lforge_rage9::rpf::metadata::transform::{self, Algorithm};
use lforge_rage9::rpf::metadata::{
    Entry, Error, Field, Layout, Metadata, Prefix, Processing, Stored,
};
use lforge_rage9::rpf::names::{self, Candidate, Class, Matches, MountPrefix, Types};
use serde_json::{Value, json};

/// Larger metadata areas are not read.
const MAX_METADATA: u64 = 256 * 1024 * 1024;

pub struct Options {
    pub entries: bool,
    pub limit: usize,
    pub candidates: Option<PathBuf>,
    pub archive_path: Option<String>,
    pub mount_prefix: Option<String>,
    pub extensions: Vec<Extension>,
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

/// The name inputs, if the caller supplied candidates.
struct Naming {
    candidates: Vec<Vec<u8>>,
    prefix: MountPrefix,
    types: Types,
}

impl Naming {
    fn read(options: &Options) -> Result<Option<Self>, String> {
        let Some(path) = &options.candidates else {
            return Ok(None);
        };
        let text =
            fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        let candidates = text
            .split(|&b| b == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
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
            candidates,
            prefix,
            types,
        }))
    }
}

pub fn run(path: &Path, options: &Options) -> Result<(), String> {
    let naming = Naming::read(options)?;
    let mut source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    rpf::read_header(&mut source).map_err(|err| format!("{}: {err}", path.display()))?;
    let report = report(&source, options, naming.as_ref());
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
fn raw_json(entry: &Entry, source: &Source) -> Value {
    match entry.raw_source(source, &[]) {
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

fn entry_json(entry: &Entry, source: &Source, names: Option<(&Matches, &Naming)>) -> Value {
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
        "raw": raw_json(entry, source),
    });
    if let Some((matches, naming)) = names
        && let Some(row) = matches.row(entry.row)
    {
        value["names"] = row
            .candidates
            .iter()
            .map(|&n| json!(String::from_utf8_lossy(&naming.candidates[n])))
            .collect();
        value["ambiguous"] = json!(row.ambiguous);
    }
    value
}

fn report(source: &Source, options: &Options, naming: Option<&Naming>) -> Value {
    let unreadable = |err: Error| {
        json!({
            "format": "RPF9",
            "state": "unreadable",
            "entries": { "available": false, "reason": err.to_string() },
        })
    };
    let mut source = source.clone();
    // The header, and at most the A table, decide whether the whole metadata
    // area is worth reading.
    let probe = match Stored::probe(&mut source) {
        Ok(probe) => probe,
        Err(err) => return unreadable(err),
    };
    let prefix = probe.prefix;
    let mut report = json!({
        "format": "RPF9",
        "prefix": prefix_json(&prefix),
        "regions": layout_json(&probe.layout),
        "passes": passes_json(&prefix, probe.processing),
        "transformed": false,
        "verified": false,
    });
    if let Some(reason) = probe.unsupported() {
        report["state"] = json!("stored");
        report["entries"] = json!({
            "available": false,
            "reason": format!("{}; {reason}", Error::Transformed(probe.processing)),
        });
        return report;
    }
    let metadata = match Stored::read(&mut source, MAX_METADATA).and_then(Stored::decode) {
        Ok(metadata) => metadata,
        Err(err) => {
            report["state"] = json!("stored");
            report["entries"] = json!({ "available": false, "reason": err.to_string() });
            return report;
        }
    };
    report["state"] = json!("decoded");
    report["entries"] = entries_json(&metadata, &source, options, naming);
    report
}

fn entries_json(
    metadata: &Metadata,
    source: &Source,
    options: &Options,
    naming: Option<&Naming>,
) -> Value {
    let entries: Vec<Entry> = metadata.entries().collect();
    let mut value = json!({ "available": true, "rows": entries.len() });
    let matches = naming.map(|naming| {
        let candidates: Vec<Candidate> = naming
            .candidates
            .iter()
            .map(|c| Candidate::Path(c))
            .collect();
        names::match_entries(&entries, &naming.prefix, &naming.types, &candidates)
    });
    let matches = match matches {
        None => None,
        Some(Ok(matches)) => {
            let matched = matches
                .rows
                .iter()
                .filter(|r| !r.candidates.is_empty())
                .count();
            let unresolved = matches.candidates.iter().filter(|c| c.is_err()).count();
            value["names"] = json!({
                "candidates": matches.candidates.len(),
                "unresolved_candidates": unresolved,
                "named_rows": matched,
                "ambiguous_rows": matches.rows.iter().filter(|r| r.ambiguous).count(),
            });
            Some(matches)
        }
        Some(Err(err)) => {
            value["names"] = json!({ "error": err.to_string() });
            None
        }
    };
    if options.entries {
        let names = matches.as_ref().zip(naming);
        value["listed"] = entries
            .iter()
            .take(options.limit)
            .map(|entry| entry_json(entry, source, names))
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
        writeln!(out, "transformed: no")?;
        writeln!(out, "verified:    no (the signature is not checked)")?;
    }
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
                "names:       {} of {} candidates unresolved, {} rows named, {} ambiguous",
                names["unresolved_candidates"],
                names["candidates"],
                names["named_rows"],
                names["ambiguous_rows"]
            )?,
        }
    }
    let Some(listed) = entries["listed"].as_array() else {
        return Ok(());
    };
    writeln!(out)?;
    writeln!(
        out,
        "{:>6} {:<6} {:>4} {:>14} {:>12} {:>12} {:>4} {:>6} {:<18} raw",
        "row", "layout", "type", "offset", "stored", "logical", "mode", "source", "name"
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
        let number = |key: &str| match &entry[key] {
            Value::Number(n) => n
                .as_u64()
                .map_or_else(|| n.to_string(), |n| format!("{n:#x}")),
            other => text(other),
        };
        write!(
            out,
            "{:>6} {:<6} {:>4} {:>14} {:>12} {:>12} {:>4} {:>6} {:<18} {raw}",
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
