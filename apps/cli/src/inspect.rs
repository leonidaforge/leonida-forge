//! `lforge binary inspect` and `lforge archive inspect`: structured inspection
//! of the formats this build decodes.
//!
//! The format is recognised from content, never from the file name. Only the
//! fields the research documentation establishes are reported; a field whose
//! meaning is unknown is reported as the number it stores, and an unknown
//! region is reported as a range, never as a guess. No payload bytes are
//! printed: block payloads stay behind [`lforge_rage9::rds5::decode_block`].

use std::io::{Read, Seek};
use std::path::Path;
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_rage9::rbf0;
use lforge_rage9::rds5::{self, Container, Storage};
use serde_json::{Map, Value, json};

use crate::native::{self, Alternates};

/// The schema of an inspection document.
pub const SCHEMA: &str = "leonida-forge.format-inspection/1";
/// Bytes read to recognise a format.
const SIGNATURE_LEN: usize = 16;
/// As in `archive metadata`.
const MAX_METADATA: u64 = 256 * 1024 * 1024;
/// Block failures listed by `--verify`; the count is always complete.
const MAX_FAILURES: usize = 20;
/// Blocks and entries shown by default.
pub const DEFAULT_SAMPLE: usize = 8;
/// The largest sample the command accepts.
pub const MAX_SAMPLE: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// How many records and entries are included.
    pub sample: usize,
    /// Read every block's storage selector instead of the first `sample`.
    pub blocks: bool,
    /// Inflate every zlib block and report what failed.
    pub verify: bool,
    pub json: bool,
}

/// Where the inspected bytes came from.
enum Origin<'a> {
    File(&'a Path),
    Row {
        archive: &'a Path,
        row: u32,
        executable: Option<&'a Path>,
    },
}

impl Origin<'_> {
    fn json(&self) -> Value {
        match self {
            Origin::File(path) => json!({ "file": path_string(path) }),
            Origin::Row {
                archive,
                row,
                executable,
            } => json!({
                "archive": path_string(archive),
                "row": row,
                "executable": executable.map(path_string),
            }),
        }
    }
}

fn path_string(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

pub fn file(path: &Path, options: &Options) -> Result<(), String> {
    let mut source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    let len = source.len();
    inspect(&mut source, len, Origin::File(path), options)
}

pub fn row(
    file: &Path,
    row: u32,
    executable: Option<&Path>,
    options: &Options,
) -> Result<(), String> {
    let opened = native::open_metadata(file, MAX_METADATA, executable)?;
    let rows = opened.metadata.rows();
    if row >= rows {
        return Err(match rows {
            0 => format!("the table of contents of {} has no rows", file.display()),
            1 => format!("row {row} is out of range: the only row is 0"),
            _ => format!("row {row} is out of range: the rows are 0 to {}", rows - 1),
        });
    }
    let entry = opened.metadata.entry(row).map_err(|err| err.to_string())?;
    let alternates = Alternates::resolve(file, &opened.metadata);
    let mut payload = entry
        .payload(&opened.source, alternates.sources())
        .map_err(|err| format!("row {row} cannot be read: {err}"))?;
    let len = payload.len();
    let origin = Origin::Row {
        archive: file,
        row,
        executable,
    };
    inspect(&mut payload, len, origin, options)
}

fn inspect<R: Read + Seek>(
    source: &mut R,
    len: u64,
    origin: Origin<'_>,
    options: &Options,
) -> Result<(), String> {
    let head = lforge_binary::read_at(source, 0, SIGNATURE_LEN)
        .map_err(|err| format!("cannot read the signature: {err}"))?;
    let (format, structure, failure) = if rds5::is_rds5(&head) {
        rds5_structure(source, len, options)
    } else if rbf0::is_rbf0(&head) {
        rbf0_structure(&head)
    } else if head.starts_with(b"PSIN") {
        psin_structure()
    } else if lforge_rage9::rpf::is_rpf9(&head) {
        nested_archive_structure()
    } else {
        (None, Value::Null, None)
    };

    let mut document = Map::new();
    document.insert("schema".into(), json!(SCHEMA));
    document.insert("source".into(), origin.json());
    document.insert("size".into(), json!(len));
    document.insert("signature".into(), json!(lforge_binary::hex_bytes(&head)));
    document.insert("format".into(), format.unwrap_or(Value::Null));
    document.insert("structure".into(), structure);
    document.insert(
        "raw".into(),
        json!({
            "available": true,
            "note": "the bytes are read-only; `binary dump` shows any range",
        }),
    );
    let document = Value::Object(document);

    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&document).expect("JSON value")
        );
    } else {
        print_text(&document);
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// A recognised format, its structure, and why it could not be parsed.
type Structure = (Option<Value>, Value, Option<String>);

fn format_json(id: &str, name: &str, support: &str, detail: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "support": support,
        "detail": detail,
    })
}

fn rds5_structure<R: Read + Seek>(source: &mut R, len: u64, options: &Options) -> Structure {
    let format = format_json(
        "rds5",
        "RDS5",
        "structural",
        "header, record array, ETPF chunk extent and block catalogue",
    );
    let limits = rds5::Limits::default();
    let cancel = AtomicBool::new(false);
    let mut container = match Container::read(source, len, &limits, &cancel) {
        Ok(container) => container,
        Err(err) => {
            return (
                Some(format),
                json!({ "valid": false, "error": err.to_string() }),
                Some(err.to_string()),
            );
        }
    };

    let sample = options.sample.clamp(1, MAX_SAMPLE);
    let classified = if options.blocks {
        container.classify(source, usize::MAX, &cancel).unwrap_or(0)
    } else {
        container.classify(source, sample, &cancel).unwrap_or(0)
    };

    let mut diagnostics: Vec<Value> = container
        .warnings
        .iter()
        .map(|warning| json!({ "severity": "warning", "message": warning }))
        .collect();
    let mut unknown: Vec<Value> = Vec::new();
    let mut failure = None;

    let verified = options.verify.then(|| {
        let mut checked = 0u64;
        let mut decoded = 0u64;
        let mut failures: Vec<Value> = Vec::new();
        let mut failed = 0u64;
        for block in &container.blocks {
            if !block.storage.is_zlib() {
                continue;
            }
            checked += 1;
            let mut len = 0u64;
            let result = rds5::decode_block(source, &container, block.index, &limits, &cancel, |_| {
                Ok(())
            })
            .map(|report| {
                len = report.len;
            });
            match result {
                Ok(()) => decoded += len,
                Err(err) => {
                    failed += 1;
                    if failures.len() < MAX_FAILURES {
                        failures.push(json!({
                            "block": block.index,
                            "offset": hex(block.offset),
                            "error": err.to_string(),
                        }));
                    }
                }
            }
        }
        let present = 0x1000u64.saturating_add(decoded);
        if decoded > 0 && present != u64::from(container.uncompressed_total) {
            diagnostics.push(json!({
                "severity": "note",
                "message": format!(
                    "0x{present:X} decoded bytes do not reproduce the declared uncompressed total 0x{:X}",
                    container.uncompressed_total
                ),
            }));
        }
        if failed > 0 {
            failure = Some(format!("{failed} zlib blocks did not decode"));
        }
        json!({
            "zlib_blocks": checked,
            "decoded_bytes": decoded,
            "failures": failed,
            "failure_sample": failures,
        })
    });

    if container.entry_count > 0 {
        unknown.push(json!({
            "offset": hex(container.entry_table_offset() + container.entry_table_len()),
            "length": container.region_len(),
            "field": "ETPF content after the entry table",
            "reason": "length is probable, content unknown",
        }));
    }
    for block in container
        .blocks
        .iter()
        .filter(|block| !block.storage.is_zlib() && block.storage != Storage::Unread)
    {
        unknown.push(json!({
            "offset": hex(block.offset),
            "length": block.stored_len,
            "field": format!("block {}", block.index),
            "reason": match block.storage {
                Storage::NotZlib => "carries the zlib selector value but is not zlib",
                Storage::Unidentified(_) => "compressor selector not identified",
                _ => "",
            },
        }));
    }

    let records: Vec<Value> = container
        .records
        .iter()
        .take(sample)
        .map(|record| {
            let role = if record.index == 0 {
                "chunk"
            } else if record.index == container.record_count() - 1 {
                "end"
            } else {
                "block"
            };
            let mut value = json!({
                "index": record.index,
                "role": role,
                "offset": hex(record.offset),
                "high_byte": format!("0x{:02X}", record.high_byte),
                "selector": record.selector(),
                "second_word": hex(u64::from(record.second_word)),
            });
            if role == "block" {
                value["counter"] = json!(record.counter());
                value["unknown"] = json!(record.upper());
            } else if role == "chunk" {
                value["layout_flag"] = json!(record.second_word >> 28);
            }
            value
        })
        .collect();
    let entries: Vec<Value> = container
        .entries(source, 0, sample as u32)
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            json!({
                "index": entry.index,
                "words": entry.words.iter().map(|word| format!("0x{word:08X}")).collect::<Vec<_>>(),
                "page": entry.page(),
            })
        })
        .collect();

    // The selector value is reported per group: the research identifies only
    // selector 0, and selectors 1, 2 and 3 each select an unknown codec.
    let mut by_storage = Map::new();
    let mut counts: Vec<(String, usize)> = vec![
        (
            "zlib".to_string(),
            container
                .blocks
                .iter()
                .filter(|block| block.storage == Storage::Zlib)
                .count(),
        ),
        (
            "not_zlib".to_string(),
            container
                .blocks
                .iter()
                .filter(|block| block.storage == Storage::NotZlib)
                .count(),
        ),
        (
            "unread".to_string(),
            container
                .blocks
                .iter()
                .filter(|block| block.storage == Storage::Unread)
                .count(),
        ),
    ];
    for selector in 1..=3u8 {
        counts.push((
            format!("selector_{selector}"),
            container
                .blocks
                .iter()
                .filter(|block| block.storage == Storage::Unidentified(selector))
                .count(),
        ));
    }
    for (name, count) in counts {
        if count > 0 {
            by_storage.insert(name, json!(count));
        }
    }
    let stored_bytes: u64 = container.blocks.iter().map(|block| block.stored_len).sum();
    let blocks: Vec<Value> = container
        .blocks
        .iter()
        .take(sample)
        .map(|block| {
            json!({
                "index": block.index,
                "record": block.record,
                "offset": hex(block.offset),
                "stored_len": block.stored_len,
                "selector": block.selector(),
                "storage": block.storage.name(),
                "counter": block.counter,
            })
        })
        .collect();

    let mut ranges = vec![
        json!({ "offset": hex(0), "length": rds5::HEADER_LEN, "field": "header" }),
        json!({
            "offset": hex(rds5::HEADER_LEN),
            "length": u64::from(container.record_count()) * 8,
            "field": "record array",
        }),
        json!({ "offset": hex(container.etpf_offset), "length": 0x10, "field": "ETPF header" }),
        json!({
            "offset": hex(container.entry_table_offset()),
            "length": container.entry_table_len(),
            "field": "ETPF entry table",
        }),
        json!({
            "offset": hex(container.content_end),
            "length": container.first_block - container.content_end,
            "field": "zero padding",
        }),
    ];
    if let Some((first, last)) = container.blocks.first().zip(container.blocks.last()) {
        ranges.push(json!({
            "offset": hex(first.offset),
            "length": last.offset + last.stored_len - first.offset,
            "field": "blocks",
        }));
    }

    let structure = json!({
        "valid": true,
        "header": {
            "version": format!("0x{:08X}", container.version),
            "record_count": container.record_count(),
            "uncompressed_total": container.uncompressed_total,
        },
        "records": {
            "count": container.record_count(),
            "blocks": container.blocks.len(),
            "shown": records.len(),
            "items": records,
        },
        "chunk": {
            "offset": hex(container.etpf_offset),
            "type": format!("0x{:X}", rds5::ETPF_TYPE),
            "entry_count": container.entry_count,
            "field_m": container.field_m,
            "content_end": hex(container.content_end),
            "shown": entries.len(),
            "entry_sample": entries,
        },
        "blocks": {
            "count": container.blocks.len(),
            "stored_bytes": stored_bytes,
            "classified": classified,
            "by_storage": by_storage,
            "shown": blocks.len(),
            "items": blocks,
        },
        "first_block": hex(container.first_block),
        "parsed_ranges": ranges,
        "unknown_regions": unknown,
        "verified": verified.unwrap_or(Value::Null),
        "diagnostics": diagnostics,
        "limitations": [
            "entry fields and the block record's upper second word have no established meaning",
            "the ETPF content after the entry table is not interpreted",
            "page sizes and pixel formats are not part of this container",
            "a block whose compressor selector is not identified is not decoded",
        ],
    });
    (Some(format), structure, failure)
}

fn rbf0_structure(head: &[u8]) -> Structure {
    let format = format_json(
        "rbf0",
        "RBF0",
        "header",
        "the fixed prefix and the root name length; the body grammar is unknown",
    );
    match rbf0::Header::parse(head) {
        Ok(header) => (
            Some(format),
            json!({
                "valid": true,
                "prefix": {
                    "len": rbf0::PREFIX_LEN,
                    "word": format!("0x{:04X}", header.word),
                    "flags": header.flags,
                    "root_name_len": header.root_name_len,
                },
                "parsed_ranges": [
                    { "offset": hex(0), "length": rbf0::PREFIX_LEN, "field": "prefix" },
                ],
                "unknown_regions": [
                    {
                        "offset": hex(rbf0::PREFIX_LEN as u64 + u64::from(header.root_name_len)),
                        "length": Value::Null,
                        "field": "body",
                        "reason": "the tag grammar and type system are not decoded",
                    },
                ],
                "diagnostics": [],
                "limitations": [
                    "the `u16` at +0x04 and the `u32` at +0x06 have no established meaning",
                    "the root name is payload text and is not printed",
                    "the body is not parsed; field names and values are not reported",
                ],
            }),
            None,
        ),
        Err(err) => (
            Some(format),
            json!({ "valid": false, "error": err.describe() }),
            Some(err.describe().to_string()),
        ),
    }
}

fn psin_structure() -> Structure {
    let format = format_json(
        "psin",
        "PSIN",
        "recognition",
        "the magic only; no header field, record structure or purpose is established",
    );
    (
        Some(format),
        json!({
            "valid": true,
            "unknown_regions": [
                {
                    "offset": hex(4),
                    "length": Value::Null,
                    "field": "payload",
                    "reason": "no field or record meaning is established",
                },
            ],
            "diagnostics": [],
            "limitations": [
                "only the four-byte magic is established",
                "no checked field in the first 32 bytes equals the payload size",
            ],
        }),
        None,
    )
}

fn nested_archive_structure() -> Structure {
    let format = format_json(
        "rpf9",
        "RPF9",
        "recognition",
        "a nested archive; its table of contents is read by the archive commands",
    );
    (
        Some(format),
        json!({
            "valid": true,
            "diagnostics": [],
            "limitations": [
                "inspection of a nested archive's own rows needs the archive commands",
            ],
        }),
        None,
    )
}

fn hex(value: u64) -> String {
    format!("0x{value:016X}")
}

/// Prints a document as `key: value` lines, recursing one level per object.
fn print_text(document: &Value) {
    let Some(map) = document.as_object() else {
        return;
    };
    let name = map
        .get("format")
        .and_then(|format| format.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unrecognised");
    let support = map
        .get("format")
        .and_then(|format| format.get("support"))
        .and_then(Value::as_str)
        .unwrap_or("-");
    println!("format:      {name} ({support})");
    if let Some(format) = map.get("format").and_then(Value::as_object)
        && let Some(detail) = format.get("detail").and_then(Value::as_str)
    {
        println!("detail:      {detail}");
    }
    if let Some(size) = map.get("size").and_then(Value::as_u64) {
        println!("size:        {size} bytes ({size:#x})");
    }
    if let Some(source) = map.get("source").and_then(Value::as_object) {
        if let Some(file) = source.get("file").and_then(Value::as_str) {
            println!("file:        {file}");
        }
        if let Some(archive) = source.get("archive").and_then(Value::as_str) {
            let row = source.get("row").and_then(Value::as_u64).unwrap_or(0);
            println!("archive:     {archive} row {row}");
        }
    }
    if let Some(structure) = map.get("structure").and_then(Value::as_object) {
        println!();
        print_object(structure, 0);
    }
}

fn print_object(map: &Map<String, Value>, depth: usize) {
    let indent = "  ".repeat(depth);
    for (key, value) in map {
        match value {
            Value::Object(nested) if depth < 3 => {
                println!("{indent}{key}:");
                print_object(nested, depth + 1);
            }
            Value::Array(items) if !items.is_empty() && depth >= 3 => {
                println!("{indent}{key}: {} items", items.len());
            }
            Value::Array(items) if items.iter().all(|item| !item.is_object()) => {
                println!("{indent}{key}: {}", join(items));
            }
            Value::Array(items) => {
                println!("{indent}{key}: {} items", items.len());
            }
            Value::Null => println!("{indent}{key}: -"),
            other => println!("{indent}{key}: {}", scalar(other)),
        }
    }
}

fn join(items: &[Value]) -> String {
    items.iter().map(scalar).collect::<Vec<_>>().join(", ")
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "-".to_string(),
        other => other.to_string(),
    }
}
