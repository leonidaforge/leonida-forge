//! `lforge binary inspect` and `lforge archive inspect`: structured inspection
//! of the formats this build decodes.
//!
//! The format is recognised from content, never from the file name. Only the
//! fields the research documentation establishes are reported; a field whose
//! meaning is unknown is reported as the number it stores, and an unknown
//! region is reported as a range, never as a guess. No payload bytes are
//! printed: block payloads stay behind [`lforge_rage9::rds5::decode_block`].
//!
//! `archive inspect` reads the decoded logical payload of a native row or ZIP
//! entry, at any nesting level reached with `--enter`. `--raw` selects the
//! bytes as they are stored instead, and fails explicitly when a transform or
//! codec is not supported. The document separates the two.

use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_core::archive::Format;
use lforge_core::inspect as recognition;
use lforge_core::zip as zip_archive;
use lforge_rage9::rpf::metadata::{Entry, Payload};
use serde_json::{Map, Value, json};

use crate::native::{self, Alternates};
use crate::nested::{self, Selector};

/// The schema of an inspection document.
pub const SCHEMA: &str = recognition::SCHEMA;
/// As in `archive metadata`.
const MAX_METADATA: u64 = 256 * 1024 * 1024;
/// Blocks and entries shown by default.
pub const DEFAULT_SAMPLE: usize = recognition::DEFAULT_SAMPLE;

#[derive(Debug, Clone)]
pub struct Options {
    /// How many records and entries are included.
    pub sample: usize,
    /// Read every block's storage class instead of the first `sample`.
    pub blocks: bool,
    /// Decode every decodable block and report what failed.
    pub verify: bool,
    /// The RDS5 descriptor whose byte-level chain is reported.
    pub texture: Option<u32>,
    /// Where the reconstructed bytes of `texture` are written.
    pub output: Option<PathBuf>,
    /// Replace the output file if it already exists.
    pub overwrite: bool,
    pub json: bool,
}

impl Options {
    fn recognition(&self) -> recognition::Options {
        recognition::Options {
            sample: self.sample,
            blocks: self.blocks,
            verify: self.verify,
            texture: self.texture,
        }
    }
}

/// The final entry to inspect in the last archive of a chain.
#[derive(Debug, Clone, Copy, Default)]
pub struct Selection {
    pub row: Option<u32>,
    pub zip: Option<usize>,
    /// Inspect the bytes as stored instead of the decoded payload.
    pub raw: bool,
}

/// Where the inspected bytes came from, as the document reports it.
struct Context {
    source: Value,
    provenance: Value,
}

fn path_string(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// Inspects a file on disk.
pub fn file(path: &Path, options: &Options) -> Result<(), String> {
    let mut source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    let len = source.len();
    let provenance = json!({
        "depth": 0,
        "root": {
            "kind": "file",
            "name": file_name(path),
            "format": Value::Null,
            "format_id": Value::Null,
        },
        "chain": [],
        "selection": { "kind": "none" },
        "representation": {
            "kind": "file",
            "decoded": true,
            "note": "the bytes of a file on disk; nothing was decoded",
        },
    });
    let context = Context {
        source: json!({ "file": path_string(path) }),
        provenance,
    };
    emit(&mut source, len, context, options)?;
    // An explicit byte-level export of one descriptor, when asked for.
    if let (Some(descriptor), Some(output)) = (options.texture, options.output.as_deref()) {
        crate::output::ensure_not_input(output, &[path])?;
        let mut source =
            Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
        let len = source.len();
        let cancel = AtomicBool::new(false);
        let written = crate::output::write_file(output, options.overwrite, |writer| {
            recognition::rds5_texture(&mut source, len, descriptor, &cancel, |bytes| {
                writer.write_all(bytes)
            })
            .map(|report| report.decoded_len)
            .map_err(|err| format!("descriptor {descriptor} cannot be reconstructed: {err}"))
        })?;
        if options.json {
            eprintln!(
                "reconstructed descriptor {descriptor}: {written} bytes to {}",
                output.display()
            );
        } else {
            println!(
                "reconstructed descriptor {descriptor}: {written} bytes to {}",
                output.display()
            );
        }
    }
    Ok(())
}

/// Inspects a native row or ZIP entry of an archive, after descending through
/// `enters`.
pub fn archive(
    file: &Path,
    executable: Option<&Path>,
    enters: &[Selector],
    selection: &Selection,
    options: &Options,
) -> Result<(), String> {
    if selection.row.is_some() && selection.zip.is_some() {
        return Err("--row and --zip select different entries; give one".to_string());
    }
    let cancel = AtomicBool::new(false);
    let resolved = nested::resolve(file, executable, enters, &cancel)?;
    // `archive inspect FILE` without any selection keeps reading row 0, as it
    // always has. With `--enter`, a missing selection inspects the entered
    // archive itself.
    let legacy_row = enters.is_empty() && selection.row.is_none() && selection.zip.is_none();
    let row = selection.row.or(legacy_row.then_some(0));
    let source = json!({
        "archive": path_string(file),
        "row": row,
        "zip": selection.zip,
        "executable": executable.map(path_string),
        "entered": enters.iter().map(Selector::label).collect::<Vec<_>>(),
    });
    let representation = |kind: &'static str, decoded: bool, note: &str, error: Option<String>| {
        let mut value = json!({ "kind": kind, "decoded": decoded, "note": note });
        if let Some(error) = error {
            value["error"] = json!(error);
        }
        value
    };

    match (selection.zip, row) {
        (None, None) => {
            // No final selection: inspect the last archive file itself.
            let mut source_file = Source::open(&resolved.path)
                .map_err(|err| format!("cannot open the nested archive: {err}"))?;
            let len = source_file.len();
            let representation = representation(
                "file",
                true,
                "the bytes of the nested archive itself; its rows need --row",
                None,
            );
            let provenance = resolved.provenance_json(json!({ "kind": "none" }), representation);
            emit(
                &mut source_file,
                len,
                Context { source, provenance },
                options,
            )
        }
        (None, Some(row)) => {
            if resolved.format != Format::Rpf9 {
                return Err(format!(
                    "the last archive is {}; --row selects an RPF9 row, use --zip for a ZIP entry",
                    resolved.format
                ));
            }
            inspect_row(
                &resolved,
                row,
                executable,
                selection.raw,
                source,
                representation,
                options,
            )
        }
        (Some(index), None) => {
            if resolved.format != Format::Zip {
                return Err(format!(
                    "the last archive is {}; --zip selects a ZIP entry, use --row for an RPF9 row",
                    resolved.format
                ));
            }
            inspect_zip(
                &resolved,
                index,
                selection.raw,
                source,
                representation,
                options,
            )
        }
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
}

fn inspect_row(
    resolved: &nested::Resolved,
    row: u32,
    executable: Option<&Path>,
    raw: bool,
    source: Value,
    representation: impl Fn(&'static str, bool, &str, Option<String>) -> Value,
    options: &Options,
) -> Result<(), String> {
    let opened = native::open_metadata(&resolved.path, MAX_METADATA, executable)?;
    let rows = opened.metadata.rows();
    if row >= rows {
        return Err(match rows {
            0 => "the nested archive has no rows".to_string(),
            1 => format!("row {row} is out of range: the only row is 0"),
            _ => format!("row {row} is out of range: the rows are 0 to {}", rows - 1),
        });
    }
    let entry = opened.metadata.entry(row).map_err(|err| err.to_string())?;
    let alternates = Alternates::resolve(&resolved.path, &opened.metadata);
    let selection = json!({ "kind": "row", "index": row, "raw": raw });

    if raw {
        return match stored_bytes(&entry, &opened.source, &alternates) {
            Ok(mut stored) => {
                let len = stored.source.len();
                let provenance = resolved.provenance_json(
                    selection,
                    representation("stored", false, stored.note, None),
                );
                emit(
                    &mut stored.source,
                    len,
                    Context { source, provenance },
                    options,
                )
            }
            Err(err) => {
                let note = "the stored bytes of the row cannot be read";
                let provenance = resolved.provenance_json(
                    selection,
                    representation("stored", false, note, Some(err.clone())),
                );
                emit_failure(source, provenance, "decoding", err, options)
            }
        };
    }

    match entry.payload(&opened.source, alternates.sources()) {
        Ok(payload) => {
            let len = payload.len();
            let note = "decoded through the existing RPF9 row decoder";
            let provenance =
                resolved.provenance_json(selection, representation("logical", true, note, None));
            emit_payload(payload, len, Context { source, provenance }, options)
        }
        Err(err) => {
            let note = "the row cannot be decoded by this build";
            let provenance = resolved.provenance_json(
                selection,
                representation("logical", false, note, Some(err.to_string())),
            );
            emit_failure(source, provenance, "decoding", err.to_string(), options)
        }
    }
}

/// The bytes of a row as they are stored, including a compressed, chunked or
/// transformed representation. A row stored as it is gives its contents.
struct StoredSource {
    source: Source,
    /// How the bytes relate to the row's contents.
    note: &'static str,
}

fn stored_bytes(
    entry: &Entry,
    main: &Source,
    alternates: &Alternates,
) -> Result<StoredSource, String> {
    let location = match &entry.location {
        Ok(Some(location)) => *location,
        Ok(None) => return Err(format!("row {} has no location record", entry.row)),
        Err(reason) => {
            return Err(format!(
                "row {}: malformed location record: {reason}",
                entry.row
            ));
        }
    };
    let chunked = match &entry.chunks {
        Ok(chunks) => chunks.is_some(),
        Err(reason) => {
            return Err(format!(
                "row {}: malformed chunk table: {reason}",
                entry.row
            ));
        }
    };
    let transformed = match &entry.payload_transform {
        Ok(flag) => *flag,
        Err(reason) => {
            return Err(format!(
                "row {}: malformed payload transform flag: {reason}",
                entry.row
            ));
        }
    };
    let source = match &entry.read_source {
        Ok(None) => main,
        Ok(Some(index)) => usize::try_from(*index)
            .ok()
            .and_then(|index| alternates.sources().get(index)?.as_ref())
            .ok_or_else(|| {
                format!(
                    "row {} reads through alternate source {index}, which is not available",
                    entry.row
                )
            })?,
        Err(reason) => {
            return Err(format!(
                "row {}: malformed read source: {reason}",
                entry.row
            ));
        }
    };
    let plain = location.mode == 0 && !chunked && !transformed;
    let len = if plain {
        location.logical_len
    } else {
        location.stored_len
    };
    let end = location
        .payload_offset
        .checked_add(len)
        .ok_or_else(|| format!("the stored range of row {} overflows", entry.row))?;
    if end > source.len() {
        return Err(format!(
            "row {} ends at {end:#x}, after the end of the archive ({:#x})",
            entry.row,
            source.len()
        ));
    }
    let source = source.slice(location.payload_offset, len).map_err(|err| {
        format!(
            "the stored range of row {} cannot be read: {err}",
            entry.row
        )
    })?;
    let note = if plain {
        "the bytes as stored, which are the row's contents"
    } else if transformed {
        "the stored representation before the unsupported payload transform; it may include alignment padding"
    } else {
        "the stored representation before decoding; it may include alignment padding"
    };
    Ok(StoredSource { source, note })
}

fn inspect_zip(
    resolved: &nested::Resolved,
    index: usize,
    raw: bool,
    source: Value,
    representation: impl Fn(&'static str, bool, &str, Option<String>) -> Value,
    options: &Options,
) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    let mut archive = Source::open(&resolved.path)
        .map_err(|err| format!("cannot open the nested archive: {err}"))?;
    let len = archive.len();
    let zip = zip_archive::Archive::read(&mut archive, &zip_archive::Limits::default(), &cancel)
        .map_err(|err| format!("cannot read the ZIP archive: {err}"))?;
    let entry = zip.entry(index).map_err(|err| err.to_string())?;
    if entry.is_dir() {
        return Err(format!("ZIP entry {index} is a directory, not a file"));
    }
    let selection = json!({ "kind": "zip", "index": index, "raw": raw });

    if raw {
        if entry.is_encrypted() {
            return Err(format!(
                "ZIP entry {index} is encrypted; its stored bytes cannot be read"
            ));
        }
        let start = zip
            .data_start(&mut archive, len, entry)
            .map_err(|err| format!("ZIP entry {index} cannot be read: {err}"))?;
        let compressed = entry.compressed_size;
        let mut stored = archive
            .slice(start, compressed)
            .map_err(|err| format!("ZIP entry {index} is out of range: {err}"))?;
        let len = stored.len();
        let note = "the bytes as stored in the ZIP entry, before decompression";
        let provenance =
            resolved.provenance_json(selection, representation("stored", false, note, None));
        emit(&mut stored, len, Context { source, provenance }, options)
    } else {
        let len = entry.uncompressed_size;
        if len > nested::MAX_ARCHIVE_BYTES {
            return Err(format!(
                "ZIP entry {index} decodes to {len} bytes, more than the {} byte limit",
                nested::MAX_ARCHIVE_BYTES
            ));
        }
        let mut temp = tempfile::NamedTempFile::new()
            .map_err(|err| format!("cannot create a temporary file: {err}"))?;
        let archive_len = archive.len();
        zip.decode_entry(
            &mut archive,
            archive_len,
            entry,
            &cancel,
            nested::MAX_ARCHIVE_BYTES,
            &mut temp,
        )
        .map_err(|err| format!("ZIP entry {index} cannot be decoded: {err}"))?;
        temp.as_file_mut()
            .flush()
            .map_err(|err| format!("cannot write the temporary file: {err}"))?;
        let (file, temp_path) = temp.into_parts();
        let mut stored = Source::from_file(file)
            .map_err(|err| format!("cannot reopen the temporary file: {err}"))?;
        let note = "decompressed through the ZIP reader; its CRC-32 was checked";
        let provenance =
            resolved.provenance_json(selection, representation("logical", true, note, None));
        let result = emit(&mut stored, len, Context { source, provenance }, options);
        // The temporary file is removed once the report is written.
        drop(temp_path);
        result
    }
}

fn emit_payload(
    mut payload: Payload,
    len: u64,
    context: Context,
    options: &Options,
) -> Result<(), String> {
    emit(&mut payload, len, context, options)
}

fn emit_failure(
    source: Value,
    provenance: Value,
    stage: &'static str,
    message: String,
    options: &Options,
) -> Result<(), String> {
    let document = json!({
        "schema": SCHEMA,
        "tool": tool_json(),
        "source": source,
        "provenance": provenance,
        "size": Value::Null,
        "signature": Value::Null,
        "format": Value::Null,
        "structure": Value::Null,
        "raw": raw_json(),
        "failure_stage": stage,
        "failure": message,
    });
    print_document(&document, options);
    Err(message)
}

fn raw_json() -> Value {
    json!({
        "available": true,
        "note": "the bytes are read-only; `binary dump` shows any range of a file",
    })
}

fn tool_json() -> Value {
    json!({
        "name": "lforge",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn emit<R: Read + Seek>(
    source: &mut R,
    len: u64,
    context: Context,
    options: &Options,
) -> Result<(), String> {
    let cancellation = AtomicBool::new(false);
    let report = recognition::inspect(source, len, &options.recognition(), &cancellation)
        .map_err(|err| format!("cannot read the signature: {err}"))?;
    let failure_stage = report.failure.as_ref().map(|failure| failure.stage);
    let mut document = Map::new();
    document.insert("schema".into(), json!(SCHEMA));
    document.insert("tool".into(), tool_json());
    document.insert("source".into(), context.source);
    document.insert("provenance".into(), context.provenance);
    document.insert("size".into(), json!(len));
    document.insert(
        "signature".into(),
        json!(lforge_binary::hex_bytes(&report.signature)),
    );
    document.insert(
        "format".into(),
        report
            .format
            .map(|format| format.json())
            .unwrap_or(Value::Null),
    );
    document.insert("structure".into(), report.structure);
    document.insert("raw".into(), raw_json());
    document.insert(
        "failure_stage".into(),
        failure_stage.map_or(Value::Null, |stage| json!(stage)),
    );
    let document = Value::Object(document);
    print_document(&document, options);
    match report.failure {
        Some(failure) => Err(failure.message),
        None => Ok(()),
    }
}

fn print_document(document: &Value, options: &Options) {
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(document).expect("JSON value")
        );
    } else {
        print_text(document);
    }
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
            match (
                source.get("row").and_then(Value::as_u64),
                source.get("zip").and_then(Value::as_u64),
            ) {
                (Some(row), _) => println!("archive:     {archive} row {row}"),
                (None, Some(zip)) => println!("archive:     {archive} ZIP entry {zip}"),
                (None, None) => println!("archive:     {archive}"),
            }
        }
    }
    if let Some(provenance) = map.get("provenance").and_then(Value::as_object) {
        if let Some(chain) = provenance.get("chain").and_then(Value::as_array)
            && !chain.is_empty()
        {
            let path = chain
                .iter()
                .map(|step| {
                    let selector = step.get("selector").and_then(Value::as_str).unwrap_or("-");
                    let format = step.get("format").and_then(Value::as_str).unwrap_or("-");
                    format!("{selector} -> {format}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("entered:     {path}");
        }
        if let Some(representation) = provenance.get("representation").and_then(Value::as_object) {
            let kind = representation
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("-");
            let decoded = representation
                .get("decoded")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            println!("bytes:       {kind} (decoded: {decoded})");
            if let Some(error) = representation.get("error").and_then(Value::as_str) {
                println!("decode:      {error}");
            }
        }
    }
    if let Some(stage) = map.get("failure_stage").and_then(Value::as_str) {
        println!("failure:     {stage}");
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
