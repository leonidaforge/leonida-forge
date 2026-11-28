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
use lforge_core::resource::{EntryId, Locator, ResourcePath};
use lforge_core::zip as zip_archive;
use lforge_rage9::psin::pso::names::Names;
use lforge_rage9::rpf::metadata::transform::Algorithm;
use lforge_rage9::rpf::metadata::{Entry, Payload};
use lforge_rage9::rpf::names::Types;
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
    /// Name tables for metadata structure and field hashes. Empty means the
    /// archive's own `<archive>.names.txt` when it exists.
    pub names: Vec<PathBuf>,
    /// The index built from `names`, and from the built-in tables.
    pub metadata_names: Option<Names>,
    /// Where the decoded metadata document is written.
    pub metadata_output: Option<PathBuf>,
    /// Write the metadata document as XML instead of JSON.
    pub metadata_xml: bool,
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
/// `enters`, and writes the decoded metadata document when asked for.
pub fn archive(
    file: &Path,
    executable: Option<&Path>,
    enters: &[Selector],
    selection: &Selection,
    options: &Options,
) -> Result<(), String> {
    let mut options = options.clone();
    // Metadata names come from the archive's table or the ones given.
    if let Ok(tables) = crate::native::load_name_tables(file, &options.names)
        && !tables.table.entries().is_empty()
    {
        options.metadata_names = Some(Names::from_table(&tables.table));
    }
    let row = selection.row.or_else(|| {
        (enters.is_empty() && selection.row.is_none() && selection.zip.is_none()).then_some(0)
    });
    let cancel = AtomicBool::new(false);
    let resolved = nested::resolve(file, executable, enters, &cancel)?;
    let report = archive_report(file, executable, enters, &resolved, selection, &options);
    let Some(output) = options.metadata_output.clone() else {
        return report;
    };
    report?;
    let Some(row) = row else {
        return Err("a metadata document comes from one native row; give --row".to_string());
    };
    write_metadata(file, &resolved, executable, row, &options, &output)
}

fn archive_report(
    file: &Path,
    executable: Option<&Path>,
    enters: &[Selector],
    resolved: &nested::Resolved,
    selection: &Selection,
    options: &Options,
) -> Result<(), String> {
    if selection.row.is_some() && selection.zip.is_some() {
        return Err("--row and --zip select different entries; give one".to_string());
    }
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
                resolved,
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
                resolved,
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

/// The resource block of a document: the canonical path, never the row index.
fn resource_json(path: &ResourcePath) -> Value {
    json!({
        "display": path.display(),
        "identity": path.identity(),
        "limitations": path.limitations(),
    })
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
    // Every document names the entry by its canonical path, so a failure
    // report does too. The row index stays a diagnostic selection.
    let mut source = source;
    source["resource"] = resource_json(&resolved.resource().with_entry(EntryId::from_row(
        &entry,
        None,
        &Types::default(),
    )));
    let alternates = Alternates::resolve(&resolved.path, &opened.metadata);
    let selection = json!({ "kind": "row", "index": row, "raw": raw });

    if raw {
        return match stored_bytes(&entry, &opened.source, &alternates) {
            Ok(mut stored) => {
                let len = stored.source.len();
                let provenance = resolved.provenance_json(
                    selection,
                    representation("stored", false, &stored.note, None),
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
        Err(err) if matches!(entry.payload_transform, Ok(true)) && opened.stream.is_some() => {
            let stream = opened.stream.as_ref().expect("checked");
            match native::transformed_payload(&entry, &opened.source, &alternates, stream) {
                Ok(payload) => {
                    let len = payload.len();
                    let note = "decoded through the verified payload transform";
                    let provenance = resolved
                        .provenance_json(selection, representation("logical", true, note, None));
                    emit_payload(payload, len, Context { source, provenance }, options)
                }
                Err(reason) => {
                    let message = format!("{err} ({reason})");
                    let provenance = resolved.provenance_json(
                        selection,
                        representation(
                            "logical",
                            false,
                            "the payload transform could not be verified",
                            Some(message.clone()),
                        ),
                    );
                    emit_failure(source, provenance, "decoding", message, options)
                }
            }
        }
        Err(err) => {
            let note = if transform_descriptor(&entry).is_some() {
                "the row is stored behind a payload transform, which this build does not decode"
            } else {
                "the row cannot be decoded by this build"
            };
            let message = match transform_descriptor(&entry) {
                Some(descriptor) => format!("{err} ({descriptor})"),
                None => err.to_string(),
            };
            let provenance = resolved.provenance_json(
                selection,
                representation("logical", false, note, Some(message.clone())),
            );
            emit_failure(source, provenance, "decoding", message, options)
        }
    }
}

/// The bytes of a row as they are stored, including a compressed, chunked or
/// transformed representation. A row stored as it is gives its contents.
struct StoredSource {
    source: Source,
    /// How the bytes relate to the row's contents.
    note: String,
}

/// The cipher descriptor of a row's payload transform, when the row has the
/// transform flag. The engine selects the key state and algorithm from it; this
/// build does not implement that algorithm.
fn transform_descriptor(entry: &Entry) -> Option<String> {
    if !matches!(entry.payload_transform, Ok(true)) {
        return None;
    }
    Some(match &entry.payload_cipher {
        Ok(Some(cipher)) => {
            let algorithm = Algorithm::of(cipher.kind)
                .map(|algorithm| format!("{:#x}", algorithm.id()))
                .unwrap_or_else(|err| err.to_string());
            format!(
                "cipher type {:#x}, algorithm {algorithm}, key id 0x{:08X}",
                cipher.kind, cipher.key_id
            )
        }
        Ok(None) => "no cipher descriptor".to_string(),
        Err(reason) => format!("cipher descriptor malformed: {reason}"),
    })
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
        "the bytes as stored, which are the row's contents".to_string()
    } else if transformed {
        format!(
            "the stored representation before the payload transform ({}); it may include alignment padding",
            transform_descriptor(entry).unwrap_or_else(|| "descriptor unknown".to_string())
        )
    } else {
        "the stored representation before decoding; it may include alignment padding".to_string()
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
    let mut source = source;
    source["resource"] = resource_json(&resolved.resource().with_entry(EntryId::named(
        entry.name.clone(),
        None,
        Locator::Zip(index),
    )));
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

/// Writes the decoded metadata document of one native row.
///
/// The document keeps every stored hash, so a name the table resolves is an
/// addition, never a replacement. The provenance names the archive, the row
/// and the row's stored keys, so a decoded document can be traced back to the
/// bytes it came from.
fn write_metadata(
    origin: &Path,
    resolved: &nested::Resolved,
    executable: Option<&Path>,
    row: u32,
    options: &Options,
    output: &Path,
) -> Result<(), String> {
    let read = resolved.path.as_path();
    let opened = native::open_metadata(read, MAX_METADATA, executable)?;
    let entry = opened.metadata.entry(row).map_err(|err| err.to_string())?;
    // The document names the row by its canonical path, exactly as an
    // inspection document does; the row index stays a diagnostic selection.
    let resource = resource_json(&resolved.resource().with_entry(EntryId::from_row(
        &entry,
        None,
        &Types::default(),
    )));
    // Companions sit beside the file the chain starts at, not beside the
    // temporary file an entered archive was decompressed into.
    let alternates = Alternates::resolve(origin, &opened.metadata);
    let mut payload = match entry.payload(&opened.source, alternates.sources()) {
        Ok(payload) => payload,
        Err(err) => {
            let Some(stream) = opened.stream.as_ref() else {
                return Err(format!("row {row} cannot be read: {err}"));
            };
            native::transformed_payload(&entry, &opened.source, &alternates, stream)?
        }
    };
    let cancel = AtomicBool::new(false);
    let mut bytes = Vec::new();
    let mut buffer = vec![0u8; crate::output::BUFFER];
    loop {
        match payload.read_cancellable(&mut buffer, &cancel) {
            Ok(0) => break,
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.len() as u64 > crate::output::MAX_OUTPUT {
                    return Err(format!(
                        "row {row} decodes to more than the {} byte limit",
                        crate::output::MAX_OUTPUT
                    ));
                }
            }
            Err(err) => return Err(format!("row {row} cannot be decoded: {err}")),
        }
    }
    // A `0DRP` resource stores a graphics segment after its system pages. The
    // row's page table says where the second segment starts; the page map then
    // says how many pages belong to each.
    let split = if lforge_rage9::odrp::is_odrp(&bytes) {
        opened
            .metadata
            .chunk_table(row)
            .ok()
            .flatten()
            .and_then(|table| {
                lforge_rage9::rpf::resource::page_split(
                    &mut std::io::Cursor::new(bytes.as_slice()),
                    bytes.len() as u64,
                    &table,
                    lforge_rage9::rpf::RESOURCE_SYSTEM_LIMIT,
                )
                .ok()
            })
    } else {
        None
    };
    let document = lforge_core::metadata::decode_with_split(&bytes, split)
        .map_err(|err| format!("row {row} holds no metadata document this build decodes: {err}"))?;
    let empty = Names::empty();
    let names = options.metadata_names.as_ref().unwrap_or(&empty);
    let sample = if options.blocks {
        usize::MAX
    } else {
        options.sample
    };
    let source = [
        ("archive", path_string(origin)),
        ("row", row.to_string()),
        (
            "nameHash64",
            entry
                .name_hash
                .clone()
                .ok()
                .flatten()
                .map_or_else(String::new, |hash| format!("0x{hash:016X}")),
        ),
        (
            "nameKey32",
            entry
                .name_key
                .clone()
                .ok()
                .flatten()
                .map_or_else(String::new, |key| format!("0x{key:08X}")),
        ),
        ("namesIndexed", names.len().to_string()),
    ];
    let provenance = json!({
        "archive": path_string(origin),
        // An entered archive is decompressed into temporary storage, and that
        // path names nothing a reader could open, so it is never recorded. The
        // canonical resource path already names the chain.
        "read_from": resolved.chain.is_empty().then(|| path_string(read)),
        "resource": resource,
        "row": row,
        "name_hash": entry.name_hash.clone().ok().flatten().map(|hash| format!("0x{hash:016X}")),
        "name_key": entry.name_key.clone().ok().flatten().map(|key| format!("0x{key:08X}")),
        "names_indexed": names.len(),
        "names": options.names.iter().map(|path| path_string(path)).collect::<Vec<String>>(),
        "format": document.format(),
        "status": document.status(),
        // An RBF0 document is a tree and is always written whole, so there is
        // no block sample to report.
        "blocks_written": if options.blocks || document.format() == "rbf0" {
            Value::Null
        } else {
            json!(sample)
        },
    });
    crate::output::ensure_not_input(output, &[origin, read])?;
    let written = crate::output::write_file(output, options.overwrite, |writer| {
        if options.metadata_xml {
            let text = document.document_xml(sample, &source);
            writer
                .write_all(text.as_bytes())
                .map_err(|err| crate::output::write_error(output, err))?;
            return Ok(text.len() as u64);
        }
        let export = json!({
            "schema": document.schema(),
            "source": provenance,
            "document": document.document_json(names, sample),
        });
        let text = serde_json::to_vec_pretty(&export)
            .map_err(|err| format!("cannot serialise the document: {err}"))?;
        writer
            .write_all(&text)
            .map_err(|err| crate::output::write_error(output, err))?;
        Ok(text.len() as u64)
    })?;
    let identity = entry
        .name_hash
        .clone()
        .ok()
        .flatten()
        .map_or_else(|| format!("row {row}"), |hash| format!("{hash:#018X}"));
    println!(
        "decoded {identity} as {}: {}; {written} bytes to {}",
        document.format(),
        document.summary(),
        output.display()
    );
    Ok(())
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
    let recognition_options = options.recognition();
    let report = recognition::inspect_with_names(
        source,
        len,
        &recognition_options,
        options.metadata_names.as_ref(),
        &cancellation,
    )
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
            println!("archive:     {archive}");
        }
        if let Some(display) = source
            .get("resource")
            .and_then(|resource| resource.get("display"))
            .and_then(Value::as_str)
        {
            println!("resource:    {display}");
        }
        match (
            source.get("row").and_then(Value::as_u64),
            source.get("zip").and_then(Value::as_u64),
        ) {
            (Some(row), _) => println!(
                "selected:    row {row} of the archive above (diagnostic, not a resource \
                 identifier)"
            ),
            (None, Some(zip)) => println!(
                "selected:    ZIP entry {zip} of the archive above (diagnostic, not a resource \
                 identifier)"
            ),
            (None, None) => {}
        }
    }
    if let Some(provenance) = map.get("provenance").and_then(Value::as_object) {
        if let Some(chain) = provenance.get("chain").and_then(Value::as_array)
            && !chain.is_empty()
        {
            let path = chain
                .iter()
                .map(|step| {
                    let selector = step
                        .get("resource")
                        .and_then(|resource| resource.get("display"))
                        .and_then(Value::as_str)
                        .or_else(|| step.get("selector").and_then(Value::as_str))
                        .unwrap_or("-");
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
