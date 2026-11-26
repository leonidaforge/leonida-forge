//! `lforge catalog extract`.
//!
//! Every readable native row is decoded into memory, bounded by
//! `--max-row-bytes`, and offered to the XML catalog reader. A row that is
//! stored behind the payload transform, exceeds the limit, is not XML or fails
//! to parse is counted in the report and does not block the other rows. The
//! command never writes to the archive.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use lforge_rage9::catalog::{DocumentExtraction, Observation};
use lforge_rage9::rpf::metadata::{Entry, Error, Field, Payload};
use serde_json::{Value, json};

use crate::catalog::CategoryFilter;
use crate::catalog::json::sha256_hex;
use crate::native::{self, Alternates};

const MAX_METADATA: u64 = 256 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const PREFIX_LEN: u64 = 64 * 1024;

pub struct Options {
    pub archive: PathBuf,
    pub executable: Option<PathBuf>,
    pub source_id: Option<String>,
    pub output: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub category: CategoryFilter,
    pub max_row_bytes: u64,
    pub max_rows: Option<u32>,
}

#[derive(Default)]
struct Counts {
    rows: u64,
    decoded: u64,
    not_xml: u64,
    unsupported: u64,
    unsupported_transform: u64,
    unsupported_compression: u64,
    missing_source: u64,
    malformed_metadata: u64,
    decode_failed: u64,
    excluded: u64,
    prefix_only: u64,
    too_large: u64,
    parse_failed: u64,
    recognized_documents: u64,
    unrecognized_documents: u64,
    observations: BTreeMap<&'static str, u64>,
    entity_types: BTreeMap<String, u64>,
}

/// A payload failure's cause, as the report names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cause {
    Transform,
    Compression,
    Source,
    Malformed,
}

impl Cause {
    fn of(err: &Error) -> Self {
        match err {
            Error::Encoded { encoding, .. } if *encoding == "behind the payload transform" => {
                Cause::Transform
            }
            Error::Encoded { .. } | Error::Undecodable { .. } => Cause::Compression,
            Error::ReadSource { .. } => Cause::Source,
            _ => Cause::Malformed,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Cause::Transform => "unsupported_transform",
            Cause::Compression => "unsupported_compression",
            Cause::Source => "missing_source",
            Cause::Malformed => "malformed_metadata",
        }
    }
}

impl Counts {
    fn add_unsupported(&mut self, cause: Cause) {
        self.unsupported += 1;
        match cause {
            Cause::Transform => self.unsupported_transform += 1,
            Cause::Compression => self.unsupported_compression += 1,
            Cause::Source => self.missing_source += 1,
            Cause::Malformed => self.malformed_metadata += 1,
        }
    }
}

pub fn run(options: Options) -> Result<(), String> {
    let source_id = options
        .source_id
        .clone()
        .or_else(|| {
            options
                .archive
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .ok_or_else(|| "the archive has no file name; pass --source-id".to_string())?;
    if source_id.is_empty() || source_id.contains(['/', '\\']) || source_id.len() > 128 {
        return Err("--source-id must be a short name without path separators".to_string());
    }

    let opened = native::open_metadata(
        &options.archive,
        MAX_METADATA,
        options.executable.as_deref(),
    )?;
    let stream = opened.stream;
    let source = opened.source;
    let metadata = opened.metadata;
    let alternates = Alternates::resolve(&options.archive, &metadata);
    let total_rows = metadata.rows();
    let stop = options.max_rows.unwrap_or(total_rows).min(total_rows);
    let mut counts = Counts::default();
    let mut issues: Vec<Value> = Vec::new();

    let mut writer: Box<dyn Write> = match &options.output {
        Some(path) => {
            Box::new(BufWriter::new(File::create(path).map_err(|err| {
                format!("cannot create {}: {err}", path.display())
            })?))
        }
        None => Box::new(BufWriter::new(std::io::stdout().lock())),
    };

    for row in 0..stop {
        counts.rows += 1;
        let entry = match metadata.entry(row) {
            Ok(entry) => entry,
            Err(err) => {
                issues.push(json!({ "row": row, "stage": "metadata", "message": err.to_string() }));
                continue;
            }
        };
        if entry.type_id() == Some(0) {
            // Type 0 is a nested RPF archive, never a catalog XML document.
            counts.excluded += 1;
            if issues.len() < 100 {
                issues.push(json!({
                    "row": row,
                    "stage": "catalog",
                    "cause": "nested_archive",
                    "message": "nested RPF archive excluded from catalog extraction"
                }));
            }
            continue;
        }
        let mut payload = match entry.payload(&source, alternates.sources()) {
            Ok(payload) => payload,
            Err(_err) if matches!(entry.payload_transform, Ok(true)) => {
                let Some(stream) = stream.as_ref() else {
                    counts.add_unsupported(Cause::Transform);
                    if issues.len() < 100 {
                        issues.push(json!({
                            "row": row,
                            "stage": "payload",
                            "cause": "unsupported_transform",
                            "message": "the payload transform requires the executable that provided the key state"
                        }));
                    }
                    continue;
                };
                match native::transformed_payload(&entry, &source, &alternates, stream) {
                    Ok(payload) => payload,
                    Err(reason) => {
                        counts.add_unsupported(Cause::Transform);
                        if issues.len() < 100 {
                            issues.push(json!({
                                "row": row,
                                "stage": "decoding",
                                "cause": "unsupported_transform",
                                "message": reason
                            }));
                        }
                        continue;
                    }
                }
            }
            Err(err) => {
                let cause = Cause::of(&err);
                counts.add_unsupported(cause);
                if issues.len() < 100 {
                    issues.push(json!({
                        "row": row,
                        "stage": "payload",
                        "cause": cause.code(),
                        "message": err.to_string()
                    }));
                }
                continue;
            }
        };
        let declared = payload.len();
        if declared > options.max_row_bytes {
            // A large non-XML resource is classified from a bounded prefix
            // instead of being decoded in full or counted as a document limit.
            let mut prefix = Vec::new();
            if let Err(err) = read_prefix(&mut payload, &mut prefix, PREFIX_LEN) {
                counts.decode_failed += 1;
                if issues.len() < 100 {
                    issues.push(json!({
                        "row": row,
                        "stage": "decoding",
                        "cause": "decode_failed",
                        "message": err
                    }));
                }
                continue;
            }
            let body = prefix.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&prefix);
            if !body.starts_with(b"<") {
                counts.not_xml += 1;
                counts.prefix_only += 1;
                continue;
            }
            counts.too_large += 1;
            if issues.len() < 100 {
                issues.push(json!({
                    "row": row,
                    "stage": "limit",
                    "message": format!("the decoded XML document is {declared} bytes, above the {} byte materialization limit", options.max_row_bytes)
                }));
            }
            continue;
        }
        let mut bytes = Vec::with_capacity(declared.min(16 * 1024 * 1024) as usize);
        if let Err(err) = read_payload(&mut payload, &mut bytes, options.max_row_bytes) {
            match err {
                ReadError::Limit(message) => {
                    counts.too_large += 1;
                    if issues.len() < 100 {
                        issues.push(json!({ "row": row, "stage": "limit", "message": message }));
                    }
                }
                ReadError::Decode(message) => {
                    counts.decode_failed += 1;
                    if issues.len() < 100 {
                        issues.push(json!({
                            "row": row,
                            "stage": "decoding",
                            "cause": "decode_failed",
                            "message": message
                        }));
                    }
                }
            }
            continue;
        }
        counts.decoded += 1;

        let body = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
        if !body.starts_with(b"<") {
            counts.not_xml += 1;
            continue;
        }
        let extraction = match lforge_rage9::catalog::extract_document(&bytes) {
            Ok(extraction) => extraction,
            Err(err) => {
                counts.parse_failed += 1;
                if issues.len() < 100 {
                    issues.push(json!({ "row": row, "stage": "xml", "message": err }));
                }
                continue;
            }
        };
        if extraction.recognized {
            counts.recognized_documents += 1;
        } else {
            counts.unrecognized_documents += 1;
            continue;
        }
        emit(
            &mut writer,
            &extraction,
            &entry,
            &bytes,
            &source_id,
            options
                .archive
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
            &options.category,
            &mut counts,
        )?;
    }
    writer
        .flush()
        .map_err(|err| format!("cannot write observations: {err}"))?;

    let status = if counts.unsupported > 0 || counts.too_large > 0 || counts.parse_failed > 0 {
        "partial"
    } else {
        "complete"
    };
    let mut limitations = Vec::new();
    if counts.unsupported_transform > 0 {
        limitations.push(format!(
            "{} row(s) are stored behind the payload transform and were not decoded",
            counts.unsupported_transform
        ));
    }
    if counts.unsupported_compression > 0 {
        limitations.push(format!(
            "{} row(s) use an unsupported compression mode and were not decoded",
            counts.unsupported_compression
        ));
    }
    if counts.missing_source > 0 {
        limitations.push(format!(
            "{} row(s) read through an alternate source that is not available and were not decoded",
            counts.missing_source
        ));
    }
    if counts.malformed_metadata > 0 {
        limitations.push(format!(
            "{} row(s) have malformed metadata and could not be read",
            counts.malformed_metadata
        ));
    }
    if counts.decode_failed > 0 {
        limitations.push(format!(
            "{} row(s) failed while reading the decoded payload",
            counts.decode_failed
        ));
    }
    if counts.excluded > 0 {
        limitations.push(format!(
            "{} nested archive row(s) were excluded from catalog extraction",
            counts.excluded
        ));
    }
    if counts.prefix_only > 0 {
        limitations.push(format!(
            "{} large non-XML row(s) were classified from a bounded prefix",
            counts.prefix_only
        ));
    }
    if counts.too_large > 0 {
        limitations.push(format!(
            "{} row(s) exceeded the {} byte XML materialization limit",
            counts.too_large, options.max_row_bytes
        ));
    }
    if counts.parse_failed > 0 {
        limitations.push(format!(
            "{} XML document(s) could not be parsed",
            counts.parse_failed
        ));
    }
    let report = json!({
        "schema": "leonida-forge.catalog-extraction-report/1",
        "tool": { "name": "lforge", "version": env!("CARGO_PKG_VERSION") },
        "source": {
            "id": source_id,
            "file": options.archive.file_name().map(|name| name.to_string_lossy().into_owned()),
            "metadataRead": true,
            "rows": total_rows,
            "scannedRows": counts.rows
        },
        "status": status,
        "counts": {
            "rows": counts.rows,
            "decoded": counts.decoded,
            "notXml": counts.not_xml,
            "unsupported": counts.unsupported,
            "unsupportedTransform": counts.unsupported_transform,
            "unsupportedCompression": counts.unsupported_compression,
            "missingSource": counts.missing_source,
            "malformedMetadata": counts.malformed_metadata,
            "decodeFailed": counts.decode_failed,
            "excluded": counts.excluded,
            "prefixOnly": counts.prefix_only,
            "tooLarge": counts.too_large,
            "parseFailed": counts.parse_failed,
            "recognizedDocuments": counts.recognized_documents,
            "unrecognizedDocuments": counts.unrecognized_documents,
            "observations": counts.observations,
            "entityTypes": counts.entity_types
        },
        "limitations": limitations,
        "issues": issues
    });
    match &options.report {
        Some(path) => {
            let text = serde_json::to_string_pretty(&report)
                .map_err(|err| format!("cannot serialize the report: {err}"))?;
            std::fs::write(path, text)
                .map_err(|err| format!("cannot write {}: {err}", path.display()))?;
        }
        None => {
            eprintln!(
                "catalog extract: {} rows, {} decoded, {} observations ({status})",
                counts.rows,
                counts.decoded,
                counts.observations.values().sum::<u64>()
            );
        }
    }
    if status == "partial" {
        eprintln!("catalog extract: the extraction is partial; see the report for the limitations");
    }
    Ok(())
}

enum ReadError {
    Limit(String),
    Decode(String),
}

fn read_prefix(payload: &mut Payload, out: &mut Vec<u8>, limit: u64) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    let mut buffer = vec![0u8; READ_CHUNK];
    while (out.len() as u64) < limit {
        let want = (limit - out.len() as u64).min(READ_CHUNK as u64) as usize;
        match payload.read_cancellable(&mut buffer[..want], &cancel) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buffer[..n]),
            Err(err) => return Err(format!("the payload prefix cannot be read: {err}")),
        }
    }
    Ok(())
}

fn read_payload(payload: &mut Payload, out: &mut Vec<u8>, limit: u64) -> Result<(), ReadError> {
    let cancel = AtomicBool::new(false);
    let mut buffer = vec![0u8; READ_CHUNK];
    loop {
        match payload.read_cancellable(&mut buffer, &cancel) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                if out.len() as u64 + count as u64 > limit {
                    return Err(ReadError::Limit(format!(
                        "the decoded XML document exceeds the {limit} byte limit"
                    )));
                }
                out.extend_from_slice(&buffer[..count]);
            }
            Err(err) => {
                return Err(ReadError::Decode(format!(
                    "row could not be decoded: {err}"
                )));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    writer: &mut dyn Write,
    extraction: &DocumentExtraction,
    entry: &Entry,
    payload: &[u8],
    source_id: &str,
    archive_file: Option<String>,
    filter: &CategoryFilter,
    counts: &mut Counts,
) -> Result<(), String> {
    let payload_sha256 = sha256_hex(payload);
    for observation in &extraction.observations {
        if !filter.includes(observation.category) {
            continue;
        }
        let value = observation_json(
            observation,
            entry,
            source_id,
            archive_file.as_deref(),
            &payload_sha256,
            &extraction.root,
        );
        let line = serde_json::to_string(&value)
            .map_err(|err| format!("cannot serialize an observation: {err}"))?;
        writeln!(writer, "{line}").map_err(|err| format!("cannot write an observation: {err}"))?;
        *counts
            .observations
            .entry(observation.category.name())
            .or_insert(0) += 1;
        *counts
            .entity_types
            .entry(observation.entity_type.clone())
            .or_insert(0) += 1;
    }
    Ok(())
}

fn observation_json(
    observation: &Observation,
    entry: &Entry,
    source_id: &str,
    archive_file: Option<&str>,
    payload_sha256: &str,
    root: &str,
) -> Value {
    json!({
        "schema": "leonida-forge.catalog-extraction/1",
        "category": observation.category.name(),
        "entityType": observation.entity_type,
        "internalName": observation.internal_name,
        "displayName": observation.display_name,
        "fields": observation.fields,
        "metadata": observation.metadata,
        "source": {
            "id": source_id,
            "file": archive_file,
            "row": entry.row,
            "rowHash64": field(&entry.name_hash, |value| format!("0x{value:016X}")),
            "rowKey32": field(&entry.name_key, |value| format!("0x{value:08X}")),
            "payloadSha256": payload_sha256,
            "root": root,
            "path": observation.source_path,
            "verification": "verified_structure"
        }
    })
}

fn field<T>(value: &Field<T>, show: impl Fn(&T) -> String) -> Value {
    match value {
        Ok(Some(value)) => json!(show(value)),
        Ok(None) => Value::Null,
        Err(reason) => json!({ "malformed": reason }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_failures_are_classified_by_cause() {
        assert_eq!(
            Cause::of(&Error::Encoded {
                row: 0,
                encoding: "behind the payload transform"
            }),
            Cause::Transform
        );
        assert_eq!(
            Cause::of(&Error::Encoded {
                row: 1,
                encoding: "compressed"
            }),
            Cause::Compression
        );
        assert_eq!(
            Cause::of(&Error::Undecodable {
                row: 2,
                reason: "mode 2".to_string()
            }),
            Cause::Compression
        );
        assert_eq!(
            Cause::of(&Error::ReadSource { row: 3, index: 1 }),
            Cause::Source
        );
        assert_eq!(
            Cause::of(&Error::Invalid("bad metadata".to_string())),
            Cause::Malformed
        );
    }

    #[test]
    fn unsupported_counts_keep_the_total_and_each_cause() {
        let mut counts = Counts::default();
        for cause in [
            Cause::Transform,
            Cause::Transform,
            Cause::Compression,
            Cause::Source,
            Cause::Malformed,
        ] {
            counts.add_unsupported(cause);
        }
        assert_eq!(counts.unsupported, 5);
        assert_eq!(counts.unsupported_transform, 2);
        assert_eq!(counts.unsupported_compression, 1);
        assert_eq!(counts.missing_source, 1);
        assert_eq!(counts.malformed_metadata, 1);
    }
}
