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
use lforge_rage9::rpf::metadata::{Entry, Field, Payload};
use serde_json::{Value, json};

use crate::catalog::CategoryFilter;
use crate::catalog::json::sha256_hex;
use crate::native::{self, Alternates};

const MAX_METADATA: u64 = 256 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;

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
    too_large: u64,
    parse_failed: u64,
    recognized_documents: u64,
    unrecognized_documents: u64,
    observations: BTreeMap<&'static str, u64>,
    entity_types: BTreeMap<String, u64>,
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
        let mut payload = match entry.payload(&source, alternates.sources()) {
            Ok(payload) => payload,
            Err(err) => {
                counts.unsupported += 1;
                if issues.len() < 100 {
                    issues.push(
                        json!({ "row": row, "stage": "payload", "message": err.to_string() }),
                    );
                }
                continue;
            }
        };
        let declared = payload.len();
        if declared > options.max_row_bytes {
            counts.too_large += 1;
            if issues.len() < 100 {
                issues.push(json!({
                    "row": row,
                    "stage": "limit",
                    "message": format!("the decoded row is {declared} bytes, above the {0} byte limit", options.max_row_bytes)
                }));
            }
            continue;
        }
        let mut bytes = Vec::with_capacity(declared.min(16 * 1024 * 1024) as usize);
        if let Err(err) = read_payload(&mut payload, &mut bytes, options.max_row_bytes) {
            counts.too_large += 1;
            if issues.len() < 100 {
                issues.push(json!({ "row": row, "stage": "limit", "message": err }));
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
    if counts.unsupported > 0 {
        limitations.push(format!(
            "{} row(s) are stored behind an unsupported payload transform or compression and were not decoded",
            counts.unsupported
        ));
    }
    if counts.too_large > 0 {
        limitations.push(format!(
            "{} row(s) exceeded the {} byte decoded-row limit",
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

fn read_payload(payload: &mut Payload, out: &mut Vec<u8>, limit: u64) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    let mut buffer = vec![0u8; READ_CHUNK];
    loop {
        match payload.read_cancellable(&mut buffer, &cancel) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                if out.len() as u64 + count as u64 > limit {
                    return Err(format!("the decoded row exceeds the {limit} byte limit"));
                }
                out.extend_from_slice(&buffer[..count]);
            }
            Err(err) => return Err(format!("row could not be decoded: {err}")),
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
