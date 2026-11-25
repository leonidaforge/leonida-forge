//! Content-based recognition and structural inspection of the formats this
//! build decodes.
//!
//! Shared by `lforge binary inspect`, `lforge archive inspect` and the
//! desktop binary inspector, so a recognised format means the same thing in
//! every front end. Nothing here prints or returns payload bytes: a field
//! whose meaning the research does not establish is reported as the number it
//! stores, and an unknown region as a range.
//!
//! `PSIN` is reported as a recognised magic only. Nothing relates it to a
//! confirmed PSO format, and this module does not claim otherwise.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_rage9::rbf0;
use lforge_rage9::rds5::{self, Container, Storage};
use serde_json::{Map, Value, json};

/// The schema of an inspection document. Version 2 adds `provenance`,
/// `representation` and `failure_stage`; every version 1 field keeps its
/// meaning.
pub const SCHEMA: &str = "leonida-forge.format-inspection/2";

/// Bytes read to recognise a format.
pub const SIGNATURE_LEN: usize = 16;
/// Blocks and entries shown by default.
pub const DEFAULT_SAMPLE: usize = 8;
/// The largest sample a caller may request.
pub const MAX_SAMPLE: usize = 256;
/// Block failures listed by `--verify`; the count is always complete.
const MAX_FAILURES: usize = 20;
/// Bytes of an RBF0 payload read for structural parsing.
const MAX_RBF0_BYTES: u64 = 16 * 1024 * 1024;

/// A recognised format and how much of it is parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatInfo {
    pub id: &'static str,
    pub name: &'static str,
    /// `structural`, `header` or `recognition`.
    pub support: &'static str,
    pub detail: &'static str,
}

pub const RDS5: FormatInfo = FormatInfo {
    id: "rds5",
    name: "RDS5",
    support: "structural",
    detail: "header, record array, ETPF chunk extent and block catalogue",
};

pub const RBF0: FormatInfo = FormatInfo {
    id: "rbf0",
    name: "RBF0",
    support: "structural",
    detail: "the header, the object tree, the local field dictionary and the string and attribute values",
};

pub const PSIN: FormatInfo = FormatInfo {
    id: "psin",
    name: "PSIN",
    support: "recognition",
    detail: "the magic only; no header field, record structure or purpose is established",
};

pub const RPF9: FormatInfo = FormatInfo {
    id: "rpf9",
    name: "RPF9",
    support: "recognition",
    detail: "an archive; the archive commands read its table of contents",
};

impl FormatInfo {
    /// The `format` object of an inspection document.
    pub fn json(self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "support": self.support,
            "detail": self.detail,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// How many records and entries are included.
    pub sample: usize,
    /// Read every block's storage selector instead of the first `sample`.
    pub blocks: bool,
    /// Inflate every zlib block and report what failed.
    pub verify: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sample: DEFAULT_SAMPLE,
            blocks: false,
            verify: false,
        }
    }
}

/// Why structure or decoding failed, and at which stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// `recognition`, `header`, `structure` or `decode`.
    pub stage: &'static str,
    pub message: String,
}

/// The grounded facts a display can show without parsing the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Summary {
    Rds5 {
        version: u32,
        records: u32,
        blocks: usize,
        /// Blocks whose storage selector was read.
        classified: usize,
        zlib_blocks: usize,
        entries: u32,
        uncompressed_total: u32,
        warning: Option<String>,
    },
    Rbf0 {
        word: u16,
        flags: u32,
        root_name_len: u16,
        /// Counts from the parsed body; `None` when the body did not parse.
        body: Option<Rbf0Body>,
    },
    Psin,
    Rpf9,
}

/// Counts the grounded RBF0 body fields a display can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rbf0Body {
    pub objects: usize,
    pub depth: usize,
    pub fields: usize,
    pub attributes: usize,
    pub string_values: usize,
    pub definitions: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// The bytes the report was produced from, as read.
    pub signature: Vec<u8>,
    pub format: Option<FormatInfo>,
    pub summary: Option<Summary>,
    /// The parsed structure, or `Value::Null` when nothing is recognised.
    pub structure: Value,
    pub failure: Option<Failure>,
}

/// The format whose signature the data starts with, never the file name.
pub fn recognise(head: &[u8]) -> Option<FormatInfo> {
    if rds5::is_rds5(head) {
        Some(RDS5)
    } else if rbf0::is_rbf0(head) {
        Some(RBF0)
    } else if head.starts_with(b"PSIN") {
        Some(PSIN)
    } else if lforge_rage9::rpf::is_rpf9(head) {
        Some(RPF9)
    } else {
        None
    }
}

/// Recognises `source` and parses as much of it as the format's support level
/// establishes. `len` is the subject length; `source` must be seekable from
/// its start.
pub fn inspect<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    cancel: &AtomicBool,
) -> Result<Report, String> {
    let signature =
        lforge_binary::read_at(source, 0, SIGNATURE_LEN).map_err(|err| err.to_string())?;
    let format = recognise(&signature);
    let (structure, summary, failure) = match format {
        Some(format) if format == RDS5 => rds5_structure(source, len, options, cancel),
        Some(format) if format == RBF0 => rbf0_structure(source, len, options, cancel),
        Some(format) if format == PSIN => (psin_structure(), Some(Summary::Psin), None),
        Some(format) if format == RPF9 => (rpf9_structure(), Some(Summary::Rpf9), None),
        _ => (Value::Null, None, None),
    };
    Ok(Report {
        signature,
        format,
        summary,
        structure,
        failure,
    })
}

fn hex(value: u64) -> String {
    format!("0x{value:016X}")
}

fn rds5_structure<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
    let limits = rds5::Limits::default();
    let mut container = match Container::read(source, len, &limits, cancel) {
        Ok(container) => container,
        Err(err) => {
            let message = err.to_string();
            return (
                json!({ "valid": false, "error": message }),
                None,
                Some(Failure {
                    stage: "structure",
                    message,
                }),
            );
        }
    };

    let sample = options.sample.clamp(1, MAX_SAMPLE);
    let classified = if options.blocks {
        container.classify(source, usize::MAX, cancel).unwrap_or(0)
    } else {
        container.classify(source, sample, cancel).unwrap_or(0)
    };
    let zlib_blocks = container
        .blocks
        .iter()
        .take(classified)
        .filter(|block| block.storage == Storage::Zlib)
        .count();

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
            let result = rds5::decode_block(source, &container, block.index, &limits, cancel, |_| {
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
            failure = Some(Failure {
                stage: "decode",
                message: format!("{failed} zlib blocks did not decode"),
            });
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
    let summary = Summary::Rds5 {
        version: container.version,
        records: container.record_count(),
        blocks: container.blocks.len(),
        classified,
        zlib_blocks,
        entries: container.entry_count,
        uncompressed_total: container.uncompressed_total,
        warning: container.warnings.first().cloned(),
    };
    (structure, Some(summary), failure)
}

fn rbf0_structure<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
    if len > MAX_RBF0_BYTES {
        let message =
            format!("the payload is {len} bytes, more than the {MAX_RBF0_BYTES} byte parse limit");
        return (
            json!({ "valid": false, "error": message.clone() }),
            None,
            Some(Failure {
                stage: "structure",
                message,
            }),
        );
    }
    let bytes = match read_bounded(source, len, cancel) {
        Ok(bytes) => bytes,
        Err(message) => {
            return (
                json!({ "valid": false, "error": message.clone() }),
                None,
                Some(Failure {
                    stage: "structure",
                    message,
                }),
            );
        }
    };
    match rbf0::parse(&bytes, &rbf0::Limits::default(), cancel) {
        Ok(document) => (
            rbf0_document(&document, options),
            Some(rbf0_summary(&document)),
            None,
        ),
        Err(err) => {
            let header = rbf0::Header::parse(&bytes).ok();
            let stage = match err.kind {
                rbf0::ErrorKind::NotRbf0
                | rbf0::ErrorKind::TooShort
                | rbf0::ErrorKind::UnsupportedVersion => "header",
                _ => "structure",
            };
            let message = err.to_string();
            let structure = match header {
                Some(header) => json!({
                    "valid": false,
                    "header": rbf0_header(&header, None),
                    "error": message.clone(),
                }),
                None => json!({ "valid": false, "error": message.clone() }),
            };
            let summary = header.map(|header| Summary::Rbf0 {
                word: header.word,
                flags: header.flags,
                root_name_len: header.root_name_len,
                body: None,
            });
            (structure, summary, Some(Failure { stage, message }))
        }
    }
}

/// Reads at most the whole subject from its start, in bounded steps.
fn read_bounded<R: Read + Seek>(
    source: &mut R,
    len: u64,
    cancel: &AtomicBool,
) -> Result<Vec<u8>, String> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|err| err.to_string())?;
    let mut bytes = Vec::with_capacity(usize::try_from(len.min(1 << 20)).unwrap_or(0));
    let mut reader = source.take(len);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(bytes)
}

fn rbf0_header(header: &rbf0::Header, digest: Option<&[u8; 32]>) -> Value {
    let mut value = json!({
        "len": rbf0::PREFIX_LEN,
        "marker": format!("0x{:04X}", header.word),
        "value": header.flags,
        "root_name_len": header.root_name_len,
    });
    if let Some(digest) = digest {
        value["root_name_sha256"] = json!(lforge_binary::hex_bytes(digest));
    }
    value
}

fn rbf0_summary(document: &rbf0::Document) -> Summary {
    Summary::Rbf0 {
        word: document.header.word,
        flags: document.header.flags,
        root_name_len: document.header.root_name_len,
        body: Some(Rbf0Body {
            objects: document.objects,
            depth: document.depth,
            fields: document.fields,
            attributes: document.attributes,
            string_values: document.strings.count,
            definitions: document.definitions.len(),
        }),
    }
}

fn text_stats(stats: rbf0::TextStats) -> Value {
    if stats.count == 0 {
        json!({ "count": 0, "bytes": 0 })
    } else {
        json!({
            "count": stats.count,
            "bytes": stats.bytes,
            "min_len": stats.min_len,
            "max_len": stats.max_len,
        })
    }
}

fn rbf0_document(document: &rbf0::Document, options: &Options) -> Value {
    let sample = options.sample.clamp(1, MAX_SAMPLE);
    let definitions: Vec<Value> = document
        .definitions
        .iter()
        .take(sample)
        .map(|definition| {
            json!({
                "field_id": format!("0x{:04X}", definition.field_id),
                "class": rbf0::FieldClass::of(definition.field_id)
                    .map_or("unknown", |class| class.name()),
                "slot": definition.field_id & 0x0FFF,
                "offset": hex(definition.offset as u64),
                "name_len": definition.name_len,
                "name_sha256": lforge_binary::hex_bytes(&definition.name_digest),
            })
        })
        .collect();
    let diagnostics: Vec<Value> = document
        .diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "severity": "note",
                "offset": hex(diagnostic.offset as u64),
                "message": diagnostic.message,
            })
        })
        .collect();
    let body_len = (document.end - document.body_offset) as u64;
    json!({
        "valid": true,
        "header": rbf0_header(&document.header, Some(&document.root_name_digest)),
        "body": {
            "offset": hex(document.body_offset as u64),
            "length": body_len,
            "objects": document.objects,
            "depth": document.depth,
            "fields": document.fields,
            "object_fields": document.object_fields,
            "string_fields": document.string_fields,
            "fixed8_fields": document.fixed8_fields,
            "attributes": document.attributes,
            "definitions": {
                "count": document.definitions.len(),
                "shown": definitions.len(),
                "items": definitions,
            },
            "strings": text_stats(document.strings),
            "attribute_values": text_stats(document.attribute_values),
        },
        "parsed_ranges": [
            { "offset": hex(0), "length": rbf0::PREFIX_LEN, "field": "header" },
            {
                "offset": hex(rbf0::PREFIX_LEN as u64),
                "length": u64::from(document.header.root_name_len),
                "field": "root name",
            },
            {
                "offset": hex(document.body_offset as u64),
                "length": body_len,
                "field": "body",
            },
        ],
        "unknown_regions": [],
        "diagnostics": diagnostics,
        "limitations": [
            "the meaning of the header marker, the header value and every field identifier is unknown",
            "field names and text values are payload text; only their lengths and digests are reported",
            "only identifiers 0x0001, 0x0002, 0x0004 to 0x000A, 0x1006 and 0x6003/0x6004 are parsed; another identifier stops the parse",
            "attribute position is unresolved: the counted attributes precede the fields",
        ],
    })
}

fn psin_structure() -> Value {
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
            "nothing relates PSIN to a confirmed PSO format",
            "no checked field in the first 32 bytes equals the payload size",
        ],
    })
}

fn rpf9_structure() -> Value {
    json!({
        "valid": true,
        "diagnostics": [],
        "limitations": [
            "recognition only; the archive commands read the table of contents",
            "a nested archive is traversed with `--enter`, not parsed here",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_formats_from_their_signatures() {
        assert_eq!(recognise(b"RDS5\0\0\0\0"), Some(RDS5));
        assert_eq!(recognise(b"RBF0\0\0"), Some(RBF0));
        assert_eq!(recognise(b"PSIN\0\0\0\0"), Some(PSIN));
        assert_eq!(recognise(b"9FPR\0\0\0\0"), Some(RPF9));
        assert_eq!(recognise(b"\x89PNG\r\n\x1a\n"), None);
        assert_eq!(recognise(b""), None);
    }

    #[test]
    fn psin_is_described_as_recognition_only() {
        let bytes = b"PSIN\0\0\0\0";
        let report = inspect(
            &mut std::io::Cursor::new(bytes),
            bytes.len() as u64,
            &Options::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        let format = report.format.unwrap();
        assert_eq!(format.id, "psin");
        assert_eq!(format.name, "PSIN");
        assert_eq!(format.support, "recognition");
        assert_eq!(report.summary, Some(Summary::Psin));
        let limitations = report.structure["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        // The only mention of PSO is the disclaimer that no relation exists.
        assert!(limitations.contains("nothing relates"), "{limitations}");
        assert!(
            limitations.contains("magic") || limitations.contains("recognition"),
            "{limitations}"
        );
    }
}
