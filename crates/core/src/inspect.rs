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

use lforge_rage9::gfx;
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

pub const GFX: FormatInfo = FormatInfo {
    id: "gfx",
    name: "GFx",
    support: "structural",
    detail: "the version-42 header, the RECT extent, frame rate and count, and the tag walk; tag bodies are opaque",
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
    /// Read every block's storage class instead of the first `sample`.
    pub blocks: bool,
    /// Decode every decodable block and report what failed.
    pub verify: bool,
    /// The RDS5 descriptor whose byte-level chain is reported.
    pub texture: Option<u32>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            sample: DEFAULT_SAMPLE,
            blocks: false,
            verify: false,
            texture: None,
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
        /// Whether the versioned header with the `0xFFFB` marker is present.
        versioned: bool,
        version: Option<u16>,
        /// Width of a number value, from the header variant.
        number_len: usize,
        /// Names the document defined.
        names: usize,
        /// Counts from the parsed body; `None` when the body did not parse.
        body: Option<Rbf0Body>,
    },
    Psin,
    Gfx {
        version: u8,
        declared_len: u32,
        rect_len: usize,
        frame_rate: u16,
        frame_count: u16,
        /// Top-level tags, then nested records.
        tags: usize,
        max_depth: usize,
    },
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
    } else if gfx::is_gfx(head) {
        Some(GFX)
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
        Some(format) if format == GFX => gfx_structure(source, len, options, cancel),
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
        let indices: Vec<u32> = container.blocks.iter().map(|block| block.index).collect();
        for index in indices {
            let decodable = matches!(
                container.blocks[index as usize].storage,
                Storage::Zlib | Storage::Stored
            );
            if !decodable {
                continue;
            }
            checked += 1;
            let mut len = 0u64;
            let result = rds5::decode_block(
                source,
                &mut container,
                index,
                &limits,
                cancel,
                |_| Ok(()),
            )
            .map(|report| {
                len = report.len;
            });
            match result {
                Ok(()) => decoded += len,
                Err(err) => {
                    failed += 1;
                    if failures.len() < MAX_FAILURES {
                        let block = &container.blocks[index as usize];
                        failures.push(json!({
                            "block": index,
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
                message: format!("{failed} blocks did not decode"),
            });
        }
        json!({
            "decodable_blocks": checked,
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
                Storage::Stored => "stored content of the block's virtual length",
                Storage::ZlibHeaderMissing =>
                    "carries zlib class 0x20 but does not start with a zlib header",
                Storage::Undecoded(_) => "storage class whose payload is not decoded",
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
                "class_id": record.class_id(),
                "class_dispatch": record.dispatch_class(),
                "ambiguous_offset": record.is_ambiguous(),
                "second_word": hex(u64::from(record.second_word)),
            });
            if role == "block" {
                value["counter"] = json!(record.counter());
                value["page_term"] = json!(record.page_term());
                value["padding"] = json!(record.padding());
                value["virtual_position"] = json!(record.virtual_position());
                if record.is_ambiguous() {
                    value["offset26"] = json!(hex(record.offset26()));
                }
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
                "width": entry.width(),
                "height": entry.height(),
                "mip": entry.mip(),
                "flags": entry.flags(),
                "format_id": entry.format_id(),
                "array_size": entry.array_size(),
                "kind": entry.kind(),
                "tile_mode": entry.tile_mode(),
                "unknown_high_nibble": entry.unknown_high_nibble(),
                "locator_page": entry.locator_page(),
                "locator_high": hex(entry.locator_high()),
            })
        })
        .collect();

    // Storage is reported per class id. Only `0x20` and `0x00` are decoded;
    // the other observed ids keep their number and get no codec name.
    let mut by_storage = Map::new();
    let mut counts: Vec<(String, usize)> = Vec::new();
    for (name, storage) in [
        ("zlib".to_string(), Storage::Zlib),
        ("stored".to_string(), Storage::Stored),
        (
            "zlib_header_missing".to_string(),
            Storage::ZlibHeaderMissing,
        ),
        ("unread".to_string(), Storage::Unread),
    ] {
        counts.push((
            name,
            container
                .blocks
                .iter()
                .filter(|block| block.storage == storage)
                .count(),
        ));
    }
    for id in [0x04u8, 0x0C, 0x10, 0x14, 0x18, 0x1C] {
        counts.push((
            format!("class_{id:02X}"),
            container
                .blocks
                .iter()
                .filter(|block| block.storage == Storage::Undecoded(id))
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
            let mut value = json!({
                "index": block.index,
                "record": block.record,
                "offset": hex(block.offset),
                "stored_len": block.stored_len,
                "padding": block.padding,
                "content_len": block.content_len,
                "virtual_len": block.virtual_len,
                "virtual_position": hex(block.virtual_position),
                "class_id": block.class_id,
                "ambiguous_offset": block.ambiguous,
                "storage": block.storage.name(),
            });
            if let Some(offset26) = block.offset26 {
                value["offset26"] = json!(hex(offset26));
            }
            value
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

    let keys = container.keys(source).ok();
    let texture = options.texture.map(|descriptor| {
        match texture_chain(source, &mut container, descriptor, &limits, cancel) {
            Ok(report) => texture_json(&report),
            Err(err) => json!({ "descriptor": descriptor, "error": err.to_string() }),
        }
    });
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
            "keys": keys.as_ref().map(|keys| json!({
                "count": keys.len(),
                "strictly_increasing": rds5::Container::keys_sorted(keys),
                "values": "not published",
            })),
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
        "texture": texture,
        "parsed_ranges": ranges,
        "unknown_regions": unknown,
        "verified": verified.unwrap_or(Value::Null),
        "diagnostics": diagnostics,
        "limitations": [
            "the meaning of the descriptor fields beyond their widths, the block record's layout flag and the locator high bits is unknown",
            "the ETPF content after the key table is not interpreted",
            "page sizes and pixel formats are not part of this container",
            "only storage classes 0x20 and 0x00 are decoded; the other ids are reported and refused",
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

/// Reconstructs one RDS5 descriptor's bytes into `sink` and returns the
/// chain. The bytes are never part of the returned report.
pub fn rds5_texture<R: Read + Seek>(
    source: &mut R,
    len: u64,
    descriptor: u32,
    cancel: &AtomicBool,
    sink: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<rds5::TextureReport, String> {
    let limits = rds5::Limits::default();
    let mut container =
        Container::read(source, len, &limits, cancel).map_err(|err| err.to_string())?;
    rds5::reconstruct_texture(source, &mut container, descriptor, &limits, cancel, sink)
        .map_err(|err| err.to_string())
}

fn texture_chain<R: Read + Seek>(
    source: &mut R,
    container: &mut Container,
    descriptor: u32,
    limits: &rds5::Limits,
    cancel: &AtomicBool,
) -> Result<rds5::TextureReport, rds5::Error> {
    rds5::reconstruct_texture(source, container, descriptor, limits, cancel, |_| Ok(()))
}

fn texture_json(report: &rds5::TextureReport) -> Value {
    json!({
        "descriptor": report.descriptor,
        "width": report.width,
        "height": report.height,
        "mip": report.mip,
        "format_id": report.format_id,
        "kind": report.kind,
        "tile_mode": report.tile_mode,
        "first_page": report.first_page,
        "first_block": report.first_block,
        "block_count": report.block_count,
        "classes": report.classes,
        "virtual_start": hex(report.virtual_start),
        "virtual_end": hex(report.virtual_end),
        "decoded_len": report.decoded_len,
        "bytes_per_texel": report.bytes_per_texel,
        "complete": report.complete,
        "notes": report.notes,
        "representation": "reconstructed bytes, not a decoded image",
    })
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
                versioned: header.versioned,
                version: header.version,
                number_len: header.number_len(),
                names: 0,
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
        "versioned": header.versioned,
        "version": header.version,
        "number_len": header.number_len(),
        "body_offset": header.body_offset(),
    });
    if let Some(digest) = digest {
        value["root_name_sha256"] = json!(lforge_binary::hex_bytes(digest));
    }
    value
}

fn rbf0_summary(document: &rbf0::Document) -> Summary {
    Summary::Rbf0 {
        versioned: document.header.versioned,
        version: document.header.version,
        number_len: document.header.number_len(),
        names: document.names,
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
                "name_index": definition.index,
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
    let header_len = document.body_offset as u64;
    json!({
        "valid": true,
        "header": rbf0_header(&document.header, Some(&document.root_name_digest)),
        "body": {
            "offset": hex(document.body_offset as u64),
            "length": body_len,
            "names": document.names,
            "objects": document.objects,
            "depth": document.depth,
            "fields": document.fields,
            "attributes": document.attributes,
            "text_nodes": document.text_nodes,
            "values_by_type": document.types.iter().enumerate().map(|(code, count)| {
                json!({ "type": code, "count": count })
            }).collect::<Vec<Value>>(),
            "definitions": {
                "count": document.definitions.len(),
                "shown": definitions.len(),
                "items": definitions,
            },
            "strings": text_stats(document.strings),
            "length_prefixed_values": text_stats(document.attribute_values),
        },
        "parsed_ranges": [
            { "offset": hex(0), "length": header_len, "field": "header" },
            {
                "offset": hex(document.body_offset as u64),
                "length": body_len,
                "field": "token stream",
            },
        ],
        "unknown_regions": [],
        "diagnostics": diagnostics,
        "limitations": [
            "the meaning of the version marker, the reserved word and every name is unknown",
            "names and text values are payload text; only their lengths and digests are reported",
            "token classes 7 to 14 were not observed and stop the parse",
            "the value forms are widths; no numeric or boolean meaning is established",
        ],
    })
}

/// The largest GFx payload read for structural parsing.
const MAX_GFX_BYTES: u64 = 64 * 1024 * 1024;

fn gfx_structure<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
    if len > MAX_GFX_BYTES {
        let message =
            format!("the payload is {len} bytes, more than the {MAX_GFX_BYTES} byte parse limit");
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
    match gfx::parse(&bytes, &gfx::Limits::default(), cancel) {
        Ok(document) => {
            let header = &document.header;
            let sample = options.sample.clamp(1, MAX_SAMPLE);
            let tags: Vec<Value> = document
                .tags
                .iter()
                .take(sample)
                .map(|tag| {
                    json!({
                        "offset": hex(tag.offset as u64),
                        "code": tag.code,
                        "length": tag.length,
                        "depth": tag.depth,
                        "body": { "start": tag.body.start, "end": tag.body.end },
                    })
                })
                .collect();
            let structure = json!({
                "valid": true,
                "header": {
                    "version": header.version,
                    "declared_len": header.declared_len,
                    "payload_len": bytes.len(),
                    "rect_len": header.rect_len,
                    "nbits": header.nbits,
                    "frame_rate_8_8": header.frame_rate,
                    "frame_count": header.frame_count,
                    "tag_start": header.tag_start,
                },
                "tags": {
                    "top_level": document.top_level,
                    "total": document.tags.len(),
                    "max_depth": document.max_depth,
                    "shown": tags.len(),
                    "items": tags,
                },
                "parsed_ranges": [
                    { "offset": hex(0), "length": 8, "field": "identifier and length" },
                    {
                        "offset": hex(8),
                        "length": (header.tag_start - 8) as u64,
                        "field": "RECT and frame header",
                    },
                    {
                        "offset": hex(header.tag_start as u64),
                        "length": (document.end - header.tag_start) as u64,
                        "field": "tag stream",
                    },
                ],
                "unknown_regions": [],
                "diagnostics": [],
                "limitations": [
                    "versions other than 42 are recognised but not parsed",
                    "tag bodies other than the nested record stream of tag 39 are opaque",
                    "no tag body, ActionScript, rendering or playback is interpreted",
                    "the RECT coordinates and the frames per second are not decoded",
                ],
            });
            let summary = Summary::Gfx {
                version: header.version,
                declared_len: header.declared_len,
                rect_len: header.rect_len,
                frame_rate: header.frame_rate,
                frame_count: header.frame_count,
                tags: document.tags.len(),
                max_depth: document.max_depth,
            };
            (structure, Some(summary), None)
        }
        Err(err) => {
            let stage = match err.kind {
                gfx::ErrorKind::NotGfx
                | gfx::ErrorKind::TooShort
                | gfx::ErrorKind::UnsupportedVersion
                | gfx::ErrorKind::Length => "header",
                _ => "structure",
            };
            let message = err.to_string();
            (
                json!({ "valid": false, "error": message.clone() }),
                None,
                Some(Failure { stage, message }),
            )
        }
    }
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

    #[test]
    fn recognises_the_gfx_identifier_with_its_version_byte() {
        assert_eq!(recognise(b"GFX\x2A\x08\x00\x00\x00"), Some(GFX));
        // The identifier alone is the family; the version is a separate byte.
        assert_eq!(recognise(b"GFX\x2B"), Some(GFX));
        assert_eq!(recognise(b"GF"), None);
    }

    #[test]
    fn reports_a_version_42_gfx_payload() {
        let mut bytes = b"GFX\x2A".to_vec();
        let mut body = Vec::new();
        body.extend_from_slice(&0x1E00u16.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0x0040u16.to_le_bytes());
        body.extend_from_slice(&0x0000u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        // nbits 0 leaves a one-byte RECT.
        bytes.push(0);
        bytes.extend_from_slice(&body);
        let len = bytes.len() as u32;
        bytes[4..8].copy_from_slice(&len.to_le_bytes());
        let total = bytes.len() as u64;
        let mut cursor = std::io::Cursor::new(bytes);
        let report = inspect(
            &mut cursor,
            total,
            &Options::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.format.map(|format| format.id), Some("gfx"));
        let structure = &report.structure;
        assert_eq!(structure["valid"], true);
        assert_eq!(structure["header"]["version"], 42);
        assert_eq!(structure["header"]["rect_len"], 1);
        assert_eq!(structure["header"]["frame_rate_8_8"], 0x1E00);
        assert_eq!(structure["tags"]["top_level"], 2);
        assert_eq!(structure["tags"]["items"][0]["code"], 1);
        assert_eq!(structure["tags"]["items"][1]["code"], 0);
    }
}
