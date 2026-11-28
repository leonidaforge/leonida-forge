//! Content-based recognition and structural inspection of the formats this
//! build decodes.
//!
//! Shared by `lforge binary inspect`, `lforge archive inspect` and the
//! desktop binary inspector, so a recognised format means the same thing in
//! every front end. Nothing here prints or returns payload bytes: a field
//! whose meaning the research does not establish is reported as the number it
//! stores, and an unknown region as a range.
//!
//! `PSIN` is recognised by its magic and walked by its own framing. The
//! `LSCH` family also carries a self-describing schema and instance data,
//! which is decoded into a typed document; the `PMAP` family is reported as a
//! recognised framing with no decoded structure.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_rage9::gfx;
use lforge_rage9::psin::pso::names::Names;
use lforge_rage9::rbf0;
use lforge_rage9::rds5::{self, Container, Storage};
use lforge_rage9::{adat, edup, kb2, psin};
use serde_json::{Map, Value, json};

/// The schema of an inspection document. Version 2 adds `provenance`,
/// `representation` and `failure_stage`; every version 1 field keeps its
/// meaning.
pub const SCHEMA: &str = "leonida-forge.format-inspection/2";

/// Bytes read to recognise a format. The metadata resource tag sits at `+0x10`.
pub const SIGNATURE_LEN: usize = 0x14;
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
    support: "structural",
    detail: "the section walk, the LSCH schema and instance blocks, the PMAP and PSCH tables and the CHKS checksum",
};

pub const META_RESOURCE: FormatInfo = FormatInfo {
    id: "meta-resource",
    name: "metadata resource",
    support: "recognition",
    detail: "the `0DRP` tag and the object type byte; the self-describing tables decode as a `0DRP` document",
};

pub const EDUP: FormatInfo = FormatInfo {
    id: "edup",
    name: "EDUP",
    support: "structural",
    detail: "the entry count, the two 8-byte fields without their values and the opaque trailing blob",
};

pub const ADAT: FormatInfo = FormatInfo {
    id: "adat",
    name: "ADAT",
    support: "structural",
    detail: "the header, the per-stream tables, the chunk records and the 2,048-byte packet framing of the 0x0B streams",
};

pub const KB2: FormatInfo = FormatInfo {
    id: "kb2",
    name: "KB2",
    support: "structural",
    detail: "the header, the frame index and the per-frame audio record framing; no frame is decoded",
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
    Psin {
        /// `LSCH`, `PMAP` or `other`.
        family: &'static str,
        sections: usize,
        /// `verified`, `mismatched` or `unsupported`.
        checksum: &'static str,
        /// What the `LSCH` family decoded, when it decoded.
        decoded: Option<crate::pso::Counts>,
    },
    Edup {
        count: u32,
        first_distinct: usize,
        second_distinct: usize,
        blob_len: u32,
    },
    Adat {
        variant: u16,
        streams: u32,
        records: u32,
        packets: u64,
        blocks: u64,
        violations: u64,
        framing_checked: bool,
    },
    Kb2 {
        variant: &'static str,
        frames: u32,
        width: u32,
        height: u32,
        tracks: u32,
        issues: usize,
    },
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
    /// The `0DRP` form of the same metadata: a resource whose system segment
    /// holds the schema, the blocks and a text pool.
    MetaResource {
        object_type: u8,
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
    } else if psin::is_psin(head) {
        Some(PSIN)
    } else if head.get(0x10..0x14) == Some(b"0DRP") {
        Some(META_RESOURCE)
    } else if edup::is_edup(head) {
        Some(EDUP)
    } else if adat::is_adat(head) {
        Some(ADAT)
    } else if kb2::is_kb2(head) {
        Some(KB2)
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
    inspect_with_names(source, len, options, None, cancel)
}

/// Inspects `source`, naming the metadata structure and field hashes that
/// `names` reproduces.
pub fn inspect_with_names<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    names: Option<&Names>,
    cancel: &AtomicBool,
) -> Result<Report, String> {
    let signature =
        lforge_binary::read_at(source, 0, SIGNATURE_LEN).map_err(|err| err.to_string())?;
    let format = recognise(&signature);
    let (structure, summary, failure) = match format {
        Some(format) if format == RDS5 => rds5_structure(source, len, options, cancel),
        Some(format) if format == RBF0 => rbf0_structure(source, len, options, cancel),
        Some(format) if format == GFX => gfx_structure(source, len, options, cancel),
        Some(format) if format == PSIN => psin_structure(source, len, options, names, cancel),
        Some(format) if format == EDUP => edup_structure(source, len, options, cancel),
        Some(format) if format == ADAT => adat_structure(source, len, options, cancel),
        Some(format) if format == KB2 => kb2_structure(source, len, options, cancel),
        Some(format) if format == META_RESOURCE => meta_resource_structure(source, cancel),
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

fn rbf0_summary(document: &rbf0::Statistics) -> Summary {
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

fn rbf0_document(document: &rbf0::Statistics, options: &Options) -> Value {
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

fn psin_structure<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    names: Option<&Names>,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
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
    match psin::parse(&bytes) {
        Ok(report) => {
            let sample = options.sample.clamp(1, MAX_SAMPLE);
            // The instance data of the `LSCH` family decodes into typed
            // structures. The other families stop at the framing.
            let empty = Names::empty();
            let names = names.unwrap_or(&empty);
            let (metadata, decoded) = match psin::pso::decode(&bytes) {
                Ok(document) => {
                    let counts = crate::pso::counts(&document);
                    let shown = if options.blocks { usize::MAX } else { sample };
                    (
                        json!({
                            "status": "decoded",
                            "document": crate::pso::document_json(&document, names, shown),
                        }),
                        Some(counts),
                    )
                }
                Err(psin::pso::Error::Unsupported { family, first_tag }) => (
                    json!({
                        "status": "unsupported",
                        "family": family,
                        "firstTag": first_tag,
                        "reason": "the container is recognised but its family has no decoded structure here",
                    }),
                    None,
                ),
                Err(err) => (
                    json!({ "status": "failed", "error": err.to_string() }),
                    None,
                ),
            };
            let sections: Vec<Value> = report
                .sections
                .iter()
                .take(sample)
                .map(|section| {
                    json!({
                        "tag": section.tag_text(),
                        "offset": hex(u64::from(section.offset)),
                        "length": section.len,
                        "body_length": section.body_len(),
                    })
                })
                .collect();
            let structure = json!({
                "valid": true,
                "size": bytes.len(),
                "first_section": hex(u64::from(report.first_offset)),
                "first_tag": String::from_utf8_lossy(&report.first_tag),
                "family": report.family.name(),
                "sections": {
                    "count": report.sections.len(),
                    "shown": sections.len(),
                    "items": sections,
                },
                "descriptors": report.descriptors.as_ref().map(|table| json!({
                    "count": table.count,
                    "candidates": table.candidates,
                    "blocks": table.descriptors.iter().map(|descriptor| json!({
                        "word": hex_u32(descriptor.word),
                        "length": descriptor.len,
                    })).collect::<Vec<Value>>(),
                })),
                "blocks": report.blocks.as_ref().map(|table| json!({
                    "mode": table.mode,
                    "second": table.second,
                    "count": table.blocks.len(),
                    "predicted_first_offset": table.predicted_first_offset,
                    "offset_matches": table.offset_matches,
                    "padding_ok": table.padding_ok,
                    "items": table.blocks.iter().map(|block| json!({
                        "id": block.id,
                        "offset": block.offset,
                        "zero": block.zero,
                        "length": block.len,
                    })).collect::<Vec<Value>>(),
                })),
                "section_table": report.section_table.as_ref().map(|table| json!({
                    "count": table.count,
                    "tiling_ok": table.tiling_ok,
                    "tiling_error": table.tiling_error,
                    "values": table.values.iter().take(sample).map(|value| json!({
                        "id": value.id,
                        "offset": value.offset,
                        "length": value.len,
                    })).collect::<Vec<Value>>(),
                })),
                "lsch_body": report.lsch.as_ref().map(|body| json!({
                    "length": body.len,
                    "header_word": body.header_word,
                    "header_zero": body.header_zero,
                    "marker_records": body.marker_records,
                    "tail_length": body.tail_len,
                    "aligned": body.aligned,
                })),
                "lenm_body": report.lenm.as_ref().map(|body| json!({
                    "length": body.len,
                    "count": body.count,
                    "chain_length": body.chain_len,
                    "extra_length": body.extra,
                    "count_delimits_body": body.count_delimits_body,
                })),
                "id1_block": report.id1_block.map(|block| json!({
                    "offset": block.offset,
                    "length": block.len,
                    "nul_terminated": block.nul_terminated,
                })),
                "checksum": match report.checksum {
                    psin::Checksum::Verified => json!({ "status": "verified" }),
                    psin::Checksum::Mismatch { stored, computed } => json!({
                        "status": "mismatched",
                        "stored": hex_u32(stored),
                        "computed": hex_u32(computed),
                    }),
                    psin::Checksum::Unsupported => json!({ "status": "unsupported" }),
                },
                "issues": report.issues,
                "metadata": metadata,
                "unknown_regions": [
                    { "field": "PSCH value contents", "reason": "bounded by offsets, not decoded" },
                    { "field": "LSCH marker fields and tail", "reason": "no field meaning is established" },
                    { "field": "LENM chain and extra region", "reason": "not decoded" },
                    { "field": "STDN, STFN, STNS, PSIG bodies", "reason": "no field meaning is established" },
                ],
                "limitations": [
                    "the two families share a tag vocabulary, not a grammar; every result names its family",
                    "the LSCH family decodes its own schema; the PMAP family is framing only",
                    "the checksum is reported separately from the structural parse",
                    "the trailing NUL of the id-1 block is an observation, not a requirement",
                ],
            });
            let summary = Summary::Psin {
                family: report.family.name(),
                sections: report.sections.len(),
                checksum: report.checksum.name(),
                decoded,
            };
            (structure, Some(summary), None)
        }
        Err(err) => {
            let message = err.to_string();
            (
                json!({ "valid": false, "error": message.clone() }),
                None,
                Some(Failure {
                    stage: "structure",
                    message,
                }),
            )
        }
    }
}

fn hex_u32(value: u32) -> String {
    format!("0x{value:08X}")
}

fn edup_structure<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
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
    match edup::parse(&bytes, 1 << 22) {
        Ok(report) => {
            let sample = options.sample.clamp(1, MAX_SAMPLE);
            let entries: Vec<Value> = report
                .entries
                .iter()
                .take(sample)
                .map(|entry| {
                    json!({
                        "first": hex(entry.first),
                        "second": hex(entry.second),
                    })
                })
                .collect();
            let structure = json!({
                "valid": true,
                "size": report.size,
                "count": report.count,
                "first_distinct": report.first_distinct,
                "second_distinct": report.second_distinct,
                "first_unique": report.first_unique,
                "fields_disjoint": report.fields_disjoint,
                "entries": {
                    "count": report.entries.len(),
                    "shown": entries.len(),
                    "items": entries,
                },
                "trailing_blob": {
                    "offset": hex(report.blob.offset),
                    "length": report.blob.len,
                },
                "key_direction": {
                    "status": "not evaluated",
                    "reason": "no texture store set was supplied, so no key was compared",
                },
                "unknown_regions": [
                    { "field": "trailing blob", "reason": "length-delimited and opaque" },
                    { "field": "entry field meaning", "reason": "the key direction is established for one table only" },
                ],
                "limitations": [
                    "a matching stored key does not establish the purpose of an entry",
                    "the direction is confirmed for the large table only; the smaller tables remain unresolved",
                    "no store is scanned when a payload is inspected",
                ],
            });
            let summary = Summary::Edup {
                count: report.count,
                first_distinct: report.first_distinct,
                second_distinct: report.second_distinct,
                blob_len: report.blob.len,
            };
            (structure, Some(summary), None)
        }
        Err(err) => {
            let message = err.to_string();
            (
                json!({ "valid": false, "error": message.clone() }),
                None,
                Some(Failure {
                    stage: "structure",
                    message,
                }),
            )
        }
    }
}

fn adat_structure<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
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
    match adat::parse(&bytes, &adat::Limits::default()) {
        Ok(report) => {
            let sample = options.sample.clamp(1, MAX_SAMPLE);
            let records: Vec<Value> = report
                .records
                .iter()
                .take(sample)
                .map(|record| {
                    json!({
                        "index": record.index,
                        "type": format!("{:#04x}", record.kind),
                        "offset": hex(u64::from(record.offset)),
                        "length": record.size,
                    })
                })
                .collect();
            let structure = json!({
                "valid": true,
                "size": report.stored_len,
                "version": report.version,
                "variant": hex_u32(u32::from(report.variant)),
                "streams": report.streams,
                "data_offset": hex(u64::from(report.data_offset)),
                "chunk_records": {
                    "count": report.record_count,
                    "shown": records.len(),
                    "items": records,
                    "by_type": report.type_counts.iter().map(|(kind, count)| json!({
                        "type": format!("{kind:#04x}"),
                        "count": count,
                    })).collect::<Vec<Value>>(),
                },
                "phrases": report.phrases.iter().map(|phrase| json!({
                    "offset": hex(u64::from(phrase.offset)),
                    "declared": phrase.declared,
                    "rate": phrase.rate,
                    "rate_flags": phrase.rate_flags,
                    "codec": phrase.codec,
                })).collect::<Vec<Value>>(),
                "pages": report.pages.iter().map(|page| json!({
                    "offset": hex(u64::from(page.offset)),
                    "pages": page.pages,
                    "stride": page.stride,
                    "entries": page.entries.iter().map(|entry| json!({
                        "decoded": entry.decoded,
                        "rate": entry.rate,
                        "rate_flags": entry.rate_flags,
                        "codec": entry.codec,
                    })).collect::<Vec<Value>>(),
                })).collect::<Vec<Value>>(),
                "codecs": report.codecs.iter().map(|codec| json!({
                    "codec": codec.codec,
                    "streams": codec.streams,
                    "support": codec.support,
                })).collect::<Vec<Value>>(),
                "blocks": {
                    "data": report.blocks.data,
                    "sentinel": report.blocks.sentinel,
                    "metadata": report.blocks.metadata,
                    "zero": report.blocks.zero,
                },
                "packets": report.packets,
                "packet_bytes": report.packet_bytes,
                "padding_bytes": report.padding,
                "framing_violations": report.framing_violations,
                "failure_sample": report.failures,
                "positions": report.positions.map(|table| json!({
                    "tables": table.tables,
                    "entries": table.entries,
                    "starts_at_zero": table.starts_at_zero,
                    "non_decreasing": table.non_decreasing,
                    "interpretation": "probable position table; the unit is unknown",
                })),
                "page_summary": report.page_summary.map(|summary| json!({
                    "declared_pages": summary.declared_pages,
                    "stride": summary.stride,
                    "sentinel_pages": summary.sentinel_pages,
                    "pages_with_metadata": summary.pages_with_metadata,
                    "page_count_matches": summary.page_count_matches,
                })),
                "rates": report.rates.iter().map(|(rate, count)| json!({
                    "rate": rate,
                    "records": count,
                })).collect::<Vec<Value>>(),
                "issues": report.issues,
                "unknown_regions": [
                    { "field": "codec identity", "reason": "no decoder was run" },
                    { "field": "packet contents", "reason": "no audio is decoded" },
                ],
                "limitations": [
                    "no codec is named and no decoder is run",
                    "only the 0x0B and 0x02 stream classes receive a check",
                    "the page classifier would absorb a corrupted first data block as metadata",
                    "packets are counted, never materialised",
                ],
            });
            let summary = Summary::Adat {
                variant: report.variant,
                streams: report.streams,
                records: report.record_count,
                packets: report.packets,
                blocks: report.blocks.data,
                violations: report.framing_violations,
                framing_checked: report.framing_checked,
            };
            (structure, Some(summary), None)
        }
        Err(err) => {
            let message = err.to_string();
            (
                json!({ "valid": false, "error": message.clone() }),
                None,
                Some(Failure {
                    stage: "structure",
                    message,
                }),
            )
        }
    }
}

fn kb2_structure<R: Read + Seek>(
    source: &mut R,
    len: u64,
    options: &Options,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
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
    match kb2::parse(&bytes, &kb2::Limits::default()) {
        Ok(report) => {
            let sample = options.sample.clamp(1, MAX_SAMPLE);
            let frames: Vec<Value> = report
                .frames
                .iter()
                .take(sample)
                .map(|frame| {
                    json!({
                        "index": frame.index,
                        "raw": hex_u32(frame.raw),
                        "flag": frame.flag,
                        "offset": frame.offset,
                    })
                })
                .collect();
            let structure = json!({
                "valid": true,
                "size": report.size,
                "variant": report.variant.name(),
                "header": {
                    "declared_length": report.declared_len,
                    "frame_count": report.frame_count,
                    "largest_frame": report.largest_frame,
                    "duplicate_count": report.duplicate_count,
                    "width": report.width,
                    "height": report.height,
                    "rate_numerator": report.rate_num,
                    "rate_denominator": report.rate_den,
                    "flags": report.flags,
                    "tracks": report.tracks,
                    "variant_word": report.variant_word,
                },
                "frame_index": {
                    "offset": hex(u64::from(report.table_offset)),
                    "end": hex(u64::from(report.table_end)),
                    "entries": report.frame_count_checked,
                    "shown": frames.len(),
                    "items": frames,
                    "checks": {
                        "monotone": report.checks.monotone,
                        "intervals_within_largest": report.checks.intervals_within_largest,
                        "last_offset_matches": report.checks.last_offset_matches,
                        "first_is_keyframe": report.checks.first_is_keyframe,
                        "frames_within_table": report.checks.frames_within_table,
                    },
                },
                "audio": {
                    "tracks": report.audio.iter().map(|track| json!({
                        "decoded_max": track.decoded_max,
                        "rate": track.rate,
                        "rate_flags": track.rate_flags,
                        "id": track.id,
                    })).collect::<Vec<Value>>(),
                    "track_ids_permutation": report.track_ids_permutation,
                    "frames": report.audio_records.frames,
                    "non_empty_records": report.audio_records.non_empty,
                    "zero_records": report.audio_records.zero_records,
                    "record_bytes": report.audio_records.bytes,
                    "violations": report.audio_records.violations,
                },
                "issues": report.issues,
                "failure_sample": report.failures,
                "unknown_regions": [
                    { "field": "frame payloads", "reason": "no frame is decoded" },
                    { "field": "flags word", "reason": "the bits are reported, not named" },
                    { "field": "variant word at +0x2C", "reason": "no meaning is established" },
                ],
                "limitations": [
                    "no video or audio codec is claimed and nothing is decoded",
                    "the 0x100000 flag bit is not established as an alpha flag",
                    "the low bit of an entry is reported as a flag, not as a confirmed keyframe",
                ],
            });
            let summary = Summary::Kb2 {
                variant: report.variant.name(),
                frames: report.frame_count,
                width: report.width,
                height: report.height,
                tracks: report.tracks,
                issues: report.issues.len() + report.failures.len(),
            };
            (structure, Some(summary), None)
        }
        Err(err) => {
            let message = err.to_string();
            (
                json!({ "valid": false, "error": message.clone() }),
                None,
                Some(Failure {
                    stage: "structure",
                    message,
                }),
            )
        }
    }
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

/// Reads the `0DRP` tag, the object type byte and the table counts of the
/// resource form. The tables themselves decode as a `0DRP` document
/// (`lforge_core::metadata`), which is a separate layout from the `PSIN`
/// container; this structure report is the recognition only.
fn meta_resource_structure<R: Read + Seek>(
    source: &mut R,
    cancel: &AtomicBool,
) -> (Value, Option<Summary>, Option<Failure>) {
    let head = match lforge_binary::read_at(source, 0, 0x50) {
        Ok(head) => head,
        Err(err) => {
            return (
                json!({ "valid": false, "error": err.to_string() }),
                None,
                Some(Failure {
                    stage: "header",
                    message: err.to_string(),
                }),
            );
        }
    };
    if cancel.load(Ordering::Relaxed) {
        return (Value::Null, None, None);
    }
    let object_type = head.get(0x14).copied();
    let word = |at: usize| -> Option<u16> {
        Some(u16::from_le_bytes(head.get(at..at + 2)?.try_into().ok()?))
    };
    let structure = json!({
        "valid": true,
        "tag": "0DRP",
        "object_type": object_type,
        "root_block": head.get(0x20..0x24).map(|word| u32::from_le_bytes(word.try_into().expect("4 bytes"))),
        "structures": word(0x48),
        "enums": word(0x4a),
        "blocks": word(0x4c),
        "unknown_word": word(0x4e),
        "page_map": lforge_rage9::resource::page_map_offset(&head),
        "limitations": [
            "this report is the recognition; `--metadata-output` decodes the resource's schema, blocks and values",
            "no field, block or value of this form is assigned a meaning",
        ],
    });
    (
        structure,
        object_type.map(|object_type| Summary::MetaResource { object_type }),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_formats_from_their_signatures() {
        assert_eq!(recognise(b"RDS5\0\0\0\0"), Some(RDS5));
        assert_eq!(recognise(b"RBF0\0\0"), Some(RBF0));
        assert_eq!(recognise(b"PSIN\0\0\0\0"), Some(PSIN));
        assert_eq!(recognise(b"EDUP\0\0\0\0"), Some(EDUP));
        assert_eq!(recognise(b"ADAT\x01\x00"), Some(ADAT));
        assert_eq!(recognise(b"KB2n\0\0\0\0"), Some(KB2));
        assert_eq!(recognise(b"KB2j\0\0\0\0"), Some(KB2));
        assert_eq!(recognise(b"9FPR\0\0\0\0"), Some(RPF9));
        assert_eq!(recognise(b"\x89PNG\r\n\x1a\n"), None);
        assert_eq!(recognise(b""), None);
    }

    #[test]
    fn psin_is_structural_and_names_its_family() {
        // An unknown first tag still walks the framing and the checksum.
        let mut bytes = b"PSIN".to_vec();
        bytes.extend_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(b"ZZZZ");
        bytes.extend_from_slice(&16u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        let total = bytes.len() as u64;
        let report = inspect(
            &mut std::io::Cursor::new(bytes),
            total,
            &Options::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        let format = report.format.unwrap();
        assert_eq!(format.id, "psin");
        assert_eq!(format.support, "structural");
        assert!(matches!(
            report.summary,
            Some(Summary::Psin {
                family: "other",
                sections: 1,
                ..
            })
        ));
        assert_eq!(report.structure["valid"], true);
        assert_eq!(report.structure["family"], "other");
        assert_eq!(report.structure["checksum"]["status"], "unsupported");
        let text = serde_json::to_string(&report.structure)
            .unwrap()
            .to_lowercase();
        assert!(!text.contains("\"pso\""));
    }

    #[test]
    fn psin_reports_a_structural_failure() {
        let bytes = b"PSIN\0\0\0\0";
        let total = bytes.len() as u64;
        let report = inspect(
            &mut std::io::Cursor::new(bytes.to_vec()),
            total,
            &Options::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.structure["valid"], false);
        assert!(report.failure.is_some());
    }

    #[test]
    fn reports_an_edup_table_without_key_values() {
        let mut bytes = b"EDUP".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&7u64.to_le_bytes());
        bytes.extend_from_slice(&9u64.to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        let total = bytes.len() as u64;
        let report = inspect(
            &mut std::io::Cursor::new(bytes),
            total,
            &Options::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.format.map(|format| format.id), Some("edup"));
        assert!(matches!(
            report.summary,
            Some(Summary::Edup {
                count: 1,
                blob_len: 16,
                ..
            })
        ));
        assert_eq!(
            report.structure["entries"]["items"][0]["first"],
            "0x0000000000000007"
        );
        assert_eq!(report.structure["key_direction"]["status"], "not evaluated");
        assert_eq!(report.structure["trailing_blob"]["length"], 16);
    }

    #[test]
    fn reports_an_adat_header_and_its_refusals() {
        // Version 1, variant 0xFF21, one stream, no records: the record run
        // starts at 0x1E and the data offset is 0x1E.
        let mut bytes = vec![0u8; 0x1E];
        bytes[..4].copy_from_slice(b"ADAT");
        bytes[4..8].copy_from_slice(&0xFF21_0001u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x0C..0x10].copy_from_slice(&0x1Eu32.to_le_bytes());
        let total = bytes.len() as u64;
        let report = inspect(
            &mut std::io::Cursor::new(bytes),
            total,
            &Options::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.format.map(|format| format.id), Some("adat"));
        assert_eq!(report.structure["valid"], true);
        assert_eq!(report.structure["variant"], "0x0000FF21");
        assert_eq!(report.structure["streams"], 1);
        assert_eq!(report.structure["chunk_records"]["count"], 0);
        let text = serde_json::to_string(&report.structure).unwrap();
        assert!(!text.to_lowercase().contains("opus"));
    }

    #[test]
    fn reports_a_kb2_header_and_frame_table() {
        // Two frames of 4 bytes with no audio track.
        let entries = 3usize;
        let table = 0x30 + 4 * entries;
        let size = table + 8;
        let mut bytes = vec![0u8; size];
        bytes[..4].copy_from_slice(b"KB2n");
        bytes[4..8].copy_from_slice(&((size - 8) as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x0C..0x10].copy_from_slice(&4u32.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&320u32.to_le_bytes());
        bytes[0x18..0x1C].copy_from_slice(&240u32.to_le_bytes());
        bytes[0x1C..0x20].copy_from_slice(&30u32.to_le_bytes());
        bytes[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x24..0x28].copy_from_slice(&0x0004_0013u32.to_le_bytes());
        for (index, value) in [table as u32 | 1, table as u32 + 4, size as u32]
            .into_iter()
            .enumerate()
        {
            let at = 0x30 + 4 * index;
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let total = bytes.len() as u64;
        let report = inspect(
            &mut std::io::Cursor::new(bytes),
            total,
            &Options::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.format.map(|format| format.id), Some("kb2"));
        assert!(matches!(
            report.summary,
            Some(Summary::Kb2 {
                variant: "KB2n",
                frames: 2,
                width: 320,
                height: 240,
                tracks: 0,
                ..
            })
        ));
        assert_eq!(report.structure["frame_index"]["checks"]["monotone"], true);
        assert_eq!(
            report.structure["audio"]["tracks"]
                .as_array()
                .unwrap()
                .len(),
            0
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
