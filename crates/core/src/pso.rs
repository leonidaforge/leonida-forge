//! JSON and XML views of a decoded `PSIN` metadata container.
//!
//! Both views carry the same facts and keep the stored hashes: a name the
//! [`Names`] index resolves is reported beside the hash, never in place of it.
//! A field whose type the schema establishes is reported with its type name
//! and value; a field whose type is not established keeps its type word and
//! the bytes of the storage the schema implies.
//!
//! `sample` is the number of blocks whose records and elements are written in
//! full. Every other block is still described: its type, extent, record count
//! and decoded count. Pass [`usize::MAX`] to write every block.

use lforge_rage9::psin::pso::names::Names;
use lforge_rage9::psin::pso::{
    ArrayElements, Content, Document, EnumValueMatch, Field, PoolEntry, Record, Reference,
    ReferenceFault, Resolution, Scalar, Structure, Target, Value,
};
use serde_json::{Map, Value as Json, json};

/// What the document holds, for a summary line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub structures: usize,
    pub fields: usize,
    pub enums: usize,
    pub enum_values: usize,
    pub blocks: usize,
    pub records: usize,
    pub records_decoded: usize,
    pub roots: usize,
    pub structure_blocks: usize,
    pub pool_blocks: usize,
    /// Elements of a block typed by a field code, and how many were read.
    pub elements: usize,
    pub elements_decoded: usize,
    pub unsupported_blocks: usize,
    /// `Some(false)` when the copied resource header disagrees with the tables.
    pub header_matches: Option<bool>,
    pub issues: usize,
}

/// Counts the facts a summary can state.
pub fn counts(document: &Document) -> Counts {
    let mut counts = Counts {
        structures: document.structures.len(),
        fields: document
            .structures
            .iter()
            .map(|structure| structure.fields.len())
            .sum(),
        enums: document.enums.len(),
        enum_values: document
            .enums
            .iter()
            .map(|enumeration| enumeration.values.len())
            .sum(),
        blocks: document.blocks.len(),
        roots: document.roots().len(),
        header_matches: document.header_matches(),
        issues: document.issues.len(),
        ..Counts::default()
    };
    for block in &document.blocks {
        match &block.content {
            Content::Records { total, records, .. } => {
                counts.structure_blocks += 1;
                counts.records += *total as usize;
                counts.records_decoded += records.len();
            }
            Content::Pool { .. } => counts.pool_blocks += 1,
            Content::Elements { total, entries, .. } => {
                counts.pool_blocks += 1;
                counts.elements += *total as usize;
                counts.elements_decoded += entries.len();
            }
            Content::Unsupported(_) => counts.unsupported_blocks += 1,
        }
    }
    counts
}

pub(crate) fn hash32(value: u32) -> String {
    format!("0x{value:08X}")
}

pub(crate) fn hash64(value: u64) -> String {
    format!("0x{value:016X}")
}

pub(crate) fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// The candidates a hash index offers, as a document of its own.
pub(crate) fn named(names: &Names, hash: u32) -> Json {
    match names.lookup(hash) {
        [] => json!({ "status": "unresolved" }),
        [only] => json!({ "status": "resolved", "name": only }),
        several => json!({ "status": "ambiguous", "names": several }),
    }
}

/// The type name of a type code the schema establishes, or `None`.
pub(crate) fn type_name(code: u16, upper: u16) -> Option<&'static str> {
    lforge_rage9::psin::pso::type_width(code, upper)?;
    Some(match code {
        0x01 => "bool",
        0x05 => "structure",
        0x07 => "reference",
        0x08 => "u64",
        0x10 => "i8",
        0x11 => "u8",
        0x12 => "i16",
        0x13 => "u16",
        0x15 => "u32",
        0x16 => "i32",
        0x20 => "f16",
        0x21 => "f32",
        0x32 => "vec3",
        0x33 => "vec4",
        0x34 => "vec4",
        0x44 => "text",
        0x4a => "hash32",
        0x4d => "hash64",
        0x4f => "id",
        0x50 => "inline_array",
        0x52 => "array",
        0x5c => "array",
        0x60 => "enum8",
        0x62 => "enum32",
        0x65 => "bitset",
        0x71 => "map",
        0x75 => "map",
        _ => return None,
    })
}

pub(crate) fn field_json(field: &Field) -> Json {
    json!({
        "name": hash32(field.name),
        "offset": field.offset,
        "type": format!("0x{:04X}", field.code()),
        "upper": field.upper(),
        "typeName": type_name(field.code(), field.upper()),
        "auxiliary": hash32(field.auxiliary),
        "descriptor": field.is_descriptor(),
    })
}

pub(crate) fn structure_json(structure: &Structure, names: &Names) -> Json {
    json!({
        "name": hash32(structure.name),
        "nameCandidates": named(names, structure.name),
        "signature": hash32(structure.signature),
        "flags": hash32(structure.flags),
        "size": structure.size,
        "fields": structure.fields.iter().map(|field| {
            let mut value = field_json(field);
            value["nameCandidates"] = named(names, field.name);
            value["extent"] = json!(structure.extent(field));
            value
        }).collect::<Vec<Json>>(),
    })
}

pub(crate) fn target_json(target: &Target, names: &Names) -> Json {
    json!({
        "block": target.block,
        "record": target.record,
        "offset": target.offset,
        "structure": hash32(target.structure),
        "structureCandidates": named(names, target.structure),
    })
}

pub(crate) fn fault_text(fault: ReferenceFault) -> &'static str {
    match fault {
        ReferenceFault::BlockOutside => "block_outside",
        ReferenceFault::NoStructure => "no_structure",
        ReferenceFault::NotARecord => "not_a_record",
    }
}

pub(crate) fn reference_json(reference: &Reference, names: &Names) -> Json {
    if reference.is_null() {
        return json!({ "word": hash64(0), "null": true });
    }
    match (reference.target, reference.fault) {
        (Some(target), _) => json!({
            "word": hash64(reference.word),
            "target": target_json(&target, names),
        }),
        (None, Some(fault)) => json!({
            "word": hash64(reference.word),
            "fault": fault_text(fault),
            "reason": fault.text(),
        }),
        (None, None) => json!({ "word": hash64(reference.word) }),
    }
}

pub(crate) fn resolution_json(resolution: Resolution, word: u64) -> Json {
    match resolution {
        Resolution::Null => json!({ "word": hash64(word), "null": true }),
        Resolution::Located(location) => json!({
            "word": hash64(word),
            "block": location.block,
            "offset": location.offset,
            "blockLength": location.len,
        }),
        Resolution::Fault(fault) => json!({
            "word": hash64(word),
            "fault": fault_text(fault),
            "reason": fault.text(),
        }),
    }
}

pub(crate) fn enum_json(value: &EnumValueMatch, names: &Names) -> Json {
    json!({
        "kind": "enum",
        "value": value.value,
        "enumeration": hash32(value.enumeration),
        "enumerationCandidates": named(names, value.enumeration),
        "defined": value.defined,
        "matches": value.matches.iter().map(|member| json!({
            "value": member.value,
            "name": hash32(member.name),
            "nameCandidates": named(names, member.name),
        })).collect::<Vec<Json>>(),
    })
}

pub(crate) fn scalar_json(scalar: &Scalar, names: &Names) -> Json {
    let mut value = json!({
        "kind": "scalar",
        "type": scalar.type_name(),
    });
    match scalar {
        Scalar::Bool(inner) => value["value"] = json!(inner),
        Scalar::I8(inner) => value["value"] = json!(inner),
        Scalar::U8(inner) => value["value"] = json!(inner),
        Scalar::I16(inner) => value["value"] = json!(inner),
        Scalar::U16(inner) => value["value"] = json!(inner),
        Scalar::U32(inner) => value["value"] = json!(inner),
        Scalar::I32(inner) => value["value"] = json!(inner),
        Scalar::U64(inner) => value["value"] = json!(inner),
        Scalar::F16(inner) | Scalar::F32(inner) => value["value"] = json!(inner),
        Scalar::Hash32(inner) => {
            value["value"] = json!(hash32(*inner));
            value["valueCandidates"] = named(names, *inner);
        }
        Scalar::Hash64(inner) => value["value"] = json!(hash64(*inner)),
        Scalar::Vector { values, count } => {
            let shown: Vec<f32> = values[..usize::from(*count)].to_vec();
            value["value"] = json!(shown);
        }
    }
    value
}

pub(crate) fn scalar_text(scalar: &Scalar) -> String {
    match scalar {
        Scalar::Bool(inner) => inner.to_string(),
        Scalar::I8(inner) => inner.to_string(),
        Scalar::U8(inner) => inner.to_string(),
        Scalar::I16(inner) => inner.to_string(),
        Scalar::U16(inner) => inner.to_string(),
        Scalar::U32(inner) => inner.to_string(),
        Scalar::I32(inner) => inner.to_string(),
        Scalar::U64(inner) => inner.to_string(),
        Scalar::F16(inner) | Scalar::F32(inner) => inner.to_string(),
        Scalar::Hash32(inner) => hash32(*inner),
        Scalar::Hash64(inner) => hash64(*inner),
        Scalar::Vector { values, count } => values[..usize::from(*count)]
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(","),
    }
}

pub(crate) fn array_json(elements: &Result<ArrayElements, String>, names: &Names) -> Json {
    match elements {
        Err(reason) => json!({ "error": reason }),
        Ok(ArrayElements::Structure {
            structure,
            stride,
            links,
        }) => json!({
            "type": "structure",
            "structure": hash32(*structure),
            "structureCandidates": named(names, *structure),
            "stride": stride,
            "links": links.iter().map(|link| json!({
                "index": link.index,
                "block": link.target.block,
                "offset": link.target.offset,
                "record": link.target.record,
            })).collect::<Vec<Json>>(),
        }),
        Ok(ArrayElements::Reference { links }) => json!({
            "type": "reference",
            "links": links.iter().map(|reference| reference_json(reference, names)).collect::<Vec<Json>>(),
        }),
        Ok(ArrayElements::Records { records }) => json!({
            "type": "records",
            "records": records.iter().map(|record| record_json(record, names)).collect::<Vec<Json>>(),
        }),
        Ok(ArrayElements::Scalars { code, values }) => json!({
            "type": "scalars",
            "elementType": format!("0x{code:04X}"),
            "values": values.iter().map(|scalar| scalar_json(scalar, names)).collect::<Vec<Json>>(),
        }),
        Ok(ArrayElements::Hash32 { values }) => json!({
            "type": "hash32",
            "values": values.iter().map(|value| json!({
                "value": hash32(*value),
                "candidates": named(names, *value),
            })).collect::<Vec<Json>>(),
        }),
        Ok(ArrayElements::Enum32 {
            enumeration,
            values,
        }) => json!({
            "type": "enum32",
            "enumeration": hash32(*enumeration),
            "enumerationCandidates": named(names, *enumeration),
            "values": values,
        }),
    }
}

pub(crate) fn value_json(value: &Value, names: &Names) -> Json {
    match value {
        Value::Scalar(scalar) => scalar_json(scalar, names),
        Value::Enum(inner) => enum_json(inner, names),
        Value::Structure(record) => {
            let mut document = record_json(record, names);
            document["kind"] = json!("structure");
            document
        }
        Value::Reference(reference) => {
            let mut document = reference_json(reference, names);
            document["kind"] = json!("reference");
            document
        }
        Value::Array(array) => json!({
            "kind": "array",
            "descriptor": array.descriptor,
            "count": array.span.count,
            "capacity": array.span.capacity,
            "tail": array.span.tail,
            "reference": resolution_json(array.span.resolution, array.span.word),
            "elements": array_json(&array.elements, names),
        }),
        Value::Map(map) => json!({
            "kind": "map",
            "keyDescriptor": map.key_descriptor,
            "valueDescriptor": map.value_descriptor,
            "count": map.span.count,
            "capacity": map.span.capacity,
            "tail": map.span.tail,
            "reference": resolution_json(map.span.resolution, map.span.word),
            "entries": match &map.entries {
                Err(reason) => json!({ "error": reason }),
                Ok((structure, records)) => json!({
                    "structure": hash32(*structure),
                    "structureCandidates": named(names, *structure),
                    "records": records.iter().map(|record| record_json(record, names)).collect::<Vec<Json>>(),
                }),
            },
        }),
        Value::Bitset(bitset) => json!({
            "kind": "bitset",
            "bits": hash64(bitset.bits),
            "bitCount": bitset.bit_count,
            "enumeration": hash32(bitset.enumeration),
            "enumerationCandidates": named(names, bitset.enumeration),
        }),
        Value::Text(text) => {
            let mut document = json!({
                "kind": "text",
                "word": hash64(text.word),
                "reference": resolution_json(text.resolution, text.word),
            });
            match &text.text {
                Ok(value) => document["text"] = json!(value),
                Err(reason) => {
                    document["text"] = Json::Null;
                    document["note"] = json!(reason);
                }
            }
            document
        }
        Value::TextSlot { raw } => json!({
            "kind": "text_slot",
            "bytes": bytes_hex(raw),
            "note": "16 bytes whose text storage is not established",
        }),
        Value::Descriptor {
            code,
            upper,
            auxiliary,
        } => json!({
            "kind": "descriptor",
            "type": format!("0x{code:04X}"),
            "upper": upper,
            "typeName": type_name(*code, *upper),
            "auxiliary": hash32(*auxiliary),
            "note": "array or map element descriptor; no storage",
        }),
        Value::Unresolved {
            code,
            upper,
            auxiliary,
            raw,
        } => json!({
            "kind": "unresolved",
            "type": format!("0x{code:04X}"),
            "upper": upper,
            "typeName": type_name(*code, *upper),
            "auxiliary": hash32(*auxiliary),
            "bytes": bytes_hex(raw),
            "note": "the type has no established width; the bytes of its extent are kept",
        }),
    }
}

pub(crate) fn record_json(record: &Record, names: &Names) -> Json {
    json!({
        "offset": record.offset,
        "structure": hash32(record.structure),
        "fields": record.fields.iter().map(|field_value| {
            let mut document = field_json(&field_value.field);
            document["nameCandidates"] = named(names, field_value.field.name);
            document["extent"] = json!(field_value.extent);
            document["value"] = value_json(&field_value.value, names);
            document
        }).collect::<Vec<Json>>(),
    })
}

pub(crate) fn entries_json(entries: &[PoolEntry], names: &Names) -> Vec<Json> {
    entries
        .iter()
        .map(|entry| match entry {
            PoolEntry::Text(text) => json!(text),
            PoolEntry::Bytes(bytes) => json!({ "bytes": bytes_hex(bytes) }),
            PoolEntry::Hash32(value) => json!({
                "value": hash32(*value),
                "candidates": named(names, *value),
            }),
            PoolEntry::Reference(word) => json!(hash64(*word)),
            PoolEntry::Word32(word) => json!(format!("0x{word:08X}")),
            PoolEntry::Word64(word) => json!(hash64(*word)),
            PoolEntry::Word128(bytes) => json!(bytes_hex(bytes)),
        })
        .collect()
}

fn block_json(block: &lforge_rage9::psin::pso::Block, names: &Names, full: bool) -> Json {
    let mut document = json!({
        "index": block.index,
        "type": hash32(block.id),
        "typeCandidates": named(names, block.id),
        "offset": block.offset,
        "length": block.len,
    });
    match &block.content {
        Content::Records {
            structure,
            stride,
            total,
            records,
        } => {
            document["kind"] = json!("records");
            document["structure"] = json!(hash32(*structure));
            document["structureCandidates"] = named(names, *structure);
            document["stride"] = json!(stride);
            document["total"] = json!(total);
            document["decoded"] = json!(records.len());
            if full {
                document["records"] = json!(
                    records
                        .iter()
                        .map(|record| record_json(record, names))
                        .collect::<Vec<Json>>()
                );
            }
        }
        Content::Pool {
            kind,
            total,
            entries,
        } => {
            document["kind"] = json!("pool");
            document["pool"] = json!(kind.name());
            document["total"] = json!(total);
            document["decoded"] = json!(entries.len());
            if full {
                document["entries"] = json!(entries_json(entries, names));
            }
        }
        Content::Elements {
            code,
            width,
            total,
            entries,
        } => {
            document["kind"] = json!("elements");
            document["elementType"] = json!(format!("0x{code:04X}"));
            document["width"] = json!(width);
            document["total"] = json!(total);
            document["decoded"] = json!(entries.len());
            if full {
                document["entries"] = json!(
                    entries
                        .iter()
                        .map(|scalar| scalar_json(scalar, names))
                        .collect::<Vec<Json>>()
                );
            }
        }
        Content::Unsupported(reason) => {
            document["kind"] = json!("unsupported");
            document["reason"] = json!(reason);
        }
    }
    document
}

/// The decoded container as a JSON document.
pub fn document_json(document: &Document, names: &Names, sample: usize) -> Json {
    let counts = counts(document);
    let complete = counts.records_decoded == counts.records
        && counts.unsupported_blocks == 0
        && counts.header_matches != Some(false);
    let structures: Vec<Json> = document
        .structures
        .iter()
        .map(|structure| structure_json(structure, names))
        .collect();
    let enums: Vec<Json> = document
        .enums
        .iter()
        .map(|enumeration| {
            json!({
                "name": hash32(enumeration.name),
                "nameCandidates": named(names, enumeration.name),
                "signature": hash32(enumeration.signature),
                "values": enumeration.values.iter().map(|value| json!({
                    "value": value.value,
                    "name": hash32(value.name),
                    "nameCandidates": named(names, value.name),
                })).collect::<Vec<Json>>(),
            })
        })
        .collect();
    let blocks: Vec<Json> = document
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| block_json(block, names, index < sample))
        .collect();
    let roots: Vec<Json> = document
        .roots()
        .iter()
        .map(|name| {
            json!({
                "structure": hash32(*name),
                "structureCandidates": named(names, *name),
            })
        })
        .collect();
    json!({
        "format": "pso",
        "status": if complete { "decoded" } else { "partial" },
        "header": document.header.map(|header| json!({
            "objectType": header.object_type,
            "roots": header.roots,
            "structures": header.structures,
            "enums": header.enums,
            "blocks": header.blocks,
            "countsMatch": document.header_matches(),
        })),
        "counts": {
            "structures": counts.structures,
            "fields": counts.fields,
            "enums": counts.enums,
            "enumValues": counts.enum_values,
            "blocks": counts.blocks,
            "structureBlocks": counts.structure_blocks,
            "poolBlocks": counts.pool_blocks,
            "unsupportedBlocks": counts.unsupported_blocks,
            "records": counts.records,
            "recordsDecoded": counts.records_decoded,
            "roots": counts.roots,
            "distinctRootStructures": roots.len(),
        },
        "rootStructures": roots,
        "structures": structures,
        "enums": enums,
        "blocks": blocks,
        "issues": document.issues,
        "names": {
            "indexed": names.len(),
            "note": "candidates come from the caller's name table; the stored hash stays the identity",
        },
        "limitations": [
            "a structure name stays the 32-bit hash the schema stores; no name replaces it",
            "a field whose type has no established width keeps its type word and bytes",
            "an enumeration member is matched by value; the table does not establish signedness",
            "array and map length and capacity are reported separately, as stored",
        ],
    })
}

pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

pub(crate) fn attribute(out: &mut String, name: &str, value: impl std::fmt::Display) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    out.push_str(&escape(&value.to_string()));
    out.push('"');
}

pub(crate) fn open(out: &mut String, tag: &str, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
    out.push('<');
    out.push_str(tag);
}

pub(crate) fn close(out: &mut String, tag: &str, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
    out.push_str("</");
    out.push_str(tag);
    out.push_str(">\n");
}

pub(crate) fn field_attributes(document: &mut String, field: &Field) {
    attribute(document, "name", hash32(field.name));
    attribute(document, "offset", field.offset);
    attribute(document, "type", format!("0x{:04X}", field.code()));
    if field.upper() != 0 {
        attribute(document, "upper", field.upper());
    }
    if let Some(name) = type_name(field.code(), field.upper()) {
        attribute(document, "typeName", name);
    }
    if field.auxiliary != 0 {
        attribute(document, "auxiliary", hash32(field.auxiliary));
    }
}

pub(crate) fn array_attributes(document: &mut String, array: &lforge_rage9::psin::pso::ArrayValue) {
    attribute(document, "descriptor", array.descriptor);
    attribute(document, "count", array.span.count);
    attribute(document, "capacity", array.span.capacity);
    if array.span.tail != 0 {
        attribute(document, "tail", array.span.tail);
    }
    attribute(document, "word", hash64(array.span.word));
    if let Resolution::Located(location) = array.span.resolution {
        attribute(document, "block", location.block);
        attribute(document, "blockOffset", location.offset);
    }
    if let Resolution::Fault(fault) = array.span.resolution {
        attribute(document, "fault", fault_text(fault));
    }
}

pub(crate) fn value_xml(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Scalar(scalar) => {
            open(out, "value", depth);
            attribute(out, "kind", "scalar");
            attribute(out, "type", scalar.type_name());
            match scalar {
                Scalar::Bool(inner) => attribute(out, "text", inner),
                Scalar::I8(inner) => attribute(out, "text", inner),
                Scalar::U8(inner) => attribute(out, "text", inner),
                Scalar::I16(inner) => attribute(out, "text", inner),
                Scalar::U16(inner) => attribute(out, "text", inner),
                Scalar::U32(inner) => attribute(out, "text", inner),
                Scalar::I32(inner) => attribute(out, "text", inner),
                Scalar::U64(inner) => attribute(out, "text", inner),
                Scalar::F16(inner) | Scalar::F32(inner) => attribute(out, "text", inner),
                Scalar::Hash32(inner) => attribute(out, "hash", hash32(*inner)),
                Scalar::Hash64(inner) => attribute(out, "hash", hash64(*inner)),
                Scalar::Vector { values, count } => {
                    let parts: Vec<String> = values[..usize::from(*count)]
                        .iter()
                        .map(ToString::to_string)
                        .collect();
                    attribute(out, "components", parts.join(","));
                }
            }
            out.push_str("/>\n");
        }
        Value::Enum(inner) => {
            open(out, "value", depth);
            attribute(out, "kind", "enum");
            attribute(out, "value", inner.value);
            attribute(out, "enumeration", hash32(inner.enumeration));
            attribute(out, "defined", inner.defined);
            if inner.matches.is_empty() {
                out.push_str("/>\n");
                return;
            }
            out.push_str(">\n");
            for member in &inner.matches {
                open(out, "member", depth + 1);
                attribute(out, "value", member.value);
                attribute(out, "name", hash32(member.name));
                out.push_str("/>\n");
            }
            close(out, "value", depth);
        }
        Value::Structure(record) => {
            open(out, "value", depth);
            attribute(out, "kind", "structure");
            attribute(out, "structure", hash32(record.structure));
            attribute(out, "offset", record.offset);
            out.push_str(">\n");
            for field_value in &record.fields {
                open(out, "field", depth + 1);
                field_attributes(out, &field_value.field);
                out.push_str(">\n");
                value_xml(out, &field_value.value, depth + 2);
                close(out, "field", depth + 1);
            }
            close(out, "value", depth);
        }
        Value::Reference(reference) => {
            open(out, "value", depth);
            attribute(out, "kind", "reference");
            attribute(out, "word", hash64(reference.word));
            match (reference.target, reference.fault) {
                (Some(target), _) => {
                    attribute(out, "block", target.block);
                    attribute(out, "record", target.record);
                    attribute(out, "blockOffset", target.offset);
                    attribute(out, "structure", hash32(target.structure));
                }
                (None, Some(fault)) => attribute(out, "fault", fault_text(fault)),
                (None, None) => attribute(out, "null", true),
            }
            out.push_str("/>\n");
        }
        Value::Array(array) => {
            open(out, "value", depth);
            attribute(out, "kind", "array");
            array_attributes(out, array);
            out.push_str(">\n");
            match &array.elements {
                Err(reason) => {
                    open(out, "error", depth + 1);
                    out.push('>');
                    out.push_str(&escape(reason));
                    out.push_str("</error>\n");
                }
                Ok(ArrayElements::Hash32 { values }) => {
                    for value in values {
                        open(out, "element", depth + 1);
                        attribute(out, "hash", hash32(*value));
                        out.push_str("/>\n");
                    }
                }
                Ok(ArrayElements::Enum32 { values, .. }) => {
                    for value in values {
                        open(out, "element", depth + 1);
                        attribute(out, "value", value);
                        out.push_str("/>\n");
                    }
                }
                Ok(ArrayElements::Structure { links, .. }) => {
                    for link in links {
                        open(out, "element", depth + 1);
                        attribute(out, "index", link.index);
                        attribute(out, "block", link.target.block);
                        attribute(out, "record", link.target.record);
                        attribute(out, "blockOffset", link.target.offset);
                        out.push_str("/>\n");
                    }
                }
                Ok(ArrayElements::Reference { links }) => {
                    for reference in links {
                        open(out, "element", depth + 1);
                        attribute(out, "word", hash64(reference.word));
                        match (reference.target, reference.fault) {
                            (Some(target), _) => {
                                attribute(out, "block", target.block);
                                attribute(out, "record", target.record);
                                attribute(out, "structure", hash32(target.structure));
                            }
                            (None, Some(fault)) => attribute(out, "fault", fault_text(fault)),
                            (None, None) => attribute(out, "null", true),
                        }
                        out.push_str("/>\n");
                    }
                }
                Ok(ArrayElements::Records { records }) => {
                    for record in records {
                        record_xml(out, record, depth + 1);
                    }
                }
                Ok(ArrayElements::Scalars { code, values }) => {
                    for value in values {
                        open(out, "element", depth + 1);
                        attribute(out, "type", format!("0x{code:04X}"));
                        attribute(out, "typeName", value.type_name());
                        attribute(out, "text", scalar_text(value));
                        out.push_str("/>\n");
                    }
                }
            }
            close(out, "value", depth);
        }
        Value::Map(map) => {
            open(out, "value", depth);
            attribute(out, "kind", "map");
            attribute(out, "keyDescriptor", map.key_descriptor);
            attribute(out, "valueDescriptor", map.value_descriptor);
            attribute(out, "count", map.span.count);
            attribute(out, "capacity", map.span.capacity);
            attribute(out, "word", hash64(map.span.word));
            match &map.entries {
                Err(reason) => {
                    attribute(out, "error", reason.clone());
                    out.push_str("/>\n");
                }
                Ok((structure, records)) => {
                    attribute(out, "structure", hash32(*structure));
                    out.push_str(">\n");
                    for record in records {
                        open(out, "record", depth + 1);
                        attribute(out, "offset", record.offset);
                        out.push_str(">\n");
                        for field_value in &record.fields {
                            open(out, "field", depth + 2);
                            field_attributes(out, &field_value.field);
                            out.push_str(">\n");
                            value_xml(out, &field_value.value, depth + 3);
                            close(out, "field", depth + 2);
                        }
                        close(out, "record", depth + 1);
                    }
                    close(out, "value", depth);
                }
            }
        }
        Value::Bitset(bitset) => {
            open(out, "value", depth);
            attribute(out, "kind", "bitset");
            attribute(out, "bits", hash64(bitset.bits));
            if let Some(count) = bitset.bit_count {
                attribute(out, "bitCount", count);
            }
            attribute(out, "enumeration", hash32(bitset.enumeration));
            out.push_str("/>\n");
        }
        Value::TextSlot { raw } => {
            open(out, "value", depth);
            attribute(out, "kind", "text_slot");
            attribute(out, "bytes", bytes_hex(raw));
            out.push_str("/>\n");
        }
        Value::Text(text) => {
            open(out, "value", depth);
            attribute(out, "kind", "text");
            attribute(out, "word", hash64(text.word));
            if let Resolution::Located(location) = text.resolution {
                attribute(out, "block", location.block);
                attribute(out, "blockOffset", location.offset);
            }
            if let Resolution::Fault(fault) = text.resolution {
                attribute(out, "fault", fault_text(fault));
            }
            match &text.text {
                Ok(value) => attribute(out, "text", value),
                Err(reason) => attribute(out, "note", reason),
            }
            out.push_str("/>\n");
        }
        Value::Descriptor {
            code,
            upper,
            auxiliary,
        } => {
            open(out, "value", depth);
            attribute(out, "kind", "descriptor");
            attribute(out, "type", format!("0x{code:04X}"));
            if *upper != 0 {
                attribute(out, "upper", upper);
            }
            attribute(out, "auxiliary", hash32(*auxiliary));
            out.push_str("/>\n");
        }
        Value::Unresolved {
            code,
            upper,
            auxiliary,
            raw,
        } => {
            open(out, "value", depth);
            attribute(out, "kind", "unresolved");
            attribute(out, "type", format!("0x{code:04X}"));
            if *upper != 0 {
                attribute(out, "upper", upper);
            }
            attribute(out, "auxiliary", hash32(*auxiliary));
            attribute(out, "bytes", bytes_hex(raw));
            out.push_str("/>\n");
        }
    }
}

pub(crate) fn record_xml(out: &mut String, record: &Record, depth: usize) {
    open(out, "record", depth);
    attribute(out, "offset", record.offset);
    attribute(out, "structure", hash32(record.structure));
    out.push_str(">\n");
    for field_value in &record.fields {
        open(out, "field", depth + 1);
        field_attributes(out, &field_value.field);
        if let Some(extent) = field_value.extent {
            attribute(out, "extent", extent);
        }
        out.push_str(">\n");
        value_xml(out, &field_value.value, depth + 2);
        close(out, "field", depth + 1);
    }
    close(out, "record", depth);
}

/// The decoded container as an XML document.
///
/// Every element name is a fixed word from this module; the schema's own names
/// are attributes, because they are hashes and not always valid element names.
/// `source` becomes a `source` element holding where the bytes came from.
pub fn document_xml(document: &Document, sample: usize, source: &[(&str, String)]) -> String {
    let counts = counts(document);
    let complete = counts.records_decoded == counts.records
        && counts.unsupported_blocks == 0
        && counts.header_matches != Some(false);
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    open(&mut out, "meta", 0);
    attribute(&mut out, "format", "pso");
    attribute(
        &mut out,
        "status",
        if complete { "decoded" } else { "partial" },
    );
    attribute(&mut out, "structures", counts.structures);
    attribute(&mut out, "enums", counts.enums);
    attribute(&mut out, "blocks", counts.blocks);
    attribute(&mut out, "records", counts.records);
    out.push_str(">\n");
    if !source.is_empty() {
        open(&mut out, "source", 1);
        for (name, value) in source {
            attribute(&mut out, name, value.clone());
        }
        out.push_str("/>\n");
    }

    if let Some(header) = document.header {
        open(&mut out, "header", 1);
        attribute(&mut out, "objectType", header.object_type);
        attribute(&mut out, "roots", header.roots);
        attribute(&mut out, "structures", header.structures);
        attribute(&mut out, "enums", header.enums);
        attribute(&mut out, "blocks", header.blocks);
        attribute(
            &mut out,
            "countsMatch",
            document.header_matches() == Some(true),
        );
        out.push_str("/>\n");
    }

    for structure in &document.structures {
        open(&mut out, "structure", 1);
        attribute(&mut out, "name", hash32(structure.name));
        attribute(&mut out, "signature", hash32(structure.signature));
        attribute(&mut out, "flags", hash32(structure.flags));
        attribute(&mut out, "size", structure.size);
        out.push_str(">\n");
        for field in &structure.fields {
            open(&mut out, "field", 2);
            field_attributes(&mut out, field);
            if let Some(extent) = structure.extent(field) {
                attribute(&mut out, "extent", extent);
            }
            out.push_str("/>\n");
        }
        close(&mut out, "structure", 1);
    }

    for enumeration in &document.enums {
        open(&mut out, "enum", 1);
        attribute(&mut out, "name", hash32(enumeration.name));
        attribute(&mut out, "signature", hash32(enumeration.signature));
        out.push_str(">\n");
        for value in &enumeration.values {
            open(&mut out, "member", 2);
            attribute(&mut out, "value", value.value);
            attribute(&mut out, "name", hash32(value.name));
            out.push_str("/>\n");
        }
        close(&mut out, "enum", 1);
    }

    for (index, block) in document.blocks.iter().enumerate() {
        open(&mut out, "block", 1);
        attribute(&mut out, "index", block.index);
        attribute(&mut out, "type", hash32(block.id));
        attribute(&mut out, "offset", block.offset);
        attribute(&mut out, "length", block.len);
        match &block.content {
            Content::Records {
                structure,
                stride,
                total,
                records,
            } => {
                attribute(&mut out, "kind", "records");
                attribute(&mut out, "structure", hash32(*structure));
                attribute(&mut out, "stride", stride);
                attribute(&mut out, "total", total);
                attribute(&mut out, "decoded", records.len());
                if index < sample && !records.is_empty() {
                    out.push_str(">\n");
                    for record in records {
                        record_xml(&mut out, record, 2);
                    }
                    close(&mut out, "block", 1);
                } else {
                    out.push_str("/>\n");
                }
            }
            Content::Pool {
                kind,
                total,
                entries,
            } => {
                attribute(&mut out, "kind", "pool");
                attribute(&mut out, "pool", kind.name());
                attribute(&mut out, "total", total);
                attribute(&mut out, "decoded", entries.len());
                if index < sample && !entries.is_empty() {
                    out.push_str(">\n");
                    for entry in entries {
                        open(&mut out, "entry", 2);
                        match entry {
                            PoolEntry::Text(text) => attribute(&mut out, "text", text.clone()),
                            PoolEntry::Bytes(bytes) => {
                                attribute(&mut out, "bytes", bytes_hex(bytes));
                            }
                            PoolEntry::Hash32(value) => attribute(&mut out, "hash", hash32(*value)),
                            PoolEntry::Reference(word) => {
                                attribute(&mut out, "word", hash64(*word));
                            }
                            PoolEntry::Word32(word) => {
                                attribute(&mut out, "word", format!("0x{word:08X}"));
                            }
                            PoolEntry::Word64(word) => attribute(&mut out, "word", hash64(*word)),
                            PoolEntry::Word128(bytes) => {
                                attribute(&mut out, "bytes", bytes_hex(bytes));
                            }
                        }
                        out.push_str("/>\n");
                    }
                    close(&mut out, "block", 1);
                } else {
                    out.push_str("/>\n");
                }
            }
            Content::Elements {
                code,
                width,
                total,
                entries,
            } => {
                attribute(&mut out, "kind", "elements");
                attribute(&mut out, "type", format!("0x{code:04X}"));
                attribute(&mut out, "width", width);
                attribute(&mut out, "total", total);
                attribute(&mut out, "decoded", entries.len());
                if index < sample && !entries.is_empty() {
                    out.push_str(">\n");
                    for entry in entries {
                        open(&mut out, "entry", 2);
                        attribute(&mut out, "type", entry.type_name());
                        attribute(&mut out, "text", scalar_text(entry));
                        out.push_str("/>\n");
                    }
                    close(&mut out, "block", 1);
                } else {
                    out.push_str("/>\n");
                }
            }
            Content::Unsupported(reason) => {
                attribute(&mut out, "kind", "unsupported");
                attribute(&mut out, "reason", reason.clone());
                out.push_str("/>\n");
            }
        }
    }

    for issue in &document.issues {
        open(&mut out, "issue", 1);
        out.push('>');
        out.push_str(&escape(issue));
        out.push_str("</issue>\n");
    }
    close(&mut out, "meta", 0);
    out
}

/// A JSON object of nothing but the counts, for a summary.
pub fn counts_json(document: &Document) -> Json {
    let counts = counts(document);
    let mut object = Map::new();
    object.insert("structures".into(), json!(counts.structures));
    object.insert("fields".into(), json!(counts.fields));
    object.insert("enums".into(), json!(counts.enums));
    object.insert("blocks".into(), json!(counts.blocks));
    object.insert("records".into(), json!(counts.records));
    object.insert("recordsDecoded".into(), json!(counts.records_decoded));
    object.insert("roots".into(), json!(counts.roots));
    object.insert("unsupportedBlocks".into(), json!(counts.unsupported_blocks));
    object.insert("headerMatches".into(), json!(counts.header_matches));
    Json::Object(object)
}

#[cfg(test)]
mod tests;
