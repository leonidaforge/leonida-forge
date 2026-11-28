//! JSON, XML and counts for a decoded `0DRP` metadata resource.
//!
//! The values, records, structures and enumerations serialize with the same
//! functions a `PSIN` container uses, because they are the same decoded types.
//! What differs is the document around them: a resource has two segments, block
//! lengths and segment offsets instead of container offsets, and root blocks
//! instead of root structures.

use lforge_rage9::odrp::{Block, Document};
use lforge_rage9::psin::pso::{Content, PoolEntry};
use lforge_rage9::resource::Segment;
use serde_json::{Value as Json, json};

use crate::pso::{
    attribute, bytes_hex, close, entries_json, fault_text, hash32, hash64, named, open,
    record_json, record_xml, resolution_json, scalar_json, scalar_text, structure_json, type_name,
};

/// What the document holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub structures: usize,
    pub fields: usize,
    pub enums: usize,
    pub enum_values: usize,
    pub blocks: usize,
    pub structure_blocks: usize,
    pub pool_blocks: usize,
    pub element_blocks: usize,
    pub unsupported_blocks: usize,
    pub records: usize,
    pub records_decoded: usize,
    pub roots: usize,
    pub texts: usize,
    pub depth: usize,
    pub unresolved_references: u32,
    pub issues: usize,
}

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
        roots: document.roots.len(),
        texts: document.text_count(),
        depth: document.depth(),
        unresolved_references: document.unresolved_references,
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
                counts.element_blocks += 1;
                counts.records += *total as usize;
                counts.records_decoded += entries.len();
            }
            Content::Unsupported(_) => counts.unsupported_blocks += 1,
        }
    }
    counts
}

fn segment_name(segment: Segment) -> &'static str {
    match segment {
        Segment::System => "system",
        Segment::Graphics => "graphics",
    }
}

fn block_json(block: &Block, names: &lforge_rage9::psin::pso::names::Names, full: bool) -> Json {
    let mut document = json!({
        "index": block.index,
        "type": hash32(block.id),
        "typeCandidates": named(names, block.id),
        "segment": segment_name(block.segment),
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

/// The decoded resource as JSON. `names` may resolve a stored hash; the hash
/// stays the identity and the name is added beside it.
pub fn document_json(
    document: &Document,
    names: &lforge_rage9::psin::pso::names::Names,
    sample: usize,
) -> Json {
    let counts = counts(document);
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
        .roots
        .iter()
        .filter_map(|number| {
            let block = document
                .blocks
                .iter()
                .find(|block| block.index == *number)?;
            Some(json!({
                "block": block.index,
                "type": hash32(block.id),
                "typeCandidates": named(names, block.id),
                "records": match &block.content {
                    Content::Records { records, .. } => records.len(),
                    _ => 0,
                },
            }))
        })
        .collect();
    json!({
        "format": "0drp",
        "status": document.status(),
        "header": {
            "objectType": document.header.object_type,
            "rootBlock": document.header.root_block,
            "structures": document.header.structures,
            "enums": document.header.enums,
            "blocks": document.header.blocks,
            "unknownWord": document.header.unknown,
            "pageMap": document.header.page_map,
            "systemPages": document.header.system_pages,
            "graphicsPages": document.header.graphics_pages,
            "extraPointer": document.header.extra_pointer,
        },
        "counts": {
            "structures": counts.structures,
            "fields": counts.fields,
            "enums": counts.enums,
            "enumValues": counts.enum_values,
            "blocks": counts.blocks,
            "structureBlocks": counts.structure_blocks,
            "poolBlocks": counts.pool_blocks,
            "elementBlocks": counts.element_blocks,
            "unsupportedBlocks": counts.unsupported_blocks,
            "records": counts.records,
            "recordsDecoded": counts.records_decoded,
            "roots": counts.roots,
            "texts": counts.texts,
            "depth": counts.depth,
            "unresolvedReferences": counts.unresolved_references,
        },
        "roots": roots,
        "structures": structures,
        "enums": enums,
        "blocks": blocks,
        "issues": document.issues,
        "names": {
            "indexed": names.len(),
            "note": "candidates come from the caller's name table; the stored hash stays the identity",
        },
        "limitations": [
            "a structure or field name stays the 32-bit hash the schema stores; no name replaces it",
            "a block's type word is reported as stored; a type whose element width is not established keeps its bytes",
            "a map's two words are the number of bucket records and the number of entries they hold",
            "the pointer at +0x40 is reported as stored; no meaning is established for it",
            "the roots are derived from the decoded references, not stored as a list",
        ],
    })
}

/// The decoded resource as XML, with `source` naming where the bytes came from.
pub fn document_xml(document: &Document, sample: usize, source: &[(&str, String)]) -> String {
    let counts = counts(document);
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    open(&mut out, "document", 0);
    attribute(&mut out, "format", "0drp");
    attribute(&mut out, "status", document.status());
    attribute(&mut out, "generator", "leonida-forge");
    attribute(&mut out, "schema", crate::metadata::ODRP_SCHEMA);
    out.push_str(">\n");

    open(&mut out, "source", 1);
    for (key, value) in source {
        attribute(&mut out, key, value.clone());
    }
    out.push_str("/>\n");

    open(&mut out, "header", 1);
    attribute(&mut out, "objectType", document.header.object_type);
    attribute(&mut out, "rootBlock", document.header.root_block);
    attribute(&mut out, "structures", document.header.structures);
    attribute(&mut out, "enums", document.header.enums);
    attribute(&mut out, "blocks", document.header.blocks);
    attribute(&mut out, "unknownWord", document.header.unknown);
    attribute(&mut out, "pageMap", document.header.page_map);
    attribute(&mut out, "systemPages", document.header.system_pages);
    attribute(&mut out, "graphicsPages", document.header.graphics_pages);
    if let Some(pointer) = document.header.extra_pointer {
        attribute(&mut out, "extraPointer", pointer);
    }
    out.push_str("/>\n");

    open(&mut out, "counts", 1);
    attribute(&mut out, "structures", counts.structures);
    attribute(&mut out, "fields", counts.fields);
    attribute(&mut out, "enums", counts.enums);
    attribute(&mut out, "enumValues", counts.enum_values);
    attribute(&mut out, "blocks", counts.blocks);
    attribute(&mut out, "structureBlocks", counts.structure_blocks);
    attribute(&mut out, "poolBlocks", counts.pool_blocks);
    attribute(&mut out, "elementBlocks", counts.element_blocks);
    attribute(&mut out, "unsupportedBlocks", counts.unsupported_blocks);
    attribute(&mut out, "records", counts.records);
    attribute(&mut out, "recordsDecoded", counts.records_decoded);
    attribute(&mut out, "roots", counts.roots);
    attribute(&mut out, "texts", counts.texts);
    attribute(&mut out, "depth", counts.depth);
    attribute(
        &mut out,
        "unresolvedReferences",
        counts.unresolved_references,
    );
    out.push_str("/>\n");

    open(&mut out, "roots", 1);
    if document.roots.is_empty() {
        out.push_str("/>\n");
    } else {
        out.push_str(">\n");
        for number in &document.roots {
            let Some(block) = document.blocks.iter().find(|block| block.index == *number) else {
                continue;
            };
            open(&mut out, "root", 2);
            attribute(&mut out, "block", block.index);
            attribute(&mut out, "type", hash32(block.id));
            out.push_str("/>\n");
        }
        close(&mut out, "roots", 1);
    }

    open(&mut out, "structures", 1);
    if document.structures.is_empty() {
        out.push_str("/>\n");
    } else {
        out.push_str(">\n");
        for structure in &document.structures {
            open(&mut out, "structure", 2);
            attribute(&mut out, "name", hash32(structure.name));
            attribute(&mut out, "signature", hash32(structure.signature));
            attribute(&mut out, "flags", hash32(structure.flags));
            attribute(&mut out, "size", structure.size);
            out.push_str(">\n");
            for field in &structure.fields {
                open(&mut out, "field", 3);
                attribute(&mut out, "name", hash32(field.name));
                attribute(&mut out, "offset", field.offset);
                attribute(&mut out, "type", format!("0x{:04X}", field.code()));
                if let Some(name) = type_name(field.code(), field.upper()) {
                    attribute(&mut out, "typeName", name);
                }
                attribute(&mut out, "auxiliary", hash32(field.auxiliary));
                out.push_str("/>\n");
            }
            close(&mut out, "structure", 2);
        }
        close(&mut out, "structures", 1);
    }

    open(&mut out, "enums", 1);
    if document.enums.is_empty() {
        out.push_str("/>\n");
    } else {
        out.push_str(">\n");
        for enumeration in &document.enums {
            open(&mut out, "enum", 2);
            attribute(&mut out, "name", hash32(enumeration.name));
            attribute(&mut out, "signature", hash32(enumeration.signature));
            out.push_str(">\n");
            for value in &enumeration.values {
                open(&mut out, "member", 3);
                attribute(&mut out, "value", value.value);
                attribute(&mut out, "name", hash32(value.name));
                out.push_str("/>\n");
            }
            close(&mut out, "enum", 2);
        }
        close(&mut out, "enums", 1);
    }

    open(&mut out, "blocks", 1);
    if document.blocks.is_empty() {
        out.push_str("/>\n");
    } else {
        out.push_str(">\n");
        for (index, block) in document.blocks.iter().enumerate() {
            open(&mut out, "block", 2);
            attribute(&mut out, "index", block.index);
            attribute(&mut out, "type", hash32(block.id));
            attribute(&mut out, "segment", segment_name(block.segment));
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
                            record_xml(&mut out, record, 3);
                        }
                        close(&mut out, "block", 2);
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
                            open(&mut out, "entry", 3);
                            match entry {
                                PoolEntry::Text(text) => attribute(&mut out, "text", text.clone()),
                                PoolEntry::Bytes(bytes) => {
                                    attribute(&mut out, "bytes", bytes_hex(bytes));
                                }
                                PoolEntry::Hash32(value) => {
                                    attribute(&mut out, "hash", hash32(*value));
                                }
                                PoolEntry::Reference(word) => {
                                    attribute(&mut out, "word", hash64(*word));
                                }
                                PoolEntry::Word32(word) => {
                                    attribute(&mut out, "word", format!("0x{word:08X}"));
                                }
                                PoolEntry::Word64(word) => {
                                    attribute(&mut out, "word", hash64(*word));
                                }
                                PoolEntry::Word128(bytes) => {
                                    attribute(&mut out, "bytes", bytes_hex(bytes));
                                }
                            }
                            out.push_str("/>\n");
                        }
                        close(&mut out, "block", 2);
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
                            open(&mut out, "entry", 3);
                            attribute(&mut out, "type", entry.type_name());
                            attribute(&mut out, "text", scalar_text(entry));
                            out.push_str("/>\n");
                        }
                        close(&mut out, "block", 2);
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
        close(&mut out, "blocks", 1);
    }

    for issue in &document.issues {
        open(&mut out, "issue", 1);
        out.push('>');
        out.push_str(&crate::pso::escape(issue));
        out.push_str("</issue>\n");
    }
    close(&mut out, "document", 0);
    out
}

/// A JSON object of nothing but the counts, for a summary.
pub fn counts_json(document: &Document) -> Json {
    let counts = counts(document);
    json!({
        "format": "0drp",
        "structures": counts.structures,
        "fields": counts.fields,
        "enums": counts.enums,
        "enumValues": counts.enum_values,
        "blocks": counts.blocks,
        "structureBlocks": counts.structure_blocks,
        "poolBlocks": counts.pool_blocks,
        "elementBlocks": counts.element_blocks,
        "unsupportedBlocks": counts.unsupported_blocks,
        "records": counts.records,
        "recordsDecoded": counts.records_decoded,
        "roots": counts.roots,
        "texts": counts.texts,
        "depth": counts.depth,
        "unresolvedReferences": counts.unresolved_references,
    })
}

/// The unresolved values of a block, by type code, for a survey of what the
/// decoder does not read. Only the type words are counted; no value is kept.
pub fn unresolved_types(document: &Document) -> std::collections::BTreeMap<u16, usize> {
    let mut types = std::collections::BTreeMap::new();
    for block in &document.blocks {
        if let Content::Records { records, .. } = &block.content {
            for record in records {
                for value in &record.fields {
                    let lforge_rage9::psin::pso::Value::Unresolved { code, .. } = &value.value
                    else {
                        continue;
                    };
                    *types.entry(*code).or_insert(0) += 1;
                }
            }
        }
    }
    types
}

/// The display text of a references fault, for callers outside this module.
pub fn fault(fault: lforge_rage9::psin::pso::ReferenceFault) -> &'static str {
    fault_text(fault)
}

/// The resolution of a reference word, for callers outside this module.
pub fn resolution(resolution: lforge_rage9::psin::pso::Resolution, word: u64) -> Json {
    resolution_json(resolution, word)
}
