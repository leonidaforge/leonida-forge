//! The JSON and XML views carry the same facts. Tests build the document by
//! hand so no game payload is needed.

use super::*;
use lforge_rage9::psin::pso::{
    Block, Content, Document, Enumeration, EnumValue, Field, FieldValue, PoolEntry, Record,
    Scalar, Structure, Value,
};
use lforge_rage9::rpf::names::StringTable;

fn field(name: u32, offset: u32, type_word: u32, auxiliary: u32) -> Field {
    Field {
        name,
        offset,
        type_word,
        auxiliary,
    }
}

fn record(offset: u32, values: Vec<(Field, Value)>) -> Record {
    Record {
        offset,
        structure: 0x1111_1111,
        fields: values
            .into_iter()
            .map(|(field, value)| FieldValue {
                field,
                extent: field.width(),
                value,
            })
            .collect(),
    }
}

fn document() -> Document {
    let structure = Structure {
        name: 0x1111_1111,
        signature: 0x2222_2222,
        flags: 0x300,
        size: 12,
        fields: vec![
            field(0xaaaa_0001, 0, 0x21, 0),
            field(0xaaaa_0002, 4, 0x4a, 0),
            field(0xaaaa_0003, 8, 0x9f, 0x42),
        ],
    };
    let records = vec![
        record(
            64,
            vec![
                (structure.fields[0], Value::Scalar(Scalar::F32(1.5))),
                (structure.fields[1], Value::Scalar(Scalar::Hash32(0xdead_beef))),
                (
                    structure.fields[2],
                    Value::Unresolved {
                        code: 0x9f,
                        upper: 0,
                        auxiliary: 0x42,
                        raw: vec![0x78, 0x56],
                    },
                ),
            ],
        ),
        record(
            76,
            vec![
                (structure.fields[0], Value::Scalar(Scalar::F32(-2.0))),
                (structure.fields[1], Value::Scalar(Scalar::Hash32(0x1234_5678))),
                (
                    structure.fields[2],
                    Value::Unresolved {
                        code: 0x9f,
                        upper: 0,
                        auxiliary: 0x42,
                        raw: Vec::new(),
                    },
                ),
            ],
        ),
    ];
    Document {
        structures: vec![structure],
        enums: vec![Enumeration {
            name: 0x7777_7777,
            signature: 0,
            values: vec![EnumValue {
                value: 7,
                name: 0x0100,
            }],
        }],
        blocks: vec![
            Block {
                index: 1,
                id: 0x1111_1111,
                offset: 64,
                len: 24,
                content: Content::Records {
                    structure: 0x1111_1111,
                    stride: 12,
                    total: 2,
                    records,
                },
            },
            Block {
                index: 2,
                id: 0x4a,
                offset: 96,
                len: 8,
                content: Content::Pool {
                    kind: lforge_rage9::psin::pso::PoolKind::Hash32,
                    total: 2,
                    entries: vec![PoolEntry::Hash32(0xaaaa_aaaa), PoolEntry::Hash32(0xbbbb_bbbb)],
                },
            },
        ],
        header: Some(lforge_rage9::psin::pso::Header {
            object_type: 0x7a,
            roots: 1,
            structures: 1,
            enums: 1,
            blocks: 2,
        }),
        issues: Vec::new(),
    }
}

#[test]
fn the_counts_match_the_document() {
    let counts = counts(&document());
    assert_eq!(counts.structures, 1);
    assert_eq!(counts.fields, 3);
    assert_eq!(counts.enums, 1);
    assert_eq!(counts.enum_values, 1);
    assert_eq!(counts.blocks, 2);
    assert_eq!(counts.records, 2);
    assert_eq!(counts.records_decoded, 2);
    assert_eq!(counts.structure_blocks, 1);
    assert_eq!(counts.pool_blocks, 1);
    assert_eq!(counts.unsupported_blocks, 0);
    assert_eq!(counts.header_matches, Some(true));
}

#[test]
fn the_json_view_carries_every_decoded_fact() {
    let names = Names::empty();
    let value = document_json(&document(), &names, usize::MAX);
    assert_eq!(value["status"], "decoded");
    assert_eq!(value["counts"]["records"], 2);
    assert_eq!(value["structures"][0]["name"], "0x11111111");
    assert_eq!(value["structures"][0]["fields"][1]["typeName"], "hash32");
    assert_eq!(value["enums"][0]["values"][0]["value"], 7);
    let records = value["blocks"][0]["records"].as_array().expect("records");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["fields"][0]["value"]["value"], 1.5);
    assert_eq!(records[0]["fields"][1]["value"]["value"], "0xDEADBEEF");
    assert_eq!(records[0]["fields"][2]["value"]["kind"], "unresolved");
    assert_eq!(records[0]["fields"][2]["value"]["bytes"], "7856");
    assert_eq!(value["blocks"][1]["entries"][0]["value"], "0xAAAAAAAA");
}

#[test]
fn a_sampled_json_view_keeps_the_counts_but_not_the_records() {
    let names = Names::empty();
    let value = document_json(&document(), &names, 0);
    assert_eq!(value["counts"]["records"], 2);
    assert_eq!(value["blocks"][0]["decoded"], 2);
    assert!(value["blocks"][0].get("records").is_none());
    assert!(value["blocks"][1].get("entries").is_none());

    // One block of detail: the first block only.
    let value = document_json(&document(), &names, 1);
    assert!(value["blocks"][0].get("records").is_some());
    assert!(value["blocks"][1].get("entries").is_none());
}

#[test]
fn the_xml_view_is_well_formed_and_carries_the_same_facts() {
    let source = [("archive", "example.rpf".to_string()), ("row", "7".to_string())];
    let text = document_xml(&document(), usize::MAX, &source);
    let parsed = roxmltree::Document::parse(&text).expect("the XML parses");
    let root = parsed.root_element();
    assert_eq!(root.tag_name().name(), "meta");
    assert_eq!(root.attribute("status"), Some("decoded"));
    assert_eq!(root.attribute("records"), Some("2"));
    let source_element = root
        .children()
        .find(|node| node.has_tag_name("source"))
        .expect("the source element");
    assert_eq!(source_element.attribute("archive"), Some("example.rpf"));
    assert_eq!(source_element.attribute("row"), Some("7"));

    let structure = root
        .children()
        .find(|node| node.has_tag_name("structure"))
        .expect("the structure element");
    assert_eq!(structure.attribute("name"), Some("0x11111111"));
    assert_eq!(structure.attribute("size"), Some("12"));
    let fields: Vec<_> = structure
        .children()
        .filter(|node| node.has_tag_name("field"))
        .collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[1].attribute("typeName"), Some("hash32"));
    assert_eq!(fields[2].attribute("extent"), Some("4"));

    let blocks: Vec<_> = root
        .children()
        .filter(|node| node.has_tag_name("block"))
        .collect();
    assert_eq!(blocks.len(), 2);
    let records: Vec<_> = blocks[0]
        .children()
        .filter(|node| node.has_tag_name("record"))
        .collect();
    assert_eq!(records.len(), 2);
    let values: Vec<_> = records[0]
        .descendants()
        .filter(|node| node.has_tag_name("value"))
        .collect();
    assert_eq!(values[0].attribute("kind"), Some("scalar"));
    assert_eq!(values[0].attribute("text"), Some("1.5"));
    assert_eq!(values[1].attribute("hash"), Some("0xDEADBEEF"));
    assert_eq!(values[2].attribute("kind"), Some("unresolved"));
    assert_eq!(values[2].attribute("bytes"), Some("7856"));

    let members: Vec<_> = root
        .children()
        .filter(|node| node.has_tag_name("enum"))
        .flat_map(|node| node.children().filter(|child| child.has_tag_name("member")))
        .collect();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].attribute("value"), Some("7"));
}

#[test]
fn an_unsupported_block_is_named_in_both_views() {
    let mut document = document();
    document.blocks[0].content = Content::Unsupported("no structure".into());
    let value = document_json(&document, &Names::empty(), usize::MAX);
    assert_eq!(value["blocks"][0]["kind"], "unsupported");
    assert_eq!(value["blocks"][0]["reason"], "no structure");
    assert_eq!(value["status"], "partial");
    let text = document_xml(&document, usize::MAX, &[]);
    let parsed = roxmltree::Document::parse(&text).expect("the XML parses");
    let block = parsed
        .root_element()
        .children()
        .find(|node| node.has_tag_name("block"))
        .expect("the block element");
    assert_eq!(block.attribute("kind"), Some("unsupported"));
    assert_eq!(block.attribute("reason"), Some("no structure"));
}

#[test]
fn a_resolved_name_is_an_attribute_beside_the_hash() {
    let mut table = StringTable::default();
    table.add(lforge_rage9::rpf::names::TableEntry {
        name: "fRainbow".into(),
        provenance: lforge_rage9::rpf::names::Provenance::UserMapping,
        declared: None,
    });
    let names = Names::from_table(&table);
    let hash = lforge_rage9::psin::pso::names::metadata_hash(b"fRainbow");
    let mut document = document();
    document.structures[0].fields[0].name = hash;
    let value = document_json(&document, &names, usize::MAX);
    assert_eq!(value["structures"][0]["fields"][0]["name"], format!("0x{hash:08X}"));
    assert_eq!(value["structures"][0]["fields"][0]["nameCandidates"]["name"], "fRainbow");
}
