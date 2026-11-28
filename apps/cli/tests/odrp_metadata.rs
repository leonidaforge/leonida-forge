//! A synthetic `0DRP` metadata resource, stored as a native row and read
//! through the generic metadata workflow.
//!
//! The resource is built here, not taken from a game archive: the system
//! segment carries the schema, the block table and a text block, and the
//! graphics segment carries one record, so the test exercises the segment
//! split as well as the decode.

mod common;

use common::{Spec, assemble, chunk_value, lforge, spec, stderr, write_archive, zlib_chunk2};
use serde_json::Value;

const SYSTEM_BASE: u64 = 0x5000_0000;
const GRAPHICS_BASE: u64 = 0x6000_0000;

const STRUCTURE: u32 = 0xAAAA_0001;
const TEXT_FIELD: u32 = 0xBBBB_0001;
const COUNT_FIELD: u32 = 0xBBBB_0002;

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

/// A reference word: `(offset << 20) | block`.
fn reference(block: u64, offset: u64) -> u64 {
    (offset << 20) | block
}

/// Builds the system and graphics segments of one resource.
///
/// Structure `0xAAAA0001` is `{ u32 count at 0, 0x42 text reference at 8 }`,
/// 16 bytes a record. Block 1 holds one record in the system segment, block 2
/// holds one record in the graphics segment, block 3 is a text block, and
/// block 4 is a hash32 pool.
fn segments() -> (Vec<u8>, Vec<u8>) {
    let mut system = vec![0u8; 0x60];
    let mut graphics = Vec::new();

    let field_at = system.len() as u32;
    push_u32(&mut system, COUNT_FIELD);
    push_u32(&mut system, 0);
    push_u32(&mut system, 0x15);
    push_u32(&mut system, 0);
    push_u32(&mut system, TEXT_FIELD);
    push_u32(&mut system, 8);
    push_u32(&mut system, 0x42);
    push_u32(&mut system, 0);

    let structure_at = system.len() as u32;
    push_u32(&mut system, STRUCTURE);
    push_u32(&mut system, 0x1234_5678);
    push_u32(&mut system, 0x300);
    push_u32(&mut system, 0);
    push_u64(&mut system, SYSTEM_BASE | u64::from(field_at));
    push_u32(&mut system, 16);
    push_u16(&mut system, 0);
    push_u16(&mut system, 2);

    let record = |count: u32, block: u64, offset: u64| {
        let mut bytes = Vec::new();
        push_u32(&mut bytes, count);
        push_u32(&mut bytes, 0);
        push_u64(&mut bytes, reference(block, offset));
        bytes
    };
    let system_at = system.len() as u32;
    system.extend_from_slice(&record(7, 3, 0));
    let graphic_record = record(9, 3, 6);
    graphics.extend_from_slice(&graphic_record);

    let text_at = system.len() as u32;
    let text = b"first\0second\0";
    system.extend_from_slice(text);
    let hash_at = system.len() as u32;
    push_u32(&mut system, 0xDEAD_BEEF);

    let block_at = system.len() as u32;
    for (type_word, len, pointer) in [
        (STRUCTURE, 16, SYSTEM_BASE | u64::from(system_at)),
        (
            STRUCTURE,
            graphics.len() as u32,
            GRAPHICS_BASE | u64::from(0u32),
        ),
        (0x10, text.len() as u32, SYSTEM_BASE | u64::from(text_at)),
        (0x4a, 4, SYSTEM_BASE | u64::from(hash_at)),
    ] {
        push_u32(&mut system, type_word);
        push_u32(&mut system, len);
        push_u64(&mut system, pointer);
    }

    let pages = 1 + 1;
    let map_at = system.len() as u32;
    let mut map = vec![0u8; 16 + 8 * pages];
    map[8] = 1;
    map[9] = 1;
    system.extend_from_slice(&map);

    let header = &mut system[..0x60];
    header[0x08..0x10].copy_from_slice(&(SYSTEM_BASE | u64::from(map_at)).to_le_bytes());
    header[0x10..0x14].copy_from_slice(b"0DRP");
    header[0x14] = 0x7A;
    header[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    header[0x28..0x30].copy_from_slice(&(SYSTEM_BASE | u64::from(structure_at)).to_le_bytes());
    header[0x38..0x40].copy_from_slice(&(SYSTEM_BASE | u64::from(block_at)).to_le_bytes());
    header[0x40..0x48].copy_from_slice(&(SYSTEM_BASE | u64::from(block_at)).to_le_bytes());
    header[0x48..0x4A].copy_from_slice(&1u16.to_le_bytes());
    header[0x4C..0x4E].copy_from_slice(&4u16.to_le_bytes());
    // Encoding-2 chunks record their decoded length in 16-byte units, so both
    // segments are padded to a multiple of 16 after their last table.
    system.resize(system.len().next_multiple_of(16), 0);
    graphics.resize(graphics.len().next_multiple_of(16), 0);
    (system, graphics)
}

/// The row payload: the two segments as encoding-2 zlib chunks, one page each.
fn chunks() -> Spec {
    let (system, graphics) = segments();
    let (region_a, entry_a) = zlib_chunk2(&system);
    let (region_b, entry_b) = zlib_chunk2(&graphics);
    let mut payload = vec![0u8; 16];
    payload.extend_from_slice(&region_a);
    payload.extend_from_slice(&region_b);
    Spec {
        type_id: 11,
        chunks: Some(chunk_value(2, 2, &[entry_a, entry_b])),
        logical: Some((system.len() + graphics.len()) as u64),
        ..spec(&payload)
    }
}

fn archive(dir: &std::path::Path) -> std::path::PathBuf {
    let bytes = assemble(&[chunks()], &[]);
    write_archive(dir, "odrp.rpf", &bytes)
}

#[test]
fn a_resource_row_exports_the_shared_metadata_document() {
    let temp = tempfile::tempdir().unwrap();
    let archive = archive(temp.path());
    let output_json = temp.path().join("document.json");

    let output = lforge(&[
        "archive",
        "inspect",
        archive.to_str().unwrap(),
        "--row",
        "0",
        "--metadata-output",
        output_json.to_str().unwrap(),
        "--blocks",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let export: Value = serde_json::from_slice(&std::fs::read(&output_json).unwrap()).unwrap();
    assert_eq!(export["schema"], "leonida-forge.odrp-document/1");
    assert_eq!(export["source"]["format"], "0drp");
    assert_eq!(export["source"]["status"], "decoded");
    assert_eq!(export["source"]["row"], 0);
    let display = export["source"]["resource"]["display"]
        .as_str()
        .expect("a canonical display");
    assert!(
        display.starts_with("odrp.rpf!"),
        "the resource is named by the canonical path: {display}"
    );

    let document = &export["document"];
    assert_eq!(document["format"], "0drp");
    assert_eq!(document["status"], "decoded");
    assert_eq!(document["header"]["objectType"], 0x7A);
    assert_eq!(document["header"]["systemPages"], 1);
    assert_eq!(document["header"]["graphicsPages"], 1);
    assert_eq!(document["counts"]["structures"], 1);
    assert_eq!(document["counts"]["blocks"], 4);
    assert_eq!(document["counts"]["records"], 2);
    assert_eq!(document["counts"]["recordsDecoded"], 2);
    assert_eq!(document["counts"]["texts"], 2);
    assert_eq!(document["counts"]["unsupportedBlocks"], 0);
    assert_eq!(document["counts"]["unresolvedReferences"], 0);

    // Block 2 stores its record in the graphics segment.
    let blocks = document["blocks"].as_array().expect("blocks");
    assert_eq!(blocks[0]["segment"], "system");
    assert_eq!(blocks[1]["segment"], "graphics");
    assert_eq!(blocks[1]["kind"], "records");
    let graphics_record = &blocks[1]["records"][0];
    let text = graphics_record["fields"][1]["value"].clone();
    assert_eq!(text["kind"], "text");
    assert_eq!(text["text"], "second");

    // The text block keeps its two strings, and the pool its hash.
    assert_eq!(blocks[2]["kind"], "pool");
    assert_eq!(blocks[2]["pool"], "text");
    assert_eq!(blocks[2]["entries"][0], "first");
    assert_eq!(blocks[3]["entries"][0]["value"], "0xDEADBEEF");

    // The root block is derived from the references: block 1 is unreferenced
    // only when nothing points at it, and block 2 is reached from block 1.
    assert_eq!(document["roots"].as_array().expect("roots").len(), 2);
}

#[test]
fn a_resource_row_exports_xml_that_names_itself_as_generated() {
    let temp = tempfile::tempdir().unwrap();
    let archive = archive(temp.path());
    let output_xml = temp.path().join("document.xml");

    let output = lforge(&[
        "archive",
        "inspect",
        archive.to_str().unwrap(),
        "--row",
        "0",
        "--metadata-output",
        output_xml.to_str().unwrap(),
        "--metadata-xml",
        "--blocks",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let xml = std::fs::read_to_string(&output_xml).unwrap();
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("format=\"0drp\""));
    assert!(xml.contains("schema=\"leonida-forge.odrp-document/1\""));
    assert!(xml.contains("segment=\"graphics\""));
    assert!(xml.contains("kind=\"text\""));
    assert!(xml.contains("text=\"second\""));
    // A strict reader accepts the document.
    let parsed = roxmltree::Document::parse(&xml).expect("the XML parses");
    let blocks: Vec<&str> = parsed
        .descendants()
        .filter(|node| node.has_tag_name("block"))
        .map(|node| node.attribute("segment").unwrap_or(""))
        .collect();
    assert_eq!(blocks.len(), 4);
    assert!(blocks.contains(&"graphics"));
}

#[test]
fn a_resource_row_without_its_page_table_says_what_is_missing() {
    // One stored chunk cannot describe two pages, so the graphics segment
    // cannot be located. The error must name the missing information rather
    // than report an unknown payload.
    let temp = tempfile::tempdir().unwrap();
    let (system, graphics) = segments();
    let mut payload = system;
    payload.extend_from_slice(&graphics);
    let stored = Spec {
        type_id: 11,
        ..spec(&payload)
    };
    let bytes = assemble(&[stored], &[]);
    let archive = write_archive(temp.path(), "stored.rpf", &bytes);
    let output = lforge(&[
        "archive",
        "inspect",
        archive.to_str().unwrap(),
        "--row",
        "0",
        "--metadata-output",
        temp.path().join("out.json").to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("0DRP"), "{message}");
    assert!(
        message.contains("page table") || message.contains("pages"),
        "{message}"
    );
}
