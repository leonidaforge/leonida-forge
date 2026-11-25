//! Format inspection: content-based recognition, the structured document and
//! the archive row path. All fixtures are synthetic.

mod common;

use std::io::Write;

use common::{assemble, lforge, spec, write_archive};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde_json::Value;

const MASK: u32 = 0x00FF_FFFF;
const MAGIC: &[u8; 4] = b"RDS5";

fn up(value: usize, to: usize) -> usize {
    value.next_multiple_of(to)
}

fn set_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// A synthetic RDS5 container: one entry per block, blocks back to back.
fn rds5(blocks: &[Vec<u8>]) -> Vec<u8> {
    let count = blocks.len() + 2;
    let record_end = up(0x10 + 8 * count, 0x100);
    let table = 16 * blocks.len();
    let first_block = record_end + up(0x10 + 2 * table + 0x40, 0x1000);
    let mut offsets = vec![record_end, first_block];
    let mut pos = first_block;
    for block in blocks {
        pos += up(block.len(), 0x100);
        offsets.push(pos);
    }
    let mut bytes = vec![0u8; pos];
    bytes[..4].copy_from_slice(MAGIC);
    set_u32(&mut bytes, 4, count as u32);
    set_u32(
        &mut bytes,
        8,
        0x1000
            + blocks
                .iter()
                .map(|block| up(block.len(), 0x1000))
                .sum::<usize>() as u32,
    );
    set_u32(&mut bytes, 0x0C, 0x1600_0000);
    for (index, offset) in offsets.iter().enumerate() {
        set_u32(
            &mut bytes,
            0x10 + 8 * index,
            (*offset as u32 / 0x100) & MASK,
        );
    }
    bytes[record_end..record_end + 4].copy_from_slice(b"ETPF");
    set_u32(&mut bytes, record_end + 4, 0x27A);
    set_u32(&mut bytes, record_end + 8, blocks.len() as u32);
    set_u32(&mut bytes, record_end + 0x0C, 0x40);
    for index in 0..blocks.len() {
        let at = record_end + 0x10 + 16 * index;
        set_u32(&mut bytes, at, 0xC001);
        set_u32(&mut bytes, at + 4, 0x20);
        set_u32(&mut bytes, at + 8, index as u32 + 1);
        set_u32(&mut bytes, at + 12, 1);
    }
    let mut pos = first_block;
    for block in blocks {
        bytes[pos..pos + block.len()].copy_from_slice(block);
        pos += up(block.len(), 0x100);
    }
    bytes
}

fn block() -> Vec<u8> {
    zlib(b"SYNTHETIC-BLOCK-".repeat(40).as_slice())
}

fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("JSON document")
}

#[test]
fn binary_inspect_reports_an_rds5_container() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "sample.bin",
        &rds5(&[block(), block(), block()]),
    );
    let output = lforge(&[
        "binary",
        "inspect",
        path.to_str().unwrap(),
        "--json",
        "--sample",
        "4",
    ]);
    assert!(output.status.success(), "{}", common::stderr(&output));

    let document = json(&output);
    assert_eq!(document["schema"], "leonida-forge.format-inspection/1");
    assert_eq!(document["format"]["id"], "rds5");
    assert_eq!(document["format"]["support"], "structural");
    assert_eq!(
        document["source"]["file"].as_str().unwrap(),
        path.to_str().unwrap()
    );
    let structure = &document["structure"];
    assert_eq!(structure["valid"], true);
    assert_eq!(structure["header"]["record_count"], 5);
    assert_eq!(structure["header"]["version"], "0x16000000");
    assert_eq!(structure["records"]["blocks"], 3);
    assert_eq!(structure["records"]["items"].as_array().unwrap().len(), 4);
    assert_eq!(structure["chunk"]["entry_count"], 3);
    assert_eq!(
        structure["chunk"]["entry_sample"].as_array().unwrap().len(),
        3
    );
    assert_eq!(structure["blocks"]["by_storage"]["zlib"], 3);
    assert!(structure["verified"].is_null());
    let ranges = structure["parsed_ranges"].as_array().unwrap();
    assert!(ranges.iter().any(|range| range["field"] == "record array"));
    // No payload bytes are part of the document.
    let text = serde_json::to_string(&document).unwrap();
    assert!(!text.contains("SYNTHETIC-BLOCK"));
}

#[test]
fn binary_inspect_verifies_every_block() {
    let temp = tempfile::tempdir().unwrap();
    let blocks = vec![block(), block()];
    let mut container = rds5(&blocks);
    // Break the second block's stream: its checksum no longer matches.
    let second = {
        let count = 4usize;
        let record_end = up(0x10 + 8 * count, 0x100);
        let table = 16 * 2;
        let first = record_end + up(0x10 + 2 * table + 0x40, 0x1000);
        first + up(blocks[0].len(), 0x100) + 4
    };
    container[second] ^= 0xFF;
    let path = write(temp.path(), "broken.bin", &container);

    let output = lforge(&[
        "binary",
        "inspect",
        path.to_str().unwrap(),
        "--json",
        "--verify",
    ]);
    assert!(!output.status.success());
    let document = json(&output);
    assert_eq!(document["structure"]["valid"], true);
    let verified = &document["structure"]["verified"];
    assert_eq!(verified["zlib_blocks"], 2);
    assert_eq!(verified["failures"], 1);
    assert!(
        verified["failure_sample"][0]["error"]
            .as_str()
            .unwrap()
            .contains("zlib")
    );
}

#[test]
fn binary_inspect_reports_an_unrecognised_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "plain.bin", b"nothing to see here");
    let output = lforge(&["binary", "inspect", path.to_str().unwrap(), "--json"]);
    assert!(output.status.success());
    let document = json(&output);
    assert!(document["format"].is_null());
    assert!(document["structure"].is_null());

    let output = lforge(&["binary", "inspect", path.to_str().unwrap()]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("unrecognised"), "{text}");
}

#[test]
fn binary_inspect_reports_an_rbf0_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&0xFFFBu16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&17u16.to_le_bytes());
    bytes.extend_from_slice(b"SYNTHETIC-ROOT-NAME");
    bytes.extend_from_slice(&[0xFF; 8]);
    let path = write(temp.path(), "doc.bin", &bytes);

    let output = lforge(&["binary", "inspect", path.to_str().unwrap(), "--json"]);
    assert!(output.status.success());
    let document = json(&output);
    assert_eq!(document["format"]["id"], "rbf0");
    assert_eq!(document["format"]["support"], "header");
    assert_eq!(document["structure"]["prefix"]["root_name_len"], 17);
    assert_eq!(document["structure"]["prefix"]["word"], "0xFFFB");
    // The root name itself is payload text and is never printed.
    let text = serde_json::to_string(&document).unwrap();
    assert!(!text.contains("SYNTHETIC-ROOT-NAME"));
}

#[test]
fn binary_inspect_reports_a_malformed_container() {
    let temp = tempfile::tempdir().unwrap();
    let mut bytes = rds5(&[block()]);
    set_u32(&mut bytes, 0x0C, 0x1600_0009);
    let path = write(temp.path(), "bad.bin", &bytes);
    let output = lforge(&["binary", "inspect", path.to_str().unwrap(), "--json"]);
    assert!(!output.status.success());
    let document = json(&output);
    assert_eq!(document["format"]["id"], "rds5");
    assert_eq!(document["structure"]["valid"], false);
    assert!(
        document["structure"]["error"]
            .as_str()
            .unwrap()
            .contains("unsupported RDS5 version")
    );
}

#[test]
fn archive_inspect_reads_a_row_without_extracting_it() {
    let temp = tempfile::tempdir().unwrap();
    let payload = rds5(&[block(), block()]);
    let path = write_archive(temp.path(), "row.rpf", &assemble(&[spec(&payload)], &[]));

    let output = lforge(&[
        "archive",
        "inspect",
        path.to_str().unwrap(),
        "--row",
        "0",
        "--json",
    ]);
    assert!(output.status.success(), "{}", common::stderr(&output));
    let document = json(&output);
    assert_eq!(document["format"]["id"], "rds5");
    assert_eq!(document["source"]["row"], 0);
    assert_eq!(document["size"].as_u64().unwrap(), payload.len() as u64);
    assert_eq!(document["structure"]["blocks"]["count"], 2);
    // Nothing was written next to the archive.
    let entries: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn archive_inspect_rejects_an_out_of_range_row() {
    let temp = tempfile::tempdir().unwrap();
    let path = write_archive(
        temp.path(),
        "row.rpf",
        &assemble(&[spec(&rds5(&[block()]))], &[]),
    );
    let output = lforge(&[
        "archive",
        "inspect",
        path.to_str().unwrap(),
        "--row",
        "7",
        "--json",
    ]);
    assert!(!output.status.success());
    assert!(common::stderr(&output).contains("out of range"));
}

#[test]
fn inspect_output_is_stable() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "sample.bin", &rds5(&[block(), block()]));
    let first = lforge(&["binary", "inspect", path.to_str().unwrap(), "--json"]);
    let second = lforge(&["binary", "inspect", path.to_str().unwrap(), "--json"]);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    // Offsets stay hex strings, so no 64-bit value loses precision.
    let document = json(&first);
    for record in document["structure"]["records"]["items"]
        .as_array()
        .unwrap()
    {
        assert!(record["offset"].as_str().unwrap().starts_with("0x"));
    }
}
