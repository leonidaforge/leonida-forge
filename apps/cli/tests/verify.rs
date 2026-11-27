//! `lforge archive verify`, on synthetic RPF9 archives built in memory.

mod common;

use common::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn records(path: &std::path::Path) -> (Vec<Value>, Value) {
    let mut entries = Vec::new();
    let mut summary = Value::Null;
    for line in std::fs::read_to_string(path).unwrap().lines() {
        let record: Value = serde_json::from_str(line).unwrap();
        match record["record"].as_str() {
            Some("entry") => entries.push(record),
            Some("summary") => summary = record,
            _ => {}
        }
    }
    (entries, summary)
}

#[test]
fn verifies_encoding_4_with_and_without_a_stored_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let first: Vec<u8> = (0..0x200u32).map(|i| (i % 251) as u8).collect();
    let second: Vec<u8> = (0..0x40u32).map(|i| b'a' + (i % 26) as u8).collect();
    let (region_a, entry_a) = zlib_chunk(&first);
    let (region_b, entry_b) = copy_chunk(&second);
    let mut prefixed = vec![0u8; 16];
    prefixed.extend_from_slice(&region_a);
    prefixed.extend_from_slice(&region_b);
    let (plain_region, plain_entry) = zlib_chunk(b"plain");
    let rows = vec![
        Spec {
            chunks: Some(chunk_value(2, 4, &[entry_a, entry_b])),
            logical: Some((first.len() + second.len()) as u64),
            ..spec(&prefixed)
        },
        Spec {
            chunks: Some(chunk_value(1, 4, &[plain_entry])),
            logical: Some(5),
            ..spec(&plain_region)
        },
    ];
    let archive = write_archive(temp.path(), "encoding4.rpf", &assemble(&rows, &[]));
    let output = temp.path().join("verify.jsonl");

    let result = lforge(&[
        "archive",
        "verify",
        archive.to_str().unwrap(),
        "--encoding",
        "4",
        "--output",
        output.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(result.status.success(), "{}", stderr(&result));
    let (entries, summary) = records(&output);
    assert_eq!(summary["candidates"], 2);
    assert_eq!(summary["decoded"], 2);
    assert_eq!(summary["failed"], 0);
    assert_eq!(summary["by_prefix"]["16"], 1);
    assert_eq!(summary["by_prefix"]["0"], 1);
    let mut expected = first.clone();
    expected.extend_from_slice(&second);
    let digest = format!("{:x}", Sha256::digest(&expected));
    assert_eq!(entries[0]["verification"]["digest_sha256"], digest);
    assert_eq!(entries[0]["chunk_table"]["stored_prefix"], 16);
    assert_eq!(
        entries[1]["verification"]["digest_sha256"],
        format!("{:x}", Sha256::digest(b"plain"))
    );
    assert_eq!(entries[1]["chunk_table"]["stored_prefix"], 0);
    assert_eq!(entries[0]["verification"]["logical_size_matched"], true);
    assert_eq!(
        entries[0]["verification"]["integrity"],
        "zlib-adler32-and-copy"
    );
}

#[test]
fn replaces_an_existing_output_only_when_asked() {
    let temp = tempfile::tempdir().unwrap();
    let (region, entry) = zlib_chunk(b"data");
    let row = Spec {
        chunks: Some(chunk_value(1, 4, &[entry])),
        logical: Some(4),
        ..spec(&region)
    };
    let archive = write_archive(temp.path(), "one.rpf", &assemble(&[row], &[]));
    let output = temp.path().join("verify.jsonl");
    std::fs::write(&output, "old\n").unwrap();

    let refused = lforge(&[
        "archive",
        "verify",
        archive.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "old\n");

    let replaced = lforge(&[
        "archive",
        "verify",
        archive.to_str().unwrap(),
        "--encoding",
        "4",
        "--output",
        output.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(replaced.status.success(), "{}", stderr(&replaced));
    let (entries, summary) = records(&output);
    assert_eq!(entries.len(), 1);
    assert_eq!(summary["candidates"], 1);
}

#[test]
fn reports_a_chunk_that_does_not_decode() {
    let temp = tempfile::tempdir().unwrap();
    let row = Spec {
        chunks: Some(chunk_value(1, 4, &[chunk4(100, 32, 0, 3)])),
        logical: Some(100),
        ..spec(&[0xA5; 32])
    };
    let archive = write_archive(temp.path(), "bad-chunk.rpf", &assemble(&[row], &[]));
    let output = temp.path().join("verify.jsonl");

    let result = lforge(&[
        "archive",
        "verify",
        archive.to_str().unwrap(),
        "--encoding",
        "4",
        "--output",
        output.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(!result.status.success());
    let (entries, summary) = records(&output);
    assert_eq!(summary["candidates"], 1);
    assert_eq!(summary["decoded"], 0);
    assert_eq!(summary["failed"], 1);
    assert_eq!(summary["by_error"]["chunk-decode"], 1);
    assert_eq!(entries[0]["verification"]["status"], "failed");
    assert_eq!(entries[0]["verification"]["error_category"], "chunk-decode");
    assert_eq!(entries[0]["verification"]["digest_sha256"], Value::Null);
    assert_eq!(entries[0]["verification"]["all_chunks_decoded"], false);
}
