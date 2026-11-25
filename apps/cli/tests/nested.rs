//! Nested archive traversal: content-based recognition, explicit selectors,
//! provenance and the logical-versus-stored distinction. All fixtures are
//! synthetic.

mod common;

use std::io::Write;
use std::path::Path;
use std::process::Output;

use common::{assemble, deflate, lforge, spec, stderr, write_archive};
use serde_json::Value;
use zip::write::SimpleFileOptions;

/// An RBF0 prefix with a distinct flag value, so a leaf can be identified.
fn rbf0(flags: u32) -> Vec<u8> {
    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&0xFFFBu16.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&[0xFF; 8]);
    bytes
}

fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut out);
    for (name, data) in files {
        zip.start_file(*name, SimpleFileOptions::default()).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
    out.into_inner()
}

fn rpf9(rows: &[Vec<u8>]) -> Vec<u8> {
    let specs: Vec<_> = rows.iter().map(|row| spec(row)).collect();
    assemble(&specs, &[])
}

fn json(output: &Output) -> Value {
    assert!(output.status.success(), "{}", stderr(output));
    serde_json::from_slice(&output.stdout).expect("JSON document")
}

fn inspect(archive: &Path, extra: &[&str]) -> Value {
    let mut args = vec!["archive", "inspect", archive.to_str().unwrap()];
    args.extend_from_slice(extra);
    args.push("--json");
    json(&lforge(&args))
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    write_archive(dir, name, bytes)
}

#[test]
fn an_rpf9_inside_an_rpf9_is_traversed_by_row_index() {
    let temp = tempfile::tempdir().unwrap();
    let inner = rpf9(&[rbf0(1)]);
    let outer = rpf9(&[inner]);
    // The extension does not decide the format.
    let path = write(temp.path(), "outer.bin", &outer);

    let document = inspect(&path, &["--enter", "row:0", "--row", "0"]);
    assert_eq!(document["format"]["id"], "rbf0");
    assert_eq!(document["structure"]["prefix"]["flags"], 1);
    assert_eq!(document["provenance"]["depth"], 1);
    assert_eq!(document["provenance"]["root"]["format"], "RPF9");
    let chain = document["provenance"]["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0]["selector"], "row:0");
    assert_eq!(chain[0]["format"], "RPF9");
    assert_eq!(chain[0]["entry"]["representation"], "logical");
    assert_eq!(chain[0]["authentication"]["status"], "not_applicable");
    assert_eq!(document["source"]["row"], 0);
    assert_eq!(document["source"]["entered"][0], "row:0");
}

#[test]
fn a_zip_inside_an_rpf9_is_traversed_by_entry_index() {
    let temp = tempfile::tempdir().unwrap();
    let inner = zip(&[("leaf.bin", &rbf0(2))]);
    let outer = rpf9(&[inner]);
    let path = write(temp.path(), "outer.rpf", &outer);

    let document = inspect(&path, &["--enter", "row:0", "--zip", "0"]);
    assert_eq!(document["format"]["id"], "rbf0");
    assert_eq!(document["structure"]["prefix"]["flags"], 2);
    assert_eq!(document["provenance"]["chain"][0]["format"], "ZIP");
    assert_eq!(document["provenance"]["selection"]["kind"], "zip");
    assert_eq!(document["provenance"]["selection"]["index"], 0);
    assert_eq!(document["provenance"]["representation"]["kind"], "logical");
}

#[test]
fn an_rpf9_inside_a_zip_is_traversed_by_row_index() {
    let temp = tempfile::tempdir().unwrap();
    let inner = rpf9(&[rbf0(3)]);
    let outer = zip(&[("inner.rpf", &inner)]);
    let path = write(temp.path(), "outer.bin", &outer);

    let document = inspect(&path, &["--enter", "zip:0", "--row", "0"]);
    assert_eq!(document["format"]["id"], "rbf0");
    assert_eq!(document["structure"]["prefix"]["flags"], 3);
    assert_eq!(document["provenance"]["root"]["format"], "ZIP");
    assert_eq!(document["provenance"]["chain"][0]["selector"], "zip:0");
    assert_eq!(document["provenance"]["chain"][0]["format"], "RPF9");
    assert_eq!(document["source"]["entered"][0], "zip:0");
}

#[test]
fn a_zip_inside_a_zip_is_traversed_by_entry_index() {
    let temp = tempfile::tempdir().unwrap();
    let inner = zip(&[("leaf.bin", &rbf0(4))]);
    let outer = zip(&[("inner.zip", &inner)]);
    let path = write(temp.path(), "outer.zip", &outer);

    let document = inspect(&path, &["--enter", "zip:0", "--zip", "0"]);
    assert_eq!(document["format"]["id"], "rbf0");
    assert_eq!(document["structure"]["prefix"]["flags"], 4);
    assert_eq!(document["provenance"]["chain"][0]["format"], "ZIP");
    assert_eq!(document["provenance"]["selection"]["kind"], "zip");
}

#[test]
fn entries_with_the_same_name_keep_their_identity() {
    let temp = tempfile::tempdir().unwrap();
    // The same visible file name in two folders. The selector is the entry
    // index, never the name.
    let outer = zip(&[("a/same.bin", &rbf0(5)), ("b/same.bin", &rbf0(6))]);
    let path = write(temp.path(), "duplicates.zip", &outer);

    let first = inspect(&path, &["--zip", "0"]);
    let second = inspect(&path, &["--zip", "1"]);
    assert_eq!(first["structure"]["prefix"]["flags"], 5);
    assert_eq!(second["structure"]["prefix"]["flags"], 6);
    assert!(first["provenance"]["chain"].as_array().unwrap().is_empty());
    assert_eq!(first["provenance"]["selection"]["index"], 0);
    assert_eq!(second["provenance"]["selection"]["index"], 1);
}

#[test]
fn a_nested_archive_is_selected_by_index_not_by_name() {
    let temp = tempfile::tempdir().unwrap();
    let first = rpf9(&[rbf0(7)]);
    let second = rpf9(&[rbf0(8)]);
    let outer = zip(&[("a/dup", &first), ("b/dup", &second)]);
    let path = write(temp.path(), "outer.zip", &outer);

    let document = inspect(&path, &["--enter", "zip:1", "--row", "0"]);
    assert_eq!(document["structure"]["prefix"]["flags"], 8);
    assert_eq!(document["provenance"]["chain"][0]["selector_index"], 1);
}

#[test]
fn an_encoding_2_chunked_nested_archive_is_decoded() {
    let temp = tempfile::tempdir().unwrap();
    let inner = rpf9(&[rbf0(9)]);
    let split = inner.len() / 2;
    let split = split - split % 16;
    let (first, entry_a) = common::zlib_chunk2(&inner[..split]);
    let (second, entry_b) = common::zlib_chunk2(&inner[split..]);
    let mut stored = vec![0u8; 16];
    stored.extend_from_slice(&first);
    stored.extend_from_slice(&second);
    let row = common::Spec {
        chunks: Some(common::chunk_value(2, 2, &[entry_a, entry_b])),
        logical: Some(inner.len() as u64),
        ..spec(&stored)
    };
    let outer = assemble(&[row], &[]);
    let path = write(temp.path(), "outer.rpf", &outer);

    let document = inspect(&path, &["--enter", "row:0", "--row", "0"]);
    assert_eq!(document["structure"]["prefix"]["flags"], 9);
}

#[test]
fn an_inner_rpf9_with_processed_metadata_requires_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let inner = common::assemble_processed(&[spec(&rbf0(18))], 1);
    let outer = rpf9(&[inner]);
    let path = write(temp.path(), "outer.rpf", &outer);

    // The inner archive needs its metadata authenticated before the second
    // row selector can be resolved.
    let output = lforge(&[
        "archive",
        "inspect",
        path.to_str().unwrap(),
        "--enter",
        "row:0",
        "--enter",
        "row:0",
        "--row",
        "0",
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("requires --executable"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_malformed_inner_archive_is_reported() {
    let temp = tempfile::tempdir().unwrap();
    let mut broken = vec![0u8; 0x40];
    broken[..4].copy_from_slice(b"9FPR");
    broken[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
    let outer = rpf9(&[broken]);
    let path = write(temp.path(), "outer.rpf", &outer);

    let output = lforge(&[
        "archive",
        "inspect",
        path.to_str().unwrap(),
        "--enter",
        "row:0",
        "--row",
        "0",
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a valid RPF9 archive"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_payload_that_is_not_an_archive_cannot_be_entered() {
    let temp = tempfile::tempdir().unwrap();
    let outer = rpf9(&[rbf0(10)]);
    let path = write(temp.path(), "outer.rpf", &outer);
    let output = lforge(&[
        "archive",
        "inspect",
        path.to_str().unwrap(),
        "--enter",
        "row:0",
        "--row",
        "0",
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not an archive in a supported format"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_selector_must_match_the_current_container() {
    let temp = tempfile::tempdir().unwrap();
    let rpf = write(temp.path(), "outer.rpf", &rpf9(&[rbf0(11)]));
    let zip = write(temp.path(), "outer.zip", &zip(&[("leaf", &rbf0(12))]));

    let rpf_zip = lforge(&[
        "archive",
        "inspect",
        rpf.to_str().unwrap(),
        "--enter",
        "zip:0",
        "--row",
        "0",
    ]);
    assert!(!rpf_zip.status.success());
    assert!(
        stderr(&rpf_zip).contains("current archive is RPF9"),
        "{}",
        stderr(&rpf_zip)
    );

    let zip_row = lforge(&[
        "archive",
        "inspect",
        zip.to_str().unwrap(),
        "--enter",
        "row:0",
        "--zip",
        "0",
    ]);
    assert!(!zip_row.status.success());
    assert!(
        stderr(&zip_row).contains("current archive is ZIP"),
        "{}",
        stderr(&zip_row)
    );

    let bad_row = lforge(&["archive", "inspect", rpf.to_str().unwrap(), "--row", "9"]);
    assert!(!bad_row.status.success());
    assert!(
        stderr(&bad_row).contains("out of range"),
        "{}",
        stderr(&bad_row)
    );

    let bad_zip = lforge(&["archive", "inspect", zip.to_str().unwrap(), "--zip", "9"]);
    assert!(!bad_zip.status.success());
    assert!(
        stderr(&bad_zip).contains("out of range"),
        "{}",
        stderr(&bad_zip)
    );

    let bad_final = lforge(&["archive", "inspect", zip.to_str().unwrap(), "--row", "0"]);
    assert!(!bad_final.status.success());
    assert!(
        stderr(&bad_final).contains("--row selects an RPF9 row"),
        "{}",
        stderr(&bad_final)
    );
}

#[test]
fn raw_inspection_reads_the_stored_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let payload = rbf0(13);
    let path = write(
        temp.path(),
        "outer.rpf",
        &rpf9(std::slice::from_ref(&payload)),
    );

    let document = inspect(&path, &["--row", "0", "--raw"]);
    assert_eq!(document["format"]["id"], "rbf0");
    assert_eq!(document["size"].as_u64().unwrap(), payload.len() as u64);
    assert_eq!(document["provenance"]["representation"]["kind"], "stored");
    assert_eq!(
        document["provenance"]["representation"]["decoded"],
        serde_json::json!(false)
    );
}

#[test]
fn raw_inspection_reads_a_compressed_row_as_stored() {
    let temp = tempfile::tempdir().unwrap();
    let original = rbf0(14);
    let stored = deflate(&original);
    let row = common::Spec {
        mode: 1,
        logical: Some(original.len() as u64),
        ..spec(&stored)
    };
    let path = write(temp.path(), "outer.rpf", &assemble(&[row], &[]));

    let document = inspect(&path, &["--row", "0", "--raw"]);
    // The stored bytes are the raw DEFLATE stream, not the RBF0 payload.
    assert!(document["format"].is_null());
    assert_eq!(
        document["size"].as_u64().unwrap(),
        stored.len().next_multiple_of(16) as u64
    );
    assert_eq!(document["provenance"]["representation"]["kind"], "stored");
    assert_eq!(
        document["provenance"]["representation"]["decoded"],
        serde_json::json!(false)
    );
}

#[test]
fn a_payload_transform_is_reported_as_an_unsupported_decode() {
    let temp = tempfile::tempdir().unwrap();
    let row = common::Spec {
        transform: true,
        ..spec(&rbf0(19))
    };
    let path = write(temp.path(), "outer.rpf", &assemble(&[row], &[]));

    let output = lforge(&[
        "archive",
        "inspect",
        path.to_str().unwrap(),
        "--row",
        "0",
        "--json",
    ]);
    assert!(!output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["failure_stage"], "decoding");
    assert_eq!(document["provenance"]["representation"]["kind"], "logical");
    assert_eq!(
        document["provenance"]["representation"]["decoded"],
        serde_json::json!(false)
    );
    assert!(
        document["provenance"]["representation"]["error"]
            .as_str()
            .unwrap()
            .contains("payload transform"),
        "{}",
        document["provenance"]["representation"]["error"]
    );
}

#[test]
fn extract_descends_into_a_nested_archive() {
    let temp = tempfile::tempdir().unwrap();
    let payload = rbf0(15);
    let inner = rpf9(std::slice::from_ref(&payload));
    let outer = rpf9(&[inner]);
    let path = write(temp.path(), "outer.rpf", &outer);
    let out = temp.path().join("leaf.bin");

    let output = lforge(&[
        "archive",
        "extract",
        path.to_str().unwrap(),
        "--enter",
        "row:0",
        "--row",
        "0",
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), payload);
}

#[test]
fn ls_descends_into_a_nested_archive() {
    let temp = tempfile::tempdir().unwrap();
    let inner = rpf9(&[rbf0(16), rbf0(17)]);
    let outer = rpf9(&[inner]);
    let path = write(temp.path(), "outer.rpf", &outer);

    let document = json(&lforge(&[
        "archive",
        "ls",
        path.to_str().unwrap(),
        "--enter",
        "row:0",
        "--json",
    ]));
    assert_eq!(document["schema"], "leonida-forge.native-list/1");
    assert_eq!(document["total"], 2);
    assert_eq!(document["rows"][0]["row"], 0);
    assert_eq!(document["rows"][1]["row"], 1);
}
