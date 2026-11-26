//! `lforge archive census`: every entry classified by its payload rather than
//! its type, nested archives entered where they lie, and honest limits. All
//! fixtures are synthetic.

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{Spec, assemble, chunk_value, copy_chunk, lforge, spec, stderr, write_archive};
use serde_json::Value;

/// An RPF9 archive holding one stored row.
fn archive(payload: &[u8]) -> Vec<u8> {
    assemble(&[spec(payload)], &[])
}

/// A row whose chunks all copy their bytes, so the payload can be read in
/// place instead of being decoded.
fn copied(payload: &[u8]) -> Spec {
    let (stored, entry) = copy_chunk(payload);
    let mut value = spec(&stored);
    value.chunks = Some(chunk_value(1, 4, &[entry]));
    value.logical = Some(payload.len() as u64);
    value
}

fn psin() -> Vec<u8> {
    let mut bytes = b"PSIN".to_vec();
    bytes.extend_from_slice(&[0; 12]);
    bytes
}

/// Eight zero bytes then a `0x5…` pointer: the shape of a resource header.
fn resource() -> Vec<u8> {
    let mut bytes = vec![0u8; 8];
    bytes.extend_from_slice(&0x5000_0310u64.to_le_bytes());
    bytes
}

fn census(path: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["archive", "census", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    lforge(&args)
}

fn records(output: &Output) -> Vec<Value> {
    assert!(output.status.success(), "{}", stderr(output));
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSONL record"))
        .collect()
}

fn summary(records: &[Value]) -> &Value {
    records
        .iter()
        .find(|record| record["record"] == "summary")
        .expect("a summary record")
}

fn combination<'a>(summary: &'a Value, entry_type: u8, identification: &str) -> &'a Value {
    summary["combinations"]
        .as_array()
        .expect("combinations")
        .iter()
        .find(|combination| {
            combination["type"] == entry_type && combination["identification"] == identification
        })
        .unwrap_or_else(|| panic!("no combination for type {entry_type} as {identification}"))
}

fn write(temp: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    write_archive(temp, name, bytes)
}

#[test]
fn an_entry_is_classified_by_its_payload_and_not_by_its_type() {
    let temp = tempfile::tempdir().unwrap();
    let mut nested = spec(&archive(&psin()));
    nested.type_id = 0;
    let mut typed_psin = spec(&psin());
    typed_psin.type_id = 0;
    let mut resource_row = spec(&resource());
    resource_row.type_id = 255;
    let mut unknown = spec(&[0u8; 24]);
    unknown.type_id = 255;
    let bytes = assemble(&[nested, typed_psin, resource_row, unknown], &[]);
    let path = write(temp.path(), "typed.rpf", &bytes);

    let records = records(&census(&path, &[]));
    let summary = summary(&records);
    assert_eq!(summary["archives"], 1);
    assert_eq!(summary["entries"], 4);

    let archive_row = combination(summary, 0, "format:rpf9");
    assert_eq!(archive_row["capability"], "archive");
    assert_eq!(archive_row["extension"], "rpf");
    // Type 0 is also the archive type, and this row holds an archive.
    let psin_row = combination(summary, 0, "format:psin");
    assert_eq!(psin_row["capability"], "structural");
    assert_eq!(psin_row["extension"], "-");
    // The `PSIN` recogniser walks the payload's framing from the head.
    assert_eq!(psin_row["confidence"], "verified");
    // Four entries, and the nested archive was not entered: no depth growth.
    assert_eq!(resident_entries(summary), 4);
}

fn resident_entries(summary: &Value) -> u64 {
    summary["combinations"]
        .as_array()
        .expect("combinations")
        .iter()
        .map(|combination| combination["entries"].as_u64().expect("entries"))
        .sum()
}

#[test]
fn a_resource_header_is_named_and_left_without_an_extension() {
    let temp = tempfile::tempdir().unwrap();
    let mut row = spec(&resource());
    row.type_id = 88;
    let path = write(temp.path(), "resource.rpf", &assemble(&[row], &[]));

    let records = records(&census(&path, &[]));
    let resource = combination(summary(&records), 88, "resource:segment-5");
    assert_eq!(resource["capability"], "resource");
    assert_eq!(resource["extension"], "-");
    assert_eq!(resource["confidence"], "probable");
    let sample = &resource["samples"][0];
    assert_eq!(
        sample["head"],
        format!("{}{}", "0".repeat(16), "1003005000000000")
    );
}

#[test]
fn a_nested_archive_is_entered_and_its_rows_are_counted() {
    let temp = tempfile::tempdir().unwrap();
    let inner = assemble(&[spec(&psin())], &[]);
    let mut row = spec(&inner);
    row.type_id = 0;
    let path = write(
        temp.path(),
        "outer.rpf",
        &assemble(&[row, spec(&psin())], &[]),
    );

    let records = records(&census(&path, &["--recursive"]));
    let summary = summary(&records);
    assert_eq!(summary["archives"], 2);
    assert_eq!(summary["entries"], 3);
    let nested = summary["combinations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|combination| combination["identification"] == "format:psin")
        .expect("the nested row");
    assert_eq!(nested["entries"], 2);
    assert!(
        nested["samples"]
            .as_array()
            .unwrap()
            .iter()
            .any(|sample| sample["chain"] == "outer.rpf!0!0"),
        "the nested row is named by its chain"
    );
}

#[test]
fn a_nested_archive_of_copied_chunks_is_read_in_place() {
    let temp = tempfile::tempdir().unwrap();
    let inner = archive(&psin());
    let mut row = copied(&inner);
    row.type_id = 0;
    let path = write(temp.path(), "chunked.rpf", &assemble(&[row], &[]));

    let records = records(&census(&path, &["--recursive"]));
    let summary = summary(&records);
    assert_eq!(summary["archives"], 2);
    // Nothing had to be copied to temporary storage.
    assert_eq!(summary["spooled_bytes"], 0);
    assert_eq!(summary["entries"], 2);
}

#[test]
fn the_depth_limit_stops_recursion() {
    let temp = tempfile::tempdir().unwrap();
    let inner = archive(&psin());
    let mut row = spec(&inner);
    row.type_id = 0;
    let path = write(temp.path(), "deep.rpf", &assemble(&[row], &[]));

    let records = records(&census(&path, &["--recursive", "--max-depth", "1"]));
    let summary = summary(&records);
    assert_eq!(summary["archives"], 1);
    assert_eq!(summary["entries"], 1);
}

#[test]
fn an_entry_limit_stops_the_census_and_says_so() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "many.rpf",
        &assemble(&[spec(&psin()), spec(&psin())], &[]),
    );

    let records = records(&census(&path, &["--max-entries", "1"]));
    let summary = summary(&records);
    assert_eq!(summary["entries"], 1);
    assert_eq!(summary["stopped"], "max_entries");
}

#[test]
fn one_record_per_entry_is_written_on_request() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "rows.rpf", &assemble(&[spec(&psin())], &[]));

    let quiet = records(&census(&path, &[]));
    assert_eq!(
        quiet
            .iter()
            .filter(|record| record["record"] == "entry")
            .count(),
        0
    );
    let verbose = records(&census(&path, &["--entries"]));
    let entry = verbose
        .iter()
        .find(|record| record["record"] == "entry")
        .expect("an entry record");
    assert_eq!(entry["chain"], "rows.rpf!0");
    assert_eq!(entry["classification"]["format"], "psin");
    assert_eq!(entry["classification"]["capability"], "structural");
    assert_eq!(entry["classification"]["extension"], Value::Null);
    assert_eq!(entry["classification"]["extension_verified"], false);
}

#[test]
fn the_output_is_deterministic() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "same.rpf",
        &assemble(&[spec(&psin()), spec(&resource()), spec(&[1, 2, 3])], &[]),
    );
    let first = census(&path, &[]);
    let second = census(&path, &[]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn an_unreadable_root_is_a_failure_record() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "broken.rpf", &[0u8; 128]);

    let output = census(&path, &[]);
    let records = records(&output);
    let summary = summary(&records);
    assert_eq!(summary["archives"], 0);
    assert_eq!(summary["entries"], 0);
    assert_eq!(summary["failures"].as_array().unwrap().len(), 1);
}
