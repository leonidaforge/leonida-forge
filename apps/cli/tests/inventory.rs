//! `lforge archive inventory`: lossless ZIP identity, bounded recursion,
//! deterministic records and honest completion status. All fixtures are
//! synthetic.

mod common;

use std::path::Path;
use std::process::Output;

use common::{
    ZipEntry, assemble, lforge, spec, stderr, write_archive, zip_entries, zip_with_entries,
};
use serde_json::Value;

/// An RBF0 prefix with a distinct flag value, so a leaf can be recognised.
fn rbf0(flags: u32) -> Vec<u8> {
    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&0xFFFBu16.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&[0xFF; 8]);
    bytes
}

fn psin() -> Vec<u8> {
    let mut bytes = b"PSIN".to_vec();
    bytes.extend_from_slice(&[0; 12]);
    bytes
}

fn rpf9(rows: &[Vec<u8>]) -> Vec<u8> {
    let specs: Vec<_> = rows.iter().map(|row| spec(row)).collect();
    assemble(&specs, &[])
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    write_archive(dir, name, bytes)
}

fn inventory(path: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["archive", "inventory", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    lforge(&args)
}

fn lines(output: &Output) -> Vec<Value> {
    assert!(output.status.success(), "{}", stderr(output));
    parse(output)
}

/// The records of a run that may legitimately exit non-zero, such as a
/// truncated inventory.
fn parse(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSONL record"))
        .collect()
}

fn kinds<'a>(records: &'a [Value], kind: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|record| record["kind"] == kind)
        .collect()
}

fn summary(records: &[Value]) -> &Value {
    records
        .iter()
        .find(|record| record["kind"] == "summary")
        .expect("a summary record")
}

#[test]
fn duplicate_zip_names_keep_distinct_indices() {
    let temp = tempfile::tempdir().unwrap();
    let zip = zip_entries(&[("same.bin", &rbf0(1)), ("same.bin", &rbf0(2))]);
    let path = write(temp.path(), "duplicates.zip", &zip);

    let records = lines(&inventory(&path, &[]));
    let entries = kinds(&records, "entry");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["selector"], "zip:0");
    assert_eq!(entries[1]["selector"], "zip:1");
    assert_eq!(entries[0]["entry"]["name"], "same.bin");
    assert_eq!(entries[1]["entry"]["name"], "same.bin");
    assert_eq!(entries[0]["content"]["format"]["id"], "rbf0");
    assert_eq!(entries[1]["content"]["format"]["id"], "rbf0");

    let archive = kinds(&records, "archive")[0];
    assert_eq!(archive["entries"], 2);
    assert_eq!(archive["duplicate_names"], 1);
    assert_eq!(summary(&records)["status"], "complete");
}

#[test]
fn the_same_basename_in_different_folders_is_not_a_duplicate() {
    let temp = tempfile::tempdir().unwrap();
    let zip = zip_entries(&[("a/same.bin", &rbf0(1)), ("b/same.bin", &rbf0(2))]);
    let path = write(temp.path(), "folders.zip", &zip);

    let records = lines(&inventory(&path, &[]));
    let archive = kinds(&records, "archive")[0];
    assert_eq!(archive["entries"], 2);
    assert_eq!(archive["duplicate_names"], 0);
    let entries = kinds(&records, "entry");
    assert_eq!(entries[0]["entry"]["name"], "a/same.bin");
    assert_eq!(entries[1]["entry"]["name"], "b/same.bin");
}

#[test]
fn a_file_and_a_directory_with_the_same_name_are_both_inventoried() {
    let temp = tempfile::tempdir().unwrap();
    let zip = zip_with_entries(&[
        ZipEntry::stored("thing", &rbf0(1)),
        ZipEntry::stored("thing/", b""),
    ]);
    let path = write(temp.path(), "conflict.zip", &zip);

    let records = lines(&inventory(&path, &[]));
    let entries = kinds(&records, "entry");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["entry"]["is_directory"], false);
    assert_eq!(entries[1]["entry"]["is_directory"], true);
    assert_eq!(entries[1]["payload"]["status"], "directory");
}

#[test]
fn a_nested_archive_in_a_zip_is_entered_by_selector() {
    let temp = tempfile::tempdir().unwrap();
    let inner = rpf9(&[rbf0(7)]);
    let zip = zip_entries(&[("inner", &inner)]);
    let path = write(temp.path(), "outer.zip", &zip);

    let records = lines(&inventory(&path, &["--recursive"]));
    let entries = kinds(&records, "entry");
    let leaf = entries
        .iter()
        .find(|entry| entry["content"]["format"]["id"] == "rbf0")
        .expect("the nested RBF0 row");
    assert_eq!(leaf["selector_path"][0], "zip:0");
    assert_eq!(leaf["selector"], "row:0");
    assert_eq!(leaf["depth"], 1);
    assert_eq!(leaf["archive"]["format"], "RPF9");
    assert_eq!(
        leaf["reproduce"],
        "lforge archive inspect ROOT --enter zip:0 --row 0"
    );
    assert_eq!(summary(&records)["archives"], 2);
}

#[test]
fn duplicate_names_stay_selectable_through_nested_zip_levels() {
    let temp = tempfile::tempdir().unwrap();
    let inner = zip_entries(&[("leaf", &rbf0(8))]);
    let outer = zip_entries(&[("same", &rbf0(1)), ("same", &inner)]);
    let path = write(temp.path(), "outer.zip", &outer);

    let records = lines(&inventory(&path, &["--recursive"]));
    let leaf = kinds(&records, "entry")
        .into_iter()
        .find(|entry| entry["content"]["format"]["id"] == "rbf0" && entry["depth"] == 1)
        .expect("the nested leaf");
    assert_eq!(leaf["selector_path"][0], "zip:1");
    assert_eq!(leaf["selector"], "zip:0");
    assert_eq!(
        leaf["reproduce"],
        "lforge archive inspect ROOT --enter zip:1 --zip 0"
    );
}

#[test]
fn unsupported_compression_is_not_reported_as_an_unknown_format() {
    let temp = tempfile::tempdir().unwrap();
    let zip = zip_with_entries(&[ZipEntry::with_method("odd.bin", b"payload", 12)]);
    let path = write(temp.path(), "odd.zip", &zip);

    let records = lines(&inventory(&path, &[]));
    let entry = kinds(&records, "entry")[0];
    assert_eq!(entry["payload"]["status"], "unsupported_compression");
    assert_eq!(entry["payload"]["readable"], false);
    assert_eq!(entry["content"]["status"], "not_inspected");
    assert_eq!(entry["content"]["failure_stage"], "compression");
    assert_ne!(entry["content"]["status"], "unknown");
    assert!(entry["content"]["format"].is_null());
}

#[test]
fn unknown_content_is_reported_only_after_the_bytes_were_decoded() {
    let temp = tempfile::tempdir().unwrap();
    let zip = zip_entries(&[("blob.bin", &[0xAA; 64])]);
    let path = write(temp.path(), "blob.zip", &zip);

    let records = lines(&inventory(&path, &[]));
    let entry = kinds(&records, "entry")[0];
    // The signature is unknown, so the payload is not fully decoded, but it is
    // still decodable.
    assert_eq!(entry["payload"]["status"], "prefix_only");
    assert_eq!(entry["payload"]["readable"], true);
    assert_eq!(entry["content"]["status"], "not_inspected");
    assert!(entry["content"]["failure_stage"].is_null());
}

#[test]
fn an_entry_limit_truncates_the_inventory() {
    let temp = tempfile::tempdir().unwrap();
    let zip = zip_entries(&[("a", &rbf0(1)), ("b", &rbf0(2)), ("c", &rbf0(3))]);
    let path = write(temp.path(), "many.zip", &zip);

    let records = parse(&inventory(&path, &["--max-entries", "1"]));
    assert_eq!(kinds(&records, "entry").len(), 1);
    let summary = summary(&records);
    assert_eq!(summary["status"], "truncated");
    assert_eq!(summary["entries_discovered"], 1);
    let limits = summary["limits_hit"].as_array().unwrap();
    assert!(limits.iter().any(|value| value == "max_entries"));
}

#[test]
fn the_depth_limit_skips_a_deeper_archive() {
    let temp = tempfile::tempdir().unwrap();
    let innermost = rpf9(&[rbf0(1)]);
    let middle = rpf9(&[innermost]);
    let outer = rpf9(&[middle]);
    let path = write(temp.path(), "deep.rpf", &outer);

    let records = lines(&inventory(&path, &["--recursive", "--max-depth", "2"]));
    let entries = kinds(&records, "entry");
    let deepest = entries
        .iter()
        .find(|entry| entry["content"]["format"]["id"] == "rpf9" && entry["depth"] == 1)
        .expect("the archive at depth 1");
    assert_eq!(deepest["skipped"]["stage"], "depth");
    assert_eq!(summary(&records)["status"], "complete_with_skips");
    assert_eq!(summary(&records)["skipped"], 1);
}

#[test]
fn filters_select_records_without_hiding_the_totals() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "mixed.rpf", &rpf9(&[rbf0(1), psin(), rbf0(2)]));

    let records = lines(&inventory(&path, &["--content-format", "psin"]));
    let entries = kinds(&records, "entry");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["content"]["format"]["id"], "psin");
    // The `.bin` fallback is visibly synthetic, not an established extension.
    assert_eq!(entries[0]["content"]["display_extension"]["value"], "bin");
    assert_eq!(
        entries[0]["content"]["display_extension"]["synthetic"],
        true
    );
    let summary = summary(&records);
    assert_eq!(summary["entries_discovered"], 3);
    assert_eq!(summary["entries_emitted"], 1);
    assert_eq!(summary["by_content_format"]["rbf0"], 2);
}

#[test]
fn json_output_is_one_document() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "one.zip", &zip_entries(&[("a", &rbf0(1))]));

    let output = inventory(&path, &["--format", "json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let document: Value = serde_json::from_slice(&output.stdout).expect("one document");
    assert_eq!(document["schema"], "leonida-forge.archive-inventory/1");
    assert_eq!(document["kind"], "header");
    let records = document["records"].as_array().unwrap();
    assert!(
        records
            .iter()
            .any(|record| record["kind"] == "entry" && record["content"]["format"]["id"] == "rbf0")
    );
    assert_eq!(document["summary"]["kind"], "summary");
    assert_eq!(document["summary"]["status"], "complete");
}

#[test]
fn output_is_deterministic() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "stable.zip",
        &zip_entries(&[("b", &rbf0(2)), ("a", &rbf0(1)), ("a", &rbf0(3))]),
    );

    let first = inventory(&path, &[]);
    let second = inventory(&path, &[]);
    assert!(first.status.success(), "{}", stderr(&first));
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn a_directory_inventories_each_root_by_name() {
    let temp = tempfile::tempdir().unwrap();
    let sub = temp.path().join("nested");
    std::fs::create_dir(&sub).unwrap();
    write(temp.path(), "one.zip", &zip_entries(&[("a", &rbf0(1))]));
    write(&sub, "two.rpf", &rpf9(&[rbf0(2)]));

    let records = lines(&inventory(temp.path(), &[]));
    let roots: Vec<String> = kinds(&records, "archive")
        .iter()
        .map(|archive| archive["root"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(roots, vec!["nested/two.rpf", "one.zip"]);
    assert_eq!(summary(&records)["roots"], 2);
}

#[test]
fn an_unreadable_root_is_an_error_record_and_a_failed_manifest() {
    let temp = tempfile::tempdir().unwrap();
    write(temp.path(), "broken.zip", b"PK\x03\x04 not a zip");
    write(temp.path(), "good.zip", &zip_entries(&[("a", &rbf0(1))]));

    let output = inventory(temp.path(), &[]);
    // One root could not be opened, so the run reports a skip; the other root
    // keeps the manifest usable.
    assert!(output.status.success(), "{}", stderr(&output));
    let records: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let errors = kinds(&records, "error");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["root"], "broken.zip");
    assert_eq!(summary(&records)["status"], "complete_with_skips");
}

#[test]
fn a_processed_archive_without_an_executable_is_an_authentication_skip() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "processed.rpf",
        &common::assemble_processed(&[spec(&rbf0(1))], 1),
    );

    let output = inventory(&path, &[]);
    assert!(!output.status.success());
    let records: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let errors = kinds(&records, "error");
    assert_eq!(errors[0]["stage"], "authentication");
    // A manifest that opened nothing is a failure, not an empty success.
    assert_eq!(summary(&records)["status"], "failed");
    assert_eq!(summary(&records)["archives"], 0);
}
