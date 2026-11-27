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
    // Type 0 is registered as `rpf`, so the engine's extension is what the
    // classification applies even though the payload is a `PSIN`.
    assert_eq!(psin_row["extension"], "rpf");
    // The `PSIN` recogniser walks the payload's framing from the head.
    assert_eq!(psin_row["structure"], "verified");
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
fn a_resource_header_is_a_container_and_the_type_names_the_extension() {
    let temp = tempfile::tempdir().unwrap();
    let mut row = spec(&resource());
    row.type_id = 88;
    let path = write(temp.path(), "resource.rpf", &assemble(&[row], &[]));

    let records = records(&census(&path, &[]));
    let resource = combination(summary(&records), 88, "resource:segment-5");
    assert_eq!(resource["capability"], "resource");
    // Type 88 is registered as `zsm`, so the extension is known without
    // reading the page map the header points at.
    assert_eq!(resource["extension"], "zsm");
    assert_eq!(resource["structure"], "unknown");
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
    assert_eq!(entry["classification"]["extension"], "rpf");
    assert_eq!(entry["classification"]["extension_provenance"], "native");
    assert_eq!(entry["classification"]["extension_verified"], true);
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

/// The journal lines written so far.
fn journal(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("a journal record"))
        .collect()
}

fn journalled(path: &Path, identity: &str) -> Vec<String> {
    let journal = path.to_str().unwrap().to_string();
    let identity = identity.to_string();
    vec![
        "--journal".to_string(),
        journal,
        "--journal-identity".to_string(),
        identity,
    ]
}

fn with(journal: &[String], extra: &[&str]) -> Vec<String> {
    let mut all = journal.to_vec();
    all.extend(extra.iter().map(|value| value.to_string()));
    all
}

fn strings(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[test]
fn a_journalled_archive_is_not_counted_twice() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "resumed.rpf",
        &assemble(&[spec(&psin()), spec(&resource())], &[]),
    );
    let log = temp.path().join("run.journal.jsonl");
    let args = journalled(&log, "run-1");

    let first = records(&census(&path, &strings(&with(&args, &[]))));
    let second = records(&census(&path, &strings(&with(&args, &[]))));
    assert_eq!(summary(&first)["entries"], 2);
    assert_eq!(summary(&second)["entries"], 2);
    assert_eq!(summary(&first)["resumed_archives"], 0);
    assert_eq!(summary(&second)["resumed_archives"], 1);
    assert_eq!(
        summary(&first)["combinations"],
        summary(&second)["combinations"]
    );

    let lines = journal(&log);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["complete"], true);
    assert_eq!(lines[0]["archive"], "resumed.rpf");
    assert_eq!(lines[0]["tally"]["entries"], 2);
}

#[test]
fn a_journal_from_another_identity_is_not_this_run_progress() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "crossed.rpf",
        &assemble(&[spec(&psin()), spec(&resource())], &[]),
    );
    let log = temp.path().join("run.journal.jsonl");

    let first = census(&path, &strings(&journalled(&log, "build-a")));
    let second = census(&path, &strings(&journalled(&log, "build-b")));
    // A different identity means the archive is walked again, and counted
    // once: the earlier record is not this run's progress.
    assert_eq!(first.stdout, second.stdout);
    let lines = journal(&log);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["identity"], "build-b");
}

#[test]
fn an_archive_that_stopped_short_is_walked_again() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "short.rpf",
        &assemble(&[spec(&psin()), spec(&resource())], &[]),
    );
    let log = temp.path().join("run.journal.jsonl");
    let args = journalled(&log, "run-1");

    let stopped = records(&census(
        &path,
        &strings(&with(&args, &["--max-entries", "1"])),
    ));
    assert_eq!(summary(&stopped)["stopped"], "max_entries");
    assert_eq!(journal(&log)[0]["complete"], false);

    // The same run continues with room to finish: the partial record is not
    // reused as a completed archive.
    let resumed = records(&census(&path, &strings(&with(&args, &[]))));
    assert_eq!(summary(&resumed)["entries"], 2);
    assert_eq!(summary(&resumed)["stopped"], Value::Null);
    assert_eq!(journal(&log).last().unwrap()["complete"], true);
}

#[test]
fn a_finished_nested_archive_survives_an_interrupted_root() {
    let temp = tempfile::tempdir().unwrap();
    let inner = assemble(&[spec(&psin()), spec(&psin())], &[]);
    let mut archive_row = spec(&inner);
    archive_row.type_id = 0;
    let path = write(
        temp.path(),
        "nested.rpf",
        &assemble(&[archive_row, spec(&psin()), spec(&resource())], &[]),
    );
    let log = temp.path().join("run.journal.jsonl");
    let args = journalled(&log, "run-1");

    // The nested archive finishes, then the entry limit stops the root.
    let stopped = records(&census(
        &path,
        &strings(&with(&args, &["--recursive", "--max-entries", "4"])),
    ));
    assert_eq!(summary(&stopped)["stopped"], "max_entries");
    assert_eq!(summary(&stopped)["entries"], 4);
    let names: Vec<String> = journal(&log)
        .iter()
        .map(|line| line["archive"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["nested.rpf!0", "nested.rpf"]);
    assert_eq!(journal(&log)[0]["complete"], true);
    assert_eq!(journal(&log)[1]["complete"], false);

    // The resumed run reuses the finished nested archive and finishes the
    // root: five rows in total, each counted once.
    let resumed = records(&census(&path, &strings(&with(&args, &["--recursive"]))));
    assert_eq!(summary(&resumed)["entries"], 5);
    assert_eq!(summary(&resumed)["archives"], 2);
}
