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
    lines(output)
}

/// The records of a run that is expected to fail: a run that stopped at a limit
/// or could not read an archive still writes its summary.
fn failed_records(output: &Output) -> Vec<Value> {
    assert!(!output.status.success(), "the run should have failed");
    lines(output)
}

fn lines(output: &Output) -> Vec<Value> {
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
    // The `PSIN` row is typed 0, so it was a declared-archive candidate. The
    // bytes did not open as an archive: that is a rejected candidate, not a
    // failure to read an archive, and the run still succeeds.
    assert!(
        summary["coverage"]["rejected_archive_candidates"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert_eq!(summary["completion"]["failed_archives"], 0);
    assert_eq!(summary["completion"]["complete"], true);
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

    let records = failed_records(&census(&path, &["--max-entries", "1"]));
    let summary = summary(&records);
    assert_eq!(summary["entries"], 1);
    assert_eq!(summary["stopped"], "max_entries");
    assert_eq!(summary["completion"]["complete"], false);
    assert_eq!(summary["completion"]["stopped"], "max_entries");
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
fn a_declared_extension_and_a_payload_extension_stay_apart() {
    let temp = tempfile::tempdir().unwrap();
    // A document under an unregistered type: the payload establishes `xml`.
    let mut document = spec(b"<?xml version=\"1.0\"?><root><a/></root>");
    document.type_id = 255;
    // The same bytes under a registered type: the type declares its extension.
    let mut typed = spec(b"<?xml version=\"1.0\"?><root><a/></root>");
    typed.type_id = 88;
    let path = write(
        temp.path(),
        "documents.rpf",
        &assemble(&[document, typed], &[]),
    );

    let records = records(&census(&path, &[]));
    let summary = summary(&records);
    assert_eq!(summary["entries"], 2);
    let combinations = summary["combinations"].as_array().unwrap();
    let by_provenance = |provenance: &str| {
        combinations
            .iter()
            .find(|combination| combination["extension_provenance"] == provenance)
            .unwrap_or_else(|| panic!("no combination with provenance {provenance}"))
    };
    assert_eq!(by_provenance("payload")["extension"], "xml");
    assert_eq!(by_provenance("payload")["entries"], 1);
    assert_eq!(by_provenance("native")["extension"], "zsm");
    assert_eq!(by_provenance("native")["entries"], 1);
}

#[test]
fn every_entry_has_one_outcome_in_the_summary() {
    let temp = tempfile::tempdir().unwrap();
    let mut document = spec(b"<?xml version=\"1.0\"?><root><a/></root>");
    document.type_id = 255;
    let mut unknown = spec(&[0u8; 24]);
    unknown.type_id = 255;
    let mut archive_row = spec(&archive(&psin()));
    archive_row.type_id = 0;
    let path = write(
        temp.path(),
        "outcomes.rpf",
        &assemble(&[document, unknown, archive_row], &[]),
    );

    let records = records(&census(&path, &[]));
    let summary = summary(&records);
    let outcomes = summary["outcomes"].as_object().expect("outcomes");
    let total: u64 = outcomes.values().map(|value| value.as_u64().unwrap()).sum();
    // The counts add up to every entry, so no entry is left without an outcome.
    assert_eq!(total, summary["entries"].as_u64().unwrap());
    assert_eq!(outcomes["identified"], 1);
    assert_eq!(outcomes["unresolved"], 1);
    // A magic-only archive match is a partial identification.
    assert_eq!(outcomes["partially-identified"], 1);
}

#[test]
fn an_unreadable_root_is_a_failure_record() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "broken.rpf", &[0u8; 128]);

    let output = census(&path, &[]);
    // A run in which a root could not be opened did not do what was asked, so
    // it fails even though it wrote a summary.
    let records = failed_records(&output);
    let summary = summary(&records);
    assert_eq!(summary["archives"], 0);
    assert_eq!(summary["entries"], 0);
    assert_eq!(summary["failures"].as_array().unwrap().len(), 1);
    assert_eq!(summary["completion"]["complete"], false);
    assert_eq!(summary["completion"]["failed_archives"], 1);
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

    let stopped = failed_records(&census(
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
    let stopped = failed_records(&census(
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

#[test]
fn a_root_name_prefixes_every_chain_and_identity() {
    let temp = tempfile::tempdir().unwrap();
    let inner = assemble(&[spec(&psin())], &[]);
    let mut row = spec(&inner);
    row.type_id = 0;
    let path = write(
        temp.path(),
        "core_bvh4.rpf",
        &assemble(&[row, spec(&psin())], &[]),
    );

    let records = records(&census(
        &path,
        &["--recursive", "--root-name", "pack/core_bvh4/core_bvh4.rpf"],
    ));
    let summary = summary(&records);
    // Two roots that share a basename stay distinct: the identity is the path
    // relative to the installation, not the file name.
    assert_eq!(summary["root"], "pack/core_bvh4/core_bvh4.rpf");
    let nested = summary["combinations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|combination| combination["identification"] == "format:psin")
        .expect("the nested row");
    assert!(
        nested["samples"]
            .as_array()
            .unwrap()
            .iter()
            .any(|sample| sample["chain"] == "pack/core_bvh4/core_bvh4.rpf!0!0"),
        "the chain carries the installation-relative path"
    );
}

#[test]
fn a_type_reports_the_archives_that_hold_it_exactly() {
    let temp = tempfile::tempdir().unwrap();
    // Three nested archives, each holding one row of type 88 with a different
    // header shape, so no single combination is present in more than one
    // archive. A count taken from the largest combination would answer one;
    // the exact count is three.
    let mut rows = Vec::new();
    for word in [0x0000_0123u32, 0x0000_0000, 0x5000_0000] {
        let mut payload = vec![0u8; 8];
        payload.extend_from_slice(&0x5000_0310u64.to_le_bytes());
        payload.extend_from_slice(&word.to_le_bytes());
        payload.extend_from_slice(&word.to_le_bytes());
        let mut inner = spec(&payload);
        inner.type_id = 88;
        let mut outer = spec(&assemble(&[inner], &[]));
        outer.type_id = 0;
        rows.push(outer);
    }
    let path = write(temp.path(), "spread.rpf", &assemble(&rows, &[]));

    let records = records(&census(&path, &["--recursive"]));
    let summary = summary(&records);
    let resources = summary["types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["type"] == 88)
        .expect("the resource type");
    assert_eq!(resources["entries"], 3);
    assert_eq!(resources["archives"], 3);
    // The combinations really are apart, or the test would prove nothing.
    let per_combination: u64 = summary["combinations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|combination| combination["type"] == 88)
        .map(|combination| combination["archive_count"].as_u64().unwrap())
        .sum();
    assert_eq!(per_combination, 3);
    let largest = summary["combinations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|combination| combination["type"] == 88)
        .map(|combination| combination["archive_count"].as_u64().unwrap())
        .max()
        .unwrap();
    assert_eq!(largest, 1);
}

#[test]
fn a_metadata_pass_reports_entries_as_not_probed() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(
        temp.path(),
        "metadata.rpf",
        &assemble(&[spec(&psin()), spec(&[0u8; 24])], &[]),
    );

    let records = records(&census(&path, &["--metadata-only"]));
    let summary = summary(&records);
    assert_eq!(summary["entries"], 2);
    assert_eq!(summary["metadata_only"], true);
    assert_eq!(summary["coverage"]["entries_probed"], 0);
    // Nothing was read, so nothing was blocked and nothing was identified.
    assert_eq!(summary["outcomes"]["not-probed"], 2);
    assert_eq!(summary["outcomes"]["blocked"], Value::Null);
    assert_eq!(summary["completion"]["complete"], true);
}

#[test]
fn a_completed_census_is_published_only_once_it_is_finished() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "atomic.rpf", &assemble(&[spec(&psin())], &[]));
    let target = temp.path().join("out.jsonl");

    let output = census(
        &path,
        &["--output", target.to_str().unwrap(), "--overwrite"],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("\"record\":\"summary\""));

    // The run writes beside the target and renames: no partial file is left.
    let parts = std::fs::read_dir(temp.path())
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".part"))
        .count();
    assert_eq!(parts, 0);

    // A run that stopped still publishes its summary, because what it counted
    // is evidence, but it fails so a caller cannot take it for a complete one.
    let stopped = census(
        &path,
        &[
            "--output",
            target.to_str().unwrap(),
            "--overwrite",
            "--max-entries",
            "0",
        ],
    );
    assert!(!stopped.status.success());
    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("\"stopped\":\"max_entries\""));
}

#[test]
fn a_journal_with_a_truncated_last_record_takes_the_next_append() {
    let temp = tempfile::tempdir().unwrap();
    let path = write(temp.path(), "torn.rpf", &assemble(&[spec(&psin())], &[]));
    let log = temp.path().join("run.journal.jsonl");
    // A run killed between a record's bytes and its newline.
    std::fs::write(&log, "{\"identity\":\"run-1\",\"archive\":\"torn.rpf!9\"").unwrap();

    let records = records(&census(&path, &strings(&journalled(&log, "run-1"))));
    assert_eq!(summary(&records)["entries"], 1);

    let text = std::fs::read_to_string(&log).unwrap();
    let complete: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("\"complete\""))
        .collect();
    assert_eq!(complete.len(), 1, "the new record is readable: {text}");
    let record: Value = serde_json::from_str(complete[0]).expect("a whole record");
    assert_eq!(record["complete"], true);
    assert_eq!(record["tally"]["entries"], 1);
}
