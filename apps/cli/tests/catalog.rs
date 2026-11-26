//! `lforge catalog extract` classification on synthetic archives.

mod common;

use std::fs;

use common::{assemble, lforge, spec, write_archive};
use serde_json::Value;

#[test]
fn excludes_nested_archives_before_the_row_limit() {
    let temp = tempfile::tempdir().unwrap();
    let mut nested = spec(b"9FPR nested archive bytes");
    nested.type_id = 0;
    let plain = spec(b"not a catalog document");
    let mut plain = plain;
    plain.type_id = 5;
    let path = write_archive(temp.path(), "catalog.rpf", &assemble(&[nested, plain], &[]));
    let observations = temp.path().join("observations.ndjson");
    let report = temp.path().join("report.json");
    let run = lforge(&[
        "catalog",
        "extract",
        path.to_str().unwrap(),
        "--output",
        observations.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--max-row-bytes",
        "64",
    ]);
    assert!(run.status.success(), "{}", common::stderr(&run));
    let document: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(document["status"], "complete");
    assert_eq!(document["counts"]["rows"], 2);
    assert_eq!(document["counts"]["decoded"], 1);
    assert_eq!(document["counts"]["excluded"], 1);
    assert_eq!(document["counts"]["notXml"], 1);
    assert_eq!(document["counts"]["tooLarge"], 0);
    assert_eq!(document["counts"]["unsupportedTransform"], 0);
    assert_eq!(fs::read_to_string(&observations).unwrap(), "");

    let small_limit = temp.path().join("report-small.json");
    let run = lforge(&[
        "catalog",
        "extract",
        path.to_str().unwrap(),
        "--output",
        observations.to_str().unwrap(),
        "--report",
        small_limit.to_str().unwrap(),
        "--max-row-bytes",
        "8",
    ]);
    assert!(run.status.success(), "{}", common::stderr(&run));
    let document: Value = serde_json::from_slice(&fs::read(&small_limit).unwrap()).unwrap();
    assert_eq!(document["status"], "complete");
    assert_eq!(document["counts"]["decoded"], 0);
    assert_eq!(document["counts"]["excluded"], 1);
    assert_eq!(document["counts"]["notXml"], 1);
    assert_eq!(document["counts"]["prefixOnly"], 1);
    assert_eq!(document["counts"]["tooLarge"], 0);
}
