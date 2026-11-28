//! The metadata document export of `lforge archive inspect`, on a synthetic
//! RPF9 archive holding one `RBF0` payload. No game files are used.

mod common;

use common::*;
use serde_json::Value;

fn u16v(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn u32v(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn token(code: u8, index: u16) -> Vec<u8> {
    u16v(u16::from(code) << 12 | index)
}

fn named(name: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(name.len() as u16);
    bytes.extend_from_slice(name);
    bytes
}

/// A versioned RBF0 document: `screen` with one `kind` attribute, one text
/// node, one integer and one nested `row`.
fn document() -> Vec<u8> {
    let mut row_body = token(1, 3);
    row_body.extend_from_slice(&named(b"count"));
    row_body.extend_from_slice(&3_i64.to_le_bytes());
    let mut row = token(0, 2);
    row.extend_from_slice(&named(b"row"));
    row.extend_from_slice(&u32v(0));
    row.extend_from_slice(&u16v(0));
    row.extend_from_slice(&row_body);
    row.extend_from_slice(&u16v(0xFFFF));

    let mut body = u16v(0xFFFD);
    body.extend_from_slice(&u32v(0x05));
    body.extend_from_slice(b"note\0");
    body.extend_from_slice(&row);

    let mut attribute = token(6, 1);
    attribute.extend_from_slice(&named(b"kind"));
    attribute.extend_from_slice(&u16v(8));
    attribute.extend_from_slice(b"uiScreen");

    let mut root = token(0, 0);
    root.extend_from_slice(&named(b"screen"));
    root.extend_from_slice(&u32v(0));
    root.extend_from_slice(&u16v(1));
    root.extend_from_slice(&attribute);
    root.extend_from_slice(&body);
    root.extend_from_slice(&u16v(0xFFFF));

    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&u16v(0xFFFB));
    bytes.extend_from_slice(&u16v(1));
    bytes.extend_from_slice(&root);
    bytes
}

fn archive(dir: &std::path::Path) -> std::path::PathBuf {
    let rows = vec![Spec {
        type_id: 11,
        ..spec(&document())
    }];
    let bytes = assemble(&rows, &[]);
    write_archive(dir, "rbf0.rpf", &bytes)
}

#[test]
fn an_rbf0_row_exports_the_shared_metadata_document() {
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
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let export: Value = serde_json::from_slice(&std::fs::read(&output_json).unwrap()).unwrap();
    assert_eq!(export["schema"], "leonida-forge.rbf0-document/1");
    // The provenance names the canonical resource, not the row chain.
    assert_eq!(export["source"]["format"], "rbf0");
    assert_eq!(export["source"]["status"], "decoded");
    assert_eq!(export["source"]["row"], 0);
    let display = export["source"]["resource"]["display"]
        .as_str()
        .expect("a canonical display");
    assert!(
        display.starts_with("rbf0.rpf!"),
        "the resource is named by the archive's file name: {display}"
    );
    let document = &export["document"];
    assert_eq!(document["format"], "rbf0");
    assert_eq!(document["status"], "decoded");
    assert_eq!(document["root"]["name"], "screen");
    assert_eq!(
        document["root"]["attributes"][0]["name"], "kind",
        "the attribute keeps the name the document defines"
    );
    assert_eq!(document["root"]["children"][0]["text"], "note");
    assert_eq!(document["root"]["children"][1]["name"], "row");
    assert_eq!(
        document["root"]["children"][1]["children"][0]["value"]["integer"],
        3
    );
    // The decoder's own limits are reported, not hidden.
    assert!(document["limitations"].as_array().unwrap().len() >= 4);
}

#[test]
fn an_rbf0_row_exports_xml_that_names_itself_as_generated() {
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
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let xml = std::fs::read_to_string(&output_xml).unwrap();
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
    assert!(xml.contains("generator=\"leonida-forge\""));
    // The index is written beside a name, so a name is never the only record.
    assert!(xml.contains("<element index=\"0\" name=\"screen\""));
    assert!(xml.contains("<element index=\"2\" name=\"row\""));
    assert!(xml.contains(">uiScreen</value>"));
    assert!(xml.contains(">note</text>"));
}

#[test]
fn an_rbf0_row_is_inspectable_without_writing_a_document() {
    let temp = tempfile::tempdir().unwrap();
    let archive = archive(temp.path());

    let output = lforge(&[
        "archive",
        "inspect",
        archive.to_str().unwrap(),
        "--row",
        "0",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["format"]["id"], "rbf0");
    assert_eq!(report["structure"]["valid"], true);
    assert_eq!(report["structure"]["body"]["objects"], 2);
    assert_eq!(report["structure"]["body"]["text_nodes"], 1);
    assert_eq!(report["failure_stage"], Value::Null);
}
