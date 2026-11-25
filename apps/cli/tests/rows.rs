//! `archive ls`, `archive search` and `archive manifest` against synthetic
//! archives. No game files are used.

mod common;

use std::fs;

use common::{assemble, lforge, spec, write_archive};
use lforge_rage9::rpf::names::{hash64, joaat};
use serde_json::Value;

fn archive(dir: &std::path::Path) -> std::path::PathBuf {
    let mut first = spec(b"inner archive bytes");
    first.type_id = 0;
    first.hash = Some(hash64(b"packs/item"));
    let mut second = spec(b"readme contents");
    second.type_id = 255;
    second.key = Some(joaat(b"readme"));
    let mut third = spec(b"unnamed payload");
    third.type_id = 0;
    third.hash = Some(hash64(b"unnamed"));
    let path = write_archive(dir, "rows.rpf", &assemble(&[first, second, third], &[]));
    fs::write(dir.join("rows.rpf.names.txt"), "packs/item.rpf\nreadme\n").unwrap();
    path
}

fn json(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        common::stderr(output)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is JSON")
}

#[test]
fn lists_rows_with_names_types_and_readability() {
    let temp = tempfile::tempdir().unwrap();
    let path = archive(temp.path());
    let value = json(&lforge(&[
        "archive",
        "ls",
        path.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(value["schema"], "leonida-forge.native-list/1");
    assert_eq!(value["total"], 3);
    assert_eq!(value["returned"], 3);
    assert_eq!(value["authentication"]["status"], "not_applicable");
    let rows = value["rows"].as_array().unwrap();
    assert_eq!(rows[0]["schema"], "leonida-forge.native-row/1");
    assert_eq!(rows[0]["type_id"], 0);
    assert_eq!(rows[0]["extension"], "rpf");
    assert_eq!(rows[0]["namespace"], "hash64");
    assert_eq!(rows[0]["name"]["status"], "resolved");
    assert_eq!(rows[0]["name"]["candidates"][0]["name"], "packs/item.rpf");
    assert_eq!(rows[0]["contents"]["readable"], true);
    assert_eq!(rows[1]["type_id"], 255);
    assert_eq!(rows[1]["namespace"], "key32");
    assert_eq!(rows[1]["name"]["status"], "resolved");
    assert_eq!(rows[2]["name"]["status"], "unresolved");
    // 64-bit values are strings, so nothing loses precision.
    let hash = rows[0]["name_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 18, "{hash}");
    assert_eq!(hash, format!("0x{:016X}", hash64(b"packs/item")));
    assert_eq!(rows[1]["name_key"], format!("0x{:08X}", joaat(b"readme")));
}

#[test]
fn pagination_bounds_the_listing() {
    let temp = tempfile::tempdir().unwrap();
    let path = archive(temp.path());
    let value = json(&lforge(&[
        "archive",
        "ls",
        path.to_str().unwrap(),
        "--offset",
        "1",
        "--limit",
        "1",
        "--json",
    ]));
    assert_eq!(value["total"], 3);
    assert_eq!(value["offset"], 1);
    assert_eq!(value["returned"], 1);
    assert_eq!(value["truncated"], true);
    assert_eq!(value["rows"][0]["row"], 1);
}

#[test]
fn searches_by_name_hash_type_extension_and_readability() {
    let temp = tempfile::tempdir().unwrap();
    let path = archive(temp.path());
    let path = path.to_str().unwrap();

    let by_name = json(&lforge(&[
        "archive", "search", path, "--name", "README", "--json",
    ]));
    assert_eq!(by_name["matched"], 1);
    assert_eq!(by_name["rows"][0]["row"], 1);

    let by_hash = json(&lforge(&[
        "archive",
        "search",
        path,
        "--hash",
        &format!("{:#018X}", hash64(b"packs/item")),
        "--json",
    ]));
    assert_eq!(by_hash["matched"], 1);
    assert_eq!(by_hash["rows"][0]["row"], 0);

    let by_type = json(&lforge(&[
        "archive", "search", path, "--type", "0", "--json",
    ]));
    assert_eq!(by_type["matched"], 2);

    let by_extension = json(&lforge(&[
        "archive",
        "search",
        path,
        "--extension",
        "RPF",
        "--json",
    ]));
    assert_eq!(by_extension["matched"], 2);

    let unreadable = json(&lforge(&[
        "archive",
        "search",
        path,
        "--readable",
        "false",
        "--json",
    ]));
    assert_eq!(unreadable["matched"], 0);
    let readable = json(&lforge(&[
        "archive",
        "search",
        path,
        "--readable",
        "true",
        "--json",
    ]));
    assert_eq!(readable["matched"], 3);
}

#[test]
fn searches_a_directory_of_archives_and_reports_skips() {
    let temp = tempfile::tempdir().unwrap();
    archive(temp.path());
    fs::write(temp.path().join("broken.rpf"), b"not an archive").unwrap();
    let value = json(&lforge(&[
        "archive",
        "search",
        temp.path().to_str().unwrap(),
        "--name",
        "item",
        "--json",
    ]));
    assert_eq!(value["archives"], 2);
    assert_eq!(value["matched"], 1);
    assert_eq!(value["rows"][0]["archive"], "rows.rpf");
    assert_eq!(value["skipped"].as_array().unwrap().len(), 1);
}

#[test]
fn manifest_formats_are_deterministic_and_versioned() {
    let temp = tempfile::tempdir().unwrap();
    let path = archive(temp.path());
    let output = temp.path().join("manifest.jsonl");
    let run = lforge(&[
        "archive",
        "manifest",
        path.to_str().unwrap(),
        "--format",
        "jsonl",
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "{}", common::stderr(&run));
    let text = fs::read_to_string(&output).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4, "one header and three rows");
    let header: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(header["schema"], "leonida-forge.native-manifest/1");
    assert_eq!(header["kind"], "header");
    assert_eq!(header["rows"], 3);
    let row: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(row["kind"], "row");
    assert_eq!(row["schema"], "leonida-forge.native-row/1");
    assert!(row.get("name_hash").is_some());
    // No payload bytes and no cryptographic state are written.
    assert!(row.get("payload").is_none());
    assert!(row.get("cipher").is_none());

    // Without --overwrite the existing manifest is preserved.
    let again = lforge(&[
        "archive",
        "manifest",
        path.to_str().unwrap(),
        "--format",
        "jsonl",
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!again.status.success());
    assert_eq!(fs::read_to_string(&output).unwrap(), text);

    let json_output = temp.path().join("manifest.json");
    let run = lforge(&[
        "archive",
        "manifest",
        path.to_str().unwrap(),
        "--format",
        "json",
        "--output",
        json_output.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "{}", common::stderr(&run));
    let document: Value = serde_json::from_slice(&fs::read(&json_output).unwrap()).unwrap();
    assert_eq!(document["schema"], "leonida-forge.native-manifest/1");
    assert_eq!(document["rows"].as_array().unwrap().len(), 3);
    assert_eq!(document["rows"][0]["row"], 0);
}

#[test]
fn rejects_a_bad_manifest_format_and_bad_hash() {
    let temp = tempfile::tempdir().unwrap();
    let path = archive(temp.path());
    let bad_format = lforge(&[
        "archive",
        "manifest",
        path.to_str().unwrap(),
        "--format",
        "xml",
    ]);
    assert!(!bad_format.status.success());
    let bad_hash = lforge(&[
        "archive",
        "search",
        path.to_str().unwrap(),
        "--hash",
        "0x12",
    ]);
    assert!(!bad_hash.status.success());
    assert!(common::stderr(&bad_hash).contains("hexadecimal"));
}
