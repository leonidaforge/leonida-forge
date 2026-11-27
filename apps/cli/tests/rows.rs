//! `archive ls`, `archive search` and `archive manifest` against synthetic
//! archives. No game files are used.

mod common;

use std::fs;

use common::{Spec, assemble, lforge, spec, write_archive};
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
fn reports_the_payload_transform_cipher_descriptor() {
    let temp = tempfile::tempdir().unwrap();
    let mut descriptor = Vec::new();
    descriptor.extend_from_slice(&0x1000_002Eu32.to_le_bytes());
    descriptor.extend_from_slice(&0x11u16.to_le_bytes());
    descriptor.extend(0..16u8);
    let row = Spec {
        transform: true,
        transform_descriptor: Some(descriptor),
        ..spec(&[0x11; 48])
    };
    let path = write_archive(temp.path(), "transform.rpf", &assemble(&[row], &[]));
    let value = json(&lforge(&[
        "archive",
        "ls",
        path.to_str().unwrap(),
        "--json",
    ]));
    let row = &value["rows"][0];
    assert_eq!(row["payload_transform"], true);
    assert_eq!(row["contents"]["readable"], false);
    assert_eq!(row["contents"]["state"], "transform_key_missing");
    let cipher = &row["payload_cipher"];
    assert_eq!(cipher["type"], 0x11);
    assert_eq!(cipher["algorithm"], "0x11");
    assert_eq!(cipher["key_id"], "0x1000002E");
    assert_eq!(cipher["parameter"], "000102030405060708090a0b0c0d0e0f");
    assert_eq!(cipher["supported"], true);
}

#[test]
fn searches_by_payload_transform_state() {
    let temp = tempfile::tempdir().unwrap();
    let mut transformed = spec(b"transformed row");
    transformed.transform = true;
    let plain = spec(b"plain row");
    let path = write_archive(
        temp.path(),
        "transform-search.rpf",
        &assemble(&[transformed, plain], &[]),
    );
    let path = path.to_str().unwrap();

    let yes = json(&lforge(&[
        "archive",
        "search",
        path,
        "--transformed",
        "true",
        "--json",
    ]));
    assert_eq!(yes["matched"], 1);
    assert_eq!(yes["rows"][0]["row"], 0);
    assert_eq!(yes["rows"][0]["payload_transform"], true);

    let no = json(&lforge(&[
        "archive",
        "search",
        path,
        "--transformed",
        "false",
        "--json",
    ]));
    assert_eq!(no["matched"], 1);
    assert_eq!(no["rows"][0]["row"], 1);

    let all = json(&lforge(&["archive", "search", path, "--json"]));
    assert_eq!(all["matched"], 2);
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
    // The extension the application shows, and where it came from: the
    // archive's own type table, or the engine registry recovered from the
    // executable. Never a guess.
    assert!(
        matches!(
            rows[0]["extension_source"].as_str(),
            Some("archive" | "declared")
        ),
        "{}",
        rows[0]["extension_source"]
    );
    assert_eq!(rows[0]["namespace"], "hash64");
    assert_eq!(rows[0]["name"]["status"], "resolved");
    assert_eq!(rows[0]["name"]["candidates"][0]["name"], "packs/item.rpf");
    assert_eq!(rows[0]["contents"]["readable"], true);
    assert_eq!(rows[1]["type_id"], 255);
    assert_eq!(rows[1]["namespace"], "key32");
    // Type 255 is not registered: no extension is declared and none is
    // invented.
    assert_eq!(rows[1]["extension"], Value::Null);
    assert_eq!(rows[1]["extension_source"], Value::Null);
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
    // Companion discovery runs once per opened archive, not once per row.
    assert_eq!(readable["companions_resolved"], 1);
}

#[test]
fn hash_search_uses_only_the_class_column() {
    let temp = tempfile::tempdir().unwrap();
    // A row that stores both keys must not match through the column its type
    // class does not make authoritative.
    let mut hash_row = spec(b"hash row");
    hash_row.type_id = 0;
    hash_row.hash = Some(hash64(b"alpha"));
    hash_row.key = Some(joaat(b"beta"));
    let mut key_row = spec(b"key row");
    key_row.type_id = 11;
    key_row.hash = Some(hash64(b"gamma"));
    key_row.key = Some(joaat(b"delta"));
    let mut unknown_row = spec(b"unknown row");
    unknown_row.type_id = 5;
    unknown_row.hash = Some(hash64(b"epsilon"));
    unknown_row.key = Some(joaat(b"zeta"));
    let path = write_archive(
        temp.path(),
        "classes.rpf",
        &assemble(&[hash_row, key_row, unknown_row], &[]),
    );
    let path = path.to_str().unwrap();
    let search = |hash: String| {
        json(&lforge(&[
            "archive", "search", path, "--hash", &hash, "--json",
        ]))
    };

    let hash64_alpha = search(format!("{:#018X}", hash64(b"alpha")));
    assert_eq!(hash64_alpha["matched"], 1);
    assert_eq!(hash64_alpha["rows"][0]["row"], 0);

    // The 32-bit column of a hash64-class row is not authoritative.
    let key32_beta = search(format!("{:#010X}", joaat(b"beta")));
    assert_eq!(key32_beta["matched"], 0);

    // The 64-bit column of a key32-class row is not authoritative.
    let hash64_gamma = search(format!("{:#018X}", hash64(b"gamma")));
    assert_eq!(hash64_gamma["matched"], 0);

    let key32_delta = search(format!("{:#010X}", joaat(b"delta")));
    assert_eq!(key32_delta["matched"], 1);
    assert_eq!(key32_delta["rows"][0]["row"], 1);

    // An unknown class has no authoritative column at all.
    assert_eq!(
        search(format!("{:#018X}", hash64(b"epsilon")))["matched"],
        0
    );
    assert_eq!(search(format!("{:#010X}", joaat(b"zeta")))["matched"], 0);
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
