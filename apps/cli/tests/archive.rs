use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde_json::Value;

fn lforge(args: &[&str], app_data: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lforge"))
        .args(args)
        .env("APPDATA", app_data)
        .output()
        .expect("failed to run lforge")
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// A header with the table of contents ending at 0x80, then `parts` at
/// aligned offsets starting there.
fn write_rpf(path: &Path, parts: &[Vec<u8>]) {
    let mut bytes = vec![0u8; 0x40];
    bytes[..4].copy_from_slice(b"9FPR");
    bytes[4..8].copy_from_slice(&0x80u32.to_le_bytes());
    bytes.resize(0x80, 0x3C);
    for part in parts {
        bytes.extend_from_slice(part);
        bytes.resize(bytes.len().next_multiple_of(16), 0);
    }
    std::fs::write(path, bytes).unwrap();
}

fn sample(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("sample.rpf");
    let xml = b"<?xml version=\"1.0\"?><data>example</data>";
    let chunk: Vec<u8> = (0..0x10000u32).map(|i| (i % 7) as u8 + b'a').collect();
    write_rpf(
        &path,
        &[
            zlib(xml),
            vec![0xEE; 20],
            zlib(&chunk),
            zlib(b"rest of the chunked file"),
        ],
    );
    path
}

fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn info_reports_header_and_recovery_summary() {
    let temp = tempfile::tempdir().unwrap();
    let path = sample(temp.path());
    let path = path.to_str().unwrap();
    let info = json(&lforge(
        &["archive", "info", path, "--json", "--no-cache"],
        temp.path(),
    ));
    assert_eq!(info["format"], "RPF9");
    assert_eq!(info["toc_end"], 0x80);
    assert_eq!(info["data_start"], 0x80);
    assert_eq!(info["table_of_contents"], "encrypted, not read");
    assert_eq!(info["index_source"], "scan");
    assert_eq!(info["streams"], 3);
    assert_eq!(info["entries"], 2);
    assert_eq!(info["unrecovered_regions"], 1);
    assert!(info["header"].as_str().unwrap().starts_with("39 46 50 52"));
    let kinds = info["by_kind"].as_array().unwrap();
    assert!(kinds.contains(&serde_json::json!({
        "kind": "xml", "status": "complete", "count": 1, "size": 41
    })));
    assert!(!temp.path().join("Leonida Forge").exists());

    let text = lforge(&["archive", "info", path, "--no-cache"], temp.path());
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(stdout.contains("format:      RPF9"));
    assert!(stdout.contains("table of contents is encrypted"));
}

#[test]
fn list_distinguishes_entries_and_unrecovered_regions() {
    let temp = tempfile::tempdir().unwrap();
    let path = sample(temp.path());
    let path = path.to_str().unwrap();
    let listing = json(&lforge(
        &["archive", "list", path, "--json", "--no-cache"],
        temp.path(),
    ));
    let entries = listing["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["id"], "0x0000000080");
    assert_eq!(entries[0]["kind"], "xml");
    assert_eq!(entries[0]["status"], "complete");
    assert_eq!(entries[0]["streams"], 1);
    assert_eq!(entries[1]["kind"], "text");
    assert_eq!(entries[1]["status"], "unverified");
    assert_eq!(entries[1]["streams"], 2);
    assert_eq!(entries[1]["size"], 0x10000 + 24);
    for entry in entries {
        for key in ["offset", "size", "compressed_size"] {
            assert!(entry[key].is_u64(), "{key}");
        }
    }
    let regions = listing["unrecovered_regions"].as_array().unwrap();
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0]["size"], 32);
    assert!(listing["note"].as_str().unwrap().contains("encrypted"));

    let text = lforge(&["archive", "list", path, "--no-cache"], temp.path());
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(stdout.contains("0x0000000080 xml        complete"));
    assert!(stdout.contains("unrecovered"));
}

#[test]
fn an_archive_without_streams_is_not_reported_as_empty() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("opaque.rpf");
    write_rpf(&path, &[vec![0x99; 100]]);
    let path = path.to_str().unwrap();
    let listing = json(&lforge(
        &["archive", "list", path, "--json", "--no-cache"],
        temp.path(),
    ));
    assert!(listing["entries"].as_array().unwrap().is_empty());
    let note = listing["note"].as_str().unwrap();
    assert!(note.contains("does not mean the archive is empty"));
    let text = lforge(&["archive", "info", path, "--no-cache"], temp.path());
    assert!(
        String::from_utf8(text.stdout)
            .unwrap()
            .contains("No zlib streams were found")
    );
}

#[test]
fn a_second_run_uses_the_cache_in_app_data() {
    let temp = tempfile::tempdir().unwrap();
    let path = sample(temp.path());
    let path = path.to_str().unwrap();
    let first = json(&lforge(&["archive", "info", path, "--json"], temp.path()));
    assert_eq!(first["index_source"], "scan");
    let cache = temp.path().join("Leonida Forge").join("cache").join("rpf");
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 1);
    let second = json(&lforge(&["archive", "info", path, "--json"], temp.path()));
    assert_eq!(second["index_source"], "cache");
    assert_eq!(second["entries"], first["entries"]);
}

#[test]
fn rejects_files_that_are_not_rpf9_archives() {
    let temp = tempfile::tempdir().unwrap();
    let zip = temp.path().join("pack.rpf");
    std::fs::write(&zip, b"PK\x03\x04 not an rpf").unwrap();
    let bad_header = temp.path().join("bad.rpf");
    let mut bytes = vec![0u8; 0x40];
    bytes[..4].copy_from_slice(b"9FPR");
    bytes[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
    std::fs::write(&bad_header, bytes).unwrap();
    let missing = temp.path().join("missing.rpf");

    for (path, message) in [
        (&zip, "not an RPF9 archive"),
        (&bad_header, "invalid RPF9 header"),
        (&missing, "cannot open"),
    ] {
        let output = lforge(
            &["archive", "list", path.to_str().unwrap(), "--no-cache"],
            temp.path(),
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(message), "{stderr}");
    }
}

/// A resource at 0x1010 that declares two graphics pages but has only one.
fn partial_resource(dir: &Path) -> (std::path::PathBuf, Vec<u64>) {
    let path = dir.join("resource.rpf");
    let mut system = vec![0u8; 0x100];
    system[8..16].copy_from_slice(&0x5000_00C0u64.to_le_bytes());
    system[0xC8] = 1;
    system[0xC9] = 2;
    let mut bytes = vec![0u8; 0x40];
    bytes[..4].copy_from_slice(b"9FPR");
    bytes[4..8].copy_from_slice(&0x40u32.to_le_bytes());
    bytes.resize(0x1010, 0);
    let mut offsets = Vec::new();
    for page in [system, vec![0xAB; 0x2_0000]] {
        bytes.resize(bytes.len().next_multiple_of(16), 0);
        offsets.push(bytes.len() as u64);
        bytes.extend_from_slice(&zlib(&page));
    }
    bytes.resize(bytes.len().next_multiple_of(16), 0);
    std::fs::write(&path, bytes).unwrap();
    (path, offsets)
}

#[test]
fn reports_reconstructed_resources() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = partial_resource(temp.path());
    let path = path.to_str().unwrap();

    let info = json(&lforge(
        &["archive", "info", path, "--json", "--no-cache"],
        temp.path(),
    ));
    assert_eq!(info["resources"]["count"], 1);
    assert_eq!(info["resources"]["partial"], 1);
    assert_eq!(info["resources"]["graphics_size"], 0x2_0000);

    let listing = json(&lforge(
        &["archive", "list", path, "--json", "--no-cache"],
        temp.path(),
    ));
    let entries = listing["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "resource");
    assert_eq!(entries[0]["status"], "partial");
    assert_eq!(entries[0]["resource"]["pages"].as_array().unwrap().len(), 2);

    let id = format!("0x{:X}", offsets[0]);
    let report = json(&lforge(
        &["archive", "resource", path, &id, "--json", "--no-cache"],
        temp.path(),
    ));
    assert_eq!(report["offset"], offsets[0]);
    assert_eq!(report["status"], "partial");
    assert_eq!(report["system_size"], 0x100);
    assert_eq!(report["page_map"]["graphics_pages"], 2);
    assert_eq!(report["pages"][1]["segment"], "graphics");
    assert_eq!(report["pages"][1]["offset"], offsets[1]);
    assert_eq!(report["issues"][0], "1 of 2 graphics pages found");

    // A page id leads to its resource.
    let by_page = json(&lforge(
        &[
            "archive",
            "resource",
            path,
            &offsets[1].to_string(),
            "--json",
            "--no-cache",
        ],
        temp.path(),
    ));
    assert_eq!(by_page, report);

    let text = lforge(
        &["archive", "resource", path, &id, "--no-cache"],
        temp.path(),
    );
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(stdout.contains("status:      partial"), "{stdout}");
    assert!(stdout.contains("warning: 1 of 2 graphics pages found"));

    let missing = lforge(
        &["archive", "resource", path, "0x40", "--no-cache"],
        temp.path(),
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        String::from_utf8(missing.stderr)
            .unwrap()
            .contains("no resource")
    );
}

#[test]
fn refuses_a_drawable_walk_of_a_resource_without_the_chain() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = partial_resource(temp.path());
    let id = format!("0x{:X}", offsets[0]);
    let output = lforge(
        &[
            "archive",
            "resource",
            path.to_str().unwrap(),
            &id,
            "--drawable",
            "--no-cache",
        ],
        temp.path(),
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("does not have the drawable chain shape"),
        "{stderr}"
    );
}

/// Decoded metadata with two rows, then their payloads: row 0 raw, named
/// `item`, row 1 compressed, named `packed`. `selector` is `hdr[0x2E]`.
fn decoded_rpf(path: &Path, selector: u8) {
    use lforge_rage9::rpf::metadata::keys;
    use lforge_rage9::rpf::names::hash64;

    let mut bytes = vec![0u8; 0xC8];
    let put = |bytes: &mut Vec<u8>, at: usize, value: &[u8]| {
        bytes[at..at + value.len()].copy_from_slice(value);
    };
    put(&mut bytes, 0, b"9FPR");
    put(&mut bytes, 0x04, &0xC8u32.to_le_bytes());
    put(&mut bytes, 0x08, &0xC8u32.to_le_bytes());
    put(&mut bytes, 0x1A, &1u16.to_le_bytes());
    put(&mut bytes, 0x1C, &0x10u32.to_le_bytes());
    put(&mut bytes, 0x20, &2u16.to_le_bytes());
    put(&mut bytes, 0x24, &2u32.to_le_bytes());
    bytes[0x2C] = 1;
    bytes[0x2D] = 1;
    bytes[0x2E] = selector;
    // One A record for sub-block 2, then the descriptors at 0x60.
    put(&mut bytes, 0x40, &2u16.to_le_bytes());
    for (column, (key, pool_offset, width)) in
        [(keys::NAME_HASH, 0u32, 8u16), (keys::LOCATION_A, 16, 16)]
            .into_iter()
            .enumerate()
    {
        let at = 0x60 + column * 24;
        put(&mut bytes, at, &key.to_le_bytes());
        put(&mut bytes, at + 0x0C, &pool_offset.to_le_bytes());
        put(&mut bytes, at + 0x10, &width.to_le_bytes());
    }
    // Cells at 0x90, row-major; each row uses its own value.
    put(&mut bytes, 0x90, &[0, 0, 1, 1]);
    put(&mut bytes, 0x98, &hash64(b"item").to_le_bytes());
    put(&mut bytes, 0xA0, &hash64(b"packed").to_le_bytes());
    for (row, (offset16, mode)) in [(0x10u32, 0u64), (0x11, 1)].into_iter().enumerate() {
        let at = 0xA8 + row * 16;
        put(&mut bytes, at, &1u32.to_le_bytes());
        put(&mut bytes, at + 4, &offset16.to_le_bytes());
        put(&mut bytes, at + 8, &(16 | (mode << 56)).to_le_bytes());
    }
    bytes.resize(0x100, 0);
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.extend_from_slice(&[0x22; 16]);
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn metadata_lists_decoded_entries_with_names() {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("decoded.rpf");
    decoded_rpf(&archive, 0);
    let candidates = temp.path().join("names.txt");
    std::fs::write(
        &candidates,
        "dev:/x/item.rpf\r\ndev:/x/ITEM.rpf\n\ndev:/x/missing.rpf\ndev:/x/model.ydr\n",
    )
    .unwrap();
    let archive = archive.to_str().unwrap();
    let candidates = candidates.to_str().unwrap();
    let args = [
        "archive",
        "metadata",
        archive,
        "--entries",
        "--candidates",
        candidates,
        "--archive-path",
        "dev:/x/sample.rpf",
    ];

    let report = json(&lforge(&[&args[..], &["--json"]].concat(), temp.path()));
    assert_eq!(report["state"], "decoded");
    assert_eq!(report["transformed"], false);
    assert_eq!(report["verified"], false);
    assert_eq!(report["authentication"]["status"], "not_applicable");
    assert_eq!(report["prefix"]["rows"], 2);
    assert_eq!(report["regions"]["descriptors"]["start"], 0x60);
    assert_eq!(report["passes"]["static_pass"], Value::Null);
    let entries = &report["entries"];
    assert_eq!(entries["rows"], 2);
    assert_eq!(entries["names"]["candidates"], 4);
    assert_eq!(entries["names"]["unresolved_candidates"], 1);
    assert_eq!(entries["names"]["named_rows"], 1);
    let listed = entries["listed"].as_array().unwrap();
    assert_eq!(listed[0]["layout"], "A");
    assert_eq!(listed[0]["payload_offset"], 0x100);
    assert_eq!(listed[0]["read_source"], "main");
    let name_hash = listed[0]["name_hash"].as_str().unwrap();
    assert!(name_hash.starts_with("0x"));
    assert_eq!(name_hash.len(), 18);
    assert_eq!(listed[0]["raw"]["available"], true);
    assert_eq!(
        listed[0]["names"],
        serde_json::json!(["dev:/x/item.rpf", "dev:/x/ITEM.rpf"])
    );
    assert_eq!(listed[0]["ambiguous"], false);
    assert_eq!(listed[1]["mode"], 1);
    assert_eq!(listed[1]["raw"]["reason"], "stored compressed");
    assert_eq!(listed[1]["names"], serde_json::json!([]));
    assert_eq!(listed[1]["name_key"], Value::Null);

    let text = lforge(&args, temp.path());
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(stdout.contains("state:       decoded"), "{stdout}");
    assert!(
        stdout.contains("dev:/x/item.rpf, dev:/x/ITEM.rpf"),
        "{stdout}"
    );
    assert!(stdout.contains("stored compressed"), "{stdout}");

    let limited = json(&lforge(
        &[
            "archive",
            "metadata",
            archive,
            "--entries",
            "--limit",
            "1",
            "--json",
        ],
        temp.path(),
    ));
    assert_eq!(limited["entries"]["listed"].as_array().unwrap().len(), 1);
    assert_eq!(limited["entries"]["names"]["entries"], 0);
    assert!(
        limited["entries"]["names"]["builtin"]["entries"]
            .as_u64()
            .unwrap()
            > 0
    );
    let text = lforge(
        &["archive", "metadata", archive, "--entries", "--limit", "1"],
        temp.path(),
    );
    assert!(
        String::from_utf8(text.stdout)
            .unwrap()
            .contains("1 more rows")
    );
}

#[test]
fn metadata_explains_why_entries_are_unavailable() {
    let temp = tempfile::tempdir().unwrap();
    let processed = temp.path().join("processed.rpf");
    decoded_rpf(&processed, 9);
    let report = json(&lforge(
        &[
            "archive",
            "metadata",
            processed.to_str().unwrap(),
            "--entries",
            "--json",
        ],
        temp.path(),
    ));
    assert_eq!(report["state"], "stored");
    assert_eq!(report["passes"]["static_pass"]["cipher_type"], 16);
    assert_eq!(report["passes"]["static_pass"]["algorithm"], "0x10 (CBC)");
    assert!(
        report["passes"]["archive_pass"]
            .as_str()
            .unwrap()
            .starts_with("unknown")
    );
    let reason = report["entries"]["reason"].as_str().unwrap();
    assert!(reason.contains("processed before use"), "{reason}");
    assert!(reason.contains("it is encrypted"), "{reason}");
    assert!(reason.contains("key is not available"), "{reason}");
    assert!(report["entries"].get("listed").is_none());

    // A header whose table layout is invalid is still reported.
    let path = sample(temp.path());
    let report = json(&lforge(
        &["archive", "metadata", path.to_str().unwrap(), "--json"],
        temp.path(),
    ));
    assert_eq!(report["state"], "unreadable");
    assert!(
        report["entries"]["reason"]
            .as_str()
            .unwrap()
            .contains("primary area")
    );
}

#[test]
fn metadata_reports_declared_and_unconfirmed_name_mappings() {
    use lforge_rage9::rpf::names::hash64;

    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("mapped.rpf");
    decoded_rpf(&archive, 0);
    let hash = hash64(b"item");
    let names = temp.path().join("names.txt");
    std::fs::write(&names, format!("hash64:{hash:016X}\tItem.ydr\n")).unwrap();
    let archive_text = archive.to_str().unwrap();
    let names_text = names.to_str().unwrap();

    let report = json(&lforge(
        &[
            "archive",
            "metadata",
            archive_text,
            "--entries",
            "--name-file",
            names_text,
            "--json",
        ],
        temp.path(),
    ));
    let summary = &report["entries"]["names"];
    assert_eq!(summary["entries"], 1);
    assert_eq!(summary["candidates"], 0);
    assert_eq!(summary["mappings"], 1);
    assert_eq!(summary["verified_mappings"], 1);
    assert_eq!(summary["unconfirmed_mappings"], 0);
    assert_eq!(summary["named_rows"], 1);
    assert_eq!(summary["resolved_rows"], 1);
    assert_eq!(summary["unresolved_rows"], 1);
    let listed = report["entries"]["listed"].as_array().unwrap();
    // The original key keeps its 16-digit hexadecimal form.
    assert_eq!(listed[0]["name_hash"], format!("0x{hash:016X}"));
    let resolution = &listed[0]["name_resolution"];
    assert_eq!(resolution["status"], "resolved");
    assert_eq!(resolution["ambiguous"], false);
    assert_eq!(resolution["namespace"], "hash64");
    assert_eq!(resolution["candidates"][0]["name"], "Item.ydr");
    assert_eq!(resolution["candidates"][0]["provenance"], "user_mapping");
    assert_eq!(resolution["candidates"][0]["algorithm"], "hash64");
    assert_eq!(resolution["candidates"][0]["verified"], true);
    assert_eq!(listed[1]["name_resolution"]["status"], "unresolved");
    assert_eq!(
        listed[1]["name_resolution"]["candidates"],
        Value::Array(vec![])
    );

    // A name next to the key that does not produce it stays unconfirmed.
    std::fs::write(&names, format!("hash64:{hash:016X}\tNotTheName\n")).unwrap();
    let report = json(&lforge(
        &[
            "archive",
            "metadata",
            archive_text,
            "--entries",
            "--name-file",
            names_text,
            "--json",
        ],
        temp.path(),
    ));
    assert_eq!(report["entries"]["names"]["verified_mappings"], 0);
    assert_eq!(report["entries"]["names"]["unconfirmed_mappings"], 1);
    let candidate = &report["entries"]["listed"][0]["name_resolution"]["candidates"][0];
    assert_eq!(candidate["name"], "NotTheName");
    assert_eq!(candidate["verified"], false);
    assert_eq!(candidate["provenance"], "user_mapping");

    // Without a local table only the built-in mappings apply, and none of them
    // has this key.
    let report = json(&lforge(
        &["archive", "metadata", archive_text, "--entries", "--json"],
        temp.path(),
    ));
    let names = &report["entries"]["names"];
    assert_eq!(names["entries"], 0);
    assert_eq!(names["mappings"], 0);
    assert!(names["builtin"]["entries"].as_u64().unwrap() > 0);
    let resolution = &report["entries"]["listed"][0]["name_resolution"];
    assert_eq!(resolution["status"], "unresolved");
    assert_eq!(resolution["namespace"], "hash64");
    assert_eq!(resolution["candidates"], Value::Array(vec![]));

    // Without an explicit file the sidecar next to the archive is used.
    let sidecar = temp.path().join("mapped.rpf.names.txt");
    std::fs::write(&sidecar, "item.rpf\n").unwrap();
    let report = json(&lforge(
        &["archive", "metadata", archive_text, "--entries", "--json"],
        temp.path(),
    ));
    assert_eq!(report["entries"]["names"]["sidecar"], true);
    assert_eq!(report["entries"]["names"]["candidates"], 1);
    assert_eq!(report["entries"]["names"]["named_rows"], 1);
    let resolution = &report["entries"]["listed"][0]["name_resolution"];
    assert_eq!(resolution["candidates"][0]["name"], "item.rpf");
    assert_eq!(resolution["candidates"][0]["provenance"], "candidate_path");
}

#[test]
fn metadata_rejects_invalid_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let archive = temp.path().join("decoded.rpf");
    decoded_rpf(&archive, 0);
    let candidates = temp.path().join("names.txt");
    std::fs::write(&candidates, "x\n").unwrap();
    let archive = archive.to_str().unwrap();
    let candidates = candidates.to_str().unwrap();
    for (args, message) in [
        (
            vec![
                "--candidates",
                candidates,
                "--mount-prefix",
                "no/separator/end",
            ],
            "not a mount prefix",
        ),
        (vec!["--candidates", "missing.txt"], "cannot read"),
    ] {
        let output = lforge(
            &[&["archive", "metadata", archive][..], &args].concat(),
            temp.path(),
        );
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(message), "{stderr}");
    }
    for args in [
        vec!["--mount-prefix", "a/"],
        vec!["--candidates", candidates, "--extension", "ydr"],
        vec!["--candidates", candidates, "--extension", "ydr=300"],
        vec!["--candidates", candidates, "--extension", "ydr=7:other"],
    ] {
        let output = lforge(
            &[&["archive", "metadata", archive][..], &args].concat(),
            temp.path(),
        );
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
    let output = lforge(&["archive", "metadata", "missing.rpf"], temp.path());
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn a_psin_stream_is_named_psin_not_pso() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("psin.rpf");
    write_rpf(&path, &[zlib(b"PSIN\x00\x00\x00\x00synthetic payload")]);
    let path = path.to_str().unwrap();

    let listing = json(&lforge(
        &["archive", "list", path, "--json", "--no-cache"],
        temp.path(),
    ));
    assert_eq!(listing["schema"], "leonida-forge.archive-list/1");
    let entries = listing["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "psin");
    let text = serde_json::to_string(&listing)
        .unwrap()
        .to_ascii_lowercase();
    assert!(!text.contains("\"pso\""), "{text}");

    let info = json(&lforge(
        &["archive", "info", path, "--json", "--no-cache"],
        temp.path(),
    ));
    assert_eq!(info["schema"], "leonida-forge.archive-info/1");
    assert_eq!(info["by_kind"][0]["kind"], "psin");
}
