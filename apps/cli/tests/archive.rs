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
