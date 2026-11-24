//! `lforge archive recover`, on synthetic RPF9 archives built in memory. No
//! game files or data extracted from them are used.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde_json::Value;

fn lforge(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lforge"))
        .args(args)
        .output()
        .expect("failed to run lforge")
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// A header whose table of contents ends at 0x80, filled with opaque bytes as
/// an encrypted one would be, then `parts` at aligned offsets starting there.
/// Returns the offset of each part.
fn write_rpf(path: &Path, parts: &[Vec<u8>]) -> Vec<u64> {
    let mut bytes = vec![0u8; 0x40];
    bytes[..4].copy_from_slice(b"9FPR");
    bytes[4..8].copy_from_slice(&0x80u32.to_le_bytes());
    bytes.resize(0x80, 0x3C);
    let mut offsets = Vec::new();
    for part in parts {
        bytes.resize(bytes.len().next_multiple_of(16), 0);
        offsets.push(bytes.len() as u64);
        bytes.extend_from_slice(part);
    }
    bytes.resize(bytes.len().next_multiple_of(16), 0);
    std::fs::write(path, bytes).unwrap();
    offsets
}

fn recover(args: &[&str]) -> Output {
    let mut full = vec!["archive", "recover"];
    full.extend_from_slice(args);
    full.push("--no-cache");
    lforge(&full)
}

fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const XML: &[u8] = b"<?xml version=\"1.0\"?><data>example</data>";

/// XML (complete, signed), a 64 KiB printable chunk joined to a trailing
/// stream (unverified text), and a region of non-zlib bytes between them.
fn sample(dir: &Path) -> (std::path::PathBuf, Vec<u64>) {
    let path = dir.join("sample.rpf");
    let chunk: Vec<u8> = (0..0x10000u32).map(|i| (i % 7) as u8 + b'a').collect();
    let offsets = write_rpf(
        &path,
        &[
            zlib(XML),
            vec![0xEE; 20],
            zlib(&chunk),
            zlib(b"rest of the chunked file"),
        ],
    );
    (path, offsets)
}

#[test]
fn lists_recovery_candidates_with_observed_and_inferred_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = sample(temp.path());
    let path = path.to_str().unwrap();

    let report = json(&recover(&[path, "--list", "--json"]));
    assert_eq!(report["table_of_contents"], "encrypted, not read");
    assert!(report["note"].as_str().unwrap().contains("not a complete"));
    assert_eq!(report["names"], "none recovered; ids are archive offsets");
    let candidates = report["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 2);

    let xml = &candidates[0];
    assert_eq!(xml["id"], "0x0000000080");
    assert_eq!(xml["observed"]["offset"], offsets[0]);
    assert_eq!(xml["observed"]["start"], offsets[0]);
    assert_eq!(xml["observed"]["compression"], "zlib");
    assert_eq!(xml["observed"]["streams"], 1);
    assert_eq!(xml["observed"]["decoded_size"], XML.len());
    assert_eq!(xml["observed"]["signature"], "xml");
    assert_eq!(xml["inferred"]["kind"], "xml");
    assert_eq!(xml["inferred"]["status"], "complete");
    assert_eq!(xml["exportable"], true);
    assert!(xml["observed"]["compressed_size"].is_u64());
    assert!(xml["observed"]["end"].as_u64().unwrap() > offsets[0]);

    // The chunked file: two streams, no file signature, inferred unverified.
    let chunked = &candidates[1];
    assert_eq!(chunked["observed"]["offset"], offsets[2]);
    assert_eq!(chunked["observed"]["streams"], 2);
    assert_eq!(chunked["observed"]["decoded_size"], 0x10000 + 24);
    assert_eq!(chunked["observed"]["signature"], Value::Null);
    assert_eq!(chunked["inferred"]["kind"], "text");
    assert_eq!(chunked["inferred"]["status"], "unverified");

    let text = recover(&[path, "--list"]);
    let out = stdout(&text);
    let xml_line = out
        .lines()
        .find(|line| line.starts_with("0x0000000080"))
        .unwrap();
    let cols: Vec<&str> = xml_line.split_whitespace().collect();
    assert_eq!(
        &cols[..4],
        ["0x0000000080", "xml", "yes", "complete"],
        "{out}"
    );
    let text_line = out
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some("text"))
        .unwrap();
    let cols: Vec<&str> = text_line.split_whitespace().collect();
    assert_eq!((cols[2], cols[3]), ("-", "unverified"), "{out}");
}

#[test]
fn identifiers_are_stable_across_independent_scans() {
    let temp = tempfile::tempdir().unwrap();
    let (path, _) = sample(temp.path());
    let path = path.to_str().unwrap();
    // --no-cache forces a fresh scan each run, so equal output proves the ids
    // come from the deterministic scan, not from a reused index.
    let first = recover(&[path, "--list", "--json"]);
    let second = recover(&[path, "--list", "--json"]);
    assert_eq!(first.stdout, second.stdout);
}

#[test]
fn exports_a_selected_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = sample(temp.path());
    let out = temp.path().join("out.xml");
    let id = format!("0x{:X}", offsets[0]);

    let output = recover(&[
        path.to_str().unwrap(),
        "--id",
        &id,
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), XML);
    let text = stdout(&output);
    assert!(
        text.contains("recovered 0x0000000080 (xml, complete)"),
        "{text}"
    );
    assert!(text.contains("41 bytes"), "{text}");
    // A complete candidate carries no caveat.
    assert!(!text.contains("note:"), "{text}");
}

#[test]
fn exports_a_chunked_candidate_whole() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = sample(temp.path());
    let out = temp.path().join("chunked.bin");
    let id = offsets[2].to_string();

    let output = recover(&[
        path.to_str().unwrap(),
        "--id",
        &id,
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let mut expected: Vec<u8> = (0..0x10000u32).map(|i| (i % 7) as u8 + b'a').collect();
    expected.extend_from_slice(b"rest of the chunked file");
    assert_eq!(std::fs::read(&out).unwrap(), expected);
    // An unverified candidate is exported with a conservative note.
    let text = stdout(&output);
    assert!(text.contains("unverified"), "{text}");
    assert!(text.contains("note:"), "{text}");
}

#[test]
fn false_positive_without_a_signature_is_reported_as_unverified() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("binary.rpf");
    // A valid zlib stream of non-printable bytes: the scanner cannot tell a
    // whole file from a coincidental stream, so it must not claim either.
    let data: Vec<u8> = (0..300u32).map(|i| (i % 256) as u8).collect();
    let offsets = write_rpf(&path, &[zlib(&data)]);

    let report = json(&recover(&[path.to_str().unwrap(), "--list", "--json"]));
    let candidate = &report["candidates"][0];
    assert_eq!(candidate["observed"]["offset"], offsets[0]);
    assert_eq!(candidate["observed"]["signature"], Value::Null);
    assert_eq!(candidate["inferred"]["kind"], "binary");
    assert_eq!(candidate["inferred"]["status"], "unverified");

    // Exporting it still works, but the note reports the uncertainty.
    let out = temp.path().join("fp.bin");
    let output = recover(&[
        path.to_str().unwrap(),
        "--id",
        &offsets[0].to_string(),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), data);
    assert!(stdout(&output).contains("note:"));
}

#[test]
fn an_archive_without_streams_has_no_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("opaque.rpf");
    write_rpf(&path, &[vec![0x99; 200]]);
    let path = path.to_str().unwrap();

    let report = json(&recover(&[path, "--list", "--json"]));
    assert!(report["candidates"].as_array().unwrap().is_empty());
    assert!(
        report["note"]
            .as_str()
            .unwrap()
            .contains("not mean the archive is empty")
    );
    let text = recover(&[path, "--list"]);
    assert!(
        stdout(&text).contains("no recovery candidates"),
        "{}",
        stdout(&text)
    );
}

#[test]
fn rejects_ids_that_are_not_candidates_and_writes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = sample(temp.path());
    let path = path.to_str().unwrap();
    let out = temp.path().join("nope.bin");

    // An unknown id.
    let output = recover(&[path, "--id", "0xDEAD", "--output", out.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no recovery candidate"),
        "{}",
        stderr(&output)
    );
    assert!(!out.exists());

    // The region between the first two streams is not a candidate.
    let region = format!("0x{:X}", offsets[1]);
    let output = recover(&[path, "--id", &region, "--output", out.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("unrecovered region"),
        "{}",
        stderr(&output)
    );
    assert!(!out.exists());
}

#[test]
fn a_resource_page_id_points_to_the_whole_resource() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("resource.rpf");
    // One resource: a system page that declares one graphics page, then it.
    let mut system = vec![0u8; 0x100];
    system[8..16].copy_from_slice(&0x5000_00C0u64.to_le_bytes());
    system[0xC8] = 1;
    system[0xC9] = 1;
    let graphics: Vec<u8> = (0..0x3000u32).map(|i| (i % 251) as u8).collect();
    let mut bytes = vec![0u8; 0x40];
    bytes[..4].copy_from_slice(b"9FPR");
    bytes[4..8].copy_from_slice(&0x40u32.to_le_bytes());
    bytes.resize(0x1010, 0);
    let mut offsets = Vec::new();
    for page in [&system, &graphics] {
        bytes.resize(bytes.len().next_multiple_of(16), 0);
        offsets.push(bytes.len() as u64);
        bytes.extend_from_slice(&zlib(page));
    }
    bytes.resize(bytes.len().next_multiple_of(16), 0);
    std::fs::write(&path, bytes).unwrap();
    let path = path.to_str().unwrap();

    // The resource head is a candidate; exporting it writes system then graphics.
    let out = temp.path().join("res.bin");
    let output = recover(&[
        path,
        "--id",
        &offsets[0].to_string(),
        "--output",
        out.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), [system, graphics].concat());

    // The graphics page's own offset is not a candidate; the error points back.
    let out2 = temp.path().join("page.bin");
    let output = recover(&[
        path,
        "--id",
        &offsets[1].to_string(),
        "--output",
        out2.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("resource page"),
        "{}",
        stderr(&output)
    );
    assert!(!out2.exists());
}

#[test]
fn refuses_to_overwrite_without_the_flag() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = sample(temp.path());
    let out = temp.path().join("out.bin");
    std::fs::write(&out, b"existing content").unwrap();
    let id = offsets[0].to_string();

    let output = recover(&[
        path.to_str().unwrap(),
        "--id",
        &id,
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("already exists"),
        "{}",
        stderr(&output)
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"existing content");

    let output = recover(&[
        path.to_str().unwrap(),
        "--id",
        &id,
        "--output",
        out.to_str().unwrap(),
        "--overwrite",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), XML);
}

#[test]
fn a_failed_finalization_preserves_the_destination() {
    let temp = tempfile::tempdir().unwrap();
    let (path, offsets) = sample(temp.path());
    // The output path is an existing directory: the decode succeeds, but the
    // move into place cannot replace a directory, so it must fail without
    // removing the directory or leaving a temporary file behind.
    let out = temp.path().join("occupied");
    std::fs::create_dir(&out).unwrap();
    let id = offsets[0].to_string();

    let output = recover(&[
        path.to_str().unwrap(),
        "--id",
        &id,
        "--output",
        out.to_str().unwrap(),
        "--overwrite",
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(out.is_dir(), "the directory must be preserved");
    let leftovers: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name != "sample.rpf" && name != "occupied")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary file left behind: {leftovers:?}"
    );
}

#[test]
fn requires_a_mode_and_rejects_conflicting_arguments() {
    let temp = tempfile::tempdir().unwrap();
    let (path, _) = sample(temp.path());
    let path = path.to_str().unwrap();
    let out = temp.path().join("x.bin");
    let out = out.to_str().unwrap();

    // Neither --list nor --id.
    assert_eq!(lforge(&["archive", "recover", path]).status.code(), Some(2));
    // --id without --output.
    assert_eq!(
        lforge(&["archive", "recover", path, "--id", "0x80"])
            .status
            .code(),
        Some(2)
    );
    // --list together with an export argument.
    assert_eq!(
        lforge(&["archive", "recover", path, "--list", "--output", out])
            .status
            .code(),
        Some(2)
    );
}
