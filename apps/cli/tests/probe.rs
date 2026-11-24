//! CLI stability tests for `archive probe`. Synthetic PE and archive bytes
//! only; no game file is used.

use std::process::{Command, Output};

fn lforge(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lforge"))
        .args(args)
        .output()
        .expect("failed to run lforge")
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn align(value: usize, to: usize) -> usize {
    value.div_ceil(to) * to
}

/// A minimal PE32+ image with one read-only section.
fn minimal_pe() -> Vec<u8> {
    let optional_start = 0x58usize;
    let optional_size = 0xF0usize;
    let table_start = optional_start + optional_size;
    let raw = align(table_start + 40, 0x200);
    let mut bytes = vec![0u8; raw + 0x200];
    bytes[0..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3C, 0x40);
    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x44, 0x8664);
    put_u16(&mut bytes, 0x46, 1);
    put_u16(&mut bytes, 0x54, optional_size as u16);
    put_u16(&mut bytes, 0x56, 0x0022);
    put_u16(&mut bytes, optional_start, 0x20B);
    put_u64(&mut bytes, optional_start + 24, 0x1_4000_0000);
    put_u32(&mut bytes, optional_start + 32, 0x1000);
    put_u32(&mut bytes, optional_start + 36, 0x200);
    put_u32(&mut bytes, optional_start + 56, 0x2000);
    put_u16(&mut bytes, optional_start + 68, 3);
    put_u32(&mut bytes, optional_start + 108, 0);

    let section = table_start;
    bytes[section..section + 8].copy_from_slice(b".rdata\0\0");
    put_u32(&mut bytes, section + 8, 0x200);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x200);
    put_u32(&mut bytes, section + 20, 0x200);
    put_u32(&mut bytes, section + 36, 0x4000_0040);
    bytes
}

/// A header that selects no static pass.
fn not_applicable_archive() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x40];
    bytes[..4].copy_from_slice(b"9FPR");
    put_u32(&mut bytes, 0x04, 0x40);
    put_u32(&mut bytes, 0x08, 0x40);
    bytes[0x2C] = 1;
    bytes[0x2D] = 1;
    bytes
}

fn write(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, bytes).unwrap();
    file
}

fn path(file: &tempfile::NamedTempFile) -> &str {
    file.path().to_str().unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

#[test]
fn probe_json_is_stable_without_a_static_pass() {
    let archive = write(&not_applicable_archive());
    let executable = write(&minimal_pe());
    let output = lforge(&[
        "archive",
        "probe",
        path(&archive),
        "--executable",
        path(&executable),
        "--json",
    ]);
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(!stdout.contains(path(&archive)));
    assert!(!stdout.contains(path(&executable)));

    let value = json(&output);
    assert_eq!(value["format"], "RPF9");
    assert_eq!(value["probe"]["outcome"], "not_applicable");
    assert_eq!(value["probe"]["authentication"], "not performed");
    assert_eq!(value["probe"]["archive"]["selector"], 0);
    assert_eq!(value["probe"]["archive"]["static_pass"], false);
    assert_eq!(value["probe"]["stages"]["executable"]["status"], "ok");
    assert_eq!(
        value["probe"]["stages"]["registry"]["status"],
        "not_attempted"
    );
    assert_eq!(
        value["probe"]["stages"]["a_table"]["status"],
        "not_attempted"
    );
}

#[test]
fn probe_reports_an_unsupported_executable() {
    let archive = write(&not_applicable_archive());
    let executable = write(b"not a PE image");
    let output = lforge(&[
        "archive",
        "probe",
        path(&archive),
        "--executable",
        path(&executable),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(!stdout.contains(path(&archive)));
    assert!(!stdout.contains(path(&executable)));

    let value = json(&output);
    assert_eq!(value["probe"]["outcome"], "executable_unsupported");
    assert_eq!(value["probe"]["authentication"], "not performed");
    assert!(value["probe"]["archive"].is_null());
    assert_eq!(value["probe"]["stages"]["executable"]["status"], "failed");
    assert_eq!(
        value["probe"]["stages"]["registry"]["status"],
        "not_attempted"
    );
}
