use std::process::{Command, Output};

fn lforge(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lforge"))
        .args(args)
        .output()
        .expect("failed to run lforge")
}

#[test]
fn info_json_is_valid_and_complete() {
    let output = lforge(&["info", "--json"]);
    assert!(output.status.success());

    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["name"], "Leonida Forge");
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    for key in ["os", "arch", "profile"] {
        assert!(info[key].as_str().is_some_and(|value| !value.is_empty()));
    }
}

#[test]
fn version_flag_prints_version() {
    let output = lforge(&["--version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim(),
        format!("lforge {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_command_fails_with_usage_error() {
    let output = lforge(&["unpack"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn missing_command_fails_with_usage_error() {
    let output = lforge(&[]);
    assert_eq!(output.status.code(), Some(2));
}

fn sample_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let mut bytes = b"LFG\0\x01\0\0\0".to_vec();
    bytes.extend_from_slice(&[0x20, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0x80, 0, 0, 0, 0x10, 0, 0, 0]);
    bytes.extend_from_slice(&[0, 0, 0x80, 0x3F, 0, 0, 0, 0]);
    bytes.extend_from_slice(b"Test\0\0\0\0");
    std::io::Write::write_all(&mut file, &bytes).unwrap();
    file
}

fn path(file: &tempfile::NamedTempFile) -> &str {
    file.path().to_str().unwrap()
}

#[test]
fn binary_info_json() {
    let file = sample_file();
    let output = lforge(&["binary", "info", path(&file), "--json"]);
    assert!(output.status.success());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["size"], 40);
    assert_eq!(
        info["signature"],
        "4C 46 47 00 01 00 00 00 20 00 00 00 00 00 00 00"
    );
    assert_eq!(info["sha256"].as_str().unwrap().len(), 64);
    assert!(info["modified"].is_string());

    let output = lforge(&["binary", "info", path(&file), "--json", "--no-hash"]);
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(info["sha256"].is_null());
}

#[test]
fn binary_info_of_empty_file() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let output = lforge(&["binary", "info", path(&file), "--json"]);
    assert!(output.status.success());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["size"], 0);
    assert_eq!(info["signature"], "");
    assert_eq!(
        info["sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn binary_dump_is_clamped_to_the_file() {
    let file = sample_file();
    let output = lforge(&[
        "binary",
        "dump",
        path(&file),
        "--offset",
        "0x18",
        "--length",
        "100",
        "--width",
        "8",
    ]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "00000018  00 00 80 3F 00 00 00 00  |...?....|\n\
         00000020  54 65 73 74 00 00 00 00  |Test....|\n"
    );
}

#[test]
fn binary_search_hex_and_text() {
    let file = sample_file();
    let output = lforge(&["binary", "search", path(&file), "--hex", "00 00 80 3f"]);
    assert!(output.status.success());
    assert_eq!(output.stdout, b"0x00000018\n");

    let output = lforge(&["binary", "search", path(&file), "--text", "Test", "--json"]);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["pattern"], "54 65 73 74");
    assert_eq!(result["matches"], serde_json::json!([32]));

    let output = lforge(&[
        "binary",
        "search",
        path(&file),
        "--hex",
        "00",
        "--offset",
        "4",
        "--limit",
        "2",
    ]);
    assert_eq!(output.stdout, b"0x00000005\n0x00000006\n");

    let output = lforge(&["binary", "search", path(&file), "--hex", "FF", "--json"]);
    assert!(output.status.success());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["matches"], serde_json::json!([]));
}

#[test]
fn binary_interpret_json() {
    let file = sample_file();
    let output = lforge(&[
        "binary",
        "interpret",
        path(&file),
        "--offset",
        "0x18",
        "--json",
    ]);
    assert!(output.status.success());
    let values: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values["offset"], 24);
    assert_eq!(values["uint32"], 0x3F80_0000);
    assert_eq!(values["float32"], 1.0);

    let output = lforge(&[
        "binary",
        "interpret",
        path(&file),
        "--offset",
        "37",
        "--endian",
        "big",
        "--json",
    ]);
    let values: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values["endian"], "big");
    assert_eq!(values["uint16"], 0);
    assert!(values["uint32"].is_null());
    assert!(values["float64"].is_null());
}

#[test]
fn binary_commands_report_errors() {
    let file = sample_file();
    for args in [
        &["binary", "search", path(&file), "--hex", "0G"][..],
        &["binary", "search", path(&file), "--hex", "ABC"],
        &["binary", "search", path(&file), "--text", ""],
        &["binary", "search", path(&file)],
        &["binary", "dump", path(&file), "--offset", "0x1_0"],
        &["binary", "dump", path(&file), "--width", "12"],
    ] {
        let output = lforge(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
    }

    let missing = file.path().with_extension("missing");
    for args in [
        &["binary", "info", missing.to_str().unwrap()][..],
        &["binary", "dump", path(&file), "--offset", "41"],
        &[
            "binary",
            "interpret",
            path(&file),
            "--offset",
            "0xFFFFFFFFFFFFFFFF",
        ],
    ] {
        let output = lforge(args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with("error: ")
        );
    }
}
