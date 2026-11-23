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
