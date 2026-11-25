mod common;

use std::path::Path;

use common::{Spec, assemble, lforge, spec, write_archive};
use lforge_rage9::rpf::names::{hash64, joaat};
use serde_json::Value;

fn json(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn sample_archives(dir: &Path) {
    let asset = hash64(b"synthetic/asset");
    let readme = joaat(b"readme");
    write_archive(
        dir,
        "alpha.rpf",
        &assemble(
            &[
                Spec {
                    payload: b"before synthetic/asset.rpf after".to_vec(),
                    hash: Some(asset),
                    type_id: 0,
                    ..spec(&[])
                },
                Spec {
                    payload: b"readme.txt".to_vec(),
                    key: Some(readme),
                    type_id: 255,
                    ..spec(&[])
                },
                Spec {
                    payload: b"hidden synthetic/asset.rpf".to_vec(),
                    hash: Some(hash64(b"hidden/asset")),
                    type_id: 0,
                    transform: true,
                    ..spec(&[])
                },
            ],
            &[],
        ),
    );
    write_archive(
        dir,
        "beta.rpf",
        &assemble(
            &[Spec {
                payload: b"synthetic/asset.rpf".to_vec(),
                hash: Some(asset),
                type_id: 0,
                ..spec(&[])
            }],
            &[],
        ),
    );
    std::fs::write(dir.join("broken.rpf"), b"not an archive").unwrap();
}

#[test]
fn indexes_rows_across_archives_and_skips_broken_files() {
    let temp = tempfile::tempdir().unwrap();
    sample_archives(temp.path());
    let executable = temp.path().join("alpha.rpf");
    let report = json(&lforge(&[
        "names",
        "index",
        temp.path().to_str().unwrap(),
        "--executable",
        executable.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(report["indexed"], 2);
    assert_eq!(report["rows"], 4);
    assert_eq!(report["namespace_rows"]["hash64"], 3);
    assert_eq!(report["namespace_rows"]["key32"], 1);
    assert_eq!(report["unique_keys"]["hash64"], 2);
    assert_eq!(report["unique_keys"]["key32"], 1);
    assert_eq!(report["occurrences"], 4);
    assert_eq!(report["skipped"].as_array().unwrap().len(), 1);
    assert!(
        report["skipped"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("broken.rpf")
    );
}

#[test]
fn harvests_payload_text_and_exports_a_lut_that_resolves_again() {
    let temp = tempfile::tempdir().unwrap();
    sample_archives(temp.path());
    let executable = temp.path().join("alpha.rpf");
    let results = temp.path().join("results.jsonl");
    let report = json(&lforge(&[
        "names",
        "harvest",
        temp.path().to_str().unwrap(),
        "--executable",
        executable.to_str().unwrap(),
        "--sources",
        "payloads",
        "--output",
        results.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(report["archives"]["indexed"], 2);
    assert_eq!(report["payloads"]["examined"], 4);
    assert_eq!(report["payloads"]["skipped"], 1);
    assert!(
        report["matches"]["records"].as_u64().unwrap() >= 3,
        "{report}"
    );
    assert_eq!(report["matches"]["unique_keys"], 2);
    assert_eq!(report["matches"]["rows"], 3);

    let text = std::fs::read_to_string(&results).unwrap();
    let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
    assert!(lines.iter().all(|line| {
        let value: Value = serde_json::from_str(line).unwrap();
        value["kind"] == "match"
    }));
    let names: Vec<String> = lines
        .iter()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap();
            value["name"].as_str().unwrap().to_string()
        })
        .collect();
    assert!(names.iter().any(|name| name == "synthetic/asset.rpf"));
    assert!(names.iter().any(|name| name == "readme.txt"));

    let lut = temp.path().join("resolved.lut");
    let exported = json(&lforge(&[
        "names",
        "export",
        results.to_str().unwrap(),
        "--format",
        "lut",
        "--output",
        lut.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(exported["mappings"], 2);
    assert_eq!(exported["files"].as_array().unwrap().len(), 2);
    let hash64_lut = temp.path().join("resolved.hash64.lut");
    let key32_lut = temp.path().join("resolved.key32.lut");
    assert!(hash64_lut.is_file());
    assert!(key32_lut.is_file());
    let hash64_text = std::fs::read_to_string(&hash64_lut).unwrap();
    assert!(hash64_text.starts_with("# leonida-forge-lut: 1\n# namespace: hash64\n"));
    assert!(hash64_text.contains("synthetic/asset.rpf"));
    let key32_text = std::fs::read_to_string(&key32_lut).unwrap();
    assert!(key32_text.starts_with("# leonida-forge-lut: 1\n# namespace: key32\n"));
    assert!(key32_text.contains("readme.txt"));

    let archive = temp.path().join("alpha.rpf");
    let resolved = json(&lforge(&[
        "archive",
        "metadata",
        archive.to_str().unwrap(),
        "--entries",
        "--name-file",
        hash64_lut.to_str().unwrap(),
        "--name-file",
        key32_lut.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(resolved["entries"]["names"]["mappings"], 2);
    assert_eq!(resolved["entries"]["names"]["verified_mappings"], 2);
    let listed = resolved["entries"]["listed"].as_array().unwrap();
    assert_eq!(listed[0]["name_resolution"]["status"], "resolved");
    assert_eq!(
        listed[0]["name_resolution"]["candidates"][0]["name"],
        "synthetic/asset.rpf"
    );
    assert_eq!(
        listed[0]["name_resolution"]["candidates"][0]["provenance"],
        "user_mapping"
    );
    assert_eq!(
        listed[0]["name_resolution"]["candidates"][0]["verified"],
        true
    );
    assert_eq!(
        listed[0]["name_hash"],
        format!("0x{:016X}", hash64(b"synthetic/asset"))
    );
    assert_eq!(listed[1]["name_resolution"]["status"], "resolved");
    assert_eq!(
        listed[1]["name_resolution"]["candidates"][0]["name"],
        "readme.txt"
    );
    assert_eq!(listed[1]["name_resolution"]["namespace"], "key32");
}

#[test]
fn export_refuses_a_harvest_without_matches() {
    let temp = tempfile::tempdir().unwrap();
    let results = temp.path().join("empty.jsonl");
    std::fs::write(&results, "").unwrap();
    let output = lforge(&[
        "names",
        "export",
        results.to_str().unwrap(),
        "--output",
        temp.path().join("none.lut").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no verified mappings"));
}

#[test]
fn harvest_reports_transform_skips() {
    let temp = tempfile::tempdir().unwrap();
    sample_archives(temp.path());
    let executable = temp.path().join("alpha.rpf");
    let output = temp.path().join("results.jsonl");
    let report = json(&lforge(&[
        "names",
        "harvest",
        temp.path().to_str().unwrap(),
        "--executable",
        executable.to_str().unwrap(),
        "--sources",
        "payloads",
        "--output",
        output.to_str().unwrap(),
        "--json",
    ]));
    assert!(
        report["payloads"]["skip_reasons"]
            .as_object()
            .unwrap()
            .keys()
            .any(|reason| reason.contains("transform"))
    );
}
