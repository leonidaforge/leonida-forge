//! Payload-readability diagnostics of `lforge archive metadata --entries`,
//! on synthetic RPF9 archives built in memory.

mod common;

use common::*;
use serde_json::Value;

#[test]
fn metadata_reports_payload_readability() {
    let temp = tempfile::tempdir().unwrap();
    let (chunk_region, chunk_entry) = zlib_chunk(b"a small chunked payload");
    let rows = vec![
        spec(b"stored as it is"),
        Spec {
            mode: 1,
            logical: Some(40),
            ..spec(&deflate(&[7u8; 40]))
        },
        Spec {
            transform: true,
            ..spec(&[0x11; 16])
        },
        Spec {
            mode: 2,
            ..spec(&[0x22; 16])
        },
        Spec {
            source: Some(0),
            ..spec(&[0x33; 16])
        },
        Spec {
            chunks: Some(chunk_value(1, 4, &[chunk_entry])),
            logical: Some(23),
            ..spec(&chunk_region)
        },
        Spec {
            has_location: false,
            ..spec(b"")
        },
    ];
    let bytes = assemble(&rows, &[(b"ghost.dat".to_vec(), 1)]);
    let archive = write_archive(temp.path(), "diagnostics.rpf", &bytes);

    let output = lforge(&[
        "archive",
        "metadata",
        archive.to_str().unwrap(),
        "--entries",
        "--json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["state"], "decoded");
    let entries = &report["entries"];
    assert_eq!(entries["companions"]["records"], 1);
    assert_eq!(entries["companions"]["missing"], 1);
    let listed = entries["listed"].as_array().unwrap();
    let state = |row: usize| listed[row]["contents"]["state"].as_str().unwrap();
    assert_eq!(state(0), "stored");
    assert_eq!(listed[0]["contents"]["readable"], true);
    assert_eq!(state(1), "decoded");
    assert_eq!(state(2), "unsupported_transform");
    assert_eq!(listed[2]["contents"]["readable"], false);
    assert_eq!(state(3), "unsupported_compression");
    assert_eq!(state(4), "alternate_source");
    assert_eq!(state(5), "decoded");
    assert_eq!(state(6), "malformed");

    let text = lforge(&[
        "archive",
        "metadata",
        archive.to_str().unwrap(),
        "--entries",
    ]);
    let stdout = String::from_utf8(text.stdout).unwrap();
    assert!(stdout.contains("companions:  1 ("), "{stdout}");
    assert!(stdout.contains("transform"), "{stdout}");
    assert!(stdout.contains("compression"), "{stdout}");
}
