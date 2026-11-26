//! `lforge archive extract`, on synthetic RPF9 archives built in memory.

mod common;

use common::*;

#[test]
fn exports_a_stored_entry() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = assemble(&[spec(b"stored contents, verbatim")], &[]);
    let archive = write_archive(temp.path(), "stored.rpf", &bytes);
    let out = temp.path().join("out.bin");

    let output = extract(&archive, 0, &out, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), b"stored contents, verbatim");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("(stored)"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn exports_a_raw_deflate_entry() {
    let temp = tempfile::tempdir().unwrap();
    let original: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let row = Spec {
        mode: 1,
        logical: Some(original.len() as u64),
        ..spec(&deflate(&original))
    };
    let archive = write_archive(temp.path(), "deflate.rpf", &assemble(&[row], &[]));
    let out = temp.path().join("out.bin");

    let output = extract(&archive, 0, &out, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), original);
    assert!(String::from_utf8_lossy(&output.stdout).contains("(raw DEFLATE)"));
}

#[test]
fn exports_a_chunked_entry_with_zlib_and_copy_methods() {
    let temp = tempfile::tempdir().unwrap();
    let first: Vec<u8> = (0..9000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let second = b"a copied chunk, stored as it is".to_vec();
    let (region_a, entry_a) = zlib_chunk(&first);
    let (region_b, entry_b) = copy_chunk(&second);
    let mut payload = region_a;
    payload.extend_from_slice(&region_b);
    let row = Spec {
        chunks: Some(chunk_value(2, 4, &[entry_a, entry_b])),
        logical: Some((first.len() + second.len()) as u64),
        ..spec(&payload)
    };
    let archive = write_archive(temp.path(), "chunked.rpf", &assemble(&[row], &[]));
    let out = temp.path().join("out.bin");

    let output = extract(&archive, 0, &out, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(std::fs::read(&out).unwrap(), expected);
    assert!(String::from_utf8_lossy(&output.stdout).contains("(chunked)"));
}

#[test]
fn exports_an_encoding_2_chunked_entry() {
    let temp = tempfile::tempdir().unwrap();
    let first: Vec<u8> = (0..0x1000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let second: Vec<u8> = (0..32u32).map(|i| (i % 251) as u8).collect();
    let (region_a, entry_a) = zlib_chunk2(&first);
    let (region_b, entry_b) = copy_chunk2(&second);
    // Encoding-2 entries hold 16 bytes before the first chunk.
    let mut payload = vec![0u8; 16];
    payload.extend_from_slice(&region_a);
    payload.extend_from_slice(&region_b);
    let row = Spec {
        chunks: Some(chunk_value(2, 2, &[entry_a, entry_b])),
        logical: Some((first.len() + second.len()) as u64),
        ..spec(&payload)
    };
    let archive = write_archive(temp.path(), "chunked2.rpf", &assemble(&[row], &[]));
    let out = temp.path().join("out.bin");

    let output = extract(&archive, 0, &out, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let mut expected = first;
    expected.extend_from_slice(&second);
    assert_eq!(std::fs::read(&out).unwrap(), expected);

    // The listing reports the same row as decodable.
    let listing = lforge(&["archive", "ls", archive.to_str().unwrap(), "--json"]);
    assert!(listing.status.success(), "{}", stderr(&listing));
    let value: serde_json::Value = serde_json::from_slice(&listing.stdout).unwrap();
    assert_eq!(value["rows"][0]["contents"]["readable"], true);
    assert_eq!(value["rows"][0]["contents"]["state"], "decoded");
}

#[test]
fn exports_an_entry_read_from_a_companion() {
    let temp = tempfile::tempdir().unwrap();
    let payload = b"these bytes live only in the companion".to_vec();
    let row = Spec {
        source: Some(0),
        ..spec(&payload)
    };
    let full = assemble(&[row], &[(b"data.dat".to_vec(), 0xABCD)]);

    // The companion holds the real payload; the main archive is zeroed there.
    let mut companion = full.clone();
    companion[..16].copy_from_slice(&[&COMPANION_MAGIC[..], &0xABCDu64.to_le_bytes()].concat());
    let location = decode(&full).location(0).unwrap();
    let (offset, stored) = (
        location.payload_offset as usize,
        location.stored_len as usize,
    );
    let mut main = full.clone();
    main[offset..offset + stored].fill(0);

    let archive = write_archive(temp.path(), "main.rpf", &main);
    write_archive(temp.path(), "data.dat", &companion);
    let out = temp.path().join("out.bin");

    let output = extract(&archive, 0, &out, &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), payload);
}

#[test]
fn refuses_entries_read_from_missing_or_invalid_companions() {
    let temp = tempfile::tempdir().unwrap();
    let row = Spec {
        source: Some(0),
        ..spec(b"payload that needs a companion")
    };

    // Missing: the named companion file does not exist.
    let missing = assemble(std::slice::from_ref(&row), &[(b"ghost.dat".to_vec(), 7)]);
    let archive = write_archive(temp.path(), "missing.rpf", &missing);
    let out = temp.path().join("missing.bin");
    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("alternate source 0"),
        "{}",
        stderr(&output)
    );
    assert!(!out.exists(), "no output on failure");

    // Invalid: the companion exists but its identifier does not match.
    let invalid = assemble(&[row], &[(b"wrong.dat".to_vec(), 7)]);
    let archive = write_archive(temp.path(), "invalid.rpf", &invalid);
    let mut companion = COMPANION_MAGIC.to_vec();
    companion.extend_from_slice(&999u64.to_le_bytes());
    write_archive(temp.path(), "wrong.dat", &companion);
    let out = temp.path().join("invalid.bin");
    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("alternate source 0"));
    assert!(!out.exists());
}

#[test]
fn enforces_the_operation_output_limit() {
    let temp = tempfile::tempdir().unwrap();
    let archive = write_archive(
        temp.path(),
        "limit.rpf",
        &assemble(&[spec(&[7u8; 100])], &[]),
    );
    let out = temp.path().join("out.bin");

    let over = lforge(&[
        "archive",
        "extract",
        archive.to_str().unwrap(),
        "--row",
        "0",
        "--output",
        out.to_str().unwrap(),
        "--max-output-bytes",
        "99",
    ]);
    assert_eq!(over.status.code(), Some(1));
    assert!(stderr(&over).contains("output limit"), "{}", stderr(&over));
    assert!(!out.exists());

    let at = lforge(&[
        "archive",
        "extract",
        archive.to_str().unwrap(),
        "--row",
        "0",
        "--output",
        out.to_str().unwrap(),
        "--max-output-bytes",
        "100",
    ]);
    assert!(at.status.success(), "{}", stderr(&at));
    assert_eq!(std::fs::read(&out).unwrap(), vec![7u8; 100]);
}

#[test]
fn rejects_unsupported_transforms_and_compression_modes() {
    let temp = tempfile::tempdir().unwrap();
    let transform = Spec {
        transform: true,
        ..spec(&[0x11; 16])
    };
    let archive = write_archive(temp.path(), "transform.rpf", &assemble(&[transform], &[]));
    let out = temp.path().join("t.bin");
    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("behind the payload transform"),
        "{}",
        stderr(&output)
    );
    assert!(!out.exists());

    let mode = Spec {
        mode: 2,
        ..spec(&[0x22; 16])
    };
    let archive = write_archive(temp.path(), "mode.rpf", &assemble(&[mode], &[]));
    let out = temp.path().join("m.bin");
    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("compression mode 2"),
        "{}",
        stderr(&output)
    );
    assert!(!out.exists());
}

#[test]
fn rejects_unavailable_native_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let mut bytes = assemble(&[spec(b"unreachable")], &[]);
    // A nonzero static-pass selector means the engine processes the table of
    // contents before use, which is not reproduced.
    bytes[0x2E] = 9;
    let archive = write_archive(temp.path(), "encrypted.rpf", &bytes);
    let out = temp.path().join("out.bin");
    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not read"), "{}", stderr(&output));
    assert!(!out.exists());
}

#[test]
fn rejects_out_of_range_rows() {
    let temp = tempfile::tempdir().unwrap();
    let archive = write_archive(
        temp.path(),
        "small.rpf",
        &assemble(&[spec(b"only row")], &[]),
    );
    let out = temp.path().join("out.bin");
    let output = extract(&archive, 9, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("out of range"),
        "{}",
        stderr(&output)
    );
    assert!(!out.exists());
}

#[test]
fn reports_corrupted_compressed_data_and_writes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    // Declared as raw DEFLATE, but the stored bytes are not a valid stream.
    let row = Spec {
        mode: 1,
        logical: Some(64),
        ..spec(&[0xFF; 32])
    };
    let archive = write_archive(temp.path(), "corrupt.rpf", &assemble(&[row], &[]));
    let out = temp.path().join("out.bin");
    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("decoded"), "{}", stderr(&output));
    assert!(!out.exists(), "a failed decode leaves no output");
}

#[test]
fn leaves_no_partial_file_when_a_later_chunk_fails() {
    let temp = tempfile::tempdir().unwrap();
    let good: Vec<u8> = (0..4000u32).map(|i| (i % 97) as u8).collect();
    let (region_a, entry_a) = zlib_chunk(&good);
    // A second zlib chunk whose stored bytes are not a valid stream.
    let region_b = vec![0xFFu8; 32];
    let entry_b = chunk4(16, 32, 0, 3);
    let mut payload = region_a;
    payload.extend_from_slice(&region_b);
    let row = Spec {
        chunks: Some(chunk_value(2, 4, &[entry_a, entry_b])),
        logical: Some(good.len() as u64 + 16),
        ..spec(&payload)
    };
    let archive = write_archive(temp.path(), "partial.rpf", &assemble(&[row], &[]));
    let out = temp.path().join("out.bin");

    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!out.exists(), "no partial final file");
    let leftovers: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|name| name != "partial.rpf")
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary file left behind: {leftovers:?}"
    );
}

#[test]
fn enforces_the_output_size_limit() {
    let temp = tempfile::tempdir().unwrap();
    // A small stored stream that declares more than the 512 MiB output limit.
    let row = Spec {
        mode: 1,
        logical: Some(512 * 1024 * 1024 + 1),
        ..spec(&deflate(b"small"))
    };
    let archive = write_archive(temp.path(), "huge.rpf", &assemble(&[row], &[]));
    let out = temp.path().join("out.bin");
    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("output limit"),
        "{}",
        stderr(&output)
    );
    assert!(!out.exists());
}

#[test]
fn does_not_overwrite_without_the_flag() {
    let temp = tempfile::tempdir().unwrap();
    let archive = write_archive(
        temp.path(),
        "stored.rpf",
        &assemble(&[spec(b"fresh bytes")], &[]),
    );
    let out = temp.path().join("out.bin");
    std::fs::write(&out, b"existing content").unwrap();

    let output = extract(&archive, 0, &out, &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("already exists"),
        "{}",
        stderr(&output)
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"existing content");

    let output = extract(&archive, 0, &out, &["--overwrite"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(std::fs::read(&out).unwrap(), b"fresh bytes");
}

#[test]
fn refuses_an_output_that_is_the_input_archive() {
    let temp = tempfile::tempdir().unwrap();
    let bytes = assemble(&[spec(b"stored contents, verbatim")], &[]);
    let archive = write_archive(temp.path(), "self.rpf", &bytes);
    let output = extract(&archive, 0, &archive, &["--overwrite"]);
    assert!(!output.status.success());
    let message = stderr(&output);
    assert!(message.contains("one of the inputs"), "{message}");
    // The archive is untouched.
    assert_eq!(std::fs::read(&archive).unwrap(), bytes);
}
