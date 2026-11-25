use super::*;

fn parse(text: &str) -> StringTable {
    StringTable::parse(text.as_bytes(), false)
}

#[test]
fn parses_candidate_paths_and_mappings() {
    let table = parse(
        "\u{FEFF}# local names\r\n\
         packs/inner.rpf\r\n\
         \r\n\
         hash64:0x3FC602FCF22D7472\tSub/Dir/Item.Name\r\n\
         key32:B7076B62\treadme.txt\r\n",
    );
    assert_eq!(table.skipped(), 0);
    assert_eq!(table.duplicates(), 0);
    assert!(!table.truncated());
    assert_eq!(table.candidates(), 1);
    assert_eq!(table.mappings(), 2);
    assert_eq!(
        table.entries(),
        [
            TableEntry {
                name: "packs/inner.rpf".to_string(),
                provenance: Provenance::CandidatePath,
                declared: None,
            },
            TableEntry {
                name: "Sub/Dir/Item.Name".to_string(),
                provenance: Provenance::UserMapping,
                declared: Some(Key::Hash64(0x3FC6_02FC_F22D_7472)),
            },
            TableEntry {
                name: "readme.txt".to_string(),
                provenance: Provenance::UserMapping,
                declared: Some(Key::Key32(0xB707_6B62)),
            },
        ]
    );
}

#[test]
fn keeps_plain_lines_as_candidate_paths() {
    // The original `.names.txt` format: one path per line, CRLF accepted.
    let table = parse("a.rpf\r\nB\\C.rpf\n");
    assert_eq!(table.candidates(), 2);
    assert_eq!(table.entries()[1].name, "B\\C.rpf");
    assert_eq!(table.entries()[1].provenance, Provenance::CandidatePath);
}

#[test]
fn skips_malformed_lines_without_guessing() {
    let long = "x".repeat(MAX_LINE + 1);
    let table = parse(&format!(
        "good.rpf\n\
         hash64:nothex\tname\n\
         sha256:0011\tname\n\
         key32:100000000\tname\n\
         hash64:0x1\ttwo\ttabs\n\
         hash64:0x1\t\n\
         path\twith\ttab\n\
         bad\u{7f}byte\n\
         {long}\n"
    ));
    assert_eq!(table.entries().len(), 1);
    assert_eq!(table.entries()[0].name, "good.rpf");
    assert_eq!(table.skipped(), 8);
}

#[test]
fn rejects_invalid_utf8_and_controls() {
    let mut bytes = b"ok.rpf\n".to_vec();
    bytes.extend_from_slice(b"bad\xffname\n");
    bytes.extend_from_slice(b"nul\0name\n");
    bytes.extend_from_slice(b"esc\x1bname\n");
    bytes.extend_from_slice("c1\u{9b}name\n".as_bytes());
    bytes.extend_from_slice("bidi\u{202e}name\n".as_bytes());
    let table = StringTable::parse(&bytes, false);
    assert_eq!(table.entries().len(), 1);
    assert_eq!(table.skipped(), 5);
}

#[test]
fn drops_exact_duplicates_and_keeps_distinct_spellings() {
    let table = parse(
        "a.rpf\n\
         a.rpf\n\
         A.rpf\n\
         hash64:0x1\tsame\n\
         hash64:0x1\tsame\n",
    );
    assert_eq!(table.entries().len(), 3);
    assert_eq!(table.duplicates(), 2);
    assert_eq!(table.candidates(), 2);
    assert_eq!(table.mappings(), 1);
}

#[test]
fn cuts_a_truncated_input_at_a_complete_line() {
    let table = StringTable::parse(b"one.rpf\ntwo", true);
    assert!(table.truncated());
    assert_eq!(table.entries().len(), 1);
    assert_eq!(table.entries()[0].name, "one.rpf");
}

#[test]
fn reads_a_bounded_file() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("names.txt");
    std::fs::write(&path, "one.rpf\r\ntwo.rpf\r\n").unwrap();
    let table = StringTable::read(&path).unwrap();
    assert_eq!(table.entries().len(), 2);
    assert_eq!(table.entries()[1].name, "two.rpf");
}

#[test]
fn accepts_a_zero_hash_mapping() {
    let table = parse("hash64:0x0\tempty name is not empty text\n");
    assert_eq!(
        table.entries()[0].declared,
        Some(Key::Hash64(0)),
        "an explicit zero is still a declared key"
    );
}
