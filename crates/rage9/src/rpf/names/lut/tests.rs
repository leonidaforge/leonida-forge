use super::*;
use crate::rpf::names::{hash64, joaat};

fn lut(text: &str) -> Lut {
    Lut::parse(text.as_bytes()).unwrap()
}

#[test]
fn parses_the_canonical_format() {
    let hash = hash64(b"synthetic/asset");
    let text = format!(
        "\u{FEFF}# leonida-forge-lut: 1\r\n# namespace: hash64\r\n\r\n0x{hash:016X}\tsynthetic/asset.bin\r\n"
    );
    let parsed = lut(&text);
    assert_eq!(parsed.namespace(), Class::Hash64);
    assert_eq!(parsed.entries().len(), 1);
    assert_eq!(parsed.entries()[0].name, "synthetic/asset.bin");
    assert!(parsed.entries()[0].verified);
    assert_eq!(
        parsed.to_text(),
        text.trim_start_matches('\u{FEFF}').replace("\r\n", "\n")
    );
}

#[test]
fn keeps_different_names_for_one_hash_and_drops_exact_duplicates() {
    let hash = hash64(b"synthetic/asset");
    let text = format!(
        "# leonida-forge-lut: 1\n# namespace: hash64\n\
         0x{hash:016X}\tsynthetic/asset.bin\n\
         0x{hash:016X}\tsynthetic/other.bin\n\
         0x{hash:016X}\tsynthetic/asset.bin\n"
    );
    let parsed = lut(&text);
    assert_eq!(parsed.entries().len(), 2);
    assert_eq!(parsed.duplicates(), 1);
    assert!(parsed.entries()[0].verified);
    assert!(!parsed.entries()[1].verified);
}

#[test]
fn sorts_records_and_writes_uppercase_hashes() {
    let a = hash64(b"a");
    let z = hash64(b"z");
    let text = format!(
        "# leonida-forge-lut: 1\n# namespace: hash64\n\
         0x{z:016x}\tz.file\n\
         0x{a:016X}\ta.file\n"
    );
    let parsed = lut(&text);
    let output = parsed.to_text();
    let first = a.min(z);
    assert!(
        output.contains(&format!("0x{first:016X}")),
        "canonical hashes are uppercase: {output}"
    );
    let first_name = if first == a { "a.file" } else { "z.file" };
    let second_name = if first == a { "z.file" } else { "a.file" };
    assert!(
        output.find(first_name).unwrap() < output.find(second_name).unwrap(),
        "{output}"
    );
}

#[test]
fn preserves_spaces_inside_names() {
    let hash = hash64(b"synthetic/with space");
    let parsed = lut(&format!(
        "# leonida-forge-lut: 1\n# namespace: hash64\n0x{hash:016X}\tsynthetic/with space.bin\n"
    ));
    assert_eq!(parsed.entries()[0].name, "synthetic/with space.bin");
}

#[test]
fn rejects_malformed_declarations_and_records() {
    for text in [
        "# namespace: hash64\n0x0000000000000001\tname.bin\n",
        "# leonida-forge-lut: 2\n# namespace: hash64\n",
        "# leonida-forge-lut: 1\n# namespace: other\n",
        "# leonida-forge-lut: 1\n0x0000000000000001\tname.bin\n",
        "# leonida-forge-lut: 1\n# namespace: hash64\n0x1\tname.bin\n",
        "# leonida-forge-lut: 1\n# namespace: hash64\n1234\tname.bin\n",
        "# leonida-forge-lut: 1\n# namespace: hash64\n0xZZZZZZZZZZZZZZZZ\tname.bin\n",
        "# leonida-forge-lut: 1\n# namespace: hash64\n0x0000000000000001\n",
        "# leonida-forge-lut: 1\n# namespace: hash64\n0x0000000000000001\tsynthetic/\u{202e}bad.bin\n",
    ] {
        assert!(Lut::parse(text.as_bytes()).is_err(), "{text:?}");
    }
}

#[test]
fn applies_namespace_hash_widths() {
    let key = joaat(b"synthetic/asset");
    let text =
        format!("# leonida-forge-lut: 1\n# namespace: key32\n0x{key:08X}\tsynthetic/asset.bin\n");
    let parsed = lut(&text);
    assert_eq!(parsed.namespace(), Class::Key32);
    assert!(parsed.entries()[0].verified);
    let wrong =
        format!("# leonida-forge-lut: 1\n# namespace: key32\n0x{key:016X}\tsynthetic/asset.bin\n");
    assert!(Lut::parse(wrong.as_bytes()).is_err());
}

#[test]
fn builds_a_canonical_lut_from_mappings() {
    let hash = hash64(b"synthetic/asset");
    let built = Lut::new(
        Class::Hash64,
        [
            (Key::Hash64(hash), "synthetic/asset.bin".to_string()),
            (Key::Hash64(hash), "synthetic/asset.bin".to_string()),
        ],
    )
    .unwrap();
    assert_eq!(built.entries().len(), 1);
    assert_eq!(built.duplicates(), 1);
    assert!(built.entries()[0].verified);
    assert!(Lut::new(Class::Key32, [(Key::Hash64(hash), "x".to_string())]).is_err());
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let hash = hash64(b"synthetic/asset");
    let parsed = lut(&format!(
        "# leonida-forge-lut: 1\n# namespace: hash64\n# note\n\n0x{hash:016X}\tsynthetic/asset.bin\n"
    ));
    assert_eq!(parsed.entries().len(), 1);
}
