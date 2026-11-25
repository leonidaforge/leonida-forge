use super::*;
use crate::rpf::names::{hash64, joaat};

fn strings(bytes: &[u8]) -> Vec<String> {
    extract_strings(bytes, Limits::default())
}

#[test]
fn extracts_paths_from_ascii_and_utf8() {
    let found = strings(b"\x00synthetic/path/file.bin\x00synthetic/caf\xC3\xA9/item.ymt\x00");
    assert!(found.contains(&"synthetic/path/file.bin".to_string()));
    assert!(found.contains(&"synthetic/café/item.ymt".to_string()));
}

#[test]
fn extracts_utf16le_paths() {
    let text: Vec<u8> = "synthetic\\win\\file.rpf"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut bytes = vec![0];
    bytes.extend_from_slice(&text);
    bytes.push(0);
    let found = strings(&bytes);
    assert!(found.contains(&"synthetic\\win\\file.rpf".to_string()));
}

#[test]
fn finds_paths_embedded_in_surrounding_words() {
    let found = strings(b"before synthetic/asset.bin after");
    assert!(found.contains(&"synthetic/asset.bin".to_string()));
    assert!(found.contains(&"before synthetic/asset.bin after".to_string()));
}

#[test]
fn rejects_noise_controls_and_long_runs() {
    assert!(strings(b"\x01\x02\x03\x04").is_empty());
    assert!(strings(b"a.b").is_empty());
    assert!(strings(b"plain words without a path").is_empty());
    assert!(strings(b"http://example.invalid/file.bin").is_empty());
    let long = format!("synthetic/{}.bin", "x".repeat(MAX_STRING));
    assert!(strings(long.as_bytes()).is_empty());
}

#[test]
fn deduplicates_per_source_and_respects_the_limit() {
    let found = strings(b"synthetic/a.bin\0synthetic/a.bin\0synthetic/b.bin\0");
    assert_eq!(found, ["synthetic/a.bin", "synthetic/b.bin"]);
    let limits = Limits {
        max_strings: 1,
        ..Limits::default()
    };
    assert_eq!(
        extract_strings(b"synthetic/a.bin\0synthetic/b.bin\0", limits).len(),
        1
    );
}

#[test]
fn variants_keep_the_display_extension() {
    let variants = candidate_variants("common:/data/foo.ymt");
    let stem = variants
        .iter()
        .find(|variant| variant.kind == VariantKind::AfterSchemeStem)
        .unwrap();
    assert_eq!(stem.text, "data/foo");
    assert_eq!(stem.display, "data/foo.ymt");
    assert_eq!(
        hash_variant(stem, Class::Hash64),
        Some(Key::Hash64(hash64(b"data/foo")))
    );
    assert!(
        variants
            .iter()
            .any(|variant| variant.text == "data/foo.ymt")
    );
}

#[test]
fn variants_trim_leading_separators() {
    let variants = candidate_variants("/synthetic/foo.rpf");
    assert!(variants.iter().any(|variant| {
        variant.kind == VariantKind::TrimmedStem
            && variant.text == "synthetic/foo"
            && variant.display == "synthetic/foo.rpf"
    }));
}

#[test]
fn key32_variants_hash_whole_and_stem() {
    let variants = candidate_variants("readme.txt");
    let whole = variants
        .iter()
        .find(|variant| variant.kind == VariantKind::Exact)
        .unwrap();
    let stem = variants
        .iter()
        .find(|variant| variant.kind == VariantKind::Stem)
        .unwrap();
    assert_eq!(
        hash_variant(whole, Class::Key32),
        Some(Key::Key32(joaat(b"readme.txt")))
    );
    assert_eq!(
        hash_variant(stem, Class::Key32),
        Some(Key::Key32(joaat(b"readme")))
    );
    assert_eq!(hash_variant(whole, Class::Hash64), None);
}

#[test]
fn a_drive_letter_is_not_a_scheme() {
    let variants = candidate_variants(r"D:\synthetic\foo.bin");
    assert!(
        variants
            .iter()
            .all(|variant| !variant.kind.text().starts_with("after_scheme"))
    );
}
