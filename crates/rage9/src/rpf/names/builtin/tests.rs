use super::*;
use crate::rpf::names::{Key, joaat};

fn key32_lut(name: &str, declared: u32) -> String {
    format!("# leonida-forge-lut: 1\n# namespace: key32\n\n0x{declared:08X}\t{name}\n")
}

#[test]
fn the_embedded_tables_parse_and_cover_both_namespaces() {
    let builtin = Builtin::load(None);
    assert_eq!(builtin.sources().len(), EMBEDDED.len());
    assert!(
        builtin.problems().next().is_none(),
        "{:?}",
        builtin.sources()
    );
    for source in builtin.sources() {
        assert!(source.path.is_none(), "{source:?}");
        assert!(source.entries > 0, "{source:?}");
    }
    assert!(builtin.sources().iter().all(|source| source.added > 0));
    let keys: Vec<&Key> = builtin
        .table()
        .entries()
        .iter()
        .filter_map(|entry| entry.declared.as_ref())
        .collect();
    assert!(keys.iter().any(|key| matches!(key, Key::Hash64(_))));
    assert!(keys.iter().any(|key| matches!(key, Key::Key32(_))));
}

#[test]
fn a_lut_beside_the_executable_is_merged_after_the_embedded_ones() {
    let directory = tempfile::tempdir().unwrap();
    let readme = joaat(b"readme");
    std::fs::write(
        directory.path().join(KEY32_FILE),
        key32_lut("Readme.txt", readme),
    )
    .unwrap();
    let builtin = Builtin::load(Some(directory.path()));
    assert_eq!(builtin.sources().len(), EMBEDDED.len() + 1);
    let added = builtin.sources().last().unwrap();
    assert_eq!(added.file, KEY32_FILE);
    assert_eq!(
        added.path.as_deref(),
        Some(directory.path().join(KEY32_FILE).as_path())
    );
    assert_eq!(added.entries, 1);
    assert_eq!(added.added, 1);
    assert!(added.problem.is_none());
    assert!(
        builtin
            .table()
            .entries()
            .iter()
            .any(|entry| entry.name == "Readme.txt")
    );
}

#[test]
fn an_unusable_lut_beside_the_executable_is_reported_and_skipped() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join(HASH64_FILE), "not a LUT\n").unwrap();
    let builtin = Builtin::load(Some(directory.path()));
    let problem = builtin.problems().next().expect("the file is reported");
    assert_eq!(problem.file, HASH64_FILE);
    assert!(problem.problem.as_ref().unwrap().contains("line 1"));
    assert!(!builtin.is_empty());
}

#[test]
fn a_missing_directory_reads_only_the_embedded_tables() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");
    assert_eq!(Builtin::load(Some(&missing)), Builtin::load(None));
}
