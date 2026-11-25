use super::*;
use crate::rpf::metadata::{Location, RecordLayout};
use crate::rpf::names::{MountPrefix, StringTable, Unresolved, hash64, joaat};

fn entry(row: u32, type_id: Option<u8>, hash: Option<u64>, key: Option<u32>) -> Entry {
    Entry {
        row,
        location: Ok(type_id.map(|type_id| Location {
            layout: RecordLayout::F,
            payload_offset: 0,
            stored_len: 0,
            logical_len: 0,
            type_id,
            mode: 0,
        })),
        name_hash: Ok(hash),
        name_key: Ok(key),
        chunks: Ok(None),
        payload_transform: Ok(false),
        payload_cipher: Ok(None),
        read_source: Ok(None),
        payload_end: None,
    }
}

fn parse(text: &str) -> StringTable {
    StringTable::parse(text.as_bytes(), false)
}

fn resolve(table: &StringTable, entries: &[Entry]) -> ResolutionSet {
    Resolver::new(table, &Types::default(), MountPrefix::EMPTY).resolve(entries)
}

#[test]
fn reports_unresolved_rows_with_their_namespace() {
    let entries = [
        entry(0, Some(0), Some(0x1234), None),
        entry(1, Some(255), None, Some(0x5678)),
        entry(2, Some(11), Some(1), Some(2)),
        entry(3, Some(13), Some(3), Some(4)),
    ];
    let resolved = resolve(&StringTable::default(), &entries);
    assert_eq!(resolved.unusable_rows, 0);
    assert_eq!(resolved.rows.len(), 4);
    assert_eq!(resolved.rows[0].namespace, Namespace::Hash64);
    assert_eq!(resolved.rows[1].namespace, Namespace::Key32);
    // Type 11 uses the 32-bit class, established from the executable's
    // per-type tables.
    assert_eq!(resolved.rows[2].namespace, Namespace::Key32);
    // A type with no established class and both keys stays unknown.
    assert_eq!(resolved.rows[3].namespace, Namespace::Unknown);
    for row in &resolved.rows {
        assert_eq!(row.resolution, Resolution::Unresolved);
    }
}

#[test]
fn resolves_a_unique_candidate_path() {
    let entries = [entry(3, Some(0), Some(hash64(b"packs/inner")), None)];
    let table = parse("packs/inner.rpf\n");
    let resolved = resolve(&table, &entries);
    let row = resolved.row(3).unwrap();
    assert_eq!(
        row.resolution,
        Resolution::Resolved(vec![Name {
            text: "packs/inner.rpf".to_string(),
            provenance: Provenance::CandidatePath,
            algorithm: Class::Hash64,
            verified: true,
        }])
    );
    assert_eq!(row.namespace, Namespace::Hash64);
    assert_eq!(
        resolved.candidates[0].outcome,
        CandidateOutcome::Matched(vec![3])
    );
}

#[test]
fn keeps_spellings_of_one_name_but_not_as_ambiguity() {
    let entries = [entry(0, Some(0), Some(hash64(b"packs/inner")), None)];
    let table = parse("packs/inner.rpf\nPACKS\\INNER.rpf\n");
    let resolved = resolve(&table, &entries);
    let row = &resolved.rows[0];
    let Resolution::Resolved(names) = &row.resolution else {
        panic!("expected one resolved name, got {:?}", row.resolution);
    };
    assert_eq!(names.len(), 2);
    assert_eq!(names[0].text, "packs/inner.rpf");
    assert_eq!(names[1].text, "PACKS\\INNER.rpf");
}

#[test]
fn reports_different_names_with_one_key_as_ambiguous() {
    let hash = hash64(b"alpha");
    let entries = [entry(0, Some(0), Some(hash), None)];
    let table = parse(&format!(
        "hash64:{hash:016X}\talpha\nhash64:{hash:016X}\tbeta\n"
    ));
    let resolved = resolve(&table, &entries);
    let Resolution::Ambiguous(names) = &resolved.rows[0].resolution else {
        panic!("expected ambiguity, got {:?}", resolved.rows[0].resolution);
    };
    assert_eq!(
        names
            .iter()
            .map(|name| (name.text.as_str(), name.verified))
            .collect::<Vec<_>>(),
        [("alpha", true), ("beta", false)]
    );
    assert_eq!(resolved.rows[0].namespace, Namespace::Hash64);
}

#[test]
fn verifies_a_mapping_only_when_the_name_reproduces_the_key() {
    let hash = hash64(b"props/crate");
    let entries = [entry(0, Some(0), Some(hash), None)];
    // The full path is normalized and reduced to its stem before hashing.
    let table = parse(&format!("hash64:{hash:016X}\tProps/Crate.ydr\n"));
    let resolved = resolve(&table, &entries);
    let Name {
        verified,
        provenance,
        algorithm,
        ..
    } = &resolved.rows[0].resolution.names()[0];
    assert!(*verified);
    assert_eq!(*provenance, Provenance::UserMapping);
    assert_eq!(*algorithm, Class::Hash64);

    // A name that does not hash to the declared key stays a suggestion.
    let table = parse(&format!("hash64:{hash:016X}\tnothing/like/it\n"));
    let resolved = resolve(&table, &entries);
    assert!(!resolved.rows[0].resolution.names()[0].verified);
    assert_eq!(
        resolved.rows[0].resolution.names()[0].text,
        "nothing/like/it"
    );
}

#[test]
fn never_mixes_the_32_and_64_bit_namespaces() {
    let key = joaat(b"readme");
    let entries = [entry(0, Some(255), None, Some(key))];
    let hash64_mapping = parse(&format!("hash64:{key:016X}\treadme\n"));
    let resolved = resolve(&hash64_mapping, &entries);
    assert_eq!(resolved.rows[0].resolution, Resolution::Unresolved);
    assert_eq!(
        resolved.candidates[0].outcome,
        CandidateOutcome::NoRow,
        "a 64-bit mapping must not address a 32-bit row"
    );

    let key32_mapping = parse(&format!("key32:{key:08X}\treadme\n"));
    let resolved = resolve(&key32_mapping, &entries);
    assert_eq!(resolved.rows[0].namespace, Namespace::Key32);
    assert!(resolved.rows[0].resolution.is_resolved());
}

#[test]
fn path_candidates_must_match_the_type_too() {
    let hash = hash64(b"shared");
    let entries = [
        entry(0, Some(0), Some(hash), None),
        entry(1, Some(5), Some(hash), None),
    ];
    let table = parse("shared.rpf\n");
    let resolved = resolve(&table, &entries);
    assert_eq!(resolved.rows[0].resolution.names().len(), 1);
    assert_eq!(resolved.rows[1].resolution, Resolution::Unresolved);
}

#[test]
fn reports_unusable_candidates_and_rows() {
    let entries = [entry(0, Some(0), Some(hash64(b"item")), None)];
    let table = parse("missing.rpf\nmodel.ydr\n");
    let resolved = resolve(&table, &entries);
    assert_eq!(resolved.rows[0].resolution, Resolution::Unresolved);
    assert_eq!(resolved.candidates[0].outcome, CandidateOutcome::NoRow);
    assert_eq!(
        resolved.candidates[1].outcome,
        CandidateOutcome::Unresolved(Unresolved::UnknownExtension(b"ydr".to_vec()))
    );

    let mut malformed = [entry(0, Some(0), Some(hash64(b"item")), None)];
    malformed[0].name_hash = Err("bad".to_string());
    let resolved = resolve(&StringTable::default(), &malformed);
    assert_eq!(resolved.unusable_rows, 1);
    assert_eq!(resolved.rows[0].resolution, Resolution::Unresolved);
}

#[test]
fn one_spelling_from_two_sources_is_kept_once() {
    let hash = hash64(b"item");
    let entries = [entry(0, Some(0), Some(hash), None)];
    let table = parse(&format!("item.rpf\nhash64:{hash:016X}\titem.rpf\n"));
    let resolved = resolve(&table, &entries);
    assert_eq!(
        resolved.rows[0].resolution,
        Resolution::Resolved(vec![Name {
            text: "item.rpf".to_string(),
            provenance: Provenance::CandidatePath,
            algorithm: Class::Hash64,
            verified: true,
        }])
    );
}

#[test]
fn keeps_the_stored_keys_untouched() {
    let hash = hash64(b"item");
    let key = joaat(b"item");
    let entries = [entry(0, Some(0), Some(hash), Some(key))];
    let table = parse(&format!(
        "hash64:{hash:016X}\titem\nkey32:{key:08X}\titem\n"
    ));
    let resolved = resolve(&table, &entries);
    assert!(resolved.rows[0].resolution.is_resolved());
    assert_eq!(entries[0].name_hash, Ok(Some(hash)));
    assert_eq!(entries[0].name_key, Ok(Some(key)));
    assert_eq!(resolved.rows[0].namespace, Namespace::Hash64);
}
