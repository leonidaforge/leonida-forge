//! Tests on synthetic EDUP payloads built in memory.

use super::*;

fn payload(entries: &[(u64, u64)], blob: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (first, second) in entries {
        bytes.extend_from_slice(&first.to_le_bytes());
        bytes.extend_from_slice(&second.to_le_bytes());
    }
    bytes.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    bytes.extend_from_slice(blob);
    bytes
}

#[test]
fn parses_entry_framing_and_the_blob() {
    let bytes = payload(&[(1, 100), (2, 100), (3, 200)], &[0xAB; 16]);
    let report = parse(&bytes, 1024).unwrap();
    assert_eq!(report.count, 3);
    assert_eq!(
        report.entries[0],
        Entry {
            first: 1,
            second: 100
        }
    );
    assert!(report.first_unique);
    assert_eq!(report.first_distinct, 3);
    assert_eq!(report.second_distinct, 2);
    assert!(report.fields_disjoint);
    assert_eq!(report.blob.offset, 8 + 3 * 16 + 4);
    assert_eq!(report.blob.len, 16);
    assert_eq!(report.size, 8 + 3 * 16 + 4 + 16);
}

#[test]
fn an_empty_table_with_a_blob_is_valid() {
    let bytes = payload(&[], &[0u8; 16]);
    let report = parse(&bytes, 1024).unwrap();
    assert_eq!(report.count, 0);
    assert!(report.entries.is_empty());
    assert_eq!(report.blob.len, 16);
}

#[test]
fn a_truncated_entry_is_an_error() {
    let mut bytes = payload(&[(1, 2)], &[0u8; 16]);
    bytes.truncate(bytes.len() - 8);
    assert!(parse(&bytes, 1024).is_err());
}

#[test]
fn a_count_beyond_the_limit_is_an_error() {
    let bytes = payload(&[(1, 2)], &[0u8; 16]);
    assert!(parse(&bytes, 0).is_err());
}

#[test]
fn an_invalid_trailing_length_is_an_error() {
    let mut bytes = payload(&[(1, 2)], &[0u8; 16]);
    let length_at = 8 + 16;
    bytes[length_at..length_at + 4].copy_from_slice(&99u32.to_le_bytes());
    assert!(parse(&bytes, 1024).is_err());
}

#[test]
fn a_not_edup_magic_is_rejected() {
    assert!(matches!(parse(b"EDUQ", 8), Err(Error::NotEdup)));
    assert!(!is_edup(b"EDU"));
}

#[test]
fn the_comparison_reports_each_direction() {
    let bytes = payload(&[(1, 100), (2, 100), (3, 200)], &[0u8; 16]);
    let report = parse(&bytes, 1024).unwrap();

    let second = compare(&report, &[100, 200], 8);
    assert_eq!(second.direction, Direction::SecondField);
    assert_eq!(second.second_matches, 3);
    assert_eq!(second.first_matches, 0);
    assert_eq!(second.second_keys, vec![100, 100, 200]);

    let first = compare(&report, &[1, 2, 3], 8);
    assert_eq!(first.direction, Direction::FirstField);
    assert_eq!(first.first_matches, 3);

    let both = compare(&report, &[1, 100], 8);
    assert_eq!(both.direction, Direction::Ambiguous);
    assert_eq!(both.both_matches, 1);

    let neither = compare(&report, &[9, 99], 8);
    assert_eq!(neither.direction, Direction::Unresolved);
    assert_eq!(neither.first_matches, 0);
    assert_eq!(neither.second_matches, 0);

    let empty = compare(&parse(&payload(&[], &[]), 8).unwrap(), &[1], 8);
    assert_eq!(empty.direction, Direction::NotEvaluated);
}

#[test]
fn duplicates_are_counted_and_kept_out_of_the_key_detail() {
    let bytes = payload(&[(1, 5), (2, 5), (3, 5)], &[0u8; 16]);
    let report = parse(&bytes, 1024).unwrap();
    assert!(report.first_unique);
    assert_eq!(report.second_distinct, 1);
    let comparison = compare(&report, &[5], 1);
    assert_eq!(comparison.second_matches, 3);
    assert_eq!(comparison.second_keys, vec![5]);
}
