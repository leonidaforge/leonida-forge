//! Synthetic drawable dictionaries. None of these bytes come from the game.

use super::*;

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn system_ptr(offset: u64) -> u64 {
    0x5000_0000 | offset
}

fn graphics_ptr(offset: u64) -> u64 {
    0x6000_0000 | offset
}

/// The chain a member drawable needs for the walk to resolve.
fn member(system: &mut [u8], at: usize, name_at: usize, name: &str) {
    // The member's own page-map word stays zero.
    put_u64(system, at + 0x50, system_ptr(0x2C0));
    put_u64(system, at + 0xA8, system_ptr(name_at as u64));
    system[name_at..name_at + name.len()].copy_from_slice(name.as_bytes());
}

fn chain(system: &mut [u8]) {
    // LOD group, model array, model, geometry array, geometry, vertex buffer,
    // index descriptor, index record and bounds record.
    put_u64(system, 0x2C0, system_ptr(0x2E0));
    put_u16(system, 0x2C8, 1);
    put_u16(system, 0x2CA, 1);
    put_u64(system, 0x2E0, system_ptr(0x2F0));
    put_u64(system, 0x2F8, system_ptr(0x330));
    put_u16(system, 0x300, 1);
    put_u16(system, 0x302, 1);
    put_u32(system, 0x304, 3);
    put_u64(system, 0x308, system_ptr(0x490));
    put_u64(system, 0x330, system_ptr(0x340));
    put_u64(system, 0x348, system_ptr(0x390));
    put_u64(system, 0x380, system_ptr(0x3E0));
    put_u32(system, 0x398, 8);
    put_u16(system, 0x39C, 4);
    put_u64(system, 0x3A8, graphics_ptr(0x00));
    put_u64(system, 0x3E0, system_ptr(0x400));
    put_u16(system, 0x3E8, 1);
    put_u16(system, 0x3EA, 6);
    put_u32(system, 0x3EC, 0x0000_0600);
    put_u32(system, 0x408, 6);
    put_u16(system, 0x40C, 2);
    put_u64(system, 0x418, graphics_ptr(0x40));
}

/// A dictionary with `count` members. Member 0 resolves and is named
/// `synthetic_a.#dr`; member 1 resolves and is named `synthetic_b.#dr`.
fn dictionary(count: u16) -> (Vec<u8>, Vec<u8>) {
    let mut system = vec![0u8; 0x600];
    let mut graphics = vec![0u8; 0x100];
    // Root.
    put_u64(&mut system, 0x08, system_ptr(0x430));
    put_u64(&mut system, 0x18, WORD_18);
    put_u64(&mut system, 0x20, system_ptr(0x460));
    put_u16(&mut system, 0x28, count);
    put_u16(&mut system, 0x2A, count);
    put_u64(&mut system, 0x30, system_ptr(0x470));
    put_u16(&mut system, 0x38, count);
    put_u16(&mut system, 0x3A, count);
    // Page map: one system page, one graphics page.
    system[0x438] = 1;
    system[0x439] = 1;
    // Members and their shared chain.
    member(&mut system, 0x100, 0x280, "synthetic_a.#dr");
    member(&mut system, 0x1C0, 0x2A0, "synthetic_b.#dr");
    chain(&mut system);
    graphics[0x00..4].copy_from_slice(&[0x42, 0x40, 0x00, 0x00]);
    // Hashes ascend, and the values are positional.
    let hashes = [0x1111_1111u32, 0x2222_2222];
    let values = [system_ptr(0x100), system_ptr(0x1C0)];
    for index in 0..usize::from(count) {
        put_u32(&mut system, 0x460 + index * 4, hashes[index]);
        put_u64(&mut system, 0x470 + index * 8, values[index]);
    }
    (system, graphics)
}

#[test]
fn a_single_member_dictionary_is_recognised() {
    let (system, graphics) = dictionary(1);
    assert!(is_drawable_dictionary(&system, &graphics));
    let report = parse(&system, &graphics).expect("a dictionary");
    assert_eq!(report.header.count, 1);
    assert_eq!(report.header.page_map, 0x430);
    assert_eq!(report.header.word_18, WORD_18);
    assert!(report.hash_sorted);
    assert!(!report.empty);
    assert_eq!(report.members.len(), 1);
    assert_eq!(report.members[0].hash, 0x1111_1111);
    assert_eq!(report.members[0].state, MemberState::Drawable);
    assert_eq!(report.members[0].drawable, Some(0x100));
    assert_eq!(report.members[0].name.as_deref(), Some("synthetic_a.#dr"));
}

#[test]
fn every_member_of_a_multi_member_dictionary_is_listed() {
    let (system, graphics) = dictionary(2);
    let report = parse(&system, &graphics).unwrap();
    assert_eq!(report.members.len(), 2);
    assert_eq!(report.drawable_members().count(), 2);
    assert_eq!(report.members[1].name.as_deref(), Some("synthetic_b.#dr"));
    assert_eq!(report.members[1].drawable, Some(0x1C0));
}

#[test]
fn an_empty_dictionary_is_valid() {
    let (system, graphics) = dictionary(0);
    assert!(is_drawable_dictionary(&system, &graphics));
    let report = parse(&system, &graphics).unwrap();
    assert!(report.empty);
    assert!(report.members.is_empty());
    assert_eq!(report.header.count, 0);
}

#[test]
fn an_empty_root_without_the_observed_word_is_not_accepted() {
    let (mut system, graphics) = dictionary(0);
    put_u64(&mut system, 0x18, 0);
    assert!(!is_drawable_dictionary(&system, &graphics));
    // The root still parses; only the recognition test needs the word.
    assert!(parse(&system, &graphics).is_ok());
}

#[test]
fn a_null_member_does_not_hide_the_others() {
    let (mut system, graphics) = dictionary(2);
    put_u64(&mut system, 0x470, 0);
    let report = parse(&system, &graphics).unwrap();
    assert_eq!(report.members[0].state, MemberState::Null);
    assert_eq!(report.members[0].drawable, None);
    assert_eq!(report.members[1].state, MemberState::Drawable);
    assert!(is_drawable_dictionary(&system, &graphics));
}

#[test]
fn a_value_that_is_not_a_drawable_is_reported_per_member() {
    let (mut system, graphics) = dictionary(2);
    // Point the first value at the hash array, which has no drawable header.
    put_u64(&mut system, 0x470, system_ptr(0x460));
    let report = parse(&system, &graphics).unwrap();
    assert_eq!(report.members[0].state, MemberState::NotADrawable);
    assert_eq!(report.members[0].drawable, Some(0x460));
    assert_eq!(report.members[1].state, MemberState::Drawable);
    assert!(is_drawable_dictionary(&system, &graphics));
}

#[test]
fn a_value_that_is_not_a_system_pointer_is_reported_per_member() {
    let (mut system, graphics) = dictionary(2);
    put_u64(&mut system, 0x470, 0x1234_5678);
    let report = parse(&system, &graphics).unwrap();
    assert_eq!(report.members[0].state, MemberState::NotAPointer);
    assert_eq!(report.members[1].state, MemberState::Drawable);
}

#[test]
fn unsorted_hashes_are_reported_and_still_recognised() {
    let (mut system, graphics) = dictionary(2);
    put_u32(&mut system, 0x460, 0x2222_2222);
    put_u32(&mut system, 0x464, 0x1111_1111);
    let report = parse(&system, &graphics).unwrap();
    assert!(!report.hash_sorted);
    assert_eq!(report.members.len(), 2);
    // Ordering is a property of the table, not of the root's identity: the
    // members are still selected by position.
    assert!(is_drawable_dictionary(&system, &graphics));
}

#[test]
fn duplicate_hashes_keep_every_member() {
    let (mut system, graphics) = dictionary(2);
    put_u32(&mut system, 0x460, 0x2222_2222);
    put_u32(&mut system, 0x464, 0x2222_2222);
    let report = parse(&system, &graphics).unwrap();
    assert!(!report.hash_sorted, "a repeated hash is not sorted");
    assert_eq!(report.members.len(), 2, "no member is dropped");
    assert_eq!(report.members[0].index, 0);
    assert_eq!(report.members[1].index, 1);
    assert_ne!(
        report.members[0].drawable, report.members[1].drawable,
        "the two entries still name their own drawables"
    );
    assert!(is_drawable_dictionary(&system, &graphics));
}

#[test]
fn two_members_may_share_one_drawable() {
    let (mut system, graphics) = dictionary(2);
    let shared = u64_at(&system, 0x470).expect("the first member value");
    put_u64(&mut system, 0x478, shared);
    let report = parse(&system, &graphics).unwrap();
    assert_eq!(report.members.len(), 2);
    assert_eq!(report.members[0].drawable, report.members[1].drawable);
    // Both entries stay selectable by index even though the target is shared.
    assert_eq!(report.members[0].index, 0);
    assert_eq!(report.members[1].index, 1);
}

#[test]
fn a_count_above_the_capacity_is_rejected() {
    let (mut system, graphics) = dictionary(2);
    put_u16(&mut system, 0x2A, 1);
    assert_eq!(
        parse(&system, &graphics),
        Err(Error::NotADictionary(Step::Counts))
    );
}

#[test]
fn counts_that_differ_are_rejected() {
    let (mut system, graphics) = dictionary(2);
    put_u16(&mut system, 0x38, 1);
    assert_eq!(
        parse(&system, &graphics),
        Err(Error::NotADictionary(Step::Counts))
    );
}

#[test]
fn an_array_outside_the_segment_is_rejected() {
    let (mut system, graphics) = dictionary(2);
    put_u64(&mut system, 0x20, system_ptr(0x5FC));
    assert_eq!(
        parse(&system, &graphics),
        Err(Error::NotADictionary(Step::Array))
    );
}

#[test]
fn a_hash_slot_that_is_not_a_pointer_is_rejected() {
    let (mut system, graphics) = dictionary(2);
    put_u64(&mut system, 0x20, 0x1234_5678);
    assert_eq!(
        parse(&system, &graphics),
        Err(Error::NotADictionary(Step::HashPointer))
    );
}

#[test]
fn a_root_without_the_zero_word_is_rejected() {
    let (mut system, graphics) = dictionary(1);
    put_u64(&mut system, 0, 1);
    assert_eq!(
        parse(&system, &graphics),
        Err(Error::NotADictionary(Step::ZeroWord))
    );
}

#[test]
fn a_page_map_slot_that_is_not_a_pointer_is_rejected() {
    let (mut system, graphics) = dictionary(1);
    put_u64(&mut system, 0x08, 0x1234_5678);
    assert_eq!(
        parse(&system, &graphics),
        Err(Error::NotADictionary(Step::PageMap))
    );
}

#[test]
fn a_short_segment_is_rejected() {
    let (system, graphics) = dictionary(1);
    assert_eq!(
        parse(&system[..0x20], &graphics),
        Err(Error::NotADictionary(Step::HeaderLen))
    );
}
