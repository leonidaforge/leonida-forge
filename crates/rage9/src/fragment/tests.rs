//! Synthetic fragments. None of these bytes come from the game.

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

/// A fragment root at zero and one member drawable at `0x80` with a name.
///
/// Only the shape the walk resolves is filled in; the vertex and index words
/// describe a buffer the test never decodes.
fn fragment(name: &str) -> (Vec<u8>, Vec<u8>) {
    let mut system = vec![0u8; 0x400];
    let mut graphics = vec![0u8; 0x100];

    // Root header.
    put_u64(&mut system, 0x08, system_ptr(0x300));
    put_u64(&mut system, 0x10, system_ptr(0x2C0));
    put_u64(&mut system, 0x18, system_ptr(0x80));
    put_u64(&mut system, 0x28, system_ptr(0x2E0));
    for slot in 0..COUNT_SLOTS {
        put_u16(&mut system, 0x30 + slot * 2, 1);
    }

    // Member drawable at 0x80. Its page-map word stays zero.
    put_u64(&mut system, 0x80 + 0x50, system_ptr(0x160));
    put_u64(&mut system, 0x80 + 0xA8, system_ptr(0x3A0));
    put_u64(&mut system, 0x80 + 0xB8, 3);

    // LOD group and model array.
    put_u64(&mut system, 0x160, system_ptr(0x180));
    put_u16(&mut system, 0x168, 1);
    put_u16(&mut system, 0x16A, 1);
    put_u16(&mut system, 0x170, 0);
    put_u16(&mut system, 0x172, 1);
    put_u64(&mut system, 0x180, system_ptr(0x190));

    // Model.
    put_u64(&mut system, 0x198, system_ptr(0x1C0));
    put_u16(&mut system, 0x1A0, 1);
    put_u16(&mut system, 0x1A2, 1);
    put_u32(&mut system, 0x1A4, 3);
    put_u64(&mut system, 0x1A8, system_ptr(0x3C0));
    put_u64(&mut system, 0x1B0, system_ptr(0x170));
    put_u64(&mut system, 0x1C0, system_ptr(0x1D0));

    // Geometry, vertex buffer and index descriptor.
    put_u64(&mut system, 0x1D8, system_ptr(0x200));
    put_u64(&mut system, 0x210, system_ptr(0x240));
    put_u32(&mut system, 0x208, 8);
    put_u16(&mut system, 0x20C, 4);
    put_u64(&mut system, 0x218, graphics_ptr(0x00));
    put_u64(&mut system, 0x240, system_ptr(0x280));
    put_u16(&mut system, 0x248, 1);
    put_u16(&mut system, 0x24A, 6);
    put_u32(&mut system, 0x24C, 0x0000_0600);
    put_u32(&mut system, 0x288, 6);
    put_u16(&mut system, 0x28C, 2);
    put_u64(&mut system, 0x298, graphics_ptr(0x40));

    // Bounds record and name text.
    system[0x3A0..0x3A0 + name.len()].copy_from_slice(name.as_bytes());
    put_u64(&mut system, 0x3C0, 0);

    // The member drawable's name is read from the resource, so the test name
    // has to fit before the bounds record.
    assert!(0x3A0 + name.len() < 0x3C0);
    graphics[0x00..4].copy_from_slice(&[0x42, 0x40, 0x00, 0x00]);
    (system, graphics)
}

#[test]
fn a_fragment_named_member_is_recognised() {
    let (system, graphics) = fragment("synthetic_prop.#ft");
    let report = inspect(&system, &graphics).expect("a fragment");
    assert_eq!(report.name(), Some("synthetic_prop.#ft"));
    assert_eq!(report.header.drawable, 0x80);
    assert_eq!(report.header.page_map, 0x300);
    assert_eq!(report.header.counts, [1, 1, 1, 1]);
    assert_eq!(report.header.unexplained_present(), 2);
    assert!(report.named_fragment);
    assert!(
        !report.ambiguous_with_drawable,
        "a root with no LOD slot at +0x50 does not also read as a drawable"
    );
}

/// Gives the fragment root a populated LOD slot at `+0x50`, which is what a
/// resource-level drawable header reads. The bytes then satisfy both
/// interpretations.
fn also_a_drawable_at_zero(system: &mut [u8]) {
    put_u64(system, 0x50, system_ptr(0x160));
}

#[test]
fn a_named_member_that_also_reads_as_a_drawable_reports_the_ambiguity() {
    let (mut system, graphics) = fragment("synthetic_prop.#ft");
    also_a_drawable_at_zero(&mut system);
    assert!(drawable::is_drawable_at(&system, &graphics, 0));
    let report = inspect(&system, &graphics).expect("the named member decides");
    assert!(report.named_fragment);
    assert!(
        report.ambiguous_with_drawable,
        "the overlap is reported instead of hidden"
    );
    assert_eq!(
        report.header.drawable, 0x80,
        "the member the root points at is still the one that is decoded"
    );
}

#[test]
fn an_unnamed_member_that_also_reads_as_a_drawable_is_not_a_fragment() {
    let (mut system, graphics) = fragment("synthetic_prop.#dr");
    also_a_drawable_at_zero(&mut system);
    assert!(drawable::is_drawable_at(&system, &graphics, 0));
    assert!(
        inspect(&system, &graphics).is_none(),
        "an ambiguous root without a fragment name is refused, not guessed"
    );
}

#[test]
fn a_member_with_another_suffix_is_still_the_fragment_its_structure_says() {
    let (system, graphics) = fragment("synthetic_prop.#dr");
    let report = inspect(&system, &graphics).expect("the structure is a fragment root");
    assert!(!report.named_fragment);
    assert_eq!(report.name(), Some("synthetic_prop.#dr"));
    // The member itself still parses, which is what the model decoder uses.
    let member = drawable::inspect_member_at(&system, &graphics, 0x80).expect("a member drawable");
    assert!(!is_fragment_name(&member));
}

#[test]
fn a_resource_level_drawable_is_not_a_fragment() {
    let (mut system, graphics) = fragment("synthetic_prop.#ft");
    // A drawable dictionary root stores a small integer at `+0x18` rather than
    // the member pointer, so the fragment root shape does not hold.
    put_u64(&mut system, 0x18, 1);
    assert_eq!(header(&system), Err(Step::Drawable));
    assert!(inspect(&system, &graphics).is_none());
}

#[test]
fn a_drawable_that_carries_the_fragment_suffix_is_not_a_fragment() {
    // The name is the only fragment-specific signal in the bytes, so a
    // drawable whose embedded name ends in `#ft` is the case where a suffix-led
    // parser would be wrong. The root shape has to hold too, and here it does
    // not: the word at `+0x18` is not a member pointer.
    let (mut system, graphics) = fragment("misleading_prop.#ft");
    put_u64(&mut system, 0x18, 0);
    assert!(inspect(&system, &graphics).is_none());
    put_u64(&mut system, 0x18, graphics_ptr(0x80));
    assert!(
        inspect(&system, &graphics).is_none(),
        "a graphics pointer in the member slot does not resolve to a member"
    );
}

#[test]
fn a_root_without_the_zero_word_is_rejected() {
    let (mut system, _) = fragment("synthetic_prop.#ft");
    put_u64(&mut system, 0, 1);
    assert_eq!(header(&system), Err(Step::ZeroWord));
}

#[test]
fn a_root_without_a_page_map_is_rejected() {
    let (mut system, _) = fragment("synthetic_prop.#ft");
    put_u64(&mut system, 0x08, 0);
    assert_eq!(header(&system), Err(Step::PageMap));
}

#[test]
fn a_root_without_a_drawable_is_rejected() {
    let (mut system, _) = fragment("synthetic_prop.#ft");
    put_u64(&mut system, 0x18, 0);
    assert_eq!(header(&system), Err(Step::Drawable));
}

#[test]
fn a_drawable_slot_outside_the_segment_is_rejected() {
    let (mut system, graphics) = fragment("synthetic_prop.#ft");
    put_u64(&mut system, 0x18, system_ptr(0x9000));
    assert!(inspect(&system, &graphics).is_none());
}

#[test]
fn a_short_segment_is_rejected() {
    let (system, _) = fragment("synthetic_prop.#ft");
    assert_eq!(header(&system[..0x20]), Err(Step::HeaderLen));
}
