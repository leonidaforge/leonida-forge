//! Synthetic drawables. None of these bytes come from the game.

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

fn put_f32(bytes: &mut [u8], at: usize, value: f32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn system_ptr(offset: u64) -> u64 {
    0x5000_0000 | offset
}

fn graphics_ptr(offset: u64) -> u64 {
    0x6000_0000 | offset
}

/// A 52-entry layout with the given present attributes.
fn layout(system: &mut [u8], at: u64, vertex_count: u32, attributes: &[(usize, u32, u8, u8)]) {
    for &(slot, offset, size, format) in attributes {
        put_u32(system, at as usize + 4 * slot, offset);
        system[at as usize + 0xD0 + slot] = size;
        system[at as usize + 0x104 + slot] = format;
    }
    put_u32(system, at as usize + 0x138, (vertex_count << 10) | 0x51);
}

/// A drawable with one populated LOD slot, one model, two geometries and one
/// shader.
fn drawable() -> (Vec<u8>, Vec<u8>) {
    let mut system = vec![0u8; 0x1200];
    // Header.
    put_u64(&mut system, 0x08, system_ptr(0x1000));
    put_u64(&mut system, 0x10, system_ptr(0x980));
    put_f32(&mut system, 0x2C, 1.5);
    put_f32(&mut system, 0x30, -1.0);
    put_f32(&mut system, 0x40, 1.0);
    put_u64(&mut system, 0x50, system_ptr(0x200));
    for slot in 0..LOD_SLOTS {
        put_f32(&mut system, 0x70 + 4 * slot, 9998.0);
    }
    put_u32(&mut system, 0x80, 0x0000_FF01);
    put_u64(&mut system, 0xA8, system_ptr(0x1100));
    put_u64(&mut system, 0xB8, 0x103);

    // LOD group, shader indices and model array.
    put_u64(&mut system, 0x200, system_ptr(0x240));
    put_u16(&mut system, 0x208, 1);
    put_u16(&mut system, 0x20A, 1);
    put_u16(&mut system, 0x210, 0);
    put_u16(&mut system, 0x212, 1);
    put_u16(&mut system, 0x220, 0);
    put_u16(&mut system, 0x222, 1);
    put_u64(&mut system, 0x240, system_ptr(0x300));

    // Model.
    put_u64(&mut system, 0x308, system_ptr(0x340));
    put_u16(&mut system, 0x310, 2);
    put_u16(&mut system, 0x312, 2);
    put_u32(&mut system, 0x314, 0x0002_0000);
    put_u64(&mut system, 0x318, system_ptr(0x1100));
    put_u64(&mut system, 0x320, system_ptr(0x220));
    put_u64(&mut system, 0x330, 0x11);
    put_u64(&mut system, 0x340, system_ptr(0x380));
    put_u64(&mut system, 0x348, system_ptr(0x440));

    // Geometries.
    for (at, buffer, index) in [(0x380, 0x500, 0x600), (0x440, 0x540, 0x680)] {
        put_u64(&mut system, at + 0x08, system_ptr(buffer));
        put_u64(&mut system, at + 0x30, 0x1234_5678_9ABC_DEF0);
        put_u64(&mut system, at + 0x40, system_ptr(index));
    }

    // Vertex buffers.
    put_u32(&mut system, 0x508, 128);
    put_u16(&mut system, 0x50C, 4);
    put_u16(&mut system, 0x50E, 9);
    put_u32(&mut system, 0x510, 0x0000_1601);
    put_u64(&mut system, 0x518, graphics_ptr(0x100));
    put_u64(&mut system, 0x528, system_ptr(0x620));
    put_u64(&mut system, 0x540, system_ptr(0x700));

    put_u32(&mut system, 0x548, 40);
    put_u16(&mut system, 0x54C, 4);
    put_u16(&mut system, 0x54E, 9);
    put_u32(&mut system, 0x550, 0x0000_1601);
    put_u64(&mut system, 0x558, graphics_ptr(0x400));
    put_u64(&mut system, 0x568, system_ptr(0x6A0));
    put_u64(&mut system, 0x580, system_ptr(0x840));

    // Index descriptors and records.
    for (descriptor, record, buffer, elements, graphics) in [
        (0x600u64, 0x620u64, 0x660u64, 40u32, 0x300u64),
        (0x680, 0x6A0, 0x6E0, 12, 0x500),
    ] {
        put_u64(&mut system, descriptor as usize, system_ptr(buffer));
        put_u16(&mut system, descriptor as usize + 8, 1);
        put_u64(&mut system, record as usize + 0x10, INDEX_CONSTANT);
        put_u32(&mut system, buffer as usize + 0x08, elements);
        put_u16(&mut system, buffer as usize + 0x0C, 4);
        put_u64(&mut system, buffer as usize + 0x18, graphics_ptr(graphics));
        put_u64(&mut system, buffer as usize + 0x28, system_ptr(0x220));
    }

    // Layouts: 128 elements of 4 bytes hold 32 vertices of 8 + 4 bytes after
    // the 0x80 prefix; 40 elements hold 4 vertices of 8 bytes.
    layout(
        &mut system,
        0x700,
        32,
        &[(0, 0x80, 8, 0x10), (4, 0x180, 4, 0x29)],
    );
    layout(&mut system, 0x840, 4, &[(0, 0x80, 8, 0x10)]);

    // Shader group, one shader, two texture parameters with one bound slot.
    put_u64(&mut system, 0x990, system_ptr(0x9C0));
    put_u16(&mut system, 0x998, 1);
    put_u16(&mut system, 0x99A, 1);
    put_u64(&mut system, 0x9C0, system_ptr(0xA00));
    put_u32(&mut system, 0xA00, 0x0000_1234);
    put_u32(&mut system, 0xA04, 0x6D65_7461);
    put_u64(&mut system, 0xA10, system_ptr(0xAA0));
    put_u64(&mut system, 0xA20, system_ptr(0xBA0));
    put_u64(&mut system, 0xAA0, system_ptr(0xB00));
    put_u64(&mut system, 0xAA8, 0);
    put_u64(&mut system, 0xB30, system_ptr(0xB80));
    put_u64(&mut system, 0xB80, system_ptr(0x1100));
    put_u64(&mut system, 0xB88, 0x1122_3344_5566_7788);
    system[0xBA0] = 1;
    system[0xBA1] = 2;
    put_u16(&mut system, 0xBA4, 3);
    put_u16(&mut system, 0xBA6, 0x0800);
    system[0x1100..0x1112].copy_from_slice(b"SYNTHETIC-DRAWABLE");

    let mut graphics = vec![0u8; 0x600];
    graphics[0x100..0x104].copy_from_slice(&MARKER);
    graphics[0x400..0x404].copy_from_slice(&MARKER);
    (system, graphics)
}

#[test]
fn walks_the_verified_drawable_chain() {
    let (system, graphics) = drawable();
    assert!(is_drawable(&system, &graphics));
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "complete", "{:?}", report.issues);
    assert!(report.issues.is_empty(), "{:?}", report.issues);

    assert_eq!(report.header.page_map, 0x1000);
    assert_eq!(report.header.shader_group, Some(0x980));
    assert_eq!(report.header.name, Some(0x1100));
    assert_eq!(report.header.bounds.radius, 1.5);
    assert_eq!(report.empty_slots, vec![1, 2, 3]);

    assert_eq!(report.lod.len(), 1);
    let slot = &report.lod[0];
    assert_eq!(slot.slot, 0);
    assert_eq!(slot.model_count, 1);
    assert_eq!(slot.shader_indices, [0, 1]);
    assert_eq!(slot.models.len(), 1);

    let model = &slot.models[0];
    assert_eq!(model.geometry_count, 2);
    assert_eq!(model.word_14, 0x0002_0000);
    assert_eq!(model.shader_indices, Some(0x220));
    assert_eq!(model.flags, 0x11);
    assert_eq!(model.geometries.len(), 2);

    let first = &model.geometries[0];
    assert_eq!(first.word_30, 0x1234_5678_9ABC_DEF0);
    let buffer = first.vertex_buffer.as_ref().unwrap();
    assert_eq!(buffer.elements, 128);
    assert_eq!(buffer.unit, 4);
    assert_eq!(buffer.vertex_count, 32);
    assert_eq!(buffer.declared_bytes, 512);
    assert_eq!(buffer.attribute_bytes, 384);
    assert_eq!(buffer.layout_end, 512);
    assert_eq!(buffer.prefix_gap, 128);
    assert_eq!(
        buffer.attributes,
        vec![
            Attribute {
                slot: 0,
                offset: 0x80,
                size: 8,
                format: 0x10
            },
            Attribute {
                slot: 4,
                offset: 0x180,
                size: 4,
                format: 0x29
            },
        ]
    );
    let index = first.index.as_ref().unwrap();
    assert_eq!(index.clusters, 1);
    assert_eq!(index.elements, 40);
    assert_eq!(
        index.range,
        Some(Region {
            segment: Segment::Graphics,
            offset: 0x300,
            len: 160
        })
    );
    assert!(index.in_bounds);
    assert_eq!(index.constant, Some(INDEX_CONSTANT));

    assert_eq!(
        report.graphics_base,
        GraphicsBase::Unique {
            base: 0,
            supports: 2
        }
    );

    let group = report.shader_group.as_ref().unwrap();
    assert_eq!(group.count, 1);
    assert_eq!(group.shaders.len(), 1);
    let shader = &group.shaders[0];
    assert_eq!(shader.marker, 0x6D65_7461);
    assert_eq!(shader.texture_parameters, 2);
    assert_eq!(shader.total_parameters, 3);
    assert_eq!(shader.slots, 2);
    assert_eq!(shader.bound_slots, 1);
}

#[test]
fn refuses_a_payload_without_the_chain() {
    let (mut system, graphics) = drawable();
    // A zero page-map pointer breaks the header shape.
    put_u64(&mut system, 0x08, 0);
    assert!(!is_drawable(&system, &graphics));
    assert!(inspect(&system, &graphics).is_none());

    // No populated LOD slot is not a drawable either.
    let (mut system, graphics) = drawable();
    put_u64(&mut system, 0x50, 0);
    assert!(!is_drawable(&system, &graphics));
}

#[test]
fn reports_an_unresolved_pointer_and_keeps_the_rest() {
    let (mut system, graphics) = drawable();
    // The second geometry's vertex-buffer pointer no longer decodes.
    put_u64(&mut system, 0x440 + 0x08, 0x7000_0000_0000_0000);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "partial");
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Pointer {
            field: "vertex buffer",
            ..
        }
    )));
    // The first geometry is still reported.
    assert_eq!(report.lod[0].models[0].geometries.len(), 1);
}

#[test]
fn clamps_an_array_that_does_not_fit() {
    let (mut system, graphics) = drawable();
    put_u16(&mut system, 0x310, 0xFFFF);
    put_u16(&mut system, 0x312, 0xFFFF);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "partial");
    assert!(
        report
            .issues
            .iter()
            .any(|issue| matches!(issue, Issue::Clamped { .. }))
    );
}

#[test]
fn reports_an_unavailable_base_from_one_pointer() {
    let (mut system, graphics) = drawable();
    // The model now has one geometry, so one graphics offset remains.
    put_u16(&mut system, 0x310, 1);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.graphics_base, GraphicsBase::Unavailable);
}

#[test]
fn two_geometries_sharing_one_vertex_buffer_are_one_support() {
    let (mut system, graphics) = drawable();
    // The second geometry points at the first geometry's vertex buffer.
    put_u64(&mut system, 0x440 + 0x08, system_ptr(0x500));
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.lod[0].models[0].geometries.len(), 2);
    assert_eq!(report.graphics_base, GraphicsBase::Unavailable);
}

#[test]
fn reports_two_candidate_bases_as_ambiguous() {
    let (system, mut graphics) = drawable();
    // A second copy of both markers one 0x100 page later supports a second
    // base.
    graphics[0x200..0x204].copy_from_slice(&MARKER);
    graphics[0x500..0x504].copy_from_slice(&MARKER);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(
        report.graphics_base,
        GraphicsBase::Ambiguous { candidates: 2 }
    );
}

#[test]
fn reports_a_layout_whose_arithmetic_disagrees() {
    let (mut system, graphics) = drawable();
    // Claim 64 vertices with the same two arrays: the entries end at 0x300.
    put_u32(&mut system, 0x700 + 0x138, (64 << 10) | 0x51);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "partial");
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Arithmetic {
            field: "vertex layout",
            ..
        }
    )));
}
