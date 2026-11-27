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

/// A bounds record: `min.xyz`, `min.x`, `max.xyz`, `max.x`.
fn bounds_record(system: &mut [u8], at: usize, min: [f32; 3], max: [f32; 3]) {
    for (ix, value) in [
        min[0], min[1], min[2], min[0], max[0], max[1], max[2], max[0],
    ]
    .into_iter()
    .enumerate()
    {
        put_f32(system, at + 4 * ix, value);
    }
}

/// A drawable with one populated LOD slot, one model, two geometries and one
/// shader.
fn drawable() -> (Vec<u8>, Vec<u8>) {
    let mut system = vec![0u8; 0x1200];
    // Header.
    put_u64(&mut system, 0x08, system_ptr(0x1000));
    put_u64(&mut system, 0x10, system_ptr(0x980));
    put_f32(&mut system, 0x2C, 1.5);
    for (ix, value) in [-1.0f32, -1.0, -1.0].into_iter().enumerate() {
        put_f32(&mut system, 0x30 + 4 * ix, value);
    }
    for (ix, value) in [1.0f32, 1.0, 1.0].into_iter().enumerate() {
        put_f32(&mut system, 0x40 + 4 * ix, value);
    }
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

    // Model, its geometry array and its bounds array.
    put_u64(&mut system, 0x308, system_ptr(0x340));
    put_u16(&mut system, 0x310, 2);
    put_u16(&mut system, 0x312, 2);
    put_u32(&mut system, 0x314, 0x0002_0000);
    put_u64(&mut system, 0x318, system_ptr(0x1140));
    put_u64(&mut system, 0x320, system_ptr(0x220));
    put_u64(&mut system, 0x330, 0x11);
    put_u64(&mut system, 0x340, system_ptr(0x380));
    put_u64(&mut system, 0x348, system_ptr(0x440));

    // Aggregate, then one record per geometry.
    bounds_record(&mut system, 0x1140, [-1.0, -1.0, -1.0], [1.0, 1.0, 1.0]);
    bounds_record(&mut system, 0x1160, [-1.0, -1.0, -1.0], [1.0, 1.0, 0.0]);
    bounds_record(&mut system, 0x1180, [-1.0, -1.0, 0.0], [1.0, 1.0, 1.0]);

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

    // Index descriptors and records: cluster count, count A and count B.
    for (descriptor, record, buffer, elements, graphics, count_a, count_b) in [
        (0x600u64, 0x620u64, 0x660u64, 40u32, 0x300u64, 5u16, 7u16),
        (0x680, 0x6A0, 0x6E0, 12, 0x500, 3, 4),
    ] {
        put_u64(&mut system, descriptor as usize, system_ptr(buffer));
        put_u16(&mut system, descriptor as usize + 8, 1);
        put_u16(&mut system, descriptor as usize + 0x0A, count_a);
        put_u32(
            &mut system,
            descriptor as usize + 0x0C,
            u32::from(count_b) << 8,
        );
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

    // Shader group, one shader, two texture parameters with one bound slot
    // and one non-texture parameter.
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
    // `{u32 name hash, u32 packed}` pairs: two texture entries and one other.
    put_u32(&mut system, 0xBA8, 0xC8E8_C282);
    put_u32(&mut system, 0xBAC, 0);
    put_u32(&mut system, 0xBB0, 0xC8E8_C282);
    put_u32(&mut system, 0xBB4, 4);
    put_u32(&mut system, 0xBB8, 0x0CD2_7763);
    put_u32(&mut system, 0xBBC, 0x100);
    system[0x1100..0x1112].copy_from_slice(b"SYNTHETIC-DRAWABLE");

    let mut graphics = vec![0u8; 0x600];
    // Declaration tables at both graphics targets.
    graphics[0x100..0x104].copy_from_slice(&MARKER);
    put_u32(&mut graphics, 0x104, (0x180 / 2) << 8 | 0x21);
    graphics[0x400..0x404].copy_from_slice(&MARKER);
    // Index headers matching both descriptors.
    put_u32(&mut graphics, 0x300, 0x8000_0001);
    put_u32(&mut graphics, 0x304, 5);
    put_u32(&mut graphics, 0x308, 7);
    put_u32(&mut graphics, 0x500, 0x8000_0001);
    put_u32(&mut graphics, 0x504, 3);
    put_u32(&mut graphics, 0x508, 4);
    (system, graphics)
}

#[test]
fn walks_the_verified_drawable_chain() {
    let (system, graphics) = drawable();
    assert!(is_drawable(&system, &graphics));
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "complete", "{:?}", report.issues);
    assert!(report.issues.is_empty(), "{:?}", report.issues);

    assert_eq!(report.header.page_map, Some(0x1000));
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
    assert_eq!(index.count_a, 5);
    assert_eq!(index.count_b, 7);
    assert_eq!(index.count_word, 7 << 8);
    assert_eq!(index.low_byte, 0);
    assert_eq!(index.header, Some([0x8000_0001, 5, 7]));
    assert_eq!(index.header_matches, Some(true));
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
    assert_eq!(shader.shader_hash, 0x0000_1234);
    assert_eq!(shader.texture_parameters, 2);
    assert_eq!(shader.total_parameters, 3);
    assert_eq!(shader.slots, 2);
    assert_eq!(shader.bound_slots, 1);
    assert_eq!(shader.parameters.len(), 3);
    assert!(shader.parameters[0].texture);
    assert_eq!(shader.parameters[0].name_hash, 0xC8E8_C282);
    assert_eq!(shader.parameters[1].slot, 1);
    assert!(!shader.parameters[2].texture);
    assert_eq!(shader.slot_states.len(), 2);
    assert_eq!(
        shader.slot_states[0].state,
        crate::dictionary::SlotState::Bound
    );
    assert_eq!(shader.slot_states[0].key, Some(0x1122_3344_5566_7788));
    assert_eq!(
        shader.slot_states[1].state,
        crate::dictionary::SlotState::Unbound
    );
    assert_eq!(report.materials.declared_slots, 2);
    assert_eq!(report.materials.bound, 1);
    assert_eq!(report.materials.unbound, 1);
    assert_eq!(report.materials.invalid, 0);
    assert_eq!(report.materials.distinct_keys, 1);
    assert_eq!(report.model_union.models, 1);
    assert!(report.model_union.matches);
    assert_eq!(report.model_union.trivial, 0);
    let header_union = report.header_union.expect("a header union check");
    assert!(header_union.matches, "{header_union:?}");
    assert!(header_union.finite);
    let bounds = model.bounds.as_ref().expect("a bounds array");
    assert_eq!(bounds.records, 3);
    assert_eq!(bounds.per_geometry.len(), 2);
    assert_eq!(bounds.union_matches, Some(true));
    assert!(bounds.extra_min_equal);
    assert!(bounds.extra_max_equal);

    // The declaration tables match the present layout offsets.
    assert_eq!(buffer.declarations.len(), 2);
    assert_eq!(buffer.declarations[0].format, 0x42);
    assert_eq!(buffer.declarations[0].offset, 0x80);
    assert_eq!(buffer.declarations[1].format, 0x21);
    assert_eq!(buffer.declarations[1].offset, 0x180);
    assert!(buffer.declarations.iter().all(|entry| entry.matches_layout));
    assert_eq!(buffer.packed_flags, 0x51);
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

#[test]
fn a_single_geometry_model_needs_only_the_aggregate_record() {
    let (mut system, graphics) = drawable();
    put_u16(&mut system, 0x310, 1);
    put_u16(&mut system, 0x312, 1);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "complete", "{:?}", report.issues);
    let model = &report.lod[0].models[0];
    assert_eq!(model.geometry_count, 1);
    let bounds = model.bounds.as_ref().expect("a bounds array");
    assert_eq!(bounds.records, 1);
    assert!(bounds.per_geometry.is_empty());
    assert_eq!(bounds.union_matches, None);
    assert_eq!(report.model_union.trivial, 1);
    assert_eq!(report.model_union.models, 0);
    assert!(report.model_union.matches);
}

#[test]
fn a_multi_geometry_aggregate_beyond_the_tolerance_fails() {
    let (mut system, graphics) = drawable();
    // The aggregate's maximum stays at 1.0; the second geometry reaches 1.1.
    bounds_record(&mut system, 0x1180, [-1.0, -1.0, 0.0], [1.0, 1.0, 1.1]);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "partial");
    assert!(!report.model_union.matches);
    assert!(report.model_union.delta > AABB_TOLERANCE);
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Arithmetic {
            field: "model bounds aggregate",
            ..
        }
    )));
}

#[test]
fn a_header_union_exception_keeps_the_drawable_complete() {
    let (mut system, graphics) = drawable();
    // The header maximum is larger than every model aggregate.
    put_f32(&mut system, 0x48, 50.0);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "complete", "{:?}", report.issues);
    assert!(report.model_union.matches);
    let header_union = report.header_union.expect("a header union check");
    assert!(!header_union.matches);
    assert!(header_union.delta >= 49.0);
}

#[test]
fn non_finite_bounds_are_reported() {
    let (mut system, graphics) = drawable();
    put_f32(&mut system, 0x1140, f32::NAN);
    let report = inspect(&system, &graphics).unwrap();
    assert!(report.header_union.is_some_and(|check| !check.finite));
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Arithmetic {
            field: "model bounds array",
            ..
        }
    )));
}

#[test]
fn index_count_b_is_masked_out_of_the_word() {
    let (mut system, graphics) = drawable();
    // The low byte is not count B and the high byte is not either.
    put_u32(&mut system, 0x600 + 0x0C, (0xAB << 8) | 0x5A);
    let report = inspect(&system, &graphics).unwrap();
    let index = report.lod[0].models[0].geometries[0]
        .index
        .as_ref()
        .expect("an index descriptor");
    assert_eq!(index.count_b, 0xAB);
    assert_eq!(index.low_byte, 0x5A);
    assert_eq!(index.high_byte, 0);
}

#[test]
fn a_descriptor_and_header_count_disagreement_is_reported() {
    let (system, mut graphics) = drawable();
    // The index bytes claim a different count B.
    put_u32(&mut graphics, 0x308, 9);
    let report = inspect(&system, &graphics).unwrap();
    let index = report.lod[0].models[0].geometries[0]
        .index
        .as_ref()
        .expect("an index descriptor");
    assert_eq!(index.header_matches, Some(false));
    let message = report
        .issues
        .iter()
        .find_map(|issue| match issue {
            Issue::Arithmetic {
                field: "index header",
                message,
            } => Some(message.clone()),
            _ => None,
        })
        .expect("an index header issue");
    assert!(message.contains("0x00000009"), "{message}");
    assert!(message.contains("7"), "{message}");
}

#[test]
fn packed_counts_with_0x61_flags_decode_the_same_count() {
    let (mut system, graphics) = drawable();
    put_u32(&mut system, 0x700 + 0x138, (32 << 10) | 0x61);
    let report = inspect(&system, &graphics).unwrap();
    let buffer = report.lod[0].models[0].geometries[0]
        .vertex_buffer
        .as_ref()
        .expect("a vertex buffer");
    assert_eq!(buffer.vertex_count, 32);
    assert_eq!(buffer.packed_flags, 0x61);
    assert_eq!(buffer.layout_end, buffer.declared_bytes);
}

#[test]
fn a_vertex_buffer_size_disagreement_is_reported() {
    let (mut system, graphics) = drawable();
    // 129 elements of 4 bytes is 516 bytes; the layout still ends at 512.
    put_u32(&mut system, 0x508, 129);
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

#[test]
fn a_declaration_offset_that_no_layout_entry_uses_is_reported() {
    let (system, mut graphics) = drawable();
    put_u32(&mut graphics, 0x108, (0x200 / 2) << 8 | 0x28);
    let report = inspect(&system, &graphics).unwrap();
    let first = report.lod[0].models[0].geometries[0]
        .vertex_buffer
        .as_ref()
        .expect("a vertex buffer");
    assert_eq!(first.declarations.len(), 3);
    assert_eq!(first.declarations[2].offset, 0x200);
    assert!(!first.declarations[2].matches_layout);
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Arithmetic {
            field: "declaration table",
            ..
        }
    )));
}

#[test]
fn a_missing_declaration_terminator_is_reported() {
    let (system, mut graphics) = drawable();
    // Every word of the table is non-zero for the whole window.
    for ix in 0..MAX_DECLARATIONS {
        put_u32(&mut graphics, 0x100 + 4 * ix, (0x80 / 2) << 8 | 0x42);
    }
    let report = inspect(&system, &graphics).unwrap();
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Missing {
            field: "the declaration-table terminator"
        }
    )));
}

#[test]
fn a_texture_slot_outside_the_declared_count_is_invalid() {
    let (mut system, graphics) = drawable();
    // The second texture parameter selects slot 9 with only two declared.
    put_u32(&mut system, 0xBB4, 9 << 2);
    let report = inspect(&system, &graphics).unwrap();
    let shader = &report.shader_group.as_ref().unwrap().shaders[0];
    assert_eq!(
        shader.slot_states[1].state,
        crate::dictionary::SlotState::Invalid
    );
    assert_eq!(report.materials.invalid, 1);
    assert_eq!(report.materials.unbound, 0);
}

#[test]
fn a_non_texture_parameter_class_has_no_slot() {
    let (mut system, graphics) = drawable();
    // The second texture parameter declares class 1.
    put_u32(&mut system, 0xBB4, (1 << 2) | 1);
    let report = inspect(&system, &graphics).unwrap();
    let shader = &report.shader_group.as_ref().unwrap().shaders[0];
    assert_eq!(shader.slot_states.len(), 1);
    assert_eq!(report.materials.declared_slots, 2);
    assert_eq!(report.materials.bound, 1);
}

#[test]
fn a_shader_without_texture_parameters_may_store_no_slot_table() {
    let (mut system, graphics) = drawable();
    // No texture parameter, no non-texture parameter, no slot table.
    system[0xBA1] = 0;
    put_u16(&mut system, 0xBA4, 0);
    put_u64(&mut system, 0xA10, 0);
    let report = inspect(&system, &graphics).unwrap();
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.status, "complete");
    let shader = &report.shader_group.as_ref().unwrap().shaders[0];
    assert_eq!(shader.texture_parameters, 0);
    assert_eq!(shader.slots, 0);
    assert_eq!(shader.bound_slots, 0);
    assert!(shader.parameters.is_empty());
    assert!(shader.slot_states.is_empty());
    assert_eq!(report.materials.declared_slots, 0);
}

#[test]
fn a_missing_slot_table_with_texture_parameters_is_reported() {
    let (mut system, graphics) = drawable();
    // The shader still declares two texture parameters.
    put_u64(&mut system, 0xA10, 0);
    let report = inspect(&system, &graphics).unwrap();
    assert_eq!(report.status, "partial");
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Pointer {
            field: "texture slot table",
            ..
        }
    )));
    let shader = &report.shader_group.as_ref().unwrap().shaders[0];
    assert_eq!(shader.texture_parameters, 2);
    assert!(shader.slot_states.is_empty());
    assert_eq!(report.materials.bound, 0);
}

#[test]
fn an_overflowing_bounds_extent_is_clamped() {
    let (mut system, graphics) = drawable();
    put_u16(&mut system, 0x310, 0xFF00);
    put_u16(&mut system, 0x312, 0xFFFF);
    let report = inspect(&system, &graphics).unwrap();
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::Clamped {
            field: "model bounds array",
            ..
        }
    )));
    let bounds = report.lod[0].models[0].bounds.as_ref().unwrap();
    assert!(bounds.records < 0xFF01);
}

#[test]
fn a_member_drawable_carries_no_page_map() {
    let (mut system, graphics) = drawable();
    // A drawable inside a fragment holds zero in its page-map word.
    put_u64(&mut system, 0x08, 0);
    assert!(!is_drawable(&system, &graphics));
    assert!(!is_drawable_at(&system, &graphics, 0));
    assert!(inspect(&system, &graphics).is_none());
    assert!(is_member_drawable_at(&system, &graphics, 0));
    let report = inspect_member_at(&system, &graphics, 0).expect("a member drawable");
    assert_eq!(report.header.page_map, None);
    assert_eq!(report.status, "complete");
}

#[test]
fn a_member_word_that_is_not_a_pointer_is_still_rejected() {
    let (mut system, graphics) = drawable();
    put_u64(&mut system, 0x08, 0x1234_5678);
    assert!(!is_member_drawable_at(&system, &graphics, 0));
    assert!(inspect_member_at(&system, &graphics, 0).is_none());
}
