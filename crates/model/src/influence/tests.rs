//! Influence decoding tests over synthetic vertex buffers.

use lforge_rage9::drawable::{Attribute, Declaration, VertexBuffer};
use lforge_scene::{InfluenceStatus, VertexInfluence};

use super::{InfluenceDecode, decode};

/// One declared attribute: semantic slot, declaration format, byte offset and
/// the layout size at that offset.
struct Decl {
    slot: u32,
    format: u8,
    offset: u32,
    size: u8,
}

fn buffer(declarations: &[Decl], vertex_count: usize, bytes: usize) -> VertexBuffer {
    VertexBuffer {
        at: 0,
        elements: 0,
        unit: 4,
        word_0e: 0,
        word_10: 0,
        graphics: 0,
        layout: None,
        vertex_count: vertex_count as u32,
        packed_flags: 0,
        declared_bytes: bytes as u64,
        attribute_bytes: 0,
        layout_end: 0,
        prefix_gap: 0,
        attributes: declarations
            .iter()
            .enumerate()
            .map(|(index, entry)| Attribute {
                slot: index,
                offset: entry.offset,
                size: entry.size,
                format: 0,
            })
            .collect(),
        declarations: declarations
            .iter()
            .map(|entry| Declaration {
                slot: entry.slot as usize,
                format: entry.format,
                offset: entry.offset,
                matches_layout: true,
            })
            .collect(),
        declaration_end: None,
    }
}

fn weights_and_indices(weights: &[[u8; 4]], indices: &[[u8; 4]], bones: usize) -> InfluenceDecode {
    let mut blob = vec![0u8; 0x100];
    for (vertex, lanes) in weights.iter().enumerate() {
        blob[0x20 + vertex * 4..0x20 + vertex * 4 + 4].copy_from_slice(lanes);
    }
    for (vertex, lanes) in indices.iter().enumerate() {
        blob[0x80 + vertex * 4..0x80 + vertex * 4 + 4].copy_from_slice(lanes);
    }
    let buffer = buffer(
        &[
            Decl {
                slot: 6,
                format: 0x26,
                offset: 0x20,
                size: 4,
            },
            Decl {
                slot: 8,
                format: 0x25,
                offset: 0x80,
                size: 4,
            },
        ],
        weights.len(),
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    decode(&buffer, &blob, weights.len(), Some(bones), &mut diagnostics)
}

fn decoded(decode: InfluenceDecode) -> lforge_scene::VertexInfluences {
    match decode {
        InfluenceDecode::Decoded(influences) => influences,
        other => panic!("expected a decoded set, got {other:?}"),
    }
}

fn unsupported(decode: InfluenceDecode) -> String {
    match decode {
        InfluenceDecode::Unsupported { reason } => reason,
        other => panic!("expected an unsupported set, got {other:?}"),
    }
}

#[test]
fn four_u8_weights_and_four_u8_indices_decode_with_their_lane_pairs() {
    let influences = decoded(weights_and_indices(
        &[[255, 0, 0, 0], [128, 127, 0, 0]],
        &[[3, 0, 0, 0], [3, 5, 0, 0]],
        10,
    ));
    assert_eq!(influences.status, InfluenceStatus::Complete);
    assert!(influences.weighted);
    assert_eq!(influences.lanes, 4);
    assert_eq!(influences.max_influences, 2);
    assert_eq!(influences.bones, vec![3, 5]);
    assert_eq!(
        influences.per_vertex[0][0],
        VertexInfluence {
            bone: 3,
            weight: 1.0
        }
    );
    assert_eq!(influences.per_vertex[0][1], VertexInfluence::NONE);
    assert_eq!(influences.per_vertex[1][0].bone, 3);
    assert!((influences.per_vertex[1][0].weight - 128.0 / 255.0).abs() < 1e-6);
    assert!((influences.per_vertex[1][1].weight - 127.0 / 255.0).abs() < 1e-6);
    assert_eq!(
        influences.resolution,
        lforge_scene::BoneResolution::DirectSkeleton
    );
}

#[test]
fn a_127_total_is_a_supported_denominator() {
    let influences = decoded(weights_and_indices(&[[127, 0, 0, 0]], &[[1, 0, 0, 0]], 4));
    assert_eq!(influences.status, InfluenceStatus::Complete);
    assert_eq!(influences.per_vertex[0][0].weight, 1.0);
}

#[test]
fn an_unnormalised_total_is_reported_and_uses_its_own_denominator() {
    let influences = decoded(weights_and_indices(&[[204, 0, 0, 0]], &[[2, 0, 0, 0]], 4));
    assert!(matches!(
        influences.status,
        InfluenceStatus::Unnormalised {
            vertex: 0,
            total: 204
        }
    ));
    assert!(!influences.deformable());
    assert_eq!(influences.per_vertex[0][0].weight, 1.0);
}

#[test]
fn an_active_index_outside_the_skeleton_is_never_clamped() {
    let reason = unsupported(weights_and_indices(&[[255, 0, 0, 0]], &[[9, 0, 0, 0]], 4));
    assert!(reason.contains("bone 9"), "{reason}");
}

#[test]
fn a_zero_weight_vertex_is_not_deformed() {
    let reason = unsupported(weights_and_indices(&[[0, 0, 0, 0]], &[[1, 0, 0, 0]], 4));
    assert!(reason.contains("all zero"), "{reason}");
}

#[test]
fn a_weight_outside_the_index_lanes_is_rejected() {
    let mut blob = vec![0u8; 0x100];
    // One vertex, two u32 indices (8 bytes) at 0x40, four u8 weights at 0x20.
    blob[0x20..0x24].copy_from_slice(&[0, 0, 0, 255]);
    blob[0x40..0x44].copy_from_slice(&5u32.to_le_bytes());
    let buffer = buffer(
        &[
            Decl {
                slot: 6,
                format: 0x26,
                offset: 0x20,
                size: 4,
            },
            Decl {
                slot: 8,
                format: 0x4a,
                offset: 0x40,
                size: 8,
            },
        ],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let reason = unsupported(decode(&buffer, &blob, 1, Some(10), &mut diagnostics));
    assert!(reason.contains("lane 3"), "{reason}");
}

#[test]
fn four_u32_indices_are_read_at_their_own_width() {
    let mut blob = vec![0u8; 0x100];
    blob[0x20..0x24].copy_from_slice(&[255, 0, 0, 0]);
    blob[0x40..0x44].copy_from_slice(&368u32.to_le_bytes());
    let buffer = buffer(
        &[
            Decl {
                slot: 6,
                format: 0x26,
                offset: 0x20,
                size: 4,
            },
            Decl {
                slot: 8,
                format: 0x8c,
                offset: 0x40,
                size: 16,
            },
        ],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let influences = decoded(decode(&buffer, &blob, 1, Some(386), &mut diagnostics));
    assert_eq!(influences.per_vertex[0][0].bone, 368);
    assert_eq!(influences.lanes, 4);
}

#[test]
fn two_u32_indices_are_read_at_their_own_width() {
    let mut blob = vec![0u8; 0x100];
    blob[0x20..0x24].copy_from_slice(&[128, 127, 0, 0]);
    blob[0x40..0x44].copy_from_slice(&338u32.to_le_bytes());
    blob[0x44..0x48].copy_from_slice(&5u32.to_le_bytes());
    let buffer = buffer(
        &[
            Decl {
                slot: 6,
                format: 0x26,
                offset: 0x20,
                size: 4,
            },
            Decl {
                slot: 8,
                format: 0x4a,
                offset: 0x40,
                size: 8,
            },
        ],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let influences = decoded(decode(&buffer, &blob, 1, Some(386), &mut diagnostics));
    assert_eq!(influences.lanes, 2);
    assert_eq!(influences.max_influences, 2);
    assert_eq!(influences.bones, vec![5, 338]);
}

#[test]
fn a_single_u8_index_carries_an_implicit_unit_weight() {
    let mut blob = vec![0u8; 0x40];
    blob[0x20..0x24].copy_from_slice(&[7, 8, 9, 10]);
    let buffer = buffer(
        &[Decl {
            slot: 8,
            format: 0x00,
            offset: 0x20,
            size: 1,
        }],
        4,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let influences = decoded(decode(&buffer, &blob, 4, Some(32), &mut diagnostics));
    assert_eq!(influences.status, InfluenceStatus::Complete);
    assert!(influences.single_influence());
    // Four vertices name four different bones, so this is single-influence
    // vertex skinning, not one rigid piece.
    assert!(!influences.rigid_attachment());
    assert_eq!(influences.bones, vec![7, 8, 9, 10]);
    assert!(!influences.inferred());
    assert_eq!(influences.lanes, 1);
    for (vertex, expected) in [7u16, 8, 9, 10].into_iter().enumerate() {
        assert_eq!(
            influences.per_vertex[vertex][0],
            VertexInfluence {
                bone: expected,
                weight: 1.0
            }
        );
    }
}

#[test]
fn a_single_u16_index_reaches_past_255() {
    let mut blob = vec![0u8; 0x40];
    blob[0x20..0x22].copy_from_slice(&385u16.to_le_bytes());
    let buffer = buffer(
        &[Decl {
            slot: 8,
            format: 0x00,
            offset: 0x20,
            size: 2,
        }],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let influences = decoded(decode(&buffer, &blob, 1, Some(386), &mut diagnostics));
    assert_eq!(influences.per_vertex[0][0].bone, 385);
    assert_eq!(influences.per_vertex[0][0].weight, 1.0);
}

#[test]
fn a_single_index_outside_the_skeleton_is_reported() {
    let mut blob = vec![0u8; 0x40];
    blob[0x20..0x22].copy_from_slice(&386u16.to_le_bytes());
    let buffer = buffer(
        &[Decl {
            slot: 8,
            format: 0x00,
            offset: 0x20,
            size: 2,
        }],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let reason = unsupported(decode(&buffer, &blob, 1, Some(386), &mut diagnostics));
    assert!(reason.contains("bone 386"), "{reason}");
}

#[test]
fn an_unknown_index_declaration_is_reported() {
    let blob = vec![0u8; 0x40];
    let buffer = buffer(
        &[Decl {
            slot: 8,
            format: 0x99,
            offset: 0x20,
            size: 4,
        }],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let reason = unsupported(decode(&buffer, &blob, 1, Some(4), &mut diagnostics));
    assert!(reason.contains("0x99"), "{reason}");
}

#[test]
fn a_one_bone_skeleton_needs_no_index_stream() {
    let mut blob = vec![0u8; 0x40];
    blob[0x20..0x24].copy_from_slice(&[255, 0, 0, 0]);
    let buffer = buffer(
        &[Decl {
            slot: 6,
            format: 0x26,
            offset: 0x20,
            size: 4,
        }],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let influences = decoded(decode(&buffer, &blob, 1, Some(1), &mut diagnostics));
    assert_eq!(influences.bones, vec![0]);
    assert_eq!(influences.per_vertex[0][0].weight, 1.0);
    // A weight stream with no index stream on a one-bone skeleton is decoded,
    // not inferred: the record states the bone count and the weights.
    assert!(!influences.inferred());
}

/// A geometry that declares no influence attribute at all on a one-bone
/// skeleton is an inferred association: it deforms, but the record states no
/// bone reference, so it is reported apart from a decoded one.
#[test]
fn a_one_bone_geometry_without_attributes_is_inferred() {
    let buffer = buffer(&[], 1, 0x40);
    let blob = vec![0u8; 0x40];
    let mut diagnostics = Vec::new();
    let influences = match decode(&buffer, &blob, 1, Some(1), &mut diagnostics) {
        InfluenceDecode::Decoded(influences) => influences,
        other => panic!("expected an inferred association, got {other:?}"),
    };
    assert!(influences.inferred());
    assert!(influences.deformable());
    assert!(influences.rigid_attachment());
    assert_eq!(influences.per_vertex[0][0].weight, 1.0);
    assert_eq!(influences.status_name(), "complete (inferred single bone)");
}

#[test]
fn a_truncated_weight_stream_is_reported() {
    let mut blob = vec![0u8; 0x30];
    blob[0x20..0x24].copy_from_slice(&[255, 0, 0, 0]);
    let buffer = buffer(
        &[
            Decl {
                slot: 6,
                format: 0x26,
                offset: 0x20,
                size: 4,
            },
            Decl {
                slot: 8,
                format: 0x25,
                offset: 0x80,
                size: 4,
            },
        ],
        4,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    let reason = unsupported(decode(&buffer, &blob, 4, Some(4), &mut diagnostics));
    assert!(reason.contains("past the vertex buffer"), "{reason}");
}

#[test]
fn a_geometry_without_influence_attributes_is_not_declared() {
    let buffer = buffer(&[], 1, 0x40);
    let blob = vec![0u8; 0x40];
    let mut diagnostics = Vec::new();
    assert_eq!(
        decode(&buffer, &blob, 1, Some(4), &mut diagnostics),
        InfluenceDecode::NotDeclared
    );
}

#[test]
fn no_skeleton_leaves_the_geometry_undeclared_for_deformation() {
    let mut blob = vec![0u8; 0x40];
    blob[0x20..0x24].copy_from_slice(&[7, 0, 0, 0]);
    let buffer = buffer(
        &[Decl {
            slot: 8,
            format: 0x00,
            offset: 0x20,
            size: 1,
        }],
        1,
        blob.len(),
    );
    let mut diagnostics = Vec::new();
    assert_eq!(
        decode(&buffer, &blob, 1, None, &mut diagnostics),
        InfluenceDecode::NotDeclared
    );
}
