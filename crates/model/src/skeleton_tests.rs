// Skeleton composition and association tests, appended by the skeleton work.
use super::*;
use glam::{Mat3, Quat};

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

const SKELETON_AT: usize = 0x100;
const BONES_AT: usize = 0x200;
const INVERSE_AT: usize = 0x500;
const PARENTS_AT: usize = 0x700;

struct BoneSpec {
    rotation: Quat,
    translation: [f32; 3],
    parent: u16,
}

/// Builds a system segment with one skeleton and, when `inverse` is set, one
/// stored inverse-bind record per bone computed from the composed pose.
fn skeleton_system(bones: &[BoneSpec], inverse: bool, corrupt_inverse: bool) -> Vec<u8> {
    let mut system = vec![0u8; 0x900];
    put_u32(&mut system, SKELETON_AT + 0x10, 1);
    put_u32(&mut system, SKELETON_AT + 0x18, 0x20);
    put_u32(&mut system, SKELETON_AT + 0x1C, bones.len() as u32 * 2);
    put_u64(&mut system, SKELETON_AT + 0x28, system_ptr(BONES_AT as u64));
    if inverse {
        put_u64(
            &mut system,
            SKELETON_AT + 0x30,
            system_ptr(INVERSE_AT as u64),
        );
    }
    put_u64(
        &mut system,
        SKELETON_AT + 0x40,
        system_ptr(PARENTS_AT as u64),
    );

    let mut model_rotation: Vec<Quat> = Vec::new();
    let mut model_translation: Vec<glam::Vec3> = Vec::new();
    for (index, spec) in bones.iter().enumerate() {
        let at = BONES_AT + index * 0x50;
        let [x, y, z, w] = spec.rotation.to_array();
        for (slot, value) in [x, y, z, w].into_iter().enumerate() {
            put_f32(&mut system, at + 4 * slot, value);
        }
        for (slot, value) in spec.translation.into_iter().enumerate() {
            put_f32(&mut system, at + 0x10 + 4 * slot, value);
        }
        put_u32(&mut system, at + 0x1C, index as u32 * 7 + 1);
        for slot in 0..3 {
            put_f32(&mut system, at + 0x20 + 4 * slot, 1.0);
        }
        put_u16(&mut system, at + 0x40, 0xD077);
        put_u16(&mut system, at + 0x42, 7);
        put_u16(&mut system, at + 0x44, 0xFFFF);
        put_u16(&mut system, at + 0x46, spec.parent);
        put_u16(&mut system, at + 0x48, index as u16);
        put_u16(&mut system, at + 0x4A, index as u16 + 1);
        put_u16(&mut system, at + 0x4C, index as u16);
        put_u16(&mut system, at + 0x4E, bones.len() as u16);
        put_u16(&mut system, PARENTS_AT + index * 2, spec.parent);

        let (rotation, translation) = match spec.parent {
            0xFFFF => (spec.rotation, glam::Vec3::from_array(spec.translation)),
            parent => {
                let parent_rotation = model_rotation[parent as usize];
                let parent_translation = model_translation[parent as usize];
                (
                    parent_rotation * spec.rotation,
                    parent_translation + parent_rotation * glam::Vec3::from_array(spec.translation),
                )
            }
        };
        model_rotation.push(rotation);
        model_translation.push(translation);

        if inverse {
            let rotation = rotation.normalize();
            let record = INVERSE_AT + index * 0x40;
            let matrix = Mat3::from_quat(rotation).to_cols_array();
            // Stored transposed: the 3x3 is the model-space rotation in
            // row-major order and the translation is the negated rotated one.
            let rows = [
                [matrix[0], matrix[3], matrix[6]],
                [matrix[1], matrix[4], matrix[7]],
                [matrix[2], matrix[5], matrix[8]],
            ];
            for (row, cells) in rows.iter().enumerate() {
                for (column, cell) in cells.iter().enumerate() {
                    let mut value = *cell;
                    if corrupt_inverse && index == 0 {
                        value += 0.5;
                    }
                    put_f32(&mut system, record + 4 * (row * 4 + column), value);
                }
            }
            let rotated = rotation.inverse() * translation;
            for (slot, value) in [-rotated.x, -rotated.y, -rotated.z].into_iter().enumerate() {
                put_f32(&mut system, record + 0x30 + 4 * slot, value);
            }
        }
    }
    system
}

#[test]
fn a_child_translation_is_rotated_by_its_parent() {
    let quarter_turn = Quat::from_rotation_z(std::f32::consts::FRAC_PI_2);
    let system = skeleton_system(
        &[
            BoneSpec {
                rotation: quarter_turn,
                translation: [0.0, 0.0, 0.0],
                parent: 0xFFFF,
            },
            BoneSpec {
                rotation: Quat::IDENTITY,
                translation: [1.0, 0.0, 0.0],
                parent: 0,
            },
            BoneSpec {
                rotation: Quat::IDENTITY,
                translation: [1.0, 0.0, 0.0],
                parent: 1,
            },
        ],
        false,
        false,
    );
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) =
        skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    let skeleton = skeleton.expect("a skeleton");
    assert_eq!(
        completeness,
        SkeletonCompleteness::Complete,
        "{diagnostics:?}"
    );
    assert_eq!(skeleton.bones.len(), 3);
    assert_eq!(skeleton.max_depth, 3);
    assert_eq!(skeleton.roots, vec![0]);
    let second = skeleton.bone_position(1).expect("bone 1");
    assert!(
        (second - glam::Vec3::new(0.0, 1.0, 0.0)).length() < 1e-5,
        "{second}"
    );
    let third = skeleton.bone_position(2).expect("bone 2");
    assert!(
        (third - glam::Vec3::new(0.0, 2.0, 0.0)).length() < 1e-5,
        "{third}"
    );
    // The parent rotation is composed into the child's model rotation.
    let model_rotation = skeleton.bones[2].model_rotation;
    assert!(
        (model_rotation * glam::Vec3::X - glam::Vec3::Y).length() < 1e-5,
        "{model_rotation}"
    );
}

#[test]
fn a_matching_inverse_bind_record_is_accepted() {
    let system = skeleton_system(
        &[
            BoneSpec {
                rotation: Quat::from_rotation_z(0.4),
                translation: [1.0, 2.0, 3.0],
                parent: 0xFFFF,
            },
            BoneSpec {
                rotation: Quat::from_rotation_x(0.3),
                translation: [0.5, 0.0, -1.0],
                parent: 0,
            },
        ],
        true,
        false,
    );
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) =
        skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    let skeleton = skeleton.expect("a skeleton");
    assert_eq!(
        completeness,
        SkeletonCompleteness::Complete,
        "{diagnostics:?}"
    );
    assert!(
        skeleton
            .bones
            .iter()
            .all(|bone| bone.inverse_bind.is_some())
    );
    let inverse = skeleton.bones[1].inverse_bind.expect("bone 1 inverse bind");
    let position = skeleton.bones[1].model_position;
    let mapped = inverse.transform_point3(position);
    assert!(mapped.length() < 1e-4, "{mapped}");
}

#[test]
fn a_disagreeing_inverse_bind_record_is_reported_and_dropped() {
    let system = skeleton_system(
        &[BoneSpec {
            rotation: Quat::from_rotation_z(0.4),
            translation: [1.0, 2.0, 3.0],
            parent: 0xFFFF,
        }],
        true,
        true,
    );
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) =
        skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    let skeleton = skeleton.expect("a skeleton");
    match completeness {
        SkeletonCompleteness::Partial { .. } => {}
        other => panic!("expected partial, got {other:?}"),
    }
    assert!(skeleton.bones[0].inverse_bind.is_none());
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.reason.contains("inverse-bind"))
    );
}

#[test]
fn a_null_skeleton_pointer_is_not_a_failure() {
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) = skeleton::build(&[0u8; 16], None, &mut diagnostics);
    assert!(skeleton.is_none());
    assert_eq!(completeness, SkeletonCompleteness::NotPresent);
    assert!(diagnostics.is_empty());
}

#[test]
fn a_non_unit_quaternion_is_reported_not_normalised() {
    let mut system = skeleton_system(
        &[BoneSpec {
            rotation: Quat::IDENTITY,
            translation: [0.0; 3],
            parent: 0xFFFF,
        }],
        false,
        false,
    );
    put_f32(&mut system, BONES_AT + 0x0C, 3.0);
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) =
        skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    let skeleton = skeleton.expect("a skeleton");
    assert!(matches!(completeness, SkeletonCompleteness::Partial { .. }));
    assert_eq!(skeleton.bones[0].local_rotation.w, 3.0);
}

#[test]
fn association_completeness_separates_absent_and_partial() {
    assert_eq!(
        association_completeness(0, 0, 0),
        AssociationCompleteness::NotReferenced
    );
    assert_eq!(
        association_completeness(2, 2, 2),
        AssociationCompleteness::Complete
    );
    assert!(matches!(
        association_completeness(2, 1, 1),
        AssociationCompleteness::Partial { .. }
    ));
}

fn influence_buffer(
    blob_len: usize,
    declarations: &[(u32, u8, u32, u8)],
    vertex_count: usize,
) -> lforge_rage9::drawable::VertexBuffer {
    use lforge_rage9::drawable::{Attribute, Declaration, VertexBuffer};
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
        declared_bytes: blob_len as u64,
        attribute_bytes: 0,
        layout_end: 0,
        prefix_gap: 0,
        attributes: declarations
            .iter()
            .enumerate()
            .map(|(index, (_, _, offset, size))| Attribute {
                slot: index,
                offset: *offset,
                size: *size,
                format: 0,
            })
            .collect(),
        declarations: declarations
            .iter()
            .map(|(slot, format, offset, _)| Declaration {
                slot: *slot as usize,
                format: *format,
                offset: *offset,
                matches_layout: true,
            })
            .collect(),
        declaration_end: None,
    }
}

#[test]
fn a_one_bone_geometry_needs_no_index_stream() {
    let mut blob = vec![0u8; 0x80];
    for vertex in 0..2 {
        blob[0x20 + vertex * 4..0x24 + vertex * 4].copy_from_slice(&[255, 0, 0, 0]);
    }
    let buffer = influence_buffer(blob.len(), &[(6, 0x26, 0x20, 4)], 2);
    let mut diagnostics = Vec::new();
    let decoded = crate::influence::decode(&buffer, &blob, 2, Some(1), &mut diagnostics);
    let crate::influence::InfluenceDecode::Decoded(influence) = decoded else {
        panic!("one bone resolves without an index stream");
    };
    assert_eq!(influence.bones, vec![0]);
    assert!(!influence.weighted);
    assert!(diagnostics.is_empty());
}

#[test]
fn a_multi_bone_geometry_without_an_index_stream_is_not_guessed() {
    let mut blob = vec![0u8; 0x80];
    for vertex in 0..2 {
        blob[0x20 + vertex * 4..0x24 + vertex * 4].copy_from_slice(&[255, 0, 0, 0]);
    }
    let buffer = influence_buffer(blob.len(), &[(6, 0x26, 0x20, 4)], 2);
    let mut diagnostics = Vec::new();
    assert!(matches!(
        crate::influence::decode(&buffer, &blob, 2, Some(2), &mut diagnostics),
        crate::influence::InfluenceDecode::Unsupported { .. }
    ));
}

#[test]
fn a_packed_index_stream_reports_a_weighted_association() {
    let mut blob = vec![0u8; 0x80];
    blob[0x20..0x24].copy_from_slice(&[128, 127, 0, 0]);
    blob[0x40..0x44].copy_from_slice(&[0, 1, 0, 0]);
    let buffer = influence_buffer(blob.len(), &[(6, 0x26, 0x20, 4), (8, 0x25, 0x40, 4)], 1);
    let mut diagnostics = Vec::new();
    let crate::influence::InfluenceDecode::Decoded(influence) =
        crate::influence::decode(&buffer, &blob, 1, Some(2), &mut diagnostics)
    else {
        panic!("two influences resolve");
    };
    assert_eq!(influence.bones, vec![0, 1]);
    assert!(influence.weighted);
}

#[test]
fn a_seven_bit_weight_normalisation_is_accepted() {
    let mut blob = vec![0u8; 0x80];
    blob[0x20..0x24].copy_from_slice(&[31, 32, 32, 32]);
    blob[0x40..0x44].copy_from_slice(&[1, 2, 3, 4]);
    let buffer = influence_buffer(blob.len(), &[(6, 0x26, 0x20, 4), (8, 0x25, 0x40, 4)], 1);
    let mut diagnostics = Vec::new();
    let crate::influence::InfluenceDecode::Decoded(influence) =
        crate::influence::decode(&buffer, &blob, 1, Some(5), &mut diagnostics)
    else {
        panic!("a 127-scale weight set resolves");
    };
    assert_eq!(influence.bones, vec![1, 2, 3, 4]);
    assert!(influence.weighted);
    assert!(diagnostics.is_empty());
}

#[test]
fn an_unnormalised_weight_total_is_accepted_and_reported() {
    let mut blob = vec![0u8; 0x80];
    blob[0x20..0x24].copy_from_slice(&[40, 43, 43, 43]);
    blob[0x40..0x44].copy_from_slice(&[2, 3, 4, 5]);
    let buffer = influence_buffer(blob.len(), &[(6, 0x26, 0x20, 4), (8, 0x25, 0x40, 4)], 1);
    let mut diagnostics = Vec::new();
    let crate::influence::InfluenceDecode::Decoded(influence) =
        crate::influence::decode(&buffer, &blob, 1, Some(8), &mut diagnostics)
    else {
        panic!("the non-zero lanes name valid bones");
    };
    assert_eq!(influence.bones, vec![2, 3, 4, 5]);
    assert!(influence.weighted);
    assert!(!influence.deformable());
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.reason.contains("not normalised"))
    );
}

#[test]
fn an_index_outside_the_skeleton_is_rejected() {
    let mut blob = vec![0u8; 0x80];
    blob[0x20..0x24].copy_from_slice(&[255, 0, 0, 0]);
    blob[0x40..0x44].copy_from_slice(&[2, 0, 0, 0]);
    let buffer = influence_buffer(blob.len(), &[(6, 0x26, 0x20, 4), (8, 0x25, 0x40, 4)], 1);
    let mut diagnostics = Vec::new();
    assert!(matches!(
        crate::influence::decode(&buffer, &blob, 1, Some(2), &mut diagnostics),
        crate::influence::InfluenceDecode::Unsupported { .. }
    ));
}

const LOCAL_AT: usize = 0xA00;

/// Adds the `+0x38` array: each bone's local transform with the rotation stored
/// transposed, as the samples do.
fn with_local_matrices(mut system: Vec<u8>, bones: &[BoneSpec], corrupt: bool) -> Vec<u8> {
    system.resize(0x1000, 0);
    put_u64(&mut system, SKELETON_AT + 0x38, system_ptr(LOCAL_AT as u64));
    for (index, spec) in bones.iter().enumerate() {
        let record = LOCAL_AT + index * 0x40;
        // The array stores the transposed local rotation row after row, so the
        // rotation's columns are written in order.
        let matrix = Mat3::from_quat(spec.rotation.normalize()).to_cols_array();
        for (slot, value) in matrix.into_iter().enumerate() {
            let row = slot / 3;
            let column = slot % 3;
            let value = if corrupt && index == 1 {
                value + 0.5
            } else {
                value
            };
            put_f32(&mut system, record + 4 * (row * 4 + column), value);
        }
        for (slot, value) in spec.translation.into_iter().enumerate() {
            put_f32(&mut system, record + 0x30 + 4 * slot, value);
        }
    }
    system
}

#[test]
fn a_local_matrix_record_that_matches_its_quaternion_is_accepted() {
    let bones = [
        BoneSpec {
            rotation: Quat::from_rotation_z(0.3),
            translation: [1.0, 2.0, 3.0],
            parent: 0xFFFF,
        },
        BoneSpec {
            rotation: Quat::from_rotation_x(-0.7),
            translation: [-2.0, 0.5, 1.0],
            parent: 0,
        },
    ];
    let system = with_local_matrices(skeleton_system(&bones, true, false), &bones, false);
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) =
        skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    assert_eq!(
        completeness,
        SkeletonCompleteness::Complete,
        "{diagnostics:?}"
    );
    assert_eq!(skeleton.map(|skeleton| skeleton.bones.len()), Some(2));
}

#[test]
fn a_local_matrix_record_that_disagrees_is_reported() {
    let bones = [
        BoneSpec {
            rotation: Quat::IDENTITY,
            translation: [0.0; 3],
            parent: 0xFFFF,
        },
        BoneSpec {
            rotation: Quat::from_rotation_y(0.4),
            translation: [0.0, 1.0, 0.0],
            parent: 0,
        },
    ];
    let system = with_local_matrices(skeleton_system(&bones, true, false), &bones, true);
    let mut diagnostics = Vec::new();
    let (_, completeness) = skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    assert!(matches!(completeness, SkeletonCompleteness::Partial { .. }));
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.reason.contains("local-matrix record of bone 1"))
    );
}

#[test]
fn noncommuting_rotations_compose_parent_then_child() {
    // A quarter turn about Z followed by a quarter turn about X gives different
    // matrices in the two orders, so this pins the multiplication order.
    let parent = Quat::from_rotation_z(std::f32::consts::FRAC_PI_2);
    let child = Quat::from_rotation_x(std::f32::consts::FRAC_PI_2);
    let system = skeleton_system(
        &[
            BoneSpec {
                rotation: parent,
                translation: [2.0, -1.0, 0.5],
                parent: 0xFFFF,
            },
            BoneSpec {
                rotation: child,
                translation: [1.0, 2.0, -3.0],
                parent: 0,
            },
        ],
        false,
        false,
    );
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) =
        skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    let skeleton = skeleton.expect("a skeleton");
    assert_eq!(
        completeness,
        SkeletonCompleteness::Complete,
        "{diagnostics:?}"
    );

    let expected_rotation = parent * child;
    let expected_position =
        glam::Vec3::new(2.0, -1.0, 0.5) + parent * glam::Vec3::new(1.0, 2.0, -3.0);
    let bone = &skeleton.bones[1];
    assert!(bone.model_rotation.abs_diff_eq(expected_rotation, 1e-5));
    assert!(bone.model_position.abs_diff_eq(expected_position, 1e-5));
    // The other order would place the child somewhere else; the assertion above
    // is only meaningful if that is true.
    let reversed = child * parent;
    let reversed_position =
        glam::Vec3::new(2.0, -1.0, 0.5) + child * glam::Vec3::new(1.0, 2.0, -3.0);
    assert!(!expected_rotation.abs_diff_eq(reversed, 1e-3));
    assert!(!expected_position.abs_diff_eq(reversed_position, 1e-3));
}

#[test]
fn a_nonuniform_scale_is_recorded_but_not_applied() {
    // Scale is identity in every one of the 133,110 surveyed bones, so no
    // sampled resource can tell whether a non-identity scale belongs in the
    // composition. The decoder records the value and composes rotation and
    // translation only, which this test pins rather than claims as support.
    let mut system = skeleton_system(
        &[
            BoneSpec {
                rotation: Quat::IDENTITY,
                translation: [0.0; 3],
                parent: 0xFFFF,
            },
            BoneSpec {
                rotation: Quat::IDENTITY,
                translation: [1.0, 0.0, 0.0],
                parent: 0,
            },
        ],
        false,
        false,
    );
    // A non-uniform scale on the parent.
    put_f32(&mut system, BONES_AT + 0x20, 2.0);
    put_f32(&mut system, BONES_AT + 0x24, 3.0);
    put_f32(&mut system, BONES_AT + 0x28, 4.0);
    let mut diagnostics = Vec::new();
    let (skeleton, completeness) =
        skeleton::build(&system, Some(SKELETON_AT as u32), &mut diagnostics);
    let skeleton = skeleton.expect("a skeleton");
    assert_eq!(
        completeness,
        SkeletonCompleteness::Complete,
        "{diagnostics:?}"
    );
    assert_eq!(
        skeleton.bones[0].local_scale,
        glam::Vec3::new(2.0, 3.0, 4.0)
    );
    // The child position is the parent translation plus the local one, with no
    // scale applied.
    assert!(
        skeleton.bones[1]
            .model_position
            .abs_diff_eq(glam::Vec3::new(1.0, 0.0, 0.0), 1e-6)
    );
}
