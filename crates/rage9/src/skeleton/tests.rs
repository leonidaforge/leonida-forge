//! Synthetic skeletons. None of these bytes come from the game.

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

struct Spec<'a> {
    rotation: [f32; 4],
    translation: [f32; 3],
    scale: [f32; 3],
    parent: u16,
    name: Option<&'a str>,
    identifier: u32,
}

impl Default for Spec<'_> {
    fn default() -> Self {
        Self {
            rotation: [0.0, 0.0, 0.0, 1.0],
            translation: [0.0; 3],
            scale: [1.0; 3],
            parent: ROOT_PARENT,
            name: None,
            identifier: 0,
        }
    }
}

const SKELETON: usize = 0x400;
const BONES: usize = 0x600;
const INVERSE: usize = 0x900;
const LOCAL: usize = 0xB00;
const PARENTS: usize = 0xD00;
const NAMES: usize = 0xE00;

/// Builds a system segment holding one skeleton at [`SKELETON`].
fn skeleton(bones: &[Spec<'_>]) -> Vec<u8> {
    let mut system = vec![0u8; 0x1200];
    put_u32(&mut system, SKELETON + 0x10, 1);
    put_u32(&mut system, SKELETON + 0x18, 0x20);
    put_u32(&mut system, SKELETON + 0x1C, bones.len() as u32 * 2);
    put_u64(&mut system, SKELETON + 0x20, system_ptr(0x380));
    put_u64(&mut system, SKELETON + 0x28, system_ptr(BONES as u64));
    put_u64(&mut system, SKELETON + 0x30, system_ptr(INVERSE as u64));
    put_u64(&mut system, SKELETON + 0x38, system_ptr(LOCAL as u64));
    put_u64(&mut system, SKELETON + 0x40, system_ptr(PARENTS as u64));
    put_u64(&mut system, SKELETON + 0x48, system_ptr(NAMES as u64));

    let mut name_offset = NAMES;
    for (index, spec) in bones.iter().enumerate() {
        let at = BONES + index * BONE_LEN;
        for (slot, value) in spec.rotation.into_iter().enumerate() {
            put_f32(&mut system, at + 4 * slot, value);
        }
        for (slot, value) in spec.translation.into_iter().enumerate() {
            put_f32(&mut system, at + 0x10 + 4 * slot, value);
        }
        put_u32(&mut system, at + 0x1C, spec.identifier);
        for (slot, value) in spec.scale.into_iter().enumerate() {
            put_f32(&mut system, at + 0x20 + 4 * slot, value);
        }
        if let Some(name) = spec.name {
            put_u64(&mut system, at + 0x30, system_ptr(name_offset as u64));
            let bytes = name.as_bytes();
            system[name_offset..name_offset + bytes.len()].copy_from_slice(bytes);
            system[name_offset + bytes.len()] = 0;
            name_offset += bytes.len() + 1;
        }
        put_u16(&mut system, at + 0x40, 0xD077);
        put_u16(&mut system, at + 0x42, 7);
        put_u16(&mut system, at + 0x44, 0xFFFF);
        put_u16(&mut system, at + 0x46, spec.parent);
        put_u16(&mut system, at + 0x48, index as u16);
        put_u16(&mut system, at + 0x4A, index as u16 * 3 + 1);
        put_u16(&mut system, at + 0x4C, index as u16);
        // A subtree-end jump, which equals the array length on the single-root
        // skeletons these fixtures build. The parser does not read it.
        put_u16(&mut system, at + 0x4E, bones.len() as u16);

        put_u16(&mut system, PARENTS + index * 2, spec.parent);

        // The local matrix stores the transposed local rotation and the local
        // translation; the inverse bind stores the model-space rotation.
        let record = LOCAL + index * MATRIX_LEN;
        put_f32(&mut system, record, 1.0);
        put_f32(&mut system, record + 4 * 4 + 4, 1.0);
        put_f32(&mut system, record + 8 * 4 + 8, 1.0);
        for (slot, value) in spec.translation.into_iter().enumerate() {
            put_f32(&mut system, record + 0x30 + 4 * slot, value);
        }
        let inverse_record = INVERSE + index * MATRIX_LEN;
        put_f32(&mut system, inverse_record, 1.0);
        put_f32(&mut system, inverse_record + 4 * 4 + 4, 1.0);
        put_f32(&mut system, inverse_record + 8 * 4 + 8, 1.0);
    }
    system
}

#[test]
fn reads_bones_names_parents_and_identifiers() {
    let system = skeleton(&[
        Spec {
            name: Some("Root_Bone"),
            identifier: 0xAAAA_AAAA,
            ..Spec::default()
        },
        Spec {
            name: Some("Child_Bone"),
            parent: 0,
            translation: [1.0, 2.0, 3.0],
            identifier: 0xBBBB_BBBB,
            ..Spec::default()
        },
    ]);
    let report = inspect(&system, SKELETON as u32);
    assert!(report.complete(), "{:?}", report.issues);
    assert_eq!(report.bone_count(), 2);
    assert_eq!(report.roots, vec![0]);
    assert_eq!(report.max_depth, 2);
    assert_eq!(report.named_count(), 2);
    assert_eq!(report.bones[0].name.as_deref(), Some("Root_Bone"));
    assert_eq!(report.bones[1].parent, Some(0));
    assert_eq!(report.bones[1].translation, [1.0, 2.0, 3.0]);
    assert_eq!(report.bones[1].identifier, 0xBBBB_BBBB);
    assert_eq!(report.inverse_bind.len(), 2);
    assert_eq!(report.parent_array, Some(vec![ROOT_PARENT, 0]));
}

#[test]
fn a_bone_without_a_name_is_kept_unnamed() {
    let system = skeleton(&[
        Spec::default(),
        Spec {
            parent: 0,
            ..Spec::default()
        },
    ]);
    let report = inspect(&system, SKELETON as u32);
    assert!(report.complete());
    assert_eq!(report.named_count(), 0);
    assert!(report.bones.iter().all(|bone| bone.name.is_none()));
}

#[test]
fn duplicate_names_keep_distinct_stable_identities() {
    let system = skeleton(&[
        Spec {
            name: Some("Same"),
            ..Spec::default()
        },
        Spec {
            name: Some("Same"),
            parent: 0,
            identifier: 5,
            ..Spec::default()
        },
    ]);
    let report = inspect(&system, SKELETON as u32);
    assert!(report.complete());
    let names: Vec<_> = report
        .bones
        .iter()
        .map(|bone| (bone.index, bone.name.clone()))
        .collect();
    assert_eq!(
        names,
        vec![(0, Some("Same".to_string())), (1, Some("Same".to_string()))]
    );
    assert_eq!(report.bones[1].identifier, 5);
}

#[test]
fn an_out_of_range_parent_is_reported_and_unresolved() {
    let system = skeleton(&[Spec {
        parent: 9,
        ..Spec::default()
    }]);
    let report = inspect(&system, SKELETON as u32);
    assert_eq!(report.status, "partial");
    assert!(
        report
            .issues
            .iter()
            .any(|issue| matches!(issue, Issue::InvalidParent { bone: 0, parent: 9 }))
    );
    assert_eq!(report.bones[0].parent, None);
    assert_eq!(report.roots, vec![0]);
}

#[test]
fn a_self_parenting_bone_is_reported() {
    let system = skeleton(&[Spec {
        parent: 0,
        ..Spec::default()
    }]);
    let report = inspect(&system, SKELETON as u32);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| matches!(issue, Issue::SelfParent { bone: 0 }))
    );
    assert_eq!(report.bones[0].parent, None);
}

#[test]
fn every_member_of_a_cycle_is_reported() {
    let system = skeleton(&[
        Spec {
            parent: 1,
            ..Spec::default()
        },
        Spec {
            parent: 0,
            ..Spec::default()
        },
    ]);
    let report = inspect(&system, SKELETON as u32);
    let cycles: Vec<_> = report
        .issues
        .iter()
        .filter_map(|issue| match issue {
            Issue::Cycle { bone } => Some(*bone),
            _ => None,
        })
        .collect();
    assert_eq!(cycles, vec![0, 1]);
    assert_eq!(report.max_depth, 1);
}

#[test]
fn a_deeper_hierarchy_measures_its_depth() {
    let bones: Vec<Spec<'_>> = (0..6)
        .map(|index| Spec {
            parent: if index == 0 {
                ROOT_PARENT
            } else {
                (index - 1) as u16
            },
            ..Spec::default()
        })
        .collect();
    let system = skeleton(&bones);
    let report = inspect(&system, SKELETON as u32);
    assert!(report.complete(), "{:?}", report.issues);
    assert_eq!(report.max_depth, 6);
    assert_eq!(report.roots, vec![0]);
}

#[test]
fn a_non_finite_translation_is_reported_and_kept() {
    let mut system = skeleton(&[Spec::default()]);
    put_f32(&mut system, BONES + 0x14, f32::NAN);
    let report = inspect(&system, SKELETON as u32);
    assert_eq!(report.status, "partial");
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::NonFinite {
            bone: 0,
            field: "translation",
            ..
        }
    )));
    assert!(report.bones[0].translation[1].is_nan());
}

#[test]
fn the_recorded_header_word_is_kept_and_does_not_truncate_the_walk() {
    let mut system = skeleton(&[Spec::default(), Spec::default()]);
    put_u32(&mut system, SKELETON + 0x1C, 3);
    let report = inspect(&system, SKELETON as u32);
    assert_eq!(report.recorded_keys, 3);
    assert_eq!(report.bone_count(), 2);
    assert!(report.complete());
}

#[test]
fn a_parent_array_that_disagrees_is_reported() {
    let mut system = skeleton(&[
        Spec::default(),
        Spec {
            parent: 0,
            ..Spec::default()
        },
    ]);
    put_u16(&mut system, PARENTS + 2, 1);
    let report = inspect(&system, SKELETON as u32);
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::ParentArrayMismatch {
            bone: 1,
            recorded: 0,
            array: 1
        }
    )));
}

#[test]
fn a_truncated_bone_array_reports_a_bounds_issue() {
    let system = skeleton(&[
        Spec::default(),
        Spec {
            parent: 0,
            ..Spec::default()
        },
    ]);
    // The header and the first bone record fit; the second is cut in half.
    let truncated = system[..BONES + BONE_LEN + 0x10].to_vec();
    let report = inspect(&truncated, SKELETON as u32);
    assert_eq!(report.status, "partial");
    assert!(
        report
            .issues
            .iter()
            .any(|issue| matches!(issue, Issue::Bounds { .. }))
    );
}

#[test]
fn a_missing_bone_pointer_is_reported() {
    let mut system = skeleton(&[Spec::default()]);
    put_u64(&mut system, SKELETON + 0x28, 0);
    let report = inspect(&system, SKELETON as u32);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| matches!(issue, Issue::Pointer { .. }))
    );
    assert_eq!(report.bone_count(), 0);
}

#[test]
fn an_unnamed_name_pointer_is_not_guessed() {
    let system = skeleton(&[Spec::default()]);
    let report = inspect(&system, SKELETON as u32);
    assert!(report.bones[0].name.is_none());
    assert!(report.bones[0].name_offset.is_none());
}
