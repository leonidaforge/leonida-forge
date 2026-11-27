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
const KEYS: usize = 0x500;

/// How a fixture deviates from the packed layout.
#[derive(Default, Clone, Copy)]
struct Layout {
    /// Rewrite the matrix arrays so a further bone record looks plausible, the
    /// way data after the bone allocation does in two real skeletons.
    decoy_after_bones: bool,
    /// Cut the segment short, so a bone record ends outside it.
    truncate_segment: bool,
    /// Break the index sequence at this bone, keeping the earlier records.
    break_index_at: Option<usize>,
    /// Write a parent into the `+0x40` array that its bone record does not hold.
    parent_array_override: Option<(usize, u16)>,
    /// Make the local-matrix record of this bone disagree with its quaternion.
    corrupt_local_matrix_at: Option<usize>,
}

/// The addresses of one fixture's arrays, so a test can assert about them.
struct Addresses {
    bones: usize,
    inverse: usize,
    local: usize,
    parents: usize,
    names: usize,
}

/// Builds a system segment holding one skeleton at [`SKELETON`].
///
/// The arrays are packed the way the samples are: each one occupies exactly
/// `count * stride` bytes and the next starts where it ends, so the layout
/// bounds the count the same way a real resource does.
fn skeleton_with(bones: &[Spec<'_>], layout: Layout) -> (Vec<u8>, Addresses) {
    let count = bones.len();
    // Two keys per bone, as the samples store them.
    let bones_at = align(KEYS + count * 16);
    let decoy = if layout.decoy_after_bones { 0x50 } else { 0 };
    let inverse_at = bones_at + count * BONE_LEN + decoy;
    let local_at = inverse_at + count * MATRIX_LEN;
    let parents_at = local_at + count * MATRIX_LEN;
    let names_at = align(parents_at + count * 2);
    let end = names_at + 0x200;
    // The last bone record of the declared array runs off the end.
    let truncated_end = bones_at + (count - 1) * BONE_LEN + 0x20;
    let mut system = vec![0u8; end];
    let size = system.len();
    let addresses = Addresses {
        bones: bones_at,
        inverse: inverse_at,
        local: local_at,
        parents: parents_at,
        names: names_at,
    };
    put_u32(&mut system, SKELETON + 0x10, 1);
    put_u32(&mut system, SKELETON + 0x18, 0x20);
    put_u32(&mut system, SKELETON + 0x1C, count as u32 * 2);
    put_u64(&mut system, SKELETON + 0x20, system_ptr(KEYS as u64));
    put_u64(&mut system, SKELETON + 0x28, system_ptr(bones_at as u64));
    put_u64(&mut system, SKELETON + 0x30, system_ptr(inverse_at as u64));
    put_u64(&mut system, SKELETON + 0x38, system_ptr(local_at as u64));
    put_u64(&mut system, SKELETON + 0x40, system_ptr(parents_at as u64));
    put_u64(&mut system, SKELETON + 0x48, system_ptr(names_at as u64));

    let mut name_offset = names_at;
    for (index, spec) in bones.iter().enumerate() {
        let at = bones_at + index * BONE_LEN;
        if at + BONE_LEN > size {
            break;
        }
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
        if let Some(name) = spec.name
            && name_offset + name.len() < size
        {
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
        let stored_index = if layout.break_index_at == Some(index) {
            index as u16 + 100
        } else {
            index as u16
        };
        put_u16(&mut system, at + 0x48, stored_index);
        put_u16(&mut system, at + 0x4A, index as u16 * 3 + 1);
        put_u16(&mut system, at + 0x4C, index as u16);
        // A subtree-end jump, which equals the array length on the single-root
        // skeletons these fixtures build. The parser does not read it.
        put_u16(&mut system, at + 0x4E, count as u16);

        if let Some(offset) = spec.parent_override(layout, index) {
            put_u16(&mut system, parents_at + index * 2, offset);
        } else {
            put_u16(&mut system, parents_at + index * 2, spec.parent);
        }

        // The local matrix stores the transposed local rotation and the local
        // translation; the inverse bind stores the model-space rotation.
        let record = local_at + index * MATRIX_LEN;
        if layout.corrupt_local_matrix_at != Some(index) {
            let rotation = rotation_matrix(spec.rotation);
            for row in 0..3 {
                for column in 0..3 {
                    put_f32(
                        &mut system,
                        record + 4 * (row * 4 + column),
                        rotation[column * 3 + row],
                    );
                }
            }
        } else {
            put_f32(&mut system, record, 0.5);
        }
        for (slot, value) in spec.translation.into_iter().enumerate() {
            put_f32(&mut system, record + 0x30 + 4 * slot, value);
        }
        let inverse_record = inverse_at + index * MATRIX_LEN;
        put_f32(&mut system, inverse_record, 1.0);
        put_f32(&mut system, inverse_record + 4 * 4 + 4, 1.0);
        put_f32(&mut system, inverse_record + 8 * 4 + 8, 1.0);
    }
    if layout.decoy_after_bones {
        // Real data after the bone allocation carried the next index at `+0x48`
        // by chance. This record does the same.
        let at = bones_at + count * BONE_LEN;
        put_u16(&mut system, at + 0x48, count as u16);
        put_u16(&mut system, at + 0x4C, count as u16);
    }
    if layout.truncate_segment {
        system.truncate(truncated_end);
    }
    (system, addresses)
}

impl Spec<'_> {
    fn parent_override(&self, layout: Layout, index: usize) -> Option<u16> {
        match layout.parent_array_override {
            Some((at, value)) if at == index => Some(value),
            _ => None,
        }
    }
}

fn align(value: usize) -> usize {
    value.div_ceil(16) * 16
}

/// The 3x3 rotation of a quaternion, as `x, y, z, w`, row-major.
fn rotation_matrix(quaternion: [f32; 4]) -> [f32; 9] {
    let [x, y, z, w] = quaternion;
    let norm = (x * x + y * y + z * z + w * w).sqrt();
    let (x, y, z, w) = (x / norm, y / norm, z / norm, w / norm);
    [
        1.0 - 2.0 * (y * y + z * z),
        2.0 * (x * y - z * w),
        2.0 * (x * z + y * w),
        2.0 * (x * y + z * w),
        1.0 - 2.0 * (x * x + z * z),
        2.0 * (y * z - x * w),
        2.0 * (x * z - y * w),
        2.0 * (y * z + x * w),
        1.0 - 2.0 * (x * x + y * y),
    ]
}

fn skeleton(bones: &[Spec<'_>]) -> Vec<u8> {
    skeleton_with(bones, Layout::default()).0
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
    let (mut system, addresses) = skeleton_with(&[Spec::default()], Layout::default());
    put_f32(&mut system, addresses.bones + 0x14, f32::NAN);
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
    let (system, _) = skeleton_with(
        &[
            Spec::default(),
            Spec {
                parent: 0,
                ..Spec::default()
            },
        ],
        Layout {
            parent_array_override: Some((1, 1)),
            ..Layout::default()
        },
    );
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
    let (system, _) = skeleton_with(
        &[
            Spec::default(),
            Spec {
                parent: 0,
                ..Spec::default()
            },
        ],
        Layout {
            truncate_segment: true,
            ..Layout::default()
        },
    );
    let report = inspect(&system, SKELETON as u32);
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

#[test]
fn a_skeleton_with_several_roots_is_complete() {
    // Helper bones head their own chains, so a second root is ordinary data.
    let (system, _) = skeleton_with(
        &[
            Spec {
                name: Some("Root"),
                ..Spec::default()
            },
            Spec {
                parent: 0,
                ..Spec::default()
            },
            Spec {
                name: Some("OH_TorsoDirection_01"),
                ..Spec::default()
            },
            Spec {
                parent: 2,
                ..Spec::default()
            },
        ],
        Layout::default(),
    );
    let report = inspect(&system, SKELETON as u32);
    assert!(report.complete(), "{:?}", report.issues);
    assert_eq!(report.bone_count(), 4);
    assert_eq!(report.roots, vec![0, 2]);
    assert_eq!(report.max_depth, 2);
}

#[test]
fn a_large_skeleton_is_read_whole() {
    let bones: Vec<Spec> = (0..600)
        .map(|index| Spec {
            parent: if index == 0 { ROOT_PARENT } else { 0 },
            identifier: index as u32,
            ..Spec::default()
        })
        .collect();
    let (system, addresses) = skeleton_with(&bones, Layout::default());
    let report = inspect(&system, SKELETON as u32);
    assert!(report.complete(), "{:?}", report.issues);
    assert_eq!(report.bone_count(), 600);
    assert_eq!(report.max_depth, 2);
    assert_eq!(report.inverse_bind.len(), 600);
    // The packed arrays tile: the bone array ends where the inverse bind starts
    // and the local array ends where the parent array starts.
    assert_eq!(report.arrays.bones, Some(addresses.bones as u32));
    assert_eq!(report.arrays.inverse_bind, Some(addresses.inverse as u32));
    assert_eq!(addresses.bones + 600 * BONE_LEN, addresses.inverse);
    assert_eq!(addresses.local + 600 * MATRIX_LEN, addresses.parents);
    assert_eq!(
        addresses.bones + 600 * BONE_LEN,
        report.bone_bound.map(|bound| bound.at as usize).unwrap()
    );
    assert!(report.bone_bound.is_some_and(|bound| bound.exact));
    assert!(addresses.names > addresses.parents);
}

#[test]
fn data_after_the_bone_array_that_carries_the_next_index_is_bounded() {
    // Two of the 5,628 surveyed skeletons continue into the array that follows
    // the bones. The layout bounds the count, so the extra record is dropped
    // and named in an issue instead of becoming a bone.
    let (system, _) = skeleton_with(
        &[
            Spec {
                name: Some("Root"),
                ..Spec::default()
            },
            Spec {
                parent: 0,
                name: Some("Child"),
                ..Spec::default()
            },
        ],
        Layout {
            decoy_after_bones: true,
            ..Layout::default()
        },
    );
    let report = inspect(&system, SKELETON as u32);
    assert_eq!(report.bone_count(), 2);
    assert_eq!(report.bones[1].name.as_deref(), Some("Child"));
    assert_eq!(report.status, "partial");
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::BoneArrayOverrun {
            walked: 3,
            kept: 2,
            ..
        }
    )));
}

#[test]
fn an_index_discontinuity_ends_the_array_without_an_issue() {
    let (system, _) = skeleton_with(
        &[
            Spec::default(),
            Spec {
                parent: 0,
                ..Spec::default()
            },
            Spec {
                parent: 1,
                ..Spec::default()
            },
        ],
        Layout {
            break_index_at: Some(2),
            ..Layout::default()
        },
    );
    let report = inspect(&system, SKELETON as u32);
    assert_eq!(report.bone_count(), 2);
    assert!(report.complete(), "{:?}", report.issues);
}

#[test]
fn the_accepted_maximum_is_reported_rather_than_silently_capped() {
    // The cap itself is the only limit: a record that continues past it makes
    // the skeleton partial instead of quietly shorter.
    let bones: Vec<Spec> = (0..MAX_BONES + 1)
        .map(|index| Spec {
            parent: if index == 0 { ROOT_PARENT } else { 0 },
            ..Spec::default()
        })
        .collect();
    let (system, _) = skeleton_with(&bones, Layout::default());
    let report = inspect(&system, SKELETON as u32);
    assert_eq!(report.bone_count(), MAX_BONES);
    assert!(report.issues.iter().any(|issue| matches!(
        issue,
        Issue::BeyondLimit {
            limit: MAX_BONES,
            ..
        }
    )));
}
