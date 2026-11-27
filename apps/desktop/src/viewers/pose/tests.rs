//! State tests for the pose session.

use glam::{Quat, Vec3};
use lforge_scene::{Bone, Skeleton};

use super::{PoseDisplay, PoseFrame, PoseSession, ROTATION_STEP_DEGREES, TRANSLATION_STEP};

fn skeleton(bones: Vec<(Option<usize>, Vec3, Quat)>) -> Skeleton {
    let mut out: Vec<Bone> = Vec::new();
    for (index, (parent, translation, rotation)) in bones.into_iter().enumerate() {
        let (model_rotation, model_position) = match parent {
            Some(parent) => {
                let parent = &out[parent];
                (
                    parent.model_rotation * rotation,
                    parent.model_position + parent.model_rotation * translation,
                )
            }
            None => (rotation, translation),
        };
        out.push(Bone {
            name: Some(format!("bone_{index}")),
            index,
            parent,
            identifier: Some(index as u32 + 1),
            identifier16: Some(index as u16 + 1),
            local_translation: translation,
            local_rotation: rotation,
            local_scale: Vec3::ONE,
            model_rotation,
            model_position,
            inverse_bind: Some(
                glam::Mat4::from_rotation_translation(model_rotation, model_position).inverse(),
            ),
        });
    }
    Skeleton {
        bones: out,
        roots: vec![0, 2],
        max_depth: 2,
    }
}

fn reference_skeleton() -> Skeleton {
    skeleton(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(0.0, 2.0, 0.0), Quat::IDENTITY),
        (None, Vec3::new(5.0, 0.0, 0.0), Quat::IDENTITY),
    ])
}

#[test]
fn a_new_session_reproduces_the_reference_pose() {
    let skeleton = reference_skeleton();
    let session = PoseSession::new(skeleton.bones.len());
    assert_eq!(session.display(), PoseDisplay::Posed);
    assert!(session.is_reference());
    let frame = session.frame(&skeleton).unwrap();
    assert!(frame.active);
    assert!(!frame.influence);
    assert_eq!(frame.bone_positions[1], Vec3::new(0.0, 2.0, 0.0));
    assert_eq!(frame.matrices.len(), skeleton.bones.len());
}

#[test]
fn a_parent_rotation_moves_the_child_and_leaves_the_other_root_alone() {
    let skeleton = reference_skeleton();
    let mut session = PoseSession::new(skeleton.bones.len());
    let before = session.revision();
    session.adjust_rotation(0, 2, 18).unwrap(); // 90 degrees around Z
    assert!(session.revision() > before);
    assert_eq!(
        session.rotation_degrees(0),
        Some([0.0, 0.0, 18.0 * ROTATION_STEP_DEGREES])
    );
    let frame = session.frame(&skeleton).unwrap();
    assert!(
        (frame.bone_positions[1] - Vec3::new(-2.0, 0.0, 0.0)).length() < 1e-5,
        "child at {:?}",
        frame.bone_positions[1]
    );
    assert_eq!(frame.bone_positions[2], Vec3::new(5.0, 0.0, 0.0));
}

#[test]
fn a_translation_delta_uses_the_parent_space() {
    let skeleton = reference_skeleton();
    let mut session = PoseSession::new(skeleton.bones.len());
    session.adjust_translation(1, 0, 2).unwrap();
    assert_eq!(
        session.translation(1),
        Some(Vec3::new(2.0 * TRANSLATION_STEP, 0.0, 0.0))
    );
    let frame = session.frame(&skeleton).unwrap();
    assert_eq!(
        frame.bone_positions[1],
        Vec3::new(2.0 * TRANSLATION_STEP, 2.0, 0.0)
    );
}

#[test]
fn resetting_one_bone_keeps_the_rest_and_reset_all_returns_to_reference() {
    let skeleton = reference_skeleton();
    let mut session = PoseSession::new(skeleton.bones.len());
    session.adjust_rotation(0, 0, 1).unwrap();
    session.adjust_translation(2, 1, 1).unwrap();
    session.reset_bone(0).unwrap();
    assert!(!session.is_reference());
    assert_eq!(session.rotation_degrees(0), Some([0.0; 3]));
    assert_ne!(session.translation(2), Some(Vec3::ZERO));
    session.reset_all();
    assert!(session.is_reference());
    let frame = session.frame(&skeleton).unwrap();
    assert_eq!(frame.bone_positions[1], Vec3::new(0.0, 2.0, 0.0));
}

#[test]
fn the_authored_display_keeps_the_edit_but_draws_the_reference() {
    let skeleton = reference_skeleton();
    let mut session = PoseSession::new(skeleton.bones.len());
    session.adjust_rotation(0, 2, 18).unwrap();
    session.set_display(PoseDisplay::Authored);
    assert_eq!(session.display(), PoseDisplay::Authored);
    let frame = session.frame(&skeleton).unwrap();
    assert!(!frame.active);
    assert!(!frame.influence);
    assert_eq!(frame.bone_positions[1], Vec3::new(0.0, 2.0, 0.0));
    session.set_display(PoseDisplay::Posed);
    let frame = session.frame(&skeleton).unwrap();
    assert!(frame.active);
    assert!((frame.bone_positions[1] - Vec3::new(-2.0, 0.0, 0.0)).length() < 1e-5);
}

#[test]
fn the_influence_view_switches_the_display_to_posed() {
    let skeleton = reference_skeleton();
    let mut session = PoseSession::new(skeleton.bones.len());
    session.set_display(PoseDisplay::Authored);
    session.set_influence_view(true);
    assert_eq!(session.display(), PoseDisplay::Posed);
    let frame = session.frame(&skeleton).unwrap();
    assert!(frame.influence);
}

#[test]
fn an_invalid_bone_is_reported_without_changing_the_pose() {
    let mut session = PoseSession::new(3);
    assert!(session.adjust_rotation(7, 0, 1).is_err());
    assert!(session.adjust_translation(7, 0, 1).is_err());
    assert!(session.reset_bone(7).is_err());
    assert!(session.is_reference());
}

#[test]
fn a_rotation_reaches_a_full_turn_without_unbounded_angles() {
    let mut session = PoseSession::new(1);
    for _ in 0..100 {
        session.adjust_rotation(0, 0, 1).unwrap();
    }
    let angle = session.rotation_degrees(0).unwrap()[0];
    assert!((-180.0..=180.0).contains(&angle), "{angle}");
}

#[test]
fn the_reference_frame_restores_the_authored_skeleton() {
    let skeleton = reference_skeleton();
    let frame = PoseFrame::reference(&skeleton).unwrap();
    assert!(!frame.active);
    assert!(!frame.influence);
    assert_eq!(frame.matrices.len(), skeleton.bones.len());
    assert_eq!(frame.bone_positions[1], Vec3::new(0.0, 2.0, 0.0));
}
