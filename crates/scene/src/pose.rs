//! A pose over a decoded skeleton.
//!
//! A pose is a set of per-bone local deltas, never a mutation of the decoded
//! skeleton. The reference pose has no deltas and reproduces the stored bind
//! pose exactly.
//!
//! Conventions, fixed for the CPU reference, the GPU shader and the desktop
//! controls alike:
//!
//! - The local rotation is `bind_local_rotation * delta_rotation`, so a delta
//!   turns the bone around its own axes after the stored rotation.
//! - The local translation is `bind_local_translation + delta_translation`.
//!   Local translation is expressed in the parent's space, so its delta is too.
//! - Scale is not posed. The supported skeletons carry identity scale; a
//!   non-identity scale is reported rather than silently composed.
//!
//! Global transforms are rebuilt from the local values, so changing a parent
//! moves its descendants and leaves unrelated roots untouched.

use glam::{Mat4, Quat, Vec3};

use crate::{Bone, Skeleton};

/// The largest scale deviation from one accepted by the pose solver.
const SCALE_TOLERANCE: f32 = 1e-4;

/// Why a skeleton cannot be posed or deformed.
#[derive(Debug, Clone, PartialEq)]
pub enum PoseError {
    /// The skeleton array does not hold this bone.
    InvalidBone(usize),
    /// A parent index points outside the bone array.
    InvalidParent { bone: usize, parent: usize },
    /// The parent chain revisits a bone.
    Cycle { bone: usize },
    /// The bone carries a non-identity scale, which this feature does not pose.
    UnsupportedScale { bone: usize, scale: Vec3 },
    /// A deltas or input value is not finite.
    NonFinite { bone: usize },
}

impl std::fmt::Display for PoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoseError::InvalidBone(bone) => write!(f, "bone {bone} is outside the skeleton"),
            PoseError::InvalidParent { bone, parent } => {
                write!(f, "bone {bone} names parent {parent}, outside the skeleton")
            }
            PoseError::Cycle { bone } => {
                write!(f, "the parent chain of bone {bone} forms a cycle")
            }
            PoseError::UnsupportedScale { bone, scale } => {
                write!(f, "bone {bone} has scale {scale:?}, which is not supported")
            }
            PoseError::NonFinite { bone } => write!(f, "bone {bone} holds a non-finite value"),
        }
    }
}

impl std::error::Error for PoseError {}

/// One bone's local delta.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PoseDelta {
    /// Translation delta in the parent's space.
    pub translation: Vec3,
    /// Rotation delta applied in the bone's own space.
    pub rotation: Quat,
}

impl Default for PoseDelta {
    fn default() -> Self {
        Self {
            translation: Vec3::ZERO,
            rotation: Quat::IDENTITY,
        }
    }
}

impl PoseDelta {
    pub fn is_identity(&self) -> bool {
        self.translation == Vec3::ZERO && self.rotation == Quat::IDENTITY
    }
}

/// A bone's resolved local and model-space transform under a pose.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PosedBone {
    pub rotation: Quat,
    pub translation: Vec3,
    pub model_rotation: Quat,
    pub model_position: Vec3,
}

/// A pose over one skeleton. Cheap to clone; cloning keeps the revision.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Pose {
    deltas: Vec<PoseDelta>,
    revision: u64,
}

impl Pose {
    /// The reference pose over `bone_count` bones.
    pub fn new(bone_count: usize) -> Self {
        Self {
            deltas: vec![PoseDelta::default(); bone_count],
            revision: 0,
        }
    }

    /// The reference pose for a skeleton.
    pub fn reference(skeleton: &Skeleton) -> Self {
        Self::new(skeleton.bones.len())
    }

    pub fn bone_count(&self) -> usize {
        self.deltas.len()
    }

    /// Monotonic change counter. A consumer compares revisions to skip work.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn delta(&self, bone: usize) -> Option<PoseDelta> {
        self.deltas.get(bone).copied()
    }

    pub fn is_reference(&self) -> bool {
        self.deltas.iter().all(PoseDelta::is_identity)
    }

    /// Whether `skeleton` matches this pose's bone count.
    pub fn matches(&self, skeleton: &Skeleton) -> bool {
        self.deltas.len() == skeleton.bones.len()
    }

    /// Replaces one bone's rotation delta.
    pub fn set_rotation(&mut self, bone: usize, rotation: Quat) -> Result<(), PoseError> {
        if !rotation.is_finite() {
            return Err(PoseError::NonFinite { bone });
        }
        let delta = self
            .deltas
            .get_mut(bone)
            .ok_or(PoseError::InvalidBone(bone))?;
        if delta.rotation != rotation {
            delta.rotation = rotation.normalize();
            self.revision = self.revision.wrapping_add(1);
        }
        Ok(())
    }

    /// Replaces one bone's translation delta.
    pub fn set_translation(&mut self, bone: usize, translation: Vec3) -> Result<(), PoseError> {
        if !translation.is_finite() {
            return Err(PoseError::NonFinite { bone });
        }
        let delta = self
            .deltas
            .get_mut(bone)
            .ok_or(PoseError::InvalidBone(bone))?;
        if delta.translation != translation {
            delta.translation = translation;
            self.revision = self.revision.wrapping_add(1);
        }
        Ok(())
    }

    /// Replaces both deltas of one bone.
    pub fn set_local(
        &mut self,
        bone: usize,
        translation: Vec3,
        rotation: Quat,
    ) -> Result<(), PoseError> {
        self.set_rotation(bone, rotation)?;
        self.set_translation(bone, translation)
    }

    /// The rotation delta of one bone, for a caller that accumulates it.
    pub fn rotation(&self, bone: usize) -> Option<Quat> {
        self.deltas.get(bone).map(|delta| delta.rotation)
    }

    pub fn translation(&self, bone: usize) -> Option<Vec3> {
        self.deltas.get(bone).map(|delta| delta.translation)
    }

    /// Clears one bone's deltas.
    pub fn reset_bone(&mut self, bone: usize) -> Result<(), PoseError> {
        let delta = self
            .deltas
            .get_mut(bone)
            .ok_or(PoseError::InvalidBone(bone))?;
        if !delta.is_identity() {
            *delta = PoseDelta::default();
            self.revision = self.revision.wrapping_add(1);
        }
        Ok(())
    }

    /// Clears every delta, returning to the reference pose.
    pub fn reset(&mut self) {
        if !self.is_reference() {
            self.deltas.fill(PoseDelta::default());
            self.revision = self.revision.wrapping_add(1);
        }
    }

    /// Resolves the local and model-space transforms for every bone.
    ///
    /// The stored array is not required to be parent-first: each bone is
    /// resolved through its own parent chain, and a cycle is reported instead
    /// of recursing.
    pub fn globals(&self, skeleton: &Skeleton) -> Result<Vec<PosedBone>, PoseError> {
        if !self.matches(skeleton) {
            return Err(PoseError::InvalidBone(self.deltas.len()));
        }
        let count = skeleton.bones.len();
        let mut state = vec![0u8; count];
        let mut resolved: Vec<Option<PosedBone>> = vec![None; count];
        for index in 0..count {
            self.resolve(index, skeleton, &mut state, &mut resolved)?;
        }
        Ok(resolved
            .into_iter()
            .map(|bone| bone.expect("every bone was resolved"))
            .collect())
    }

    fn resolve(
        &self,
        index: usize,
        skeleton: &Skeleton,
        state: &mut [u8],
        resolved: &mut [Option<PosedBone>],
    ) -> Result<PosedBone, PoseError> {
        match state[index] {
            2 => return Ok(resolved[index].expect("a resolved bone is stored")),
            1 => return Err(PoseError::Cycle { bone: index }),
            _ => {}
        }
        state[index] = 1;
        let bone = skeleton
            .bones
            .get(index)
            .ok_or(PoseError::InvalidBone(index))?;
        if !bone.local_rotation.is_finite()
            || !bone.local_translation.is_finite()
            || !bone.local_scale.is_finite()
        {
            return Err(PoseError::NonFinite { bone: index });
        }
        if (bone.local_scale - Vec3::ONE).abs().max_element() > SCALE_TOLERANCE {
            return Err(PoseError::UnsupportedScale {
                bone: index,
                scale: bone.local_scale,
            });
        }
        let delta = self.deltas.get(index).copied().unwrap_or_default();
        let rotation = bone.local_rotation.normalize() * delta.rotation.normalize();
        let translation = bone.local_translation + delta.translation;
        if !rotation.is_finite() || !translation.is_finite() {
            return Err(PoseError::NonFinite { bone: index });
        }
        let (model_rotation, model_position) = match bone.parent {
            Some(parent) => {
                if parent >= skeleton.bones.len() {
                    return Err(PoseError::InvalidParent {
                        bone: index,
                        parent,
                    });
                }
                let parent = self.resolve(parent, skeleton, state, resolved)?;
                (
                    parent.model_rotation * rotation,
                    parent.model_position + parent.model_rotation * translation,
                )
            }
            None => (rotation, translation),
        };
        let posed = PosedBone {
            rotation,
            translation,
            model_rotation,
            model_position,
        };
        resolved[index] = Some(posed);
        state[index] = 2;
        Ok(posed)
    }

    /// The model-space transform of every bone under this pose.
    pub fn model_transforms(&self, skeleton: &Skeleton) -> Result<Vec<Mat4>, PoseError> {
        Ok(self
            .globals(skeleton)?
            .into_iter()
            .zip(&skeleton.bones)
            .map(|(posed, bone)| {
                Mat4::from_scale_rotation_translation(
                    bone.local_scale,
                    posed.model_rotation,
                    posed.model_position,
                )
            })
            .collect())
    }
}

/// Whether a skeleton can be posed by this feature.
pub fn check_supported(skeleton: &Skeleton) -> Result<(), PoseError> {
    for (index, bone) in skeleton.bones.iter().enumerate() {
        if (bone.local_scale - Vec3::ONE).abs().max_element() > SCALE_TOLERANCE {
            return Err(PoseError::UnsupportedScale {
                bone: index,
                scale: bone.local_scale,
            });
        }
        if let Some(parent) = bone.parent
            && parent >= skeleton.bones.len()
        {
            return Err(PoseError::InvalidParent {
                bone: index,
                parent,
            });
        }
    }
    Ok(())
}

/// The authored transform of one bone, for a bind-pose comparison.
pub fn bind_transform(bone: &Bone) -> Mat4 {
    Mat4::from_rotation_translation(bone.model_rotation, bone.model_position)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skeleton(bones: Vec<(Option<usize>, Vec3, Quat)>) -> Skeleton {
        let bones = bones
            .into_iter()
            .enumerate()
            .map(|(index, (parent, translation, rotation))| Bone {
                name: None,
                index,
                parent,
                identifier: None,
                identifier16: None,
                local_translation: translation,
                local_rotation: rotation,
                local_scale: Vec3::ONE,
                model_rotation: rotation,
                model_position: translation,
                inverse_bind: None,
            })
            .collect();
        Skeleton {
            bones,
            roots: Vec::new(),
            max_depth: 0,
        }
    }

    #[test]
    fn the_reference_pose_reproduces_the_stored_transforms() {
        let skeleton = skeleton(vec![
            (None, Vec3::new(1.0, 0.0, 0.0), Quat::IDENTITY),
            (
                Some(0),
                Vec3::new(0.0, 2.0, 0.0),
                Quat::from_rotation_z(std::f32::consts::FRAC_PI_2),
            ),
        ]);
        let pose = Pose::reference(&skeleton);
        assert!(pose.is_reference());
        let posed = pose.globals(&skeleton).unwrap();
        assert_eq!(posed[0].model_position, Vec3::new(1.0, 0.0, 0.0));
        let expected = Vec3::new(1.0, 0.0, 0.0) + Quat::IDENTITY * Vec3::new(0.0, 2.0, 0.0);
        assert_eq!(posed[1].model_position, expected);
        assert!(
            (posed[1].model_rotation - Quat::from_rotation_z(std::f32::consts::FRAC_PI_2)).length()
                < 1e-6
        );
    }

    #[test]
    fn a_parent_rotation_moves_its_child_and_nothing_else() {
        let skeleton = skeleton(vec![
            (None, Vec3::ZERO, Quat::IDENTITY),
            (Some(0), Vec3::new(0.0, 1.0, 0.0), Quat::IDENTITY),
            (None, Vec3::new(5.0, 0.0, 0.0), Quat::IDENTITY),
        ]);
        let mut pose = Pose::reference(&skeleton);
        pose.set_rotation(0, Quat::from_rotation_z(std::f32::consts::FRAC_PI_2))
            .unwrap();
        let posed = pose.globals(&skeleton).unwrap();
        assert!((posed[1].model_position - Vec3::new(-1.0, 0.0, 0.0)).length() < 1e-6);
        assert_eq!(posed[2].model_position, Vec3::new(5.0, 0.0, 0.0));
        assert_eq!(posed[2].model_rotation, Quat::IDENTITY);
    }

    #[test]
    fn a_translation_delta_is_applied_in_the_parent_space() {
        let skeleton = skeleton(vec![
            (
                None,
                Vec3::ZERO,
                Quat::from_rotation_z(std::f32::consts::FRAC_PI_2),
            ),
            (Some(0), Vec3::ZERO, Quat::IDENTITY),
        ]);
        let mut pose = Pose::reference(&skeleton);
        pose.set_translation(1, Vec3::new(1.0, 0.0, 0.0)).unwrap();
        let posed = pose.globals(&skeleton).unwrap();
        assert!((posed[1].model_position - Vec3::new(0.0, 1.0, 0.0)).length() < 1e-6);
    }

    #[test]
    fn a_non_parent_first_array_still_resolves() {
        let mut skeleton = skeleton(vec![
            (Some(1), Vec3::new(0.0, 2.0, 0.0), Quat::IDENTITY),
            (None, Vec3::new(1.0, 0.0, 0.0), Quat::IDENTITY),
        ]);
        // Keep the stored model values consistent with the resolved order.
        skeleton.bones[0].model_position = Vec3::new(1.0, 2.0, 0.0);
        let pose = Pose::reference(&skeleton);
        let posed = pose.globals(&skeleton).unwrap();
        assert_eq!(posed[0].model_position, Vec3::new(1.0, 2.0, 0.0));
    }

    #[test]
    fn a_cycle_is_reported_before_any_pose_is_composed() {
        let mut skeleton = skeleton(vec![
            (Some(1), Vec3::ZERO, Quat::IDENTITY),
            (Some(0), Vec3::ZERO, Quat::IDENTITY),
        ]);
        skeleton.bones[0].parent = Some(1);
        skeleton.bones[1].parent = Some(0);
        let pose = Pose::reference(&skeleton);
        assert!(matches!(
            pose.globals(&skeleton),
            Err(PoseError::Cycle { .. })
        ));
    }

    #[test]
    fn a_non_identity_scale_is_not_posed() {
        let mut skeleton = skeleton(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
        skeleton.bones[0].local_scale = Vec3::splat(2.0);
        let pose = Pose::reference(&skeleton);
        assert!(matches!(
            pose.globals(&skeleton),
            Err(PoseError::UnsupportedScale { .. })
        ));
    }

    #[test]
    fn resetting_one_bone_keeps_the_others() {
        let skeleton = skeleton(vec![
            (None, Vec3::ZERO, Quat::IDENTITY),
            (None, Vec3::ZERO, Quat::IDENTITY),
        ]);
        let mut pose = Pose::reference(&skeleton);
        pose.set_translation(0, Vec3::X).unwrap();
        pose.set_translation(1, Vec3::Y).unwrap();
        let before = pose.revision();
        pose.reset_bone(0).unwrap();
        assert_eq!(pose.translation(0), Some(Vec3::ZERO));
        assert_eq!(pose.translation(1), Some(Vec3::Y));
        assert!(pose.revision() > before);
        pose.reset();
        assert!(pose.is_reference());
    }

    #[test]
    fn non_finite_and_out_of_range_inputs_are_rejected() {
        let skeleton = skeleton(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
        let mut pose = Pose::reference(&skeleton);
        assert_eq!(
            pose.set_translation(0, Vec3::splat(f32::NAN)),
            Err(PoseError::NonFinite { bone: 0 })
        );
        assert_eq!(
            pose.set_rotation(3, Quat::IDENTITY),
            Err(PoseError::InvalidBone(3))
        );
    }
}
