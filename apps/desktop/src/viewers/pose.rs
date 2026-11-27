//! The temporary pose state of one viewer.
//!
//! The session never touches the decoded skeleton: it holds a
//! [`lforge_scene::Pose`] of local deltas and the Euler angles the controls
//! display. Resetting a bone or the whole pose returns to the verified
//! reference pose.
//!
//! Rotation controls are three independent axis deltas composed as
//! `Quat::from_euler(EulerRot::XYZ, x, y, z)`. The delta is applied in the
//! bone's own space after the stored local rotation, as
//! [`lforge_scene::Pose`] documents. Translation deltas are in the parent's
//! space. Degrees and model-space units (metres) are the display units, and
//! scaling is not offered.

use glam::{EulerRot, Mat4, Quat, Vec3};
use lforge_scene::{Pose, PoseError, Skeleton, SkinningMatrices};

/// Degrees one rotation button adds.
pub const ROTATION_STEP_DEGREES: f32 = 5.0;
/// Model-space units one translation button adds.
pub const TRANSLATION_STEP: f32 = 0.05;

/// Which geometry a pose-mode view draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoseDisplay {
    /// The authored geometry through the ordinary static path.
    Authored,
    /// The geometry deformed at the current pose.
    Posed,
}

impl PoseDisplay {
    pub fn name(self) -> &'static str {
        match self {
            PoseDisplay::Authored => "authored",
            PoseDisplay::Posed => "posed",
        }
    }
}

/// The pose data one frame needs, built on the UI thread and applied on the
/// render thread. Immutable and cheap to share.
#[derive(Debug, Clone)]
pub struct PoseFrame {
    pub revision: u64,
    pub matrices: Vec<Mat4>,
    pub bone_positions: Vec<Vec3>,
    /// Whether the skinned pipeline should draw.
    pub active: bool,
    /// Whether the selected-bone influence view is on.
    pub influence: bool,
}

impl PoseFrame {
    /// The verified reference pose, sent once when pose mode is left so the
    /// overlay and the joint matrices return to the authored skeleton.
    pub fn reference(skeleton: &Skeleton) -> Result<Self, PoseError> {
        let pose = Pose::reference(skeleton);
        let matrices = SkinningMatrices::build(skeleton, &pose)?;
        Ok(Self {
            revision: 0,
            matrices: matrices.matrices().to_vec(),
            bone_positions: skeleton
                .bones
                .iter()
                .map(|bone| bone.model_position)
                .collect(),
            active: false,
            influence: false,
        })
    }
}

/// Pose mode state of one viewer. UI-independent so it can be tested without a
/// window.
#[derive(Debug, Clone)]
pub struct PoseSession {
    pose: Pose,
    angles: Vec<[f32; 3]>,
    translations: Vec<Vec3>,
    display: PoseDisplay,
    influence: bool,
    revision: u64,
}

impl PoseSession {
    pub fn new(bone_count: usize) -> Self {
        Self {
            pose: Pose::new(bone_count),
            angles: vec![[0.0; 3]; bone_count],
            translations: vec![Vec3::ZERO; bone_count],
            display: PoseDisplay::Posed,
            influence: false,
            revision: 0,
        }
    }

    pub fn bone_count(&self) -> usize {
        self.pose.bone_count()
    }

    /// The pose the session holds. The viewer reads it for bounds evaluation.
    pub fn pose(&self) -> &Pose {
        &self.pose
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn display(&self) -> PoseDisplay {
        self.display
    }

    pub fn influence_view(&self) -> bool {
        self.influence
    }

    /// Changes the displayed geometry. The pose is kept, so switching back to
    /// `Posed` restores the deformation.
    pub fn set_display(&mut self, display: PoseDisplay) {
        if self.display != display {
            self.display = display;
            self.revision = self.revision.wrapping_add(1);
        }
    }

    pub fn set_influence_view(&mut self, enabled: bool) {
        if self.influence != enabled {
            self.influence = enabled;
            if enabled {
                // The visualisation reads the skinned vertex data.
                self.display = PoseDisplay::Posed;
            }
            self.revision = self.revision.wrapping_add(1);
        }
    }

    /// The composed Euler angles of one bone's rotation delta, in degrees.
    pub fn rotation_degrees(&self, bone: usize) -> Option<[f32; 3]> {
        self.angles.get(bone).copied()
    }

    pub fn translation(&self, bone: usize) -> Option<Vec3> {
        self.translations.get(bone).copied()
    }

    /// Adds `steps` button presses around one axis (`0` X, `1` Y, `2` Z).
    pub fn adjust_rotation(
        &mut self,
        bone: usize,
        axis: usize,
        steps: i32,
    ) -> Result<(), PoseError> {
        if steps == 0 {
            return Ok(());
        }
        let angles = self
            .angles
            .get_mut(bone)
            .ok_or(PoseError::InvalidBone(bone))?;
        let axis = axis.min(2);
        angles[axis] += steps as f32 * ROTATION_STEP_DEGREES;
        angles[axis] = wrap_degrees(angles[axis]);
        let [x, y, z] = *angles;
        let rotation = Quat::from_euler(
            EulerRot::XYZ,
            x.to_radians(),
            y.to_radians(),
            z.to_radians(),
        );
        self.pose.set_rotation(bone, rotation)?;
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }

    /// Adds `steps` button presses along one axis of the parent space.
    pub fn adjust_translation(
        &mut self,
        bone: usize,
        axis: usize,
        steps: i32,
    ) -> Result<(), PoseError> {
        if steps == 0 {
            return Ok(());
        }
        let translation = self
            .translations
            .get_mut(bone)
            .ok_or(PoseError::InvalidBone(bone))?;
        let axis = axis.min(2);
        let delta = Vec3::ZERO + Vec3::AXES[axis] * (steps as f32 * TRANSLATION_STEP);
        *translation += delta;
        let value = *translation;
        self.pose.set_translation(bone, value)?;
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }

    /// Clears one bone's rotation and translation deltas.
    pub fn reset_bone(&mut self, bone: usize) -> Result<(), PoseError> {
        if bone >= self.bone_count() {
            return Err(PoseError::InvalidBone(bone));
        }
        self.angles[bone] = [0.0; 3];
        self.translations[bone] = Vec3::ZERO;
        self.pose.reset_bone(bone)?;
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }

    /// Clears every delta.
    pub fn reset_all(&mut self) {
        self.angles.iter_mut().for_each(|angles| *angles = [0.0; 3]);
        self.translations.fill(Vec3::ZERO);
        self.pose.reset();
        self.revision = self.revision.wrapping_add(1);
    }

    pub fn is_reference(&self) -> bool {
        self.pose.is_reference()
    }

    /// Builds the frame the renderer applies.
    ///
    /// In `Authored` display the frame carries the reference pose with
    /// `active = false`, so the render thread restores the authored skeleton
    /// and leaves the static pipeline in charge.
    pub fn frame(&self, skeleton: &Skeleton) -> Result<PoseFrame, PoseError> {
        if !self.pose.matches(skeleton) {
            return Err(PoseError::InvalidBone(self.pose.bone_count()));
        }
        if self.display == PoseDisplay::Authored {
            let reference = Pose::reference(skeleton);
            let matrices = SkinningMatrices::build(skeleton, &reference)?;
            return Ok(PoseFrame {
                revision: self.revision,
                matrices: matrices.matrices().to_vec(),
                bone_positions: skeleton
                    .bones
                    .iter()
                    .map(|bone| bone.model_position)
                    .collect(),
                active: false,
                influence: false,
            });
        }
        let matrices = SkinningMatrices::build(skeleton, &self.pose)?;
        let posed = self.pose.globals(skeleton)?;
        Ok(PoseFrame {
            revision: self.revision,
            matrices: matrices.matrices().to_vec(),
            bone_positions: posed.into_iter().map(|bone| bone.model_position).collect(),
            active: true,
            influence: self.influence,
        })
    }
}

fn wrap_degrees(value: f32) -> f32 {
    let wrapped = (value + 180.0).rem_euclid(360.0) - 180.0;
    if wrapped == -180.0 { 180.0 } else { wrapped }
}

#[cfg(test)]
mod tests;
