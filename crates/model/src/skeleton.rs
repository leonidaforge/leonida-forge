//! Skeleton decoding between the structural walk and the scene representation.
//!
//! [`lforge_rage9::skeleton`] reads the record. This module composes the stored
//! local transforms into model-space transforms, validates the stored
//! inverse-bind records against the composed pose, and reports how complete the
//! result is. Nothing here deforms geometry.

use glam::{Mat4, Quat, Vec3};
use lforge_rage9::skeleton;
use lforge_scene::{Bone, Diagnostic, Skeleton};

/// How much of a skeleton the decoder established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkeletonCompleteness {
    /// The header holds a null skeleton pointer. A drawable without a skeleton
    /// is complete as a static drawable.
    NotPresent,
    /// Every bone, parent and transform was read, and every stored
    /// inverse-bind record validated against the composed pose.
    Complete,
    /// Bones were read, but part of the record is unresolved or inconsistent.
    Partial { reason: String },
    /// The skeleton pointer resolves but the record cannot be read as bones.
    Unsupported { reason: String },
}

impl SkeletonCompleteness {
    pub fn name(&self) -> &'static str {
        match self {
            SkeletonCompleteness::NotPresent => "not present",
            SkeletonCompleteness::Complete => "complete",
            SkeletonCompleteness::Partial { .. } => "partial",
            SkeletonCompleteness::Unsupported { .. } => "unsupported",
        }
    }
}

/// Which bones a scene's primitives reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssociationCompleteness {
    /// No geometry declares a bone count and no influence stream was found.
    NotReferenced,
    /// Every geometry with a declared bone count resolved its influences.
    Complete,
    /// Some geometry declares bones, but its influence data did not validate.
    Partial { reason: String },
    /// The resource carries bone associations this decoder does not interpret.
    Unsupported { reason: String },
}

impl AssociationCompleteness {
    pub fn name(&self) -> &'static str {
        match self {
            AssociationCompleteness::NotReferenced => "not referenced",
            AssociationCompleteness::Complete => "complete",
            AssociationCompleteness::Partial { .. } => "partial",
            AssociationCompleteness::Unsupported { .. } => "unsupported",
        }
    }
}

/// What the decoder can say about the space the authored geometry sits in.
///
/// The decoder never moves geometry by a bone transform, and no rule for a
/// bone-local vertex space is claimed. The only positive evidence available is
/// the box the record itself declares for a geometry: when the decoded vertices
/// agree with it, the vertices and the record describe the same space. That is
/// still not proof that no later stage places the geometry, so the verdict names
/// the comparison rather than a conclusion about placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementCompleteness {
    /// Authored vertices match the box the record declares for every decoded
    /// geometry. Nothing was placed, and the record agrees with the vertices it
    /// ships, but a later placement stage is not ruled out.
    AuthoredGeometryMatchesBounds,
    /// The stored coordinate space is not established for this resource.
    Unverified { reason: String },
    /// A placement was applied, with the reason recorded.
    Applied { reason: String },
}

impl PlacementCompleteness {
    pub fn name(&self) -> &'static str {
        match self {
            PlacementCompleteness::AuthoredGeometryMatchesBounds => {
                "authored geometry matches bounds"
            }
            PlacementCompleteness::Unverified { .. } => "unverified",
            PlacementCompleteness::Applied { .. } => "applied",
        }
    }
}

/// Tolerance for a stored inverse-bind record against the composed pose.
const INVERSE_BIND_TOLERANCE: f32 = 2e-3;
/// Tolerance for a stored quaternion's length.
const QUATERNION_TOLERANCE: f32 = 2e-3;

/// Decodes the skeleton a drawable header points at.
///
/// `header_skeleton` is the resolved system offset from the drawable header's
/// `+0x18` slot, or `None` when that slot was null or did not decode.
pub fn build(
    system: &[u8],
    header_skeleton: Option<u32>,
    diagnostics: &mut Vec<Diagnostic>,
) -> (Option<Skeleton>, SkeletonCompleteness) {
    let Some(at) = header_skeleton else {
        return (None, SkeletonCompleteness::NotPresent);
    };
    let report = skeleton::inspect(system, at);
    for issue in &report.issues {
        diagnostics.push(Diagnostic::new(format!("skeleton: {issue}")));
    }
    if report.bones.is_empty() {
        return (
            None,
            SkeletonCompleteness::Unsupported {
                reason: "the skeleton record holds no readable bone".to_string(),
            },
        );
    }

    let mut partial_reasons: Vec<String> = Vec::new();
    let mut model_rotation: Vec<Quat> = Vec::with_capacity(report.bones.len());
    let mut model_position: Vec<Vec3> = Vec::with_capacity(report.bones.len());
    let mut bones: Vec<Bone> = Vec::with_capacity(report.bones.len());
    for source in &report.bones {
        let rotation = Quat::from_xyzw(
            source.rotation[0],
            source.rotation[1],
            source.rotation[2],
            source.rotation[3],
        );
        let translation = Vec3::from_array(source.translation);
        let scale = Vec3::from_array(source.scale);
        if !rotation.is_finite()
            || !translation.is_finite()
            || !scale.is_finite()
            || scale.abs_diff_eq(Vec3::ZERO, f32::EPSILON)
        {
            partial_reasons.push(format!(
                "bone {} stores a transformation that is not usable",
                source.index
            ));
        }
        if rotation.is_finite() && (rotation.length() - 1.0).abs() > QUATERNION_TOLERANCE {
            partial_reasons.push(format!(
                "bone {} stores a quaternion of length {:.4}",
                source.index,
                rotation.length()
            ));
        }
        // The `+0x38` array states the same local transform as a matrix, with
        // the rotation transposed. Comparing the two statements checks the
        // quaternion convention at every bone without going through the
        // hierarchy, so a wrong convention cannot hide behind a plausible pose.
        if let Some(stored) = report.local_matrices.get(source.index) {
            let stored_rotation = mat3_from_row_major(&stored.rotation).transpose();
            let actual = Mat4::from_rotation_translation(rotation, translation).to_cols_array();
            let expected = Mat4::from_cols_array(&[
                stored_rotation.x_axis.x,
                stored_rotation.x_axis.y,
                stored_rotation.x_axis.z,
                0.0,
                stored_rotation.y_axis.x,
                stored_rotation.y_axis.y,
                stored_rotation.y_axis.z,
                0.0,
                stored_rotation.z_axis.x,
                stored_rotation.z_axis.y,
                stored_rotation.z_axis.z,
                0.0,
                stored.translation[0],
                stored.translation[1],
                stored.translation[2],
                1.0,
            ])
            .to_cols_array();
            let delta = actual
                .iter()
                .zip(expected.iter())
                .map(|(a, b)| (a - b).abs())
                .fold(0.0, f32::max);
            if rotation.is_finite() && delta > INVERSE_BIND_TOLERANCE {
                diagnostics.push(Diagnostic::new(format!(
                    "skeleton: the stored local-matrix record of bone {} differs from its quaternion by {delta}",
                    source.index
                )));
                partial_reasons.push(format!(
                    "the local-matrix record of bone {} did not validate",
                    source.index
                ));
            }
        }
        let (resolved_rotation, resolved_position) = match source.parent {
            Some(parent) => {
                let parent_rotation = model_rotation
                    .get(parent)
                    .copied()
                    .unwrap_or(Quat::IDENTITY);
                let parent_position = model_position.get(parent).copied().unwrap_or(Vec3::ZERO);
                (
                    parent_rotation * rotation,
                    parent_position + parent_rotation * translation,
                )
            }
            None => (rotation, translation),
        };
        model_rotation.push(resolved_rotation);
        model_position.push(resolved_position);
        bones.push(Bone {
            name: source.name.clone(),
            index: source.index,
            parent: source.parent,
            identifier: Some(source.identifier),
            identifier16: Some(source.identifier16),
            local_translation: translation,
            local_rotation: rotation,
            local_scale: scale,
            model_rotation: resolved_rotation,
            model_position: resolved_position,
            inverse_bind: None,
        });
    }

    // Validate the stored inverse-bind records against the composed pose. A
    // record that disagrees is reported and dropped, not silently used.
    for (index, stored) in report.inverse_bind.iter().enumerate() {
        let Some(bone) = bones.get_mut(index) else {
            break;
        };
        let matrix = inverse_bind_matrix(stored);
        let expected =
            Mat4::from_rotation_translation(bone.model_rotation, bone.model_position).inverse();
        let delta = matrix_delta(&matrix, &expected);
        if delta <= INVERSE_BIND_TOLERANCE {
            bone.inverse_bind = Some(matrix);
        } else {
            diagnostics.push(Diagnostic::new(format!(
                "skeleton: the stored inverse-bind record of bone {index} differs from the resolved pose by {delta}"
            )));
            partial_reasons.push(format!(
                "the inverse-bind record of bone {index} did not validate"
            ));
        }
    }

    let completeness = if !report.complete() || !partial_reasons.is_empty() {
        let mut reason = if report.issues.is_empty() {
            String::new()
        } else {
            format!("{} structural issue(s)", report.issues.len())
        };
        if !partial_reasons.is_empty() {
            if !reason.is_empty() {
                reason.push_str("; ");
            }
            reason.push_str(&partial_reasons[0]);
            if partial_reasons.len() > 1 {
                reason.push_str(&format!(" (and {} more)", partial_reasons.len() - 1));
            }
        }
        SkeletonCompleteness::Partial { reason }
    } else {
        SkeletonCompleteness::Complete
    };

    (
        Some(Skeleton {
            bones,
            roots: report.roots.clone(),
            max_depth: report.max_depth,
        }),
        completeness,
    )
}

/// Assembles the inverse-bind matrix from the record's transposed storage.
///
/// The record stores the model-space rotation row-major. An inverse bind
/// matrix holds its transpose, so the columns below are the stored rows.
fn inverse_bind_matrix(stored: &skeleton::Matrix34) -> Mat4 {
    let [r00, r01, r02, r10, r11, r12, r20, r21, r22] = stored.rotation;
    let [tx, ty, tz] = stored.translation;
    Mat4::from_cols_array(&[
        r00, r01, r02, 0.0, //
        r10, r11, r12, 0.0, //
        r20, r21, r22, 0.0, //
        tx, ty, tz, 1.0,
    ])
}

/// A matrix as glam reads the record's row-major elements.
///
/// The record stores nine `f32` row after row, so building a `Mat3` from those
/// values as columns would silently transpose it.
fn mat3_from_row_major(stored: &[f32; 9]) -> glam::Mat3 {
    let [r00, r01, r02, r10, r11, r12, r20, r21, r22] = *stored;
    glam::Mat3::from_cols_array(&[r00, r10, r20, r01, r11, r21, r02, r12, r22])
}

/// The largest absolute difference between two matrices.
fn matrix_delta(a: &Mat4, b: &Mat4) -> f32 {
    a.to_cols_array()
        .iter()
        .zip(b.to_cols_array().iter())
        .map(|(a, b)| (a - b).abs())
        .fold(0.0, f32::max)
}
