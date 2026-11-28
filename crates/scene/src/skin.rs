//! Per-vertex bone influences and linear blend skinning.
//!
//! The types here are renderer-neutral and GPU-free: a decoder fills
//! [`VertexInfluences`], a caller builds [`SkinningMatrices`] from a
//! [`crate::Pose`], and [`deform_primitive`] produces a new primitive without
//! touching the authored one. The desktop viewer and an exporter share this
//! path; the GPU implementation consumes the same resolved indices.
//!
//! Skinning matrix convention, with column vectors:
//!
//! `S[i] = G_pose[i] * inverse(G_bind[i])`
//!
//! A stored inverse-bind record is used where it validated against the composed
//! bind pose. Where no record exists the inverse of the bind transform is
//! derived and counted, so a caller never reports stored and derived data as
//! one thing.

use glam::{Mat3, Mat4, Vec3};

use crate::{Aabb, Pose, PoseError, Primitive, Skeleton};

/// The number of influence lanes a primitive may carry.
pub const MAX_INFLUENCES: usize = 4;

/// The largest scale deviation from one accepted for deformation.
const SCALE_TOLERANCE: f32 = 1e-4;

/// One bone and its weight for one vertex.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VertexInfluence {
    /// Index into [`Skeleton::bones`]. The decoder resolves any palette before
    /// this point, so the index is the skeleton's own array position.
    pub bone: u16,
    /// Normalised weight in `0..=1`. An unused lane carries zero.
    pub weight: f32,
}

impl VertexInfluence {
    pub const NONE: Self = Self {
        bone: 0,
        weight: 0.0,
    };
}

/// What the decoder established about a primitive's influence data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfluenceStatus {
    /// Every vertex's active lanes validated against the skeleton and the
    /// stored weights are normalised.
    Complete,
    /// The weights are not normalised to a supported denominator. The
    /// primitive stays inspectable but is not reported as deformable.
    Unnormalised { vertex: usize, total: u32 },
    /// The declaration is not one this decoder interprets.
    Unsupported { reason: String },
}

impl InfluenceStatus {
    pub fn name(&self) -> &'static str {
        match self {
            InfluenceStatus::Complete => "complete",
            InfluenceStatus::Unnormalised { .. } => "unnormalised",
            InfluenceStatus::Unsupported { .. } => "unsupported",
        }
    }
}

/// How a stored blend index reaches the skeleton's bone array.
///
/// The supported resources address the skeleton directly. A palette form stays
/// expressible so a future decoder can record the indirection rather than
/// losing it while preparing GPU data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoneResolution {
    /// The stored index is a [`Skeleton::bones`] array position.
    DirectSkeleton,
    /// The stored index selects a palette entry that names the skeleton bone.
    Palette { entries: Vec<u16> },
}

/// Resolved influences for one primitive's vertices.
#[derive(Debug, Clone, PartialEq)]
pub struct VertexInfluences {
    /// Exactly one entry per vertex, padded to [`MAX_INFLUENCES`] lanes.
    pub per_vertex: Vec<[VertexInfluence; MAX_INFLUENCES]>,
    /// The skeleton bones any vertex references, sorted.
    pub bones: Vec<usize>,
    /// Whether at least one vertex blends more than one bone.
    pub weighted: bool,
    /// The lane count the declaration carries before padding (1, 2 or 4), or
    /// zero for an inferred association that has no influence attribute.
    pub lanes: u8,
    /// The largest number of non-zero lanes one vertex uses.
    pub max_influences: u8,
    /// How the stored indices reach the skeleton.
    pub resolution: BoneResolution,
    pub status: InfluenceStatus,
    /// Whether the association was inferred from a one-bone geometry that
    /// declares no influence attribute, rather than read from an influence
    /// stream. An inferred set deforms, but it is reported apart from a decoded
    /// one because the geometry record states no bone reference.
    pub inferred: bool,
}

impl VertexInfluences {
    /// Whether this data may deform geometry.
    pub fn deformable(&self) -> bool {
        self.status == InfluenceStatus::Complete
    }

    /// Whether every vertex uses exactly one influence. This is single-influence
    /// vertex skinning: the bone may still differ per vertex, so the primitive is
    /// not necessarily one rigid piece.
    pub fn single_influence(&self) -> bool {
        self.max_influences <= 1
    }

    /// Whether the whole primitive follows one bone. Distinct from
    /// [`Self::single_influence`], which allows a different bone per vertex.
    pub fn rigid_attachment(&self) -> bool {
        self.single_influence() && self.bones.len() == 1
    }

    /// Whether this association is inferred rather than decoded.
    pub fn inferred(&self) -> bool {
        self.inferred
    }

    /// The status line a viewer prints. An inferred association is named
    /// separately so it never reads as a decoded one.
    pub fn status_name(&self) -> String {
        if self.inferred {
            format!("{} (inferred single bone)", self.status.name())
        } else {
            self.status.name().to_string()
        }
    }

    /// The weight the given skeleton bone has on one vertex, if any.
    pub fn weight_of(&self, vertex: usize, bone: usize) -> Option<f32> {
        let lanes = self.per_vertex.get(vertex)?;
        let mut total = 0.0;
        let mut found = false;
        for influence in lanes {
            if influence.weight == 0.0 {
                continue;
            }
            if usize::from(influence.bone) == bone {
                total += influence.weight;
                found = true;
            }
        }
        found.then_some(total)
    }

    pub fn vertex_count(&self) -> usize {
        self.per_vertex.len()
    }
}

/// Skinning matrices built from one pose.
#[derive(Debug, Clone, PartialEq)]
pub struct SkinningMatrices {
    matrices: Vec<Mat4>,
    stored: usize,
    derived: usize,
    revision: u64,
}

impl SkinningMatrices {
    /// Builds `S[i] = G_pose[i] * inverse(G_bind[i])` for every bone.
    pub fn build(skeleton: &Skeleton, pose: &Pose) -> Result<Self, PoseError> {
        if !pose.matches(skeleton) {
            return Err(PoseError::InvalidBone(pose.bone_count()));
        }
        let posed = pose.model_transforms(skeleton)?;
        let mut matrices = Vec::with_capacity(posed.len());
        let mut stored = 0usize;
        let mut derived = 0usize;
        for ((posed, bone), index) in posed.iter().zip(&skeleton.bones).zip(0..) {
            let inverse_bind = match bone.inverse_bind {
                Some(matrix) => {
                    stored += 1;
                    matrix
                }
                None => {
                    if (bone.local_scale - Vec3::ONE).abs().max_element() > SCALE_TOLERANCE {
                        return Err(PoseError::UnsupportedScale {
                            bone: index,
                            scale: bone.local_scale,
                        });
                    }
                    derived += 1;
                    Mat4::from_rotation_translation(bone.model_rotation, bone.model_position)
                        .inverse()
                }
            };
            let matrix = *posed * inverse_bind;
            if !matrix.is_finite() {
                return Err(PoseError::NonFinite { bone: index });
            }
            matrices.push(matrix);
        }
        Ok(Self {
            matrices,
            stored,
            derived,
            revision: pose.revision(),
        })
    }

    pub fn matrices(&self) -> &[Mat4] {
        &self.matrices
    }

    pub fn len(&self) -> usize {
        self.matrices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.matrices.is_empty()
    }

    /// Bones whose inverse bind came from the validated stored record.
    pub fn stored(&self) -> usize {
        self.stored
    }

    /// Bones whose inverse bind was derived from the bind transform.
    pub fn derived(&self) -> usize {
        self.derived
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
}

/// Why a primitive cannot be deformed.
#[derive(Debug, Clone, PartialEq)]
pub enum DeformError {
    /// The primitive has no verified influence set.
    UnsupportedInfluences(InfluenceStatus),
    /// The influence array and the vertex array disagree.
    CountMismatch { vertices: usize, influences: usize },
    /// An active lane names a bone outside the matrix array.
    InvalidBone {
        vertex: usize,
        bone: u16,
        bones: usize,
    },
    /// A skeleton bone carries a scale the transform does not support.
    UnsupportedScale { bone: usize, scale: Vec3 },
    /// A resulting value is not finite.
    NonFinite { vertex: usize },
}

impl std::fmt::Display for DeformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeformError::UnsupportedInfluences(status) => {
                write!(f, "the primitive's influences are {}", status.name())
            }
            DeformError::CountMismatch {
                vertices,
                influences,
            } => write!(
                f,
                "the primitive holds {vertices} vertices but {influences} influence sets"
            ),
            DeformError::InvalidBone {
                vertex,
                bone,
                bones,
            } => write!(
                f,
                "vertex {vertex} names bone {bone}, outside the {bones}-bone skeleton"
            ),
            DeformError::UnsupportedScale { bone, scale } => {
                write!(f, "bone {bone} has scale {scale:?}, which is not supported")
            }
            DeformError::NonFinite { vertex } => {
                write!(f, "vertex {vertex} produced a non-finite value")
            }
        }
    }
}

impl std::error::Error for DeformError {}

/// One primitive deformed at a pose. The authored primitive is unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct DeformedPrimitive {
    pub positions: Vec<[f32; 3]>,
    pub normals: Vec<[f32; 3]>,
    /// Present only when the authored primitive carries tangents.
    pub tangents: Option<Vec<[f32; 4]>>,
    pub bounds: Aabb,
    /// Vertices whose blended normal collapsed and fell back to the authored
    /// normal. Linear blend skinning can cancel opposing rotations; the fallback
    /// is reported rather than hidden.
    pub collapsed_normals: usize,
}

impl DeformedPrimitive {
    pub fn vertex_count(&self) -> usize {
        self.positions.len()
    }
}

/// Linear blend skinning of one primitive. Every call starts from `primitive`'s
/// authored vertices, so evaluating a pose twice never compounds a deformation.
pub fn deform_primitive(
    primitive: &Primitive,
    influences: &VertexInfluences,
    matrices: &SkinningMatrices,
) -> Result<DeformedPrimitive, DeformError> {
    if !influences.deformable() {
        return Err(DeformError::UnsupportedInfluences(
            influences.status.clone(),
        ));
    }
    if influences.per_vertex.len() != primitive.vertices.len() {
        return Err(DeformError::CountMismatch {
            vertices: primitive.vertices.len(),
            influences: influences.per_vertex.len(),
        });
    }
    let bones = matrices.matrices();
    let mut positions = Vec::with_capacity(primitive.vertices.len());
    let mut normals = Vec::with_capacity(primitive.vertices.len());
    let mut tangents = primitive
        .vertices
        .iter()
        .any(|vertex| vertex.tangent.is_some())
        .then(|| Vec::with_capacity(primitive.vertices.len()));
    let mut bounds = Aabb::EMPTY;
    let mut collapsed_normals = 0usize;
    for (index, (vertex, lanes)) in primitive
        .vertices
        .iter()
        .zip(&influences.per_vertex)
        .enumerate()
    {
        let mut position = Vec3::ZERO;
        let mut normal = Vec3::ZERO;
        let mut tangent = Vec3::ZERO;
        for influence in lanes.iter().filter(|lane| lane.weight != 0.0) {
            let Some(matrix) = bones.get(usize::from(influence.bone)) else {
                return Err(DeformError::InvalidBone {
                    vertex: index,
                    bone: influence.bone,
                    bones: bones.len(),
                });
            };
            position += matrix.transform_point3(Vec3::from(vertex.position)) * influence.weight;
            let linear = Mat3::from_mat4(*matrix);
            normal += (linear * Vec3::from(vertex.normal)) * influence.weight;
            if let Some(source) = vertex.tangent {
                tangent +=
                    (linear * Vec3::from([source[0], source[1], source[2]])) * influence.weight;
            }
        }
        if !position.is_finite() {
            return Err(DeformError::NonFinite { vertex: index });
        }
        let normal = if normal.length_squared() > 1e-12 {
            normal.normalize()
        } else {
            collapsed_normals += 1;
            Vec3::from(vertex.normal).normalize_or_zero()
        };
        positions.push(position.to_array());
        normals.push(normal.to_array());
        if let (Some(out), Some(source)) = (tangents.as_mut(), vertex.tangent) {
            let xyz = if tangent.length_squared() > 1e-12 {
                tangent.normalize()
            } else {
                Vec3::from([source[0], source[1], source[2]]).normalize_or_zero()
            };
            out.push([xyz.x, xyz.y, xyz.z, source[3]]);
        }
        bounds = bounds.extend(position);
    }
    Ok(DeformedPrimitive {
        positions,
        normals,
        tangents,
        bounds,
        collapsed_normals,
    })
}

/// Bounds of one primitive at a pose, without materialising normals or
/// tangents. This is the CPU evaluation a viewer may request explicitly; it is
/// never needed for an interactive frame.
pub fn deformed_bounds(
    primitive: &Primitive,
    influences: &VertexInfluences,
    matrices: &SkinningMatrices,
) -> Result<Aabb, DeformError> {
    if !influences.deformable() {
        return Err(DeformError::UnsupportedInfluences(
            influences.status.clone(),
        ));
    }
    if influences.per_vertex.len() != primitive.vertices.len() {
        return Err(DeformError::CountMismatch {
            vertices: primitive.vertices.len(),
            influences: influences.per_vertex.len(),
        });
    }
    let bones = matrices.matrices();
    let mut bounds = Aabb::EMPTY;
    for (index, (vertex, lanes)) in primitive
        .vertices
        .iter()
        .zip(&influences.per_vertex)
        .enumerate()
    {
        let mut position = Vec3::ZERO;
        for influence in lanes.iter().filter(|lane| lane.weight != 0.0) {
            let Some(matrix) = bones.get(usize::from(influence.bone)) else {
                return Err(DeformError::InvalidBone {
                    vertex: index,
                    bone: influence.bone,
                    bones: bones.len(),
                });
            };
            position += matrix.transform_point3(Vec3::from(vertex.position)) * influence.weight;
        }
        if !position.is_finite() {
            return Err(DeformError::NonFinite { vertex: index });
        }
        bounds = bounds.extend(position);
    }
    Ok(bounds)
}

/// The posed mesh-space position of the vertices one bone influences.
pub fn influenced_centroid(
    primitive: &Primitive,
    influences: &VertexInfluences,
    bone: usize,
) -> Option<Vec3> {
    let mut sum = Vec3::ZERO;
    let mut weight = 0.0;
    for (vertex, lanes) in primitive.vertices.iter().zip(&influences.per_vertex) {
        for influence in lanes {
            if influence.weight != 0.0 && usize::from(influence.bone) == bone {
                sum += Vec3::from(vertex.position) * influence.weight;
                weight += influence.weight;
            }
        }
    }
    (weight > 0.0).then(|| sum / weight)
}

#[cfg(test)]
mod tests;
