//! CPU skinning tests. The expectations are calculated independently of the
//! implementation from the stated matrix convention.

use glam::{Mat4, Quat, Vec3};

use crate::{
    Aabb, InfluenceStatus, Pose, PoseError, Primitive, Skeleton, Vertex, VertexInfluence,
    VertexInfluences,
};

use super::{
    MAX_INFLUENCES, SkinningMatrices, deform_primitive, deform_primitive_with, deformed_bounds,
    influenced_centroid,
};

fn bone(
    index: usize,
    parent: Option<usize>,
    local_translation: Vec3,
    local_rotation: Quat,
    scale: Vec3,
) -> crate::Bone {
    let (model_rotation, model_position) = match parent {
        Some(_) => {
            // Callers pass model-space values for the parent case; a test that
            // needs a composed parent sets them explicitly through `skeleton_of`.
            (local_rotation, local_translation)
        }
        None => (local_rotation, local_translation),
    };
    let inverse_bind = Mat4::from_rotation_translation(model_rotation, model_position).inverse();
    crate::Bone {
        name: None,
        index,
        parent,
        identifier: None,
        identifier16: None,
        local_translation,
        local_rotation,
        local_scale: scale,
        model_rotation,
        model_position,
        inverse_bind: Some(inverse_bind),
    }
}

/// A skeleton whose model-space values are composed in array order.
fn skeleton_of(entries: Vec<(Option<usize>, Vec3, Quat)>) -> Skeleton {
    let mut bones: Vec<crate::Bone> = Vec::new();
    for (index, (parent, translation, rotation)) in entries.into_iter().enumerate() {
        let (model_rotation, model_position) = match parent {
            Some(parent) => {
                let parent = &bones[parent];
                (
                    parent.model_rotation * rotation,
                    parent.model_position + parent.model_rotation * translation,
                )
            }
            None => (rotation, translation),
        };
        let inverse_bind =
            Mat4::from_rotation_translation(model_rotation, model_position).inverse();
        bones.push(crate::Bone {
            name: None,
            index,
            parent,
            identifier: None,
            identifier16: None,
            local_translation: translation,
            local_rotation: rotation,
            local_scale: Vec3::ONE,
            model_rotation,
            model_position,
            inverse_bind: Some(inverse_bind),
        });
    }
    let roots = bones
        .iter()
        .filter(|bone| bone.parent.is_none())
        .map(|bone| bone.index)
        .collect();
    Skeleton {
        bones,
        roots,
        max_depth: 1,
    }
}

fn vertex(position: [f32; 3], normal: [f32; 3]) -> Vertex {
    Vertex {
        position,
        normal,
        tangent: None,
        uv0: [0.0; 2],
        uv1: None,
        color: [1.0; 4],
    }
}

fn primitive(vertices: Vec<Vertex>) -> Primitive {
    Primitive {
        material: 0,
        indices: (0..vertices.len() as u32).collect(),
        vertices,
    }
}

/// Influences from up to four `(bone, weight)` lanes per vertex.
fn influences(per_vertex: Vec<Vec<(u16, f32)>>) -> VertexInfluences {
    let mut bones = std::collections::BTreeSet::new();
    let mut max_influences = 0u8;
    let mut weighted = false;
    let per_vertex = per_vertex
        .into_iter()
        .map(|lanes| {
            max_influences = max_influences.max(lanes.len() as u8);
            if lanes.len() > 1 {
                weighted = true;
            }
            let mut out = [VertexInfluence::NONE; MAX_INFLUENCES];
            for (index, (bone, weight)) in lanes.into_iter().enumerate() {
                bones.insert(usize::from(bone));
                out[index] = VertexInfluence { bone, weight };
            }
            out
        })
        .collect();
    VertexInfluences {
        per_vertex,
        bones: bones.into_iter().collect(),
        weighted,
        lanes: 4,
        max_influences,
        resolution: crate::BoneResolution::DirectSkeleton,
        status: InfluenceStatus::Complete,
        inferred: false,
    }
}

#[test]
fn the_reference_pose_reconstructs_the_authored_geometry() {
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(0.0, 2.0, 0.0), Quat::IDENTITY),
    ]);
    let pose = Pose::reference(&skeleton);
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    for matrix in matrices.matrices() {
        let delta = matrix
            .to_cols_array()
            .iter()
            .zip(Mat4::IDENTITY.to_cols_array().iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0f32, f32::max);
        assert!(delta < 1e-6, "the bind pose left a matrix {matrix:?}");
    }
    let primitive = primitive(vec![
        vertex([1.0, 2.0, 3.0], [0.0, 0.0, 1.0]),
        vertex([-2.0, 0.5, 0.0], [0.0, 1.0, 0.0]),
    ]);
    let influences = influences(vec![vec![(0, 1.0)], vec![(1, 1.0)]]);
    let deformed = deform_primitive(&primitive, &influences, &matrices).unwrap();
    assert_eq!(deformed.positions, [[1.0, 2.0, 3.0], [-2.0, 0.5, 0.0]]);
    assert_eq!(deformed.normals, [[0.0, 0.0, 1.0], [0.0, 1.0, 0.0]]);
}

#[test]
fn a_rigid_single_bone_deformation_translates_its_vertices() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let mut pose = Pose::reference(&skeleton);
    pose.set_translation(0, Vec3::new(1.0, 0.0, 0.0)).unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    let primitive = primitive(vec![vertex([1.0, 0.0, 0.0], [1.0, 0.0, 0.0])]);
    let influences = influences(vec![vec![(0, 1.0)]]);
    let deformed = deform_primitive(&primitive, &influences, &matrices).unwrap();
    assert_eq!(deformed.positions[0], [2.0, 0.0, 0.0]);
    // A translation never changes a normal.
    assert_eq!(deformed.normals[0], [1.0, 0.0, 0.0]);
}

#[test]
fn two_weighted_influences_blend_their_transforms() {
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (None, Vec3::ZERO, Quat::IDENTITY),
    ]);
    let mut pose = Pose::reference(&skeleton);
    pose.set_rotation(0, Quat::from_rotation_z(std::f32::consts::FRAC_PI_2))
        .unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    let primitive = primitive(vec![vertex([1.0, 0.0, 0.0], [0.0, 0.0, 1.0])]);
    let influences = influences(vec![vec![(0, 0.5), (1, 0.5)]]);
    let deformed = deform_primitive(&primitive, &influences, &matrices).unwrap();
    let expected = Vec3::new(0.5, 0.5, 0.0);
    assert!(
        (Vec3::from(deformed.positions[0]) - expected).length() < 1e-6,
        "got {:?}",
        deformed.positions[0]
    );
}

#[test]
fn a_parent_rotation_transforms_the_child_bind_transform_once() {
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(1.0, 0.0, 0.0), Quat::IDENTITY),
    ]);
    let mut pose = Pose::reference(&skeleton);
    pose.set_rotation(0, Quat::from_rotation_z(std::f32::consts::FRAC_PI_2))
        .unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    // The child's bind transform is T(1,0,0); at the pose it is Rz90*T(1,0,0).
    // S = Rz90, so a vertex at (2,0,0) rotates to (0,2,0).
    assert!(
        (matrices.matrices()[1].transform_point3(Vec3::new(2.0, 0.0, 0.0))
            - Vec3::new(0.0, 2.0, 0.0))
        .length()
            < 1e-6
    );
    let primitive = primitive(vec![vertex([2.0, 0.0, 0.0], [1.0, 0.0, 0.0])]);
    let influences = influences(vec![vec![(1, 1.0)]]);
    let deformed = deform_primitive(&primitive, &influences, &matrices).unwrap();
    assert!((Vec3::from(deformed.positions[0]) - Vec3::new(0.0, 2.0, 0.0)).length() < 1e-6);
    assert!((Vec3::from(deformed.normals[0]) - Vec3::new(0.0, 1.0, 0.0)).length() < 1e-6);
}

#[test]
fn tangents_keep_their_handedness_when_the_basis_rotates() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let mut pose = Pose::reference(&skeleton);
    pose.set_rotation(0, Quat::from_rotation_z(std::f32::consts::FRAC_PI_2))
        .unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    let mut source = vertex([1.0, 0.0, 0.0], [0.0, 0.0, 1.0]);
    source.tangent = Some([1.0, 0.0, 0.0, -1.0]);
    let deformed = deform_primitive(
        &primitive(vec![source]),
        &influences(vec![vec![(0, 1.0)]]),
        &matrices,
    )
    .unwrap();
    let tangent = deformed.tangents.unwrap()[0];
    assert!(
        (Vec3::new(tangent[0], tangent[1], tangent[2]) - Vec3::new(0.0, 1.0, 0.0)).length() < 1e-6
    );
    assert_eq!(tangent[3], -1.0);
}

#[test]
fn deformed_bounds_cover_every_deformed_vertex() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let mut pose = Pose::reference(&skeleton);
    pose.set_translation(0, Vec3::new(1.0, 2.0, 3.0)).unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    let primitive = primitive(vec![
        vertex([0.0, 0.0, 0.0], [0.0, 0.0, 1.0]),
        vertex([1.0, 1.0, 1.0], [0.0, 0.0, 1.0]),
    ]);
    let influences = influences(vec![vec![(0, 1.0)], vec![(0, 1.0)]]);
    let bounds = deformed_bounds(&primitive, &influences, &matrices).unwrap();
    assert_eq!(
        bounds,
        Aabb {
            min: Vec3::new(1.0, 2.0, 3.0),
            max: Vec3::new(2.0, 3.0, 4.0)
        }
    );
}

#[test]
fn evaluating_the_same_pose_twice_never_compounds() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let mut pose = Pose::reference(&skeleton);
    pose.set_translation(0, Vec3::new(1.0, 0.0, 0.0)).unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    let primitive = primitive(vec![vertex([1.0, 0.0, 0.0], [0.0, 0.0, 1.0])]);
    let influences = influences(vec![vec![(0, 1.0)]]);
    let first = deform_primitive(&primitive, &influences, &matrices).unwrap();
    let second = deform_primitive(&primitive, &influences, &matrices).unwrap();
    assert_eq!(first.positions, second.positions);
    assert_eq!(first.positions[0], [2.0, 0.0, 0.0]);
}

#[test]
fn resetting_the_pose_reproduces_the_authored_vertices() {
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(1.0, 0.0, 0.0), Quat::IDENTITY),
    ]);
    let primitive = primitive(vec![vertex([2.0, 0.5, 0.0], [0.0, 0.0, 1.0])]);
    let influences = influences(vec![vec![(1, 1.0)]]);
    let authored = deform_primitive(
        &primitive,
        &influences,
        &SkinningMatrices::build(&skeleton, &Pose::reference(&skeleton)).unwrap(),
    )
    .unwrap();
    assert_eq!(authored.positions[0], [2.0, 0.5, 0.0]);

    let mut pose = Pose::reference(&skeleton);
    pose.set_rotation(0, Quat::from_rotation_z(0.7)).unwrap();
    let deformed = deform_primitive(
        &primitive,
        &influences,
        &SkinningMatrices::build(&skeleton, &pose).unwrap(),
    )
    .unwrap();
    assert_ne!(deformed.positions[0], authored.positions[0]);
    pose.reset();
    let reset = deform_primitive(
        &primitive,
        &influences,
        &SkinningMatrices::build(&skeleton, &pose).unwrap(),
    )
    .unwrap();
    assert_eq!(reset.positions, authored.positions);
}

#[test]
fn a_missing_stored_inverse_bind_is_derived_and_counted() {
    let mut skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(1.0, 0.0, 0.0), Quat::IDENTITY),
    ]);
    skeleton.bones[0].inverse_bind = None;
    let matrices = SkinningMatrices::build(&skeleton, &Pose::reference(&skeleton)).unwrap();
    assert_eq!(matrices.stored(), 1);
    assert_eq!(matrices.derived(), 1);
    let delta = matrices.matrices()[0]
        .to_cols_array()
        .iter()
        .zip(Mat4::IDENTITY.to_cols_array().iter())
        .map(|(a, b)| (a - b).abs())
        .fold(0.0f32, f32::max);
    assert!(delta < 1e-6);
}

#[test]
fn an_unsupported_influence_set_is_reported_not_deformed() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let matrices = SkinningMatrices::build(&skeleton, &Pose::reference(&skeleton)).unwrap();
    let primitive = primitive(vec![vertex([0.0; 3], [0.0, 0.0, 1.0])]);
    let mut influences = influences(vec![vec![(0, 1.0)]]);
    influences.status = InfluenceStatus::Unsupported {
        reason: "no index stream".into(),
    };
    assert!(matches!(
        deform_primitive(&primitive, &influences, &matrices),
        Err(super::DeformError::UnsupportedInfluences(_))
    ));
}

#[test]
fn an_active_bone_outside_the_skeleton_is_rejected() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let matrices = SkinningMatrices::build(&skeleton, &Pose::reference(&skeleton)).unwrap();
    let primitive = primitive(vec![vertex([0.0; 3], [0.0, 0.0, 1.0])]);
    let influences = influences(vec![vec![(3, 1.0)]]);
    assert!(matches!(
        deform_primitive(&primitive, &influences, &matrices),
        Err(super::DeformError::InvalidBone { bone: 3, .. })
    ));
}

#[test]
fn a_count_mismatch_is_rejected() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let matrices = SkinningMatrices::build(&skeleton, &Pose::reference(&skeleton)).unwrap();
    let primitive = primitive(vec![
        vertex([0.0; 3], [0.0, 0.0, 1.0]),
        vertex([1.0; 3], [0.0, 0.0, 1.0]),
    ]);
    let influences = influences(vec![vec![(0, 1.0)]]);
    assert!(matches!(
        deform_primitive(&primitive, &influences, &matrices),
        Err(super::DeformError::CountMismatch { .. })
    ));
}

#[test]
fn a_non_identity_scale_is_reported_by_the_matrix_builder() {
    let mut skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    skeleton.bones[0].local_scale = Vec3::splat(2.0);
    assert!(matches!(
        SkinningMatrices::build(&skeleton, &Pose::reference(&skeleton)),
        Err(PoseError::UnsupportedScale { .. })
    ));
}

#[test]
fn the_influenced_centroid_uses_only_the_named_bone() {
    let primitive = primitive(vec![
        vertex([0.0, 0.0, 0.0], [0.0, 0.0, 1.0]),
        vertex([2.0, 0.0, 0.0], [0.0, 0.0, 1.0]),
    ]);
    let influences = influences(vec![vec![(0, 1.0)], vec![(1, 1.0)]]);
    assert_eq!(
        influenced_centroid(&primitive, &influences, 0),
        Some(Vec3::ZERO)
    );
    assert_eq!(
        influenced_centroid(&primitive, &influences, 1),
        Some(Vec3::new(2.0, 0.0, 0.0))
    );
    assert_eq!(influenced_centroid(&primitive, &influences, 2), None);
}

/// Keeps the unused helper honest: a bone built directly still validates.
#[test]
fn a_directly_built_bone_has_a_valid_inverse_bind() {
    let bone = bone(0, None, Vec3::new(1.0, 2.0, 3.0), Quat::IDENTITY, Vec3::ONE);
    let matrix = bone.inverse_bind.unwrap();
    assert!((matrix.transform_point3(Vec3::new(1.0, 2.0, 3.0)) - Vec3::ZERO).length() < 1e-6);
}

/// A pose that moves geometry far outside its authored bounds must frame the
/// posed geometry, and the authored bounds must stay unchanged.
#[test]
fn posed_bounds_follow_a_pose_that_leaves_the_authored_bounds() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let mut primitive = primitive(vec![vertex([0.0, 1.0, 0.0], [0.0, 1.0, 0.0])]);
    primitive.indices = vec![0, 0, 0];
    let influences = influences(vec![vec![(0, 1.0)]]);
    let authored = Aabb::from_points([Vec3::new(0.0, 1.0, 0.0)]);

    let mut pose = Pose::new(1);
    // 180 degrees about the bone's own X axis sends the vertex to -Y.
    pose.set_rotation(0, Quat::from_rotation_x(std::f32::consts::PI))
        .unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();
    let deformed = deform_primitive(&primitive, &influences, &matrices).unwrap();
    let bounds = deformed_bounds(&primitive, &influences, &matrices)
        .unwrap()
        .sanitized();
    assert!(
        (Vec3::from(deformed.positions[0]) - Vec3::new(0.0, -1.0, 0.0)).length() < 1e-5,
        "{:?}",
        deformed.positions[0]
    );
    assert!(bounds.min.y <= -1.0 + 1e-4 && bounds.max.y >= -1.0 - 1e-4);
    // The authored bounds hold the original vertex and not the deformed one.
    let inside = |point: Vec3| point.cmpge(authored.min).all() && point.cmple(authored.max).all();
    assert!(inside(Vec3::new(0.0, 1.0, 0.0)));
    assert!(!inside(Vec3::new(0.0, -1.0, 0.0)));

    let mut scene = crate::Scene::new();
    let mut mesh = crate::Mesh::new("posed");
    mesh.primitives.push(primitive);
    scene.meshes.push(mesh);
    scene.materials.push(crate::Material::default());
    scene.skeleton = Some(skeleton);
    scene.associations.push(crate::PrimitiveBones {
        mesh: 0,
        primitive: 0,
        bones: vec![0],
        weighted: false,
        declared_bone_count: Some(1),
    });
    scene.influences.push(crate::PrimitiveInfluences {
        mesh: 0,
        primitive: 0,
        influences,
    });
    scene.recompute_bounds();
    let posed = scene
        .posed_bounds(&pose)
        .expect("posed bounds")
        .expect("a posed box");
    assert!(posed.min.y < 0.0, "{posed:?}");
    assert!(scene.bounds.max.y >= 1.0, "{:?}", scene.bounds);
}

/// The default policy deforms decoded associations and leaves inferred ones on
/// the authored path, and the opt-in changes exactly that.
#[test]
fn the_default_policy_excludes_inferred_associations_and_the_opt_in_includes_them() {
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(0.0, 1.0, 0.0), Quat::IDENTITY),
    ]);
    let primitive = primitive(vec![
        vertex([0.0, 0.0, 0.0], [0.0, 0.0, 1.0]),
        vertex([0.5, 0.0, 0.0], [0.0, 0.0, 1.0]),
    ]);
    let mut pose = Pose::new(2);
    pose.set_rotation(1, Quat::from_rotation_z(std::f32::consts::FRAC_PI_2))
        .unwrap();
    let matrices = SkinningMatrices::build(&skeleton, &pose).unwrap();

    // Explicit: bone 1 only, weight 1.
    let explicit = influences(vec![vec![(1, 1.0)], vec![(1, 1.0)]]);
    let deformed = deform_primitive(&primitive, &explicit, &matrices).unwrap();
    // S = T(0,1,0) * Rz(90) * T(0,-1,0) sends the origin to (1, 1, 0).
    assert!(
        (Vec3::from(deformed.positions[0]) - Vec3::new(1.0, 1.0, 0.0)).length() < 1e-5,
        "{:?}",
        deformed.positions[0]
    );

    // The same data marked inferred is refused by the default policy and
    // accepted by the opt-in, with identical numbers.
    let mut inferred = explicit.clone();
    inferred.inferred = true;
    assert_eq!(
        deform_primitive(&primitive, &inferred, &matrices),
        Err(crate::DeformError::InferredExcluded)
    );
    assert_eq!(
        deformed_bounds(&primitive, &inferred, &matrices),
        Err(crate::DeformError::InferredExcluded)
    );
    let allowed = deform_primitive_with(
        &primitive,
        &inferred,
        &matrices,
        crate::DeformationPolicy::WITH_INFERRED,
    )
    .unwrap();
    assert_eq!(allowed.positions, deformed.positions);

    // An unsupported set is refused under either policy, and the reason says so.
    let mut unsupported = explicit.clone();
    unsupported.status = InfluenceStatus::Unsupported {
        reason: "declared form is not supported".into(),
    };
    assert!(matches!(
        deform_primitive_with(
            &primitive,
            &unsupported,
            &matrices,
            crate::DeformationPolicy::WITH_INFERRED,
        ),
        Err(crate::DeformError::UnsupportedInfluences(_))
    ));
}

/// The scene counts and the posed bounds follow the policy.
#[test]
fn the_scene_counts_and_bounds_follow_the_policy() {
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let mut primitive = primitive(vec![vertex([0.0, 1.0, 0.0], [0.0, 1.0, 0.0])]);
    primitive.indices = vec![0, 0, 0];
    let mut inferred = influences(vec![vec![(0, 1.0)]]);
    inferred.inferred = true;
    let mut explicit = influences(vec![vec![(0, 1.0)]]);
    explicit.inferred = false;

    let mut scene = crate::Scene::new();
    let mut mesh = crate::Mesh::new("mixed");
    mesh.primitives.push(primitive.clone());
    mesh.primitives.push(primitive);
    scene.meshes.push(mesh);
    scene.materials.push(crate::Material::default());
    scene.skeleton = Some(skeleton);
    scene.influences.push(crate::PrimitiveInfluences {
        mesh: 0,
        primitive: 0,
        influences: explicit,
    });
    scene.influences.push(crate::PrimitiveInfluences {
        mesh: 0,
        primitive: 1,
        influences: inferred,
    });
    scene.recompute_bounds();

    assert_eq!(scene.deformable_primitive_count(), 1);
    assert_eq!(
        scene.deformable_primitive_count_under(crate::DeformationPolicy::WITH_INFERRED),
        2
    );
    assert_eq!(scene.inferred_primitive_count(), 1);

    let mut pose = Pose::new(1);
    pose.set_rotation(0, Quat::from_rotation_x(std::f32::consts::PI))
        .unwrap();
    let explicit_bounds = scene.posed_bounds(&pose).expect("bounds").expect("a box");
    let all_bounds = scene
        .posed_bounds_under(&pose, crate::DeformationPolicy::WITH_INFERRED)
        .expect("bounds")
        .expect("a box");
    // One primitive deforms under the default policy and both under the opt-in,
    // and the union of two identical deformations is the same box.
    assert!((explicit_bounds.min.y + 1.0).abs() < 1e-4);
    assert!((all_bounds.min.y + 1.0).abs() < 1e-4);
}
