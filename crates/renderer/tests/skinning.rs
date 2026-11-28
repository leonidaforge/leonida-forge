//! GPU skinning tests. Each test compares the shader's deformed values with
//! the CPU reference or checks that an ordinary render changes only when the
//! pose changes.

use glam::{Quat, Vec3};
use lforge_renderer::{Background, OrbitCamera, Renderer, SkinProbeVertex};
use lforge_scene::{
    Bone, InfluenceStatus, Material, Mesh, Pose, Primitive, Scene, Skeleton, SkinningMatrices,
    Vertex, VertexInfluence, VertexInfluences, deform_primitive,
};

fn renderer() -> Option<Renderer> {
    match Renderer::new() {
        Ok(renderer) => {
            let info = renderer.adapter_info();
            eprintln!(
                "adapter: {} ({:?}, {:?})",
                info.name, info.backend, info.device_type
            );
            Some(renderer)
        }
        Err(err) => {
            eprintln!("SKIP: no GPU adapter: {err}");
            None
        }
    }
}

fn bone(index: usize, parent: Option<usize>, translation: Vec3, rotation: Quat) -> Bone {
    Bone {
        name: Some(format!("bone_{index}")),
        index,
        parent,
        identifier: Some(index as u32 + 1),
        identifier16: Some(index as u16 + 1),
        local_translation: translation,
        local_rotation: rotation,
        local_scale: Vec3::ONE,
        model_rotation: rotation,
        model_position: translation,
        inverse_bind: None,
    }
}

/// A skeleton whose model-space values are composed and whose stored
/// inverse-bind records are the exact inverses, as the decoder validates.
fn skeleton_of(entries: Vec<(Option<usize>, Vec3, Quat)>) -> Skeleton {
    let mut bones: Vec<Bone> = Vec::new();
    for (index, (parent, translation, rotation)) in entries.into_iter().enumerate() {
        let (model_rotation, model_position) = match parent {
            Some(parent) => (
                bones[parent].model_rotation * rotation,
                bones[parent].model_position + bones[parent].model_rotation * translation,
            ),
            None => (rotation, translation),
        };
        let mut bone = bone(index, parent, translation, rotation);
        bone.model_rotation = model_rotation;
        bone.model_position = model_position;
        bone.inverse_bind =
            Some(glam::Mat4::from_rotation_translation(model_rotation, model_position).inverse());
        bones.push(bone);
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

fn vertex(position: [f32; 3], normal: [f32; 3], tangent: Option<[f32; 4]>) -> Vertex {
    Vertex {
        position,
        normal,
        tangent,
        uv0: [0.0; 2],
        uv1: None,
        color: [1.0; 4],
    }
}

fn influences(per_vertex: Vec<Vec<(u16, f32)>>) -> VertexInfluences {
    let mut bones = std::collections::BTreeSet::new();
    let mut max_influences = 0u8;
    let mut weighted = false;
    let per_vertex = per_vertex
        .into_iter()
        .map(|lanes| {
            max_influences = max_influences.max(lanes.len() as u8);
            weighted |= lanes.len() > 1;
            let mut out = [VertexInfluence::NONE; 4];
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
        resolution: lforge_scene::BoneResolution::DirectSkeleton,
        status: InfluenceStatus::Complete,
        inferred: false,
    }
}

fn scene_with(skeleton: Skeleton, primitive: Primitive, influences: VertexInfluences) -> Scene {
    let mut scene = Scene::new();
    scene.materials.push(Material {
        name: "test".into(),
        base_color: [0.8, 0.2, 0.2, 1.0],
        ..Material::default()
    });
    let mut mesh = Mesh::new("skinned");
    mesh.primitives.push(primitive);
    scene.meshes.push(mesh);
    scene.skeleton = Some(skeleton);
    scene.influences.push(lforge_scene::PrimitiveInfluences {
        mesh: 0,
        primitive: 0,
        influences,
    });
    scene.recompute_bounds();
    scene
}

fn probe_vertices(primitive: &Primitive, influences: &VertexInfluences) -> Vec<SkinProbeVertex> {
    primitive
        .vertices
        .iter()
        .zip(&influences.per_vertex)
        .map(|(vertex, lanes)| {
            let mut joints = [0u32; 4];
            let mut weights = [0.0f32; 4];
            for (lane, influence) in lanes.iter().enumerate() {
                joints[lane] = u32::from(influence.bone);
                weights[lane] = influence.weight;
            }
            SkinProbeVertex {
                position: vertex.position,
                normal: vertex.normal,
                tangent: vertex.tangent.unwrap_or([0.0, 0.0, 0.0, 1.0]),
                joints,
                weights,
                mode: 0,
            }
        })
        .collect()
}

/// Pixels whose channels differ at all.
fn differing_pixels(a: &[u8], b: &[u8]) -> usize {
    a.chunks(4).zip(b.chunks(4)).filter(|(a, b)| a != b).count()
}

/// The largest single-channel difference.
fn channel_delta(a: &[u8], b: &[u8]) -> u8 {
    a.iter()
        .zip(b)
        .map(|(a, b)| a.abs_diff(*b))
        .max()
        .unwrap_or(0)
}

fn max_error(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b)
        .map(|(a, b)| (a - b).abs())
        .fold(0.0, f32::max)
}

/// Compares the CPU reference with the GPU for one scene and pose.
fn compare(renderer: &Renderer, scene: &Scene, pose: &Pose, label: &str) {
    let skeleton = scene.skeleton.as_ref().unwrap();
    let matrices = SkinningMatrices::build(skeleton, pose).unwrap();
    let entry = &scene.influences[0];
    let primitive = &scene.meshes[entry.mesh].primitives[entry.primitive];
    let cpu = deform_primitive(primitive, &entry.influences, &matrices).unwrap();
    let probe = renderer
        .probe_skinning(
            matrices.matrices(),
            &probe_vertices(primitive, &entry.influences),
        )
        .expect("probe");
    assert_eq!(probe.len(), primitive.vertices.len());
    let mut worst_position = 0.0f32;
    let mut worst_normal = 0.0f32;
    let mut worst_tangent = 0.0f32;
    for (index, sample) in probe.iter().enumerate() {
        worst_position = worst_position.max(max_error(&cpu.positions[index], &sample.position));
        worst_normal = worst_normal.max(max_error(&cpu.normals[index], &sample.normal));
        if let Some(tangents) = &cpu.tangents
            && primitive.vertices[index].tangent.is_some()
        {
            worst_tangent = worst_tangent.max(max_error(&tangents[index], &sample.tangent));
        }
    }
    eprintln!(
        "{label}: {count} vertices, max position error {worst_position:e}, normal {worst_normal:e}, tangent {worst_tangent:e}",
        count = primitive.vertices.len()
    );
    assert!(
        worst_position < 1e-4,
        "{label}: position error {worst_position}"
    );
    assert!(worst_normal < 1e-4, "{label}: normal error {worst_normal}");
    assert!(
        worst_tangent < 1e-4,
        "{label}: tangent error {worst_tangent}"
    );
}

#[test]
fn gpu_matches_the_cpu_reference_at_the_reference_pose() {
    let Some(renderer) = renderer() else {
        return;
    };
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(0.0, 1.0, 0.0), Quat::IDENTITY),
    ]);
    let primitive = Primitive {
        material: 0,
        vertices: vec![
            vertex([0.2, 1.0, 0.0], [0.0, 0.0, 1.0], Some([1.0, 0.0, 0.0, 1.0])),
            vertex(
                [0.5, 1.5, 0.1],
                [0.0, 1.0, 0.0],
                Some([1.0, 0.0, 0.0, -1.0]),
            ),
        ],
        indices: vec![0, 1, 0],
    };
    let influences = influences(vec![vec![(0, 1.0)], vec![(1, 1.0)]]);
    let scene = scene_with(skeleton, primitive, influences);
    compare(
        &renderer,
        &scene,
        &Pose::reference(scene.skeleton.as_ref().unwrap()),
        "reference pose",
    );
}

#[test]
fn gpu_matches_the_cpu_for_rigid_weighted_and_hierarchical_poses() {
    let Some(renderer) = renderer() else {
        return;
    };
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(0.0, 1.0, 0.0), Quat::IDENTITY),
        (None, Vec3::new(2.0, 0.0, 0.0), Quat::IDENTITY),
    ]);
    let primitive = Primitive {
        material: 0,
        vertices: vec![
            vertex([0.2, 1.0, 0.0], [0.0, 0.0, 1.0], None),
            vertex([0.5, 1.5, 0.1], [0.0, 1.0, 0.0], None),
            vertex([2.4, 0.2, 0.0], [1.0, 0.0, 0.0], None),
        ],
        indices: vec![0, 1, 2],
    };
    let influences = influences(vec![
        vec![(0, 0.5), (1, 0.5)],
        vec![(1, 1.0)],
        vec![(2, 1.0)],
    ]);
    let scene = scene_with(skeleton, primitive, influences);
    let skeleton = scene.skeleton.as_ref().unwrap();

    let mut pose = Pose::reference(skeleton);
    pose.set_rotation(0, Quat::from_rotation_z(std::f32::consts::FRAC_PI_2))
        .unwrap();
    compare(&renderer, &scene, &pose, "parent rotation");

    let mut pose = Pose::reference(skeleton);
    pose.set_translation(1, Vec3::new(0.3, -0.2, 0.4)).unwrap();
    pose.set_rotation(1, Quat::from_rotation_x(0.6)).unwrap();
    compare(&renderer, &scene, &pose, "child rotation and translation");

    let mut pose = Pose::reference(skeleton);
    pose.set_rotation(2, Quat::from_rotation_y(-0.9)).unwrap();
    pose.set_rotation(0, Quat::from_rotation_z(0.4)).unwrap();
    compare(&renderer, &scene, &pose, "two independent roots");
}

/// A primitive with no tangent attribute renders the same through the skinned
/// pipeline and through the static pipeline over CPU-deformed vertices.
///
/// The skinned vertex shader normalised the skinned tangent, and a zero vector
/// normalises to NaN, so every vertex without a tangent lost its normal-mapped
/// lighting. This test pins the fallback: a collapsed direction falls back to the
/// authored direction, exactly as the CPU reference does.
#[test]
fn a_primitive_without_tangents_skins_like_the_cpu_reference() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (Some(0), Vec3::new(0.0, 1.0, 0.0), Quat::IDENTITY),
    ]);
    let primitive = Primitive {
        material: 0,
        vertices: vec![
            vertex([-0.6, 0.0, 0.0], [0.0, 0.0, 1.0], None),
            vertex([0.6, 0.0, 0.0], [0.0, 0.0, 1.0], None),
            vertex([0.0, 2.0, 0.0], [0.0, 0.0, 1.0], None),
        ],
        indices: vec![0, 1, 2],
    };
    let influences = influences(vec![vec![(1, 1.0)], vec![(1, 1.0)], vec![(0, 1.0)]]);
    let scene = scene_with(skeleton, primitive, influences);
    let skeleton = scene.skeleton.as_ref().unwrap();
    let mut pose = Pose::reference(skeleton);
    pose.set_rotation(0, Quat::from_rotation_z(0.6)).unwrap();
    let matrices = SkinningMatrices::build(skeleton, &pose).unwrap();
    let positions: Vec<Vec3> = pose
        .globals(skeleton)
        .unwrap()
        .iter()
        .map(|bone| bone.model_position)
        .collect();

    let mut cpu_scene = scene.clone();
    let deformed = deform_primitive(
        &cpu_scene.meshes[0].primitives[0],
        &cpu_scene.influences[0].influences,
        &matrices,
    )
    .unwrap();
    for (index, vertex) in cpu_scene.meshes[0].primitives[0]
        .vertices
        .iter_mut()
        .enumerate()
    {
        vertex.position = deformed.positions[index];
        vertex.normal = deformed.normals[index];
    }
    cpu_scene.recompute_bounds();
    let camera = OrbitCamera::framing(cpu_scene.bounds, 1.0);
    let cpu = renderer.upload_scene(&cpu_scene).expect("cpu upload");
    let cpu_frame = renderer
        .render(&cpu, &camera, 256, 256, Background::DARK)
        .expect("cpu render");

    let mut gpu = renderer.upload_scene(&scene).expect("gpu upload");
    renderer
        .update_pose(&mut gpu, matrices.matrices(), &positions)
        .expect("pose upload");
    gpu.set_pose_active(true);
    let gpu_frame = renderer
        .render(&gpu, &camera, 256, 256, Background::DARK)
        .expect("skinned render");
    let differing = differing_pixels(&cpu_frame.pixels, &gpu_frame.pixels);
    let delta = channel_delta(&cpu_frame.pixels, &gpu_frame.pixels);
    eprintln!("tangent-free skinned frame: {differing} differing pixels, channel delta {delta}");
    assert!(
        differing <= 8 && delta <= 4,
        "the skinned frame differs from the CPU reference: {differing} pixels, channel {delta}"
    );
}

#[test]
fn gpu_handles_a_596_bone_palette() {
    let Some(renderer) = renderer() else {
        return;
    };
    let count = 596usize;
    let entries = (0..count)
        .map(|index| {
            (
                if index > 0 { Some(index - 1) } else { None },
                Vec3::new(0.01, 0.0, 0.0),
                Quat::IDENTITY,
            )
        })
        .collect();
    let mut skeleton = skeleton_of(entries);
    // A single root keeps the chain short enough for the test's purpose: the
    // last bone must still receive its own matrix.
    skeleton.bones[0].parent = None;
    skeleton.bones[0].local_translation = Vec3::ZERO;
    skeleton.bones[0].model_position = Vec3::ZERO;
    skeleton.bones[0].inverse_bind = Some(glam::Mat4::IDENTITY);
    let last = (count - 1) as u16;
    let primitive = Primitive {
        material: 0,
        vertices: vec![vertex([0.1, 0.0, 0.0], [0.0, 0.0, 1.0], None)],
        indices: vec![0, 0, 0],
    };
    let influences = influences(vec![vec![(last, 1.0)]]);
    let scene = scene_with(skeleton, primitive, influences);
    let mut pose = Pose::reference(scene.skeleton.as_ref().unwrap());
    pose.set_translation(usize::from(last), Vec3::new(0.0, 0.5, 0.0))
        .unwrap();
    compare(&renderer, &scene, &pose, "596-bone palette");
}

#[test]
fn the_renderer_uploads_pose_state_without_touching_the_authored_buffer() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let skeleton = skeleton_of(vec![(None, Vec3::ZERO, Quat::IDENTITY)]);
    let primitive = Primitive {
        material: 0,
        vertices: vec![
            vertex([-0.5, -0.5, 0.0], [0.0, 0.0, 1.0], None),
            vertex([0.5, -0.5, 0.0], [0.0, 0.0, 1.0], None),
            vertex([0.0, 0.5, 0.0], [0.0, 0.0, 1.0], None),
        ],
        indices: vec![0, 1, 2],
    };
    let influences = influences(vec![vec![(0, 1.0)], vec![(0, 1.0)], vec![(0, 1.0)]]);
    let scene = scene_with(skeleton, primitive, influences);
    let mut gpu = renderer.upload_scene(&scene).expect("upload");
    assert!(gpu.has_skin());
    assert!(!gpu.pose_active());
    let camera = OrbitCamera::framing(scene.bounds, 1.0);
    let authored = renderer
        .render(&gpu, &camera, 160, 120, Background::DARK)
        .expect("authored render");
    gpu.set_pose_active(true);
    let identity = vec![glam::Mat4::IDENTITY; gpu.joint_count()];
    renderer
        .update_pose(&mut gpu, &identity, &[])
        .expect("reference pose");
    let reference = renderer
        .render(&gpu, &camera, 160, 120, Background::DARK)
        .expect("skinned reference render");
    // The skinned reference pose and the authored path shade the same geometry
    // through different shaders, so a last-bit difference is expected; the
    // picture itself must not change.
    assert!(
        differing_pixels(&authored.pixels, &reference.pixels) < 64
            && channel_delta(&authored.pixels, &reference.pixels) <= 2,
        "the skinned reference pose changed {} pixels (max channel delta {})",
        differing_pixels(&authored.pixels, &reference.pixels),
        channel_delta(&authored.pixels, &reference.pixels)
    );
    let matrices = SkinningMatrices::build(scene.skeleton.as_ref().unwrap(), &{
        let mut pose = Pose::reference(scene.skeleton.as_ref().unwrap());
        pose.set_translation(0, Vec3::new(0.0, 0.3, 0.0)).unwrap();
        pose
    })
    .unwrap();
    renderer
        .update_pose(&mut gpu, matrices.matrices(), &[])
        .expect("pose update");
    let posed = renderer
        .render(&gpu, &camera, 160, 120, Background::DARK)
        .expect("posed render");
    let differing = differing_pixels(&authored.pixels, &posed.pixels);
    assert!(differing > 100, "the pose changed {differing} pixels");
    // Resetting the pose reproduces the authored image.
    let identity = vec![glam::Mat4::IDENTITY; gpu.joint_count()];
    renderer
        .update_pose(&mut gpu, &identity, &[])
        .expect("reset");
    let reset = renderer
        .render(&gpu, &camera, 160, 120, Background::DARK)
        .expect("reset render");
    assert!(
        differing_pixels(&authored.pixels, &reset.pixels) < 64
            && channel_delta(&authored.pixels, &reset.pixels) <= 2
    );
}

#[test]
fn the_influence_view_colours_only_influenced_geometry() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let skeleton = skeleton_of(vec![
        (None, Vec3::ZERO, Quat::IDENTITY),
        (None, Vec3::new(1.0, 0.0, 0.0), Quat::IDENTITY),
    ]);
    let primitive = Primitive {
        material: 0,
        vertices: vec![
            vertex([-0.5, -0.5, 0.0], [0.0, 0.0, 1.0], None),
            vertex([0.5, -0.5, 0.0], [0.0, 0.0, 1.0], None),
            vertex([0.0, 0.5, 0.0], [0.0, 0.0, 1.0], None),
        ],
        indices: vec![0, 1, 2],
    };
    let influences = influences(vec![vec![(0, 1.0)], vec![(0, 1.0)], vec![(0, 1.0)]]);
    let scene = scene_with(skeleton, primitive, influences);
    let mut gpu = renderer.upload_scene(&scene).expect("upload");
    gpu.set_pose_active(true);
    gpu.set_highlight_bone(Some(0));
    let camera = OrbitCamera::framing(scene.bounds, 1.0);
    gpu.set_influence_view(false);
    let shaded = renderer
        .render(&gpu, &camera, 160, 120, Background::DARK)
        .expect("shaded");
    gpu.set_influence_view(true);
    let influence = renderer
        .render(&gpu, &camera, 160, 120, Background::DARK)
        .expect("influence");
    let differing = differing_pixels(&shaded.pixels, &influence.pixels);
    assert!(differing > 100, "the view changed {differing} pixels");
    // Selecting a bone no vertex references leaves the neutral colour, which
    // still differs from the shaded render.
    gpu.set_highlight_bone(Some(1));
    let unused = renderer
        .render(&gpu, &camera, 160, 120, Background::DARK)
        .expect("unused bone");
    assert_ne!(influence.pixels, unused.pixels);
}
