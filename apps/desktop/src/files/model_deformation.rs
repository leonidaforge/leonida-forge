//! Focused measurement of the deformation path on real resources.
//!
//! One ignored test drives every verification case from a list file, so the
//! numbers in the acceptance report come from the same code the application
//! runs: the loader, `lforge-scene`'s pose and CPU deformation, and the
//! renderer's skinned pipelines.
//!
//! The list file holds one case per line:
//!
//! ```text
//! <selector> [member=<index>] [bone=<index|name>] [axis=x|y|z] [degrees=<f>]
//!            [move=x,y,z] [label=<text>]
//! ```
//!
//! `LF_TEST_GAME_ROOT` and `LF_TEST_EXECUTABLE` name the installation.
//! `LF_DEFORM_CASES` names the list file. `LF_DEFORM_OUT` writes the preview
//! PNG files; without it no image is written.
//!
//! Nothing here is called by the application.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use glam::{Quat, Vec3};
use lforge_renderer::{Background, GpuScene, OrbitCamera, Overlay, Renderer, SkinProbeVertex};
use lforge_scene::{Pose, Scene, SkinningMatrices};

use super::*;
use crate::files::Executable;

/// One requested verification case.
#[derive(Debug, Clone)]
struct Case {
    selector: String,
    member: Option<usize>,
    bone: Option<String>,
    axis: usize,
    degrees: f32,
    translation: Vec3,
    label: String,
    /// Whether inferred single-bone associations take part.
    include_inferred: bool,
}

fn cases(path: &Path) -> Vec<Case> {
    std::fs::read_to_string(path)
        .expect("case list")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let selector = parts.next()?.to_string();
            let mut case = Case {
                selector,
                member: None,
                bone: None,
                axis: 2,
                degrees: 30.0,
                translation: Vec3::ZERO,
                label: String::new(),
                include_inferred: false,
            };
            for part in parts {
                let (key, value) = part.split_once('=')?;
                match key {
                    "member" => case.member = value.parse().ok(),
                    "bone" => case.bone = Some(value.to_string()),
                    "axis" => {
                        case.axis = match value {
                            "x" => 0,
                            "y" => 1,
                            _ => 2,
                        }
                    }
                    "degrees" => case.degrees = value.parse().ok()?,
                    "move" => {
                        let values: Vec<f32> =
                            value.split(',').filter_map(|v| v.parse().ok()).collect();
                        if values.len() == 3 {
                            case.translation = Vec3::from_slice(&values);
                        }
                    }
                    "label" => case.label = value.replace('_', " "),
                    "inferred" => case.include_inferred = value == "1" || value == "true",
                    _ => {}
                }
            }
            Some(case)
        })
        .collect()
}

/// One loaded case: the scene and the verdicts the loader attached to it.
struct Loaded {
    scene: Scene,
    name: String,
    verdicts: String,
}

fn load(case: &Case, root: &Path, access: &Access, cancel: &AtomicBool) -> Option<Loaded> {
    match case.member {
        Some(index) => {
            let (parent_chain, row) = case.selector.rsplit_once('!')?;
            let row = row.parse::<usize>().ok()?;
            let mut resolved = std::collections::BTreeMap::new();
            let mut index_map = std::collections::HashMap::new();
            let parent = super::tests::resolve_chain(
                root,
                access,
                parent_chain,
                &mut resolved,
                &mut index_map,
            )?;
            if !index_map.contains_key(&parent) {
                index_map.insert(parent.clone(), super::tests::row_index(&parent, access));
            }
            let entry = index_map
                .get(&parent)
                .and_then(|rows| rows.get(&row))
                .cloned()?;
            let loaded = load_dictionary_member(&entry, access, Some(root), index, cancel).ok()?;
            Some(Loaded {
                scene: loaded.scene,
                name: loaded.name,
                verdicts: format!("{:?}", loaded.completeness),
            })
        }
        None => {
            let loaded = super::tests::load_chain(root, access, &case.selector, cancel)?;
            Some(Loaded {
                scene: loaded.scene,
                name: loaded.name,
                verdicts: format!("{:?}", loaded.completeness),
            })
        }
    }
}

/// The bone indices whose model transform differs from the reference pose. A
/// bone rotated about its own origin keeps its position, so the rotation is
/// compared too.
fn moved_bones(reference: &[(glam::Vec3, Quat)], posed: &[(glam::Vec3, Quat)]) -> Vec<usize> {
    reference
        .iter()
        .zip(posed)
        .enumerate()
        .filter(
            |(_, ((position, rotation), (other_position, other_rotation)))| {
                (*position - *other_position).length() > 1e-6
                    || rotation.dot(*other_rotation).abs() < 1.0 - 1e-6
            },
        )
        .map(|(index, _)| index)
        .collect()
}

/// The posed bone's subtree, as a sorted list, using the decoded parents.
fn subtree(parents: &[Option<usize>], bone: usize) -> Vec<usize> {
    let mut out = vec![bone];
    let mut cursor = 0;
    while cursor < out.len() {
        let current = out[cursor];
        cursor += 1;
        for (index, parent) in parents.iter().enumerate() {
            if *parent == Some(current) && !out.contains(&index) {
                out.push(index);
            }
        }
    }
    out.sort_unstable();
    out
}

fn probe_vertices(
    primitive: &lforge_scene::Primitive,
    influences: &lforge_scene::VertexInfluences,
) -> Vec<SkinProbeVertex> {
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

fn worst(a: [f32; 3], b: [f32; 3]) -> f32 {
    (Vec3::from(a) - Vec3::from(b)).length()
}

fn worst4(a: [f32; 4], b: [f32; 4]) -> f32 {
    let direction = (Vec3::new(a[0], a[1], a[2]) - Vec3::new(b[0], b[1], b[2])).length();
    direction.max((a[3] - b[3]).abs())
}

/// Renders the CPU-deformed scene through the static pipeline so the skinned
/// pipeline can be compared with it pixel by pixel.
fn cpu_reference_scene(
    scene: &Scene,
    matrices: &SkinningMatrices,
    policy: lforge_scene::DeformationPolicy,
) -> Scene {
    let mut reference = scene.clone();
    for entry in &scene.influences {
        let primitive = &scene.meshes[entry.mesh].primitives[entry.primitive];
        let Ok(deformed) =
            lforge_scene::deform_primitive_with(primitive, &entry.influences, matrices, policy)
        else {
            continue;
        };
        let target = &mut reference.meshes[entry.mesh].primitives[entry.primitive];
        for (index, vertex) in target.vertices.iter_mut().enumerate() {
            vertex.position = deformed.positions[index];
            vertex.normal = deformed.normals[index];
            if let (Some(tangents), Some(vertex_tangent)) =
                (&deformed.tangents, vertex.tangent.as_mut())
            {
                *vertex_tangent = tangents[index];
            }
        }
    }
    reference.recompute_bounds();
    reference
}

struct Frame {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

fn save(path: &Path, frame: &Frame) -> std::io::Result<()> {
    let image = image::RgbaImage::from_raw(frame.width, frame.height, frame.pixels.clone())
        .expect("rgba frame");
    image
        .save(path)
        .map_err(|err| std::io::Error::other(err.to_string()))
}

fn render(
    renderer: &mut Renderer,
    scene: &GpuScene,
    camera: &OrbitCamera,
    overlay: Overlay,
) -> Frame {
    let frame = renderer
        .render_with_overlay(scene, camera, 900, 700, Background::DARK, overlay)
        .expect("render");
    Frame {
        width: frame.width,
        height: frame.height,
        pixels: frame.pixels,
    }
}

/// Reports the difference between two frames: pixels that differ at all, and
/// the largest per-channel delta.
fn frame_delta(a: &Frame, b: &Frame) -> (usize, u8) {
    let mut differing = 0usize;
    let mut worst = 0u8;
    for (left, right) in a
        .pixels
        .as_chunks::<4>()
        .0
        .iter()
        .zip(b.pixels.as_chunks::<4>().0.iter())
    {
        if left != right {
            differing += 1;
            for channel in 0..4 {
                worst = worst.max(left[channel].abs_diff(right[channel]));
            }
        }
    }
    (differing, worst)
}

#[test]
#[ignore = "requires LF_DEFORM_CASES, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
fn reports_deformation_measurements() {
    let list = std::env::var("LF_DEFORM_CASES").expect("LF_DEFORM_CASES");
    let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
    let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
    let out = std::env::var("LF_DEFORM_OUT")
        .ok()
        .map(std::path::PathBuf::from);
    let access = Access::with(Arc::new(
        Executable::open(Path::new(&executable)).expect("executable"),
    ));
    let cancel = AtomicBool::new(false);
    let root = Path::new(&root);
    if let Some(out) = &out {
        std::fs::create_dir_all(out).expect("output directory");
    }
    let mut keep: Option<Renderer> = None;
    let mut cases = cases(Path::new(&list));
    if let Ok(only) = std::env::var("LF_DEFORM_ONLY") {
        cases.retain(|case| case.selector.contains(&only));
    }
    assert!(!cases.is_empty(), "no case was read");

    for case in cases {
        println!("=== {}", case.selector);
        println!(
            "  request: member {:?}, bone {:?}, axis {}, {:.1} deg, move {:?}, label {}",
            case.member, case.bone, case.axis, case.degrees, case.translation, case.label
        );
        let started = Instant::now();
        let Some(Loaded {
            mut scene,
            name,
            verdicts,
        }) = load(&case, root, &access, &cancel)
        else {
            println!("  did not load");
            continue;
        };
        let decoded = started.elapsed();
        println!("  resource: {name}");
        println!("  verdicts: {verdicts}");
        println!("  loader diagnostics: {}", scene.diagnostics.len());
        scene.recompute_bounds();
        let Some(skeleton) = scene.skeleton.clone() else {
            println!("  no skeleton; decoded in {decoded:?}");
            continue;
        };
        let bones = skeleton.bones.len();
        let roots = skeleton.roots.len();
        let depth = skeleton.max_depth;
        let primitives: usize = scene.meshes.iter().map(|mesh| mesh.primitives.len()).sum();
        let vertices: usize = scene.vertex_count();
        let deformable = scene.deformable_primitive_count();
        println!(
            "  scene: {bones} bone(s), {roots} root(s), depth {depth}, {} mesh(es), {primitives} primitive(s), {vertices} vertex(es), {deformable} deformable, decoded in {decoded:?}",
            scene.meshes.len()
        );

        let mut deformable_vertices = 0usize;
        let mut highest_index = 0usize;
        let mut encodings: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut single_influence = 0usize;
        let mut multi_influence = 0usize;
        let mut rigid_attachment = 0usize;
        let mut inferred = 0usize;
        for entry in &scene.influences {
            let influences = &entry.influences;
            let primitive = &scene.meshes[entry.mesh].primitives[entry.primitive];
            let mut indices = std::collections::BTreeSet::new();
            for lanes in &influences.per_vertex {
                for influence in lanes {
                    if influence.weight > 0.0 {
                        indices.insert(usize::from(influence.bone));
                    }
                }
            }
            highest_index = highest_index.max(indices.iter().copied().max().unwrap_or(0));
            // The declaration table is the authority here: a stream the old
            // reader dropped is visible as a populated attribute below.
            let units = primitive
                .vertices
                .iter()
                .filter(|vertex| {
                    let normal = Vec3::from(vertex.normal);
                    (normal.length() - 1.0).abs() < 1e-3
                })
                .count();
            let zeros = primitive
                .vertices
                .iter()
                .filter(|vertex| Vec3::from(vertex.normal).length() < 1e-6)
                .count();
            let (u_min, u_max) = primitive
                .vertices
                .iter()
                .fold((f32::INFINITY, f32::NEG_INFINITY), |(min, max), vertex| {
                    (min.min(vertex.uv0[0]), max.max(vertex.uv0[0]))
                });
            let tangents = primitive
                .vertices
                .iter()
                .filter(|vertex| vertex.tangent.is_some())
                .count();
            println!(
                "    attributes: normals {units}/{} unit, {zeros} zero, uv0 u {u_min:.4}..{u_max:.4}, tangents {tangents}/{}",
                primitive.vertices.len(),
                primitive.vertices.len()
            );
            if influences.inferred() {
                inferred += 1;
            }
            if influences.deformable() {
                deformable_vertices += primitive.vertices.len();
                if influences.single_influence() {
                    single_influence += 1;
                    if influences.rigid_attachment() {
                        rigid_attachment += 1;
                    }
                } else {
                    multi_influence += 1;
                }
            }
            *encodings
                .entry(format!(
                    "{}-lane, max {} influence(s), distinct bones {}",
                    influences.lanes,
                    influences.max_influences,
                    indices.len()
                ))
                .or_insert(0) += 1;
            println!(
                "  mesh {} primitive {}: {} vertex(es), {} bone(s), lanes {}, max {} influence(s), {} distinct index(es) max {}, weight {:?}, status {}, {}",
                entry.mesh,
                entry.primitive,
                primitive.vertices.len(),
                influences.bones.len(),
                influences.lanes,
                influences.max_influences,
                indices.len(),
                indices.iter().copied().max().unwrap_or(0),
                influences.per_vertex.first().map(|lanes| lanes
                    .iter()
                    .filter(|lane| lane.weight > 0.0)
                    .map(|lane| lane.weight)
                    .collect::<Vec<_>>()),
                influences.status.name(),
                if influences.deformable() {
                    "deformable"
                } else {
                    "not deformed"
                }
            );
        }
        for (encoding, count) in &encodings {
            println!("  encoding: {count} x {encoding}");
        }
        let policy = lforge_scene::DeformationPolicy {
            include_inferred: case.include_inferred,
        };
        if !scene.supports_deformation_under(policy) {
            println!("  no deformable primitive; stopping here");
            continue;
        }

        // The bone to pose: the caller's choice, else the largest weight total in
        // the widest influence set.
        println!(
            "  policy: {}",
            if policy.include_inferred {
                "explicit and inferred"
            } else {
                "explicit only"
            }
        );
        let widest = scene
            .influences
            .iter()
            .filter(|entry| policy.admits(&entry.influences))
            .max_by_key(|entry| {
                let vertices = scene.meshes[entry.mesh].primitives[entry.primitive]
                    .vertices
                    .len();
                (entry.influences.max_influences, vertices)
            })
            .expect("a deformable primitive");
        let bone = match &case.bone {
            Some(wanted) => match wanted.parse::<usize>() {
                Ok(index) if index < bones => index,
                _ => match skeleton
                    .bones
                    .iter()
                    .position(|bone| bone.name.as_deref() == Some(wanted.as_str()))
                {
                    Some(index) => index,
                    None => {
                        println!("  no bone named or numbered {wanted}");
                        continue;
                    }
                },
            },
            None => {
                let mut totals = std::collections::BTreeMap::<usize, f32>::new();
                for lanes in &widest.influences.per_vertex {
                    for influence in lanes {
                        if influence.weight > 0.0 {
                            *totals.entry(usize::from(influence.bone)).or_default() +=
                                influence.weight;
                        }
                    }
                }
                totals
                    .into_iter()
                    .max_by(|a, b| a.1.total_cmp(&b.1))
                    .map(|(bone, _)| bone)
                    .unwrap_or(0)
            }
        };

        let axis = Vec3::X * f32::from(case.axis == 0)
            + Vec3::Y * f32::from(case.axis == 1)
            + Vec3::Z * f32::from(case.axis == 2);
        let rotation = Quat::from_axis_angle(axis, case.degrees.to_radians());
        let mut pose = Pose::new(bones);
        pose.set_rotation(bone, rotation).expect("rotation");
        pose.set_translation(bone, case.translation)
            .expect("translation");
        println!(
            "  pose: bone {bone} ({}), parent {:?}, local translation {:?}, rotation {:?} about {} in the bone's parent space, translation delta {:?} in the parent's space",
            skeleton.bones[bone]
                .name
                .clone()
                .unwrap_or_else(|| "#".into()),
            skeleton.bones[bone].parent,
            skeleton.bones[bone].local_translation,
            rotation.to_euler(glam::EulerRot::XYZ),
            ["X", "Y", "Z"][case.axis],
            case.translation
        );

        let started = Instant::now();
        let posed = pose.globals(&skeleton).expect("pose");
        let hierarchy = started.elapsed();
        let started = Instant::now();
        let matrices = SkinningMatrices::build(&skeleton, &pose).expect("matrices");
        let matrix_build = started.elapsed();
        let posed_positions: Vec<glam::Vec3> =
            posed.iter().map(|bone| bone.model_position).collect();
        let reference_positions: Vec<glam::Vec3> = skeleton
            .bones
            .iter()
            .map(|bone| bone.model_position)
            .collect();
        let posed_transforms: Vec<(glam::Vec3, Quat)> = posed
            .iter()
            .map(|bone| (bone.model_position, bone.model_rotation))
            .collect();
        let reference_transforms: Vec<(glam::Vec3, Quat)> = skeleton
            .bones
            .iter()
            .map(|bone| (bone.model_position, bone.model_rotation))
            .collect();
        let moved = moved_bones(&reference_transforms, &posed_transforms);
        let parents: Vec<Option<usize>> = skeleton.bones.iter().map(|bone| bone.parent).collect();
        let expected = subtree(&parents, bone);
        let outside = moved
            .iter()
            .copied()
            .filter(|index| expected.binary_search(index).is_err())
            .collect::<Vec<_>>();
        println!(
            "  propagation: {} bone(s) moved, subtree of bone {bone} holds {}; moved outside the subtree: {outside:?}",
            moved.len(),
            expected.len()
        );
        assert!(
            outside.is_empty(),
            "a bone outside the posed subtree moved: {outside:?}"
        );
        let roots_moved = skeleton
            .roots
            .iter()
            .filter(|root| moved.contains(root))
            .count();
        println!(
            "  roots: {roots} independent root(s), {roots_moved} own a moved bone; matrix array {}, {} inverse-bind record(s)",
            matrices.len(),
            matrices.stored()
        );

        let started = Instant::now();
        let mut deformed_vertices = 0usize;
        let mut moved_vertices = 0usize;
        let mut worst_displacement = 0.0f32;
        let mut collapsed = 0usize;
        let mut worst_normal = 0.0f32;
        let mut worst_tangent = 0.0f32;
        let mut deformed: Vec<(usize, usize, lforge_scene::DeformedPrimitive)> = Vec::new();
        for entry in &scene.influences {
            if !policy.admits(&entry.influences) {
                continue;
            }
            let primitive = &scene.meshes[entry.mesh].primitives[entry.primitive];
            let result = lforge_scene::deform_primitive_with(
                primitive,
                &entry.influences,
                &matrices,
                policy,
            )
            .expect("deformation");
            for (index, vertex) in primitive.vertices.iter().enumerate() {
                let delta =
                    (Vec3::from(result.positions[index]) - Vec3::from(vertex.position)).length();
                if delta > 1e-6 {
                    moved_vertices += 1;
                }
                worst_displacement = worst_displacement.max(delta);
                let normal_delta = worst(vertex.normal, result.normals[index]);
                worst_normal = worst_normal.max(normal_delta);
                if let (Some(original), Some(transformed)) = (
                    vertex.tangent,
                    result.tangents.as_ref().map(|tangents| tangents[index]),
                ) {
                    worst_tangent = worst_tangent.max(worst4(original, transformed));
                }
            }
            let mut moved_here = 0usize;
            for (index, vertex) in primitive.vertices.iter().enumerate() {
                if (Vec3::from(result.positions[index]) - Vec3::from(vertex.position)).length()
                    > 1e-6
                {
                    moved_here += 1;
                }
            }
            if moved_here > 0 {
                println!(
                    "  moved: mesh {} primitive {} holds {moved_here} of {} moved vertex(es)",
                    entry.mesh,
                    entry.primitive,
                    primitive.vertices.len()
                );
            }
            deformed_vertices += primitive.vertices.len();
            collapsed += result.collapsed_normals;
            deformed.push((entry.mesh, entry.primitive, result));
        }
        let cpu_deform = started.elapsed();
        println!(
            "  cpu deformation: {deformed_vertices} vertex(es) of {deformable} primitive(s), {moved_vertices} moved, worst displacement {worst_displacement:.6} m, worst normal delta {worst_normal:.6}, worst tangent delta {worst_tangent:.6}, {collapsed} collapsed normal(s) in {cpu_deform:?}"
        );
        println!(
            "  single-influence primitive(s) {single_influence} (of which whole-primitive rigid: {rigid_attachment}), multi-influence {multi_influence}, inferred association(s) {inferred}, highest active bone index {highest_index}"
        );

        let mut renderer = match keep.take() {
            Some(taken) => taken,
            None => match Renderer::new() {
                Ok(created) => created,
                Err(err) => {
                    println!("  no renderer: {err}");
                    continue;
                }
            },
        };
        let info = renderer.adapter_info();
        println!(
            "  adapter: {} ({}, {:?})",
            info.name, info.backend, info.device_type
        );
        let started = Instant::now();
        let mut gpu = renderer.upload_scene(&scene).expect("upload");
        let upload = started.elapsed();
        let started = Instant::now();
        renderer
            .update_pose(&mut gpu, matrices.matrices(), &posed_positions)
            .expect("pose upload");
        let pose_upload = started.elapsed();

        // Numerical comparison of every deformable primitive against the probe.
        let mut probe_positions = 0.0f32;
        let mut probe_normals = 0.0f32;
        let mut probe_tangents = 0.0f32;
        let mut compared = 0usize;
        for entry in &scene.influences {
            if !policy.admits(&entry.influences) {
                continue;
            }
            let primitive = &scene.meshes[entry.mesh].primitives[entry.primitive];
            let result = lforge_scene::deform_primitive_with(
                primitive,
                &entry.influences,
                &matrices,
                policy,
            )
            .expect("deformation");
            let probes = probe_vertices(primitive, &entry.influences);
            let samples = renderer
                .probe_skinning(matrices.matrices(), &probes)
                .expect("probe");
            for (index, sample) in samples.iter().enumerate() {
                probe_positions =
                    probe_positions.max(worst(sample.position, result.positions[index]));
                probe_normals = probe_normals.max(worst(sample.normal, result.normals[index]));
                if let Some(tangents) = &result.tangents {
                    probe_tangents = probe_tangents.max(worst4(sample.tangent, tangents[index]));
                }
                compared += 1;
            }
        }
        println!(
            "  cpu vs gpu probe: {compared} vertex(es), worst position {probe_positions:.3e} m, worst normal {probe_normals:.3e}, worst tangent {probe_tangents:.3e}"
        );
        assert!(
            probe_positions < 1e-4 && probe_normals < 1e-4 && probe_tangents < 1e-3,
            "the probe disagrees with the CPU reference: position {probe_positions}, normal {probe_normals}, tangent {probe_tangents}"
        );

        // Raster comparison: the CPU-deformed scene through the static pipeline
        // against the authored scenes through the skinned pipeline.
        let cpu_scene = cpu_reference_scene(&scene, &matrices, policy);
        let cpu_gpu = renderer
            .upload_scene(&cpu_scene)
            .expect("upload cpu reference");
        let authored_bounds = scene.bounds.sanitized();
        let posed_bounds = scene
            .posed_bounds_under(&pose, policy)
            .expect("posed bounds")
            .map_or(authored_bounds, |bounds| bounds.sanitized());
        let camera = OrbitCamera::framing(authored_bounds.union(posed_bounds), 900.0f32 / 700.0f32);
        gpu.set_skeleton_selected(Some(bone));
        let overlay = Overlay {
            visible: true,
            selected: Some(bone),
            depth_independent: true,
        };
        let started = Instant::now();
        let reference_frame = render(&mut renderer, &cpu_gpu, &camera, Overlay::NONE);
        let reference_time = started.elapsed();
        gpu.set_policy(policy);
        gpu.set_pose_active(true);
        let started = Instant::now();
        let skinned_frame = render(&mut renderer, &gpu, &camera, Overlay::NONE);
        let skinned_time = started.elapsed();
        let (differing, worst_channel) = frame_delta(&reference_frame, &skinned_frame);
        let total_pixels = (reference_frame.width * reference_frame.height) as usize;
        println!(
            "  raster cpu-reference vs gpu-skinned: {differing} of {total_pixels} pixel(s) differ, worst channel delta {worst_channel}; reference frame {reference_time:?}, skinned frame {skinned_time:?}"
        );

        let mut authored_view = renderer.upload_scene(&scene).expect("upload");
        let authored_frame = render(&mut renderer, &authored_view, &camera, Overlay::NONE);
        let (authored_vs_reference, _) = frame_delta(&authored_frame, &reference_frame);
        println!(
            "  the posed frame differs from the authored frame on {authored_vs_reference} pixel(s), which is what the pose moved"
        );

        // Leaving pose mode: the reference frame must reproduce the authored
        // render exactly.
        let reference_pose = Pose::reference(&skeleton);
        let reference_matrices =
            SkinningMatrices::build(&skeleton, &reference_pose).expect("reference matrices");
        renderer
            .update_pose(
                &mut gpu,
                reference_matrices.matrices(),
                &reference_positions,
            )
            .expect("reference upload");
        gpu.set_pose_active(false);
        gpu.set_influence_view(false);
        let reset_frame = render(&mut renderer, &gpu, &camera, Overlay::NONE);
        let (reset_delta, reset_worst) = frame_delta(&authored_frame, &reset_frame);
        println!(
            "  reset: reference joint matrices and a static draw reproduce the authored frame with {reset_delta} differing pixel(s), channel delta {reset_worst}"
        );
        assert_eq!(
            reset_delta, 0,
            "the reset frame differs from the authored frame"
        );

        // Influence view: colour by the decoded weight of the posed bone.
        let started = Instant::now();
        renderer
            .update_pose(&mut gpu, matrices.matrices(), &posed_positions)
            .expect("pose upload");
        gpu.set_pose_active(true);
        gpu.set_influence_view(true);
        let influence_frame = render(&mut renderer, &gpu, &camera, overlay);
        let influence_time = started.elapsed();
        let (influence_delta, _) = frame_delta(&influence_frame, &skinned_frame);
        println!(
            "  influence view differs from the material view on {influence_delta} pixel(s) in {influence_time:?}"
        );
        gpu.set_influence_view(false);

        authored_view.set_skeleton_visible(true);
        let overlay_frame = render(&mut renderer, &gpu, &camera, overlay);

        if let Some(out) = &out {
            let stem: String = case
                .selector
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            let member = case
                .member
                .map_or(String::new(), |index| format!("-m{index}"));
            for (name, frame) in [
                ("1-authored", &authored_frame),
                ("2-posed", &skinned_frame),
                ("3-posed-overlay", &overlay_frame),
                ("4-influence", &influence_frame),
                ("5-reset", &reset_frame),
                ("6-cpu-reference", &reference_frame),
            ] {
                let path = out.join(format!("{stem}{member}-{name}.png"));
                save(&path, frame).expect("write preview");
            }
            println!("  wrote six previews to {}", out.display());
        }

        assert!(
            authored_vs_reference > 0,
            "the pose changed no pixel, so the comparison proves nothing"
        );
        assert!(
            differing * 1000 <= total_pixels && worst_channel <= 8,
            "the skinned raster differs from the CPU reference: {differing} pixels, channel {worst_channel}"
        );
        assert_eq!(
            reset_delta, 0,
            "the reset frame differs from the authored frame"
        );

        // Memory and cost of the buffers the pose path adds.
        let authored_vertex_bytes = vertices * size_of::<lforge_scene::Vertex>();
        let skinned_vertex_bytes = deformable_vertices * SKINNED_VERTEX_BYTES;
        let joint_bytes = matrices.len() * size_of::<[[f32; 4]; 4]>();
        println!(
            "  memory: authored vertex buffers {authored_vertex_bytes} bytes, skinned vertex buffers {skinned_vertex_bytes} bytes for {deformable_vertices} vertex(es), joint matrices {joint_bytes} bytes, overlay lines {} bytes",
            bones * 6 * OVERLAY_VERTEX_BYTES
                + bones.saturating_sub(skeleton.roots.len()) * 2 * OVERLAY_VERTEX_BYTES
        );
        println!(
            "  timings: decode {decoded:?}, hierarchy {hierarchy:?}, matrices {matrix_build:?}, cpu deformation {cpu_deform:?}, scene upload {upload:?}, cpu-side pose upload {pose_upload:?}"
        );
        keep = Some(renderer);
    }
    let _ = keep;
}

/// Size of one skinned vertex in the renderer's upload.
const SKINNED_VERTEX_BYTES: usize = 4 * 4 + 4 * 3 + 4 * 4 + 4 * 4 + 4 * 4;
/// Size of one overlay vertex.
const OVERLAY_VERTEX_BYTES: usize = 6 * 4;
