//! An external consumer of the skinning API.
//!
//! This example uses only the public crates: `lforge-model` decodes a resource
//! into a [`lforge_scene::Scene`], `lforge-scene` poses it and evaluates linear
//! blend skinning on the CPU, and `lforge-renderer` optionally draws the result
//! and evaluates the same maths in a compute probe.
//!
//! ```text
//! skinning-consumer --resource <file> [--member <index>] [--bone <index|name>]
//!                   [--degrees <deg>] [--translate x,y,z]
//!                   [--compare] [--render <file.png>]
//! ```
//!
//! `--resource` names the resource bytes, as written by `lforge extract`. The
//! example carries no game path: the caller names the file, the member, the
//! bone and the step.

use std::path::PathBuf;
use std::process::ExitCode;

use glam::{Quat, Vec3};
use lforge_model::NoTextures;
use lforge_renderer::{Background, GpuScene, OrbitCamera, Overlay, Renderer, SkinProbeVertex};
use lforge_scene::{
    DeformationPolicy, Pose, Scene, SkinningMatrices, VertexInfluences, deform_primitive_with,
};

struct Options {
    resource: PathBuf,
    member: Option<usize>,
    bone: Option<String>,
    degrees: f32,
    translation: Vec3,
    compare: bool,
    render: Option<PathBuf>,
    /// Whether inferred single-bone associations may deform. Off by default.
    include_inferred: bool,
}

fn usage() -> String {
    let mut text = String::from(
        "usage: skinning-consumer --resource <file> [options]\n\
         \n\
         --member <index>       decode one drawable-dictionary member\n\
         --bone <index|name>    bone to pose; default: the largest weight total\n\
         --degrees <deg>        rotation about the bone's own Z, default 30\n\
         --translate <x,y,z>    translation in the bone's parent space, metres\n\
         --compare              compare the GPU probe with the CPU reference\n\
         --render <file>        render the posed model to a PNG file\n\
         --include-inferred     also deform single-bone associations that were\n\
         \x20                      inferred from the bone count, not decoded\n",
    );
    text.push_str(
        "\nThe example reads bytes, not archives: run `lforge extract` first. \
         It holds no game path.\n",
    );
    text
}

fn parse(
    options: &mut Options,
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<(), String> {
    let Some(flag) = args.next() else {
        return Ok(());
    };
    match flag.as_str() {
        "--resource" => {
            options.resource = PathBuf::from(args.next().ok_or("--resource needs a file")?);
        }
        "--member" => {
            let value = args.next().ok_or("--member needs an index")?;
            options.member = Some(value.parse().map_err(|_| "not an index: {value}")?);
        }
        "--bone" => options.bone = Some(args.next().ok_or("--bone needs an index or a name")?),
        "--degrees" => {
            let value = args.next().ok_or("--degrees needs a number")?;
            options.degrees = value.parse().map_err(|_| "not a number: --degrees")?;
        }
        "--translate" => {
            let value = args.next().ok_or("--translate needs x,y,z")?;
            let parts: Vec<f32> = value
                .split(',')
                .map(|part| part.trim().parse::<f32>())
                .collect::<Result<_, _>>()
                .map_err(|_| "--translate needs three numbers")?;
            if parts.len() != 3 {
                return Err("--translate needs three numbers".into());
            }
            options.translation = Vec3::from_slice(&parts);
        }
        "--compare" => options.compare = true,
        "--include-inferred" => options.include_inferred = true,
        "--render" => {
            options.render = Some(PathBuf::from(args.next().ok_or("--render needs a file")?));
        }
        "-h" | "--help" => return Err(usage()),
        other => return Err(format!("unknown option {other}\n\n{}", usage())),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut options = Options {
        resource: PathBuf::new(),
        member: None,
        bone: None,
        degrees: 30.0,
        translation: Vec3::ZERO,
        compare: false,
        render: None,
        include_inferred: false,
    };
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_none() {
        return Err(usage());
    }
    while args.peek().is_some() {
        parse(&mut options, &mut args)?;
    }
    if options.resource.as_os_str().is_empty() {
        return Err(format!("--resource is required\n\n{}", usage()));
    }

    let bytes = std::fs::read(&options.resource)
        .map_err(|err| format!("{}: {err}", options.resource.display()))?;
    let split = lforge_model::split_resource(&bytes)
        .ok_or("the resource does not split into a system and a graphics segment")?;
    let (system, graphics) = bytes.split_at(split.system_len);
    let scene = match options.member {
        Some(index) => {
            lforge_model::decode_dictionary_member(system, graphics, index, &NoTextures)
                .map_err(|err| format!("member {index}: {err}"))?
                .scene
        }
        None => {
            lforge_model::decode(system, graphics, &NoTextures)
                .map_err(|err| format!("{err}"))?
                .scene
        }
    };

    let Some(skeleton) = scene.skeleton.as_ref() else {
        return Err("the resource carries no skeleton".into());
    };
    let primitives: usize = scene.meshes.iter().map(|mesh| mesh.primitives.len()).sum();
    let policy = DeformationPolicy {
        include_inferred: options.include_inferred,
    };
    println!(
        "skeleton: {} bone(s), {} primitive(s), {} deformable under the {} policy",
        skeleton.bones.len(),
        primitives,
        scene.deformable_primitive_count_under(policy),
        if options.include_inferred {
            "inferred-inclusive"
        } else {
            "explicit-only"
        }
    );
    println!(
        "  inferred single-bone association(s): {}",
        scene.inferred_primitive_count()
    );
    for entry in &scene.influences {
        println!(
            "  mesh {} primitive {}: {} bone(s), {} influence(s), weighted {}, {}",
            entry.mesh,
            entry.primitive,
            entry.influences.bones.len(),
            entry.influences.max_influences,
            entry.influences.weighted,
            entry.influences.status_name()
        );
    }
    if !scene.supports_deformation_under(policy) {
        return Err(
            "no primitive of this resource deforms under this policy; a geometry whose only \
             association is inferred needs --include-inferred"
                .into(),
        );
    }

    let entry = scene
        .influences
        .iter()
        .filter(|entry| policy.admits(&entry.influences))
        .max_by_key(|entry| entry.influences.max_influences)
        .ok_or("no deformable primitive")?;
    let bone = match &options.bone {
        Some(name) => skeleton
            .bones
            .iter()
            .position(|bone| bone.name.as_deref() == Some(name.as_str()))
            .or_else(|| {
                name.parse()
                    .ok()
                    .filter(|index| *index < skeleton.bones.len())
            })
            .ok_or_else(|| format!("no bone named or numbered {name}"))?,
        None => {
            largest_weight_bone(&entry.influences).ok_or("the chosen primitive names no bone")?
        }
    };

    let mut pose = Pose::new(skeleton.bones.len());
    pose.set_rotation(bone, Quat::from_rotation_z(options.degrees.to_radians()))
        .map_err(|err| format!("rotation: {err:?}"))?;
    pose.set_translation(bone, options.translation)
        .map_err(|err| format!("translation: {err:?}"))?;
    let matrices = SkinningMatrices::build(skeleton, &pose)
        .map_err(|err| format!("skinning matrices: {err:?}"))?;
    let posed = pose
        .globals(skeleton)
        .map_err(|err| format!("pose evaluation: {err:?}"))?;
    let positions: Vec<Vec3> = posed.iter().map(|bone| bone.model_position).collect();
    println!(
        "pose: bone {bone} ({}) rotated {:.1} deg about its own Z and moved ({:.3}, {:.3}, {:.3}) m",
        skeleton.bones[bone]
            .name
            .clone()
            .unwrap_or_else(|| format!("#{bone}")),
        options.degrees,
        options.translation.x,
        options.translation.y,
        options.translation.z
    );

    for entry in &scene.influences {
        let primitive = &scene.meshes[entry.mesh].primitives[entry.primitive];
        let deformed = match deform_primitive_with(primitive, &entry.influences, &matrices, policy)
        {
            Ok(deformed) => deformed,
            Err(err) => {
                println!(
                    "  mesh {} primitive {}: stays authored ({err})",
                    entry.mesh, entry.primitive
                );
                continue;
            }
        };
        let mut moved = 0;
        let mut worst = 0.0f32;
        for (index, vertex) in primitive.vertices.iter().enumerate() {
            let delta =
                (Vec3::from(deformed.positions[index]) - Vec3::from(vertex.position)).length();
            if delta > 1e-6 {
                moved += 1;
            }
            worst = worst.max(delta);
        }
        println!(
            "  mesh {} primitive {}: {moved} of {} vertices moved, worst {worst:.6} m, {} collapsed normal(s)",
            entry.mesh,
            entry.primitive,
            primitive.vertices.len(),
            deformed.collapsed_normals
        );
    }

    if options.compare {
        compare(
            &scene,
            entry.mesh,
            entry.primitive,
            &entry.influences,
            &matrices,
            policy,
        )?;
    }
    if let Some(path) = &options.render {
        render(&scene, &pose, &matrices, &positions, path, policy)?;
    }
    Ok(())
}

/// The bone with the largest total weight in one influence set.
fn largest_weight_bone(influences: &VertexInfluences) -> Option<usize> {
    let mut totals = std::collections::BTreeMap::<usize, f32>::new();
    for lanes in &influences.per_vertex {
        for influence in lanes {
            if influence.weight > 0.0 {
                *totals.entry(usize::from(influence.bone)).or_default() += influence.weight;
            }
        }
    }
    totals
        .into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(bone, _)| bone)
}

/// Compares the GPU skinning probe with the CPU reference on every vertex of
/// one primitive.
fn compare(
    scene: &Scene,
    mesh: usize,
    primitive: usize,
    influences: &VertexInfluences,
    matrices: &SkinningMatrices,
    policy: DeformationPolicy,
) -> Result<(), String> {
    let primitive = &scene.meshes[mesh].primitives[primitive];
    let cpu = deform_primitive_with(primitive, influences, matrices, policy)
        .map_err(|err| format!("deformation: {err:?}"))?;
    let probes: Vec<SkinProbeVertex> = primitive
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
        .collect();
    let renderer = Renderer::new().map_err(|err| format!("renderer: {err}"))?;
    let adapter = renderer.adapter_info();
    let samples = renderer
        .probe_skinning(matrices.matrices(), &probes)
        .map_err(|err| format!("probe: {err}"))?;
    let mut worst = 0.0f32;
    for (index, sample) in samples.iter().enumerate() {
        worst =
            worst.max((Vec3::from(cpu.positions[index]) - Vec3::from(sample.position)).length());
    }
    println!(
        "gpu probe: {} ({}), {} vertices, worst difference {worst:.3e} m",
        adapter.name,
        adapter.backend,
        samples.len()
    );
    if worst > 1e-4 {
        return Err(format!("the GPU and the CPU disagree by {worst} m"));
    }
    Ok(())
}

/// Renders the posed model and the reference side by side into one image.
fn render(
    scene: &Scene,
    pose: &Pose,
    matrices: &SkinningMatrices,
    positions: &[Vec3],
    path: &PathBuf,
    policy: DeformationPolicy,
) -> Result<(), String> {
    let (width, height) = (900u32, 700u32);
    let authored = scene.bounds.sanitized();
    let deformed = scene
        .posed_bounds_under(pose, policy)
        .map_err(|(_, _, err)| format!("posed bounds: {err:?}"))?
        .unwrap_or(authored)
        .sanitized();
    let camera = OrbitCamera::framing(authored.union(deformed), width as f32 / height as f32);
    let mut renderer = Renderer::new().map_err(|err| format!("renderer: {err}"))?;
    let mut gpu: GpuScene = renderer
        .upload_scene(scene)
        .map_err(|err| format!("upload: {err}"))?;
    renderer
        .update_pose(&mut gpu, matrices.matrices(), positions)
        .map_err(|err| format!("pose upload: {err}"))?;
    gpu.set_policy(policy);
    gpu.set_pose_active(true);
    let frame = renderer
        .render_with_overlay(
            &gpu,
            &camera,
            width,
            height,
            Background::DARK,
            Overlay::NONE,
        )
        .map_err(|err| format!("render: {err}"))?;
    let image = image::RgbaImage::from_raw(width, height, frame.rgba8().to_vec())
        .ok_or("the frame does not fill the image")?;
    image.save(path).map_err(|err| format!("{path:?}: {err}"))?;
    println!("wrote {}", path.display());
    Ok(())
}
