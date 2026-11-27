//! An external consumer of the model, texture and renderer crates.
//!
//! This example does not use the desktop application or GPUI. It loads one
//! extracted native drawable or fragment resource, resolves its external
//! textures from a game installation's `.ttpf` stores, reports skeleton,
//! association and placement completeness, renders RGBA8 images at two sizes,
//! and renders once into a GPU target without readback.
//!
//! Usage:
//!   cargo run -p lforge-model --example external_viewer -- \
//!     <resource.bin> <game-root> <output.png> [system-length] \
//!     [--skeleton <overlay.png>] [--bones-only <only.png>]
//!
//! `system-length` is the caller's resource layout information; without it the
//! boundary is inferred. The two optional images are written only where the
//! caller names them.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use lforge_model::{self as model, TextureProvider, TextureReference, TextureResolution};
use lforge_renderer::{Background, OrbitCamera, Overlay, Renderer};
use lforge_texture::StoreSet;

struct Stores(Arc<StoreSet>);

impl TextureProvider for Stores {
    fn resolve(&self, reference: &TextureReference) -> TextureResolution {
        let candidates = self.0.find(reference.key64);
        match candidates.as_slice() {
            [] => TextureResolution::Missing,
            [(store_index, texture_index)] => {
                let store = match self.0.open(*store_index) {
                    Ok(store) => store,
                    Err(err) => return TextureResolution::Failed(err.to_string()),
                };
                let Some(info) = store.textures().get(*texture_index as usize) else {
                    return TextureResolution::Failed("the descriptor disappeared".into());
                };
                match store.level(
                    *texture_index,
                    0,
                    &std::sync::atomic::AtomicBool::new(false),
                ) {
                    Ok(level) => TextureResolution::Resolved(model::ResolvedTexture {
                        level,
                        source: format!(
                            "{}#{} {}",
                            self.0
                                .path(*store_index)
                                .map(|path| path.display().to_string())
                                .unwrap_or_else(|| "texture store".into()),
                            texture_index,
                            info.dimensions()
                        ),
                    }),
                    Err(err) => TextureResolution::Failed(err.to_string()),
                }
            }
            _ => TextureResolution::Ambiguous(
                candidates
                    .iter()
                    .map(|(store_index, texture_index)| {
                        format!(
                            "{}#{}",
                            self.0
                                .path(*store_index)
                                .map(|path| path.display().to_string())
                                .unwrap_or_else(|| "texture store".into()),
                            texture_index
                        )
                    })
                    .collect(),
            ),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let resource = PathBuf::from(args.next().ok_or("missing resource path")?);
    let game_root = PathBuf::from(args.next().ok_or("missing game root")?);
    let output = PathBuf::from(args.next().ok_or("missing output png")?);
    let mut exact_system_len = None;
    let mut skeleton_output = None;
    let mut bones_only_output = None;
    while let Some(argument) = args.next() {
        let argument = argument.to_string_lossy().into_owned();
        match argument.as_str() {
            "--skeleton" => {
                skeleton_output =
                    Some(PathBuf::from(args.next().ok_or("--skeleton needs a path")?));
            }
            "--bones-only" => {
                bones_only_output = Some(PathBuf::from(
                    args.next().ok_or("--bones-only needs a path")?,
                ));
            }
            other => {
                if exact_system_len.is_some() {
                    return Err(format!("unexpected argument {other}").into());
                }
                let value = match other
                    .strip_prefix("0x")
                    .or_else(|| other.strip_prefix("0X"))
                {
                    Some(hex) => usize::from_str_radix(hex, 16)?,
                    None => other.parse::<usize>()?,
                };
                exact_system_len = Some(value);
            }
        }
    }

    let bytes = std::fs::read(&resource)?;
    let (split, exact) = match exact_system_len {
        Some(system_len) => (system_len, true),
        None => (
            model::split_resource(&bytes)
                .ok_or("the resource has no drawable graphics segment")?
                .system_len,
            false,
        ),
    };
    let (system, graphics) = bytes.split_at(split);
    println!(
        "split: {split} bytes, {}",
        if exact {
            "caller-supplied page metadata"
        } else {
            "inferred from graphics markers"
        }
    );
    let stores = Arc::new(StoreSet::scan(&game_root.join("data").join("ttdb"))?);
    // A resource may be a drawable or a fragment; both decode into one scene
    // through the same provider, so this example covers both entry points.
    let (scene, completeness, texture_bindings) = if model::is_fragment(system, graphics) {
        let fragment = model::decode_fragment(system, graphics, &Stores(stores))?;
        println!(
            "fragment {:?}: {} component(s), completeness {:?}",
            fragment.report.name(),
            fragment.components.len(),
            fragment.completeness
        );
        for component in &fragment.components {
            println!(
                "  component {} {:?} lod {:?} meshes {:?} {} primitives {} vertices {} triangles",
                component.index,
                component.name,
                component.lod,
                component.meshes,
                component.primitives,
                component.vertices,
                component.triangles
            );
        }
        println!(
            "  root counts at +0x30 {:?}, {} unidentified pointer(s)",
            fragment.report.header.counts,
            fragment.report.header.unexplained_present()
        );
        let geometry = match &fragment.completeness {
            model::FragmentCompleteness::SinglePrimaryDrawable => {
                model::GeometryCompleteness::Complete
            }
            model::FragmentCompleteness::Partial { reason } => {
                model::GeometryCompleteness::Partial {
                    reason: reason.clone(),
                }
            }
            model::FragmentCompleteness::Unsupported { reason } => {
                model::GeometryCompleteness::Unsupported {
                    reason: reason.clone(),
                }
            }
        };
        let missing = fragment
            .scene
            .materials
            .iter()
            .filter(|material| material.missing_texture)
            .count();
        let textures = if missing > 0 {
            model::TextureCompleteness::Partial { missing }
        } else {
            model::TextureCompleteness::Complete
        };
        (
            fragment.scene,
            model::ModelCompleteness {
                geometry,
                textures,
                skeleton: fragment.skeleton.clone(),
                associations: fragment.associations.clone(),
                placement: fragment.placement.clone(),
                selected_root: fragment.report.header.drawable as usize,
                selected_name: fragment.report.name().map(str::to_string),
                notes: Vec::new(),
            },
            fragment.texture_bindings,
        )
    } else {
        let decoded = model::decode(system, graphics, &Stores(stores))?;
        (
            decoded.scene,
            decoded.completeness,
            decoded.texture_bindings,
        )
    };

    println!(
        "{}: {} meshes, {} materials, {} textures, {} vertices, {} triangles",
        completeness.selected_name.as_deref().unwrap_or("model"),
        scene.meshes.len(),
        scene.materials.len(),
        scene.textures.len(),
        scene.vertex_count(),
        scene.triangle_count()
    );
    println!("geometry: {:?}", completeness.geometry);
    println!("textures: {:?}", completeness.textures);
    println!("skeleton: {:?}", completeness.skeleton);
    println!("bone associations: {:?}", completeness.associations);
    println!("static placement: {:?}", completeness.placement);
    match scene.skeleton.as_ref() {
        Some(skeleton) => {
            println!(
                "bones: {} ({} named), {} root(s), depth {}",
                skeleton.bones.len(),
                skeleton
                    .bones
                    .iter()
                    .filter(|bone| bone.name.is_some())
                    .count(),
                skeleton.roots.len(),
                skeleton.max_depth
            );
            println!(
                "inverse-bind records: {}",
                skeleton
                    .bones
                    .iter()
                    .filter(|bone| bone.inverse_bind.is_some())
                    .count()
            );
            for bone in skeleton.bones.iter().take(16) {
                println!(
                    "  bone {} name {:?} parent {:?} model position {:?} local translation {:?}",
                    bone.index, bone.name, bone.parent, bone.model_position, bone.local_translation
                );
            }
            if skeleton.bones.len() > 16 {
                println!("  ... {} more", skeleton.bones.len() - 16);
            }
        }
        None => println!("bones: none"),
    }
    for association in &scene.associations {
        println!(
            "association: mesh {} primitive {} bones {:?} weighted {} declared {:?}",
            association.mesh,
            association.primitive,
            association.bones,
            association.weighted,
            association.declared_bone_count
        );
    }
    println!(
        "texture bindings: {} total, {} unresolved, {} embedded",
        texture_bindings.len(),
        texture_bindings
            .iter()
            .filter(|binding| binding.texture.is_none())
            .count(),
        texture_bindings
            .iter()
            .filter(|binding| binding.embedded)
            .count()
    );
    for binding in texture_bindings.iter().filter(|binding| binding.embedded) {
        println!(
            "embedded binding: {:?} key {:#018x} texture {:?}",
            binding.semantic, binding.key64, binding.texture
        );
    }
    for diagnostic in &scene.diagnostics {
        println!("diagnostic: {}", diagnostic.reason);
    }

    let mut renderer = Renderer::new()?;
    let gpu = renderer.upload_scene(&scene)?;
    let camera = OrbitCamera::framing(scene.bounds, 16.0 / 9.0);
    let frame = renderer.render(&gpu, &camera, 1280, 720, Background::DARK)?;
    save_rgba(&output, frame.width, frame.height, &frame.pixels)?;
    println!(
        "wrote {} ({}x{})",
        output.display(),
        frame.width,
        frame.height
    );

    let transparent = renderer.render(&gpu, &camera, 1280, 720, Background::Transparent)?;
    save_rgba(
        &output.with_file_name("external-transparent.png"),
        transparent.width,
        transparent.height,
        &transparent.pixels,
    )?;

    let target = renderer.create_target(1920, 1080)?;
    renderer.render_to_target(&gpu, &camera, &target, Background::DARK)?;
    println!(
        "gpu target: {}x{}, no readback",
        target.width(),
        target.height()
    );

    let again = renderer.render(&gpu, &camera, 1280, 720, Background::DARK)?;
    assert_eq!(again.pixels, frame.pixels, "repeated rendering is stable");
    println!("repeated rendering: stable");

    if let Some(path) = skeleton_output {
        let overlay = renderer.render_with_overlay(
            &gpu,
            &camera,
            1280,
            720,
            Background::DARK,
            Overlay::skeleton(None, true),
        )?;
        save_rgba(&path, overlay.width, overlay.height, &overlay.pixels)?;
        println!("wrote skeleton overlay {}", path.display());
    }
    if let Some(path) = bones_only_output {
        let mut skeleton_scene = renderer.upload_scene(&scene)?;
        skeleton_scene.set_skeleton_visible(true);
        for mesh in 0..scene.meshes.len() {
            skeleton_scene.set_mesh_visible(mesh, false);
        }
        let bounds = scene.skeleton_bounds().unwrap_or(scene.bounds);
        let camera = OrbitCamera::framing(bounds, 16.0 / 9.0);
        let only = renderer.render(&skeleton_scene, &camera, 1280, 720, Background::DARK)?;
        save_rgba(&path, only.width, only.height, &only.pixels)?;
        println!("wrote skeleton-only view {}", path.display());
    }
    Ok(())
}

fn save_rgba(
    path: &Path,
    width: u32,
    height: u32,
    rgba: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let image = image::RgbaImage::from_raw(width, height, rgba.to_vec())
        .ok_or("the frame size does not match its pixels")?;
    image.save(path)?;
    Ok(())
}
