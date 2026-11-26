//! An external consumer of the model, texture and renderer crates.
//!
//! This example does not use the desktop application or GPUI. It loads one
//! extracted native drawable resource, resolves its external textures from a
//! game installation's `.ttpf` stores, reports completeness, renders RGBA8
//! images at two sizes, and renders once into a GPU target without readback.
//!
//! Usage:
//!   cargo run -p lforge-model --example external_viewer -- \
//!     <resource.bin> <game-root> <output.png>

use std::path::{Path, PathBuf};
use std::sync::Arc;

use lforge_model::{self as model, TextureProvider, TextureReference, TextureResolution};
use lforge_renderer::{Background, OrbitCamera, Renderer};
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
    let exact_system_len = args
        .next()
        .map(|value| value.to_string_lossy().parse::<usize>())
        .transpose()?;

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
    let decoded = model::decode(system, graphics, &Stores(stores))?;

    println!(
        "{}: {} meshes, {} materials, {} textures, {} vertices, {} triangles",
        decoded
            .completeness
            .selected_name
            .as_deref()
            .unwrap_or("model"),
        decoded.scene.meshes.len(),
        decoded.scene.materials.len(),
        decoded.scene.textures.len(),
        decoded.scene.vertex_count(),
        decoded.scene.triangle_count()
    );
    println!("geometry: {:?}", decoded.completeness.geometry);
    println!("textures: {:?}", decoded.completeness.textures);
    println!(
        "texture bindings: {} total, {} unresolved, {} embedded",
        decoded.texture_bindings.len(),
        decoded
            .texture_bindings
            .iter()
            .filter(|binding| binding.texture.is_none())
            .count(),
        decoded
            .texture_bindings
            .iter()
            .filter(|binding| binding.embedded)
            .count()
    );
    for binding in decoded
        .texture_bindings
        .iter()
        .filter(|binding| binding.embedded)
    {
        println!(
            "embedded binding: {:?} key {:#018x} texture {:?}",
            binding.semantic, binding.key64, binding.texture
        );
    }
    for diagnostic in &decoded.scene.diagnostics {
        println!("diagnostic: {}", diagnostic.reason);
    }

    let mut renderer = Renderer::new()?;
    let gpu = renderer.upload_scene(&decoded.scene)?;
    let camera = OrbitCamera::framing(decoded.scene.bounds, 16.0 / 9.0);
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
