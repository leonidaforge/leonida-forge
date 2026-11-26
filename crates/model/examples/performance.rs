//! Measures loading and rendering of one actual decoded model.
//!
//! Usage:
//!   cargo run --release -p lforge-model --example performance -- \
//!     <resource.bin> <game-root>
//!
//! The numbers are headless wall-clock durations. They are not interactive
//! desktop FPS. GPU submission timing can be shorter than the GPU work.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
                match store.level(
                    *texture_index,
                    0,
                    &std::sync::atomic::AtomicBool::new(false),
                ) {
                    Ok(level) => TextureResolution::Resolved(model::ResolvedTexture {
                        level,
                        source: "store".into(),
                    }),
                    Err(err) => TextureResolution::Failed(err.to_string()),
                }
            }
            _ => TextureResolution::Ambiguous(vec![format!("{} candidates", candidates.len())]),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let resource = PathBuf::from(args.next().ok_or("missing resource path")?);
    let game_root = PathBuf::from(args.next().ok_or("missing game root")?);

    let read_started = Instant::now();
    let bytes = std::fs::read(&resource)?;
    let read = read_started.elapsed();

    let split_started = Instant::now();
    let split = model::split_resource(&bytes).ok_or("no graphics segment")?;
    let (system, graphics) = bytes.split_at(split.system_len);
    let split_time = split_started.elapsed();

    let scan_started = Instant::now();
    let cold_set = StoreSet::scan(&game_root.join("data").join("ttdb"))?;
    let cold_scan = scan_started.elapsed();
    let warm_started = Instant::now();
    let warm_set = StoreSet::scan(&game_root.join("data").join("ttdb"))?;
    let warm_scan = warm_started.elapsed();
    drop(warm_set);

    let decode_started = Instant::now();
    let decoded = model::decode(system, graphics, &Stores(Arc::new(cold_set)))?;
    let decode = decode_started.elapsed();

    let scene_bytes = decoded
        .scene
        .meshes
        .iter()
        .flat_map(|mesh| &mesh.primitives)
        .map(|primitive| {
            primitive.vertices.len() * std::mem::size_of_val(&primitive.vertices[0])
                + primitive.indices.len() * std::mem::size_of::<u32>()
        })
        .sum::<usize>()
        + decoded
            .scene
            .textures
            .iter()
            .map(|texture| texture.data.len())
            .sum::<usize>();

    println!(
        "model: {} | geometry {:?} | textures {:?}",
        decoded
            .completeness
            .selected_name
            .as_deref()
            .unwrap_or("model"),
        decoded.completeness.geometry,
        decoded.completeness.textures
    );
    println!(
        "counts: {} meshes, {} materials, {} textures, {} vertices, {} triangles",
        decoded.scene.meshes.len(),
        decoded.scene.materials.len(),
        decoded.scene.textures.len(),
        decoded.scene.vertex_count(),
        decoded.scene.triangle_count()
    );
    println!("scene allocation: {scene_bytes} bytes");
    println!(
        "load: read {read:?}, split {split_time:?}, store scan cold {cold_scan:?}, warm {warm_scan:?}, decode {decode:?}"
    );

    let init_started = Instant::now();
    let mut renderer = Renderer::new()?;
    let init = init_started.elapsed();
    let info = renderer.adapter_info();
    let upload_started = Instant::now();
    let gpu = renderer.upload_scene(&decoded.scene)?;
    let upload = upload_started.elapsed();
    println!(
        "gpu: {} ({}) | device init {init:?} | scene upload {upload:?}",
        info.name, info.backend
    );

    for (width, height) in [(1280, 720), (1920, 1080), (2560, 1440)] {
        let aspect = width as f32 / height as f32;
        let camera = OrbitCamera::framing(decoded.scene.bounds, aspect);
        for _ in 0..3 {
            renderer.render(&gpu, &camera, width, height, Background::DARK)?;
        }
        let mut readback = Vec::with_capacity(20);
        for _ in 0..20 {
            let started = Instant::now();
            let frame = renderer.render(&gpu, &camera, width, height, Background::DARK)?;
            std::hint::black_box(&frame);
            readback.push(started.elapsed());
        }
        let target = renderer.create_target(width, height)?;
        let mut gpu_only = Vec::with_capacity(20);
        for _ in 0..20 {
            let started = Instant::now();
            renderer.render_to_target(&gpu, &camera, &target, Background::DARK)?;
            gpu_only.push(started.elapsed());
        }
        println!(
            "{width}x{height}: readback median {:?} p95 {:?} | gpu-target submission median {:?} p95 {:?}",
            median(&readback),
            percentile(&readback, 0.95),
            median(&gpu_only),
            percentile(&gpu_only, 0.95)
        );
    }

    // Texture lookup cost over a key the model actually uses.
    if let Some(key) = decoded
        .report
        .shader_group
        .as_ref()
        .and_then(|group| group.shaders.first())
        .and_then(|shader| shader.slot_states.iter().find_map(|slot| slot.key))
    {
        let set = StoreSet::scan(&game_root.join("data").join("ttdb"))?;
        let started = Instant::now();
        let cold = set.find(key);
        let cold_find = started.elapsed();
        let started = Instant::now();
        for _ in 0..1000 {
            std::hint::black_box(set.find(key));
        }
        let warm_find = started.elapsed() / 1000;
        println!(
            "lookup {key:#018x}: {} candidate(s), cold {cold_find:?}, warm average {warm_find:?}",
            cold.len()
        );
    }
    Ok(())
}

fn median(values: &[Duration]) -> Duration {
    percentile(values, 0.5)
}

fn percentile(values: &[Duration], p: f64) -> Duration {
    let mut sorted = values.to_vec();
    sorted.sort();
    let index = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}
