//! Renders a decoded vehicle fragment to a primary WebP and a thumbnail.
//!
//! ```text
//! cargo run -p lforge-model --example vehicle_preview -- \
//!     <resource> [--textures <dir>] --out <dir> [--name <name>] \
//!     [--size <edge>] [--thumb <edge>]
//! ```
//!
//! The body geometry carries the vehicle's real materials. Materials whose
//! texture could not be resolved are given a neutral paint colour instead of
//! the checker fallback, because a vehicle body is mostly painted surfaces and
//! the checker would be read as "damaged asset" rather than "paint".
//!
//! The example reads only caller-supplied paths and writes only to `--out`.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use lforge_model as model;

struct Options {
    resource: PathBuf,
    textures: Option<PathBuf>,
    output: PathBuf,
    name: String,
    size: u32,
    thumb: u32,
    report: bool,
    rim: Option<PathBuf>,
    tyre: Option<PathBuf>,
    wheel_diameter: f32,
}

fn usage() -> ! {
    eprintln!(
        "usage: vehicle_preview <resource> [--textures <dir>] --out <dir> \
[--name <name>] [--size <edge>] [--thumb <edge>]"
    );
    std::process::exit(2)
}

fn parse() -> Options {
    let mut args = std::env::args_os().skip(1);
    let resource = PathBuf::from(args.next().unwrap_or_else(|| usage()));
    let mut textures = None;
    let mut output = None;
    let mut name = None;
    let mut size = 1024;
    let mut thumb = 320;
    let mut report = false;
    let mut rim = None;
    let mut tyre = None;
    let mut wheel_diameter = 0.64f32;
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        match text.as_str() {
            "--report" => report = true,
            "--rim" => rim = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--tyre" => tyre = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--wheel-diameter" => {
                wheel_diameter = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .to_string_lossy()
                    .parse()
                    .unwrap_or_else(|_| panic!("--wheel-diameter is not a number"))
            }
            "--textures" => textures = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--out" => output = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--name" => {
                name = Some(
                    args.next()
                        .unwrap_or_else(|| usage())
                        .to_string_lossy()
                        .into_owned(),
                )
            }
            "--size" => {
                size = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .to_string_lossy()
                    .parse()
                    .unwrap_or_else(|_| panic!("--size is not a pixel count"))
            }
            "--thumb" => {
                thumb = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .to_string_lossy()
                    .parse()
                    .unwrap_or_else(|_| panic!("--thumb is not a pixel count"))
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    let name = name.unwrap_or_else(|| {
        resource
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vehicle".into())
    });
    Options {
        resource,
        textures,
        output: output.unwrap_or_else(|| usage()),
        name,
        size: size.max(64),
        thumb: thumb.max(32),
        report,
        rim,
        tyre,
        wheel_diameter: wheel_diameter.max(0.2),
    }
}

struct Stores(lforge_texture::StoreSet);

impl model::TextureProvider for Stores {
    fn resolve(&self, reference: &model::TextureReference) -> model::TextureResolution {
        let matches = self.0.find(reference.key64);
        match matches.as_slice() {
            [] => model::TextureResolution::Missing,
            [(store_index, index)] => {
                let (store_index, index) = (*store_index, *index);
                let store = match self.0.open(store_index) {
                    Ok(store) => store,
                    Err(err) => return model::TextureResolution::Failed(err.to_string()),
                };
                match store.level(index, 0, &AtomicBool::new(false)) {
                    Ok(level) => model::TextureResolution::Resolved(model::ResolvedTexture {
                        level,
                        source: format!("{store_index}#{index}"),
                    }),
                    Err(err) => model::TextureResolution::Failed(err.to_string()),
                }
            }
            _ => model::TextureResolution::Ambiguous(
                matches
                    .iter()
                    .map(|(store, index)| format!("{store}#{index}"))
                    .collect(),
            ),
        }
    }
}

/// Vehicle material classes, keyed by the shader hashes the vehicle preview
/// reference lists. A surface with no diffuse texture is painted in the class
/// colour instead of the checker fallback.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Surface {
    Paint,
    Glass,
    Emissive,
    Tyre,
    Default,
}

fn shader_hash(name: &str) -> Option<u32> {
    let hex = name.strip_prefix("shader ")?;
    u32::from_str_radix(hex, 16).ok()
}

fn surface(hash: Option<u32>) -> Surface {
    match hash {
        Some(
            0x4AA3_8282 | 0x03B2_7476 | 0x4D2B_05E7 | 0xC5CD_BDD2 | 0xF9FB_7331 | 0xEDE8_5B0B
            | 0xE029_BF8E | 0xC0CB_80D2,
        ) => Surface::Paint,
        Some(0xFA9C_C069 | 0xBD71_BDBF | 0x7C98_D207) => Surface::Glass,
        Some(0x5A69_3BBE | 0x2964_8098 | 0x59C1_D684 | 0xF119_F925 | 0xE515_A6E7) => {
            Surface::Emissive
        }
        Some(0x99AD_6FC9) => Surface::Tyre,
        _ => Surface::Default,
    }
}

fn class_color(surface: Surface, paint: [f32; 4]) -> [f32; 4] {
    match surface {
        Surface::Paint => paint,
        Surface::Glass => [0.12, 0.14, 0.17, 0.55],
        Surface::Emissive => [0.92, 0.90, 0.82, 1.0],
        Surface::Tyre => [0.07, 0.07, 0.08, 1.0],
        Surface::Default => [0.34, 0.35, 0.37, 1.0],
    }
}

fn prepare_vehicle_materials(scene: &mut lforge_scene::Scene, paint: [f32; 4]) -> (usize, usize) {
    let mut painted = 0;
    let mut textured = 0;
    for material in &mut scene.materials {
        let surface = surface(shader_hash(&material.name));
        material.missing_texture = false;
        if material.diffuse.is_some() {
            material.base_color = [1.0, 1.0, 1.0, 1.0];
            textured += 1;
            continue;
        }
        material.base_color = class_color(surface, paint);
        material.bumpiness = 0.0;
        if matches!(surface, Surface::Glass) {
            material.alpha_mode = lforge_scene::AlphaMode::Blend;
        }
        painted += 1;
    }
    (painted, textured)
}

/// A stable paint for a model name, so repeat renders keep their colour.
fn paint_for(name: &str) -> [f32; 4] {
    const PALETTE: [[f32; 4]; 8] = [
        [0.42, 0.09, 0.10, 1.0],
        [0.08, 0.13, 0.28, 1.0],
        [0.55, 0.57, 0.60, 1.0],
        [0.08, 0.20, 0.12, 1.0],
        [0.62, 0.52, 0.34, 1.0],
        [0.05, 0.05, 0.06, 1.0],
        [0.62, 0.25, 0.06, 1.0],
        [0.05, 0.28, 0.30, 1.0],
    ];
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    PALETTE[(hash % PALETTE.len() as u64) as usize]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse();
    let bytes = std::fs::read(&options.resource)?;
    let split = model::split_resource(&bytes)
        .ok_or("the resource has no inferable system/graphics boundary")?
        .system_len;
    if split >= bytes.len() {
        return Err(format!("the split {split:#x} is not inside the resource").into());
    }
    let (system, graphics) = bytes.split_at(split);
    if !model::is_fragment(system, graphics) {
        return Err("the resource is not a fragment".into());
    }
    let stores = match &options.textures {
        Some(root) => Some(Stores(
            lforge_texture::StoreSet::scan(root)
                .map_err(|err| format!("could not scan {}: {err}", root.display()))?,
        )),
        None => None,
    };
    let decoded = match &stores {
        Some(stores) => model::decode_fragment(system, graphics, stores)?,
        None => model::decode_fragment(system, graphics, &model::NoTextures)?,
    };
    let mounts = decoded
        .components
        .first()
        .map(|component| model::wheel_mounts(system, component.drawable_at))
        .unwrap_or_default();
    if options.report {
        for component in &decoded.components {
            println!(
                "component {} drawable +{:#x}: {} mount(s)",
                component.index,
                component.drawable_at,
                model::wheel_mounts(system, component.drawable_at).len()
            );
        }
    }
    let mut scene = decoded.scene;
    if options.report {
        for (index, material) in scene.materials.iter().enumerate() {
            println!(
                "material {index} {:?}: base {:?}, diffuse {:?}, normal {:?}, specular {:?}, missing {} , alpha {:?}",
                material.name,
                material.base_color,
                material.diffuse,
                material.normal,
                material.specular,
                material.missing_texture,
                material.alpha_mode
            );
        }
        for binding in &decoded.texture_bindings {
            println!(
                "binding {:?} {:?} key {:#018x} status {:?} texture {:?}",
                binding.material, binding.semantic, binding.key64, binding.status, binding.texture
            );
        }
    }
    let (painted, textured) = prepare_vehicle_materials(&mut scene, paint_for(&options.name));
    if scene.meshes.is_empty() {
        return Err("the fragment decoded no meshes".into());
    }
    let mut wheels = 0;
    for (kind, path) in [("rim", &options.rim), ("tyre", &options.tyre)] {
        let Some(path) = path else {
            continue;
        };
        let wheel_bytes = std::fs::read(path)?;
        let wheel_split = model::split_resource(&wheel_bytes)
            .ok_or_else(|| format!("{kind} has no inferable resource split"))?
            .system_len;
        let (wheel_system, wheel_graphics) = wheel_bytes.split_at(wheel_split);
        let mut wheel_scene = if model::is_fragment(wheel_system, wheel_graphics) {
            match &stores {
                Some(stores) => model::decode_fragment(wheel_system, wheel_graphics, stores)?.scene,
                None => {
                    model::decode_fragment(wheel_system, wheel_graphics, &model::NoTextures)?.scene
                }
            }
        } else {
            match &stores {
                Some(stores) => model::decode(wheel_system, wheel_graphics, stores)?.scene,
                None => model::decode(wheel_system, wheel_graphics, &model::NoTextures)?.scene,
            }
        };
        prepare_vehicle_materials(
            &mut wheel_scene,
            if kind == "rim" {
                [0.62, 0.63, 0.65, 1.0]
            } else {
                [0.06, 0.06, 0.07, 1.0]
            },
        );
        for mount in &mounts {
            let transform = model::wheel_transform(&wheel_scene, mount, options.wheel_diameter);
            model::append_scene(&mut scene, &wheel_scene, transform);
            wheels += 1;
        }
    }
    std::fs::create_dir_all(&options.output)?;

    let mut renderer = lforge_renderer::Renderer::new()?;
    let gpu = renderer.upload_scene(&scene)?;
    let camera = lforge_renderer::OrbitCamera::framing(scene.bounds, 1.0);
    let frame = renderer.render(
        &gpu,
        &camera,
        options.size,
        options.size,
        lforge_renderer::Background::Transparent,
    )?;
    let primary = options
        .output
        .join(format!("{}-primary.webp", options.name));
    let image = image::RgbaImage::from_raw(frame.width, frame.height, frame.pixels)
        .ok_or("the frame is not RGBA8")?;
    image.save(&primary)?;

    let thumb = image::imageops::resize(
        &image,
        options.thumb,
        options.thumb,
        image::imageops::FilterType::Lanczos3,
    );
    let thumb_path = options.output.join(format!("{}-thumb.webp", options.name));
    thumb.save(&thumb_path)?;

    let mount_count = mounts.len();
    println!(
        "{}: {} meshes, {} triangles, {} materials ({painted} painted, {textured} textured), {mount_count} mount(s), {wheels} wheel part(s), primary {}x{}, thumbnail {}x{}",
        options.name,
        scene.meshes.len(),
        scene.triangle_count(),
        scene.materials.len(),
        options.size,
        options.size,
        options.thumb,
        options.thumb
    );
    println!("primary {}", primary.display());
    println!("thumb {}", thumb_path.display());
    Ok(())
}
