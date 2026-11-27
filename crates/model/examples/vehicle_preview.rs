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

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_model as model;

struct Options {
    resource: PathBuf,
    textures: Option<PathBuf>,
    output: PathBuf,
    name: String,
    model: Option<String>,
    size: u32,
    thumb: u32,
    report: bool,
    rim: Option<PathBuf>,
    tyre: Option<PathBuf>,
    wheel_diameter: f32,
    vehicle_data: Option<PathBuf>,
    colors: Option<PathBuf>,
    wheel_kits: Option<PathBuf>,
    crop: Option<(u32, u32, u32, u32)>,
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
    let mut model = None;
    let mut size = 1024;
    let mut thumb = 320;
    let mut report = false;
    let mut rim = None;
    let mut tyre = None;
    let mut wheel_diameter = 0.64f32;
    let mut vehicle_data = None;
    let mut colors = None;
    let mut wheel_kits = None;
    let mut crop = None;
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        match text.as_str() {
            "--report" => report = true,
            "--rim" => rim = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--tyre" => tyre = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--vehicle-data" => {
                vehicle_data = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())))
            }
            "--colors" => colors = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--wheel-kits" => {
                wheel_kits = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())))
            }
            "--crop" => {
                let text = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .to_string_lossy()
                    .into_owned();
                let mut parts = text.split(',').map(|part| part.parse::<u32>());
                let mut next = || parts.next().and_then(Result::ok).unwrap_or_else(|| usage());
                crop = Some((next(), next(), next(), next()));
            }
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
            "--model" => {
                model = Some(
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
        model,
        size: size.max(64),
        thumb: thumb.max(32),
        report,
        rim,
        tyre,
        wheel_diameter: wheel_diameter.max(0.2),
        vehicle_data,
        colors,
        wheel_kits,
        crop,
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
        // Glass, lights and rubber keep their class response whether or not
        // they carry a texture; only paint is replaced by the body colour.
        let shading = class_shading(surface);
        material.metallic = shading.0;
        material.roughness = shading.1;
        material.emissive = shading.2;
        if matches!(surface, Surface::Glass) {
            material.alpha_mode = lforge_scene::AlphaMode::Blend;
        }
        if material.diffuse.is_some() {
            material.base_color = [1.0, 1.0, 1.0, 1.0];
            textured += 1;
            continue;
        }
        material.base_color = class_color(surface, paint);
        material.bumpiness = 0.0;
        painted += 1;
    }
    (painted, textured)
}

/// Metalness, roughness and emissive weight per surface class.
fn class_shading(surface: Surface) -> (f32, f32, f32) {
    match surface {
        Surface::Paint => (0.45, 0.24, 0.0),
        Surface::Glass => (0.0, 0.05, 0.0),
        Surface::Emissive => (0.0, 0.2, 1.8),
        Surface::Tyre => (0.0, 0.92, 0.0),
        Surface::Default => (0.05, 0.55, 0.0),
    }
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

#[derive(Debug, Clone)]
struct VehicleInfo {
    wheel_type: String,
    wheel_scale: Option<f32>,
    wheel_scale_rear: Option<f32>,
    vehicle_type: String,
}

fn load_vehicle_info(path: &Path, model: &str) -> Option<VehicleInfo> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let entry = value.as_array()?.iter().find(|entry| {
        entry
            .get("Name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(model))
    })?;
    Some(VehicleInfo {
        wheel_type: entry
            .get("WheelType")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("VWT_SPORT")
            .to_string(),
        wheel_scale: entry
            .get("WheelScale")
            .and_then(serde_json::Value::as_f64)
            .map(|value| value as f32),
        wheel_scale_rear: entry
            .get("WheelScaleRear")
            .and_then(serde_json::Value::as_f64)
            .map(|value| value as f32),
        vehicle_type: entry
            .get("Type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("VEHICLE_TYPE_CAR")
            .to_string(),
    })
}

fn wheel_family(info: Option<&VehicleInfo>) -> Option<&'static str> {
    let Some(info) = info else {
        return Some("sport");
    };
    if info.vehicle_type.contains("BOAT")
        || info.vehicle_type.contains("PLANE")
        || info.vehicle_type.contains("HELI")
        || info.vehicle_type.contains("TRAIN")
        || info.vehicle_type.contains("SUBMARINE")
    {
        return None;
    }
    if info.vehicle_type.contains("BICYCLE") {
        return Some("bicycle");
    }
    if info.vehicle_type.contains("TRUCK") || info.vehicle_type.contains("INDUSTRIAL") {
        return Some("truck");
    }
    Some(match info.wheel_type.as_str() {
        "VWT_MUSCLE" => "muscle",
        "VWT_SUV" => "suv",
        "VWT_BIKE" => "bike",
        "VWT_HIEND" => "hiend",
        "VWT_LOWRIDER" => "lowrider",
        "VWT_TUNER" => "tuner",
        "VWT_OFFROAD" => "offroad",
        _ => "sport",
    })
}

fn load_colors(path: &Path) -> Vec<[f32; 4]> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let mut colors = Vec::new();
    for entry in value.as_array().into_iter().flatten() {
        let Some(raw) = entry.get("Colour").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let hex = raw.trim_start_matches('#');
        if hex.len() != 8 {
            continue;
        }
        let Ok(argb) = u32::from_str_radix(hex, 16) else {
            continue;
        };
        if argb >> 24 != 0xFF {
            continue;
        }
        let rgb = [(argb >> 16) as u8, (argb >> 8) as u8, argb as u8];
        if rgb.iter().all(|channel| *channel < 8) {
            continue;
        }
        colors.push([
            srgb_to_linear(rgb[0]),
            srgb_to_linear(rgb[1]),
            srgb_to_linear(rgb[2]),
            1.0,
        ]);
    }
    colors
}

fn srgb_to_linear(channel: u8) -> f32 {
    let value = f32::from(channel) / 255.0;
    if value <= 0.04045 {
        value / 12.92
    } else {
        ((value + 0.055) / 1.055).powf(2.4)
    }
}

fn color_for(name: &str, colors: &[[f32; 4]]) -> Option<[f32; 4]> {
    if colors.is_empty() {
        return None;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Some(colors[(hash % colors.len() as u64) as usize])
}

fn kit_paths(root: &Path, family: &str) -> Option<(PathBuf, PathBuf)> {
    let rim = root.join(family).join("rim.bin");
    let tyre = root.join(family).join("tyre.bin");
    (rim.is_file() && tyre.is_file()).then_some((rim, tyre))
}

/// Mounts a rim and a tyre on every wheel bone. No preview calls this: the
/// generic wheel kits fit the arches badly, so previews show the body alone.
#[allow(dead_code)]
fn attach_wheels(
    scene: &mut lforge_scene::Scene,
    stores: &Option<Stores>,
    mounts: &[model::WheelMount],
    options: &Options,
) -> Result<usize, Box<dyn std::error::Error>> {
    let vehicle_info = options.vehicle_data.as_ref().and_then(|path| {
        load_vehicle_info(path, options.model.as_deref().unwrap_or(&options.name))
    });
    let family = wheel_family(vehicle_info.as_ref());
    let mut rim = options.rim.clone();
    let mut tyre = options.tyre.clone();
    if let (Some(kits), Some(family)) = (&options.wheel_kits, family)
        && let Some((kit_rim, kit_tyre)) = kit_paths(kits, family)
    {
        rim = Some(kit_rim);
        tyre = Some(kit_tyre);
    }
    if family.is_none() {
        rim = None;
        tyre = None;
    }
    let body_min_z = scene.bounds.min.z;
    let mut rim_scene = None;
    let mut tyre_scene = None;
    for (kind, path) in [("rim", &rim), ("tyre", &tyre)] {
        let Some(path) = path else {
            continue;
        };
        let wheel_bytes = std::fs::read(path)?;
        let wheel_split = model::split_resource(&wheel_bytes)
            .ok_or_else(|| format!("{kind} has no inferable resource split"))?
            .system_len;
        let (wheel_system, wheel_graphics) = wheel_bytes.split_at(wheel_split);
        let mut wheel_part = if model::is_fragment(wheel_system, wheel_graphics) {
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
            &mut wheel_part,
            if kind == "rim" {
                [0.62, 0.63, 0.65, 1.0]
            } else {
                [0.06, 0.06, 0.07, 1.0]
            },
        );
        if kind == "rim" {
            rim_scene = Some(wheel_part);
        } else {
            tyre_scene = Some(wheel_part);
        }
    }
    // Four wheels arrive as one kit, so rim and tyre share a transform. A
    // two-wheeled body already models its own front wheel, so it takes the
    // tyre everywhere and the rim only at the rear.
    let two_wheeled = matches!(family, Some("bike" | "bicycle"));
    let mut unit = lforge_scene::Scene::default();
    if two_wheeled {
        if let Some(tyre) = &tyre_scene {
            model::append_scene(&mut unit, tyre, glam::Mat4::IDENTITY);
        }
    } else {
        for part in [&rim_scene, &tyre_scene].into_iter().flatten() {
            model::append_scene(&mut unit, part, glam::Mat4::IDENTITY);
        }
    }
    let unit_axle = model::axle_axis(unit.bounds);
    let mut wheels = 0;
    for mount in mounts {
        let geometry = (mount.pivot.z - body_min_z) * 2.0;
        let dump_scale = if mount.is_rear {
            vehicle_info
                .as_ref()
                .and_then(|info| info.wheel_scale_rear.or(info.wheel_scale))
        } else {
            vehicle_info.as_ref().and_then(|info| info.wheel_scale)
        };
        let diameter = if matches!(family, Some("bike" | "bicycle")) {
            // The body already sits on its own wheels, so the mount height
            // measures the real tyre radius.
            let dump = dump_scale.map(|scale| scale * 1.6).unwrap_or(0.0);
            geometry.max(dump).max(0.35).clamp(0.3, 0.7)
        } else {
            let dump = dump_scale.map(|scale| scale * 2.2).unwrap_or(0.0);
            options
                .wheel_diameter
                .max(geometry)
                .max(dump)
                .clamp(0.22, 0.95)
        };
        // Two-wheeled tyres are modelled far wider than the fork allows.
        let width = match family {
            Some("bike") => 0.4,
            Some("bicycle") => 0.45,
            _ => 1.0,
        };
        let transform = model::wheel_transform_sized(&unit, mount, diameter, unit_axle, width);
        if !unit.meshes.is_empty() {
            model::append_scene(scene, &unit, transform);
            wheels += 1;
        }
        if two_wheeled
            && mount.is_rear
            && let Some(rim_part) = &rim_scene
        {
            let rim_axle = model::axle_axis(rim_part.bounds);
            // Seat the rim inside the tyre instead of around it.
            let rim_transform =
                model::wheel_transform_sized(rim_part, mount, diameter * 0.62, rim_axle, width);
            model::append_scene(scene, rim_part, rim_transform);
            wheels += 1;
        }
    }
    Ok(wheels)
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
    let (painted, textured) = prepare_vehicle_materials(
        &mut scene,
        color_for(
            options.model.as_deref().unwrap_or(&options.name),
            &options
                .colors
                .as_ref()
                .map(|path| load_colors(path))
                .unwrap_or_default(),
        )
        .unwrap_or_else(|| paint_for(&options.name)),
    );
    if scene.meshes.is_empty() {
        return Err("the fragment decoded no meshes".into());
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
    if let Some((x, y, w, h)) = options.crop {
        let patch = image::imageops::crop_imm(&image, x, y, w, h).to_image();
        let zoom =
            image::imageops::resize(&patch, w * 3, h * 3, image::imageops::FilterType::Nearest);
        zoom.save(options.output.join(format!("{}-crop.png", options.name)))?;
    }

    let thumb = image::imageops::resize(
        &image,
        options.thumb,
        options.thumb,
        image::imageops::FilterType::Lanczos3,
    );
    let thumb_path = options.output.join(format!("{}-thumb.webp", options.name));
    thumb.save(&thumb_path)?;

    let mount_count = mounts.len();
    let wheels = 0;
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
