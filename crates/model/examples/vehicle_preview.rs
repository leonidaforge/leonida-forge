//! Renders one decoded vehicle fragment to a primary WebP and a thumbnail.
//!
//! ```text
//! cargo run -p lforge-model --example vehicle_preview -- \
//!     <resource> [--textures <dir>]... --out <dir> [--name <name>] \
//!     [--model <name>] [--colors <json>] [--size <edge>] [--thumb <edge>]
//! ```
//!
//! The body geometry carries the vehicle's real materials. The class policy in
//! [`lforge_model::prepare_materials`] colours a material that has no diffuse
//! texture instead of showing the checker fallback, because a vehicle body is
//! mostly painted surfaces and a checker would be read as a damaged asset.
//!
//! The example reads only caller-supplied paths and writes only to `--out`.

use std::path::PathBuf;

use lforge_model as model;

struct Options {
    resource: PathBuf,
    textures: Vec<PathBuf>,
    output: PathBuf,
    name: String,
    model: Option<String>,
    size: u32,
    thumb: u32,
    report: bool,
    colors: Option<PathBuf>,
    crop: Option<(u32, u32, u32, u32)>,
}

fn usage() -> ! {
    eprintln!(
        "usage: vehicle_preview <resource> [--textures <dir>] --out <dir> \
[--name <name>] [--model <name>] [--colors <json>] [--size <edge>] [--thumb <edge>]"
    );
    std::process::exit(2)
}

fn parse() -> Options {
    let mut args = std::env::args_os().skip(1);
    let resource = PathBuf::from(args.next().unwrap_or_else(|| usage()));
    let mut textures = Vec::new();
    let mut output = None;
    let mut name = None;
    let mut model = None;
    let mut size = 1024;
    let mut thumb = 320;
    let mut report = false;
    let mut colors = None;
    let mut crop = None;
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        match text.as_str() {
            "--report" => report = true,
            "--colors" => colors = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
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
            "--textures" => textures.push(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
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
        colors,
        crop,
    }
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
    let stores = model::Stores::scan(&options.textures)?;
    let decoded = match &stores {
        Some(stores) => model::decode_fragment(system, graphics, stores)?,
        None => model::decode_fragment(system, graphics, &model::NoTextures)?,
    };
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
    let model_name = options.model.as_deref().unwrap_or(&options.name);
    let colors = options
        .colors
        .as_ref()
        .map(|path| model::load_colors(path))
        .unwrap_or_default();
    let (painted, textured) =
        model::prepare_materials(&mut scene, model::paint_color(model_name, &colors));
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

    println!(
        "{}: {} meshes, {} triangles, {} materials ({painted} painted, {textured} textured), primary {}x{}, thumbnail {}x{}",
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
