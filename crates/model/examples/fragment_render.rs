//! Decodes a fragment, reports its components and meshes, and renders the
//! assembled static representation offscreen, without any desktop dependency.
//!
//! ```text
//! cargo run -p lforge-model --example fragment_render -- \
//!     <resource> --split <hex|infer> [--textures <dir>] [--out <dir>] \
//!     [--size <w>x<h>] [--hide-mesh <index>]...
//! ```
//!
//! The report separates the levels the model uses: one component per member
//! drawable, one mesh per model of the selected LOD, and one primitive per
//! geometry record. `--hide-mesh` repeats to render the scene without selected
//! meshes, which is how a caller checks that the parts are distinct.
//!
//! The example reads only caller-supplied paths and writes only to `--out`.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use lforge_model as model;

struct Options {
    resource: PathBuf,
    split: usize,
    textures: Option<PathBuf>,
    output: Option<PathBuf>,
    size: (u32, u32),
    hidden: Vec<usize>,
}

fn usage() -> ! {
    eprintln!(
        "usage: fragment_render <resource> --split <hex|infer> [--textures <dir>] [--out <dir>] \
[--size <w>x<h>] [--hide-mesh <index>]..."
    );
    std::process::exit(2)
}

fn parse() -> Options {
    let mut args = std::env::args_os().skip(1);
    let resource = PathBuf::from(args.next().unwrap_or_else(|| usage()));
    let mut split = None;
    let mut textures = None;
    let mut output = None;
    let mut size = (1280u32, 720u32);
    let mut hidden = Vec::new();
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        match text.as_str() {
            "--split" => {
                let value = args.next().unwrap_or_else(|| usage());
                let value = value.to_string_lossy();
                split = Some(if value.eq_ignore_ascii_case("infer") {
                    0usize
                } else {
                    usize::from_str_radix(value.trim_start_matches("0x"), 16)
                        .unwrap_or_else(|_| panic!("--split is not hexadecimal: {value}"))
                });
            }
            "--textures" => textures = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--out" => output = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--hide-mesh" => {
                let value = args.next().unwrap_or_else(|| usage());
                hidden.push(
                    value
                        .to_string_lossy()
                        .parse()
                        .unwrap_or_else(|_| panic!("--hide-mesh is not an index: {value:?}")),
                );
            }
            "--size" => {
                let value = args.next().unwrap_or_else(|| usage());
                let value = value.to_string_lossy();
                let (width, height) = value
                    .split_once('x')
                    .unwrap_or_else(|| panic!("--size is not WxH: {value}"));
                size = (
                    width
                        .parse()
                        .unwrap_or_else(|_| panic!("bad width: {width}")),
                    height
                        .parse()
                        .unwrap_or_else(|_| panic!("bad height: {height}")),
                );
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    Options {
        resource,
        // `0` is never a valid split, so it stands for "infer".
        split: split.unwrap_or_else(|| usage()),
        textures,
        output,
        size,
        hidden,
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
                        source: format!(
                            "{}#{index}",
                            self.0
                                .path(store_index)
                                .map(|path| path.display().to_string())
                                .unwrap_or_else(|| "texture store".into())
                        ),
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse();
    let bytes = std::fs::read(&options.resource)?;
    let split = if options.split == 0 {
        model::split_resource(&bytes)
            .ok_or("the resource has no inferable system/graphics boundary")?
            .system_len
    } else {
        options.split
    };
    if split >= bytes.len() {
        return Err(format!("the split {split:#x} is not inside the resource").into());
    }
    let (system, graphics) = bytes.split_at(split);
    if !model::is_fragment(system, graphics) {
        return Err("the resource is not a supported fragment".into());
    }
    let stores = match &options.textures {
        None => None,
        Some(root) => {
            let set = lforge_texture::StoreSet::scan(root)
                .map_err(|err| format!("could not scan {}: {err}", root.display()))?;
            println!(
                "textures: {} store(s), {} descriptor(s) from {}",
                set.len(),
                set.texture_count(),
                root.display()
            );
            Some(Stores(set))
        }
    };
    let decoded = match &stores {
        Some(stores) => model::decode_fragment(system, graphics, stores),
        None => model::decode_fragment(system, graphics, &model::NoTextures),
    }?;
    let scene = &decoded.scene;
    println!(
        "fragment {:?}: {} component(s), {} mesh(es), split {split:#x}, root counts {:?}, {} unexplained root pointer(s), named fragment {}",
        decoded.report.name(),
        decoded.components.len(),
        scene.meshes.len(),
        decoded.report.header.counts,
        decoded.report.header.unexplained_present(),
        decoded.report.named_fragment
    );
    println!("completeness: {:?}", decoded.completeness);
    for component in &decoded.components {
        println!(
            "  component {} {:?}: lod {:?}, drawable +{:#x}, meshes {:?}, {} primitive(s), {} vertices, {} triangles, {:?}",
            component.index,
            component.name,
            component.lod,
            component.drawable_at,
            component.meshes,
            component.primitives,
            component.vertices,
            component.triangles,
            component.status
        );
    }
    for (index, mesh) in scene.meshes.iter().enumerate() {
        println!(
            "  mesh {index} {:?}: {} primitive(s), {} material(s) referenced",
            mesh.name,
            mesh.primitives.len(),
            mesh.primitives
                .iter()
                .map(|primitive| primitive.material)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
    }
    println!(
        "scene: {} vertices, {} triangles, {} material(s), {} texture(s), bounds {:?}",
        scene.vertex_count(),
        scene.triangle_count(),
        scene.materials.len(),
        scene.textures.len(),
        scene.bounds
    );
    let bindings = decoded.texture_bindings.len();
    let resolved = decoded
        .texture_bindings
        .iter()
        .filter(|binding| matches!(binding.status, model::TextureBindingStatus::Resolved))
        .count();
    let reconstructed = decoded
        .texture_bindings
        .iter()
        .filter(|binding| binding.texture.is_some())
        .count();
    println!("textures: {bindings} binding(s), {resolved} resolved, {reconstructed} reconstructed");
    for diagnostic in &scene.diagnostics {
        println!("  diagnostic: {}", diagnostic.reason);
    }

    let Some(output) = &options.output else {
        return Ok(());
    };
    std::fs::create_dir_all(output)?;
    let mut renderer = lforge_renderer::Renderer::new()?;
    let adapter = renderer.adapter_info().clone();
    println!(
        "renderer: {} ({:?}, {:?})",
        adapter.name, adapter.device_type, adapter.backend
    );
    let mut shown = scene.clone();
    for index in &options.hidden {
        if *index < shown.meshes.len() {
            shown.meshes[*index].primitives.clear();
        }
    }
    let gpu = renderer.upload_scene(&shown)?;
    let camera = lforge_renderer::OrbitCamera::framing(
        shown.bounds,
        options.size.0 as f32 / options.size.1 as f32,
    );
    let frame = renderer.render(
        &gpu,
        &camera,
        options.size.0,
        options.size.1,
        lforge_renderer::Background::DARK,
    )?;
    let suffix = if options.hidden.is_empty() {
        "full".to_string()
    } else {
        format!(
            "without{}",
            options
                .hidden
                .iter()
                .map(|index| format!("-mesh{index}"))
                .collect::<String>()
        )
    };
    let name = format!(
        "{}-{suffix}.png",
        options
            .resource
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "fragment".into())
    );
    let path = output.join(name);
    image::RgbaImage::from_raw(frame.width, frame.height, frame.pixels)
        .ok_or("the frame is not RGBA8")?
        .save(&path)?;
    println!("wrote {}", path.display());
    Ok(())
}
