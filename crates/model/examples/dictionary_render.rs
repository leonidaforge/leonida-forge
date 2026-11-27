//! Enumerates a drawable dictionary, decodes selected members and renders them
//! offscreen, without any desktop or GPUI dependency.
//!
//! This is the reproducible external consumer of the dictionary API: it uses
//! the same `lforge-model`, `lforge-texture` and `lforge-renderer` crates the
//! application uses and nothing from the application itself.
//!
//! ```text
//! cargo run -p lforge-model --example dictionary_render -- \
//!     <resource> --split <hex|infer> [--member <index>]... \
//!     [--store <path>]... [--out <dir>] [--size <w>x<h>]
//! ```
//!
//! `--split` is the system-segment length in bytes, or `infer` to derive it.
//! `--member` may be repeated; with none, the first and last drawable members
//! are rendered. `--textures` names a directory the shared texture-store scan
//! walks (normally the game root's `data/ttdb`); without it the members decode
//! without external textures. `--out` names a directory for the RGBA8 PNGs;
//! nothing is written when it is omitted.
//!
//! The example reads only caller-supplied paths and writes only to `--out`.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_model as model;

struct Options {
    resource: PathBuf,
    split: Split,
    members: Vec<usize>,
    textures: Option<PathBuf>,
    output: Option<PathBuf>,
    size: (u32, u32),
}

enum Split {
    At(usize),
    Infer,
}

fn usage() -> ! {
    eprintln!(
        "usage: dictionary_render <resource> --split <hex|infer> [--member <index>]... \
[--store <path>]... [--out <dir>] [--size <w>x<h>]"
    );
    std::process::exit(2)
}

fn parse() -> Options {
    let mut args = std::env::args_os().skip(1);
    let resource = PathBuf::from(args.next().unwrap_or_else(|| usage()));
    let mut split = None;
    let mut members = Vec::new();
    let mut textures = None;
    let mut output = None;
    let mut size = (1280u32, 720u32);
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        match text.as_str() {
            "--split" => {
                let value = args.next().unwrap_or_else(|| usage());
                let value = value.to_string_lossy();
                split = Some(if value.eq_ignore_ascii_case("infer") {
                    Split::Infer
                } else {
                    let digits = value.trim_start_matches("0x");
                    Split::At(
                        usize::from_str_radix(digits, 16)
                            .unwrap_or_else(|_| panic!("--split is not hexadecimal: {value}")),
                    )
                });
            }
            "--member" => {
                let value = args.next().unwrap_or_else(|| usage());
                members.push(
                    value
                        .to_string_lossy()
                        .parse()
                        .unwrap_or_else(|_| panic!("--member is not an index: {value:?}")),
                );
            }
            "--textures" => textures = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--out" => output = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
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
        split: split.unwrap_or_else(|| usage()),
        members,
        textures,
        output,
        size,
    }
}

/// Resolves texture keys against the shared store scan of a caller-named
/// directory. It is the smallest provider the public API needs: the scan is the
/// same one the application uses, and nothing is cached between members.
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
    let system_len = match options.split {
        Split::At(len) => len,
        Split::Infer => {
            model::split_resource(&bytes)
                .ok_or("the resource has no inferable system/graphics boundary")?
                .system_len
        }
    };
    if system_len >= bytes.len() {
        return Err(format!("the split {system_len:#x} is not inside the resource").into());
    }
    let (system, graphics) = bytes.split_at(system_len);
    if !model::is_drawable_dictionary(system, graphics) {
        return Err("the resource is not a drawable dictionary".into());
    }
    let info = model::dictionary_info(system, graphics).ok_or("no dictionary info")?;
    println!(
        "dictionary: {} members (capacity {}), empty {}, hash sorted {}, page map {:#x}, +0x10 {:#x}, +0x18 {:#x}, split {system_len:#x}",
        info.count,
        info.capacity,
        info.empty,
        info.hash_sorted,
        info.page_map,
        info.word_10,
        info.word_18
    );
    for member in &info.members {
        println!(
            "  #{} hash {:#010x} {:?} drawable {:?} state {}",
            member.index,
            member.hash,
            member.name,
            member.drawable.map(|at| format!("+{at:#x}")),
            member.state.name()
        );
    }
    for issue in &info.issues {
        println!("  issue: {issue}");
    }

    let selected = if options.members.is_empty() {
        let drawable = info
            .drawable_members()
            .map(|member| member.index)
            .collect::<Vec<_>>();
        match drawable.as_slice() {
            [] => return Err("the dictionary holds no drawable member".into()),
            [only] => vec![*only],
            [first, .., last] => vec![*first, *last],
        }
    } else {
        options.members.clone()
    };

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
    let mut renderer = lforge_renderer::Renderer::new()?;
    let adapter = renderer.adapter_info().clone();
    println!(
        "renderer: {} ({:?}, {:?})",
        adapter.name, adapter.device_type, adapter.backend
    );
    if let Some(output) = &options.output {
        std::fs::create_dir_all(output)?;
    }
    for index in selected {
        let decoded = match &stores {
            Some(stores) => model::decode_dictionary_member(system, graphics, index, stores),
            None => model::decode_dictionary_member(system, graphics, index, &model::NoTextures),
        }?;
        let scene = &decoded.scene;
        let primitives: usize = scene.meshes.iter().map(|mesh| mesh.primitives.len()).sum();
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
        println!(
            "member {} hash {:#010x} {:?}: {} mesh(es), {primitives} primitive(s), {} vertices, {} triangles, {} material(s), lod {}",
            decoded.member.index,
            decoded.member.hash,
            decoded.member.name,
            scene.meshes.len(),
            scene.vertex_count(),
            scene.triangle_count(),
            scene.materials.len(),
            decoded.lod
        );
        println!(
            "  textures: {bindings} binding(s), {resolved} resolved, {reconstructed} reconstructed; geometry {:?}; textures {:?}",
            decoded.completeness.geometry, decoded.completeness.textures
        );
        for diagnostic in &scene.diagnostics {
            println!("  diagnostic: {}", diagnostic.reason);
        }
        if let Some(output) = &options.output {
            let gpu = renderer.upload_scene(scene)?;
            let camera = lforge_renderer::OrbitCamera::framing(
                scene.bounds,
                options.size.0 as f32 / options.size.1 as f32,
            );
            let frame = renderer.render(
                &gpu,
                &camera,
                options.size.0,
                options.size.1,
                lforge_renderer::Background::DARK,
            )?;
            let name = format!("{}-member{}.png", stem(&options.resource), index);
            let path = output.join(name);
            image::RgbaImage::from_raw(frame.width, frame.height, frame.pixels)
                .ok_or("the frame is not RGBA8")?
                .save(&path)?;
            println!("  wrote {}", path.display());
        }
    }
    Ok(())
}

fn stem(path: &Path) -> String {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dictionary".to_string())
}
