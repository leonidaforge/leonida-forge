//! Preview rendering for the discovered vehicle bodies.
//!
//! One primary image and one thumbnail are rendered per model. The body is
//! decoded from the archive on every run: the cache identity needs its digest,
//! and decoding is cheap next to rendering.
//!
//! Images are written next to a `<model>-cache.json` sidecar that records the
//! identity they were rendered from. A run reuses a pair only when the sidecar
//! matches the current identity and both files decode at the expected size.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use lforge_model as model;

use super::bodies::{self, Bodies};
use super::cache;
use super::manifest::{self, Image, ROLE_PRIMARY, ROLE_THUMBNAIL};

/// The largest metadata table read for the archive.
const MAX_METADATA: u64 = 256 * 1024 * 1024;

pub struct Options {
    pub bodies: PathBuf,
    pub output: PathBuf,
    pub archive: Option<PathBuf>,
    pub executable: Option<PathBuf>,
    pub textures: Vec<PathBuf>,
    pub colors: Option<PathBuf>,
    pub size: u32,
    pub thumb: u32,
    pub only: Option<String>,
    pub force: bool,
    pub limit: Option<usize>,
}

/// The policy version the identity records.
pub fn policy_version() -> u32 {
    model::POLICY_VERSION
}

/// How one model's render went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Rendered,
    Reused,
}

pub fn run(options: &Options) -> Result<(), String> {
    let bodies = bodies::read(&options.bodies)?;
    let archive = archive_path(options, &bodies)?;
    if bodies.models.is_empty() {
        return Err("the association document holds no models".to_string());
    }
    let colors = options
        .colors
        .as_ref()
        .map(|path| {
            let bytes = std::fs::read(path)
                .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
            Ok::<_, String>((
                cache::sha256(&bytes),
                model::parse_colors(&String::from_utf8_lossy(&bytes)),
            ))
        })
        .transpose()?;
    let (colors_sha256, colors) = match colors {
        Some((digest, colors)) => (digest, colors),
        None => (String::new(), Vec::new()),
    };
    let mut textures = Vec::with_capacity(options.textures.len());
    for root in &options.textures {
        let label = root
            .canonicalize()
            .unwrap_or_else(|_| root.clone())
            .to_string_lossy()
            .into_owned();
        textures.push((label, cache::digest_root(root)));
    }
    let stores = model::Stores::scan(&options.textures)?;
    std::fs::create_dir_all(&options.output)
        .map_err(|err| format!("cannot create {}: {err}", options.output.display()))?;

    let mut renderer = lforge_renderer::Renderer::new().map_err(|err| err.to_string())?;
    let mut archives = ArchiveCache::default();
    let mut images = Vec::with_capacity(bodies.models.len() * 2);
    let mut rendered = 0usize;
    let mut reused = 0usize;
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut considered = 0usize;
    for association in &bodies.models {
        if let Some(only) = &options.only
            && !association.model.eq_ignore_ascii_case(only)
        {
            continue;
        }
        if let Some(limit) = options.limit
            && considered >= limit
        {
            break;
        }
        considered += 1;
        let outcome = render_model(
            association,
            &archive,
            options,
            &mut archives,
            stores.as_ref(),
            &colors,
            &colors_sha256,
            &textures,
            &mut renderer,
            &mut images,
        );
        match outcome {
            Ok(Outcome::Rendered) => rendered += 1,
            Ok(Outcome::Reused) => reused += 1,
            Err(err) => {
                eprintln!("{}: {err}", association.model);
                failed.push((association.model.clone(), err));
            }
        }
    }
    manifest::write(&options.output, &images)?;
    let written = manifest::read(&options.output)?;
    println!(
        "rendered {rendered}, reused {reused}, failed {}, manifest images {}",
        failed.len(),
        written.len()
    );
    for (model_name, reason) in &failed {
        println!("failed {model_name}: {reason}");
    }
    println!(
        "manifest {}",
        options.output.join(manifest::MANIFEST_FILE).display()
    );
    if rendered == 0 && reused == 0 && !failed.is_empty() {
        return Err(format!("every selected model failed: {}", failed.len()));
    }
    Ok(())
}

fn archive_path(options: &Options, bodies: &Bodies) -> Result<PathBuf, String> {
    if let Some(archive) = &options.archive {
        return Ok(archive.clone());
    }
    let _ = bodies;
    Err(
        "--archive is required: the association document names the archive but not its path"
            .to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn render_model(
    association: &bodies::Association,
    archive: &Path,
    options: &Options,
    archives: &mut ArchiveCache,
    stores: Option<&model::Stores>,
    colors: &[[f32; 4]],
    colors_sha256: &str,
    textures: &[(String, String)],
    renderer: &mut lforge_renderer::Renderer,
    images: &mut Vec<Image>,
) -> Result<Outcome, String> {
    let bytes = archives.row_bytes(archive, options.executable.as_deref(), association)?;
    let body_sha256 = cache::sha256(&bytes);
    let key = association.model.to_ascii_lowercase();
    let paint = model::paint_color(&key, colors);
    let inputs = cache::Inputs {
        body_sha256: &body_sha256,
        model: &key,
        paint,
        colors_sha256,
        textures,
        size: options.size,
        thumb: options.thumb,
    };
    let identity = cache::identity(&inputs);
    let primary_path = options.output.join(format!("{key}-primary.webp"));
    let thumb_path = options.output.join(format!("{key}-thumb.webp"));
    let cache_path = options.output.join(format!("{key}-cache.json"));

    let cached = cache::read(&cache_path);
    let hit = !options.force
        && cached.as_ref().is_some_and(|cached| {
            cached.identity == identity
                && cache::files_match(cached, &options.output)
                && cache::image_is_valid(&primary_path, options.size)
                && cache::image_is_valid(&thumb_path, options.thumb)
        });
    if !hit && !options.force {
        let reason = match &cached {
            None => "no cache entry".to_string(),
            Some(cached) if cached.identity != identity => {
                format!(
                    "the identity changed in {}",
                    identity_difference(&cached.identity, &identity)
                )
            }
            Some(_) if !cache::image_is_valid(&primary_path, options.size) => {
                "primary image is not valid".to_string()
            }
            Some(_) if !cache::image_is_valid(&thumb_path, options.thumb) => {
                "thumbnail is not valid".to_string()
            }
            Some(_) => "image files do not match the entry".to_string(),
        };
        eprintln!("cache miss {}: {reason}", association.model);
    }
    if hit {
        let (primary, thumb) = pair(
            association,
            &key,
            &primary_path,
            &thumb_path,
            options.size,
            options.thumb,
        )?;
        images.push(primary);
        images.push(thumb);
        return Ok(Outcome::Reused);
    }

    let decoded = decode(&bytes, stores)?;
    let mut scene = decoded;
    model::prepare_materials(&mut scene, paint);
    if scene.meshes.is_empty() {
        return Err("the fragment decoded no renderable mesh".to_string());
    }
    let frame = render_frame(renderer, &scene, options.size)?;
    let primary_image = image::RgbaImage::from_raw(frame.width, frame.height, frame.pixels)
        .ok_or("the frame is not RGBA8")?;
    cache::save_image_atomic(&primary_image, &primary_path)?;
    let thumb_image = image::imageops::resize(
        &primary_image,
        options.thumb,
        options.thumb,
        image::imageops::FilterType::Lanczos3,
    );
    cache::save_image_atomic(&thumb_image, &thumb_path)?;
    let files = [
        cache::fingerprint(&primary_path)?,
        cache::fingerprint(&thumb_path)?,
    ];
    cache::write(&cache_path, &identity, &files)?;
    let (primary, thumb) = pair(
        association,
        &key,
        &primary_path,
        &thumb_path,
        options.size,
        options.thumb,
    )?;
    images.push(primary);
    images.push(thumb);
    Ok(Outcome::Rendered)
}

/// The first identity field whose value differs, for a cache diagnostic.
fn identity_difference(cached: &serde_json::Value, current: &serde_json::Value) -> String {
    let (Some(cached), Some(current)) = (cached.as_object(), current.as_object()) else {
        return "the entry".to_string();
    };
    let mut fields: Vec<&String> = cached.keys().chain(current.keys()).collect();
    fields.sort();
    fields.dedup();
    for field in fields {
        if cached.get(field) != current.get(field) {
            return field.clone();
        }
    }
    "an unlisted field".to_string()
}

fn pair(
    association: &bodies::Association,
    key: &str,
    primary_path: &Path,
    thumb_path: &Path,
    size: u32,
    thumb: u32,
) -> Result<(Image, Image), String> {
    let primary = Image {
        model: association.model.clone(),
        role: ROLE_PRIMARY.to_string(),
        file: file_name(primary_path),
        width: size,
        height: size,
        sha256: file_sha256(primary_path)?,
        alt: manifest::alt_text(key, false),
    };
    let thumbnail = Image {
        model: association.model.clone(),
        role: ROLE_THUMBNAIL.to_string(),
        file: file_name(thumb_path),
        width: thumb,
        height: thumb,
        sha256: file_sha256(thumb_path)?,
        alt: manifest::alt_text(key, true),
    };
    Ok((primary, thumbnail))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    Ok(cache::sha256(&bytes))
}

fn decode(bytes: &[u8], stores: Option<&model::Stores>) -> Result<lforge_scene::Scene, String> {
    let split = model::split_resource(bytes)
        .ok_or("the resource has no inferable system/graphics boundary")?
        .system_len;
    if split >= bytes.len() {
        return Err(format!("the split {split:#x} is not inside the resource"));
    }
    let (system, graphics) = bytes.split_at(split);
    if !model::is_fragment(system, graphics) {
        return Err("the resource is not a fragment".to_string());
    }
    let decoded = match stores {
        Some(stores) => model::decode_fragment(system, graphics, stores),
        None => model::decode_fragment(system, graphics, &model::NoTextures),
    }
    .map_err(|err| err.to_string())?;
    Ok(decoded.scene)
}

fn render_frame(
    renderer: &mut lforge_renderer::Renderer,
    scene: &lforge_scene::Scene,
    size: u32,
) -> Result<lforge_renderer::Frame, String> {
    let gpu = renderer
        .upload_scene(scene)
        .map_err(|err| err.to_string())?;
    let camera = lforge_renderer::OrbitCamera::framing(scene.bounds, 1.0);
    renderer
        .render(
            &gpu,
            &camera,
            size,
            size,
            lforge_renderer::Background::Transparent,
        )
        .map_err(|err| err.to_string())
}

/// Nested archives opened during a run, so each is spooled once.
#[derive(Default)]
struct ArchiveCache {
    opened: HashMap<u32, OpenedNested>,
}

#[allow(dead_code)]
struct OpenedNested {
    resolved: crate::nested::Resolved,
    opened: crate::native::Opened,
    alternates: crate::native::Alternates,
}

impl ArchiveCache {
    fn row_bytes(
        &mut self,
        archive: &Path,
        executable: Option<&Path>,
        association: &bodies::Association,
    ) -> Result<Vec<u8>, String> {
        if let std::collections::hash_map::Entry::Vacant(slot) =
            self.opened.entry(association.archive_row)
        {
            let cancel = std::sync::atomic::AtomicBool::new(false);
            let resolved = crate::nested::resolve(
                archive,
                executable,
                &[crate::nested::Selector::Row(association.archive_row)],
                &cancel,
            )?;
            let opened = crate::native::open_metadata(&resolved.path, MAX_METADATA, executable)?;
            let alternates = crate::native::Alternates::resolve(&resolved.path, &opened.metadata);
            slot.insert(OpenedNested {
                resolved,
                opened,
                alternates,
            });
        }
        let nested = self
            .opened
            .get(&association.archive_row)
            .ok_or("the nested archive is missing from the cache")?;
        bodies::row_bytes(&nested.opened, &nested.alternates, association.row)
    }
}
