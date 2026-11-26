//! Loading a decoded model resource and its external textures.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use lforge_model::{self as decoded, TextureProvider, TextureReference, TextureResolution};
use lforge_scene::Scene;
use lforge_texture::StoreSet;

use super::Access;

const MAX_CACHED_ROOTS: usize = 4;
/// A model is decoded from in-memory segments. Native page metadata bounds
/// the exact read; the fallback for a resource without metadata uses this
/// operation limit.
const MAX_MODEL_BYTES: u64 = 256 * 1024 * 1024;

static STORES: LazyLock<Mutex<HashMap<PathBuf, Arc<StoreSet>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct LoadedModel {
    pub name: String,
    pub scene: Scene,
    pub completeness: decoded::ModelCompleteness,
    /// Whether the system/graphics boundary came from native page metadata or
    /// from the controlled standalone-resource inference.
    pub exact_layout: bool,
}

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
                    return TextureResolution::Failed("the texture descriptor disappeared".into());
                };
                match store.level(
                    *texture_index,
                    0,
                    &std::sync::atomic::AtomicBool::new(false),
                ) {
                    Ok(level) => TextureResolution::Resolved(decoded::ResolvedTexture {
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

struct ResourceBytes {
    system: Vec<u8>,
    graphics: Vec<u8>,
    exact: bool,
}

/// Content check used before opening a recovered resource as a model. It
/// reads the resource but does not decode its geometry.
pub fn is_drawable_resource(path: &Path, access: &Access) -> bool {
    let Ok(resource) = read_resource(path, access) else {
        return false;
    };
    decoded::has_drawable(&resource.system, &resource.graphics)
}

/// Reads a resource through the existing streaming archive layer. A native
/// chunked resource uses the exact page split; only a resource without
/// authoritative metadata falls back to the controlled boundary inference.
pub fn load(path: &Path, access: &Access, gta_root: Option<&Path>) -> Result<LoadedModel, String> {
    let resource = read_resource(path, access)?;
    let stores = match gta_root {
        Some(root) => match texture_stores(root) {
            Ok(stores) => Some(Stores(stores)),
            Err(err) => {
                log::warn!("texture stores are unavailable: {err}");
                None
            }
        },
        None => None,
    };
    let decoded = match &stores {
        Some(provider) => decoded::decode(&resource.system, &resource.graphics, provider),
        None => decoded::decode(&resource.system, &resource.graphics, &decoded::NoTextures),
    }
    .map_err(|err| err.to_string())?;
    finish(path, resource.exact, decoded)
}

fn read_resource(path: &Path, access: &Access) -> Result<ResourceBytes, String> {
    let binary = super::open_binary_with(path, access)
        .map_err(|err| format!("could not open the resource: {err}"))?;
    let source = binary.source;
    if let Some(split) = super::resource_split_with(path, access, &source)
        .map_err(|err| format!("the native resource layout is invalid: {err}"))?
    {
        let total = split
            .system_len
            .checked_add(split.graphics_len)
            .ok_or_else(|| "the native resource layout overflows".to_string())?;
        if total > MAX_MODEL_BYTES {
            return Err(format!(
                "the native resource needs {total} bytes, more than the {MAX_MODEL_BYTES}-byte model limit"
            ));
        }
        return Ok(ResourceBytes {
            system: read_exact(&source, 0, split.system_len)?,
            graphics: read_exact(&source, split.system_len, split.graphics_len)?,
            exact: true,
        });
    }
    if source.len() > MAX_MODEL_BYTES {
        return Err(format!(
            "the resource is {} bytes; no native page metadata is available and the {MAX_MODEL_BYTES}-byte inference limit was exceeded",
            source.len()
        ));
    }
    let mut bytes = Vec::with_capacity(source.len() as usize);
    source
        .clone()
        .read_to_end(&mut bytes)
        .map_err(|err| format!("could not read the resource: {err}"))?;
    let split = decoded::split_resource(&bytes)
        .ok_or_else(|| "this resource has no drawable graphics segment".to_string())?;
    let (system, graphics) = bytes.split_at(split.system_len);
    Ok(ResourceBytes {
        system: system.to_vec(),
        graphics: graphics.to_vec(),
        exact: false,
    })
}

fn read_exact(source: &lforge_binary::Source, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut source = source
        .slice(offset, len)
        .map_err(|err| format!("could not slice the resource segment: {err}"))?;
    let mut bytes = Vec::with_capacity(len as usize);
    source
        .read_to_end(&mut bytes)
        .map_err(|err| format!("could not read the resource segment: {err}"))?;
    if bytes.len() as u64 != len {
        return Err(format!(
            "the resource segment holds {} bytes, expected {len}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn finish(
    path: &Path,
    exact_layout: bool,
    decoded: decoded::DecodedModel,
) -> Result<LoadedModel, String> {
    let name = decoded
        .report
        .header
        .name_text
        .clone()
        .filter(|name| !name.is_empty())
        .or_else(|| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "Model".to_string());
    Ok(LoadedModel {
        name,
        scene: decoded.scene,
        completeness: decoded.completeness,
        exact_layout,
    })
}

fn texture_stores(root: &Path) -> Result<Arc<StoreSet>, String> {
    let ttdb = root.join("data").join("ttdb");
    let scan_root = if ttdb.is_dir() {
        ttdb
    } else {
        root.to_path_buf()
    };
    {
        let cache = STORES.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(index) = cache.get(&scan_root) {
            return Ok(index.clone());
        }
    }
    let started = std::time::Instant::now();
    let index = StoreSet::scan(&scan_root)
        .map_err(|err| format!("could not scan {}: {err}", scan_root.display()))?;
    log::debug!(
        "texture stores: {} stores, {} textures indexed in {:?}",
        index.len(),
        index.texture_count(),
        started.elapsed()
    );
    let index = Arc::new(index);
    let mut cache = STORES.lock().unwrap_or_else(|err| err.into_inner());
    if cache.len() >= MAX_CACHED_ROOTS {
        cache.clear();
    }
    cache.insert(scan_root, index.clone());
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::Executable;

    /// Manual verification against a real installation. The test is ignored
    /// by default and reads only caller-supplied paths.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE, LF_TEST_EXECUTABLE and LF_TEST_GAME_ROOT"]
    fn loads_native_type_2_rows() {
        let archive = std::env::var("LF_TEST_ARCHIVE").expect("LF_TEST_ARCHIVE");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let game_root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        crate::files::archive::prepare_with(
            Path::new(&archive),
            &access,
            true,
            &crate::files::archive::Stage::default(),
            &lforge_rage9::rpf::Progress::default(),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .expect("prepare archive");
        let entries = crate::files::list_with(Path::new(&archive), &access).expect("list");
        let mut loaded_rows = 0usize;
        let mut complete_rows = 0usize;
        let mut partial_rows = 0usize;
        for entry in entries
            .iter()
            .filter(|entry| entry.type_name.starts_with("RPF9 entry, type 2"))
            .take(5)
        {
            let loaded = match load(&entry.path, &access, Some(Path::new(&game_root))) {
                Ok(loaded) => loaded,
                Err(err) => {
                    eprintln!("{}: not a model: {err}", entry.path.display());
                    continue;
                }
            };
            loaded_rows += 1;
            eprintln!(
                "{}: {} meshes, {} materials, {} textures, {} diagnostics",
                entry.path.display(),
                loaded.scene.meshes.len(),
                loaded.scene.materials.len(),
                loaded.scene.textures.len(),
                loaded.scene.diagnostics.len()
            );
            assert!(!loaded.scene.meshes.is_empty());
            assert!(loaded.scene.vertex_count() > 0);
            assert!(loaded.exact_layout, "native rows use the page split");
            for diagnostic in &loaded.scene.diagnostics {
                eprintln!("  {}", diagnostic.reason);
            }
            match &loaded.completeness.geometry {
                lforge_model::GeometryCompleteness::Complete => complete_rows += 1,
                lforge_model::GeometryCompleteness::Partial { reason } => {
                    partial_rows += 1;
                    eprintln!("  partial geometry: {reason}");
                }
                lforge_model::GeometryCompleteness::Unsupported { reason } => {
                    panic!("a loaded model cannot be unsupported: {reason}");
                }
            }
        }
        assert!(loaded_rows > 0, "no type 2 row decoded");
        assert_eq!(complete_rows + partial_rows, loaded_rows);
        eprintln!("{loaded_rows} model(s): {complete_rows} complete, {partial_rows} partial");
    }
}
