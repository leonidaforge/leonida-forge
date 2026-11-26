//! Loading a decoded model resource and its external textures.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use lforge_rage9::model::{self as decoded, TextureProvider, TextureReference, TextureResolution};
use lforge_rage9::texture_store::{Resolution, TextureStoreIndex};
use lforge_scene::Scene;

use super::Access;

const MAX_CACHED_ROOTS: usize = 4;

static STORES: LazyLock<Mutex<HashMap<PathBuf, Arc<TextureStoreIndex>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct LoadedModel {
    pub name: String,
    pub scene: Scene,
}

struct Stores(Arc<TextureStoreIndex>);

impl TextureProvider for Stores {
    fn resolve(&self, reference: &TextureReference) -> TextureResolution {
        match self.0.resolve(reference.key64) {
            Resolution::Missing => TextureResolution::Missing,
            Resolution::Unique(texture) => match self.0.decode(&texture) {
                Ok(texture) => TextureResolution::Resolved(texture),
                Err(err) => TextureResolution::Failed(err.to_string()),
            },
            Resolution::Ambiguous(candidates) => {
                TextureResolution::Ambiguous(candidates.iter().map(|t| t.describe()).collect())
            }
        }
    }
}

/// Content check used before opening a recovered resource as a model. It
/// reads the resource but does not decode its geometry.
pub fn is_drawable_resource(path: &Path, access: &Access) -> bool {
    let Ok(bytes) = super::read_with(path, access) else {
        return false;
    };
    let Some(split) = decoded::split_resource(&bytes) else {
        return false;
    };
    let (system, graphics) = bytes.split_at(split.system_len);
    decoded::has_drawable(system, graphics)
}

/// Reads a resource through the existing archive layer, infers its segment
/// boundary, and decodes the drawable. `gta_root` is the configured game
/// folder; its `data/ttdb` stores supply external textures.
pub fn load(path: &Path, access: &Access, gta_root: Option<&Path>) -> Result<LoadedModel, String> {
    let bytes = super::read_with(path, access)
        .map_err(|err| format!("could not read the resource: {err}"))?;
    let split = decoded::split_resource(&bytes)
        .ok_or_else(|| "this resource has no drawable graphics segment".to_string())?;
    let (system, graphics) = bytes.split_at(split.system_len);
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
        Some(provider) => decoded::decode(system, graphics, provider),
        None => decoded::decode(system, graphics, &decoded::NoTextures),
    }
    .map_err(|err| err.to_string())?;
    finish(path, decoded)
}

fn finish(path: &Path, decoded: decoded::DecodedModel) -> Result<LoadedModel, String> {
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
    })
}

fn texture_stores(root: &Path) -> Result<Arc<TextureStoreIndex>, String> {
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
    let index = TextureStoreIndex::scan(&scan_root)
        .map_err(|err| format!("could not scan {}: {err}", scan_root.display()))?;
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
    fn loads_a_native_type_2_row() {
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
        let entry = entries
            .iter()
            .find(|entry| entry.type_name.starts_with("RPF9 entry, type 2"))
            .expect("a type 2 row");
        let loaded = load(&entry.path, &access, Some(Path::new(&game_root))).expect("load");
        assert!(!loaded.scene.meshes.is_empty());
        assert!(loaded.scene.vertex_count() > 0);
    }
}
