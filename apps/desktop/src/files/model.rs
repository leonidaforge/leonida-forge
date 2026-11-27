//! Loading a decoded model resource and its external textures.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

use lforge_model::{self as decoded, TextureProvider, TextureReference, TextureResolution};
use lforge_scene::Scene;
use lforge_texture::StoreSet;

use super::Access;

const MAX_CACHED_ROOTS: usize = 4;
/// A model is decoded from a bounded in-memory copy of its native segments.
/// The drawable decoder needs random access across the graphics segment for
/// vertex buffers, index buffers and embedded textures, so the complete
/// segments are materialized rather than read one small range at a time.
/// Native page metadata bounds the exact read; a standalone resource uses the
/// same limit before its boundary is inferred.
const MAX_MODEL_BYTES: u64 = 256 * 1024 * 1024;

static STORES: LazyLock<Mutex<HashMap<PathBuf, Arc<StoreSet>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Aggregate ownership of model source buffers. The permit lives in
/// `ResourceBytes`, so a source copy is counted until decoding has finished.
static MODEL_SOURCE_BUDGET: LazyLock<Arc<MemoryBudget>> =
    LazyLock::new(|| Arc::new(MemoryBudget::new(MAX_MODEL_BYTES)));

pub struct LoadedModel {
    pub name: String,
    pub scene: Scene,
    pub completeness: decoded::ModelCompleteness,
    pub texture_bindings: Vec<decoded::TextureBindingReport>,
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

/// A weighted semaphore for model source buffers. The generic 64 MiB
/// materialization policy applies to whole-file helpers; a native drawable
/// may legitimately need more, so this model-specific policy caps the sum of
/// live source copies at the same 256 MiB upper bound.
struct MemoryBudget {
    capacity: u64,
    used: Mutex<u64>,
    released: Condvar,
}

struct MemoryPermit {
    budget: Arc<MemoryBudget>,
    bytes: u64,
}

impl MemoryBudget {
    fn new(capacity: u64) -> Self {
        Self {
            capacity,
            used: Mutex::new(0),
            released: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>, bytes: u64, cancel: &AtomicBool) -> Result<MemoryPermit, String> {
        if bytes > self.capacity {
            return Err(format!(
                "the resource needs {bytes} bytes, more than the {}-byte model source budget",
                self.capacity
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut used = self.used.lock().unwrap_or_else(|err| err.into_inner());
        while used
            .checked_add(bytes)
            .is_none_or(|total| total > self.capacity)
        {
            if cancel.load(Ordering::Relaxed) {
                return Err("the model load was cancelled while waiting for source memory".into());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for model source memory".into());
            }
            used = self
                .released
                .wait_timeout(used, Duration::from_millis(50))
                .unwrap_or_else(|err| err.into_inner())
                .0;
        }
        *used += bytes;
        Ok(MemoryPermit {
            budget: self.clone(),
            bytes,
        })
    }
}

impl Drop for MemoryPermit {
    fn drop(&mut self) {
        let mut used = self
            .budget
            .used
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *used = used.saturating_sub(self.bytes);
        self.budget.released.notify_all();
    }
}

struct ResourceBytes {
    bytes: Vec<u8>,
    system_len: usize,
    exact: bool,
    /// Keeps the source allocation charged to the model source budget for as
    /// long as the decoder can still read it.
    _permit: MemoryPermit,
}

impl ResourceBytes {
    fn system(&self) -> &[u8] {
        &self.bytes[..self.system_len]
    }

    fn graphics(&self) -> &[u8] {
        &self.bytes[self.system_len..]
    }
}

/// Content check used before opening a recovered resource as a model. It
/// reads the resource but does not decode its geometry.
pub fn is_drawable_resource(path: &Path, access: &Access) -> bool {
    let Ok(resource) = read_resource_with_cancel(path, access, &AtomicBool::new(false)) else {
        return false;
    };
    decoded::has_drawable(resource.system(), resource.graphics())
}

/// Loads a model and abandons the wait for source memory when `cancel` is set.
pub fn load_with_cancel(
    path: &Path,
    access: &Access,
    gta_root: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<LoadedModel, String> {
    let resource = read_resource_with_cancel(path, access, cancel)?;
    if cancel.load(Ordering::Relaxed) {
        return Err("the model load was cancelled".into());
    }
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
        Some(provider) => decoded::decode(resource.system(), resource.graphics(), provider),
        None => decoded::decode(resource.system(), resource.graphics(), &decoded::NoTextures),
    }
    .map_err(|err| err.to_string())?;
    finish(path, resource.exact, decoded)
}

fn read_resource_with_cancel(
    path: &Path,
    access: &Access,
    cancel: &AtomicBool,
) -> Result<ResourceBytes, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("the model load was cancelled".into());
    }
    let binary = super::open_binary_with(path, access)
        .map_err(|err| format!("could not open the resource: {err}"))?;
    let source = binary.source;
    let (system_len, total, exact) = if let Some(split) =
        super::resource_split_with(path, access, &source)
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
        (split.system_len, total, true)
    } else {
        let total = source.len();
        if total > MAX_MODEL_BYTES {
            return Err(format!(
                "the resource is {total} bytes; no native page metadata is available and the {MAX_MODEL_BYTES}-byte inference limit was exceeded"
            ));
        }
        (0, total, false)
    };
    let permit = MODEL_SOURCE_BUDGET.acquire(total, cancel)?;
    let bytes = read_exact(&source, 0, total)?;
    if cancel.load(Ordering::Relaxed) {
        return Err("the model load was cancelled".into());
    }
    let system_len = if exact {
        usize::try_from(system_len)
            .map_err(|_| "the system segment length overflows".to_string())?
    } else {
        decoded::split_resource(&bytes)
            .ok_or_else(|| "this resource has no drawable graphics segment".to_string())?
            .system_len
    };
    Ok(ResourceBytes {
        bytes,
        system_len,
        exact,
        _permit: permit,
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
        texture_bindings: decoded.texture_bindings,
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
            let loaded = match load_with_cancel(
                &entry.path,
                &access,
                Some(Path::new(&game_root)),
                &AtomicBool::new(false),
            ) {
                Ok(loaded) => loaded,
                Err(err) => {
                    eprintln!("{}: not a model: {err}", entry.path.display());
                    continue;
                }
            };
            loaded_rows += 1;
            eprintln!(
                "{}: {} meshes, {} materials, {} textures, {} diagnostics",
                loaded.name,
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

    #[test]
    #[ignore = "requires LF_TEST_LEVELS_ARCHIVE, LF_TEST_EXECUTABLE and LF_TEST_GAME_ROOT"]
    fn loads_a_model_through_the_original_nested_archive() {
        let archive = std::env::var("LF_TEST_LEVELS_ARCHIVE").expect("LF_TEST_LEVELS_ARCHIVE");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let game_root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let archive = Path::new(&archive);
        crate::files::archive::prepare_with(
            archive,
            &access,
            true,
            &crate::files::archive::Stage::default(),
            &lforge_rage9::rpf::Progress::default(),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .expect("prepare levels.rpf");
        let folder = archive
            .join("levels")
            .join("americas")
            .join("props")
            .join("furniture");
        let rows = crate::files::list_with(&folder, &access).expect("list furniture");
        let nested = rows
            .iter()
            .find(|entry| {
                entry
                    .path
                    .file_name()
                    .is_some_and(|name| name == "Row 00005")
            })
            .expect("am_ornaments row 5");
        eprintln!(
            "nested archive: {} [{}]",
            nested.path.display(),
            nested.type_name
        );
        crate::files::archive::prepare_with(
            &nested.path,
            &access,
            true,
            &crate::files::archive::Stage::default(),
            &lforge_rage9::rpf::Progress::default(),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .expect("prepare nested archive");
        let entries = crate::files::list_with(&nested.path, &access).expect("list nested");
        let model = entries
            .iter()
            .find(|entry| entry.type_name.starts_with("RPF9 entry, type 2"))
            .expect("a type 2 row in am_ornaments");
        eprintln!("model row: {} [{}]", model.path.display(), model.type_name);
        let loaded = load_with_cancel(
            &model.path,
            &access,
            Some(Path::new(&game_root)),
            &AtomicBool::new(false),
        )
        .expect("load");
        assert!(loaded.exact_layout);
        assert!(!loaded.scene.meshes.is_empty());
        eprintln!(
            "{}: {} meshes, {} materials, {} textures, {} triangles",
            loaded.name,
            loaded.scene.meshes.len(),
            loaded.scene.materials.len(),
            loaded.scene.textures.len(),
            loaded.scene.triangle_count()
        );
    }

    #[test]
    fn an_oversized_standalone_resource_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized.bin");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_MODEL_BYTES + 1).unwrap();
        let err = load_with_cancel(&path, &Access::none(), None, &AtomicBool::new(false))
            .err()
            .expect("the oversized resource is rejected");
        assert!(err.contains("inference limit"), "{err}");
    }

    #[test]
    fn a_truncated_segment_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("short.bin");
        std::fs::write(&path, [0u8; 4]).unwrap();
        let source = lforge_binary::Source::open(&path).unwrap();
        let err = read_exact(&source, 0, 8).unwrap_err();
        assert!(err.contains("segment"), "{err}");
    }

    #[test]
    fn the_model_source_budget_rejects_an_oversized_request() {
        let budget = Arc::new(MemoryBudget::new(10));
        let err = budget
            .acquire(11, &AtomicBool::new(false))
            .err()
            .expect("over capacity");
        assert!(err.contains("model source budget"), "{err}");
    }

    #[test]
    fn the_model_source_budget_counts_live_permits_and_releases_them() {
        let budget = Arc::new(MemoryBudget::new(10));
        let permit = budget
            .acquire(6, &AtomicBool::new(false))
            .expect("first permit");
        let (sender, receiver) = std::sync::mpsc::channel();
        let waiting = budget.clone();
        let thread = std::thread::spawn(move || {
            let second = waiting
                .acquire(6, &AtomicBool::new(false))
                .expect("second permit");
            sender.send(()).unwrap();
            drop(second);
        });
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "the second permit must wait for aggregate capacity"
        );
        drop(permit);
        receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("the released permit wakes the waiter");
        thread.join().unwrap();
    }

    #[test]
    fn a_cancelled_wait_for_source_memory_returns_promptly() {
        let budget = Arc::new(MemoryBudget::new(10));
        let _permit = budget
            .acquire(10, &AtomicBool::new(false))
            .expect("full budget");
        let cancel = Arc::new(AtomicBool::new(false));
        let waiting = budget.clone();
        let flag = cancel.clone();
        let thread = std::thread::spawn(move || waiting.acquire(1, &flag));
        std::thread::sleep(std::time::Duration::from_millis(20));
        cancel.store(true, Ordering::Relaxed);
        let err = thread
            .join()
            .unwrap()
            .err()
            .expect("the cancelled wait returns an error");
        assert!(err.contains("cancelled"), "{err}");
    }
}
