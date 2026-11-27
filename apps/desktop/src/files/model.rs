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
    /// Present when the resource was decoded as a fragment. A fragment scene
    /// is assembled from the member drawables the root references.
    pub fragment: Option<FragmentSummary>,
}

/// One decoded fragment component, as the component panel lists it.
pub struct FragmentComponentInfo {
    pub index: usize,
    pub name: String,
    pub drawable_at: usize,
    pub lod: Option<usize>,
    pub meshes: std::ops::Range<usize>,
    pub primitives: usize,
    pub vertices: usize,
    pub triangles: usize,
    pub status: String,
}

pub struct FragmentSummary {
    pub components: Vec<FragmentComponentInfo>,
    pub completeness: decoded::FragmentCompleteness,
    /// The root's four `u16` at `+0x30`, as stored.
    pub counts: [u16; 4],
    /// Root pointers whose targets the research has not identified.
    pub unexplained: usize,
}

/// Which model structure a resource turned out to hold, decided from its
/// decoded segments rather than from a file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Drawable,
    Fragment,
    Dictionary,
}

/// A drawable dictionary enumerated without decoding any member.
pub struct DictionaryResource {
    pub name: String,
    pub info: decoded::DictionaryInfo,
    /// Whether the system/graphics boundary came from native page metadata.
    pub exact_layout: bool,
}

/// One decoded dictionary member.
pub struct LoadedMember {
    pub name: String,
    pub member: decoded::DictionaryMember,
    pub scene: Scene,
    pub completeness: decoded::ModelCompleteness,
    pub texture_bindings: Vec<decoded::TextureBindingReport>,
    pub lod: usize,
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

    /// Bytes currently charged to the budget.
    #[cfg(test)]
    fn used(&self) -> u64 {
        *self.used.lock().unwrap_or_else(|err| err.into_inner())
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

/// Decides which model structure a resource holds from its decoded segments.
///
/// The declared native type selects the candidate, but the structure decides:
/// a dictionary root holds no LOD slots, a fragment root points at a member
/// drawable and names it, and a drawable holds LOD slots at zero.
///
/// The parsers overlap by construction: a dictionary contains member drawables,
/// and a fragment root can satisfy the drawable header too. The order below is
/// deliberate — the narrowest structure that accepts the bytes wins, so a
/// dictionary is not reported as a drawable merely because it holds some. Where
/// the overlap still leaves a real choice, the decoder reports it instead of
/// resolving it silently: the fragment report's `ambiguous_with_drawable` flag
/// reaches the viewer as a note.
pub fn classify_resource(
    path: &Path,
    access: &Access,
    cancel: &AtomicBool,
) -> Result<ResourceKind, String> {
    let resource = read_resource_with_cancel(path, access, cancel)?;
    let (system, graphics) = (resource.system(), resource.graphics());
    if decoded::is_drawable_dictionary(system, graphics) {
        return Ok(ResourceKind::Dictionary);
    }
    if decoded::is_fragment(system, graphics) {
        return Ok(ResourceKind::Fragment);
    }
    if decoded::has_drawable(system, graphics) {
        return Ok(ResourceKind::Drawable);
    }
    Err("the resource holds no drawable, fragment or drawable dictionary".to_string())
}

/// Enumerates a drawable dictionary's members without decoding geometry.
///
/// The source copy is released as soon as the enumeration finishes, so an
/// idle dictionary window holds no model source memory.
pub fn enumerate_dictionary(
    path: &Path,
    access: &Access,
    cancel: &AtomicBool,
) -> Result<DictionaryResource, String> {
    let resource = read_resource_with_cancel(path, access, cancel)?;
    if cancel.load(Ordering::Relaxed) {
        return Err("the dictionary load was cancelled".into());
    }
    let info = decoded::dictionary_info(resource.system(), resource.graphics())
        .ok_or_else(|| "the resource is not a drawable dictionary".to_string())?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Dictionary".to_string());
    Ok(DictionaryResource {
        name,
        info,
        exact_layout: resource.exact,
    })
}

/// Decodes one dictionary member. The resource is read again, so the window
/// holds no source copy between selections.
pub fn load_dictionary_member(
    path: &Path,
    access: &Access,
    gta_root: Option<&Path>,
    index: usize,
    cancel: &AtomicBool,
) -> Result<LoadedMember, String> {
    let resource = read_resource_with_cancel(path, access, cancel)?;
    if cancel.load(Ordering::Relaxed) {
        return Err("the member load was cancelled".into());
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
    let decoded_member = match &stores {
        Some(provider) => decoded::decode_dictionary_member(
            resource.system(),
            resource.graphics(),
            index,
            provider,
        ),
        None => decoded::decode_dictionary_member(
            resource.system(),
            resource.graphics(),
            index,
            &decoded::NoTextures,
        ),
    }
    .map_err(|err| err.to_string())?;
    let name = decoded_member
        .member
        .name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("Member {index}"));
    Ok(LoadedMember {
        name,
        member: decoded_member.member,
        scene: decoded_member.scene,
        completeness: decoded_member.completeness,
        texture_bindings: decoded_member.texture_bindings,
        lod: decoded_member.lod,
        exact_layout: resource.exact,
    })
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
    if decoded::is_fragment(resource.system(), resource.graphics()) {
        let fragment = match &stores {
            Some(provider) => {
                decoded::decode_fragment(resource.system(), resource.graphics(), provider)
            }
            None => decoded::decode_fragment(
                resource.system(),
                resource.graphics(),
                &decoded::NoTextures,
            ),
        }
        .map_err(|err| err.to_string())?;
        return finish_fragment(path, resource.exact, fragment);
    }
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
        let split = decoded::split_resource_reason(&bytes).map_err(|problem| {
            format!(
                "no native page metadata is available for this standalone resource and its system/graphics boundary cannot be inferred: {}. The file is unmeasured, not a different kind of resource; open it from its archive to use the authoritative layout.",
                problem.describe()
            )
        })?;
        split.system_len
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
        .or_else(|| file_stem_name(path))
        .unwrap_or_else(|| "Model".to_string());
    Ok(LoadedModel {
        name,
        scene: decoded.scene,
        completeness: decoded.completeness,
        texture_bindings: decoded.texture_bindings,
        exact_layout,
        fragment: None,
    })
}

fn finish_fragment(
    path: &Path,
    exact_layout: bool,
    decoded: decoded::DecodedFragment,
) -> Result<LoadedModel, String> {
    let name = decoded
        .report
        .name()
        .map(str::to_string)
        .filter(|name| !name.is_empty())
        .or_else(|| file_stem_name(path))
        .unwrap_or_else(|| "Fragment".to_string());
    let missing_textures = decoded
        .scene
        .materials
        .iter()
        .filter(|material| material.missing_texture)
        .count();
    let referenced = decoded
        .scene
        .materials
        .iter()
        .any(|material| !material.bindings.is_empty());
    let textures = if missing_textures > 0 {
        decoded::TextureCompleteness::Partial {
            missing: missing_textures,
        }
    } else if referenced {
        decoded::TextureCompleteness::Complete
    } else {
        decoded::TextureCompleteness::NotReferenced
    };
    let (geometry, mut notes) = match &decoded.completeness {
        decoded::FragmentCompleteness::SinglePrimaryDrawable => (
            decoded::GeometryCompleteness::Complete,
            vec![
                "fragment: one member drawable, decoded from its highest populated LOD".to_string(),
            ],
        ),
        decoded::FragmentCompleteness::Partial { reason } => (
            decoded::GeometryCompleteness::Partial {
                reason: reason.clone(),
            },
            vec![format!("fragment: {reason}")],
        ),
        decoded::FragmentCompleteness::Unsupported { reason } => (
            decoded::GeometryCompleteness::Unsupported {
                reason: reason.clone(),
            },
            vec![format!("fragment: {reason}")],
        ),
    };
    notes.push(format!(
        "fragment root counts at +0x30: {:?}",
        decoded.report.header.counts
    ));
    if decoded.report.header.unexplained_present() > 0 {
        notes.push(format!(
            "{} root pointer(s) reach records whose meaning is not identified",
            decoded.report.header.unexplained_present()
        ));
    }
    if decoded.report.ambiguous_with_drawable {
        notes.push(
            "the root also reads as a resource-level drawable; the member name selected the fragment interpretation"
                .to_string(),
        );
    }
    let components = decoded
        .components
        .iter()
        .map(|component| FragmentComponentInfo {
            index: component.index,
            name: component
                .name
                .clone()
                .unwrap_or_else(|| format!("component {}", component.index)),
            drawable_at: component.drawable_at,
            lod: component.lod,
            meshes: component.meshes.clone(),
            primitives: component.primitives,
            vertices: component.vertices,
            triangles: component.triangles,
            status: match &component.status {
                decoded::ComponentStatus::Decoded => "decoded".to_string(),
                decoded::ComponentStatus::Unsupported(reason) => {
                    format!("unsupported: {reason}")
                }
            },
        })
        .collect();
    let fragment = FragmentSummary {
        components,
        completeness: decoded.completeness,
        counts: decoded.report.header.counts,
        unexplained: decoded.report.header.unexplained_present(),
    };
    Ok(LoadedModel {
        name,
        scene: decoded.scene,
        completeness: decoded::ModelCompleteness {
            geometry,
            textures,
            skeleton: decoded.skeleton.clone(),
            associations: decoded.associations.clone(),
            placement: decoded.placement.clone(),
            selected_root: decoded.report.header.drawable as usize,
            selected_name: decoded.report.name().map(str::to_string),
            notes,
        },
        texture_bindings: decoded.texture_bindings,
        exact_layout,
        fragment: Some(fragment),
    })
}

fn file_stem_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// Finds a native row the explorer lists, following the folders it groups
/// rows into. Bounded so a large archive cannot be walked whole.
#[cfg(test)]
fn find_row(root: &Path, access: &Access, row: usize) -> Option<PathBuf> {
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut examined = 0usize;
    while let Some((folder, depth)) = queue.pop() {
        let entries = crate::files::list_with(&folder, access).ok()?;
        for entry in &entries {
            examined += 1;
            if examined > 65_536 {
                return None;
            }
            if entry.resource_row == u32::try_from(row).ok() {
                return Some(entry.path.clone());
            }
            // A row's path carries the folders its resolved name implies, so a
            // deep folder chain is normal rather than an error.
            if depth < 12 && entry.is_container() {
                queue.push((entry.path.clone(), depth + 1));
            }
        }
    }
    None
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
    use std::collections::BTreeMap;

    /// The archives a survey reads: `LF_TEST_ARCHIVE_LIST` names a file of
    /// paths, `LF_TEST_CHAIN_LIST` a file of census chains (`a.rpf!5!3`), and
    /// `LF_TEST_ARCHIVE_DIR` a directory of `.rpf` files. A chain list resolves
    /// to the archives that directly hold the entries, so an installation-wide
    /// census can drive the survey without extracting anything.
    pub(super) fn survey_archives() -> Vec<std::path::PathBuf> {
        if let Ok(list) = std::env::var("LF_TEST_CHAIN_LIST") {
            let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
            let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
            let access = Access::with(Arc::new(
                Executable::open(Path::new(&executable)).expect("executable"),
            ));
            let text = std::fs::read_to_string(&list).expect("chain list");
            let mut chains = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(|chain| {
                    chain
                        .rsplit_once('!')
                        .map(|(parent, _)| parent.to_string())
                        .unwrap_or_else(|| chain.to_string())
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            chains.sort();
            let mut resolved = std::collections::BTreeMap::new();
            let mut index: std::collections::HashMap<
                std::path::PathBuf,
                std::collections::HashMap<usize, std::path::PathBuf>,
            > = std::collections::HashMap::new();
            let mut paths = Vec::new();
            for chain in &chains {
                match resolve_chain(Path::new(&root), &access, chain, &mut resolved, &mut index) {
                    Some(path) => paths.push(path),
                    None => eprintln!("unresolved chain: {chain}"),
                }
            }
            return paths;
        }
        let mut paths = match std::env::var("LF_TEST_ARCHIVE_LIST") {
            Ok(list) => std::fs::read_to_string(&list)
                .expect("archive list")
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>(),
            Err(_) => {
                let directory = std::env::var("LF_TEST_ARCHIVE_DIR")
                    .expect("LF_TEST_CHAIN_LIST, LF_TEST_ARCHIVE_LIST or LF_TEST_ARCHIVE_DIR");
                std::fs::read_dir(&directory)
                    .expect("archive directory")
                    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                    .filter(|path| path.extension().is_some_and(|ext| ext == "rpf"))
                    .collect::<Vec<_>>()
            }
        };
        paths.sort();
        paths
    }

    /// Resolves a census chain (`a.rpf!5!3`) to the archive that directly holds
    /// the entry: every component but the last one.
    ///
    /// Each archive is listed once and its rows are indexed by number, so a
    /// chain list of hundreds of parents costs one walk per archive rather than
    /// one search per parent.
    pub(super) fn resolve_chain(
        root: &Path,
        access: &Access,
        chain: &str,
        resolved: &mut std::collections::BTreeMap<String, Option<std::path::PathBuf>>,
        index: &mut std::collections::HashMap<
            std::path::PathBuf,
            std::collections::HashMap<usize, std::path::PathBuf>,
        >,
    ) -> Option<std::path::PathBuf> {
        if let Some(cached) = resolved.get(chain) {
            return cached.clone();
        }
        let parts = chain.split('!').collect::<Vec<_>>();
        if parts.is_empty() {
            resolved.insert(chain.to_string(), None);
            return None;
        }
        let mut path = root.join(parts[0]);
        crate::files::archive::prepare_with(
            &path,
            access,
            true,
            &crate::files::archive::Stage::default(),
            &lforge_rage9::rpf::Progress::default(),
            &AtomicBool::new(false),
        )
        .ok()?;
        for part in &parts[1..] {
            let row: usize = part.parse().ok()?;
            if !index.contains_key(&path) {
                index.insert(path.clone(), row_index(&path, access));
            }
            path = index.get(&path)?.get(&row)?.clone();
            crate::files::archive::prepare_with(
                &path,
                access,
                true,
                &crate::files::archive::Stage::default(),
                &lforge_rage9::rpf::Progress::default(),
                &AtomicBool::new(false),
            )
            .ok()?;
        }
        resolved.insert(chain.to_string(), Some(path.clone()));
        Some(path)
    }

    /// Every native row of one archive, indexed by the number its path carries.
    pub(super) fn row_index(
        archive: &Path,
        access: &Access,
    ) -> std::collections::HashMap<usize, std::path::PathBuf> {
        let mut index = std::collections::HashMap::new();
        let mut queue = vec![(archive.to_path_buf(), 0usize)];
        let mut examined = 0usize;
        while let Some((folder, depth)) = queue.pop() {
            let Ok(entries) = crate::files::list_with(&folder, access) else {
                continue;
            };
            for entry in &entries {
                examined += 1;
                if examined > 200_000 {
                    return index;
                }
                if let Some(row) = entry.resource_row {
                    index.insert(row as usize, entry.path.clone());
                } else if depth < 12 && entry.is_container() {
                    queue.push((entry.path.clone(), depth + 1));
                }
            }
        }
        index
    }

    /// Manual verification against a real installation. The test is ignored
    /// by default and reads only caller-supplied paths.
    ///
    /// `LF_TEST_ARCHIVE` must hold type-2 drawable rows. A root archive does
    /// not: its type-2 rows are in nested archives. The census identifies
    /// `levels.rpf` row 1806 (`levels.rpf!1806`) as a 123-row archive whose
    /// type-2 rows use chunk encoding 4; extract that row to a file and point
    /// this test at it. The rows are tried until five load, so a fixture that
    /// starts with a row this build cannot read does not fail the test.
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
        let mut attempted = 0usize;
        for entry in entries
            .iter()
            .filter(|entry| entry.type_name.starts_with("RPF9 entry, type 2"))
            .take(64)
        {
            if loaded_rows == 5 {
                break;
            }
            attempted += 1;
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
                "{}: {} meshes, {} materials, {} textures, {} diagnostics [{}]",
                loaded.name,
                loaded.scene.meshes.len(),
                loaded.scene.materials.len(),
                loaded.scene.textures.len(),
                loaded.scene.diagnostics.len(),
                entry.path.display()
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
        assert!(
            loaded_rows > 0,
            "no type 2 row decoded ({attempted} attempted)"
        );
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
            .find(|entry| entry.resource_row == Some(5))
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

    /// Opens a real fragment through the shared loading path. Ignored by
    /// default; `LF_TEST_ARCHIVE`, `LF_TEST_EXECUTABLE` and
    /// `LF_TEST_GAME_ROOT` name the local inputs, and the archive supplies
    /// the page metadata the split needs.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE, LF_TEST_EXECUTABLE and LF_TEST_GAME_ROOT"]
    fn loads_a_fragment_from_a_native_type_3_row() {
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
        for entry in entries
            .iter()
            .filter(|entry| entry.type_name.starts_with("RPF9 entry, type 3"))
            .take(3)
        {
            let loaded = match load_with_cancel(
                &entry.path,
                &access,
                Some(Path::new(&game_root)),
                &AtomicBool::new(false),
            ) {
                Ok(loaded) => loaded,
                Err(err) => {
                    eprintln!("{}: not openable: {err}", entry.path.display());
                    continue;
                }
            };
            let fragment = loaded.fragment.as_ref().expect("a fragment summary");
            assert!(loaded.exact_layout);
            assert!(!fragment.components.is_empty());
            assert!(!loaded.scene.meshes.is_empty());
            for component in &fragment.components {
                eprintln!(
                    "{}: component {} {:?} lod {:?} {} mesh(es) {} vertices {} triangles {}",
                    loaded.name,
                    component.index,
                    component.name,
                    component.lod,
                    component.meshes.len(),
                    component.vertices,
                    component.triangles,
                    component.status
                );
            }
            assert!(fragment.components.iter().all(|component| {
                component
                    .meshes
                    .clone()
                    .all(|mesh| mesh < loaded.scene.meshes.len())
            }));
            loaded_rows += 1;
        }
        assert!(loaded_rows > 0, "no type 3 row opened as a fragment");
    }

    /// Enumerates a real drawable dictionary and decodes two of its members
    /// through the native archive path, so the page split comes from the
    /// archive metadata rather than from inference.
    ///
    /// Ignored by default. `LF_TEST_ARCHIVE` is the archive that holds the
    /// nested archive, `LF_TEST_NESTED_ROW` its row there, `LF_TEST_DICTIONARY_ROWS`
    /// the comma-separated row indices to open inside it, and
    /// `LF_TEST_EXECUTABLE`/`LF_TEST_GAME_ROOT` the usual local inputs.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE, LF_TEST_NESTED_ROW and LF_TEST_EXECUTABLE"]
    fn loads_members_from_native_drawable_dictionaries() {
        let archive = std::env::var("LF_TEST_ARCHIVE").expect("LF_TEST_ARCHIVE");
        let nested_row: usize = std::env::var("LF_TEST_NESTED_ROW")
            .expect("LF_TEST_NESTED_ROW")
            .parse()
            .expect("a row index");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let game_root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let rows: Vec<usize> = std::env::var("LF_TEST_DICTIONARY_ROWS")
            .expect("LF_TEST_DICTIONARY_ROWS")
            .split(',')
            .map(|value| value.trim().parse().expect("a row index"))
            .collect();
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        crate::files::archive::prepare_with(
            Path::new(&archive),
            &access,
            true,
            &crate::files::archive::Stage::default(),
            &lforge_rage9::rpf::Progress::default(),
            &AtomicBool::new(false),
        )
        .expect("prepare archive");
        let nested_path = find_row(Path::new(&archive), &access, nested_row)
            .unwrap_or_else(|| panic!("no row {nested_row} in {archive}"));
        let nested =
            crate::files::list_with(nested_path.parent().expect("a parent folder"), &access)
                .expect("list")
                .into_iter()
                .find(|entry| entry.path == nested_path)
                .expect("the nested archive");
        crate::files::archive::prepare_with(
            &nested.path,
            &access,
            true,
            &crate::files::archive::Stage::default(),
            &lforge_rage9::rpf::Progress::default(),
            &AtomicBool::new(false),
        )
        .expect("prepare the nested archive");
        let entries = crate::files::list_with(&nested.path, &access).expect("list nested");
        let mut dictionaries = 0usize;
        let mut members_rendered = 0usize;
        for entry in entries.iter().filter(|entry| {
            entry
                .resource_row
                .is_some_and(|row| rows.contains(&(row as usize)))
        }) {
            let kind = classify_resource(&entry.path, &access, &AtomicBool::new(false))
                .expect("a model resource");
            if kind != ResourceKind::Dictionary {
                continue;
            }
            let dictionary =
                enumerate_dictionary(&entry.path, &access, &AtomicBool::new(false)).expect("enum");
            assert!(dictionary.exact_layout, "native rows use the page split");
            assert!(!dictionary.info.empty, "a selected row holds members");
            // Two independent members are what the run decodes, so a row with a
            // single member cannot exercise it.
            if dictionary.info.drawable_members().count() < 2 {
                eprintln!(
                    "{}: {} member(s), not enough for the independent-decode check",
                    entry.path.display(),
                    dictionary.info.drawable_members().count()
                );
                continue;
            }
            eprintln!(
                "{}: {} members, {} drawable, page map {:#x}",
                entry.path.display(),
                dictionary.info.count,
                dictionary.info.drawable_members().count(),
                dictionary.info.page_map
            );
            let picks: Vec<usize> = dictionary
                .info
                .drawable_members()
                .take(2)
                .map(|member| member.index)
                .collect();
            let mut vertex_counts = Vec::new();
            for index in picks {
                let loaded = load_dictionary_member(
                    &entry.path,
                    &access,
                    Some(Path::new(&game_root)),
                    index,
                    &AtomicBool::new(false),
                )
                .expect("a decoded member");
                assert!(loaded.exact_layout);
                assert!(!loaded.scene.meshes.is_empty());
                assert!(loaded.scene.vertex_count() > 0);
                eprintln!(
                    "  member {} {:?}: {} vertices, {} triangles, {} material(s), geometry {:?}",
                    index,
                    loaded.member.name,
                    loaded.scene.vertex_count(),
                    loaded.scene.triangle_count(),
                    loaded.scene.materials.len(),
                    loaded.completeness.geometry
                );
                vertex_counts.push(loaded.scene.vertex_count());
                members_rendered += 1;
            }
            assert_eq!(
                vertex_counts.len(),
                2,
                "both selected members must decode independently"
            );
            dictionaries += 1;
        }
        assert!(dictionaries > 0, "no type 4 row opened as a dictionary");
        assert_eq!(members_rendered, dictionaries * 2);
    }

    #[test]
    fn a_source_permit_is_charged_and_released_with_its_owner() {
        let budget = Arc::new(MemoryBudget::new(100));
        assert_eq!(budget.used(), 0);
        let permit = budget
            .acquire(40, &AtomicBool::new(false))
            .expect("a permit inside the budget");
        assert_eq!(budget.used(), 40, "a live source is charged");
        drop(permit);
        assert_eq!(
            budget.used(),
            0,
            "the charge ends with the source it belongs to"
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

    /// Surveys every declared type-4 row in a directory of extracted archives.
    ///
    /// Ignored by default. `LF_TEST_ARCHIVE_DIR` names the directory,
    /// `LF_TEST_EXECUTABLE` names the executable that supplies the archive
    /// keys. The run reports its own coverage: how many archives were listed,
    /// how many type-4 rows were found, how many were read, how many hold a
    /// verified dictionary, the member-count distribution, and every failure
    /// with its reason.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE_DIR and LF_TEST_EXECUTABLE"]
    fn surveys_native_type_4_rows() {
        use std::collections::BTreeMap;

        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let archives = survey_archives();
        let mut listed = 0usize;
        let mut unreadable_archives = 0usize;
        let mut type_4_rows = 0usize;
        let mut read_rows = 0usize;
        let mut dictionaries = 0usize;
        let mut classified = 0usize;
        let mut empty_dictionaries = 0usize;
        let mut exact_splits = 0usize;
        let mut split_disagreements = 0usize;
        let mut inference_outcomes: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut mismatch_samples: Vec<String> = Vec::new();
        let mut resolved_samples: Vec<String> = Vec::new();
        let mut member_states: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut member_counts = BTreeMap::new();
        let mut unnamed_members = 0usize;
        let mut hash_stem_matches = 0usize;
        let mut hash_mismatches = 0usize;
        let mut name_suffixes: BTreeMap<String, usize> = BTreeMap::new();
        let mut word_10: BTreeMap<u64, usize> = BTreeMap::new();
        let mut word_18: BTreeMap<u64, usize> = BTreeMap::new();
        let mut capacities: BTreeMap<(u16, u16), usize> = BTreeMap::new();
        let mut unsorted = 0usize;
        let mut issues = 0usize;
        let mut failures: Vec<String> = Vec::new();
        // `LF_SURVEY_SELECTORS` prints the exact locator of every dictionary
        // with at least that many members.
        let selector_min: usize = std::env::var("LF_SURVEY_SELECTORS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        for archive in &archives {
            eprintln!("archive: {}", archive.display());
            let prepared = crate::files::archive::prepare_with(
                archive,
                &access,
                true,
                &crate::files::archive::Stage::default(),
                &lforge_rage9::rpf::Progress::default(),
                &cancel,
            );
            if prepared.is_err() {
                unreadable_archives += 1;
                continue;
            }
            let entries = match crate::files::list_with(archive, &access) {
                Ok(entries) => entries,
                Err(err) => {
                    unreadable_archives += 1;
                    failures.push(format!("{}: {err}", archive.display()));
                    continue;
                }
            };
            listed += 1;
            for entry in entries
                .iter()
                .filter(|entry| entry.type_name.starts_with("RPF9 entry, type 4"))
            {
                type_4_rows += 1;
                let binary = match crate::files::open_binary_with(&entry.path, &access) {
                    Ok(binary) => binary,
                    Err(err) => {
                        failures.push(format!("{}: open: {err}", entry.path.display()));
                        continue;
                    }
                };
                let source = binary.source;
                let total = source.len();
                if total > MAX_MODEL_BYTES {
                    failures.push(format!(
                        "{}: {total} bytes is over the model source limit",
                        entry.path.display()
                    ));
                    continue;
                }
                let bytes = match read_exact(&source, 0, total) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        failures.push(format!("{}: read: {err}", entry.path.display()));
                        continue;
                    }
                };
                read_rows += 1;
                let native = crate::files::resource_split_with(&entry.path, &access, &source)
                    .ok()
                    .flatten()
                    .and_then(|split| usize::try_from(split.system_len).ok());
                let inferred = decoded::split_resource(&bytes).map(|split| split.system_len);
                let system_len = native.or(inferred);
                let Some(system_len) = system_len else {
                    failures.push(format!(
                        "{}: no system/graphics boundary",
                        entry.path.display()
                    ));
                    continue;
                };
                if native.is_some_and(|native| Some(native) != inferred) {
                    split_disagreements += 1;
                    // The inferred boundary is never used for the reported
                    // results, but what it would produce decides whether a
                    // standalone open fails loudly or misreads the resource.
                    let outcome = match inferred.filter(|len| *len <= bytes.len()) {
                        None => "no candidate",
                        Some(inferred) => {
                            let (system, graphics) = bytes.split_at(inferred);
                            match decoded::dictionary_info(system, graphics) {
                                None => "no root form",
                                Some(info) => {
                                    let drawable = info.drawable_members().count();
                                    if drawable == 0 || drawable != usize::from(info.count) {
                                        "root form, members missing"
                                    } else {
                                        "root form, all members resolved"
                                    }
                                }
                            }
                        }
                    };
                    *inference_outcomes.entry(outcome).or_insert(0) += 1;
                    let line = format!(
                        "{}: native {:#x}, inferred {}, {outcome}",
                        entry.path.display(),
                        native.unwrap_or_default(),
                        inferred.map_or_else(
                            || "none".to_string(),
                            |inferred| format!("{inferred:#x}")
                        )
                    );
                    // A boundary that still resolves every member is the case
                    // that makes native metadata necessary, so it is located
                    // independently of how many other mismatches come first.
                    if outcome == "root form, all members resolved" {
                        resolved_samples.push(line.clone());
                    } else if mismatch_samples.len() < 10 {
                        mismatch_samples.push(line);
                    }
                }
                if native.is_some() {
                    exact_splits += 1;
                }
                if system_len > bytes.len() {
                    failures.push(format!(
                        "{}: the split {system_len:#x} is past the end",
                        entry.path.display()
                    ));
                    continue;
                }
                let (system, graphics) = bytes.split_at(system_len);
                let info = match decoded::dictionary_info(system, graphics) {
                    Some(info) => info,
                    None => {
                        failures.push(format!(
                            "{}: type 4 without the dictionary root form (split {system_len:#x})",
                            entry.path.display()
                        ));
                        continue;
                    }
                };
                dictionaries += 1;
                if decoded::is_drawable_dictionary(system, graphics) {
                    classified += 1;
                }
                if info.empty {
                    empty_dictionaries += 1;
                }
                if !info.hash_sorted {
                    unsorted += 1;
                }
                *member_counts.entry(info.count).or_insert(0) += 1;
                *word_10.entry(info.word_10).or_insert(0) += 1;
                *word_18.entry(info.word_18).or_insert(0) += 1;
                *capacities.entry((info.count, info.capacity)).or_insert(0) += 1;
                issues += info.issues.len();
                for member in &info.members {
                    *member_states.entry(member.state.name()).or_insert(0) += 1;
                    match &member.name {
                        None => unnamed_members += 1,
                        Some(name) => {
                            if let Some((_, suffix)) = name.rsplit_once('.') {
                                *name_suffixes
                                    .entry(format!(".{}", suffix.to_ascii_lowercase()))
                                    .or_insert(0) += 1;
                            }
                            match member.hash_matches_name {
                                Some(true) => hash_stem_matches += 1,
                                Some(false) => {
                                    hash_mismatches += 1;
                                    if failures.len() < 400 {
                                        failures.push(format!(
                                            "{}: member {} hash {:#010x} does not match {name}",
                                            entry.path.display(),
                                            member.index,
                                            member.hash
                                        ));
                                    }
                                }
                                None => {}
                            }
                        }
                    }
                }
                if !info.issues.is_empty() {
                    for issue in &info.issues {
                        failures.push(format!("{}: {issue}", entry.path.display()));
                    }
                }
                // A maintainer needs exact selectors for representative
                // dictionaries; the run prints them only when asked.
                if selector_min > 0 && usize::from(info.count) >= selector_min {
                    eprintln!(
                        "selector: {} | {} members, page map {:#x}, split {:#x}{}",
                        entry.path.display(),
                        info.count,
                        info.page_map,
                        system_len,
                        if native.is_some() { "" } else { " (inferred)" }
                    );
                }
            }
        }
        eprintln!("archives: {listed} listed, {unreadable_archives} unreadable");
        eprintln!("type-4 rows: {type_4_rows} found, {read_rows} read");
        eprintln!(
            "dictionaries: {dictionaries} verified, {classified} accepted by the classifier, {empty_dictionaries} empty, {unsorted} with an unsorted hash array"
        );
        eprintln!(
            "splits: {exact_splits} native, {split_disagreements} native/inferred disagreements"
        );
        eprintln!("inferred boundary on a disagreement: {inference_outcomes:?}");
        for line in &mismatch_samples {
            eprintln!("  mismatch: {line}");
        }
        for line in &resolved_samples {
            eprintln!("  resolved: {line}");
        }
        eprintln!("member states: {member_states:?}, {unnamed_members} unnamed");
        eprintln!(
            "member hashes: {hash_stem_matches} match the computed name hash, {hash_mismatches} do not"
        );
        eprintln!("member name suffixes: {name_suffixes:?}");
        eprintln!("member counts: {member_counts:?}");
        eprintln!("count/capacity pairs: {capacities:?}");
        eprintln!("root +0x10 words: {word_10:?}");
        eprintln!("root +0x18 words: {word_18:?}");
        eprintln!(
            "{} issue line(s), {} failure line(s)",
            issues,
            failures.len()
        );
        for line in failures.iter().take(80) {
            eprintln!("  {line}");
        }
        assert!(listed > 0, "no archive was listed");
        assert!(type_4_rows > 0, "no type-4 row was found");
        assert_eq!(member_states.values().sum::<usize>(), {
            let mut expected = 0usize;
            for (count, dictionaries) in &member_counts {
                expected += usize::from(*count) * dictionaries;
            }
            expected
        });
    }

    /// One declared-type row a survey could read.
    ///
    /// `native` records whether the system/graphics boundary came from the
    /// archive's page metadata; the reported results always use it when it is
    /// available and never treat an inferred boundary as evidence.
    pub(super) struct SurveyRow {
        pub(super) path: std::path::PathBuf,
        pub(super) bytes: Vec<u8>,
        pub(super) system_len: usize,
        pub(super) native: bool,
    }

    impl SurveyRow {
        pub(super) fn segments(&self) -> (&[u8], &[u8]) {
            self.bytes.split_at(self.system_len)
        }
    }

    /// Reads every row of `type_id` in the caller-named archives and calls
    /// `visit` for each. Returns the archives listed, the rows the metadata
    /// declares, the rows read, and the rows that could not be read.
    pub(super) fn survey_rows(
        archives: &[std::path::PathBuf],
        access: &Access,
        cancel: &AtomicBool,
        type_id: u8,
        mut visit: impl FnMut(&SurveyRow),
    ) -> (usize, usize, usize, usize) {
        let prefix = format!("RPF9 entry, type {type_id}");
        let (mut listed, mut declared, mut read, mut unreadable) = (0, 0, 0, 0);
        for archive in archives {
            eprintln!("archive: {}", archive.display());
            if crate::files::archive::prepare_with(
                archive,
                access,
                true,
                &crate::files::archive::Stage::default(),
                &lforge_rage9::rpf::Progress::default(),
                cancel,
            )
            .is_err()
            {
                continue;
            }
            let Ok(entries) = crate::files::list_with(archive, access) else {
                continue;
            };
            listed += 1;
            for entry in entries
                .iter()
                .filter(|entry| entry.type_name.starts_with(&prefix))
            {
                declared += 1;
                let Ok(binary) = crate::files::open_binary_with(&entry.path, access) else {
                    unreadable += 1;
                    continue;
                };
                let source = binary.source;
                let total = source.len();
                if total > MAX_MODEL_BYTES {
                    unreadable += 1;
                    continue;
                }
                let Ok(bytes) = read_exact(&source, 0, total) else {
                    unreadable += 1;
                    continue;
                };
                let native = crate::files::resource_split_with(&entry.path, access, &source)
                    .ok()
                    .flatten()
                    .and_then(|split| usize::try_from(split.system_len).ok());
                let inferred = decoded::split_resource(&bytes).map(|split| split.system_len);
                let boundary = native.or(inferred);
                let Some(system_len) = boundary.filter(|len| *len <= bytes.len()) else {
                    unreadable += 1;
                    continue;
                };
                read += 1;
                visit(&SurveyRow {
                    path: entry.path.clone(),
                    bytes,
                    system_len,
                    native: native.is_some(),
                });
            }
        }
        (listed, declared, read, unreadable)
    }

    /// Surveys every declared type-3 row in the caller-named archives.
    ///
    /// The question the run answers is how a fragment's static model is
    /// actually represented: the root variant, the single member drawable, and
    /// the member's own LOD slots, models, geometries and skeleton and list
    /// references. Every root slot is tested for the member-drawable form, so a
    /// fragment that carries components would be reported with the slot it
    /// carries them in.
    ///
    /// Ignored by default. `LF_TEST_ARCHIVE_LIST` names a file of extracted
    /// archives (or `LF_TEST_ARCHIVE_DIR` a directory of them) and
    /// `LF_TEST_EXECUTABLE` the executable that supplies the archive keys.
    /// `LF_SURVEY_SAMPLES` bounds the locators printed for complex rows.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE_LIST (or LF_TEST_ARCHIVE_DIR) and LF_TEST_EXECUTABLE"]
    fn surveys_native_type_3_rows() {
        use std::collections::BTreeMap;

        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let archives = survey_archives();
        let sample_limit: usize = std::env::var("LF_SURVEY_SAMPLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20);
        // `LF_SURVEY_NAME_FILTER` prints the locator of rows whose member name
        // contains the substring, so a caller can find a category of asset.
        let name_filter = std::env::var("LF_SURVEY_NAME_FILTER")
            .ok()
            .map(|value| value.to_ascii_lowercase())
            .filter(|value| !value.is_empty());
        let mut matched: Vec<String> = Vec::new();
        let mut root_shape = 0usize;
        let mut variants: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut drawable_counts: BTreeMap<usize, usize> = BTreeMap::new();
        let mut slots_holding_drawables: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut suffixed = 0usize;
        let mut suffixes: BTreeMap<String, usize> = BTreeMap::new();
        let mut counts_words: BTreeMap<[u16; 4], usize> = BTreeMap::new();
        let mut populated_lods: BTreeMap<usize, usize> = BTreeMap::new();
        let mut model_counts: BTreeMap<usize, usize> = BTreeMap::new();
        let mut geometry_counts: BTreeMap<usize, usize> = BTreeMap::new();
        let mut skeleton_present = 0usize;
        let mut list_present = 0usize;
        let mut shader_group_present = 0usize;
        let mut walk_issues = 0usize;
        let mut inferred = 0usize;
        let mut complex: Vec<String> = Vec::new();
        let (listed, declared, read, unreadable) = survey_rows(
            &archives,
            &access,
            &cancel,
            3,
            |row| {
                if !row.native {
                    inferred += 1;
                }
                let (system, graphics) = row.segments();
                let Ok(header) = lforge_rage9::fragment::header(system) else {
                    return;
                };
                root_shape += 1;
                *variants
                    .entry(if header.unexplained[0].is_some() {
                        "+0x10 pointer"
                    } else {
                        "+0x10 zero"
                    })
                    .or_insert(0) += 1;
                *counts_words.entry(header.counts).or_insert(0) += 1;
                let mut found = Vec::new();
                for (slot, at) in [
                    ("drawable +0x18", Some(header.drawable)),
                    ("+0x10", header.unexplained[0]),
                    ("+0x20", header.unexplained[1]),
                    ("+0x28", header.unexplained[2]),
                ] {
                    let Some(at) = at else { continue };
                    if !lforge_rage9::drawable::is_member_drawable_at(system, graphics, at as usize)
                    {
                        continue;
                    }
                    *slots_holding_drawables.entry(slot).or_insert(0) += 1;
                    let name = lforge_rage9::drawable::member_name_at(system, at as usize)
                        .unwrap_or_default();
                    found.push((slot, at, name));
                }
                *drawable_counts.entry(found.len()).or_insert(0) += 1;
                let Some(report) = lforge_rage9::drawable::inspect_member_at(
                    system,
                    graphics,
                    header.drawable as usize,
                ) else {
                    return;
                };
                let name = report.header.name_text.clone().unwrap_or_default();
                let suffix = name
                    .rsplit_once('.')
                    .map(|(_, suffix)| suffix.to_ascii_lowercase())
                    .unwrap_or_default();
                *suffixes.entry(format!(".{suffix}")).or_insert(0) += 1;
                if suffix.trim_start_matches('#') == "ft" {
                    suffixed += 1;
                }
                let models: usize = report.lod.iter().map(|slot| slot.models.len()).sum();
                let geometries: usize = report
                    .lod
                    .iter()
                    .flat_map(|slot| &slot.models)
                    .map(|model| model.geometries.len())
                    .sum();
                *populated_lods.entry(report.lod.len()).or_insert(0) += 1;
                *model_counts.entry(models).or_insert(0) += 1;
                *geometry_counts.entry(geometries).or_insert(0) += 1;
                if report.header.skeleton.is_some() {
                    skeleton_present += 1;
                }
                if report.header.list.is_some() {
                    list_present += 1;
                }
                if report.shader_group.is_some() {
                    shader_group_present += 1;
                }
                if !report.issues.is_empty() {
                    walk_issues += 1;
                }
                if let Some(filter) = &name_filter
                    && name.to_ascii_lowercase().contains(filter.as_str())
                    && matched.len() < sample_limit
                {
                    matched.push(format!(
                        "{}: {name:?} counts {:?}, {} lod, {} model(s), {} geometry record(s), split {:#x}{}",
                        row.path.display(),
                        header.counts,
                        report.lod.len(),
                        models,
                        geometries,
                        row.system_len,
                        if row.native { "" } else { " (inferred)" }
                    ));
                }
                if (models > 1 || geometries > 4 || report.header.skeleton.is_some())
                    && complex.len() < sample_limit
                {
                    complex.push(format!(
                        "{}: variant {}, counts {:?}, {} lod, {} model(s), {} geometry record(s), skeleton {:?}, list {:?}, name {name:?}, split {:#x}{}",
                        row.path.display(),
                        if header.unexplained[0].is_some() {
                            "+0x10 pointer"
                        } else {
                            "+0x10 zero"
                        },
                        header.counts,
                        report.lod.len(),
                        models,
                        geometries,
                        report.header.skeleton,
                        report.header.list,
                        row.system_len,
                        if row.native { "" } else { " (inferred)" }
                    ));
                }
            },
        );
        eprintln!("archives: {listed} listed");
        eprintln!("type-3 rows: {declared} declared, {read} read, {unreadable} unreadable");
        eprintln!("{inferred} row(s) used an inferred split");
        eprintln!("root shape: {root_shape}");
        eprintln!("root variants: {variants:?}");
        eprintln!("drawables per row: {drawable_counts:?}");
        eprintln!("slots holding a member drawable: {slots_holding_drawables:?}");
        eprintln!("member name suffixes: {suffixes:?} ({suffixed} with #ft)");
        eprintln!("counts words: {counts_words:?}");
        eprintln!("populated LOD slots per member: {populated_lods:?}");
        eprintln!("models per member: {model_counts:?}");
        eprintln!("geometry records per member: {geometry_counts:?}");
        eprintln!(
            "member references: {skeleton_present} skeleton, {list_present} list, {shader_group_present} shader group; {walk_issues} member(s) with a walk issue"
        );
        eprintln!("{} complex sample(s) printed", complex.len());
        for line in &complex {
            eprintln!("  complex: {line}");
        }
        if name_filter.is_some() {
            eprintln!("{} name-filtered sample(s) printed", matched.len());
            for line in &matched {
                eprintln!("  named: {line}");
            }
        }
        assert!(listed > 0, "no archive was listed");
    }

    /// Compares the dictionary framing of three declared container types.
    ///
    /// Type 4 is the drawable dictionary, type 5 the texture dictionary and
    /// type 16 the batch dictionary. The census classes all three under the
    /// same normalised header variant, so the run asks whether the framing is
    /// shared rather than assuming it: each row is offered to the drawable
    /// dictionary parser, the texture dictionary parser and the fragment root
    /// reader, and the root words are recorded as stored.
    ///
    /// Ignored by default. `LF_SURVEY_TYPES` selects the types (default
    /// `5,16,17`), `LF_TEST_ARCHIVE_LIST`/`LF_TEST_ARCHIVE_DIR` the archives
    /// and `LF_TEST_EXECUTABLE` the executable that supplies the archive keys.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE_LIST (or LF_TEST_ARCHIVE_DIR) and LF_TEST_EXECUTABLE"]
    fn surveys_native_container_rows() {
        use std::collections::BTreeMap;

        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let archives = survey_archives();
        let types: Vec<u8> = std::env::var("LF_SURVEY_TYPES")
            .unwrap_or_else(|_| "5,16,17".to_string())
            .split(',')
            .map(|value| value.trim().parse().expect("a type id"))
            .collect();
        for type_id in types {
            let mut words: BTreeMap<(u64, u64, u64), usize> = BTreeMap::new();
            let mut drawable_dictionaries = 0usize;
            let mut texture_dictionaries = 0usize;
            let mut fragments = 0usize;
            let mut member_drawables = 0usize;
            let mut sampled = 0usize;
            let (listed, declared, read, unreadable) =
                survey_rows(&archives, &access, &cancel, type_id, |row| {
                    let (system, graphics) = row.segments();
                    let word = |at: usize| {
                        system
                            .get(at..at + 8)
                            .and_then(|bytes| bytes.try_into().ok())
                            .map(u64::from_le_bytes)
                            .unwrap_or_default()
                    };
                    *words.entry((word(0), word(0x10), word(0x18))).or_insert(0) += 1;
                    if decoded::is_drawable_dictionary(system, graphics) {
                        drawable_dictionaries += 1;
                    }
                    if lforge_rage9::dictionary::is_dictionary(system) {
                        texture_dictionaries += 1;
                    }
                    if lforge_rage9::fragment::header(system).is_ok() {
                        fragments += 1;
                        if let Some(at) =
                            lforge_rage9::fragment::header(system)
                                .ok()
                                .and_then(|header| {
                                    lforge_rage9::drawable::is_member_drawable_at(
                                        system,
                                        graphics,
                                        header.drawable as usize,
                                    )
                                    .then_some(header.drawable)
                                })
                        {
                            member_drawables += 1;
                            if sampled < 8 {
                                sampled += 1;
                                eprintln!(
                                    "  type {type_id} member: {} name {:?} counts {:?}",
                                    row.path.display(),
                                    lforge_rage9::drawable::member_name_at(system, at as usize),
                                    lforge_rage9::fragment::header(system)
                                        .map(|h| h.counts)
                                        .ok()
                                );
                            }
                        }
                    }
                });
            eprintln!(
                "type {type_id}: {listed} archive(s) listed, {declared} declared, {read} read, {unreadable} unreadable"
            );
            eprintln!("  root words (+0x00, +0x10, +0x18): {words:?}");
            eprintln!(
                "  accepted as: {drawable_dictionaries} drawable dictionary, {texture_dictionaries} texture dictionary, {fragments} fragment root ({member_drawables} with a member drawable)"
            );
        }
    }

    /// The skeleton facts one surveyed row contributes.
    struct SkeletonFacts {
        bones: usize,
        roots: usize,
        depth: usize,
        named: usize,
        inverse_bind: usize,
        complete: bool,
        declared_geometries: usize,
        validated_geometries: usize,
        weighted_geometries: usize,
        /// Declared geometries whose influence streams could not be read.
        unread_geometries: usize,
        /// Why, as a histogram.
        unread_reasons: BTreeMap<String, usize>,
        /// A few declaration samples, for the run output.
        unread_samples: Vec<String>,
        /// The structural issues the skeleton parser reported, as kinds.
        issues: Vec<&'static str>,
        /// The same issues as text, for a sample line.
        issue_text: Vec<String>,
        /// One line per geometry that declares bones but did not validate.
        invalid: Vec<String>,
    }

    /// The issue kind, for a histogram. A pointer, bounds or count issue is
    /// reported with the field it concerned, because the field is the useful
    /// part of that observation.
    fn issue_kind(issue: &lforge_rage9::skeleton::Issue) -> &'static str {
        use lforge_rage9::skeleton::Issue;
        match issue {
            Issue::Pointer { .. } => "pointer",
            Issue::Bounds { .. } => "bounds",
            Issue::Clamped { field, .. } => field,
            Issue::ParentArrayMismatch { .. } => "parent array mismatch",
            Issue::InvalidParent { .. } => "invalid parent",
            Issue::SelfParent { .. } => "self parent",
            Issue::Cycle { .. } => "cycle",
            Issue::NonFinite { .. } => "non-finite",
            Issue::Missing { .. } => "missing",
            Issue::BoneArrayOverrun { .. } => "bone array overrun",
            Issue::ArrayOverlap { .. } => "array overlap",
            Issue::BeyondLimit { .. } => "beyond limit",
        }
    }

    /// Prints the raw skeleton header and records of one row.
    ///
    /// Enabled by `LF_SURVEY_DETAIL`, whose value is matched against the row
    /// locator. A partial result needs the stored counts next to the walk that
    /// disagreed with them, not only the disagreement.
    fn dump_skeleton(system: &[u8], at: u32) {
        let word = |offset: usize| {
            system
                .get(offset..offset + 4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
        };
        let half = |offset: usize| {
            system
                .get(offset..offset + 2)
                .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("two bytes")))
        };
        let base = at as usize;
        eprintln!(
            "    skeleton +{at:#x}: +0x10 {:?}, +0x18 {:?}, +0x1C {:?}, key map {:?}, bones {:?}, inverse bind {:?}, local {:?}, parents {:?}, names {:?}",
            word(base + 0x10),
            word(base + 0x18),
            word(base + 0x1C),
            word(base + 0x20),
            word(base + 0x28),
            word(base + 0x30),
            word(base + 0x38),
            word(base + 0x40),
            word(base + 0x48)
        );
        let Some(bone_base) = word(base + 0x28).map(|value| (value & 0x0FFF_FFFF) as usize) else {
            return;
        };
        eprintln!(
            "    bone array +{bone_base:#x}: first record +0x4E {:?}, +0x4C {:?}, +0x4A {:?}, +0x48 {:?}",
            half(bone_base + 0x4E),
            half(bone_base + 0x4C),
            half(bone_base + 0x4A),
            half(bone_base + 0x48)
        );
        let mut roots = Vec::new();
        let mut outside = 0usize;
        let mut index = 0usize;
        while index < 4096 {
            let record = bone_base + index * 0x50;
            if half(record + 0x48) != Some(index as u16) {
                break;
            }
            let parent = half(record + 0x46).unwrap_or(0xFFFF);
            if parent == 0xFFFF {
                roots.push(index);
            } else if usize::from(parent) >= 4096 {
                outside += 1;
            }
            if index < 12 {
                eprintln!(
                    "      bone {index}: parent {parent:#06x}, id {:?}, id16 {:?}, name {:?}, group {:?}",
                    word(record + 0x1C),
                    half(record + 0x4A),
                    word(record + 0x30),
                    [
                        half(record + 0x48),
                        half(record + 0x4A),
                        half(record + 0x4C),
                        half(record + 0x4E)
                    ]
                );
            }
            index += 1;
        }
        eprintln!(
            "    walk: {index} records, {} root(s) at {:?}, {outside} parent(s) outside the array",
            roots.len(),
            &roots[..roots.len().min(24)]
        );
        for index in index.saturating_sub(20)..index + 2 {
            let record = bone_base + index * 0x50;
            let name_pointer = word(record + 0x30).unwrap_or(0);
            let name_at = (name_pointer & 0x0FFF_FFFF) as usize;
            let name = {
                let mut text = Vec::new();
                for offset in name_at..name_at.saturating_add(48) {
                    match system.get(offset) {
                        Some(&byte) if byte.is_ascii_graphic() || byte == b' ' => text.push(byte),
                        _ => break,
                    }
                }
                String::from_utf8_lossy(&text).into_owned()
            };
            eprintln!(
                "      tail {index}: parent {:?}, group {:?}, name {name:?}",
                half(record + 0x46),
                [
                    half(record + 0x48),
                    half(record + 0x4A),
                    half(record + 0x4C),
                    half(record + 0x4E)
                ]
            );
        }
    }

    /// Reads the skeleton of one drawable and counts the influence streams its
    /// LOD-0 geometries declare.
    fn skeleton_facts(
        system: &[u8],
        graphics: &[u8],
        report: &lforge_rage9::drawable::Report,
    ) -> Option<SkeletonFacts> {
        let at = report.header.skeleton?;
        let skeleton = lforge_rage9::skeleton::inspect(system, at);
        let bone_total = skeleton.bones.len();
        let mut declared_geometries = 0;
        let mut validated_geometries = 0;
        let mut weighted_geometries = 0;
        // A geometry whose stream declaration is not the influence form, or
        // whose bytes are outside the buffer, is not a failed association: it
        // is one the survey could not read, and the two are counted apart.
        let mut unread_geometries = 0;
        let mut unread_reasons: BTreeMap<String, usize> = BTreeMap::new();
        let mut unread_samples: Vec<String> = Vec::new();
        let mut invalid = Vec::new();
        // Only the highest populated LOD is decoded and drawn, so only its
        // geometries contribute a static association.
        for model in report
            .lod
            .iter()
            .find(|slot| !slot.models.is_empty())
            .into_iter()
            .flat_map(|slot| &slot.models)
        {
            for (geometry_index, geometry) in model.geometries.iter().enumerate() {
                if geometry.bone_count == 0 {
                    continue;
                }
                declared_geometries += 1;
                let Some(buffer) = geometry.vertex_buffer.as_ref() else {
                    *unread_reasons
                        .entry("no vertex buffer".to_string())
                        .or_insert(0) += 1;
                    unread_geometries += 1;
                    continue;
                };
                let blob = graphics
                    .get(buffer.graphics as usize..)
                    .and_then(|tail| tail.get(..usize::try_from(buffer.declared_bytes).ok()?));
                let Some(blob) = blob else {
                    *unread_reasons
                        .entry("vertex buffer outside the graphics segment".to_string())
                        .or_insert(0) += 1;
                    unread_geometries += 1;
                    continue;
                };
                let Some(count) = Some(buffer.vertex_count as usize).filter(|count| *count > 0)
                else {
                    *unread_reasons.entry("no vertices".to_string()).or_insert(0) += 1;
                    unread_geometries += 1;
                    continue;
                };
                let word = |stream: usize| {
                    blob.get(stream * 4..stream * 4 + 4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
                };
                // Slots 6 and 8 are empirical: searching the declaration for the
                // weight format instead was measured and every extra candidate
                // failed the weight totals. A geometry that declares its streams
                // elsewhere is counted, not guessed at.
                let declaration: Vec<(usize, u32)> = (0..23usize)
                    .filter_map(|slot| word(slot).filter(|entry| *entry != 0).map(|e| (slot, e)))
                    .collect();
                let weight_slot = declaration
                    .iter()
                    .filter(|(_, entry)| entry & 0xFF == 0x26)
                    .map(|(slot, _)| *slot)
                    .collect::<Vec<_>>();
                let (Some(weights), Some(indexes)) = (word(6), word(8)) else {
                    *unread_reasons
                        .entry("slot 6 or 8 not declared".to_string())
                        .or_insert(0) += 1;
                    unread_geometries += 1;
                    continue;
                };
                if weights & 0xFF != 0x26 {
                    let reason = match (geometry.bone_count, weight_slot.first()) {
                        (1, _) => "no weight form (one bone)".to_string(),
                        (_, Some(slot)) => format!("weight form at slot {slot}, not 6"),
                        (_, None) => "no weight form".to_string(),
                    };
                    if unread_samples.len() < 4 {
                        unread_samples.push(format!(
                            "geometry {geometry_index}: bone_count {}, declaration {declaration:?}",
                            geometry.bone_count
                        ));
                    }
                    *unread_reasons.entry(reason).or_insert(0) += 1;
                    unread_geometries += 1;
                    continue;
                }
                // Slot 8 holds four `u8` blend indices only when its format is
                // 0x25; another format at that slot is a different attribute. A
                // one-bone skeleton needs no index stream: its single weight lane
                // names the only bone.
                let has_index_stream = indexes & 0xFF == 0x25;
                if !has_index_stream && bone_total != 1 {
                    if unread_samples.len() < 4 {
                        unread_samples.push(format!(
                            "geometry {geometry_index}: {bone_total} bones, declaration {declaration:?}"
                        ));
                    }
                    *unread_reasons
                        .entry("no index form at slot 8".to_string())
                        .or_insert(0) += 1;
                    unread_geometries += 1;
                    continue;
                }
                let weight_offset = ((weights >> 8) * 2) as usize;
                let weight_bytes = blob.get(weight_offset..weight_offset + count * 4);
                let Some(weight_bytes) = weight_bytes else {
                    *unread_reasons
                        .entry("weight or index bytes outside the buffer".to_string())
                        .or_insert(0) += 1;
                    unread_geometries += 1;
                    continue;
                };
                let index_bytes = if has_index_stream {
                    let index_offset = ((indexes >> 8) * 2) as usize;
                    let bytes = blob.get(index_offset..index_offset + count * 4);
                    let Some(bytes) = bytes else {
                        *unread_reasons
                            .entry("weight or index bytes outside the buffer".to_string())
                            .or_insert(0) += 1;
                        unread_geometries += 1;
                        continue;
                    };
                    Some(bytes)
                } else {
                    None
                };
                let mut valid = true;
                let mut weighted = false;
                for (vertex, w) in weight_bytes.as_chunks::<4>().0.iter().enumerate() {
                    let total =
                        u32::from(w[0]) + u32::from(w[1]) + u32::from(w[2]) + u32::from(w[3]);
                    if total == 0 {
                        valid = false;
                        break;
                    }
                    let used = w.iter().filter(|value| **value > 0).count();
                    if used > 1 {
                        weighted = true;
                    }
                    match index_bytes {
                        Some(bytes) => {
                            let i = &bytes[vertex * 4..vertex * 4 + 4];
                            if used > 0
                                && (0..4)
                                    .any(|lane| w[lane] > 0 && usize::from(i[lane]) >= bone_total)
                            {
                                valid = false;
                                break;
                            }
                        }
                        None => {
                            if w[1] != 0 || w[2] != 0 || w[3] != 0 {
                                valid = false;
                                break;
                            }
                        }
                    }
                }
                if valid {
                    validated_geometries += 1;
                    if weighted {
                        weighted_geometries += 1;
                    }
                } else if invalid.len() < 8 {
                    invalid.push(format!(
                        "geometry {geometry_index}: bone_count {}, weight slots {weight_slot:?}, stream 6 {:04x} 8 {:04x}, vertices {count}",
                        geometry.bone_count,
                        weights & 0xFFFF,
                        indexes & 0xFFFF
                    ));
                }
            }
        }
        Some(SkeletonFacts {
            bones: skeleton.bones.len(),
            roots: skeleton.roots.len(),
            depth: skeleton.max_depth,
            named: skeleton.named_count(),
            inverse_bind: skeleton.inverse_bind.len(),
            complete: skeleton.complete(),
            issues: skeleton.issues.iter().map(issue_kind).collect(),
            issue_text: skeleton.issues.iter().map(ToString::to_string).collect(),
            declared_geometries,
            validated_geometries,
            weighted_geometries,
            unread_geometries,
            unread_reasons,
            unread_samples,
            invalid,
        })
    }

    /// Surveys the skeletons of every declared type-2 and type-3 row in the
    /// caller-named archives.
    ///
    /// The question is how skeletons are distributed and how much of them the
    /// parser reads: presence, bone count, root count, depth, name coverage,
    /// inverse-bind coverage, and whether each LOD-0 geometry's influence
    /// streams validate. The run reports a selected sample, not an
    /// installation-wide claim.
    ///
    /// Ignored by default. `LF_TEST_ARCHIVE_LIST`/`LF_TEST_ARCHIVE_DIR` name
    /// the archives and `LF_TEST_EXECUTABLE` the executable that supplies the
    /// keys. `LF_SURVEY_SAMPLES` bounds the locators printed.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE_LIST (or LF_TEST_ARCHIVE_DIR) and LF_TEST_EXECUTABLE"]
    fn surveys_native_skeleton_rows() {
        use std::collections::BTreeMap;

        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let archives = survey_archives();
        let sample_limit: usize = std::env::var("LF_SURVEY_SAMPLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20);

        let mut presence: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut bone_counts: BTreeMap<usize, usize> = BTreeMap::new();
        let mut root_counts: BTreeMap<usize, usize> = BTreeMap::new();
        let mut depths: BTreeMap<usize, usize> = BTreeMap::new();
        let mut issue_kinds: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut incomplete = 0usize;
        let mut with_inverse_bind = 0usize;
        let mut declared_geometries = 0usize;
        let mut validated_geometries = 0usize;
        let mut weighted_geometries = 0usize;
        let mut unread_geometries = 0usize;
        let mut unread_reasons: BTreeMap<String, usize> = BTreeMap::new();
        let mut samples: Vec<String> = Vec::new();
        let mut partial_samples: Vec<String> = Vec::new();
        let mut invalid_samples: Vec<String> = Vec::new();
        let mut unread_samples: Vec<String> = Vec::new();
        let detail_dumps = std::cell::Cell::new(0usize);

        for type_id in [2u8, 3u8] {
            let (listed, declared, read, unreadable) = survey_rows(
                &archives,
                &access,
                &cancel,
                type_id,
                |row| {
                    let (system, graphics) = row.segments();
                    let report = if type_id == 3 {
                        let Ok(header) = lforge_rage9::fragment::header(system) else {
                            return;
                        };
                        lforge_rage9::drawable::inspect_member_at(
                            system,
                            graphics,
                            header.drawable as usize,
                        )
                    } else {
                        lforge_rage9::drawable::inspect(system, graphics)
                    };
                    let Some(report) = report else { return };
                    let Some(facts) = skeleton_facts(system, graphics, &report) else {
                        *presence.entry("no skeleton pointer").or_insert(0) += 1;
                        return;
                    };
                    if detail_dumps.get() < 3 {
                        let by_path = std::env::var("LF_SURVEY_DETAIL")
                            .is_ok_and(|needle| row.path.display().to_string().contains(&needle));
                        let by_issue = std::env::var("LF_SURVEY_DETAIL_ISSUE")
                            .is_ok_and(|kind| facts.issues.contains(&kind.as_str()));
                        if (by_path || by_issue)
                            && let Some(at) = report.header.skeleton
                        {
                            eprintln!("    detail: {}", row.path.display());
                            dump_skeleton(system, at);
                            detail_dumps.set(detail_dumps.get() + 1);
                        }
                    }
                    *presence.entry("skeleton").or_insert(0) += 1;
                    *bone_counts.entry(facts.bones).or_insert(0) += 1;
                    *root_counts.entry(facts.roots).or_insert(0) += 1;
                    *depths.entry(facts.depth).or_insert(0) += 1;
                    for kind in &facts.issues {
                        *issue_kinds.entry(kind).or_insert(0) += 1;
                    }
                    if !facts.complete {
                        incomplete += 1;
                        if partial_samples.len() < sample_limit {
                            partial_samples.push(format!(
                                "{}: type {type_id}, {} bones, {} root(s), depth {}, issues {:?}",
                                row.path.display(),
                                facts.bones,
                                facts.roots,
                                facts.depth,
                                facts.issue_text
                            ));
                        }
                    }
                    if facts.inverse_bind > 0 {
                        with_inverse_bind += 1;
                    }
                    declared_geometries += facts.declared_geometries;
                    validated_geometries += facts.validated_geometries;
                    weighted_geometries += facts.weighted_geometries;
                    unread_geometries += facts.unread_geometries;
                    for (reason, count) in &facts.unread_reasons {
                        *unread_reasons.entry(reason.clone()).or_insert(0) += count;
                    }
                    if samples.len() < sample_limit {
                        samples.push(format!(
                            "{}: type {type_id}, {} bones, {} root(s), depth {}, {}/{} named, {}/{} inverse bind, {} of {} geometry influence sets validated, {} weighted, split {:#x}{}",
                            row.path.display(),
                            facts.bones,
                            facts.roots,
                            facts.depth,
                            facts.named,
                            facts.bones,
                            facts.inverse_bind,
                            facts.bones,
                            facts.validated_geometries,
                            facts.declared_geometries,
                            facts.weighted_geometries,
                            row.system_len,
                            if row.native { "" } else { " (inferred)" }
                        ));
                    }
                    if !facts.invalid.is_empty() && invalid_samples.len() < 8 {
                        invalid_samples.push(format!(
                            "{}: {}",
                            row.path.display(),
                            facts.invalid.join("; ")
                        ));
                    }
                    if unread_samples.len() < 4 {
                        for sample in &facts.unread_samples {
                            unread_samples.push(format!("{}: {sample}", row.path.display()));
                        }
                    }
                },
            );
            eprintln!(
                "type {type_id}: {listed} archive(s) listed, {declared} declared, {read} read, {unreadable} unreadable"
            );
        }
        eprintln!("skeleton presence: {presence:?}");
        eprintln!("bone counts: {bone_counts:?}");
        eprintln!("root counts: {root_counts:?}");
        eprintln!("hierarchy depths: {depths:?}");
        eprintln!("structural issues: {issue_kinds:?}");
        eprintln!(
            "{incomplete} skeleton(s) partial, {with_inverse_bind} with inverse-bind records"
        );
        eprintln!(
            "influence sets: {validated_geometries} validated, {unread_geometries} without readable streams, {} invalid of {declared_geometries} declared; {weighted_geometries} weighted",
            declared_geometries - validated_geometries - unread_geometries
        );
        eprintln!("  unread reasons: {unread_reasons:?}");
        for line in &samples {
            eprintln!("  sample: {line}");
        }
        for line in &partial_samples {
            eprintln!("  partial: {line}");
        }
        for line in &invalid_samples {
            eprintln!("  invalid influence: {line}");
        }
        for line in &unread_samples {
            eprintln!("  unread influence: {line}");
        }
        assert!(!presence.is_empty(), "no row was read");
    }

    /// A matrix as glam reads the record's row-major elements.
    ///
    /// The record stores nine `f32` row after row. Building a `Mat3` from those
    /// values as columns would compare a matrix with its own transpose, which is
    /// the mistake this probe exists to avoid.
    fn mat3_from_row_major(stored: &[f32; 9]) -> glam::Mat3 {
        let [r00, r01, r02, r10, r11, r12, r20, r21, r22] = *stored;
        glam::Mat3::from_cols_array(&[r00, r10, r20, r01, r11, r21, r02, r12, r22])
    }

    fn mat3_delta(a: glam::Mat3, b: glam::Mat3) -> f32 {
        a.to_cols_array()
            .iter()
            .zip(b.to_cols_array().iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0, f32::max)
    }

    fn vec3_delta(a: glam::Vec3, b: glam::Vec3) -> f32 {
        (a - b).abs().max_element()
    }

    /// Measures how the record's arrays bound each other and what the stored
    /// matrices mean mathematically.
    ///
    /// Ignored by default. `LF_TEST_ARCHIVE_LIST`/`LF_TEST_ARCHIVE_DIR` name the
    /// archives and `LF_TEST_EXECUTABLE` the executable that supplies the keys.
    ///
    /// The bone count comes from the record walk, so this run asks whether the
    /// neighbouring arrays can confirm it: an array that starts inside the bone
    /// array proves the walk over-read, and a gap wider than one record next to
    /// the nearest following array is the signature a truncated walk would
    /// leave. The matrix comparisons keep the raw stored elements apart from the
    /// three readings of them.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE_LIST (or LF_TEST_ARCHIVE_DIR) and LF_TEST_EXECUTABLE"]
    fn examines_skeleton_array_bounds_and_storage() {
        use glam::{Mat3, Quat, Vec3};

        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let archives = survey_archives();
        let sample_limit: usize = std::env::var("LF_SURVEY_SAMPLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(6);

        let mut examined = 0usize;
        let mut with_local = 0usize;
        let mut with_inverse = 0usize;
        let mut overlaps = 0usize;
        let mut gaps: BTreeMap<i64, usize> = BTreeMap::new();
        let mut collides_one_more = 0usize;
        let mut parent_inside_bones = 0usize;

        let mut local_as_transpose_rotation = 0usize;
        let mut local_as_rotation = 0usize;
        let mut local_with_scale = 0usize;
        let mut inverse_as_model_rotation = 0usize;
        let mut inverse_as_transposed_model = 0usize;
        let mut inverse_with_scale = 0usize;
        let mut worst_local_rotation = 0f32;
        let mut worst_local_translation = 0f32;
        let mut worst_inverse_rotation = 0f32;
        let mut worst_inverse_translation = 0f32;

        let mut scale_identity = 0usize;
        let mut scale_uniform = 0usize;
        let mut scale_nonuniform = 0usize;
        let mut scale_negative = 0usize;
        let mut scale_zero = 0usize;
        let mut scale_non_finite = 0usize;
        let mut scale_samples: Vec<String> = Vec::new();
        let mut bound_samples: Vec<String> = Vec::new();
        let mut matrix_samples: Vec<String> = Vec::new();

        for type_id in [2u8, 3u8] {
            survey_rows(&archives, &access, &cancel, type_id, |row| {
                let (system, graphics) = row.segments();
                let report = if type_id == 3 {
                    let Ok(header) = lforge_rage9::fragment::header(system) else {
                        return;
                    };
                    lforge_rage9::drawable::inspect_member_at(
                        system,
                        graphics,
                        header.drawable as usize,
                    )
                } else {
                    lforge_rage9::drawable::inspect(system, graphics)
                };
                let Some(report) = report else { return };
                let Some(at) = report.header.skeleton else {
                    return;
                };
                let skeleton = lforge_rage9::skeleton::inspect(system, at);
                if skeleton.bones.is_empty() {
                    return;
                }
                examined += 1;
                let count = skeleton.bones.len();
                let arrays = skeleton.arrays;

                // Where every array starts, and how far the bone array runs.
                let start = |offset: Option<u32>| offset.map(u64::from);
                let bone_start = u64::from(arrays.bones.unwrap_or(0));
                let bone_end = bone_start + count as u64 * 0x50;
                let spans: Vec<(&'static str, u64, u64)> = [
                    ("bones", start(arrays.bones), count as u64 * 0x50),
                    ("inverse", start(arrays.inverse_bind), count as u64 * 0x40),
                    ("local", start(arrays.local_matrices), count as u64 * 0x40),
                    ("parents", start(arrays.parents), count as u64 * 2),
                    (
                        "keys",
                        start(arrays.keys),
                        u64::from(skeleton.recorded_keys) * 8,
                    ),
                ]
                .into_iter()
                .filter_map(|(name, at, len)| at.map(|at| (name, at, at + len)))
                .collect();
                for (index, a) in spans.iter().enumerate() {
                    for b in spans.iter().skip(index + 1) {
                        if a.1 != b.1 && a.1 < b.2 && b.1 < a.2 {
                            overlaps += 1;
                            if bound_samples.len() < sample_limit {
                                bound_samples.push(format!(
                                    "{}: {} +{:#x} overlaps {} +{:#x}",
                                    row.path.display(),
                                    a.0,
                                    a.1,
                                    b.0,
                                    b.1
                                ));
                            }
                        }
                    }
                }
                if let Some(offset) = arrays.parents
                    && u64::from(offset) < bone_end
                    && u64::from(offset) >= bone_start
                {
                    parent_inside_bones += 1;
                }
                let next = spans
                    .iter()
                    .filter(|(name, at, _)| *name != "bones" && *at > bone_start)
                    .map(|(_, at, _)| *at)
                    .min();
                if let Some(next) = next {
                    let gap = next as i64 - bone_end as i64;
                    *gaps.entry(gap).or_insert(0) += 1;
                    if gap < 0x50 {
                        collides_one_more += 1;
                    }
                }

                if !skeleton.local_matrices.is_empty() {
                    with_local += 1;
                }
                if !skeleton.inverse_bind.is_empty() {
                    with_inverse += 1;
                }

                for (index, bone) in skeleton.bones.iter().enumerate() {
                    let rotation = Quat::from_xyzw(
                        bone.rotation[0],
                        bone.rotation[1],
                        bone.rotation[2],
                        bone.rotation[3],
                    );
                    let translation = Vec3::from_array(bone.translation);
                    let scale = Vec3::from_array(bone.scale);
                    let identity = scale.abs_diff_eq(Vec3::ONE, 1e-6);
                    let uniform = !identity
                        && (scale.x - scale.y).abs() < 1e-6
                        && (scale.y - scale.z).abs() < 1e-6;
                    if !scale.is_finite() {
                        scale_non_finite += 1;
                    } else if scale.abs_diff_eq(Vec3::ZERO, 1e-6) {
                        scale_zero += 1;
                    } else if scale.min_element() < 0.0 {
                        scale_negative += 1;
                    } else if identity {
                        scale_identity += 1;
                    } else if uniform {
                        scale_uniform += 1;
                    } else {
                        scale_nonuniform += 1;
                    }
                    if !identity && scale.is_finite() && scale_samples.len() < sample_limit {
                        scale_samples.push(format!(
                            "{}: bone {index} {} scale {:?}",
                            row.path.display(),
                            bone.name.clone().unwrap_or_default(),
                            bone.scale
                        ));
                    }
                    if !rotation.is_finite() {
                        continue;
                    }
                    let local_rotation = Mat3::from_quat(rotation);
                    let local_scale = Mat3::from_diagonal(scale);

                    if let Some(stored) = skeleton.local_matrices.get(index) {
                        let matrix = mat3_from_row_major(&stored.rotation);
                        let as_transpose = mat3_delta(matrix, local_rotation.transpose());
                        let as_rotation = mat3_delta(matrix, local_rotation);
                        let with_scale =
                            mat3_delta(matrix, (local_rotation * local_scale).transpose());
                        if as_transpose <= 1e-3 {
                            local_as_transpose_rotation += 1;
                        } else if as_rotation <= 1e-3 {
                            local_as_rotation += 1;
                        } else if with_scale <= 1e-3 {
                            local_with_scale += 1;
                        }
                        worst_local_rotation = worst_local_rotation.max(as_transpose);
                        worst_local_translation = worst_local_translation.max(vec3_delta(
                            Vec3::from_array(stored.translation),
                            translation,
                        ));
                        if as_transpose > 1e-3 && matrix_samples.len() < sample_limit {
                            matrix_samples.push(format!(
                                "{}: bone {index} local rotation deltas transpose {as_transpose:.4} plain {as_rotation:.4} scaled {with_scale:.4}",
                                row.path.display()
                            ));
                        }
                    }
                }

                // Model-space rotation of each bone, for the inverse-bind
                // convention. A skeleton of several thousand bones would make
                // this quadratic if a parent were not already resolved, but the
                // walk stores parents in index order.
                let mut model_rotation: Vec<Mat3> = Vec::with_capacity(count);
                let mut model_position: Vec<Vec3> = Vec::with_capacity(count);
                for (index, bone) in skeleton.bones.iter().enumerate() {
                    let rotation = Quat::from_xyzw(
                        bone.rotation[0],
                        bone.rotation[1],
                        bone.rotation[2],
                        bone.rotation[3],
                    );
                    let matrix = Mat3::from_quat(rotation);
                    let translation = Vec3::from_array(bone.translation);
                    let (resolved, position) = match bone.parent {
                        Some(parent) if parent < index => (
                            model_rotation[parent] * matrix,
                            model_position[parent] + model_rotation[parent] * translation,
                        ),
                        _ => (matrix, translation),
                    };
                    model_rotation.push(resolved);
                    model_position.push(position);
                    let Some(stored) = skeleton.inverse_bind.get(index) else {
                        continue;
                    };
                    let stored_matrix = mat3_from_row_major(&stored.rotation);
                    let as_model = mat3_delta(stored_matrix, resolved);
                    let as_transposed = mat3_delta(stored_matrix, resolved.transpose());
                    let scale = Mat3::from_diagonal(Vec3::from_array(bone.scale));
                    let with_scale = mat3_delta(stored_matrix, resolved * scale);
                    if as_model <= 1e-3 {
                        inverse_as_model_rotation += 1;
                    } else if as_transposed <= 1e-3 {
                        inverse_as_transposed_model += 1;
                    } else if with_scale <= 1e-3 {
                        inverse_with_scale += 1;
                    }
                    worst_inverse_rotation = worst_inverse_rotation.max(as_model);
                    let expected_translation = -(resolved.transpose() * position);
                    worst_inverse_translation = worst_inverse_translation.max(vec3_delta(
                        Vec3::from_array(stored.translation),
                        expected_translation,
                    ));
                }
            });
        }
        eprintln!("skeletons examined: {examined}");
        eprintln!("with local matrices: {with_local}, with inverse bind: {with_inverse}");
        eprintln!(
            "spans overlapping: {overlaps}, parent array starting inside the bone array: {parent_inside_bones}"
        );
        eprintln!("gap from bone array end to the nearest later array: {gaps:?}");
        eprintln!("a further record would reach that array in {collides_one_more} skeleton(s)");
        eprintln!(
            "stored local rotation read as transpose(local): {local_as_transpose_rotation}, as local: {local_as_rotation}, as transpose(local*scale): {local_with_scale}"
        );
        eprintln!(
            "worst local rotation delta {worst_local_rotation}, worst local translation delta {worst_local_translation}"
        );
        eprintln!(
            "stored inverse rotation read as model rotation: {inverse_as_model_rotation}, as transpose: {inverse_as_transposed_model}, as model*scale: {inverse_with_scale}"
        );
        eprintln!(
            "worst inverse rotation delta {worst_inverse_rotation}, worst inverse translation delta {worst_inverse_translation}"
        );
        eprintln!(
            "scale identity {scale_identity}, uniform {scale_uniform}, nonuniform {scale_nonuniform}, negative {scale_negative}, zero {scale_zero}, non-finite {scale_non_finite}"
        );
        for line in &scale_samples {
            eprintln!("  scale: {line}");
        }
        for line in &bound_samples {
            eprintln!("  bound: {line}");
        }
        for line in &matrix_samples {
            eprintln!("  matrix: {line}");
        }
        let _ = matrix_samples;
        assert!(examined > 0, "no skeleton was read");
    }

    /// Verifies the four documented skeleton-bearing fragments through the
    /// native archive path.
    ///
    /// Ignored by default. `LF_TEST_CHAIN_LIST` names a file with the four
    /// chains (`levels.rpf!5!0`, `levels.rpf!5!1`, `data.rpf!26!9`,
    /// `levels.rpf!5!8`), `LF_TEST_GAME_ROOT` the installation and
    /// `LF_TEST_EXECUTABLE` the executable that supplies the keys.
    #[test]
    #[ignore = "requires LF_TEST_CHAIN_LIST, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
    fn decodes_real_skeleton_resources() {
        use std::collections::BTreeMap;

        let list = std::env::var("LF_TEST_CHAIN_LIST").expect("LF_TEST_CHAIN_LIST");
        let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let text = std::fs::read_to_string(&list).expect("chain list");
        let mut resolved = std::collections::BTreeMap::new();
        let mut index = std::collections::HashMap::new();
        let mut seen: BTreeMap<String, (usize, usize, usize, bool, decoded::SkeletonCompleteness)> =
            BTreeMap::new();
        let mut placement_lines: BTreeMap<String, String> = BTreeMap::new();
        for chain in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let Some((parent_chain, row)) = chain.rsplit_once('!') else {
                continue;
            };
            let Ok(row) = row.parse::<usize>() else {
                continue;
            };
            let Some(parent) = resolve_chain(
                Path::new(&root),
                &access,
                parent_chain,
                &mut resolved,
                &mut index,
            ) else {
                eprintln!("unresolved chain: {chain}");
                continue;
            };
            if !index.contains_key(&parent) {
                index.insert(parent.clone(), row_index(&parent, &access));
            }
            let Some(entry) = index.get(&parent).and_then(|rows| rows.get(&row)).cloned() else {
                eprintln!("row {row} of {} is not listed", parent.display());
                continue;
            };
            let loaded = match load_with_cancel(&entry, &access, Some(Path::new(&root)), &cancel) {
                Ok(loaded) => loaded,
                Err(err) => {
                    eprintln!("{}: {err}", entry.display());
                    continue;
                }
            };
            let skeleton = loaded.scene.skeleton.as_ref();
            let weighted = loaded
                .scene
                .associations
                .iter()
                .any(|association| association.weighted);
            let bones = skeleton.map_or(0, |skeleton| skeleton.bones.len());
            let roots = skeleton.map_or(0, |skeleton| skeleton.roots.len());
            let depth = skeleton.map_or(0, |skeleton| skeleton.max_depth);
            let evidence = loaded
                .scene
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.reason.starts_with("coordinate space"))
                .map(|diagnostic| diagnostic.reason.clone())
                .unwrap_or_else(|| "no coordinate-space statement".to_string());
            placement_lines.insert(
                loaded.name.clone(),
                format!(
                    "placement {}, associations {}, {evidence}",
                    loaded.completeness.placement.name(),
                    loaded.completeness.associations.name()
                ),
            );
            seen.insert(
                loaded.name.clone(),
                (
                    bones,
                    roots,
                    depth,
                    weighted,
                    loaded.completeness.skeleton.clone(),
                ),
            );
        }
        for (name, facts) in &seen {
            eprintln!("{name}: {facts:?}");
            if let Some(extra) = placement_lines.get(name) {
                eprintln!("  {extra}");
            }
        }
        let expected: [(&str, usize, usize, usize, bool); 4] = [
            ("prop_am_card_tarot_deck_01a.#ft", 3, 1, 3, false),
            ("prop_am_candlestick_02a.#ft", 4, 1, 4, false),
            ("w_sg_goodwin_01_bolt_01_mid.#ft", 3, 1, 3, false),
            ("mint_peacock_taxidermy_01.#ft", 10, 1, 10, true),
        ];
        for (name, bones, roots, depth, weighted) in expected {
            let Some((found_bones, found_roots, found_depth, found_weighted, completeness)) =
                seen.get(name)
            else {
                panic!(
                    "{name} was not decoded; saw {:?}",
                    seen.keys().collect::<Vec<_>>()
                );
            };
            assert_eq!(*found_bones, bones, "{name}");
            assert_eq!(*found_roots, roots, "{name}");
            assert_eq!(*found_depth, depth, "{name}");
            assert_eq!(*found_weighted, weighted, "{name}");
            assert_eq!(
                *completeness,
                decoded::SkeletonCompleteness::Complete,
                "{name}"
            );
        }
    }

    /// Looks for independent evidence of how a one-bone geometry binds.
    ///
    /// Ignored by default. `LF_TEST_ARCHIVE_LIST`/`LF_TEST_ARCHIVE_DIR` name the
    /// archives and `LF_TEST_EXECUTABLE` the executable that supplies the keys.
    ///
    /// A geometry that declares one bone and stores no weight form cannot be
    /// associated from its vertex streams. This run inspects the geometry record
    /// itself for a bone reference, so an implicit association is only adopted if
    /// the record states one.
    #[test]
    #[ignore = "requires LF_TEST_ARCHIVE_LIST (or LF_TEST_ARCHIVE_DIR) and LF_TEST_EXECUTABLE"]
    fn examines_single_bone_geometry_records() {
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let archives = survey_archives();
        let sample_limit: usize = std::env::var("LF_SURVEY_SAMPLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8);

        let mut single_bone = 0usize;
        let mut multi_bone = 0usize;
        let mut single_with_weights = 0usize;
        let mut no_weight_single_skeleton = 0usize;
        let mut no_weight_multi_skeleton = 0usize;
        let mut mixed_samples: Vec<String> = Vec::new();
        let mut words: BTreeMap<String, usize> = BTreeMap::new();
        let mut samples: Vec<String> = Vec::new();

        for type_id in [2u8, 3u8] {
            survey_rows(&archives, &access, &cancel, type_id, |row| {
                let (system, graphics) = row.segments();
                let report = if type_id == 3 {
                    let Ok(header) = lforge_rage9::fragment::header(system) else {
                        return;
                    };
                    lforge_rage9::drawable::inspect_member_at(
                        system,
                        graphics,
                        header.drawable as usize,
                    )
                } else {
                    lforge_rage9::drawable::inspect(system, graphics)
                };
                let Some(report) = report else { return };
                if report.header.skeleton.is_none() {
                    return;
                }
                let word = |at: usize, offset: usize| {
                    system
                        .get(at + offset..at + offset + 4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
                };
                for model in report
                    .lod
                    .iter()
                    .find(|slot| !slot.models.is_empty())
                    .into_iter()
                    .flat_map(|slot| &slot.models)
                {
                    for geometry in &model.geometries {
                        if geometry.bone_count == 0 {
                            continue;
                        }
                        let has_weights = geometry.vertex_buffer.as_ref().is_some_and(|buffer| {
                            graphics
                                .get(buffer.graphics as usize..)
                                .and_then(|tail| {
                                    tail.get(..usize::try_from(buffer.declared_bytes).ok()?)
                                })
                                .is_some_and(|blob| {
                                    blob.get(24..28).is_some_and(|entry| entry[0] == 0x26)
                                })
                        });
                        if geometry.bone_count == 1 {
                            single_bone += 1;
                            if has_weights {
                                single_with_weights += 1;
                            } else {
                                let skeleton_bones = lforge_rage9::skeleton::inspect(
                                    system,
                                    report.header.skeleton.unwrap_or(0),
                                )
                                .bones
                                .len();
                                if skeleton_bones == 1 {
                                    no_weight_single_skeleton += 1;
                                } else {
                                    no_weight_multi_skeleton += 1;
                                    if mixed_samples.len() < sample_limit {
                                        mixed_samples.push(format!(
                                            "{}: geometry declares 1 bone, skeleton holds {skeleton_bones}",
                                            row.path.display()
                                        ));
                                    }
                                }
                            }
                            let key = format!(
                                "word_14 {:?} flags {:?} +0x28 {:?} +0x2A {:?} +0x2E {:?} +0x30 {:?} +0x34 {:?} +0x38 {:?} +0x3C {:?}",
                                model.word_14,
                                model.flags & 0xFFFF,
                                word(geometry.at as usize, 0x28),
                                word(geometry.at as usize, 0x2A),
                                word(geometry.at as usize, 0x2E),
                                word(geometry.at as usize, 0x30),
                                word(geometry.at as usize, 0x34),
                                word(geometry.at as usize, 0x38),
                                word(geometry.at as usize, 0x3C)
                            );
                            *words.entry(key).or_insert(0) += 1;
                            if samples.len() < sample_limit {
                                samples.push(format!(
                                    "{}: bone_count 1, weights {has_weights}, word_30 {:#x}, vertex buffer {:?}",
                                    row.path.display(),
                                    geometry.word_30,
                                    geometry.vertex_buffer.as_ref().map(|buffer| (
                                        buffer.elements,
                                        buffer.unit,
                                        buffer.declared_bytes
                                    ))
                                ));
                            }
                        } else {
                            multi_bone += 1;
                        }
                    }
                }
            });
        }
        eprintln!("one-bone geometries: {single_bone} ({single_with_weights} with a weight form)");
        eprintln!("multi-bone geometries: {multi_bone}");
        eprintln!(
            "of the one-bone geometries without a weight form: {no_weight_single_skeleton} belong to a one-bone skeleton, {no_weight_multi_skeleton} to a larger one"
        );
        for line in &mixed_samples {
            eprintln!("  mixed: {line}");
        }
        eprintln!("one-bone geometry record words, most frequent first:");
        let mut ranked: Vec<(&String, &usize)> = words.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1));
        for (key, count) in ranked.iter().take(8) {
            eprintln!("  {count:5} x {key}");
        }
        for line in &samples {
            eprintln!("  sample: {line}");
        }
        assert!(single_bone > 0, "no one-bone geometry was read");
    }

    /// Finds the skeleton extremes of the chain corpus and names them natively.
    ///
    /// Ignored by default. `LF_TEST_CHAIN_LIST` names a file of census chains,
    /// `LF_TEST_GAME_ROOT` the installation and `LF_TEST_EXECUTABLE` the
    /// executable that supplies the keys. `LF_CHAIN_LIMIT` bounds the chains
    /// read.
    ///
    /// The extreme skeletons a manual check needs must be nameable as a native
    /// chain, so this run walks chains and reports the ones with the most bones
    /// and the most roots rather than the paths of extracted caches.
    #[test]
    #[ignore = "requires LF_TEST_CHAIN_LIST, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
    fn finds_skeleton_extremes_over_chains() {
        let list = std::env::var("LF_TEST_CHAIN_LIST").expect("LF_TEST_CHAIN_LIST");
        let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let limit: usize = std::env::var("LF_CHAIN_LIMIT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(usize::MAX);
        let stride: usize = std::env::var("LF_CHAIN_STRIDE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let text = std::fs::read_to_string(&list).expect("chain list");
        let mut resolved = std::collections::BTreeMap::new();
        let mut index = std::collections::HashMap::new();
        let mut read = 0usize;
        let mut with_skeleton = 0usize;
        let mut multi_root = 0usize;
        let mut by_bones: Vec<(usize, usize, usize, String, String)> = Vec::new();
        let mut by_roots: Vec<(usize, usize, usize, String, String)> = Vec::new();
        for chain in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .step_by(stride)
            .take(limit)
        {
            let Some((parent_chain, row)) = chain.rsplit_once('!') else {
                continue;
            };
            let Ok(row) = row.parse::<usize>() else {
                continue;
            };
            let Some(parent) = resolve_chain(
                Path::new(&root),
                &access,
                parent_chain,
                &mut resolved,
                &mut index,
            ) else {
                continue;
            };
            if !index.contains_key(&parent) {
                index.insert(parent.clone(), row_index(&parent, &access));
            }
            let Some(entry) = index.get(&parent).and_then(|rows| rows.get(&row)).cloned() else {
                continue;
            };
            let Ok(binary) = crate::files::open_binary_with(&entry, &access) else {
                continue;
            };
            let source = binary.source;
            let total = source.len();
            if total > MAX_MODEL_BYTES {
                continue;
            }
            let Ok(bytes) = read_exact(&source, 0, total) else {
                continue;
            };
            let native = crate::files::resource_split_with(&entry, &access, &source)
                .ok()
                .flatten()
                .and_then(|split| usize::try_from(split.system_len).ok());
            let boundary = native.or_else(|| decoded::split_resource(&bytes).map(|s| s.system_len));
            let Some(system_len) = boundary.filter(|len| *len <= bytes.len()) else {
                continue;
            };
            read += 1;
            let (system, graphics) = bytes.split_at(system_len);
            let Ok(header) = lforge_rage9::fragment::header(system) else {
                continue;
            };
            let Some(report) = lforge_rage9::drawable::inspect_member_at(
                system,
                graphics,
                header.drawable as usize,
            ) else {
                continue;
            };
            let Some(at) = report.header.skeleton else {
                continue;
            };
            let skeleton = lforge_rage9::skeleton::inspect(system, at);
            if skeleton.bones.is_empty() {
                continue;
            }
            with_skeleton += 1;
            if skeleton.roots.len() > 1 {
                multi_root += 1;
            }
            let name = lforge_rage9::drawable::member_name_at(system, header.drawable as usize)
                .unwrap_or_default();
            let record = (
                skeleton.bones.len(),
                skeleton.roots.len(),
                skeleton.max_depth,
                chain.to_string(),
                name,
            );
            by_bones.push(record.clone());
            by_roots.push(record);
            by_bones.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
            by_bones.truncate(6);
            by_roots.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
            by_roots.truncate(6);
        }
        eprintln!(
            "chains read: {read}, with a skeleton: {with_skeleton}, multi-root: {multi_root}"
        );
        eprintln!("most bones:");
        for (bones, roots, depth, chain, name) in &by_bones {
            eprintln!("  {bones} bones, {roots} root(s), depth {depth}: {chain} {name}");
        }
        eprintln!("most roots:");
        for (bones, roots, depth, chain, name) in &by_roots {
            eprintln!("  {roots} root(s), {bones} bones, depth {depth}: {chain} {name}");
        }
        assert!(with_skeleton > 0, "no skeleton was read");
    }

    /// Measures the skeleton work of one real resource.
    ///
    /// Ignored by default. `LF_TEST_CHAIN_LIST` names a file of census chains,
    /// `LF_TEST_GAME_ROOT` the installation and `LF_TEST_EXECUTABLE` the
    /// executable that supplies the keys. `LF_MEASURE_ITERATIONS` sets how often
    /// each step repeats.
    ///
    /// This is a measurement, not a benchmark harness: it reports the cost of the
    /// skeleton steps on the resource the caller names, so a large and a small
    /// skeleton can be compared on the same machine in the same run.
    #[test]
    #[ignore = "requires LF_TEST_CHAIN_LIST, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
    fn measures_skeleton_work() {
        use std::time::Instant;

        let list = std::env::var("LF_TEST_CHAIN_LIST").expect("LF_TEST_CHAIN_LIST");
        let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let iterations: u32 = std::env::var("LF_MEASURE_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(50);
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let text = std::fs::read_to_string(&list).expect("chain list");
        let mut resolved = std::collections::BTreeMap::new();
        let mut index = std::collections::HashMap::new();
        for chain in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let Some((parent_chain, row)) = chain.rsplit_once('!') else {
                continue;
            };
            let Ok(row) = row.parse::<usize>() else {
                continue;
            };
            let Some(parent) = resolve_chain(
                Path::new(&root),
                &access,
                parent_chain,
                &mut resolved,
                &mut index,
            ) else {
                continue;
            };
            if !index.contains_key(&parent) {
                index.insert(parent.clone(), row_index(&parent, &access));
            }
            let Some(entry) = index.get(&parent).and_then(|rows| rows.get(&row)).cloned() else {
                continue;
            };
            let resource = match read_resource_with_cancel(&entry, &access, &cancel) {
                Ok(resource) => resource,
                Err(err) => {
                    eprintln!("{chain}: {err}");
                    continue;
                }
            };
            let system = resource.system();
            let graphics = resource.graphics();
            let Ok(header) = lforge_rage9::fragment::header(system) else {
                continue;
            };
            let Some(report) = lforge_rage9::drawable::inspect_member_at(
                system,
                graphics,
                header.drawable as usize,
            ) else {
                continue;
            };
            let Some(at) = report.header.skeleton else {
                continue;
            };

            let mut drawable_us = 0f64;
            for _ in 0..iterations {
                let start = Instant::now();
                let _ = lforge_rage9::fragment::header(system)
                    .ok()
                    .and_then(|header| {
                        lforge_rage9::drawable::inspect_member_at(
                            system,
                            graphics,
                            header.drawable as usize,
                        )
                    });
                drawable_us += start.elapsed().as_secs_f64() * 1e6;
            }
            let mut inspect_us = 0f64;
            for _ in 0..iterations {
                let start = Instant::now();
                let _ = lforge_rage9::skeleton::inspect(system, at);
                inspect_us += start.elapsed().as_secs_f64() * 1e6;
            }
            let report = lforge_rage9::skeleton::inspect(system, at);
            let bones = report.bones.len();
            let roots = report.roots.len();
            let depth = report.max_depth;
            let mut rows_us = 0f64;
            let mut filter_us = 0f64;
            if let Ok(loaded) = crate::files::model::load_with_cancel(
                &entry,
                &access,
                Some(Path::new(&root)),
                &cancel,
            ) && let Some(skeleton) = loaded.scene.skeleton.as_ref()
            {
                {
                    let panel = crate::viewers::BonePanel::new();
                    let filter_name = skeleton
                        .bones
                        .last()
                        .and_then(|bone| bone.name.clone())
                        .unwrap_or_default();
                    for _ in 0..iterations {
                        let start = Instant::now();
                        let _ = panel.rows(skeleton, "");
                        rows_us += start.elapsed().as_secs_f64() * 1e6;
                        let start = Instant::now();
                        let _ = panel.rows(skeleton, &filter_name);
                        filter_us += start.elapsed().as_secs_f64() * 1e6;
                    }
                    let start = Instant::now();
                    let _ = crate::files::model::load_with_cancel(
                        &entry,
                        &access,
                        Some(Path::new(&root)),
                        &cancel,
                    );
                    let load_ms = start.elapsed().as_secs_f64() * 1e3;
                    eprintln!(
                        "{chain}: {bones} bones, {roots} root(s), depth {depth}, {} geometries in the selected LOD",
                        loaded
                            .scene
                            .meshes
                            .iter()
                            .map(|mesh| mesh.primitives.len())
                            .sum::<usize>()
                    );
                    eprintln!(
                        "  drawable walk {:.1} us, skeleton inspect {:.1} us, hierarchy rows {:.1} us, filtered rows {:.1} us (mean of {iterations})",
                        drawable_us / f64::from(iterations),
                        inspect_us / f64::from(iterations),
                        rows_us / f64::from(iterations),
                        filter_us / f64::from(iterations)
                    );
                    eprintln!("  full load, geometry and textures included: {load_ms:.1} ms");
                    if let Ok(mut renderer) = lforge_renderer::Renderer::new() {
                        let options = |overlay| lforge_renderer::OffscreenOptions {
                            width: 640,
                            height: 480,
                            background: lforge_renderer::Background::DARK,
                            camera: None,
                            frame_scene: true,
                            overlay,
                        };
                        let mut upload_us = 0f64;
                        for _ in 0..10 {
                            let start = Instant::now();
                            let _ = renderer.upload_scene(&loaded.scene);
                            upload_us += start.elapsed().as_secs_f64() * 1e6;
                        }
                        let mut plain_us = f64::MAX;
                        let mut overlay_us = f64::MAX;
                        for _ in 0..20 {
                            let start = Instant::now();
                            let _ = renderer.render_offscreen(
                                &loaded.scene,
                                &options(lforge_renderer::Overlay::NONE),
                            );
                            plain_us = plain_us.min(start.elapsed().as_secs_f64() * 1e6);
                            let start = Instant::now();
                            let _ = renderer.render_offscreen(
                                &loaded.scene,
                                &options(lforge_renderer::Overlay::skeleton(None, true)),
                            );
                            overlay_us = overlay_us.min(start.elapsed().as_secs_f64() * 1e6);
                        }
                        eprintln!(
                            "  GPU: upload {:.0} us, offscreen render {:.0} us, with the skeleton overlay {:.0} us (minimum of 20)",
                            upload_us / 10.0,
                            plain_us,
                            overlay_us
                        );
                    }
                }
            }
            break;
        }
    }

    /// Loads one native chain through the shared loading path.
    pub(super) fn load_chain(
        root: &Path,
        access: &Access,
        chain: &str,
        cancel: &AtomicBool,
    ) -> Option<LoadedModel> {
        let (parent_chain, row) = chain.rsplit_once('!')?;
        let row = row.parse::<usize>().ok()?;
        let mut resolved = std::collections::BTreeMap::new();
        let mut index = std::collections::HashMap::new();
        let parent = resolve_chain(root, access, parent_chain, &mut resolved, &mut index)?;
        let rows = index
            .entry(parent.clone())
            .or_insert_with(|| row_index(&parent, access));
        let entry = rows.get(&row)?.clone();
        load_with_cancel(&entry, access, Some(root), cancel).ok()
    }

    /// Checks the reference resources the acceptance run depends on.
    ///
    /// Ignored by default. `LF_TEST_GAME_ROOT` names the installation and
    /// `LF_TEST_EXECUTABLE` the executable that supplies the keys.
    ///
    /// The numbers are the ones the previous work reported, so a regression in
    /// decoding or in texture reconstruction shows up as a changed count rather
    /// than as a preview nobody compares.
    #[test]
    #[ignore = "requires LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
    fn verifies_the_reference_resources() {
        let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let root = Path::new(&root);
        let expected: [(&str, &str, usize, usize, usize, usize, usize); 5] = [
            // chain, name, meshes, materials, textures, vertices, triangles
            (
                "levels.rpf!5!252",
                "prop_am_trophy_fish_06a_batchlod.#dr",
                1,
                1,
                5,
                171,
                158,
            ),
            (
                "levels.rpf!5!0",
                "prop_am_card_tarot_deck_01a.#ft",
                1,
                1,
                3,
                88,
                76,
            ),
            (
                "levels.rpf!5!1",
                "prop_am_candlestick_02a.#ft",
                1,
                2,
                6,
                927,
                1232,
            ),
            (
                "data.rpf!26!9",
                "w_sg_goodwin_01_bolt_01_mid.#ft",
                1,
                1,
                3,
                620,
                372,
            ),
            (
                "levels.rpf!5!8",
                "mint_peacock_taxidermy_01.#ft",
                1,
                4,
                16,
                41_613,
                45_132,
            ),
        ];
        for (chain, name, meshes, materials, textures, vertices, triangles) in expected {
            let Some(loaded) = load_chain(root, &access, chain, &cancel) else {
                panic!("{chain} did not load");
            };
            eprintln!(
                "{chain} {name}: {} meshes, {} materials, {} textures, {} vertices, {} triangles, skeleton {}, placement {}",
                loaded.scene.meshes.len(),
                loaded.scene.materials.len(),
                loaded.scene.textures.len(),
                loaded.scene.vertex_count(),
                loaded.scene.triangle_count(),
                loaded.completeness.skeleton.name(),
                loaded.completeness.placement.name()
            );
            assert_eq!(loaded.name, name, "{chain}");
            if meshes > 0 {
                assert_eq!(loaded.scene.meshes.len(), meshes, "{name} meshes");
            }
            if materials > 0 {
                assert_eq!(loaded.scene.materials.len(), materials, "{name} materials");
            }
            if textures > 0 {
                assert_eq!(loaded.scene.textures.len(), textures, "{name} textures");
            }
            if vertices > 0 {
                assert_eq!(loaded.scene.vertex_count(), vertices, "{name} vertices");
            }
            if triangles > 0 {
                assert_eq!(loaded.scene.triangle_count(), triangles, "{name} triangles");
            }
        }
    }

    /// Finds native drawable dictionaries whose members carry skeletons.
    ///
    /// Ignored by default. `LF_TEST_CHAIN_LIST` names type-4 census chains,
    /// `LF_TEST_GAME_ROOT` the installation and `LF_TEST_EXECUTABLE` the
    /// executable that supplies the keys. `LF_CHAIN_STRIDE` and `LF_CHAIN_LIMIT`
    /// bound the walk, and `LF_DICTIONARY_MEMBERS` bounds the members read from
    /// one dictionary.
    ///
    /// A manual check needs a dictionary it can name and two members whose
    /// skeletons differ, so this run reports exactly those and nothing else.
    #[test]
    #[ignore = "requires LF_TEST_CHAIN_LIST, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
    fn finds_skeleton_bearing_dictionaries() {
        let list = std::env::var("LF_TEST_CHAIN_LIST").expect("LF_TEST_CHAIN_LIST");
        let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let limit: usize = std::env::var("LF_CHAIN_LIMIT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(usize::MAX);
        let stride: usize = std::env::var("LF_CHAIN_STRIDE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(1);
        let member_cap: usize = std::env::var("LF_DICTIONARY_MEMBERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8);
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let text = std::fs::read_to_string(&list).expect("chain list");
        let mut resolved = std::collections::BTreeMap::new();
        let mut index = std::collections::HashMap::new();
        let mut read = 0usize;
        let mut with_skeleton = 0usize;
        let mut found: Vec<String> = Vec::new();
        let mut mixed: Vec<String> = Vec::new();
        let mut samples: Vec<String> = Vec::new();
        for chain in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .step_by(stride)
            .take(limit)
        {
            let Some((parent_chain, row)) = chain.rsplit_once('!') else {
                continue;
            };
            let Ok(row) = row.parse::<usize>() else {
                continue;
            };
            let Some(parent) = resolve_chain(
                Path::new(&root),
                &access,
                parent_chain,
                &mut resolved,
                &mut index,
            ) else {
                continue;
            };
            if !index.contains_key(&parent) {
                index.insert(parent.clone(), row_index(&parent, &access));
            }
            let Some(entry) = index.get(&parent).and_then(|rows| rows.get(&row)).cloned() else {
                continue;
            };
            read += 1;
            let Ok(dictionary) = enumerate_dictionary(&entry, &access, &cancel) else {
                continue;
            };
            let members = dictionary.info.drawable_members().count();
            let mut lines = Vec::new();
            let mut bone_counts: Vec<usize> = Vec::new();
            for member in 0..members.min(member_cap) {
                let Ok(loaded) = load_dictionary_member(
                    &entry,
                    &access,
                    Some(Path::new(&root)),
                    member,
                    &cancel,
                ) else {
                    continue;
                };
                let bones = loaded
                    .scene
                    .skeleton
                    .as_ref()
                    .map_or(0, |skeleton| skeleton.bones.len());
                bone_counts.push(bones);
                let Some(skeleton) = loaded.scene.skeleton.as_ref() else {
                    continue;
                };
                lines.push(format!(
                    "  member {member} {}: {} bones, {} root(s), depth {}, placement {}, associations {}",
                    loaded.name,
                    skeleton.bones.len(),
                    skeleton.roots.len(),
                    skeleton.max_depth,
                    loaded.completeness.placement.name(),
                    loaded.completeness.associations.name()
                ));
            }
            if !lines.is_empty() {
                with_skeleton += 1;
                let mut block = format!("{chain}: {members} member(s)");
                for line in &lines {
                    block.push('\n');
                    block.push_str(line);
                }
                if lines.len() > 1 {
                    found.push(block.clone());
                }
                if samples.len() < 8 {
                    samples.push(block);
                }
            }
            let bearing = bone_counts.iter().filter(|bones| **bones > 0).count();
            if bearing > 0 && bearing < bone_counts.len() && mixed.len() < 6 {
                // A member that carries no skeleton in the same dictionary is
                // what a manual switch check needs, so name the counts.
                mixed.push(format!(
                    "{chain}: {members} member(s), bone counts {bone_counts:?}"
                ));
            }
        }
        eprintln!("dictionaries read: {read}, with a skeleton-bearing member: {with_skeleton}");
        for sample in samples.iter().take(6) {
            eprintln!("{sample}");
        }
        eprintln!(
            "dictionaries with differing bone counts among the members read: {}",
            found.len()
        );
        for block in found.iter().take(6) {
            eprintln!("{block}");
        }
        eprintln!(
            "dictionaries with both a skeleton-bearing and a skeleton-free member: {}",
            mixed.len()
        );
        for line in &mixed {
            eprintln!("{line}");
        }
        assert!(read > 0, "no dictionary was read");
    }

    /// Renders the three verification views of each listed resource.
    ///
    /// Ignored by default. `LF_TEST_CHAIN_LIST` names native chains,
    /// `LF_TEST_GAME_ROOT` and `LF_TEST_EXECUTABLE` the installation, and
    /// `LF_RENDER_DIR` the directory the raw RGBA8 frames are written to. With
    /// `LF_RENDER_DICTIONARY_MEMBER` set, each chain is read as a dictionary and
    /// its member at that index is rendered. The frames are raw so this needs no
    /// image dependency; `analysis/skeleton-bind-pose/rgba_to_png.py` turns them
    /// into PNGs.
    ///
    /// The views are the plain model, the model with the skeleton overlay, and
    /// the skeleton alone framed on its own bounds. A skeleton view must differ
    /// from the plain view, and the plain view must be stable across two renders,
    /// so a silently missing overlay cannot pass.
    #[test]
    #[ignore = "requires LF_TEST_CHAIN_LIST, LF_TEST_GAME_ROOT, LF_TEST_EXECUTABLE and LF_RENDER_DIR"]
    fn renders_skeleton_samples() {
        let list = std::env::var("LF_TEST_CHAIN_LIST").expect("LF_TEST_CHAIN_LIST");
        let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
        let out = std::env::var("LF_RENDER_DIR").expect("LF_RENDER_DIR");
        let member: Option<usize> = std::env::var("LF_RENDER_DICTIONARY_MEMBER")
            .ok()
            .and_then(|value| value.parse().ok());
        let access = Access::with(Arc::new(
            Executable::open(Path::new(&executable)).expect("executable"),
        ));
        let cancel = AtomicBool::new(false);
        let root = Path::new(&root);
        let out = Path::new(&out);
        let text = std::fs::read_to_string(&list).expect("chain list");
        let mut resolved = std::collections::BTreeMap::new();
        let mut index = std::collections::HashMap::new();
        let mut rendered = 0usize;
        for chain in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let (scene, label) = match member {
                Some(index_in_dictionary) => {
                    let Some((parent_chain, row)) = chain.rsplit_once('!') else {
                        continue;
                    };
                    let Ok(row) = row.parse::<usize>() else {
                        continue;
                    };
                    let Some(parent) =
                        resolve_chain(root, &access, parent_chain, &mut resolved, &mut index)
                    else {
                        continue;
                    };
                    if !index.contains_key(&parent) {
                        index.insert(parent.clone(), row_index(&parent, &access));
                    }
                    let Some(entry) = index.get(&parent).and_then(|rows| rows.get(&row)).cloned()
                    else {
                        continue;
                    };
                    match load_dictionary_member(
                        &entry,
                        &access,
                        Some(root),
                        index_in_dictionary,
                        &cancel,
                    ) {
                        Ok(loaded) => (loaded.scene, loaded.name),
                        Err(err) => {
                            eprintln!("{chain}: member {index_in_dictionary} did not load: {err}");
                            continue;
                        }
                    }
                }
                None => match load_chain(root, &access, chain, &cancel) {
                    Some(loaded) => (loaded.scene, loaded.name),
                    None => {
                        eprintln!("{chain}: did not load");
                        continue;
                    }
                },
            };
            let Some(bones) = scene.skeleton.as_ref().map(|skeleton| skeleton.bones.len()) else {
                eprintln!("{chain}: no skeleton");
                continue;
            };
            let mut renderer = match lforge_renderer::Renderer::new() {
                Ok(renderer) => renderer,
                Err(err) => {
                    eprintln!("{chain}: no renderer: {err}");
                    continue;
                }
            };
            let gpu = renderer.upload_scene(&scene).expect("upload");
            let camera = lforge_renderer::OrbitCamera::framing(scene.bounds, 16.0 / 9.0);
            let plain = renderer
                .render(&gpu, &camera, 1280, 720, lforge_renderer::Background::DARK)
                .expect("plain render");
            let again = renderer
                .render(&gpu, &camera, 1280, 720, lforge_renderer::Background::DARK)
                .expect("plain render");
            assert_eq!(
                plain.pixels, again.pixels,
                "{chain}: plain render is stable"
            );
            let overlay = renderer
                .render_with_overlay(
                    &gpu,
                    &camera,
                    1280,
                    720,
                    lforge_renderer::Background::DARK,
                    lforge_renderer::Overlay::skeleton(None, true),
                )
                .expect("overlay render");
            if overlay.pixels == plain.pixels {
                // The camera frames the meshes, so an overlay that draws nothing
                // here is only acceptable when the skeleton lies outside that
                // frame. A skeleton inside the frame that drew no pixel is a
                // defect, and the assertion below says so with the bounds.
                let skeleton = scene.skeleton_bounds().unwrap_or(scene.bounds);
                let mesh = scene.bounds;
                let outside = skeleton.min.x > mesh.max.x
                    || skeleton.max.x < mesh.min.x
                    || skeleton.min.y > mesh.max.y
                    || skeleton.max.y < mesh.min.y
                    || skeleton.min.z > mesh.max.z
                    || skeleton.max.z < mesh.min.z;
                assert!(
                    outside,
                    "{chain}: the overlay changed no pixel although the skeleton {skeleton:?} lies inside the framed meshes {mesh:?}"
                );
                eprintln!(
                    "{chain}: the skeleton lies outside the mesh bounds, so the overlay adds no pixel at this camera"
                );
            }
            let mut only_gpu = renderer.upload_scene(&scene).expect("upload");
            only_gpu.set_skeleton_visible(true);
            for mesh in 0..scene.meshes.len() {
                only_gpu.set_mesh_visible(mesh, false);
            }
            let bounds = scene.skeleton_bounds().unwrap_or(scene.bounds);
            let only_camera = lforge_renderer::OrbitCamera::framing(bounds, 16.0 / 9.0);
            let only = renderer
                .render(
                    &only_gpu,
                    &only_camera,
                    1280,
                    720,
                    lforge_renderer::Background::DARK,
                )
                .expect("skeleton-only render");
            assert!(
                only.pixels != plain.pixels,
                "{chain}: the skeleton-only view equals the model view"
            );
            let stem = chain.replace(['/', '!', '\\'], "-");
            for (suffix, frame) in [("default", &plain), ("skeleton", &overlay), ("only", &only)] {
                let path = out.join(format!("{stem}-{suffix}.rgba"));
                std::fs::write(&path, &frame.pixels).expect("write frame");
            }
            eprintln!("{chain} {label}: {bones} bone(s), wrote three 1280x720 frames");
            rendered += 1;
        }
        assert!(rendered > 0, "no resource was rendered");
    }
}

/// The declaration survey lives beside the loader so it can reuse the archive
/// walk. It is test-only: nothing in the application calls it.
#[cfg(test)]
#[path = "model_survey.rs"]
mod survey;
