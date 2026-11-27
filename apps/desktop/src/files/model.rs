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

/// The row number a native row path carries, as the table of contents labels
/// it (`Row 00042`).
#[cfg(test)]
fn row_number(path: &Path) -> Option<usize> {
    path.file_name()?
        .to_str()?
        .strip_prefix("Row ")?
        .parse()
        .ok()
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
            if row_number(&entry.path) == Some(row) {
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

    /// The archives a survey reads: `LF_TEST_ARCHIVE_LIST` names a file of
    /// paths, `LF_TEST_CHAIN_LIST` a file of census chains (`a.rpf!5!3`), and
    /// `LF_TEST_ARCHIVE_DIR` a directory of `.rpf` files. A chain list resolves
    /// to the archives that directly hold the entries, so an installation-wide
    /// census can drive the survey without extracting anything.
    fn survey_archives() -> Vec<std::path::PathBuf> {
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
    fn resolve_chain(
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
    fn row_index(
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
                if let Some(row) = row_number(&entry.path) {
                    index.insert(row, entry.path.clone());
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
        for entry in entries
            .iter()
            .filter(|entry| rows.contains(&row_number(&entry.path).unwrap_or(usize::MAX)))
        {
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
                    if mismatch_samples.len() < 10 {
                        mismatch_samples.push(format!(
                            "{}: native {:#x}, inferred {}, {outcome}",
                            entry.path.display(),
                            native.unwrap_or_default(),
                            inferred.map_or_else(
                                || "none".to_string(),
                                |inferred| format!("{inferred:#x}")
                            )
                        ));
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
    struct SurveyRow {
        path: std::path::PathBuf,
        bytes: Vec<u8>,
        system_len: usize,
        native: bool,
    }

    impl SurveyRow {
        fn segments(&self) -> (&[u8], &[u8]) {
            self.bytes.split_at(self.system_len)
        }
    }

    /// Reads every row of `type_id` in the caller-named archives and calls
    /// `visit` for each. Returns the archives listed, the rows the metadata
    /// declares, the rows read, and the rows that could not be read.
    fn survey_rows(
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
}
