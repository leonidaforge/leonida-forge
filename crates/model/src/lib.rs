//! Decoding of a drawable resource into renderer-independent scene data.
//!
//! The structural walk comes from [`lforge_rage9::drawable`]. This module adds the
//! parts the research established after that walk: the mesh-blob stream table,
//! the position quantiser and its axis rotation, octahedral normals, UVs,
//! tangents, meshlet indices, and the shader texture references. Geometry is
//! emitted in RAGE model space (Z up, metres), which is also the bind pose of
//! skinned meshes; animation is out of scope.
//!
//! A texture that cannot be resolved is reported in [`DecodedModel::scene`]
//! diagnostics and the material is marked as missing a texture. The decoder
//! never substitutes a texture whose key merely looks similar.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::AtomicBool;

use glam::Vec3;
use lforge_rage9::drawable::{self, Geometry, IndexView, Report, Shader, VertexBuffer};
use lforge_rage9::drawable_dictionary;
use lforge_rage9::fragment;
use lforge_scene::{
    AlphaMode, Diagnostic, Material, Mesh, Primitive, Scene, Texture, TextureBinding,
    TextureFormat, TextureSemantic, Vertex,
};
use lforge_texture::{Codec, EmbeddedTexture, SourceLevel, decode_embedded, embedded_textures};

/// Largest vertex or index count accepted from one geometry.
const MAX_VERTICES: usize = 8 << 20;
const MAX_INDICES: usize = 32 << 20;
const MAX_MESHLETS: usize = u16::MAX as usize;
const VERTEX_PREFIX: usize = 0x80;
const FLOAT_VERTEX_PREFIX: usize = 0x60;

pub const DIFFUSE_TEX: u32 = 0xC8E8_C282;
pub const DIFFUSE_TEX2: u32 = 0x0DF4_7048;
pub const BUMP_TEX: u32 = 0x1E77_BF4C;
pub const SPECULAR_TEX: u32 = 0xC6F4_6E79;
pub const SPECULAR_TEX2: u32 = 0x739E_3D0D;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// The texture reference a material asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureReference {
    /// The 64-bit key shared with the `.ttpf` stores.
    pub key64: u64,
    /// The 32-bit dictionary-name hash, when the record carries it.
    pub hash32: Option<u32>,
    /// The material parameter name hash.
    pub parameter: u32,
    pub material: String,
}

/// A source level and where it came from, before the model-specific
/// conversion to a drawable texture.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedTexture {
    pub level: SourceLevel,
    pub source: String,
}

/// How an external texture resolved.
#[derive(Debug, Clone, PartialEq)]
pub enum TextureResolution {
    Missing,
    Resolved(ResolvedTexture),
    /// More than one store or descriptor carries the key.
    Ambiguous(Vec<String>),
    /// The reference was found but its bytes could not be decoded.
    Failed(String),
}

fn texture_from_source(level: SourceLevel, source: String) -> Result<Texture, String> {
    let format = match (level.codec(), level.format.srgb) {
        (Some(Codec::Rgba8), false) => TextureFormat::Rgba8Unorm,
        (Some(Codec::Rgba8), true) => TextureFormat::Rgba8UnormSrgb,
        (Some(Codec::R16Float), _) => TextureFormat::R16Float,
        (Some(Codec::Bc1), false) => TextureFormat::Bc1Unorm,
        (Some(Codec::Bc1), true) => TextureFormat::Bc1UnormSrgb,
        (Some(Codec::Bc3), false) => TextureFormat::Bc3Unorm,
        (Some(Codec::Bc3), true) => TextureFormat::Bc3UnormSrgb,
        (Some(Codec::Bc4), _) => TextureFormat::Bc4Unorm,
        (Some(Codec::Bc5), _) => TextureFormat::Bc5Unorm,
        (Some(Codec::Bc7), false) => TextureFormat::Bc7Unorm,
        (Some(Codec::Bc7), true) => TextureFormat::Bc7UnormSrgb,
        (None, _) => return Err("the texture format has no pixel layout".into()),
    };
    let texture = Texture {
        name: source.clone(),
        width: level.width,
        height: level.height,
        format,
        source_mip_levels: 1,
        data: level.data,
        source,
    };
    texture.validate()?;
    Ok(texture)
}

/// The asset layer implements this over the texture stores it can reach.
pub trait TextureProvider {
    fn resolve(&self, reference: &TextureReference) -> TextureResolution;
}

/// A provider for callers that only need geometry or embedded textures.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoTextures;

impl TextureProvider for NoTextures {
    fn resolve(&self, _reference: &TextureReference) -> TextureResolution {
        TextureResolution::Missing
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeometryCompleteness {
    /// The resource's highest populated LOD was decoded from the root drawable
    /// and the structural walk reported no issues.
    Complete,
    /// A supported drawable was decoded, but the resource holds additional
    /// members, a non-root root was selected, or the structural walk reported
    /// issues.
    Partial { reason: String },
    /// The resource is not a supported drawable.
    Unsupported { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextureCompleteness {
    /// Every material texture reference resolved and reconstructed.
    Complete,
    /// At least one material uses a fallback.
    Partial { missing: usize },
    /// No material binds a texture.
    NotReferenced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCompleteness {
    pub geometry: GeometryCompleteness,
    pub textures: TextureCompleteness,
    /// System offset of the selected drawable root.
    pub selected_root: usize,
    pub selected_name: Option<String>,
    pub notes: Vec<String>,
}

/// What happened to one material texture reference. Every bound slot is
/// reported, including references that no store could satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextureBindingStatus {
    Resolved,
    Missing,
    Ambiguous(Vec<String>),
    Failed(String),
}

/// Provenance for one material texture reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureBindingReport {
    pub material: String,
    pub parameter: u32,
    pub semantic: lforge_scene::TextureSemantic,
    pub key64: u64,
    pub hash32: Option<u32>,
    /// The record was embedded in the drawable rather than looked up in a store.
    pub embedded: bool,
    /// Index in [`Scene::textures`] when the texture was reconstructed.
    pub texture: Option<usize>,
    pub status: TextureBindingStatus,
}

#[derive(Debug, Clone)]
pub struct DecodedModel {
    pub scene: Scene,
    pub report: Report,
    /// The LOD slot that was decoded; 0 is the highest quality present.
    pub lod: usize,
    /// Geometry and texture completeness are separate properties.
    pub completeness: ModelCompleteness,
    /// Every bound texture reference with its resolution status.
    pub texture_bindings: Vec<TextureBindingReport>,
}

/// Whether the resource has the header and LOD chain of a drawable at zero.
pub fn is_drawable(system: &[u8], graphics: &[u8]) -> bool {
    drawable::is_drawable(system, graphics)
}

/// Whether the resource holds a drawable at zero or as a fragment member.
pub fn has_drawable(system: &[u8], graphics: &[u8]) -> bool {
    find_drawable_root(system, graphics).is_some()
}

/// A reconstructed resource split into its system and graphics segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceSplit {
    pub system_len: usize,
    /// How many distinct graphics pointers supported the split.
    pub support: usize,
    /// Several splits were supported equally well.
    pub ambiguous: bool,
}

/// Infers the system/graphics boundary of a reconstructed resource.
///
/// The decoded bytes do not store the boundary. A drawable's vertex-buffer
/// graphics pointers and the mesh-blob marker at their targets do: a
/// candidate boundary is the offset that puts at least one pointer on a
/// marker, and a valid drawable at system zero wins. This is used for files
/// whose archive metadata is not available to the caller; the exact boundary
/// is preferred there when the archive layer can provide it.
pub fn split_resource(bytes: &[u8]) -> Option<ResourceSplit> {
    if bytes.len() < 0x200 || u64_at(bytes, 0) != Some(0) {
        return None;
    }
    let marker = [0x42, 0x40, 0x00, 0x00];
    let markers: Vec<usize> = bytes
        .windows(4)
        .take(4 << 20)
        .enumerate()
        .filter(|(_, window)| *window == marker)
        .map(|(offset, _)| offset)
        .take(2048)
        .collect();
    if markers.is_empty() {
        return None;
    }
    let pointers: Vec<u64> = (0..bytes.len().saturating_sub(8).min(4 << 20))
        .step_by(8)
        .filter_map(|offset| u64_at(bytes, offset))
        .filter(|value| value >> 28 == 6)
        .map(|value| value & 0x0FFF_FFFF)
        .filter(|offset| *offset < (4 << 20))
        .collect();
    let mut candidates: HashMap<usize, usize> = HashMap::new();
    for &marker_at in &markers {
        for &pointer in &pointers {
            let pointer = pointer as usize;
            if pointer >= marker_at {
                continue;
            }
            let split = marker_at - pointer;
            if split < 0x100 || split >= bytes.len() {
                continue;
            }
            *candidates.entry(split).or_default() += 1;
        }
    }
    let mut ranked: Vec<(usize, usize)> = candidates.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut fallback = None;
    for (split, support) in ranked.into_iter().take(64) {
        let (system, graphics) = bytes.split_at(split);
        if lforge_rage9::resource::page_map_offset(system).is_none() {
            continue;
        }
        if drawable::is_drawable(system, graphics) {
            return Some(ResourceSplit {
                system_len: split,
                support,
                ambiguous: false,
            });
        }
        if fallback.is_none() {
            fallback = Some((split, support));
        }
    }
    fallback.map(|(system_len, support)| ResourceSplit {
        system_len,
        support,
        ambiguous: false,
    })
}

/// Decodes the highest populated LOD of a drawable.
pub fn decode(
    system: &[u8],
    graphics: &[u8],
    provider: &dyn TextureProvider,
) -> Result<DecodedModel, Error> {
    let (root, report, candidates) = find_drawable_root(system, graphics)
        .ok_or_else(|| Error::new("the resource holds no drawable root"))?;
    let built = build_scene(system, graphics, provider, &report, None)?;
    let BuiltScene {
        scene,
        texture_bindings,
        lod_index,
        expected_geometries,
        decoded_geometries,
        geometry_failures,
    } = built;
    let missing_textures = scene
        .materials
        .iter()
        .filter(|material| material.missing_texture)
        .count();
    let referenced = scene
        .materials
        .iter()
        .any(|material| !material.bindings.is_empty());
    let textures = texture_completeness(missing_textures, referenced);
    let selected_name = report.header.name_text.clone();
    let mut notes = vec![format!("drawable root at system +{root:#x}")];
    if candidates > 1 {
        notes.push(format!(
            "{candidates} drawable roots resolved; one was selected"
        ));
    }
    let geometry = geometry_completeness(
        root,
        candidates,
        report.issues.len(),
        expected_geometries,
        decoded_geometries,
        geometry_failures,
    );
    Ok(DecodedModel {
        scene,
        report,
        lod: lod_index,
        completeness: ModelCompleteness {
            geometry,
            textures,
            selected_root: root,
            selected_name,
            notes,
        },
        texture_bindings,
    })
}

/// The scene one drawable report yields, before a completeness verdict.
struct BuiltScene {
    scene: Scene,
    texture_bindings: Vec<TextureBindingReport>,
    lod_index: usize,
    expected_geometries: usize,
    decoded_geometries: usize,
    geometry_failures: usize,
}

/// Decodes the highest populated LOD of `report` into scene data.
///
/// `label` prefixes the mesh names, so a caller that assembles several
/// drawables keeps their meshes distinguishable. A resource-level drawable
/// passes `None` and keeps the historical mesh names.
fn build_scene(
    system: &[u8],
    graphics: &[u8],
    provider: &dyn TextureProvider,
    report: &Report,
    label: Option<&str>,
) -> Result<BuiltScene, Error> {
    let lod_index = report
        .lod
        .iter()
        .position(|slot| !slot.models.is_empty())
        .ok_or_else(|| Error::new("the drawable has no populated LOD"))?;
    let lod = &report.lod[lod_index];
    let expected_geometries: usize = lod.models.iter().map(|model| model.geometries.len()).sum();
    let mut scene = Scene::new();
    let mut diagnostics: Vec<Diagnostic> = report
        .issues
        .iter()
        .map(|issue| Diagnostic::new(issue.to_string()))
        .collect();

    let embedded: HashMap<u64, EmbeddedTexture> = embedded_textures(system, graphics)
        .into_iter()
        .map(|texture| (texture.key, texture))
        .collect();
    let mut embedded_indices: HashMap<u64, (Option<usize>, TextureBindingStatus)> = HashMap::new();
    let mut external_indices: HashMap<u64, (Option<usize>, TextureBindingStatus)> = HashMap::new();
    let mut texture_bindings = Vec::new();

    let used_shaders = used_shader_indices(system, lod, &mut diagnostics);
    let mut shader_materials: HashMap<usize, usize> = HashMap::new();
    if let Some(group) = &report.shader_group {
        let mut context = MaterialContext {
            provider,
            graphics,
            embedded: &embedded,
            embedded_indices: &mut embedded_indices,
            external_indices: &mut external_indices,
            texture_bindings: &mut texture_bindings,
            scene: &mut scene,
            diagnostics: &mut diagnostics,
        };
        for &shader_index in &used_shaders {
            let Some(shader) = group.shaders.get(shader_index) else {
                continue;
            };
            let material = build_material(shader, shader_index, &mut context);
            shader_materials.insert(shader_index, context.scene.materials.len());
            context.scene.materials.push(material);
        }
    }
    if scene.materials.is_empty() {
        scene.materials.push(Material::default());
    }

    let mut decoded_geometries = 0usize;
    let mut geometry_failures = 0usize;
    let base_name = match label {
        Some(label) => label.to_string(),
        None => report
            .header
            .name_text
            .clone()
            .unwrap_or_else(|| "drawable".to_string()),
    };
    for (model_index, model) in lod.models.iter().enumerate() {
        let mut mesh = Mesh::new(format!("{base_name} model {model_index}"));
        for (geometry_index, geometry) in model.geometries.iter().enumerate() {
            let shader_index = read_shader_index(system, model, geometry_index).unwrap_or(0);
            let material = shader_materials.get(&shader_index).copied().unwrap_or(0);
            if !shader_materials.contains_key(&shader_index) {
                diagnostics.push(
                    Diagnostic::new(format!(
                        "geometry {geometry_index} uses shader {shader_index}, which is not present"
                    ))
                    .with_mesh(mesh.name.clone()),
                );
            }
            match decode_geometry(graphics, geometry, &mut diagnostics) {
                Ok(mut primitive) => {
                    primitive.material = material;
                    mesh.primitives.push(primitive);
                    decoded_geometries += 1;
                }
                Err(reason) => {
                    geometry_failures += 1;
                    diagnostics.push(Diagnostic::new(reason).with_mesh(mesh.name.clone()));
                }
            }
        }
        if !mesh.primitives.is_empty() {
            scene.meshes.push(mesh);
        }
    }

    if scene.meshes.is_empty() {
        return Err(Error::new("the drawable yielded no renderable mesh"));
    }
    scene.diagnostics.extend(diagnostics);
    let validation = scene.validate();
    scene.diagnostics.extend(validation);
    Ok(BuiltScene {
        scene,
        texture_bindings,
        lod_index,
        expected_geometries,
        decoded_geometries,
        geometry_failures,
    })
}

/// Whether the resource has the root header of a fragment and a member
/// drawable named as a fragment.
pub fn is_fragment(system: &[u8], graphics: &[u8]) -> bool {
    fragment::inspect(system, graphics).is_some()
}

/// What happened to one fragment component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentStatus {
    /// Every geometry record of the selected LOD decoded.
    Decoded,
    /// The drawable was reached but some geometry records did not decode.
    Unsupported(String),
}

/// One component of a fragment.
///
/// A component is one member drawable: a root reference this decoder followed.
/// A component's meshes are the models of that drawable's selected LOD, one
/// mesh per model, and a geometry record becomes a primitive inside its model's
/// mesh. The three counts therefore differ, and a mesh is never a component.
///
/// The verified corpus holds one component per fragment; the type is a list so a
/// fragment with several member drawables would not need a new shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentComponent {
    /// The order this component was enumerated in.
    pub index: usize,
    /// The member drawable's name, as the resource stores it.
    pub name: Option<String>,
    /// System offset of the member drawable.
    pub drawable_at: usize,
    /// The LOD slot that was decoded, when one was populated.
    pub lod: Option<usize>,
    /// The meshes this component contributed, as scene mesh indices.
    pub meshes: std::ops::Range<usize>,
    pub primitives: usize,
    pub vertices: usize,
    pub triangles: usize,
    pub status: ComponentStatus,
}

/// Fragment completeness for the selected static representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentCompleteness {
    /// The verified fragment variant: the root references one member drawable,
    /// that drawable's highest populated LOD decoded, and the structural walk
    /// reported no issue.
    ///
    /// The root also stores pointers at `+0x10`, `+0x20` and `+0x28` whose
    /// targets are not identified, so this verdict covers the assembled
    /// geometry only; it is not a claim about other fragment variants, damage
    /// states or physics data.
    SinglePrimaryDrawable,
    /// Part of the fragment was decoded.
    Partial { reason: String },
    /// The resource is not a supported fragment.
    Unsupported { reason: String },
}

/// A decoded fragment: one assembled scene plus the components it came from.
#[derive(Debug, Clone)]
pub struct DecodedFragment {
    pub scene: Scene,
    pub report: fragment::Report,
    pub components: Vec<FragmentComponent>,
    pub completeness: FragmentCompleteness,
    pub texture_bindings: Vec<TextureBindingReport>,
    /// The LOD slot of the member drawable that was decoded.
    pub lod: usize,
}

/// Whether the resource is a drawable dictionary: a `pgDictionary`-shaped root
/// whose members are member drawables.
pub fn is_drawable_dictionary(system: &[u8], graphics: &[u8]) -> bool {
    drawable_dictionary::is_drawable_dictionary(system, graphics)
}

/// What one dictionary member entry turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DictionaryMemberState {
    /// The value resolves to a member drawable.
    Drawable,
    /// The value is null.
    Null,
    /// The value is not a system pointer.
    NotAPointer,
    /// The value points at system data without the member drawable form.
    NotADrawable,
}

impl DictionaryMemberState {
    pub fn name(self) -> &'static str {
        match self {
            DictionaryMemberState::Drawable => "drawable",
            DictionaryMemberState::Null => "null",
            DictionaryMemberState::NotAPointer => "not a pointer",
            DictionaryMemberState::NotADrawable => "not a drawable",
        }
    }
}

/// One member of a drawable dictionary, enumerated without decoding geometry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryMember {
    /// The position in the dictionary. It is the stable identifier to select a
    /// member by: the hash array is sorted, so positions do not depend on the
    /// order the members were authored in. A position identifies one member
    /// even when two members share a hash or a drawable pointer.
    pub index: usize,
    /// The stored name hash, which equals `joaat` of the member's own name.
    pub hash: u32,
    /// System offset of the member drawable, when the value is a system pointer.
    pub drawable: Option<usize>,
    /// The member drawable's stored name, when it has one.
    pub name: Option<String>,
    /// `joaat` of the stored name, computed here and reported next to the
    /// stored hash. The stored name carries a final extension that the hash
    /// does not cover, so the hash is computed with that extension removed.
    pub name_hash: Option<u32>,
    /// Whether [`DictionaryMember::name_hash`] equals the stored
    /// [`DictionaryMember::hash`]. `None` when the member has no name.
    pub hash_matches_name: Option<bool>,
    pub state: DictionaryMemberState,
}

impl DictionaryMember {
    /// The `joaat` hash a stored member name implies, with the final extension
    /// removed. `None` when the member has no stored name.
    pub fn hash_of_name(name: &str) -> u32 {
        let stem = name.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(name);
        lforge_rage9::rpf::names::joaat(stem.as_bytes())
    }
}

/// The dictionary as enumerated: membership only, no geometry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryInfo {
    pub page_map: u32,
    /// The words at `+0x10` and `+0x18`. Their meanings are not established.
    pub word_10: u64,
    pub word_18: u64,
    pub count: u16,
    pub capacity: u16,
    /// Whether the root holds no members. An empty dictionary is valid.
    pub empty: bool,
    /// Whether the hash array is ascending and duplicate-free.
    pub hash_sorted: bool,
    pub members: Vec<DictionaryMember>,
    /// One line per member that does not resolve, and per structural check
    /// that did not hold. A failed member does not invalidate the others.
    pub issues: Vec<String>,
}

impl DictionaryInfo {
    /// The members whose value resolves to a member drawable.
    pub fn drawable_members(&self) -> impl Iterator<Item = &DictionaryMember> {
        self.members
            .iter()
            .filter(|member| member.state == DictionaryMemberState::Drawable)
    }
}

/// Enumerates a drawable dictionary without decoding any member.
pub fn dictionary_info(system: &[u8], graphics: &[u8]) -> Option<DictionaryInfo> {
    let report = drawable_dictionary::parse(system, graphics).ok()?;
    let mut issues = Vec::new();
    if !report.hash_sorted {
        issues.push("the hash array is not ascending and duplicate-free".to_string());
    }
    for member in &report.members {
        if member.state != drawable_dictionary::MemberState::Drawable {
            issues.push(format!(
                "member {} hash {:#010x}: {}",
                member.index,
                member.hash,
                member.state.name()
            ));
        }
    }
    let members = report
        .members
        .iter()
        .map(|member| {
            let name_hash = member.name.as_deref().map(DictionaryMember::hash_of_name);
            DictionaryMember {
                index: member.index as usize,
                hash: member.hash,
                drawable: member.drawable.map(|at| at as usize),
                name: member.name.clone(),
                name_hash,
                hash_matches_name: name_hash.map(|hash| hash == member.hash),
                state: match member.state {
                    drawable_dictionary::MemberState::Drawable => DictionaryMemberState::Drawable,
                    drawable_dictionary::MemberState::Null => DictionaryMemberState::Null,
                    drawable_dictionary::MemberState::NotAPointer => {
                        DictionaryMemberState::NotAPointer
                    }
                    drawable_dictionary::MemberState::NotADrawable => {
                        DictionaryMemberState::NotADrawable
                    }
                },
            }
        })
        .collect();
    Some(DictionaryInfo {
        page_map: report.header.page_map,
        word_10: report.header.word_10,
        word_18: report.header.word_18,
        count: report.header.count,
        capacity: report.header.capacity,
        empty: report.empty,
        hash_sorted: report.hash_sorted,
        members,
        issues,
    })
}

/// One decoded dictionary member.
#[derive(Debug, Clone)]
pub struct DecodedDictionaryMember {
    pub scene: Scene,
    pub report: drawable::Report,
    pub member: DictionaryMember,
    /// Completeness of this member only. The dictionary's own enumeration
    /// status stays in [`DictionaryInfo`] and is never overwritten by this.
    pub completeness: ModelCompleteness,
    pub texture_bindings: Vec<TextureBindingReport>,
    pub lod: usize,
}

/// Decodes one dictionary member into its own scene.
///
/// The member keeps the dictionary's resource context: its system and graphics
/// segments supply the geometry and any embedded textures, exactly as they do
/// for a standalone drawable. Nothing of the other members is decoded.
pub fn decode_dictionary_member(
    system: &[u8],
    graphics: &[u8],
    index: usize,
    provider: &dyn TextureProvider,
) -> Result<DecodedDictionaryMember, Error> {
    let info = dictionary_info(system, graphics)
        .ok_or_else(|| Error::new("the resource is not a drawable dictionary"))?;
    let member = info
        .members
        .get(index)
        .cloned()
        .ok_or_else(|| Error::new(format!("the dictionary has no member {index}")))?;
    let at = member.drawable.ok_or_else(|| {
        Error::new(format!(
            "member {index} does not reference a drawable ({})",
            member.state.name()
        ))
    })?;
    let report = drawable::inspect_member_at(system, graphics, at).ok_or_else(|| {
        Error::new(format!(
            "member {index} at system +{at:#x} is not a member drawable"
        ))
    })?;
    let built = build_scene(system, graphics, provider, &report, member.name.as_deref())?;
    let BuiltScene {
        scene,
        texture_bindings,
        lod_index,
        expected_geometries,
        decoded_geometries,
        geometry_failures,
    } = built;
    let missing_textures = scene
        .materials
        .iter()
        .filter(|material| material.missing_texture)
        .count();
    let referenced = scene
        .materials
        .iter()
        .any(|material| !material.bindings.is_empty());
    let textures = texture_completeness(missing_textures, referenced);
    let geometry = if report.issues.is_empty()
        && geometry_failures == 0
        && decoded_geometries == expected_geometries
    {
        GeometryCompleteness::Complete
    } else {
        GeometryCompleteness::Partial {
            reason: if !report.issues.is_empty() {
                format!(
                    "the member drawable's structural walk reported {} issue(s)",
                    report.issues.len()
                )
            } else {
                format!("decoded {decoded_geometries} of {expected_geometries} geometries")
            },
        }
    };
    let notes = vec![
        format!("dictionary member {} of {}", member.index, info.count),
        format!("member name hash {:#010x}", member.hash),
    ];
    Ok(DecodedDictionaryMember {
        scene,
        report,
        completeness: ModelCompleteness {
            geometry,
            textures,
            selected_root: at,
            selected_name: member.name.clone(),
            notes,
        },
        texture_bindings,
        lod: lod_index,
        member,
    })
}

/// Decodes a supported fragment into one assembled scene.
///
/// Only the member drawable the root references is assembled. The verified
/// samples hold exactly one such reference; the root's other pointers are
/// reported uninterpreted instead of being scanned for more drawables.
pub fn decode_fragment(
    system: &[u8],
    graphics: &[u8],
    provider: &dyn TextureProvider,
) -> Result<DecodedFragment, Error> {
    let report = fragment::inspect(system, graphics)
        .ok_or_else(|| Error::new("the resource is not a supported fragment"))?;
    let name = report.name().map(str::to_string);
    let built = build_scene(
        system,
        graphics,
        provider,
        &report.drawable,
        name.as_deref(),
    )?;
    let BuiltScene {
        scene,
        texture_bindings,
        lod_index,
        expected_geometries,
        decoded_geometries,
        geometry_failures,
    } = built;
    let primitives = scene.meshes.iter().map(|mesh| mesh.primitives.len()).sum();
    let status = if geometry_failures == 0 && decoded_geometries == expected_geometries {
        ComponentStatus::Decoded
    } else {
        ComponentStatus::Unsupported(format!(
            "{geometry_failures} of {expected_geometries} geometry record(s) did not decode"
        ))
    };
    let components = vec![FragmentComponent {
        index: 0,
        name,
        drawable_at: report.header.drawable as usize,
        lod: Some(lod_index),
        meshes: 0..scene.meshes.len(),
        primitives,
        vertices: scene.vertex_count(),
        triangles: scene.triangle_count(),
        status: status.clone(),
    }];
    let completeness = if !report.issues.is_empty() {
        FragmentCompleteness::Partial {
            reason: format!(
                "the member drawable's structural walk reported {} issue(s)",
                report.issues.len()
            ),
        }
    } else if status != ComponentStatus::Decoded {
        FragmentCompleteness::Partial {
            reason: "the member drawable yielded fewer geometries than it declares".to_string(),
        }
    } else {
        FragmentCompleteness::SinglePrimaryDrawable
    };
    Ok(DecodedFragment {
        scene,
        report,
        components,
        completeness,
        texture_bindings,
        lod: lod_index,
    })
}

/// Finds the best drawable root. A simple drawable starts at zero. A
/// fragment or a drawable dictionary holds its member drawables elsewhere in
/// the system segment; those carry no page map of their own, so the scan
/// accepts both header forms and the best member is the one with the most
/// populated LOD levels and geometries.
fn find_drawable_root(system: &[u8], graphics: &[u8]) -> Option<(usize, Report, usize)> {
    if let Some(report) = drawable::inspect(system, graphics) {
        return Some((0, report, 1));
    }
    type RootScore = (usize, usize, usize, usize, usize);
    let mut best: Option<(usize, Report, RootScore)> = None;
    let mut candidates = 0usize;
    let mut examined = 0usize;
    let last = system.len().saturating_sub(0xC0);
    for root in (0..=last).step_by(8) {
        if u64_at(system, root) != Some(0) {
            continue;
        }
        let Some(lod) = u64_at(system, root + 0x50) else {
            continue;
        };
        if lod == 0 {
            continue;
        }
        examined += 1;
        if examined > 4096 {
            break;
        }
        let page_map = u64_at(system, root + 8).unwrap_or(0);
        let resource_level = page_map >> 28 == 5;
        let accepted = if resource_level {
            drawable::is_drawable_at(system, graphics, root)
        } else {
            drawable::is_member_drawable_at(system, graphics, root)
        };
        if !accepted {
            continue;
        }
        let Some(report) = (if resource_level {
            drawable::inspect_at(system, graphics, root)
        } else {
            drawable::inspect_member_at(system, graphics, root)
        }) else {
            continue;
        };
        candidates += 1;
        let populated = report
            .lod
            .iter()
            .filter(|slot| !slot.models.is_empty())
            .count();
        let models: usize = report.lod.iter().map(|slot| slot.models.len()).sum();
        let shader_count = report
            .shader_group
            .as_ref()
            .map_or(0, |group| group.shaders.len());
        let mut valid_geometries = 0usize;
        let mut valid_shaders = 0usize;
        for model in report.lod.iter().flat_map(|slot| &slot.models) {
            for (geometry, record) in model.geometries.iter().enumerate() {
                if record.vertex_buffer.is_some() && record.index.is_some() {
                    valid_geometries += 1;
                    if read_shader_index(system, model, geometry)
                        .is_some_and(|shader| shader < shader_count)
                    {
                        valid_shaders += 1;
                    }
                }
            }
        }
        let score = (
            usize::MAX - report.issues.len(),
            valid_shaders,
            valid_geometries,
            populated,
            models,
        );
        if best
            .as_ref()
            .is_none_or(|(_, _, best_score)| score > *best_score)
        {
            best = Some((root, report, score));
        }
    }
    best.map(|(root, report, _)| (root, report, candidates.max(1)))
}

fn used_shader_indices(
    system: &[u8],
    lod: &drawable::LodSlot,
    diagnostics: &mut Vec<Diagnostic>,
) -> BTreeSet<usize> {
    let mut used = BTreeSet::new();
    for model in &lod.models {
        for (index, _) in model.geometries.iter().enumerate() {
            if let Some(shader) = read_shader_index(system, model, index) {
                used.insert(shader);
            } else {
                diagnostics.push(Diagnostic::new(format!(
                    "geometry {index} has no shader index"
                )));
                used.insert(0);
            }
        }
    }
    used
}

fn read_shader_index(system: &[u8], model: &drawable::Model, geometry: usize) -> Option<usize> {
    let at = model.shader_indices? as usize + geometry * 2;
    u16_at(system, at).map(usize::from)
}

fn geometry_completeness(
    root: usize,
    candidates: usize,
    issues: usize,
    expected_geometries: usize,
    decoded_geometries: usize,
    geometry_failures: usize,
) -> GeometryCompleteness {
    if root == 0
        && candidates <= 1
        && issues == 0
        && geometry_failures == 0
        && decoded_geometries == expected_geometries
    {
        return GeometryCompleteness::Complete;
    }
    let reason = if root != 0 {
        format!(
            "selected drawable root at system +{root:#x}; other fragment or dictionary members were not assembled"
        )
    } else if candidates > 1 {
        format!("{candidates} drawable roots resolved; one was selected")
    } else if issues > 0 {
        format!("the structural walk reported {issues} issue(s)")
    } else if geometry_failures > 0 {
        format!("{geometry_failures} geometry record(s) could not be decoded")
    } else {
        format!("decoded {decoded_geometries} of {expected_geometries} geometries")
    };
    GeometryCompleteness::Partial { reason }
}

fn texture_completeness(missing: usize, referenced: bool) -> TextureCompleteness {
    if missing > 0 {
        TextureCompleteness::Partial { missing }
    } else if referenced {
        TextureCompleteness::Complete
    } else {
        TextureCompleteness::NotReferenced
    }
}

struct MaterialContext<'a> {
    provider: &'a dyn TextureProvider,
    graphics: &'a [u8],
    embedded: &'a HashMap<u64, EmbeddedTexture>,
    embedded_indices: &'a mut HashMap<u64, (Option<usize>, TextureBindingStatus)>,
    external_indices: &'a mut HashMap<u64, (Option<usize>, TextureBindingStatus)>,
    texture_bindings: &'a mut Vec<TextureBindingReport>,
    scene: &'a mut Scene,
    diagnostics: &'a mut Vec<Diagnostic>,
}

fn build_material(
    shader: &Shader,
    shader_index: usize,
    context: &mut MaterialContext<'_>,
) -> Material {
    let MaterialContext {
        provider,
        graphics,
        embedded,
        embedded_indices,
        external_indices,
        texture_bindings,
        scene,
        diagnostics,
    } = context;
    let name = format!("shader {:08x}", shader.shader_hash);
    let mut material = Material {
        name: name.clone(),
        alpha_mode: alpha_mode(shader),
        // Thin props (fins, leaves, brackets) are common; a one-sided draw
        // would drop their reverse faces. Opaque surfaces still depth-test.
        double_sided: true,
        ..Material::default()
    };
    let mut missing = false;
    for slot in &shader.slot_states {
        if slot.state != lforge_rage9::dictionary::SlotState::Bound {
            continue;
        }
        let Some(key) = slot.key.filter(|key| *key != 0) else {
            continue;
        };
        let parameter = shader
            .parameters
            .get(usize::from(slot.index))
            .map_or(0, |parameter| parameter.name_hash);
        let semantic = semantic(parameter);
        let reference = TextureReference {
            key64: key,
            hash32: slot.hash32,
            parameter,
            material: name.clone(),
        };
        let is_embedded = embedded.contains_key(&key);
        let (texture_index, binding_status) = if let Some(texture) = embedded.get(&key) {
            match embedded_indices.get(&key) {
                Some((index, status)) => (*index, status.clone()),
                None => {
                    let result = decode_embedded(graphics, texture, 0, &AtomicBool::new(false))
                        .map_err(|err| err.to_string())
                        .and_then(|level| {
                            texture_from_source(level, format!("embedded: {}", texture.info().name))
                        });
                    let (index, status) = match result {
                        Ok(texture) => {
                            let index = scene.textures.len();
                            scene.textures.push(texture);
                            (Some(index), TextureBindingStatus::Resolved)
                        }
                        Err(reason) => {
                            diagnostics.push(
                                Diagnostic::new(format!(
                                    "embedded texture could not be decoded: {reason}"
                                ))
                                .with_material(name.clone())
                                .with_reference(format!("0x{key:016X}")),
                            );
                            (None, TextureBindingStatus::Failed(reason))
                        }
                    };
                    embedded_indices.insert(key, (index, status.clone()));
                    (index, status)
                }
            }
        } else if let Some((index, status)) = external_indices.get(&key) {
            (*index, status.clone())
        } else {
            let (index, status) = match provider.resolve(&reference) {
                TextureResolution::Missing => {
                    diagnostics.push(
                        Diagnostic::new("texture is not present in any texture store")
                            .with_material(name.clone())
                            .with_reference(format!("0x{key:016X}")),
                    );
                    (None, TextureBindingStatus::Missing)
                }
                TextureResolution::Ambiguous(candidates) => {
                    diagnostics.push(
                        Diagnostic::new(format!(
                            "texture reference is ambiguous: {} candidates",
                            candidates.len()
                        ))
                        .with_material(name.clone())
                        .with_reference(format!("0x{key:016X}: {}", candidates.join(", "))),
                    );
                    (None, TextureBindingStatus::Ambiguous(candidates))
                }
                TextureResolution::Failed(reason) => {
                    diagnostics.push(
                        Diagnostic::new(format!("texture could not be decoded: {reason}"))
                            .with_material(name.clone())
                            .with_reference(format!("0x{key:016X}")),
                    );
                    (None, TextureBindingStatus::Failed(reason))
                }
                TextureResolution::Resolved(resolved) => {
                    match texture_from_source(resolved.level, resolved.source) {
                        Ok(texture) => {
                            let index = scene.textures.len();
                            scene.textures.push(texture);
                            (Some(index), TextureBindingStatus::Resolved)
                        }
                        Err(reason) => {
                            diagnostics.push(
                                Diagnostic::new(format!(
                                    "texture could not be converted: {reason}"
                                ))
                                .with_material(name.clone())
                                .with_reference(format!("0x{key:016X}")),
                            );
                            (None, TextureBindingStatus::Failed(reason))
                        }
                    }
                }
            };
            external_indices.insert(key, (index, status.clone()));
            (index, status)
        };
        texture_bindings.push(TextureBindingReport {
            material: name.clone(),
            parameter,
            semantic,
            key64: key,
            hash32: slot.hash32,
            embedded: is_embedded,
            texture: texture_index,
            status: binding_status,
        });
        let Some(texture_index) = texture_index else {
            missing = true;
            continue;
        };
        material.bindings.push(TextureBinding {
            parameter,
            texture: texture_index,
            semantic,
        });
        // Preview policy: the single sampled specular slot prefers SpecularTex.
        // SpecularTex2 stays a distinct binding. Engine sampling is unverified.
        match semantic {
            TextureSemantic::Diffuse if material.diffuse.is_none() => {
                material.diffuse = Some(texture_index);
            }
            TextureSemantic::Normal if material.normal.is_none() => {
                material.normal = Some(texture_index);
            }
            TextureSemantic::Specular if material.specular.is_none() => {
                material.specular = Some(texture_index);
            }
            _ => {}
        }
    }
    if material.normal.is_some() {
        material.bumpiness = 1.0;
    }
    material.missing_texture = missing;
    if missing {
        diagnostics.push(
            Diagnostic::new("the material uses a fallback for a missing texture")
                .with_material(format!("{name} (shader index {shader_index})")),
        );
    }
    material
}

fn alpha_mode(shader: &Shader) -> AlphaMode {
    let bucket = shader.flags[4];
    if bucket & 0x08 != 0 {
        AlphaMode::Mask
    } else if bucket & (0x02 | 0x04 | 0x40) != 0 {
        AlphaMode::Blend
    } else {
        AlphaMode::Opaque
    }
}

fn semantic(parameter: u32) -> TextureSemantic {
    match parameter {
        DIFFUSE_TEX | DIFFUSE_TEX2 => TextureSemantic::Diffuse,
        BUMP_TEX => TextureSemantic::Normal,
        SPECULAR_TEX => TextureSemantic::Specular,
        SPECULAR_TEX2 => TextureSemantic::Specular2,
        _ => TextureSemantic::Unknown,
    }
}

fn decode_geometry(
    graphics: &[u8],
    geometry: &Geometry,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Primitive, String> {
    let vertex_buffer = geometry
        .vertex_buffer
        .as_ref()
        .ok_or_else(|| "geometry has no vertex buffer".to_string())?;
    let index = geometry
        .index
        .as_ref()
        .ok_or_else(|| "geometry has no index buffer".to_string())?;
    decode_mesh(graphics, vertex_buffer, index, diagnostics)
}

struct Stream {
    offset: usize,
    format: u8,
}

fn decode_mesh(
    graphics: &[u8],
    buffer: &VertexBuffer,
    index: &IndexView,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Primitive, String> {
    let base = buffer.graphics as usize;
    let declared = usize::try_from(buffer.declared_bytes)
        .map_err(|_| "vertex buffer size overflows".to_string())?;
    if declared == 0
        || base
            .checked_add(declared)
            .is_none_or(|end| end > graphics.len())
    {
        return Err("vertex buffer is outside the graphics segment".into());
    }
    let blob = &graphics[base..base + declared];
    let marker = u32_at(blob, 0).ok_or_else(|| "vertex buffer is too short".to_string())?;
    let float_positions = marker == 0x3063;
    if marker != 0x4042 && !float_positions {
        return Err(format!(
            "vertex buffer marker {marker:#010X} is not supported"
        ));
    }
    let mut streams: HashMap<u32, Stream> = HashMap::new();
    for slot in 0..23u32 {
        let Some(word) = u32_at(blob, 4 * slot as usize) else {
            break;
        };
        if word == 0 {
            continue;
        }
        let offset = ((word >> 8) * 2) as usize;
        let format = (word & 0xFF) as u8;
        if offset >= declared {
            diagnostics.push(Diagnostic::new(format!(
                "vertex stream {slot} starts at {offset:#x}, past the {declared}-byte buffer"
            )));
            continue;
        }
        streams.insert(slot, Stream { offset, format });
    }
    let position_stream = streams
        .get(&0)
        .ok_or_else(|| "vertex buffer has no position stream".to_string())?;
    let position_prefix = if float_positions {
        FLOAT_VERTEX_PREFIX
    } else {
        VERTEX_PREFIX
    };
    let vertex_count = if buffer.vertex_count > 0 {
        buffer.vertex_count as usize
    } else {
        let next = streams
            .values()
            .map(|stream| stream.offset)
            .filter(|offset| *offset > position_prefix)
            .min()
            .ok_or_else(|| "vertex buffer has no stream after the positions".to_string())?;
        let stride = if float_positions { 12 } else { 8 };
        (next - position_prefix) / stride
    };
    if vertex_count == 0 || vertex_count > MAX_VERTICES {
        return Err(format!("vertex count {vertex_count} is outside the limit"));
    }
    let position_stride = if float_positions { 12 } else { 8 };
    let position_end = position_stream
        .offset
        .checked_add(vertex_count * position_stride)
        .ok_or_else(|| "position range overflows".to_string())?;
    if position_end > declared {
        return Err("position stream runs past the vertex buffer".into());
    }
    let mut positions = Vec::with_capacity(vertex_count);
    if float_positions {
        for index in 0..vertex_count {
            let at = position_stream.offset + index * 12;
            positions.push(Vec3::new(
                f32_at(blob, at)?,
                f32_at(blob, at + 4)?,
                f32_at(blob, at + 8)?,
            ));
        }
    } else {
        let base_position = [
            f32_at(blob, 0x60).unwrap_or(0.0),
            f32_at(blob, 0x64).unwrap_or(0.0),
            f32_at(blob, 0x68).unwrap_or(0.0),
        ];
        let step = [
            f32_at(blob, 0x70).unwrap_or(0.0),
            f32_at(blob, 0x74).unwrap_or(0.0),
            f32_at(blob, 0x78).unwrap_or(0.0),
        ];
        let axis = u32_at(blob, 0x6C).unwrap_or(2);
        for index in 0..vertex_count {
            let at = position_stream.offset + index * 8;
            let q = u64_at(blob, at)
                .ok_or_else(|| "position data is outside the vertex buffer".to_string())?;
            let x = ((((q >> 16) & 0xFFFF) << 8) | (q & 0xFF)) as f32 * step[0] + base_position[0];
            let y = ((((q >> 32) & 0xFFFF) << 8) | ((q >> 8) & 0xFF)) as f32 * step[1]
                + base_position[1];
            let z = (q >> 48) as f32 * step[2] + base_position[2];
            let position = match axis {
                2 => Vec3::new(x, y, z),
                1 => Vec3::new(y, z, x),
                0 => Vec3::new(z, y, x),
                other => {
                    diagnostics.push(Diagnostic::new(format!(
                        "position axis {other} is not understood; using the identity order"
                    )));
                    Vec3::new(x, y, z)
                }
            };
            positions.push(position);
        }
    }
    if positions.iter().any(|position| !position.is_finite()) {
        return Err("position stream holds a non-finite value".into());
    }

    let normals = decode_normals(blob, &streams, vertex_count, diagnostics);
    let uv0 = decode_uv(blob, &streams, vertex_count, 3, diagnostics)
        .unwrap_or_else(|| vec![[0.0, 0.0]; vertex_count]);
    let uv1 = decode_uv(blob, &streams, vertex_count, 4, diagnostics);
    let colors = decode_colors(blob, &streams, vertex_count);
    let tangents = decode_tangents(blob, &streams, vertex_count, normals.as_deref());
    let mut vertices: Vec<Vertex> = (0..vertex_count)
        .map(|index| Vertex {
            position: positions[index].to_array(),
            normal: normals
                .as_ref()
                .map_or([0.0; 3], |normals| normals[index].to_array()),
            tangent: tangents.as_ref().map(|tangents| tangents[index]),
            uv0: uv0[index],
            uv1: uv1.as_ref().map(|uv| uv[index]),
            color: colors.as_ref().map_or([1.0; 4], |colors| colors[index]),
        })
        .collect();

    let (mut indices, dropped) = decode_indices(graphics, index, vertex_count)?;
    if dropped > 0 {
        diagnostics.push(Diagnostic::new(format!(
            "dropped {dropped} meshlet triangles with invalid indices"
        )));
    }
    if indices.is_empty() {
        return Err("meshlet buffer yielded no triangles".into());
    }
    fix_winding(&positions, &mut vertices, &mut indices);
    rebuild_missing_normals(&positions, &mut vertices, &indices);
    Ok(Primitive {
        material: 0,
        vertices,
        indices,
    })
}

fn decode_normals(
    blob: &[u8],
    streams: &HashMap<u32, Stream>,
    count: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Vec<Vec3>> {
    let stream = streams.get(&2)?;
    if stream.format != 0x21 {
        diagnostics.push(Diagnostic::new(format!(
            "normal stream format {:#04x} is not supported",
            stream.format
        )));
        return None;
    }
    let end = stream.offset.checked_add(count * 4)?;
    let bytes = blob.get(stream.offset..end)?;
    Some(
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| octahedral(u32::from_le_bytes(*word)).unwrap_or(Vec3::ZERO))
            .collect(),
    )
}

fn octahedral(word: u32) -> Option<Vec3> {
    if word >> 31 == 0 {
        return None;
    }
    let x = (word & 1023) as f32 / 1023.0 * 2.0 - 1.0;
    let y = ((word >> 10) & 1023) as f32 / 1023.0 * 2.0 - 1.0;
    let z = 1.0 - x.abs() - y.abs();
    let fold = (-z).max(0.0);
    let x = x + if x >= 0.0 { -fold } else { fold };
    let y = y + if y >= 0.0 { -fold } else { fold };
    Some(Vec3::new(x, y, z).normalize_or_zero())
}

fn decode_uv(
    blob: &[u8],
    streams: &HashMap<u32, Stream>,
    count: usize,
    slot: u32,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<Vec<[f32; 2]>> {
    let stream = streams.get(&slot)?;
    let mut out = Vec::with_capacity(count);
    match stream.format {
        0x28 => {
            let end = stream.offset.checked_add(count * 4)?;
            let bytes = blob.get(stream.offset..end)?;
            for value in bytes.as_chunks::<4>().0 {
                out.push([
                    i16::from_le_bytes([value[0], value[1]]) as f32 / 8192.0,
                    i16::from_le_bytes([value[2], value[3]]) as f32 / 8192.0,
                ]);
            }
        }
        0x42 => {
            let end = stream.offset.checked_add(count * 8)?;
            let bytes = blob.get(stream.offset..end)?;
            for value in bytes.as_chunks::<8>().0 {
                out.push([
                    f32::from_le_bytes(value[0..4].try_into().expect("four bytes")),
                    f32::from_le_bytes(value[4..8].try_into().expect("four bytes")),
                ]);
            }
        }
        format => {
            diagnostics.push(Diagnostic::new(format!(
                "UV stream {slot} format {format:#04x} is not supported"
            )));
            return None;
        }
    }
    Some(out)
}

fn decode_colors(
    blob: &[u8],
    streams: &HashMap<u32, Stream>,
    count: usize,
) -> Option<Vec<[f32; 4]>> {
    let stream = streams.get(&1)?;
    if stream.format != 0x26 {
        return None;
    }
    let end = stream.offset.checked_add(count * 4)?;
    let bytes = blob.get(stream.offset..end)?;
    Some(
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|color| {
                [
                    color[0] as f32 / 255.0,
                    color[1] as f32 / 255.0,
                    color[2] as f32 / 255.0,
                    color[3] as f32 / 255.0,
                ]
            })
            .collect(),
    )
}

fn decode_tangents(
    blob: &[u8],
    streams: &HashMap<u32, Stream>,
    count: usize,
    normals: Option<&[Vec3]>,
) -> Option<Vec<[f32; 4]>> {
    let stream = streams.get(&11)?;
    if stream.format != 0x27 {
        return None;
    }
    let end = stream.offset.checked_add(count * 4)?;
    let bytes = blob.get(stream.offset..end)?;
    Some(
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
            .map(|(index, word)| {
                let normal = normals.and_then(|normals| normals.get(index)).copied();
                tangent(u32::from_le_bytes(*word), normal)
            })
            .collect(),
    )
}

fn tangent(word: u32, normal: Option<Vec3>) -> [f32; 4] {
    let channel = |shift: u32| ((word >> shift) & 1023) as f32 / 1023.0 * 2.0 - 1.0;
    let mut tangent = Vec3::new(channel(0), channel(10), channel(20));
    if let Some(normal) = normal {
        tangent -= normal * tangent.dot(normal);
        if tangent.length_squared() < 1e-8 {
            tangent = if normal.x.abs() < 0.9 {
                Vec3::new(
                    1.0 - normal.x * normal.x,
                    -normal.x * normal.y,
                    -normal.x * normal.z,
                )
            } else {
                Vec3::new(
                    -normal.y * normal.x,
                    1.0 - normal.y * normal.y,
                    -normal.y * normal.z,
                )
            };
        }
    }
    let tangent = tangent.normalize_or_zero();
    let sign = if (word >> 31) & 1 == 1 { -1.0 } else { 1.0 };
    [tangent.x, tangent.y, tangent.z, sign]
}

fn decode_indices(
    graphics: &[u8],
    index: &IndexView,
    vertex_count: usize,
) -> Result<(Vec<u32>, usize), String> {
    let base = index.graphics as usize;
    let range = usize::try_from(index.elements)
        .ok()
        .and_then(|elements| elements.checked_mul(usize::from(index.unit)))
        .ok_or_else(|| "index range overflows".to_string())?;
    if range == 0
        || base
            .checked_add(range)
            .is_none_or(|end| end > graphics.len())
    {
        return Err("index buffer is outside the graphics segment".into());
    }
    let bytes = &graphics[base..base + range];
    let meshlets =
        u16_at(bytes, 0).ok_or_else(|| "index buffer is too short".to_string())? as usize;
    let triangles =
        u32_at(bytes, 4).ok_or_else(|| "index buffer is too short".to_string())? as usize;
    let remaps = u32_at(bytes, 8).ok_or_else(|| "index buffer is too short".to_string())? as usize;
    if meshlets == 0 || meshlets > MAX_MESHLETS {
        return Err(format!("meshlet count {meshlets} is not supported"));
    }
    if triangles == 0 || triangles > MAX_INDICES {
        return Err(format!(
            "index triangle count {triangles} is outside the limit"
        ));
    }
    let triangle_start = 0x0C + 16 * meshlets;
    let remap_start = triangle_start
        .checked_add(triangles * 4)
        .ok_or_else(|| "index tables overflow".to_string())?;
    let end = remap_start
        .checked_add(remaps * 2)
        .ok_or_else(|| "index remap table overflows".to_string())?;
    if end > bytes.len() {
        return Err(format!(
            "index tables need {end} bytes, the declared range has {}",
            bytes.len()
        ));
    }
    let mut starts = Vec::with_capacity(meshlets);
    let mut wrap = 0usize;
    let mut previous = 0usize;
    for meshlet in 0..meshlets {
        let start = u16_at(bytes, 0x10 + 16 * meshlet)
            .ok_or_else(|| "meshlet descriptor is out of range".to_string())?
            as usize;
        if start < previous {
            wrap += 0x1_0000;
        }
        previous = start;
        starts.push(start + wrap);
    }
    let mut indices = Vec::with_capacity(triangles * 3);
    let mut dropped = 0usize;
    for triangle in 0..triangles {
        let Some(word) = u32_at(bytes, triangle_start + triangle * 4) else {
            break;
        };
        let meshlet = (word >> 21) as usize;
        let Some(&start) = starts.get(meshlet) else {
            dropped += 1;
            continue;
        };
        let mut triangle_indices = [0u32; 3];
        let mut valid = true;
        for (corner, shift) in [0u32, 7, 14].into_iter().enumerate() {
            let local = start + ((word >> shift) & 0x7F) as usize;
            let vertex = if local < remaps {
                u16_at(bytes, remap_start + local * 2).map(usize::from)
            } else {
                None
            };
            match vertex {
                Some(vertex) if vertex < vertex_count => triangle_indices[corner] = vertex as u32,
                _ => valid = false,
            }
        }
        if valid
            && triangle_indices[0] != triangle_indices[1]
            && triangle_indices[1] != triangle_indices[2]
            && triangle_indices[0] != triangle_indices[2]
        {
            indices.extend_from_slice(&triangle_indices);
        } else {
            dropped += 1;
        }
    }
    if indices.len() > MAX_INDICES {
        return Err("decoded index count is outside the limit".into());
    }
    Ok((indices, dropped))
}

fn fix_winding(positions: &[Vec3], vertices: &mut [Vertex], indices: &mut [u32]) {
    for triangle in indices.as_chunks_mut::<3>().0 {
        let a = positions[triangle[0] as usize];
        let b = positions[triangle[1] as usize];
        let c = positions[triangle[2] as usize];
        let face = (b - a).cross(c - a);
        if face.length_squared() < 1e-12 {
            continue;
        }
        let normal = Vec3::from(vertices[triangle[0] as usize].normal)
            + Vec3::from(vertices[triangle[1] as usize].normal)
            + Vec3::from(vertices[triangle[2] as usize].normal);
        if normal != Vec3::ZERO && face.dot(normal) < 0.0 {
            triangle.swap(1, 2);
        }
    }
}

fn rebuild_missing_normals(positions: &[Vec3], vertices: &mut [Vertex], indices: &[u32]) {
    let mut normals = vec![Vec3::ZERO; vertices.len()];
    for triangle in indices.as_chunks::<3>().0 {
        let a = positions[triangle[0] as usize];
        let b = positions[triangle[1] as usize];
        let c = positions[triangle[2] as usize];
        let face = (b - a).cross(c - a);
        for &index in triangle {
            normals[index as usize] += face;
        }
    }
    for (index, vertex) in vertices.iter_mut().enumerate() {
        if Vec3::from(vertex.normal) == Vec3::ZERO {
            let normal = normals[index].normalize_or_zero();
            vertex.normal = normal.to_array();
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn f32_at(bytes: &[u8], at: usize) -> Result<f32, String> {
    bytes
        .get(at..at + 4)
        .map(|bytes| f32::from_le_bytes(bytes.try_into().expect("four bytes")))
        .ok_or_else(|| "vertex attribute is outside the buffer".to_string())
}

#[cfg(test)]
mod tests;
