//! Structural inspection of a drawable resource.
//!
//! The layout is the one the research read in two rows of one nested archive
//! (DRAW-F01 to DRAW-F21). The system segment holds a header with a page-map
//! pointer, bounded volumes, four LOD slots and a name pointer. A populated
//! slot points at a model array, a model at a geometry array, and a geometry
//! at a vertex buffer and an index descriptor. The vertex buffer points at a
//! graphics range and at a 52-entry layout.
//!
//! Everything here is a structure walk. Field meanings that the research does
//! not establish are kept neutral, no triangle is formed from an index
//! descriptor, and nothing resolves a material, texture key or mesh.
//!
//! A resource is classified as a drawable from the header and the shape of
//! its chain, not from a local type ID.

#[cfg(test)]
mod tests;

use std::fmt;

use crate::resource::{Pointer, Segment};

/// The first four bytes of a vertex-buffer graphics target in every sample.
/// An observation, not a format signature.
pub const MARKER: [u8; 4] = [0x42, 0x40, 0x00, 0x00];
/// The constant word the record behind an index descriptor carries.
pub const INDEX_CONSTANT: u64 = 0xFFFF_FFFF_FFFF_0214;
/// The unexplained prefix before the first attribute array.
pub const VERTEX_PREFIX: u64 = 0x80;
/// Layout entries.
pub const LAYOUT_SLOTS: usize = 52;
/// Bytes of one layout structure.
pub const LAYOUT_LEN: usize = 0x1_3C;
/// LOD slots in the header.
pub const LOD_SLOTS: usize = 4;
/// Largest element, geometry or shader array accepted.
pub const MAX_ARRAY: usize = 1 << 16;

/// Size of one model bounds record: eight `f32`.
pub const BOUNDS_RECORD_LEN: u64 = 0x20;
/// Tolerance the research used for the aggregate-union check.
pub const AABB_TOLERANCE: f32 = 2e-3;
/// Entries of the fixed declaration table at a vertex-buffer graphics target.
///
/// A zero word marks an absent attribute; it does not end the table. A geometry
/// with no second UV stores zero at slot 4 and a real blend-weight entry at
/// slot 6.
pub const DECLARATION_SLOTS: usize = 23;

/// The declaration slot of the authored position stream.
pub const SEMANTIC_POSITION: u32 = 0;
/// Vertex colour.
pub const SEMANTIC_COLOR: u32 = 1;
/// Normal.
pub const SEMANTIC_NORMAL: u32 = 2;
/// First texture coordinate set.
pub const SEMANTIC_UV0: u32 = 3;
/// Second texture coordinate set.
pub const SEMANTIC_UV1: u32 = 4;
/// Four `u8` blend weights, when the declaration format is `0x26`.
pub const SEMANTIC_BLEND_WEIGHTS: u32 = 6;
/// Blend indices; the width and lane count come from the format and the
/// matching layout entry.
pub const SEMANTIC_BLEND_INDICES: u32 = 8;
/// Tangent.
pub const SEMANTIC_TANGENT: u32 = 11;
/// A second position-format stream, observed on most skeleton-bearing geometry.
/// Its role is not established, so it has no name.
pub const SEMANTIC_SECOND_POSITION: u32 = 17;

/// A structural problem. Every pointer that does not resolve produces one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// A pointer that cannot be decoded to a segment and an offset.
    Pointer {
        field: &'static str,
        at: usize,
        value: u64,
    },
    /// A record that would end outside its segment.
    Bounds {
        field: &'static str,
        at: usize,
        segment: Segment,
        offset: u64,
        len: u64,
        size: u64,
    },
    /// An array whose declared count exceeds what its segment holds.
    Clamped {
        field: &'static str,
        declared: u64,
        used: u64,
    },
    /// Arithmetic that does not reproduce the declared size.
    Arithmetic {
        field: &'static str,
        message: String,
    },
    /// A record that a walk needs but cannot reach.
    Missing { field: &'static str },
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Issue::Pointer { field, at, value } => write!(
                f,
                "{field} at system +{at:#x} holds {value:#018X}, which is not a segment pointer"
            ),
            Issue::Bounds {
                field,
                at,
                segment,
                offset,
                len,
                size,
            } => write!(
                f,
                "{field} at system +{at:#x} needs {len} bytes at {} +{offset:#x}, past the {size} byte segment",
                segment.name()
            ),
            Issue::Clamped {
                field,
                declared,
                used,
            } => write!(
                f,
                "{field} declares {declared} entries; only {used} fit in the segment"
            ),
            Issue::Arithmetic { field, message } => write!(f, "{field}: {message}"),
            Issue::Missing { field } => write!(f, "{field} is not reachable"),
        }
    }
}

/// A byte range in one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub segment: Segment,
    pub offset: u64,
    pub len: u64,
}

/// The bounded volumes at `+0x20..+0x4F`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bounds {
    pub centre: [f32; 3],
    pub radius: f32,
    pub min: [f32; 3],
    pub max: [f32; 3],
}

/// An axis-aligned box as the bounds records store it: six meaningful
/// values and two repeats.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Aabb {
    pub min: [f32; 3],
    pub max: [f32; 3],
}

impl Aabb {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
        let word = |ix: usize| {
            f32::from_le_bytes(bytes[ix * 4..ix * 4 + 4].try_into().expect("four bytes"))
        };
        Some(Self {
            min: [word(0), word(1), word(2)],
            max: [word(4), word(5), word(6)],
        })
    }

    /// The largest absolute difference between the six meaningful values.
    pub fn delta(&self, other: &Aabb) -> f32 {
        let mut delta = 0f32;
        for (a, b) in self.min.iter().zip(other.min.iter()) {
            delta = delta.max((a - b).abs());
        }
        for (a, b) in self.max.iter().zip(other.max.iter()) {
            delta = delta.max((a - b).abs());
        }
        if delta.is_nan() { f32::INFINITY } else { delta }
    }

    fn union(&self, other: &Aabb) -> Aabb {
        let min = [
            self.min[0].min(other.min[0]),
            self.min[1].min(other.min[1]),
            self.min[2].min(other.min[2]),
        ];
        let max = [
            self.max[0].max(other.max[0]),
            self.max[1].max(other.max[1]),
            self.max[2].max(other.max[2]),
        ];
        Aabb { min, max }
    }

    pub fn finite(&self) -> bool {
        self.min
            .iter()
            .chain(self.max.iter())
            .all(|value| value.is_finite())
    }
}

/// The model `+0x18` bounds array: an aggregate record followed by one
/// record per geometry for a multi-geometry model.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundsArray {
    pub at: u32,
    pub records: u32,
    pub aggregate: Aabb,
    pub per_geometry: Vec<Aabb>,
    /// The fourth word of each record repeats the first.
    pub extra_min_equal: bool,
    pub extra_max_equal: bool,
    /// `None` for a one-geometry model, whose union check is trivial.
    pub union_matches: Option<bool>,
    pub union_delta: f32,
}

/// One declaration-table entry from the graphics prefix.
///
/// The entry's position in the table is its attribute semantic: slot 0 is the
/// position stream, 1 the colour, 2 the normal, 3 and 4 the texture coordinates,
/// 6 the blend weights, 8 the blend indices and 11 the tangent. The remaining
/// slots have no established name. The `format` byte is a declaration format,
/// which is a different enumeration from the layout's format byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Declaration {
    pub slot: usize,
    pub format: u8,
    pub offset: u32,
    /// Whether the offset equals a present layout entry's offset.
    pub matches_layout: bool,
}

/// One model bounds-array check result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnionCheck {
    pub matches: bool,
    pub delta: f32,
    /// Models whose aggregate was compared.
    pub models: usize,
    /// Models skipped because they hold one geometry.
    pub trivial: usize,
}

/// The header-union check, which is independent of the model checks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeaderUnion {
    pub matches: bool,
    pub delta: f32,
    pub finite: bool,
}

/// One shader parameter entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameter {
    pub index: u16,
    pub name_hash: u32,
    pub packed: u32,
    /// Low two bits of `packed`.
    pub class: u8,
    /// Bits 2..31 of `packed`.
    pub slot: u32,
    /// Class zero, the texture-entry class.
    pub texture: bool,
}

/// One texture slot: bound to a record, declared but null, or invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub index: u16,
    pub state: crate::dictionary::SlotState,
    /// The name record's 64-bit key, for a bound slot.
    pub key: Option<u64>,
    /// The name record's 32-bit dictionary hash, when it carries the `6`
    /// variant. It shares the dictionary name-hash namespace.
    pub hash32: Option<u32>,
}

/// Counts over the shader group. Keys are hashes: nothing is resolved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaterialSummary {
    pub shaders: usize,
    pub declared_slots: u32,
    pub bound: u32,
    pub unbound: u32,
    pub invalid: u32,
    /// Distinct 64-bit keys across bound slots.
    pub distinct_keys: usize,
}

/// The header fields whose positions the research confirmed.
#[derive(Debug, Clone, PartialEq)]
pub struct HeaderView {
    /// The page-map word of a resource-level drawable. A drawable embedded in
    /// a fragment or a dictionary holds zero here; the page map belongs to
    /// the containing resource.
    pub page_map: Option<u32>,
    pub shader_group: Option<u32>,
    pub skeleton: Option<u32>,
    pub bounds: Bounds,
    pub lod_slots: [u64; LOD_SLOTS],
    pub distances: [f32; LOD_SLOTS],
    pub flags: [u32; LOD_SLOTS],
    pub name: Option<u32>,
    /// The NUL-terminated ASCII bytes at the name pointer. A descriptive
    /// label; no engine role is established for the string.
    pub name_text: Option<String>,
    pub list: Option<u32>,
    pub word_a8_hi: u64,
}

/// One present layout entry. Slots are positions in the 52-entry table, not
/// recovered names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute {
    pub slot: usize,
    pub offset: u32,
    pub size: u8,
    pub format: u8,
}

/// A vertex buffer and the arithmetic of its layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VertexBuffer {
    pub at: u32,
    pub elements: u32,
    pub unit: u16,
    pub word_0e: u16,
    pub word_10: u32,
    pub graphics: u32,
    pub layout: Option<u32>,
    pub vertex_count: u32,
    /// Bits 0..9 of the packed word. Uninterpreted flags.
    pub packed_flags: u32,
    pub declared_bytes: u64,
    pub attribute_bytes: u64,
    pub layout_end: u64,
    pub prefix_gap: i64,
    pub attributes: Vec<Attribute>,
    /// Entries of the declaration table at the graphics target.
    pub declarations: Vec<Declaration>,
    pub declaration_end: Option<u64>,
}

impl VertexBuffer {
    /// The declaration entry of one attribute semantic, when it is present.
    pub fn declaration(&self, semantic: u32) -> Option<&Declaration> {
        self.declarations
            .iter()
            .find(|entry| entry.slot as u32 == semantic)
    }

    /// The present layout entry at `offset`, when there is one.
    pub fn attribute_at(&self, offset: u32) -> Option<&Attribute> {
        self.attributes.iter().find(|entry| entry.offset == offset)
    }
}

/// An index descriptor's verified fields and the range it addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexView {
    pub at: u32,
    pub clusters: u16,
    pub count_a: u16,
    /// `(value >> 8) & 0xFFFF` from `+0x0C`.
    pub count_b: u16,
    /// The whole `+0x0C` word.
    pub count_word: u32,
    pub low_byte: u8,
    pub high_byte: u8,
    pub elements: u32,
    pub unit: u16,
    pub graphics: u32,
    pub range: Option<Region>,
    pub in_bounds: bool,
    /// The first three words of the index bytes, when they are in range.
    pub header: Option<[u32; 3]>,
    /// Whether the header agrees with the descriptor.
    pub header_matches: Option<bool>,
    pub constant: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    pub at: u32,
    pub vertex_buffer: Option<VertexBuffer>,
    pub index: Option<IndexView>,
    pub word_30: u64,
    /// The `u16` at `+0x2C`. It equals the skeleton's bone count on the
    /// highest LOD of every sampled skeleton-bearing geometry and is zero on
    /// lower LODs, so it is reported as the geometry's declared bone count.
    pub bone_count: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Model {
    pub at: u32,
    pub geometry_count: u16,
    pub capacity: u16,
    pub word_14: u32,
    pub shader_indices: Option<u32>,
    pub flags: u64,
    pub geometries: Vec<Geometry>,
    pub bounds: Option<BoundsArray>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LodSlot {
    pub slot: usize,
    /// The header pointer, as stored.
    pub pointer: u64,
    pub model_count: u16,
    pub capacity: u16,
    pub shader_indices: [u16; 2],
    pub models: Vec<Model>,
}

/// The graphics base the pointers support, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphicsBase {
    /// Two or more distinct graphics offsets land on the marker.
    Unique { base: u64, supports: usize },
    /// Several bases are possible.
    Ambiguous { candidates: usize },
    /// Fewer than two distinct offsets support a base.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shader {
    pub at: u32,
    /// `+0x00`, stable per parameter schema. A hash, not a name.
    pub shader_hash: u32,
    /// `+0x04`, the constant `0x6D657461` in every sample.
    pub marker: u32,
    pub texture_parameters: u8,
    pub total_parameters: u16,
    pub word_06: u16,
    pub slots: u32,
    pub bound_slots: u32,
    /// The eight record bytes at `+0x38..+0x40`. Byte 4 is observed as a
    /// render-bucket mask (0x01 opaque, 0x02 alpha, 0x04 decal, 0x08 cutout,
    /// 0x40 water) in the public material census; the bytes stay raw here.
    pub flags: [u8; 8],
    pub parameters: Vec<Parameter>,
    pub slot_states: Vec<Slot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShaderGroup {
    pub at: u32,
    pub shaders: Vec<Shader>,
    pub count: u16,
    pub capacity: u16,
}

/// What the structural walk established.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub header: HeaderView,
    pub lod: Vec<LodSlot>,
    pub empty_slots: Vec<usize>,
    pub graphics_base: GraphicsBase,
    pub shader_group: Option<ShaderGroup>,
    pub materials: MaterialSummary,
    /// The model-union check over the walked bounds arrays.
    pub model_union: UnionCheck,
    /// The header-union check, reported independently of the model checks.
    /// `None` when no model aggregate was walked.
    pub header_union: Option<HeaderUnion>,
    pub issues: Vec<Issue>,
    /// `complete` only when no issue was produced.
    pub status: &'static str,
}

/// Whether the system segment has the header and chain shape of a drawable.
///
/// The test is structural: a zero first word, a page-map pointer inside the
/// system segment and at least one LOD slot whose model and geometry arrays
/// resolve. A local type ID plays no part.
pub fn is_drawable(system: &[u8], graphics: &[u8]) -> bool {
    is_drawable_at(system, graphics, 0)
}

/// Whether a drawable header and chain start at `root` in the system segment.
/// A resource-level header must carry a page map; an embedded member drawable
/// holds zero there, so use [`is_member_drawable_at`] for those.
pub fn is_drawable_at(system: &[u8], graphics: &[u8], root: usize) -> bool {
    header_resolves(system, graphics, root, true)
}

/// Whether an embedded member drawable starts at `root`. The page-map word is
/// allowed to be zero, which is what a drawable inside a fragment holds.
pub fn is_member_drawable_at(system: &[u8], graphics: &[u8], root: usize) -> bool {
    header_resolves(system, graphics, root, false)
}

fn header_resolves(system: &[u8], graphics: &[u8], root: usize, require_page_map: bool) -> bool {
    let Ok(header) = HeaderView::parse_at(system, root, require_page_map) else {
        return false;
    };
    header.lod_slots.iter().enumerate().any(|(slot, &value)| {
        let Some(offset) = system_pointer(value) else {
            return false;
        };
        let mut probe = Walk::new(system, graphics);
        probe
            .lod_slot(slot, offset)
            .is_some_and(|slot| !slot.models.is_empty())
    })
}

impl HeaderView {
    fn parse_at(system: &[u8], base: usize, require_page_map: bool) -> Result<Self, Issue> {
        if base.checked_add(0xC0).is_none_or(|end| end > system.len()) {
            return Err(Issue::Missing {
                field: "the 0xC0-byte header",
            });
        }
        if u64_at(system, base) != Some(0) {
            return Err(Issue::Arithmetic {
                field: "header +0x00",
                message: "the first word is not zero".to_string(),
            });
        }
        let page_map_value = u64_at(system, base + 0x08).unwrap_or(0);
        let page_map = match system_pointer(page_map_value) {
            Some(offset) => offset,
            None if !require_page_map && page_map_value == 0 => {
                // An embedded drawable carries no page map of its own.
                return Self::parse_body(system, base, None);
            }
            None => {
                return Err(Issue::Pointer {
                    field: "page map",
                    at: base + 0x08,
                    value: page_map_value,
                });
            }
        };
        Self::parse_body(system, base, Some(page_map))
    }

    fn parse_body(system: &[u8], base: usize, page_map: Option<u32>) -> Result<Self, Issue> {
        let mut lod_slots = [0u64; LOD_SLOTS];
        let mut distances = [0f32; LOD_SLOTS];
        let mut flags = [0u32; LOD_SLOTS];
        for slot in 0..LOD_SLOTS {
            lod_slots[slot] = u64_at(system, base + 0x50 + 8 * slot).unwrap_or(0);
            distances[slot] = f32_at(system, base + 0x70 + 4 * slot).unwrap_or(0.0);
            flags[slot] = u32_at(system, base + 0x80 + 4 * slot).unwrap_or(0);
        }
        let name = system_pointer(u64_at(system, base + 0xA8).unwrap_or(0));
        Ok(Self {
            page_map,
            shader_group: system_pointer(u64_at(system, base + 0x10).unwrap_or(0)),
            skeleton: system_pointer(u64_at(system, base + 0x18).unwrap_or(0)),
            bounds: Bounds {
                centre: [
                    f32_at(system, base + 0x20).unwrap_or(0.0),
                    f32_at(system, base + 0x24).unwrap_or(0.0),
                    f32_at(system, base + 0x28).unwrap_or(0.0),
                ],
                radius: f32_at(system, base + 0x2C).unwrap_or(0.0),
                min: [
                    f32_at(system, base + 0x30).unwrap_or(0.0),
                    f32_at(system, base + 0x34).unwrap_or(0.0),
                    f32_at(system, base + 0x38).unwrap_or(0.0),
                ],
                max: [
                    f32_at(system, base + 0x40).unwrap_or(0.0),
                    f32_at(system, base + 0x44).unwrap_or(0.0),
                    f32_at(system, base + 0x48).unwrap_or(0.0),
                ],
            },
            lod_slots,
            distances,
            flags,
            name,
            name_text: name.and_then(|offset| ascii_string(system, offset as usize)),
            list: system_pointer(u64_at(system, base + 0xB0).unwrap_or(0)),
            word_a8_hi: u64_at(system, base + 0xB8).unwrap_or(0),
        })
    }
}

/// The two reconstructed segments.
struct Walk<'a> {
    system: &'a [u8],
    graphics: &'a [u8],
    issues: Vec<Issue>,
}

impl<'a> Walk<'a> {
    fn new(system: &'a [u8], graphics: &'a [u8]) -> Self {
        Self {
            system,
            graphics,
            issues: Vec::new(),
        }
    }

    fn segment(&self, segment: Segment) -> &'a [u8] {
        match segment {
            Segment::System => self.system,
            Segment::Graphics => self.graphics,
        }
    }

    fn bytes(
        &mut self,
        segment: Segment,
        offset: u64,
        len: u64,
        field: &'static str,
    ) -> Option<&'a [u8]> {
        let bytes = self.segment(segment);
        match offset.checked_add(len) {
            Some(end) if end <= bytes.len() as u64 => Some(&bytes[offset as usize..end as usize]),
            _ => {
                self.issues.push(Issue::Bounds {
                    field,
                    at: offset as usize,
                    segment,
                    offset,
                    len,
                    size: bytes.len() as u64,
                });
                None
            }
        }
    }

    fn u32(&mut self, offset: u64, field: &'static str) -> Option<u32> {
        let bytes = self.bytes(Segment::System, offset, 4, field)?;
        Some(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
    }

    fn u64(&mut self, offset: u64, field: &'static str) -> Option<u64> {
        let bytes = self.bytes(Segment::System, offset, 8, field)?;
        Some(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    }

    /// A pointer stored in the system segment that must select `wanted`.
    fn pointer(&mut self, at: u64, field: &'static str, wanted: Segment) -> Option<u32> {
        let value = self.u64(at, field)?;
        match (Pointer::decode(value), wanted) {
            (Some(Pointer::System(offset)), Segment::System) => Some(offset),
            (Some(Pointer::Graphics(offset)), Segment::Graphics) => Some(offset),
            _ => {
                self.issues.push(Issue::Pointer {
                    field,
                    at: at as usize,
                    value,
                });
                None
            }
        }
    }

    /// An array of `count` pointers, clamped to the entries that fit.
    fn pointer_array(&mut self, at: u32, count: u16, field: &'static str) -> Vec<u32> {
        let declared = u64::from(count);
        let fits = u64::from(at).saturating_add(declared * 8);
        let size = self.system.len() as u64;
        let used = if fits <= size {
            declared
        } else {
            (size.saturating_sub(u64::from(at))) / 8
        };
        if used < declared {
            self.issues.push(Issue::Clamped {
                field,
                declared,
                used,
            });
        }
        let mut pointers = Vec::with_capacity(used as usize);
        for index in 0..used {
            let Some(value) = u64_at(self.system, at as usize + index as usize * 8) else {
                break;
            };
            match system_pointer(value) {
                Some(offset) => pointers.push(offset),
                None => self.issues.push(Issue::Pointer {
                    field,
                    at: at as usize + index as usize * 8,
                    value,
                }),
            }
        }
        pointers
    }

    fn lod_slot(&mut self, slot: usize, at: u32) -> Option<LodSlot> {
        let base = u64::from(at);
        let model_array = self.pointer(base, "LOD model array", Segment::System)?;
        let model_count = self.u32(base + 8, "LOD model count")? as u16;
        let capacity = self.u32(base + 10, "LOD capacity")? as u16;
        if model_count > capacity || usize::from(model_count) > MAX_ARRAY {
            self.issues.push(Issue::Arithmetic {
                field: "LOD group",
                message: format!("declares {model_count} models in a capacity of {capacity}"),
            });
        }
        let shader_a = self.u32(base + 0x10, "LOD shader indices")? as u16;
        let shader_b = self.u32(base + 0x12, "LOD shader indices")? as u16;
        let models = self
            .pointer_array(model_array, model_count, "LOD model array")
            .into_iter()
            .filter_map(|at| self.model(at))
            .collect::<Vec<_>>();
        Some(LodSlot {
            slot,
            pointer: u64::from(at) | (5u64 << 28),
            model_count,
            capacity,
            shader_indices: [shader_a, shader_b],
            models,
        })
    }

    fn model(&mut self, at: u32) -> Option<Model> {
        let base = u64::from(at);
        // The record is at least 0x38 bytes in the samples.
        self.bytes(Segment::System, base, 0x38, "model record")?;
        let geometry_array = self.pointer(base + 0x08, "model geometry array", Segment::System)?;
        let geometry_count = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x10, 2, "model geometry count")?
                .try_into()
                .expect("two bytes"),
        );
        let capacity = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x12, 2, "model capacity")?
                .try_into()
                .expect("two bytes"),
        );
        let word_14 = self.u32(base + 0x14, "model word")?;
        let shader_indices = self.u64(base + 0x20, "model shader indices")?;
        let shader_indices = system_pointer(shader_indices);
        let flags = self.u64(base + 0x30, "model flags")?;
        if geometry_count > capacity || usize::from(geometry_count) > MAX_ARRAY {
            self.issues.push(Issue::Arithmetic {
                field: "model",
                message: format!(
                    "declares {geometry_count} geometries in a capacity of {capacity}"
                ),
            });
        }
        let geometries = self
            .pointer_array(geometry_array, geometry_count, "model geometry array")
            .into_iter()
            .filter_map(|at| self.geometry(at))
            .collect();
        let bounds = self
            .pointer(base + 0x18, "model bounds array", Segment::System)
            .and_then(|at| self.bounds(at, geometry_count));
        Some(Model {
            at,
            geometry_count,
            capacity,
            word_14,
            shader_indices,
            flags,
            geometries,
            bounds,
        })
    }

    /// Reads the bounds array and checks the aggregate against the union of
    /// the per-geometry records.
    fn bounds(&mut self, at: u32, geometry_count: u16) -> Option<BoundsArray> {
        let expected = if geometry_count <= 1 {
            1
        } else {
            u32::from(geometry_count) + 1
        };
        let base = u64::from(at);
        let size = self.system.len() as u64;
        let available = if base >= size {
            0
        } else {
            (size - base) / BOUNDS_RECORD_LEN
        };
        let records = u64::from(expected).min(available) as u32;
        if records == 0 {
            self.issues.push(Issue::Bounds {
                field: "model bounds array",
                at: at as usize,
                segment: Segment::System,
                offset: base,
                len: BOUNDS_RECORD_LEN,
                size,
            });
            return None;
        }
        if records < expected {
            self.issues.push(Issue::Clamped {
                field: "model bounds array",
                declared: u64::from(expected),
                used: u64::from(records),
            });
        }
        let mut values = Vec::with_capacity(records as usize);
        for ix in 0..records as usize {
            let start = base as usize + ix * BOUNDS_RECORD_LEN as usize;
            let bytes = &self.system[start..start + BOUNDS_RECORD_LEN as usize];
            values.push(Aabb::parse(bytes)?);
        }
        let aggregate = values[0];
        let per_geometry = values[1..].to_vec();
        let extra_min_equal = (0..records as usize).all(|ix| {
            let start = base as usize + ix * BOUNDS_RECORD_LEN as usize;
            let words: [f32; 8] = std::array::from_fn(|word| {
                f32::from_le_bytes(
                    self.system[start + word * 4..start + word * 4 + 4]
                        .try_into()
                        .expect("four bytes"),
                )
            });
            words[3] == words[0]
        });
        let extra_max_equal = (0..records as usize).all(|ix| {
            let start = base as usize + ix * BOUNDS_RECORD_LEN as usize;
            let words: [f32; 8] = std::array::from_fn(|word| {
                f32::from_le_bytes(
                    self.system[start + word * 4..start + word * 4 + 4]
                        .try_into()
                        .expect("four bytes"),
                )
            });
            words[7] == words[4]
        });
        let finite = values.iter().all(Aabb::finite);
        if !finite {
            self.issues.push(Issue::Arithmetic {
                field: "model bounds array",
                message: "a bounds record holds a non-finite value".to_string(),
            });
        }
        let (union_matches, union_delta) = if geometry_count <= 1 {
            (None, 0.0)
        } else {
            let mut union = per_geometry.first().copied();
            for aabb in per_geometry.iter().skip(1) {
                if let Some(current) = union {
                    union = Some(current.union(aabb));
                }
            }
            match union {
                Some(union) if finite => {
                    let delta = aggregate.delta(&union);
                    if delta > AABB_TOLERANCE {
                        self.issues.push(Issue::Arithmetic {
                            field: "model bounds aggregate",
                            message: format!(
                                "the aggregate differs from the union of the per-geometry records by {delta}"
                            ),
                        });
                    }
                    (Some(delta <= AABB_TOLERANCE), delta)
                }
                _ => (Some(false), f32::INFINITY),
            }
        };
        Some(BoundsArray {
            at,
            records,
            aggregate,
            per_geometry,
            extra_min_equal,
            extra_max_equal,
            union_matches,
            union_delta,
        })
    }

    fn geometry(&mut self, at: u32) -> Option<Geometry> {
        let base = u64::from(at);
        self.bytes(Segment::System, base, 0x48, "geometry record")?;
        let vertex_buffer = self.pointer(base + 0x08, "vertex buffer", Segment::System)?;
        let word_30 = self.u64(base + 0x30, "geometry word")?;
        let index = self.pointer(base + 0x40, "index descriptor", Segment::System)?;
        let bone_count = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x2C, 2, "geometry bone count")?
                .try_into()
                .expect("two bytes"),
        );
        Some(Geometry {
            at,
            vertex_buffer: self.vertex_buffer(vertex_buffer),
            index: self.index_descriptor(index),
            word_30,
            bone_count,
        })
    }

    fn vertex_buffer(&mut self, at: u32) -> Option<VertexBuffer> {
        let base = u64::from(at);
        self.bytes(Segment::System, base, 0x48, "vertex buffer record")?;
        let elements = self.u32(base + 0x08, "vertex element count")?;
        let unit = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x0C, 2, "vertex element unit")?
                .try_into()
                .expect("two bytes"),
        );
        let word_0e = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x0E, 2, "vertex word")?
                .try_into()
                .expect("two bytes"),
        );
        let word_10 = self.u32(base + 0x10, "vertex word")?;
        let graphics = self.pointer(base + 0x18, "vertex graphics pointer", Segment::Graphics)?;
        let layout = self.pointer(base + 0x40, "vertex layout", Segment::System);
        let mut buffer = VertexBuffer {
            at,
            elements,
            unit,
            word_0e,
            word_10,
            graphics,
            layout,
            vertex_count: 0,
            packed_flags: 0,
            declared_bytes: u64::from(elements) * u64::from(unit),
            attribute_bytes: 0,
            layout_end: 0,
            prefix_gap: 0,
            attributes: Vec::new(),
            declarations: Vec::new(),
            declaration_end: None,
        };
        if let Some(layout) = layout {
            let _ = self.layout(layout, &mut buffer);
        }
        self.declarations(graphics, &mut buffer);
        Some(buffer)
    }

    /// Reads the fixed 23-slot declaration table at the graphics target.
    ///
    /// Each word is a `u8` format in bits 0..7 and an offset in units of two in
    /// bits 8..31. A zero word means the attribute is absent. The table has no
    /// terminator: a geometry with no second UV stores zero at slot 4 and a real
    /// blend-weight entry at slot 6, so stopping at the first zero would drop
    /// the influences.
    fn declarations(&mut self, graphics: u32, buffer: &mut VertexBuffer) {
        let mut pos = u64::from(graphics);
        let size = self.graphics.len() as u64;
        let end = pos + 4 * DECLARATION_SLOTS as u64;
        if end > size {
            self.issues.push(Issue::Bounds {
                field: "declaration table",
                at: graphics as usize,
                segment: Segment::Graphics,
                offset: pos,
                len: 4 * DECLARATION_SLOTS as u64,
                size,
            });
        }
        for slot in 0..DECLARATION_SLOTS {
            let Some(word) = self
                .graphics
                .get(pos as usize..pos as usize + 4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
            else {
                return;
            };
            pos += 4;
            if word == 0 {
                continue;
            }
            let format = (word & 0xFF) as u8;
            let offset = (word >> 8) * 2;
            let matches_layout = buffer.attributes.iter().any(|entry| entry.offset == offset);
            if !matches_layout {
                self.issues.push(Issue::Arithmetic {
                    field: "declaration table",
                    message: format!(
                        "slot {slot} declares format {format:#04x} at offset {offset:#x}, which no present layout entry uses"
                    ),
                });
            }
            if u64::from(offset) >= buffer.declared_bytes {
                self.issues.push(Issue::Arithmetic {
                    field: "declaration table",
                    message: format!(
                        "slot {slot} starts at offset {offset:#x}, past the {}-byte buffer",
                        buffer.declared_bytes
                    ),
                });
            }
            buffer.declarations.push(Declaration {
                slot,
                format,
                offset,
                matches_layout,
            });
        }
        buffer.declaration_end = Some(end);
    }

    /// Reads the 52-entry layout and checks the documented arithmetic.
    fn layout(&mut self, at: u32, buffer: &mut VertexBuffer) -> Option<()> {
        let base = u64::from(at);
        self.bytes(Segment::System, base, LAYOUT_LEN as u64, "vertex layout")?;
        let packed = u32_at(self.system, base as usize + 0x138)?;
        let vertex_count = packed >> 10;
        let mut end = 0u64;
        let mut sum = 0u64;
        for slot in 0..LAYOUT_SLOTS {
            let offset = u32_at(self.system, base as usize + 4 * slot)?;
            let size = *self.system.get(base as usize + 0xD0 + slot)?;
            let format = *self.system.get(base as usize + 0x104 + slot)?;
            if size == 0 && format == 0 {
                continue;
            }
            let attribute_end = u64::from(offset) + u64::from(size) * u64::from(vertex_count);
            end = end.max(attribute_end);
            sum += u64::from(size) * u64::from(vertex_count);
            buffer.attributes.push(Attribute {
                slot,
                offset,
                size,
                format,
            });
        }
        buffer.vertex_count = vertex_count;
        buffer.packed_flags = packed & 0x3FF;
        buffer.attribute_bytes = sum;
        buffer.layout_end = end;
        buffer.prefix_gap = buffer.declared_bytes as i64 - sum as i64;
        if end != buffer.declared_bytes {
            self.issues.push(Issue::Arithmetic {
                field: "vertex layout",
                message: format!(
                    "the entries end at {end}, but the buffer declares {} bytes",
                    buffer.declared_bytes
                ),
            });
        }
        // `vertex_count × sum(size)` must be the declared size less the
        // 0x80-byte prefix. The declared size is never rescaled to fit.
        let expected = buffer.declared_bytes.checked_sub(VERTEX_PREFIX);
        if expected != Some(sum) {
            self.issues.push(Issue::Arithmetic {
                field: "vertex layout",
                message: format!(
                    "{vertex_count} vertices of {sum} attribute bytes do not reproduce the declared {} bytes minus the {VERTEX_PREFIX}-byte prefix",
                    buffer.declared_bytes
                ),
            });
        }
        Some(())
    }

    fn index_descriptor(&mut self, at: u32) -> Option<IndexView> {
        let base = u64::from(at);
        self.bytes(Segment::System, base, 0x20, "index descriptor")?;
        let record = self.pointer(base, "index buffer record", Segment::System)?;
        let clusters = u16::from_le_bytes(
            self.bytes(Segment::System, base + 8, 2, "index cluster count")?
                .try_into()
                .expect("two bytes"),
        );
        let count_a = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x0A, 2, "index count A")?
                .try_into()
                .expect("two bytes"),
        );
        let count_word = self.u32(base + 0x0C, "index count word")?;
        let count_b = ((count_word >> 8) & 0xFFFF) as u16;
        // The record at +0x20 carries a constant word at its +0x10.
        let constant = self
            .bytes(Segment::System, base + 0x20, 0x20, "index record")
            .and_then(|bytes| bytes.get(0x10..0x18))
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")));
        let record_base = u64::from(record);
        self.bytes(Segment::System, record_base, 0x30, "index buffer record")?;
        let elements = self.u32(record_base + 0x08, "index element count")?;
        let unit = u16::from_le_bytes(
            self.bytes(Segment::System, record_base + 0x0C, 2, "index element unit")?
                .try_into()
                .expect("two bytes"),
        );
        let graphics = self.pointer(
            record_base + 0x18,
            "index graphics pointer",
            Segment::Graphics,
        )?;
        let len = u64::from(elements) * u64::from(unit);
        let in_bounds = u64::from(graphics) + len <= self.graphics.len() as u64;
        if !in_bounds {
            self.issues.push(Issue::Bounds {
                field: "index range",
                at: record_base as usize + 0x18,
                segment: Segment::Graphics,
                offset: u64::from(graphics),
                len,
                size: self.graphics.len() as u64,
            });
        }
        // The index bytes begin with the cluster word, count A and count B.
        let header = self
            .graphics
            .get(graphics as usize..graphics as usize + 12)
            .map(|bytes| {
                [
                    u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes")),
                    u32::from_le_bytes(bytes[4..8].try_into().expect("four bytes")),
                    u32::from_le_bytes(bytes[8..12].try_into().expect("four bytes")),
                ]
            });
        let header_matches = header.map(|words| {
            let expected = 0x8000_0000u32 | u32::from(clusters);
            let matches = words[0] == expected
                && words[1] == u32::from(count_a)
                && words[2] == u32::from(count_b);
            if !matches {
                self.issues.push(Issue::Arithmetic {
                    field: "index header",
                    message: format!(
                        "the index bytes begin {:#010X} {:#010X} {:#010X}; the descriptor declares {expected:#010X} {} {}",
                        words[0], words[1], words[2], count_a, count_b
                    ),
                });
            }
            matches
        });
        Some(IndexView {
            at,
            clusters,
            count_a,
            count_b,
            count_word,
            low_byte: (count_word & 0xFF) as u8,
            high_byte: (count_word >> 24) as u8,
            elements,
            unit,
            graphics,
            range: in_bounds.then_some(Region {
                segment: Segment::Graphics,
                offset: u64::from(graphics),
                len,
            }),
            in_bounds,
            header,
            header_matches,
            constant,
        })
    }

    fn shader_group(&mut self, at: u32) -> Option<ShaderGroup> {
        let base = u64::from(at);
        self.bytes(Segment::System, base, 0x20, "shader group")?;
        let array = self.pointer(base + 0x10, "shader array", Segment::System)?;
        let count = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x18, 2, "shader count")?
                .try_into()
                .expect("two bytes"),
        );
        let capacity = u16::from_le_bytes(
            self.bytes(Segment::System, base + 0x1A, 2, "shader capacity")?
                .try_into()
                .expect("two bytes"),
        );
        let shaders = self
            .pointer_array(array, count, "shader array")
            .into_iter()
            .filter_map(|at| self.shader(at))
            .collect();
        Some(ShaderGroup {
            at,
            shaders,
            count,
            capacity,
        })
    }

    fn shader(&mut self, at: u32) -> Option<Shader> {
        let base = u64::from(at);
        self.bytes(Segment::System, base, 0x40, "shader record")?;
        let shader_hash = self.u32(base, "shader hash")?;
        let marker = self.u32(base + 0x04, "shader marker")?;
        let slots_value = self.u64(base + 0x10, "texture slot table")?;
        let parameters_at = self.pointer(base + 0x20, "parameter table", Segment::System)?;
        let flags: [u8; 8] = self
            .bytes(Segment::System, base + 0x38, 8, "shader flags")?
            .try_into()
            .expect("eight bytes");
        let (texture_parameters, total_parameters, word_06) = self.parameter_counts(parameters_at);
        // A shader that declares no texture parameter stores no slot table. A
        // null table next to a non-zero parameter count is still an error.
        let slots_at = match system_pointer(slots_value) {
            Some(at) => Some(at),
            None if slots_value == 0 && texture_parameters == 0 => None,
            None => {
                self.issues.push(Issue::Pointer {
                    field: "texture slot table",
                    at: base as usize + 0x10,
                    value: slots_value,
                });
                None
            }
        };
        let parameters = self.parameters(parameters_at, total_parameters, texture_parameters);
        let (slots, bound_slots) = self.slot_counts(slots_at, texture_parameters);
        let slot_states = self.slot_states(slots_at, &parameters, texture_parameters);
        Some(Shader {
            at,
            shader_hash,
            marker,
            texture_parameters,
            total_parameters,
            word_06,
            slots,
            bound_slots,
            flags,
            parameters,
            slot_states,
        })
    }

    /// Reads the parameter pairs. `total` bounds the walk; the first
    /// `textures` entries are the texture parameters.
    fn parameters(&mut self, at: u32, total: u16, textures: u8) -> Vec<Parameter> {
        let base = u64::from(at) + 8;
        let mut parameters = Vec::new();
        for index in 0..u32::from(total) {
            if parameters.len() >= MAX_ARRAY {
                break;
            }
            let start = base as usize + index as usize * 8;
            let Some(bytes) = self.system.get(start..start + 8) else {
                self.issues.push(Issue::Clamped {
                    field: "parameter table",
                    declared: u64::from(total),
                    used: parameters.len() as u64,
                });
                break;
            };
            let name_hash = u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes"));
            let packed_value = u32::from_le_bytes(bytes[4..8].try_into().expect("four bytes"));
            let texture = index < u32::from(textures);
            parameters.push(Parameter {
                index: index as u16,
                name_hash,
                packed: packed_value,
                class: (packed_value & 0x3) as u8,
                slot: packed_value >> 2,
                texture,
            });
        }
        parameters
    }

    fn slot_states(
        &mut self,
        at: Option<u32>,
        parameters: &[Parameter],
        texture_parameters: u8,
    ) -> Vec<Slot> {
        let Some(at) = at else {
            return Vec::new();
        };
        let mut slots = Vec::with_capacity(usize::from(texture_parameters));
        for parameter in parameters.iter().filter(|parameter| parameter.texture) {
            let start = at as usize + parameter.index as usize * 8;
            let pointer = u64_at(self.system, start).unwrap_or(0);
            let bound = pointer != 0;
            let texture = crate::dictionary::TextureParameter {
                class: parameter.class,
                slot: parameter.slot,
            };
            let Some(state) =
                crate::dictionary::slot_state(texture, u32::from(texture_parameters), bound)
            else {
                continue;
            };
            let (key, hash32) = if state == crate::dictionary::SlotState::Bound {
                (self.record_key(pointer), self.record_hash32(pointer))
            } else {
                (None, None)
            };
            slots.push(Slot {
                index: parameter.index,
                state,
                key,
                hash32,
            });
        }
        slots
    }

    /// Follows a texture record to its name record's 64-bit key. The key is a
    /// hash: it is not resolved to a dictionary record.
    fn record_key(&mut self, pointer: u64) -> Option<u64> {
        let record = system_pointer(pointer)?;
        let name = u64_at(self.system, record as usize + 0x30)?;
        let name = system_pointer(name)?;
        u64_at(self.system, name as usize + 8)
    }

    /// The name record's 32-bit dictionary hash. It is read only when the
    /// `+0x10` word is the observed `6` variant; other variants hold a
    /// pointer there.
    fn record_hash32(&mut self, pointer: u64) -> Option<u32> {
        let record = system_pointer(pointer)?;
        let name = u64_at(self.system, record as usize + 0x30)?;
        let name = system_pointer(name)?;
        (u32_at(self.system, name as usize + 0x10) == Some(6))
            .then(|| u32_at(self.system, name as usize + 0x18))
            .flatten()
    }

    fn parameter_counts(&mut self, at: u32) -> (u8, u16, u16) {
        let base = u64::from(at);
        let Some(header) = self.bytes(Segment::System, base, 8, "parameter table") else {
            return (0, 0, 0);
        };
        (
            header[1],
            u16::from_le_bytes([header[4], header[5]]),
            u16::from_le_bytes([header[6], header[7]]),
        )
    }

    fn slot_counts(&mut self, at: Option<u32>, texture_parameters: u8) -> (u32, u32) {
        let declared = u32::from(texture_parameters);
        let Some(at) = at else {
            return (0, 0);
        };
        let mut bound = 0;
        let mut slots = 0;
        for index in 0..declared {
            slots += 1;
            let Some(value) = u64_at(self.system, at as usize + index as usize * 8) else {
                self.issues.push(Issue::Clamped {
                    field: "texture slot table",
                    declared: u64::from(declared),
                    used: u64::from(slots - 1),
                });
                break;
            };
            if value != 0 {
                bound += 1;
            }
        }
        (slots, bound)
    }
}

/// Inspects a reconstructed drawable. `None` when the system segment does not
/// have the header shape.
pub fn inspect(system: &[u8], graphics: &[u8]) -> Option<Report> {
    inspect_at(system, graphics, 0)
}

/// Inspects a drawable whose header starts at `root`. The header must carry a
/// page map, which is the resource-level form.
pub fn inspect_at(system: &[u8], graphics: &[u8], root: usize) -> Option<Report> {
    if !is_drawable_at(system, graphics, root) {
        return None;
    }
    inspect_body(system, graphics, root, true)
}

/// Inspects a drawable embedded in a fragment or a dictionary. The page-map
/// word is read when it is a pointer and tolerated when it is zero; the
/// containing resource owns the page map.
pub fn inspect_member_at(system: &[u8], graphics: &[u8], root: usize) -> Option<Report> {
    if !is_member_drawable_at(system, graphics, root) {
        return None;
    }
    inspect_body(system, graphics, root, false)
}

fn inspect_body(
    system: &[u8],
    graphics: &[u8],
    root: usize,
    require_page_map: bool,
) -> Option<Report> {
    let header = HeaderView::parse_at(system, root, require_page_map).ok()?;
    let mut walk = Walk::new(system, graphics);
    let mut lod = Vec::new();
    let mut empty_slots = Vec::new();
    for (slot, &value) in header.lod_slots.iter().enumerate() {
        let Some(offset) = system_pointer(value) else {
            if value == 0 {
                empty_slots.push(slot);
            } else {
                walk.issues.push(Issue::Pointer {
                    field: "LOD slot",
                    at: root + 0x50 + 8 * slot,
                    value,
                });
            }
            continue;
        };
        match walk.lod_slot(slot, offset) {
            Some(slot) => lod.push(slot),
            None => empty_slots.push(slot),
        }
    }
    let shader_group = match header.shader_group {
        Some(at) => walk.shader_group(at),
        None => None,
    };
    let graphics_offsets = lod
        .iter()
        .flat_map(|slot| slot.models.iter())
        .flat_map(|model| model.geometries.iter())
        .filter_map(|geometry| geometry.vertex_buffer.as_ref())
        .map(|buffer| buffer.graphics)
        .collect::<Vec<_>>();
    let graphics_base = graphics_base(graphics, &graphics_offsets);

    let mut materials = MaterialSummary::default();
    let mut keys: Vec<u64> = Vec::new();
    if let Some(group) = &shader_group {
        materials.shaders = group.shaders.len();
        for shader in &group.shaders {
            materials.declared_slots += u32::from(shader.texture_parameters);
            for slot in &shader.slot_states {
                match slot.state {
                    crate::dictionary::SlotState::Bound => {
                        materials.bound += 1;
                        if let Some(key) = slot.key {
                            keys.push(key);
                        }
                    }
                    crate::dictionary::SlotState::Unbound => materials.unbound += 1,
                    crate::dictionary::SlotState::Invalid => materials.invalid += 1,
                }
            }
        }
    }
    keys.sort_unstable();
    keys.dedup();
    materials.distinct_keys = keys.len();

    let mut model_union = UnionCheck {
        matches: true,
        delta: 0.0,
        models: 0,
        trivial: 0,
    };
    let mut union: Option<Aabb> = None;
    for model in lod.iter().flat_map(|slot| slot.models.iter()) {
        let Some(bounds) = &model.bounds else {
            continue;
        };
        union = Some(match union {
            Some(current) => current.union(&bounds.aggregate),
            None => bounds.aggregate,
        });
        match bounds.union_matches {
            Some(true) => model_union.models += 1,
            Some(false) => {
                model_union.models += 1;
                model_union.matches = false;
                model_union.delta = model_union.delta.max(bounds.union_delta);
            }
            None => model_union.trivial += 1,
        }
    }
    let header_box = Aabb {
        min: header.bounds.min,
        max: header.bounds.max,
    };
    let header_union = union.map(|union| {
        let delta = union.delta(&header_box);
        HeaderUnion {
            matches: delta <= AABB_TOLERANCE && union.finite() && header_box.finite(),
            delta,
            finite: union.finite() && header_box.finite(),
        }
    });

    let status = if walk.issues.is_empty() {
        "complete"
    } else {
        "partial"
    };
    Some(Report {
        header,
        lod,
        empty_slots,
        graphics_base,
        shader_group,
        materials,
        model_union,
        header_union,
        issues: walk.issues,
        status,
    })
}

/// Derives the graphics base from the vertex-buffer graphics pointers.
///
/// A base is supported when at least two distinct graphics offsets land on
/// the marker. Two references to the same offset are one support.
fn graphics_base(graphics: &[u8], offsets: &[u32]) -> GraphicsBase {
    let mut distinct = offsets.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 2 {
        return GraphicsBase::Unavailable;
    }
    // Positions of the marker in the graphics segment, bounded.
    let mut candidates: Vec<u64> = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= graphics.len() {
        if graphics[pos..pos + 4] == MARKER {
            for &offset in &distinct {
                let Some(base) = (pos as u64).checked_sub(u64::from(offset)) else {
                    continue;
                };
                if distinct.iter().all(|&other| {
                    let at = base + u64::from(other);
                    graphics
                        .get(at as usize..at as usize + 4)
                        .is_some_and(|bytes| bytes == MARKER)
                }) {
                    candidates.push(base);
                }
            }
        }
        pos += 4;
    }
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [] => GraphicsBase::Unavailable,
        [base] => GraphicsBase::Unique {
            base: *base,
            supports: distinct.len(),
        },
        _ => GraphicsBase::Ambiguous {
            candidates: candidates.len(),
        },
    }
}

/// A printable ASCII string starting at `at` and ending at a NUL. Longer than
/// 256 bytes without a terminator, any non-printable byte or a non-ASCII byte
/// yields nothing, so a pointer that does not carry a name is not guessed.
fn ascii_string(bytes: &[u8], at: usize) -> Option<String> {
    const MAX: usize = 256;
    let tail = bytes.get(at..)?;
    let end = tail.iter().take(MAX).position(|&byte| byte == 0)?;
    let text = tail.get(..end)?;
    if text.is_empty() || text.iter().any(|&byte| !(0x20..=0x7E).contains(&byte)) {
        return None;
    }
    std::str::from_utf8(text).ok().map(str::to_owned)
}

/// The stored name of the drawable at `root`, read from its `+0xA8` pointer.
///
/// This is the label the resource carries, not a resolved file name. It is
/// available without walking the LOD chain, which is what a dictionary
/// enumeration needs.
pub fn member_name_at(system: &[u8], root: usize) -> Option<String> {
    let name = system_pointer(u64_at(system, root + 0xA8)?)?;
    ascii_string(system, name as usize)
}

fn system_pointer(value: u64) -> Option<u32> {
    match Pointer::decode(value) {
        Some(Pointer::System(offset)) => Some(offset),
        _ => None,
    }
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn f32_at(bytes: &[u8], at: usize) -> Option<f32> {
    Some(f32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
