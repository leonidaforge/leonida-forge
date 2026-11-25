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

/// The header fields whose positions the research confirmed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeaderView {
    pub page_map: u32,
    pub shader_group: Option<u32>,
    pub skeleton: Option<u32>,
    pub bounds: Bounds,
    pub lod_slots: [u64; LOD_SLOTS],
    pub distances: [f32; LOD_SLOTS],
    pub flags: [u32; LOD_SLOTS],
    pub name: Option<u32>,
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
    pub declared_bytes: u64,
    pub attribute_bytes: u64,
    pub layout_end: u64,
    pub prefix_gap: i64,
    pub attributes: Vec<Attribute>,
}

/// An index descriptor's verified fields and the range it addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexView {
    pub at: u32,
    pub clusters: u16,
    pub elements: u32,
    pub unit: u16,
    pub graphics: u32,
    pub range: Option<Region>,
    pub in_bounds: bool,
    pub constant: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    pub at: u32,
    pub vertex_buffer: Option<VertexBuffer>,
    pub index: Option<IndexView>,
    pub word_30: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Model {
    pub at: u32,
    pub geometry_count: u16,
    pub capacity: u16,
    pub word_14: u32,
    pub shader_indices: Option<u32>,
    pub flags: u64,
    pub geometries: Vec<Geometry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// `+0x04`, the constant `0x6D657461` in every sample.
    pub marker: u32,
    pub texture_parameters: u8,
    pub total_parameters: u16,
    pub word_06: u16,
    pub slots: u32,
    pub bound_slots: u32,
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
    let Ok(header) = HeaderView::parse(system) else {
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
    fn parse(system: &[u8]) -> Result<Self, Issue> {
        if system.len() < 0xC0 {
            return Err(Issue::Missing {
                field: "the 0xC0-byte header",
            });
        }
        if u64_at(system, 0) != Some(0) {
            return Err(Issue::Arithmetic {
                field: "header +0x00",
                message: "the first word is not zero".to_string(),
            });
        }
        let page_map = system_pointer(u64_at(system, 0x08).unwrap_or(0)).ok_or(Issue::Pointer {
            field: "page map",
            at: 0x08,
            value: u64_at(system, 0x08).unwrap_or(0),
        })?;
        let mut lod_slots = [0u64; LOD_SLOTS];
        let mut distances = [0f32; LOD_SLOTS];
        let mut flags = [0u32; LOD_SLOTS];
        for slot in 0..LOD_SLOTS {
            lod_slots[slot] = u64_at(system, 0x50 + 8 * slot).unwrap_or(0);
            distances[slot] = f32_at(system, 0x70 + 4 * slot).unwrap_or(0.0);
            flags[slot] = u32_at(system, 0x80 + 4 * slot).unwrap_or(0);
        }
        Ok(Self {
            page_map,
            shader_group: system_pointer(u64_at(system, 0x10).unwrap_or(0)),
            skeleton: system_pointer(u64_at(system, 0x18).unwrap_or(0)),
            bounds: Bounds {
                centre: [
                    f32_at(system, 0x20).unwrap_or(0.0),
                    f32_at(system, 0x24).unwrap_or(0.0),
                    f32_at(system, 0x28).unwrap_or(0.0),
                ],
                radius: f32_at(system, 0x2C).unwrap_or(0.0),
                min: [
                    f32_at(system, 0x30).unwrap_or(0.0),
                    f32_at(system, 0x34).unwrap_or(0.0),
                    f32_at(system, 0x38).unwrap_or(0.0),
                ],
                max: [
                    f32_at(system, 0x40).unwrap_or(0.0),
                    f32_at(system, 0x44).unwrap_or(0.0),
                    f32_at(system, 0x48).unwrap_or(0.0),
                ],
            },
            lod_slots,
            distances,
            flags,
            name: system_pointer(u64_at(system, 0xA8).unwrap_or(0)),
            list: system_pointer(u64_at(system, 0xB0).unwrap_or(0)),
            word_a8_hi: u64_at(system, 0xB8).unwrap_or(0),
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
        Some(Model {
            at,
            geometry_count,
            capacity,
            word_14,
            shader_indices,
            flags,
            geometries,
        })
    }

    fn geometry(&mut self, at: u32) -> Option<Geometry> {
        let base = u64::from(at);
        self.bytes(Segment::System, base, 0x48, "geometry record")?;
        let vertex_buffer = self.pointer(base + 0x08, "vertex buffer", Segment::System)?;
        let word_30 = self.u64(base + 0x30, "geometry word")?;
        let index = self.pointer(base + 0x40, "index descriptor", Segment::System)?;
        Some(Geometry {
            at,
            vertex_buffer: self.vertex_buffer(vertex_buffer),
            index: self.index_descriptor(index),
            word_30,
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
            declared_bytes: u64::from(elements) * u64::from(unit),
            attribute_bytes: 0,
            layout_end: 0,
            prefix_gap: 0,
            attributes: Vec::new(),
        };
        if let Some(layout) = layout
            && let Some(view) = self.layout(layout, &mut buffer)
        {
            let _ = view;
        }
        Some(buffer)
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
        Some(IndexView {
            at,
            clusters,
            elements,
            unit,
            graphics,
            range: in_bounds.then_some(Region {
                segment: Segment::Graphics,
                offset: u64::from(graphics),
                len,
            }),
            in_bounds,
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
        let marker = self.u32(base + 0x04, "shader marker")?;
        let slots_at = self.pointer(base + 0x10, "texture slot table", Segment::System)?;
        let parameters_at = self.pointer(base + 0x20, "parameter table", Segment::System)?;
        let (texture_parameters, total_parameters, word_06) = self.parameter_counts(parameters_at);
        let (slots, bound_slots) = self.slot_counts(slots_at, texture_parameters);
        Some(Shader {
            at,
            marker,
            texture_parameters,
            total_parameters,
            word_06,
            slots,
            bound_slots,
        })
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

    fn slot_counts(&mut self, at: u32, texture_parameters: u8) -> (u32, u32) {
        let declared = u32::from(texture_parameters);
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
    let header = HeaderView::parse(system).ok()?;
    if !is_drawable(system, graphics) {
        return None;
    }
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
                    at: 0x50 + 8 * slot,
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
            supports: distinct.len() as usize,
        },
        _ => GraphicsBase::Ambiguous {
            candidates: candidates.len(),
        },
    }
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
