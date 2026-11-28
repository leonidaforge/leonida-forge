//! Decoding of a primitive's blend weights and blend indices.
//!
//! The declaration table at the vertex-buffer graphics target is a fixed
//! 23-slot array. The slot is the attribute's semantic and the word carries a
//! declaration format plus a byte offset; a zero word means the attribute is
//! absent. The index encoding is therefore identified by the pair
//! (declaration format, layout size), not by the format alone:
//!
//! | Declaration | Layout size | Encoding |
//! | ----------- | ----------- | -------- |
//! | `0x25` | 4 | four `u8` blend indices |
//! | `0x8c` | 16 | four `u32` blend indices |
//! | `0x4a` | 8 | two `u32` blend indices |
//! | `0x00` | 1 | one `u8` blend index |
//! | `0x00` | 2 | one `u16` blend index |
//!
//! The last two forms carry no weight attribute: a single influence has weight
//! one, which is a structural consequence rather than a guess. The two wide
//! forms pair lane `i` of the index attribute with lane `i` of the four `u8`
//! weights at slot 6.
//!
//! Indices name the skeleton's own array position. The survey checked every
//! active index against the declared bone count (none exceeded it), saw sparse
//! index sets rather than compact local ranges, and found each tail-chain index
//! of the peacock nearest the same-numbered bone. No palette array was found in
//! the geometry records; the model `+0x28` slot does not read as a `u8` or `u16`
//! bone list.

use lforge_rage9::drawable::{
    Attribute, Declaration, SEMANTIC_BLEND_INDICES, SEMANTIC_BLEND_WEIGHTS, VertexBuffer,
};
use lforge_scene::{
    BoneResolution, Diagnostic, InfluenceStatus, MAX_INFLUENCES, VertexInfluence, VertexInfluences,
};

/// The weight denominators the format establishes.
const WEIGHT_DENOMINATORS: [u32; 2] = [255, 127];

/// The detected index encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IndexForm {
    /// Bytes per index.
    width: usize,
    /// Indices per vertex.
    lanes: usize,
}

impl IndexForm {
    fn stride(self) -> usize {
        self.width * self.lanes
    }
}

/// What the decoder established for one geometry.
#[derive(Debug, Clone, PartialEq)]
pub enum InfluenceDecode {
    /// The declaration is a supported form and every active lane validated.
    Decoded(VertexInfluences),
    /// The geometry declares influence data this decoder does not interpret.
    Unsupported { reason: String },
    /// The geometry declares no influence attribute and no implicit single-bone
    /// form applies.
    NotDeclared,
}

/// Identifies the index encoding from the declaration format and the size of
/// the layout entry at the same offset.
fn index_form(buffer: &VertexBuffer, declaration: &Declaration) -> Option<IndexForm> {
    let attribute: &Attribute = buffer.attribute_at(declaration.offset)?;
    match (declaration.format, attribute.size) {
        (0x25, 4) => Some(IndexForm { width: 1, lanes: 4 }),
        (0x8c, 16) => Some(IndexForm { width: 4, lanes: 4 }),
        (0x4a, 8) => Some(IndexForm { width: 4, lanes: 2 }),
        (0x00, 1) => Some(IndexForm { width: 1, lanes: 1 }),
        (0x00, 2) => Some(IndexForm { width: 2, lanes: 1 }),
        _ => None,
    }
}

fn index_at(blob: &[u8], at: usize, width: usize) -> Option<u32> {
    Some(match width {
        1 => u32::from(*blob.get(at)?),
        2 => u32::from(u16::from_le_bytes(blob.get(at..at + 2)?.try_into().ok()?)),
        4 => u32::from_le_bytes(blob.get(at..at + 4)?.try_into().ok()?),
        _ => return None,
    })
}

/// Decodes the influence streams of one geometry.
///
/// `bone_count` is the geometry record's declared bone count. An index is
/// validated against it and against the skeleton when the skeleton is smaller.
/// An active index that fails is reported and the whole set is unsupported:
/// nothing is clamped and no index is remapped to bone zero.
pub fn decode(
    buffer: &VertexBuffer,
    blob: &[u8],
    vertex_count: usize,
    bone_count: Option<usize>,
    diagnostics: &mut Vec<Diagnostic>,
) -> InfluenceDecode {
    let Some(bones) = bone_count.filter(|bones| *bones > 0) else {
        return InfluenceDecode::NotDeclared;
    };
    let weights = buffer.declaration(SEMANTIC_BLEND_WEIGHTS);
    let indices = buffer.declaration(SEMANTIC_BLEND_INDICES);
    let form = indices.and_then(|declaration| index_form(buffer, declaration));
    if let Some(declaration) = indices.filter(|_| form.is_none()) {
        return InfluenceDecode::Unsupported {
            reason: format!(
                "the blend-index declaration (format {:#04x}) does not match a supported encoding",
                declaration.format
            ),
        };
    }
    if vertex_count == 0 {
        return InfluenceDecode::Unsupported {
            reason: "the geometry holds no vertex".to_string(),
        };
    }

    match (weights, form) {
        (Some(weights), Some(form)) => decode_weighted(
            buffer,
            blob,
            vertex_count,
            bones,
            weights,
            form,
            diagnostics,
        ),
        (Some(weights), None) => {
            // A one-bone skeleton needs no index stream: the only bone takes
            // the single non-zero weight lane.
            if bones != 1 {
                return InfluenceDecode::Unsupported {
                    reason: format!(
                        "the geometry declares {bones} bones but stores no blend-index attribute"
                    ),
                };
            }
            decode_single_bone_weights(blob, vertex_count, weights, diagnostics)
        }
        (None, Some(form)) if form.lanes == 1 => {
            decode_single_index(buffer, blob, vertex_count, bones, form)
        }
        (None, Some(form)) => InfluenceDecode::Unsupported {
            reason: format!(
                "the geometry stores {} blend indices per vertex but no blend weights",
                form.lanes
            ),
        },
        (None, None) if bones == 1 => decode_implicit_single_bone(vertex_count),
        (None, None) => InfluenceDecode::NotDeclared,
    }
}

/// A geometry that declares no influence attribute on a one-bone skeleton.
///
/// The geometry record states one bone and the skeleton holds one, but the
/// record states no bone reference. The association is therefore inferred
/// rather than decoded, and it is reported as such: it deforms, but a caller
/// can tell it apart from a verified influence stream.
fn decode_implicit_single_bone(vertex_count: usize) -> InfluenceDecode {
    if vertex_count == 0 {
        return InfluenceDecode::Unsupported {
            reason: "the geometry holds no vertex".to_string(),
        };
    }
    let mut lanes = [VertexInfluence::NONE; MAX_INFLUENCES];
    lanes[0] = VertexInfluence {
        bone: 0,
        weight: 1.0,
    };
    InfluenceDecode::Decoded(VertexInfluences {
        per_vertex: vec![lanes; vertex_count],
        bones: vec![0],
        weighted: false,
        lanes: 0,
        max_influences: 1,
        resolution: BoneResolution::DirectSkeleton,
        status: InfluenceStatus::Complete,
        inferred: true,
    })
}

fn decode_weighted(
    buffer: &VertexBuffer,
    blob: &[u8],
    vertex_count: usize,
    bones: usize,
    weights: &Declaration,
    form: IndexForm,
    diagnostics: &mut Vec<Diagnostic>,
) -> InfluenceDecode {
    if weights.format != 0x26 {
        return InfluenceDecode::Unsupported {
            reason: format!(
                "the blend-weight declaration uses format {:#04x}, not the 0x26 four-u8 form",
                weights.format
            ),
        };
    }
    let Some(weight_bytes) = blob.get(
        weights.offset as usize
            ..(weights.offset as usize).saturating_add(vertex_count.saturating_mul(4)),
    ) else {
        return InfluenceDecode::Unsupported {
            reason: "the blend-weight stream runs past the vertex buffer".to_string(),
        };
    };
    let Some(index_declaration) = buffer.declaration(SEMANTIC_BLEND_INDICES) else {
        return InfluenceDecode::NotDeclared;
    };
    let index_offset = index_declaration.offset as usize;
    if blob
        .get(index_offset..index_offset.saturating_add(vertex_count.saturating_mul(form.stride())))
        .is_none()
    {
        return InfluenceDecode::Unsupported {
            reason: "the blend-index stream runs past the vertex buffer".to_string(),
        };
    }
    let mut per_vertex = Vec::with_capacity(vertex_count);
    let mut used = std::collections::BTreeSet::new();
    let mut weighted = false;
    let mut max_influences = 0u8;
    let mut unnormalised: Option<(usize, u32)> = None;
    for vertex in 0..vertex_count {
        let weight_lanes = &weight_bytes[vertex * 4..vertex * 4 + 4];
        let total: u32 = weight_lanes.iter().map(|value| u32::from(*value)).sum();
        if total == 0 {
            return InfluenceDecode::Unsupported {
                reason: format!("the blend weights of vertex {vertex} are all zero"),
            };
        }
        let denominator = if WEIGHT_DENOMINATORS.contains(&total) {
            total
        } else {
            unnormalised.get_or_insert((vertex, total)).1
        };
        let mut lanes = [VertexInfluence::NONE; MAX_INFLUENCES];
        let mut active = 0u8;
        for lane in 0..MAX_INFLUENCES {
            let weight = u32::from(weight_lanes[lane]);
            if weight == 0 {
                continue;
            }
            if lane >= form.lanes {
                return InfluenceDecode::Unsupported {
                    reason: format!(
                        "vertex {vertex} weights lane {lane}, but the index attribute carries {} lane(s)",
                        form.lanes
                    ),
                };
            }
            let Some(index) = index_at(
                blob,
                index_offset + vertex * form.stride() + lane * form.width,
                form.width,
            ) else {
                return InfluenceDecode::Unsupported {
                    reason: "the blend-index stream runs past the vertex buffer".to_string(),
                };
            };
            if index as usize >= bones {
                return InfluenceDecode::Unsupported {
                    reason: format!(
                        "vertex {vertex} names bone {index}, outside the {bones}-bone skeleton"
                    ),
                };
            }
            let Ok(bone) = u16::try_from(index) else {
                return InfluenceDecode::Unsupported {
                    reason: format!(
                        "vertex {vertex} names bone {index}, which a {bones}-bone skeleton cannot address with a 16-bit index"
                    ),
                };
            };
            lanes[lane] = VertexInfluence {
                bone,
                weight: weight as f32 / denominator as f32,
            };
            used.insert(index as usize);
            active += 1;
        }
        if active > 1 {
            weighted = true;
        }
        max_influences = max_influences.max(active);
        per_vertex.push(lanes);
    }
    if let Some((vertex, total)) = unnormalised {
        diagnostics.push(Diagnostic::new(format!(
            "the blend weights are not normalised at vertex {vertex} (total {total}); the primitive is reported as unnormalised and is not deformed"
        )));
        return InfluenceDecode::Decoded(VertexInfluences {
            per_vertex,
            bones: used.into_iter().collect(),
            weighted,
            lanes: form.lanes as u8,
            max_influences,
            resolution: BoneResolution::DirectSkeleton,
            status: InfluenceStatus::Unnormalised { vertex, total },
            inferred: false,
        });
    }
    InfluenceDecode::Decoded(VertexInfluences {
        per_vertex,
        bones: used.into_iter().collect(),
        weighted,
        lanes: form.lanes as u8,
        max_influences,
        resolution: BoneResolution::DirectSkeleton,
        status: InfluenceStatus::Complete,
        inferred: false,
    })
}

/// Weights with no index stream on a one-bone skeleton.
fn decode_single_bone_weights(
    blob: &[u8],
    vertex_count: usize,
    weights: &Declaration,
    diagnostics: &mut Vec<Diagnostic>,
) -> InfluenceDecode {
    if weights.format != 0x26 {
        return InfluenceDecode::Unsupported {
            reason: format!(
                "the blend-weight declaration uses format {:#04x}, not the 0x26 four-u8 form",
                weights.format
            ),
        };
    }
    let Some(weight_bytes) = blob
        .get(weights.offset as usize..(weights.offset as usize).saturating_add(vertex_count * 4))
    else {
        return InfluenceDecode::Unsupported {
            reason: "the blend-weight stream runs past the vertex buffer".to_string(),
        };
    };
    let mut per_vertex = Vec::with_capacity(vertex_count);
    let mut unnormalised: Option<(usize, u32)> = None;
    for vertex in 0..vertex_count {
        let lanes = &weight_bytes[vertex * 4..vertex * 4 + 4];
        let total: u32 = lanes.iter().map(|value| u32::from(*value)).sum();
        if total == 0 {
            return InfluenceDecode::Unsupported {
                reason: format!("the blend weights of vertex {vertex} are all zero"),
            };
        }
        if lanes[1] != 0 || lanes[2] != 0 || lanes[3] != 0 {
            return InfluenceDecode::Unsupported {
                reason: format!(
                    "vertex {vertex} weights a lane other than the first on a one-bone skeleton"
                ),
            };
        }
        let denominator = if WEIGHT_DENOMINATORS.contains(&total) {
            total
        } else {
            unnormalised.get_or_insert((vertex, total)).1
        };
        let mut out = [VertexInfluence::NONE; MAX_INFLUENCES];
        out[0] = VertexInfluence {
            bone: 0,
            weight: u32::from(lanes[0]) as f32 / denominator as f32,
        };
        per_vertex.push(out);
    }
    if let Some((vertex, total)) = unnormalised {
        diagnostics.push(Diagnostic::new(format!(
            "the blend weights are not normalised at vertex {vertex} (total {total}); the primitive is reported as unnormalised and is not deformed"
        )));
        return InfluenceDecode::Decoded(VertexInfluences {
            per_vertex,
            bones: vec![0],
            weighted: false,
            lanes: 1,
            max_influences: 1,
            resolution: BoneResolution::DirectSkeleton,
            status: InfluenceStatus::Unnormalised { vertex, total },
            inferred: false,
        });
    }
    InfluenceDecode::Decoded(VertexInfluences {
        per_vertex,
        bones: vec![0],
        weighted: false,
        lanes: 1,
        max_influences: 1,
        resolution: BoneResolution::DirectSkeleton,
        status: InfluenceStatus::Complete,
        inferred: false,
    })
}

/// A single stored index per vertex, with the weight the form implies. The
/// index may differ per vertex, so this is single-influence skinning rather than
/// a whole-primitive attachment.
fn decode_single_index(
    buffer: &VertexBuffer,
    blob: &[u8],
    vertex_count: usize,
    bones: usize,
    form: IndexForm,
) -> InfluenceDecode {
    let Some(declaration) = buffer.declaration(SEMANTIC_BLEND_INDICES) else {
        return InfluenceDecode::NotDeclared;
    };
    let offset = declaration.offset as usize;
    let mut per_vertex = Vec::with_capacity(vertex_count);
    let mut used = std::collections::BTreeSet::new();
    for vertex in 0..vertex_count {
        let Some(index) = index_at(blob, offset + vertex * form.stride(), form.width) else {
            return InfluenceDecode::Unsupported {
                reason: "the blend-index stream runs past the vertex buffer".to_string(),
            };
        };
        if index as usize >= bones {
            return InfluenceDecode::Unsupported {
                reason: format!(
                    "vertex {vertex} names bone {index}, outside the {bones}-bone skeleton"
                ),
            };
        }
        let Ok(bone) = u16::try_from(index) else {
            return InfluenceDecode::Unsupported {
                reason: format!(
                    "vertex {vertex} names bone {index}, which a {bones}-bone skeleton cannot address with a 16-bit index"
                ),
            };
        };
        let mut lanes = [VertexInfluence::NONE; MAX_INFLUENCES];
        lanes[0] = VertexInfluence { bone, weight: 1.0 };
        used.insert(index as usize);
        per_vertex.push(lanes);
    }
    InfluenceDecode::Decoded(VertexInfluences {
        per_vertex,
        bones: used.into_iter().collect(),
        weighted: false,
        lanes: 1,
        max_influences: 1,
        resolution: BoneResolution::DirectSkeleton,
        status: InfluenceStatus::Complete,
        inferred: false,
    })
}

#[cfg(test)]
mod tests;
