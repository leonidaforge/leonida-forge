//! Targeted survey of the vertex declarations of skeleton-bearing geometry.
//!
//! The survey records, per geometry, the fixed 23-slot declaration table, the
//! layout attributes, the weight totals, the blend-index range and, for the
//! forms the current decoder does not read, the raw lane statistics of the
//! declared influence attribute. It exists so a new influence encoding is
//! implemented from measured declarations rather than from a guess.
//!
//! Ignored by default. `LF_TEST_ARCHIVE_LIST` (or `LF_TEST_ARCHIVE_DIR`) names
//! the archives and `LF_TEST_EXECUTABLE` the executable that supplies the
//! archive keys. `LF_SURVEY_OUT` writes one JSON line per geometry.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::*;
use crate::files::Executable;

/// One declaration entry of the fixed 23-slot table.
#[derive(Serialize, Clone)]
struct Declaration {
    slot: u32,
    format: u8,
    offset: u64,
}

/// One present layout attribute.
#[derive(Serialize, Clone)]
struct Attribute {
    slot: usize,
    offset: u32,
    size: u8,
    format: u8,
}

#[derive(Serialize)]
struct WeightFacts {
    /// Histogram of the four-lane `u8` total.
    sums: BTreeMap<u32, usize>,
    zero_vertices: usize,
    max_total: u32,
    min_total: u32,
}

#[derive(Serialize)]
struct IndexFacts {
    active_lanes: usize,
    max: u32,
    min: u32,
    distinct: usize,
    contiguous_from_zero: bool,
    inactive_nonzero_lanes: usize,
    active_out_of_range: usize,
    lane0_max: u32,
}

/// Statistics of a one-byte index attribute, read at one byte per vertex.
#[derive(Serialize)]
struct ByteIndexFacts {
    width: usize,
    min: u32,
    max: u32,
    distinct: usize,
    /// Values that are at or above the declared bone count.
    out_of_range: usize,
    /// The eight most frequent values and their counts.
    histogram: Vec<(u32, usize)>,
}

/// Candidate readings of a wide index attribute.
#[derive(Serialize)]
struct WideIndexFacts {
    stride: usize,
    /// Per component width: number of lanes, maximum value and how many
    /// non-zero lanes are at or above the declared bone count.
    widths: Vec<WidthReading>,
}

#[derive(Serialize)]
struct WidthReading {
    width: usize,
    lanes: usize,
    max: u32,
    nonzero: usize,
    out_of_range: usize,
}

/// Decoded bounds of one position stream and their agreement with the box the
/// model declares for the geometry.
#[derive(Serialize)]
struct PositionFacts {
    slot: u32,
    prefix: String,
    min: [f32; 3],
    max: [f32; 3],
    /// Largest absolute difference from the declared box, when one exists.
    declared_delta: Option<f32>,
}

/// The array behind model `+0x28`, read as candidate bone-index palettes.
#[derive(Serialize)]
struct PaletteFacts {
    pointer: u64,
    target: u32,
    count: usize,
    /// First sixteen bytes, in hex, so the width is visible in the output.
    head: String,
    readings: Vec<PaletteReading>,
}

#[derive(Serialize)]
struct PaletteReading {
    width: usize,
    values: Vec<u32>,
    max: u32,
    distinct: usize,
    out_of_skeleton: usize,
    zeroes: usize,
}

#[derive(Serialize)]
struct GeometryFacts {
    locator: String,
    type_id: u8,
    name: Option<String>,
    lod: usize,
    model: usize,
    geometry: usize,
    bone_count: u16,
    skeleton_bones: usize,
    vertex_count: usize,
    word_14: u32,
    model_flags: u64,
    /// The `u64` at model `+0x28`, which the null-skeleton samples stored zero.
    model_word_28: Option<u64>,
    geometry_word_30: u64,
    declaration: Vec<Declaration>,
    layout: Vec<Attribute>,
    weights: Option<WeightFacts>,
    indices: Option<IndexFacts>,
    byte_index: Option<ByteIndexFacts>,
    wide_index: Option<WideIndexFacts>,
    positions: Vec<PositionFacts>,
    palette: Option<PaletteFacts>,
    /// Raw bytes of the index attribute for the first four vertices.
    index_head: Option<String>,
    /// Raw bytes of the weight attribute for the first four vertices.
    weight_head: Option<String>,
    class: String,
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..at + 8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
}

fn read_f32(bytes: &[u8], at: usize) -> Option<f32> {
    bytes
        .get(at..at + 4)
        .map(|bytes| f32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

/// The 23-slot declaration table at the graphics target of one vertex buffer.
///
/// A zero word marks an absent semantic, not the end of the table: a geometry
/// with no second UV stores zero at slot 4 and a real weight entry at slot 6.
fn declaration_table(blob: &[u8]) -> Vec<Declaration> {
    (0..23u32)
        .filter_map(|slot| {
            let word = read_u32(blob, slot as usize * 4)?;
            (word != 0).then(|| Declaration {
                slot,
                format: (word & 0xFF) as u8,
                offset: u64::from(word >> 8) * 2,
            })
        })
        .collect()
}

fn signature(declaration: &[Declaration], layout: &[Attribute]) -> String {
    let d = declaration
        .iter()
        .map(|entry| format!("{}:{:02x}", entry.slot, entry.format))
        .collect::<Vec<_>>()
        .join(",");
    let l = layout
        .iter()
        .map(|entry| format!("{}:{:02x}/{}", entry.slot, entry.format, entry.size))
        .collect::<Vec<_>>()
        .join(",");
    format!("decl[{d}] layout[{l}]")
}

fn byte_index(
    blob: &[u8],
    at: usize,
    count: usize,
    width: usize,
    bones: usize,
) -> Option<ByteIndexFacts> {
    let bytes = blob.get(at..at.checked_add(count.checked_mul(width)?)?)?;
    let value = |index: usize| -> u32 {
        match width {
            1 => u32::from(bytes[index]),
            2 => u32::from(u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]])),
            _ => u32::from_le_bytes([
                bytes[index * 4],
                bytes[index * 4 + 1],
                bytes[index * 4 + 2],
                bytes[index * 4 + 3],
            ]),
        }
    };
    let mut histogram: BTreeMap<u32, usize> = BTreeMap::new();
    let mut out_of_range = 0usize;
    let mut min = u32::MAX;
    let mut max = 0u32;
    for index in 0..count {
        let value = value(index);
        *histogram.entry(value).or_insert(0) += 1;
        if value as usize >= bones {
            out_of_range += 1;
        }
        min = min.min(value);
        max = max.max(value);
    }
    let mut histogram = histogram.into_iter().collect::<Vec<_>>();
    histogram.sort_by(|a, b| b.1.cmp(&a.1));
    histogram.truncate(8);
    Some(ByteIndexFacts {
        width,
        min,
        max,
        distinct: histogram.len(),
        out_of_range,
        histogram,
    })
}

fn wide_index(
    blob: &[u8],
    at: usize,
    count: usize,
    stride: usize,
    bones: usize,
) -> Option<WideIndexFacts> {
    let bytes = blob.get(at..at.checked_add(count.checked_mul(stride)?)?)?;
    let mut widths = Vec::new();
    for width in [1usize, 2, 4] {
        let lanes = stride / width;
        let mut max = 0u32;
        let mut nonzero = 0usize;
        let mut out_of_range = 0usize;
        for vertex in 0..count {
            let start = vertex * stride;
            for lane in 0..lanes {
                let at = start + lane * width;
                let value = match width {
                    1 => u32::from(bytes[at]),
                    2 => u32::from(u16::from_le_bytes([bytes[at], bytes[at + 1]])),
                    _ => {
                        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
                    }
                };
                if value != 0 {
                    nonzero += 1;
                    if usize::try_from(value).is_ok_and(|value| value >= bones) {
                        out_of_range += 1;
                    }
                }
                max = max.max(value);
            }
        }
        widths.push(WidthReading {
            width,
            lanes,
            max,
            nonzero,
            out_of_range,
        });
    }
    Some(WideIndexFacts { stride, widths })
}

/// Decodes one position stream with the quantiser the decoder uses and reports
/// its bounds against the geometry's declared box.
fn position_facts(
    blob: &[u8],
    entry: &Declaration,
    count: usize,
    declared: Option<&lforge_rage9::drawable::Aabb>,
) -> Option<PositionFacts> {
    if entry.format != 0x42 || count == 0 {
        return None;
    }
    let at = entry.offset as usize;
    let base = [
        read_f32(blob, 0x60)?,
        read_f32(blob, 0x64)?,
        read_f32(blob, 0x68)?,
    ];
    let step = [
        read_f32(blob, 0x70)?,
        read_f32(blob, 0x74)?,
        read_f32(blob, 0x78)?,
    ];
    let axis = read_u32(blob, 0x6C).unwrap_or(2);
    let mut min = [f32::INFINITY; 3];
    let mut max = [f32::NEG_INFINITY; 3];
    for vertex in 0..count {
        let q = read_u64(blob, at + vertex * 8)?;
        let x = ((((q >> 16) & 0xFFFF) << 8) | (q & 0xFF)) as f32 * step[0] + base[0];
        let y = ((((q >> 32) & 0xFFFF) << 8) | ((q >> 8) & 0xFF)) as f32 * step[1] + base[1];
        let z = (q >> 48) as f32 * step[2] + base[2];
        let position = match axis {
            2 => [x, y, z],
            1 => [y, z, x],
            0 => [z, y, x],
            _ => [x, y, z],
        };
        for axis in 0..3 {
            min[axis] = min[axis].min(position[axis]);
            max[axis] = max[axis].max(position[axis]);
        }
    }
    let declared_delta = declared.map(|declared| {
        let mut delta = 0f32;
        for axis in 0..3 {
            delta = delta.max((min[axis] - declared.min[axis]).abs());
            delta = delta.max((max[axis] - declared.max[axis]).abs());
        }
        delta
    });
    Some(PositionFacts {
        slot: entry.slot,
        prefix: format!("base {base:?} step {step:?} axis {axis}"),
        min,
        max,
        declared_delta,
    })
}

/// Reads the array the model `+0x28` slot points at and reports how it looks as
/// a bone-index palette at several component widths.
fn palette_facts(
    system: &[u8],
    pointer: u64,
    count: usize,
    skeleton_bones: usize,
) -> Option<PaletteFacts> {
    let kind = pointer >> 28;
    if kind != 5 {
        return None;
    }
    let target = (pointer & 0x0FFF_FFFF) as u32;
    let at = target as usize;
    let available = system.len().saturating_sub(at);
    let head_bytes = system.get(at..at + available.min(16))?;
    let width = if count.checked_mul(2)? <= available {
        2
    } else {
        1
    };
    let mut readings = Vec::new();
    for candidate in [width, if width == 2 { 1 } else { 2 }] {
        let Some(len) = count.checked_mul(candidate).filter(|len| *len <= available) else {
            continue;
        };
        let bytes = &system[at..at + len];
        let mut values = Vec::with_capacity(count);
        let mut distinct = std::collections::BTreeSet::new();
        let mut out_of_skeleton = 0usize;
        let mut zeroes = 0usize;
        for index in 0..count {
            let value = match candidate {
                1 => u32::from(bytes[index]),
                _ => u32::from(u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]])),
            };
            values.push(value);
            distinct.insert(value);
            if value as usize >= skeleton_bones.max(1) {
                out_of_skeleton += 1;
            }
            if value == 0 {
                zeroes += 1;
            }
        }
        readings.push(PaletteReading {
            width: candidate,
            values: values.iter().copied().take(24).collect(),
            max: values.iter().copied().max().unwrap_or(0),
            distinct: distinct.len(),
            out_of_skeleton,
            zeroes,
        });
    }
    Some(PaletteFacts {
        pointer,
        target,
        count,
        head: head_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(""),
        readings,
    })
}

/// Reads one geometry the way the survey needs it.
fn geometry_facts(
    system: &[u8],
    graphics: &[u8],
    model: &lforge_rage9::drawable::Model,
    model_index: usize,
    lod_index: usize,
    geometry_index: usize,
    name: Option<String>,
    type_id: u8,
    locator: String,
    skeleton_bones: usize,
) -> Option<GeometryFacts> {
    let geometry = model.geometries.get(geometry_index)?;
    if geometry.bone_count == 0 && skeleton_bones == 0 {
        return None;
    }
    let buffer = geometry.vertex_buffer.as_ref()?;
    let blob = graphics
        .get(buffer.graphics as usize..)
        .and_then(|tail| tail.get(..usize::try_from(buffer.declared_bytes).ok()?))?;
    let declaration = declaration_table(blob);
    let layout = buffer
        .attributes
        .iter()
        .map(|entry| Attribute {
            slot: entry.slot,
            offset: entry.offset,
            size: entry.size,
            format: entry.format,
        })
        .collect::<Vec<_>>();
    let count = buffer.vertex_count as usize;
    let weight_entry = declaration.iter().find(|entry| entry.slot == 6);
    let index_entry = declaration.iter().find(|entry| entry.slot == 8);
    let mut weights = None;
    let mut indices = None;
    let mut byte_index = None;
    let mut wide_index = None;
    let class;
    if let Some(weights_at) = weight_entry
        .filter(|entry| entry.format == 0x26)
        .map(|entry| entry.offset as usize)
        .filter(|at| count > 0 && at + count * 4 <= blob.len())
    {
        let mut sums: BTreeMap<u32, usize> = BTreeMap::new();
        let mut zero_vertices = 0usize;
        let mut max_total = 0u32;
        let mut min_total = u32::MAX;
        for vertex in 0..count {
            let at = weights_at + vertex * 4;
            let total = (0..4).map(|lane| u32::from(blob[at + lane])).sum();
            *sums.entry(total).or_insert(0) += 1;
            if total == 0 {
                zero_vertices += 1;
            }
            max_total = max_total.max(total);
            min_total = min_total.min(total);
        }
        weights = Some(WeightFacts {
            sums,
            zero_vertices,
            max_total,
            min_total,
        });
        if let Some(indexes_at) = index_entry
            .filter(|entry| entry.format == 0x25)
            .map(|entry| entry.offset as usize)
            .filter(|at| at + count * 4 <= blob.len())
        {
            let mut used = std::collections::BTreeSet::new();
            let mut active_lanes = 0usize;
            let mut max = 0u32;
            let mut min = u32::MAX;
            let mut inactive_nonzero = 0usize;
            let mut active_out_of_range = 0usize;
            let mut lane0_max = 0u32;
            let bones = usize::from(geometry.bone_count);
            for vertex in 0..count {
                let at = indexes_at + vertex * 4;
                let wat = weights_at + vertex * 4;
                lane0_max = lane0_max.max(u32::from(blob[at]));
                for lane in 0..4 {
                    let index = u32::from(blob[at + lane]);
                    if blob[wat + lane] == 0 {
                        if index != 0 {
                            inactive_nonzero += 1;
                        }
                        continue;
                    }
                    active_lanes += 1;
                    max = max.max(index);
                    min = min.min(index);
                    used.insert(index);
                    if index as usize >= bones {
                        active_out_of_range += 1;
                    }
                }
            }
            indices = Some(IndexFacts {
                active_lanes,
                max,
                min: if active_lanes == 0 { 0 } else { min },
                distinct: used.len(),
                contiguous_from_zero: active_lanes > 0 && used.len() == max as usize + 1,
                inactive_nonzero_lanes: inactive_nonzero,
                active_out_of_range,
                lane0_max,
            });
            class = if active_out_of_range > 0 {
                "index outside skeleton".to_string()
            } else {
                "validated".to_string()
            };
        } else if geometry.bone_count == 1 {
            class = "one bone, no index stream".to_string();
        } else {
            class = "no index stream".to_string();
        }
    } else if geometry.bone_count == 1 {
        class = "one bone, no weight form".to_string();
    } else {
        class = "no weight form".to_string();
    }

    // The forms the current decoder does not read, measured rather than named.
    if let Some(entry) = index_entry {
        let at = entry.offset as usize;
        let bones = usize::from(geometry.bone_count.max(1));
        let width = layout
            .iter()
            .find(|attribute| u64::from(attribute.offset) == entry.offset)
            .map_or(1, |attribute| usize::from(attribute.size).max(1));
        match entry.format {
            0x00 => {
                byte_index = byte_index_counted(blob, at, count, width, bones);
            }
            0x8c => {
                wide_index = wide_index_stride(blob, at, count, 16, bones);
            }
            0x4a => {
                wide_index = wide_index_stride(blob, at, count, 4, bones);
            }
            _ => {}
        }
    }
    let declared = model
        .bounds
        .as_ref()
        .and_then(|bounds| bounds.per_geometry.get(geometry_index));
    let positions = [0u32, 17]
        .into_iter()
        .filter_map(|slot| declaration.iter().find(|entry| entry.slot == slot))
        .filter_map(|entry| position_facts(blob, entry, count, declared))
        .collect();
    let index_head = index_entry.and_then(|entry| {
        let stride = layout
            .iter()
            .find(|attribute| u64::from(attribute.offset) == entry.offset)
            .map_or(4, |attribute| usize::from(attribute.size).max(1));
        let at = entry.offset as usize;
        let len = (count.min(4)) * stride;
        blob.get(at..at + len).map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("")
        })
    });
    let weight_head = weight_entry.and_then(|entry| {
        let at = entry.offset as usize;
        let len = count.min(4) * 4;
        blob.get(at..at + len).map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("")
        })
    });
    let model_word_28 = read_u64(system, model.at as usize + 0x28);
    let palette = model_word_28.and_then(|pointer| {
        (usize::from(geometry.bone_count) > 0)
            .then(|| {
                palette_facts(
                    system,
                    pointer,
                    usize::from(geometry.bone_count),
                    skeleton_bones,
                )
            })
            .flatten()
    });

    Some(GeometryFacts {
        locator,
        type_id,
        name,
        lod: lod_index,
        model: model_index,
        geometry: geometry_index,
        bone_count: geometry.bone_count,
        skeleton_bones,
        vertex_count: count,
        word_14: model.word_14,
        model_flags: model.flags,
        model_word_28,
        geometry_word_30: geometry.word_30,
        declaration,
        layout,
        weights,
        indices,
        byte_index,
        wide_index,
        positions,
        palette,
        index_head,
        weight_head,
        class,
    })
}

fn byte_index_counted(
    blob: &[u8],
    at: usize,
    count: usize,
    width: usize,
    bones: usize,
) -> Option<ByteIndexFacts> {
    byte_index(blob, at, count, width, bones)
}

fn wide_index_stride(
    blob: &[u8],
    at: usize,
    count: usize,
    stride: usize,
    bones: usize,
) -> Option<WideIndexFacts> {
    wide_index(blob, at, count, stride, bones)
}

#[derive(Default)]
struct Totals {
    geometries: usize,
    validated: usize,
    unread: usize,
    groups: BTreeMap<String, (usize, String)>,
}
fn survey_drawable(
    row: &super::tests::SurveyRow,
    type_id: u8,
    out: Option<&str>,
    lines: &mut Vec<String>,
    totals: &mut Totals,
) {
    let (system, graphics) = row.segments();
    let report = if type_id == 2 {
        lforge_rage9::drawable::inspect_at(system, graphics, 0)
    } else {
        let Ok(header) = lforge_rage9::fragment::header(system) else {
            return;
        };
        lforge_rage9::drawable::inspect_member_at(system, graphics, header.drawable as usize)
    };
    let Some(report) = report else {
        return;
    };
    let skeleton_bones = report
        .header
        .skeleton
        .map(|at| lforge_rage9::skeleton::inspect(system, at).bones.len())
        .unwrap_or(0);
    let name = report.header.name_text.clone();
    let Some(lod_index) = report.lod.iter().position(|slot| !slot.models.is_empty()) else {
        return;
    };
    let lod = &report.lod[lod_index];
    for (model_index, model) in lod.models.iter().enumerate() {
        for geometry_index in 0..model.geometries.len() {
            let locator = row.path.display().to_string();
            let Some(facts) = geometry_facts(
                system,
                graphics,
                model,
                model_index,
                lod_index,
                geometry_index,
                name.clone(),
                type_id,
                locator,
                skeleton_bones,
            ) else {
                continue;
            };
            totals.geometries += 1;
            if matches!(
                facts.class.as_str(),
                "validated" | "one bone, no index stream"
            ) {
                totals.validated += 1;
            } else {
                totals.unread += 1;
            }
            let key = format!(
                "{}|{}",
                facts.class,
                signature(&facts.declaration, &facts.layout)
            );
            let sample = format!(
                "{}: lod {} model {} geometry {}",
                facts.locator, facts.lod, facts.model, facts.geometry
            );
            let entry = totals.groups.entry(key).or_insert((0, sample));
            entry.0 += 1;
            if out.is_some()
                && let Ok(json) = serde_json::to_string(&facts)
            {
                lines.push(json);
            }
        }
    }
}

#[test]
#[ignore = "requires LF_TEST_ARCHIVE_LIST (or LF_TEST_ARCHIVE_DIR) and LF_TEST_EXECUTABLE"]
fn surveys_vertex_declarations() {
    let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
    let access = Access::with(Arc::new(
        Executable::open(Path::new(&executable)).expect("executable"),
    ));
    let cancel = AtomicBool::new(false);
    let archives = super::tests::survey_archives();
    let out = std::env::var("LF_SURVEY_OUT").ok();
    let mut lines: Vec<String> = Vec::new();
    let mut totals = Totals::default();
    for type_id in [2u8, 3u8] {
        super::tests::survey_rows(&archives, &access, &cancel, type_id, |row| {
            survey_drawable(row, type_id, out.as_deref(), &mut lines, &mut totals);
        });
    }
    if let Some(path) = out {
        std::fs::write(path, lines.join("\n")).expect("write survey output");
    }
    eprintln!(
        "geometry records: {}, validated {}, unread {}",
        totals.geometries, totals.validated, totals.unread
    );
    eprintln!("groups: {}", totals.groups.len());
    let mut groups = totals.groups.iter().collect::<Vec<_>>();
    groups.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    for (key, (count, sample)) in groups {
        eprintln!("{count:6} x {key}\n         e.g. {sample}");
    }
    assert!(totals.geometries > 0, "no geometry record was surveyed");
}

/// Dumps the same facts for the native chains the caller names.
///
/// `LF_TEST_CHAIN_LIST` names a file of census chains, `LF_TEST_GAME_ROOT` the
/// installation and `LF_TEST_EXECUTABLE` the executable that supplies the keys.
/// The output goes to `LF_SURVEY_OUT`, one JSON line per geometry.
#[test]
#[ignore = "requires LF_TEST_CHAIN_LIST, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
fn dumps_chain_geometry_facts() {
    let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
    let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
    let list = std::env::var("LF_TEST_CHAIN_LIST").expect("LF_TEST_CHAIN_LIST");
    let access = Access::with(Arc::new(
        Executable::open(Path::new(&executable)).expect("executable"),
    ));
    let out = std::env::var("LF_SURVEY_OUT").expect("LF_SURVEY_OUT");
    let mut resolved = std::collections::BTreeMap::new();
    let mut index = std::collections::HashMap::new();
    let mut lines: Vec<String> = Vec::new();
    let mut totals = Totals::default();
    let text = std::fs::read_to_string(&list).expect("chain list");
    for chain in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((parent_chain, row)) = chain.rsplit_once('!') else {
            continue;
        };
        let Ok(row) = row.parse::<usize>() else {
            continue;
        };
        let Some(parent) = super::tests::resolve_chain(
            Path::new(&root),
            &access,
            parent_chain,
            &mut resolved,
            &mut index,
        ) else {
            eprintln!("unresolved: {chain}");
            continue;
        };
        let rows = index
            .entry(parent.clone())
            .or_insert_with(|| super::tests::row_index(&parent, &access));
        let Some(entry) = rows.get(&row).cloned() else {
            eprintln!("row missing: {chain}");
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
        let system_len = crate::files::resource_split_with(&entry, &access, &source)
            .ok()
            .flatten()
            .and_then(|split| usize::try_from(split.system_len).ok())
            .or_else(|| decoded::split_resource(&bytes).map(|split| split.system_len));
        let Some(system_len) = system_len.filter(|len| *len <= bytes.len()) else {
            continue;
        };
        let row_facts = super::tests::SurveyRow {
            path: entry.clone(),
            bytes,
            system_len,
            native: true,
        };
        let type_id = if lforge_rage9::fragment::header(row_facts.segments().0).is_ok() {
            3
        } else {
            2
        };
        let before = totals.geometries;
        survey_drawable(&row_facts, type_id, Some(&out), &mut lines, &mut totals);
        eprintln!(
            "{chain} -> {} geometry record(s)",
            totals.geometries - before
        );
    }
    std::fs::write(&out, lines.join("\n")).expect("write survey output");
    eprintln!(
        "geometry records: {}, validated {}, unread {}",
        totals.geometries, totals.validated, totals.unread
    );
    for (key, (count, sample)) in &totals.groups {
        eprintln!("{count:6} x {key}\n         e.g. {sample}");
    }
}

/// Decodes a geometry's authored positions from the declaration table.
fn decode_positions(
    blob: &[u8],
    declaration: &[Declaration],
    count: usize,
) -> Option<Vec<glam::Vec3>> {
    let marker = read_u32(blob, 0)?;
    let position = declaration.iter().find(|entry| entry.slot == 0)?;
    let at = position.offset as usize;
    let mut positions = Vec::with_capacity(count);
    if marker == 0x3063 {
        for vertex in 0..count {
            let base = at + vertex * 12;
            positions.push(glam::Vec3::new(
                read_f32(blob, base)?,
                read_f32(blob, base + 4)?,
                read_f32(blob, base + 8)?,
            ));
        }
        return Some(positions);
    }
    let base = [
        read_f32(blob, 0x60)?,
        read_f32(blob, 0x64)?,
        read_f32(blob, 0x68)?,
    ];
    let step = [
        read_f32(blob, 0x70)?,
        read_f32(blob, 0x74)?,
        read_f32(blob, 0x78)?,
    ];
    let axis = read_u32(blob, 0x6C).unwrap_or(2);
    for vertex in 0..count {
        let q = read_u64(blob, at + vertex * 8)?;
        let x = ((((q >> 16) & 0xFFFF) << 8) | (q & 0xFF)) as f32 * step[0] + base[0];
        let y = ((((q >> 32) & 0xFFFF) << 8) | ((q >> 8) & 0xFF)) as f32 * step[1] + base[1];
        let z = (q >> 48) as f32 * step[2] + base[2];
        positions.push(match axis {
            2 => glam::Vec3::new(x, y, z),
            1 => glam::Vec3::new(y, z, x),
            0 => glam::Vec3::new(z, y, x),
            _ => glam::Vec3::new(x, y, z),
        });
    }
    Some(positions)
}

/// Composes the stored local transforms into model-space bone positions.
fn bone_positions(system: &[u8], report: &lforge_rage9::drawable::Report) -> Vec<glam::Vec3> {
    let Some(at) = report.header.skeleton else {
        return Vec::new();
    };
    let skeleton = lforge_rage9::skeleton::inspect(system, at);
    let mut rotations: Vec<glam::Quat> = Vec::with_capacity(skeleton.bones.len());
    let mut positions: Vec<glam::Vec3> = Vec::with_capacity(skeleton.bones.len());
    for bone in &skeleton.bones {
        let rotation = glam::Quat::from_xyzw(
            bone.rotation[0],
            bone.rotation[1],
            bone.rotation[2],
            bone.rotation[3],
        );
        let translation = glam::Vec3::from_array(bone.translation);
        let (rotation, position) = match bone.parent {
            Some(parent) if parent < rotations.len() => (
                rotations[parent] * rotation,
                positions[parent] + rotations[parent] * translation,
            ),
            _ => (rotation, translation),
        };
        rotations.push(rotation);
        positions.push(position);
    }
    positions
}

/// One (stored index -> nearest bone) observation.
#[derive(Serialize)]
struct ProximityRow {
    locator: String,
    name: Option<String>,
    geometry: usize,
    /// `four-lane` or `one-byte`.
    form: &'static str,
    index: u32,
    nearest: usize,
    distance: f32,
    /// Rank of the stored bone among the bones sorted by distance, 0 = nearest.
    rank: usize,
    stored_distance: f32,
    weight: f32,
}

/// Checks whether a stored blend index names the skeleton bone nearest the
/// vertices that use it.
///
/// A palette that permuted the index space would place the influenced vertices
/// near a different bone than the one the stored index names, so comparing the
/// weighted centroid of each index group with the composed bind-pose bone
/// positions is independent of the declaration table.
#[test]
#[ignore = "requires LF_TEST_CHAIN_LIST, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
fn verifies_index_bone_proximity() {
    let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
    let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
    let list = std::env::var("LF_TEST_CHAIN_LIST").expect("LF_TEST_CHAIN_LIST");
    let access = Access::with(Arc::new(
        Executable::open(Path::new(&executable)).expect("executable"),
    ));
    let out = std::env::var("LF_SURVEY_OUT").ok();
    let mut resolved = std::collections::BTreeMap::new();
    let mut index = std::collections::HashMap::new();
    let mut rows: Vec<ProximityRow> = Vec::new();
    let mut compared = 0usize;
    let mut identity = 0usize;
    let mut permuted = 0usize;
    let text = std::fs::read_to_string(&list).expect("chain list");
    for chain in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((parent_chain, row)) = chain.rsplit_once('!') else {
            continue;
        };
        let Ok(row) = row.parse::<usize>() else {
            continue;
        };
        let Some(parent) = super::tests::resolve_chain(
            Path::new(&root),
            &access,
            parent_chain,
            &mut resolved,
            &mut index,
        ) else {
            continue;
        };
        let rows_index = index
            .entry(parent.clone())
            .or_insert_with(|| super::tests::row_index(&parent, &access));
        let Some(entry) = rows_index.get(&row).cloned() else {
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
        let system_len = crate::files::resource_split_with(&entry, &access, &source)
            .ok()
            .flatten()
            .and_then(|split| usize::try_from(split.system_len).ok())
            .or_else(|| decoded::split_resource(&bytes).map(|split| split.system_len));
        let Some(system_len) = system_len.filter(|len| *len <= bytes.len()) else {
            continue;
        };
        let (system, graphics) = bytes.split_at(system_len);
        let report = if lforge_rage9::fragment::header(system).is_ok() {
            lforge_rage9::fragment::header(system)
                .ok()
                .and_then(|header| {
                    lforge_rage9::drawable::inspect_member_at(
                        system,
                        graphics,
                        header.drawable as usize,
                    )
                })
        } else {
            lforge_rage9::drawable::inspect_at(system, graphics, 0)
        };
        let Some(report) = report else {
            continue;
        };
        let bones = bone_positions(system, &report);
        if bones.is_empty() {
            continue;
        }
        let name = report.header.name_text.clone();
        let Some(lod_index) = report.lod.iter().position(|slot| !slot.models.is_empty()) else {
            continue;
        };
        for model in &report.lod[lod_index].models {
            for (geometry_index, geometry) in model.geometries.iter().enumerate() {
                let Some(buffer) = geometry.vertex_buffer.as_ref() else {
                    continue;
                };
                let Some(blob) = graphics
                    .get(buffer.graphics as usize..)
                    .and_then(|tail| tail.get(..usize::try_from(buffer.declared_bytes).ok()?))
                else {
                    continue;
                };
                let declaration = declaration_table(blob);
                let count = buffer.vertex_count as usize;
                let Some(positions) = decode_positions(blob, &declaration, count) else {
                    continue;
                };
                let weight_entry = declaration.iter().find(|entry| entry.slot == 6);
                let index_entry = declaration.iter().find(|entry| entry.slot == 8);
                if let (Some(weights_at), Some(indexes_at)) = (
                    weight_entry
                        .filter(|entry| entry.format == 0x26)
                        .map(|entry| entry.offset as usize),
                    index_entry
                        .filter(|entry| entry.format == 0x25)
                        .map(|entry| entry.offset as usize),
                ) {
                    if weights_at + count * 4 > blob.len() || indexes_at + count * 4 > blob.len() {
                        continue;
                    }
                    let mut sums: std::collections::BTreeMap<u32, (glam::Vec3, f32)> =
                        std::collections::BTreeMap::new();
                    for vertex in 0..count {
                        for lane in 0..4 {
                            let weight = f32::from(blob[weights_at + vertex * 4 + lane]);
                            if weight == 0.0 {
                                continue;
                            }
                            let stored = u32::from(blob[indexes_at + vertex * 4 + lane]);
                            let entry = sums.entry(stored).or_insert((glam::Vec3::ZERO, 0.0));
                            entry.0 += positions[vertex] * weight;
                            entry.1 += weight;
                        }
                    }
                    for (stored, (sum, weight)) in sums {
                        let centroid = sum / weight;
                        let (nearest, distance) = nearest_vertex(&bones, centroid);
                        let stored_distance = bones
                            .get(stored as usize)
                            .map_or(f32::INFINITY, |bone| (*bone - centroid).length());
                        let rank = bones
                            .iter()
                            .filter(|bone| (**bone - centroid).length() < stored_distance)
                            .count();
                        rows.push(ProximityRow {
                            locator: entry.display().to_string(),
                            name: name.clone(),
                            geometry: geometry_index,
                            form: "four-lane",
                            index: stored,
                            nearest,
                            distance,
                            rank,
                            stored_distance,
                            weight,
                        });
                        compared += 1;
                        if nearest == stored as usize {
                            identity += 1;
                        } else {
                            permuted += 1;
                        }
                    }
                } else if let Some(indexes_at) = index_entry
                    .filter(|entry| entry.format == 0x00)
                    .map(|entry| entry.offset as usize)
                {
                    let width = buffer
                        .attributes
                        .iter()
                        .find(|attribute| indexes_at == attribute.offset as usize)
                        .map_or(1, |attribute| usize::from(attribute.size).max(1));
                    if indexes_at + count * width > blob.len() {
                        continue;
                    }
                    let mut sums: std::collections::BTreeMap<u32, (glam::Vec3, f32)> =
                        std::collections::BTreeMap::new();
                    for vertex in 0..count {
                        let at = indexes_at + vertex * width;
                        let stored = match width {
                            1 => u32::from(blob[at]),
                            2 => u32::from(u16::from_le_bytes([blob[at], blob[at + 1]])),
                            _ => u32::from_le_bytes([
                                blob[at],
                                blob[at + 1],
                                blob[at + 2],
                                blob[at + 3],
                            ]),
                        };
                        let entry = sums.entry(stored).or_insert((glam::Vec3::ZERO, 0.0));
                        entry.0 += positions[vertex];
                        entry.1 += 1.0;
                    }
                    for (stored, (sum, weight)) in sums {
                        let centroid = sum / weight;
                        let (nearest, distance) = nearest_vertex(&bones, centroid);
                        let stored_distance = bones
                            .get(stored as usize)
                            .map_or(f32::INFINITY, |bone| (*bone - centroid).length());
                        let rank = bones
                            .iter()
                            .filter(|bone| (**bone - centroid).length() < stored_distance)
                            .count();
                        rows.push(ProximityRow {
                            locator: entry.display().to_string(),
                            name: name.clone(),
                            geometry: geometry_index,
                            form: "one-byte",
                            index: stored,
                            nearest,
                            distance,
                            rank,
                            stored_distance,
                            weight,
                        });
                        compared += 1;
                        if nearest == stored as usize {
                            identity += 1;
                        } else {
                            permuted += 1;
                        }
                    }
                }
            }
        }
    }
    if let Some(path) = out {
        let text = rows
            .iter()
            .filter_map(|row| serde_json::to_string(row).ok())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, text).expect("write proximity output");
    }
    let mut by_form: BTreeMap<&'static str, [usize; 4]> = BTreeMap::new();
    for row in &rows {
        let entry = by_form.entry(row.form).or_insert([0; 4]);
        entry[0] += 1;
        if row.rank == 0 {
            entry[1] += 1;
        }
        if row.rank <= 1 {
            entry[2] += 1;
        }
        if row.rank <= 2 {
            entry[3] += 1;
        }
    }
    eprintln!("index groups compared: {compared}");
    eprintln!("nearest bone equals the stored index: {identity}, differs: {permuted}");
    for (form, counts) in by_form {
        eprintln!(
            "  {form}: {} groups; stored bone rank 0: {}, <=1: {}, <=2: {}",
            counts[0], counts[1], counts[2], counts[3]
        );
    }
    let mut mismatched: Vec<&ProximityRow> = rows
        .iter()
        .filter(|row| row.nearest != row.index as usize)
        .collect();
    mismatched.sort_by(|a, b| b.weight.total_cmp(&a.weight));
    for row in mismatched.iter().take(12) {
        eprintln!(
            "  differs: {} geometry {} {} stored {} nearest {} distance {:.4} weight {}",
            row.name.as_deref().unwrap_or("?"),
            row.geometry,
            row.form,
            row.index,
            row.nearest,
            row.distance,
            row.weight
        );
    }
    assert!(compared > 0, "no influence group was compared");
}

fn nearest_vertex(bones: &[glam::Vec3], point: glam::Vec3) -> (usize, f32) {
    let mut best = 0usize;
    let mut distance = f32::INFINITY;
    for (index, bone) in bones.iter().enumerate() {
        let delta = (*bone - point).length();
        if delta < distance {
            distance = delta;
            best = index;
        }
    }
    (best, distance)
}
