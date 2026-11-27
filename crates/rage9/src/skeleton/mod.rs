//! The skeleton record behind a drawable header's `+0x18` pointer.
//!
//! The layout below was read on four fragment member drawables from two
//! archives (SKEL-F01 to SKEL-F10) and checked against 5,628 skeletons of a
//! 27-archive census (SKEL-F11 to SKEL-F15). It is a structure walk: every count
//! is bounded by its segment, every pointer must decode as a system pointer, and
//! a field whose meaning the evidence does not establish keeps a neutral name.
//!
//! Observed skeleton header, system-relative:
//!
//! | Offset | Size | Observation                                              |
//! | -----: | ---: | -------------------------------------------------------- |
//! | `+0x00` |  8 | Zero in every sample                                      |
//! | `+0x08` |  8 | Zero in every sample                                      |
//! | `+0x10` |  8 | The constant `1` in every sample                          |
//! | `+0x18` |  4 | The constant `0x20` in every sample                       |
//! | `+0x1C` |  4 | Key count: twice the bone count on 5,604 of 5,628         |
//! | `+0x20` |  8 | Pointer to a key map, `(u32 key, u32 bone index)` pairs    |
//! | `+0x28` |  8 | Pointer to the bone records                               |
//! | `+0x30` |  8 | Pointer to the inverse-bind records                        |
//! | `+0x38` |  8 | Pointer to the local-matrix records                        |
//! | `+0x40` |  8 | Pointer to a record whose leading `u16`s are the parents   |
//! | `+0x48` |  8 | Pointer to the bone name strings                           |
//!
//! One bone record is 0x50 bytes: a quaternion at `+0x00`, a translation at
//! `+0x10`, a per-bone 32-bit identifier at `+0x1C`, a scale at `+0x20`, a name
//! pointer at `+0x30`, four `u16` at `+0x40` (the fourth is the parent, 0xFFFF
//! for a root) and four `u16` at `+0x48` (the first is the bone's own index and
//! the second a 16-bit identifier). Neither `+0x1C` nor the fourth `u16` at
//! `+0x4E` is the bone count: the array is walked until the index sequence
//! breaks, because limiting it by either value truncated skeletons whose helper
//! bones sit past them.
//!
//! One matrix record is 0x40 bytes: a 3x3 rotation in row-major order, an
//! unused fourth column, then a translation and one more value. The `+0x38`
//! array stores the transpose of the local rotation and the local translation;
//! the `+0x30` array stores the model-space rotation and the negated rotated
//! model-space translation, which is the rotation-and-translation half of an
//! inverse bind matrix. Both are checked against the composed hierarchy in the
//! tests and in the research probe, so the quaternion convention and the
//! parent composition order are not assumed.
//!
//! A skeleton may have several root bones: 548 of the surveyed 5,628 do, because
//! helper bones such as `OH_TorsoDirection_01` head their own short chains. The
//! walk therefore returns every root and never treats a second root as a fault.

#[cfg(test)]
mod tests;

use std::fmt;

use crate::resource::Pointer;

/// Bytes of the skeleton header this module reads.
pub const HEADER_LEN: usize = 0x50;
/// Bytes of one bone record.
pub const BONE_LEN: usize = 0x50;
/// Bytes of one matrix record.
pub const MATRIX_LEN: usize = 0x40;
/// Largest bone count accepted.
pub const MAX_BONES: usize = 4096;
/// The parent value that marks a root in the bone record.
pub const ROOT_PARENT: u16 = 0xFFFF;
/// Longest bone name accepted, including its terminator.
const MAX_NAME: usize = 256;

/// A structural problem with the skeleton record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// A pointer that cannot be decoded to a system-segment offset.
    Pointer {
        field: &'static str,
        at: usize,
        value: u64,
    },
    /// A record that would end outside the system segment.
    Bounds {
        field: &'static str,
        at: usize,
        len: u64,
        size: u64,
    },
    /// A count larger than the segment can hold, clamped to what fits.
    Clamped {
        field: &'static str,
        declared: u64,
        used: u64,
    },
    /// The `+0x40` record's parent does not repeat the bone record's parent.
    ParentArrayMismatch {
        bone: usize,
        recorded: u16,
        array: u16,
    },
    /// A parent index outside the bone array.
    InvalidParent { bone: usize, parent: u16 },
    /// A bone that names itself as its parent.
    SelfParent { bone: usize },
    /// A parent chain that revisits a bone.
    Cycle { bone: usize },
    /// A transformation value that is not finite.
    NonFinite {
        bone: usize,
        field: &'static str,
        at: usize,
    },
    /// A record the walk needs but cannot reach.
    Missing { field: &'static str },
    /// The walk ran past the start of the next array.
    ///
    /// A neighbouring array starts at a known address, so the bone records
    /// cannot extend to it. The walk lost its footing in data that happened to
    /// carry the next index; the records past the boundary are dropped.
    BoneArrayOverrun {
        walked: u64,
        kept: u64,
        field: &'static str,
        at: u64,
    },
    /// Two arrays of one skeleton share bytes, which makes both suspect.
    ArrayOverlap {
        first: &'static str,
        at: u64,
        second: &'static str,
        second_at: u64,
    },
    /// The bone records continue past the accepted maximum.
    BeyondLimit { field: &'static str, limit: usize },
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Issue::Pointer { field, at, value } => write!(
                f,
                "{field} at skeleton-relative +{at:#x} holds {value:#018X}, which is not a system pointer"
            ),
            Issue::Bounds {
                field,
                at,
                len,
                size,
            } => write!(
                f,
                "{field} needs {len} bytes at system +{at:#x}, past the {size}-byte segment"
            ),
            Issue::Clamped {
                field,
                declared,
                used,
            } => write!(
                f,
                "{field} declares {declared} entries; only {used} fit in the segment"
            ),
            Issue::ParentArrayMismatch {
                bone,
                recorded,
                array,
            } => write!(
                f,
                "bone {bone} stores parent {recorded}, but the parent array stores {array}"
            ),
            Issue::InvalidParent { bone, parent } => {
                write!(
                    f,
                    "bone {bone} names parent {parent}, outside the bone array"
                )
            }
            Issue::SelfParent { bone } => write!(f, "bone {bone} names itself as its parent"),
            Issue::Cycle { bone } => {
                write!(f, "bone {bone} is part of a parent cycle")
            }
            Issue::NonFinite { bone, field, at } => write!(
                f,
                "bone {bone} stores a non-finite {field} at skeleton-relative +{at:#x}"
            ),
            Issue::Missing { field } => write!(f, "{field} is not reachable"),
            Issue::BoneArrayOverrun {
                walked,
                kept,
                field,
                at,
            } => write!(
                f,
                "the bone records were walked to {walked}, but the {field} at system +{at:#x} starts inside them; {kept} records are kept"
            ),
            Issue::ArrayOverlap {
                first,
                at,
                second,
                second_at,
            } => write!(
                f,
                "the {first} at system +{at:#x} and the {second} at +{second_at:#x} share bytes"
            ),
            Issue::BeyondLimit { field, limit } => write!(
                f,
                "the {field} continue past the accepted maximum of {limit}"
            ),
        }
    }
}

/// One bone as the record stores it.
#[derive(Debug, Clone, PartialEq)]
pub struct Bone {
    pub index: usize,
    /// The validated parent, the root sentinel aside. `None` for a root and
    /// for a parent that does not resolve.
    pub parent: Option<usize>,
    /// The parent as stored.
    pub raw_parent: u16,
    pub name: Option<String>,
    /// System offset of the stored name, for provenance.
    pub name_offset: Option<u32>,
    /// Local rotation as `x, y, z, w`.
    pub rotation: [f32; 4],
    pub translation: [f32; 3],
    pub scale: [f32; 3],
    /// The per-bone 32-bit value at `+0x1C`. The samples use it as a lookup key
    /// in the skeleton's own key map; its hash function is not established.
    pub identifier: u32,
    /// The per-bone 16-bit value at `+0x4A`, also a key in that map.
    pub identifier16: u16,
    /// The four `u16` at `+0x40`, as stored.
    pub flags: [u16; 4],
}

/// One matrix record: a 3x3 rotation in row-major order and a translation.
///
/// The inverse-bind array stores the model-space rotation with the negated
/// rotated model-space translation. This is the rotation and translation of
/// an inverse bind matrix in transposed storage; the renderer-facing scene
/// layer assembles the full matrix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Matrix34 {
    pub rotation: [f32; 9],
    pub translation: [f32; 3],
    /// The fourth value of the record's trailing group. Its meaning is not
    /// established; it is reported so a later investigation can use it.
    pub unknown: f32,
}

impl Matrix34 {
    /// Whether every stored value is finite.
    pub fn finite(&self) -> bool {
        self.rotation.iter().all(|value| value.is_finite())
            && self.translation.iter().all(|value| value.is_finite())
            && self.unknown.is_finite()
    }
}

/// The nearest array that follows the bone array, which bounds its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoneArrayBound {
    /// The field whose array starts there.
    pub field: &'static str,
    /// System offset of that array.
    pub at: u32,
    /// Whether the bone records end exactly at that offset, which corroborates
    /// the walked count rather than only bounding it.
    pub exact: bool,
}

/// Where a skeleton record's arrays live, in system offsets.
///
/// The offsets are kept so a caller can bound one array by its neighbours, and
/// so a diagnostic can name the address a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Arrays {
    pub keys: Option<u32>,
    pub bones: Option<u32>,
    pub inverse_bind: Option<u32>,
    pub local_matrices: Option<u32>,
    pub parents: Option<u32>,
    pub names: Option<u32>,
}

/// What the walk established.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// System offset of the skeleton record.
    pub at: u32,
    /// The header word at `+0x1C`, recorded but not used as a count. It is
    /// twice the bone count on 5,604 of 5,628 surveyed skeletons and short by 1
    /// or 2 on the rest, so it tracks the key map rather than the array.
    pub recorded_keys: u32,
    /// The resolved array offsets, for provenance and span checks.
    pub arrays: Arrays,
    /// The array that follows the bone array, when one does.
    pub bone_bound: Option<BoneArrayBound>,
    pub bones: Vec<Bone>,
    /// Bones without a parent, in index order.
    pub roots: Vec<usize>,
    /// Number of bones on the longest parent chain.
    pub max_depth: usize,
    /// One inverse-bind record per bone, when the array resolves. Stored in
    /// transposed form, as described on [`Matrix34`].
    pub inverse_bind: Vec<Matrix34>,
    /// One local-matrix record per bone, when the array resolves. This array
    /// is a second statement of the local transforms, independent of the bone
    /// records' quaternions.
    pub local_matrices: Vec<Matrix34>,
    /// The leading `u16`s of the `+0x40` record, when it resolves. They repeat
    /// the bone records' parent indices in every sample and are kept as a
    /// second, independent statement of the hierarchy.
    pub parent_array: Option<Vec<u16>>,
    /// The name string table offset, for provenance.
    pub names_at: Option<u32>,
    pub issues: Vec<Issue>,
    /// `complete` only when no issue was produced.
    pub status: &'static str,
}

impl Report {
    pub fn bone_count(&self) -> usize {
        self.bones.len()
    }

    pub fn complete(&self) -> bool {
        self.status == "complete"
    }

    /// The bones whose names the record carries.
    pub fn named_count(&self) -> usize {
        self.bones.iter().filter(|bone| bone.name.is_some()).count()
    }
}

/// The nearest array that starts above the bone array.
///
/// Only fixed-length arrays count: the name table is a string blob whose end is
/// not stored, so it can neither bound nor corroborate the bone count.
fn nearest_array_after(bone_base: u64, arrays: &Arrays) -> Option<(&'static str, u32)> {
    [
        ("key map", arrays.keys),
        ("inverse-bind array", arrays.inverse_bind),
        ("local-matrix array", arrays.local_matrices),
        ("parent array", arrays.parents),
    ]
    .into_iter()
    .filter_map(|(field, at)| at.map(|at| (field, at)))
    .filter(|(_, at)| u64::from(*at) > bone_base)
    .min_by_key(|(_, at)| *at)
}

/// The largest bone count the array layout allows.
///
/// Every array whose length is the bone count occupies `count * stride` bytes,
/// so an array that starts later bounds an earlier one. Two arrays only have to
/// tile: the walk can continue into whatever follows the bone allocation, and
/// data there can carry the next record index by chance. The smallest limit any
/// pair implies is the one the layout permits, and the field pair that produced
/// it is returned so a diagnostic can name it.
fn implied_bone_ceiling(arrays: &Arrays) -> Option<(&'static str, u32, u64)> {
    let sized: Vec<(&'static str, u64, u64)> = [
        ("bone array", arrays.bones, BONE_LEN as u64),
        ("inverse-bind array", arrays.inverse_bind, MATRIX_LEN as u64),
        (
            "local-matrix array",
            arrays.local_matrices,
            MATRIX_LEN as u64,
        ),
        ("parent array", arrays.parents, 2u64),
    ]
    .into_iter()
    .filter_map(|(field, at, stride)| at.map(|at| (field, u64::from(at), stride)))
    .collect();
    let mut best: Option<(&'static str, u32, u64)> = None;
    for earlier in &sized {
        for later in &sized {
            if later.1 <= earlier.1 {
                continue;
            }
            let allowed = (later.1 - earlier.1) / earlier.2;
            if best.is_none_or(|(_, _, current)| allowed < current) {
                best = Some((earlier.0, later.1 as u32, allowed));
            }
        }
    }
    best
}

/// Reports arrays that share bytes. Identical pointers are a shared array, not
/// an overlap, and are left alone.
fn check_array_overlap(report: &Report, bone_count: usize, issues: &mut Vec<Issue>) {
    let arrays = &report.arrays;
    let span = |field: (&'static str, Option<u32>), len: u64| {
        field
            .1
            .map(|at| (field.0, u64::from(at), u64::from(at) + len))
    };
    let spans: Vec<(&'static str, u64, u64)> = [
        span(
            ("bone array", arrays.bones),
            bone_count as u64 * BONE_LEN as u64,
        ),
        span(
            ("inverse-bind array", arrays.inverse_bind),
            bone_count as u64 * MATRIX_LEN as u64,
        ),
        span(
            ("local-matrix array", arrays.local_matrices),
            bone_count as u64 * MATRIX_LEN as u64,
        ),
        span(("parent array", arrays.parents), bone_count as u64 * 2),
        span(
            ("key map", arrays.keys),
            u64::from(report.recorded_keys) * 8,
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    for (index, first) in spans.iter().enumerate() {
        for second in spans.iter().skip(index + 1) {
            if first.1 != second.1 && first.1 < second.2 && second.1 < first.2 {
                issues.push(Issue::ArrayOverlap {
                    first: first.0,
                    at: first.1,
                    second: second.0,
                    second_at: second.1,
                });
            }
        }
    }
}

/// Reads the skeleton record at `at` in the system segment.
///
/// `Ok` carries everything that could be read. A malformed parent reference,
/// a cycle or a non-finite value is an issue and a `partial` status, never a
/// silent repair: the bone keeps its stored values and the caller reports the
/// incomplete pose.
pub fn inspect(system: &[u8], at: u32) -> Report {
    let base = u64::from(at);
    let mut issues = Vec::new();
    let mut report = Report {
        at,
        recorded_keys: 0,
        arrays: Arrays::default(),
        bone_bound: None,
        bones: Vec::new(),
        roots: Vec::new(),
        max_depth: 0,
        inverse_bind: Vec::new(),
        local_matrices: Vec::new(),
        parent_array: None,
        names_at: None,
        issues: Vec::new(),
        status: "partial",
    };
    if base
        .checked_add(HEADER_LEN as u64)
        .is_none_or(|end| end > system.len() as u64)
    {
        issues.push(Issue::Missing {
            field: "the skeleton header",
        });
        report.issues = issues;
        return report;
    }
    report.recorded_keys = u32_at(system, base as usize + 0x1C).unwrap_or(0);

    let bone_base = match pointer_at(system, base as usize + 0x28, "bone array", &mut issues) {
        Some(offset) => u64::from(offset),
        None => {
            report.issues = issues;
            return report;
        }
    };
    report.names_at = optional_pointer_at(system, base as usize + 0x48, "bone names", &mut issues);
    report.arrays = Arrays {
        keys: optional_pointer_at(system, base as usize + 0x20, "key map", &mut issues),
        bones: Some(bone_base as u32),
        inverse_bind: optional_pointer_at(
            system,
            base as usize + 0x30,
            "inverse-bind array",
            &mut issues,
        ),
        local_matrices: optional_pointer_at(
            system,
            base as usize + 0x38,
            "local-matrix array",
            &mut issues,
        ),
        parents: optional_pointer_at(system, base as usize + 0x40, "parent array", &mut issues),
        names: report.names_at,
    };

    // The array length comes from the records themselves: the first `u16` of
    // the trailing group is the record's index, so a record that does not
    // continue the sequence ends the array. Two nearby counts are recorded and
    // deliberately not used: the header word at `+0x1C` is short of twice the
    // bone count on some skeletons, and the fourth `u16` of a record's trailing
    // group is a jump to the end of that bone's subtree, so it equals the bone
    // count only on a single-root skeleton. Wider sampling found named bones
    // past both values; neither field can truncate the walk.
    let size = system.len() as u64;
    let mut bones = Vec::new();
    for index in 0..MAX_BONES {
        let record = bone_base + index as u64 * BONE_LEN as u64;
        let Some(end) = record.checked_add(BONE_LEN as u64) else {
            issues.push(Issue::Bounds {
                field: "bone record",
                at: record as usize,
                len: BONE_LEN as u64,
                size,
            });
            break;
        };
        if end > size {
            issues.push(Issue::Bounds {
                field: "bone record",
                at: record as usize,
                len: BONE_LEN as u64,
                size,
            });
            break;
        }
        let at = record as usize;
        if u16_at(system, at + 0x48).map(i128::from) != Some(index as i128) {
            break;
        }
        let raw_parent = u16_at(system, at + 0x46).unwrap_or(ROOT_PARENT);
        let name_pointer = u64_at(system, at + 0x30).unwrap_or(0);
        let name_offset = system_pointer(name_pointer);
        let name = name_offset.and_then(|offset| ascii_string(system, offset as usize));
        let bone = Bone {
            index,
            parent: None,
            raw_parent,
            name,
            name_offset,
            rotation: [
                f32_at(system, at),
                f32_at(system, at + 4),
                f32_at(system, at + 8),
                f32_at(system, at + 12),
            ],
            translation: [
                f32_at(system, at + 0x10),
                f32_at(system, at + 0x14),
                f32_at(system, at + 0x18),
            ],
            scale: [
                f32_at(system, at + 0x20),
                f32_at(system, at + 0x24),
                f32_at(system, at + 0x28),
            ],
            identifier: u32_at(system, at + 0x1C).unwrap_or(0),
            identifier16: u16_at(system, at + 0x4A).unwrap_or(0),
            flags: [
                u16_at(system, at + 0x40).unwrap_or(0),
                u16_at(system, at + 0x42).unwrap_or(0),
                u16_at(system, at + 0x44).unwrap_or(0),
                u16_at(system, at + 0x46).unwrap_or(0),
            ],
        };
        bones.push(bone);
    }
    if bones.is_empty() {
        issues.push(Issue::Missing {
            field: "the bone records",
        });
        report.issues = issues;
        return report;
    }

    // A neighbouring array starts at a known address and holds one record per
    // bone, so two arrays that only have to tile give the layout's own limit on
    // the count. The walk only trusts a continued index, and data at the end of
    // the bone allocation can carry the next index by chance: two of the 5,628
    // surveyed skeletons did exactly that, and in both the following matrix
    // arrays only tile when the last record is dropped. The limit is enforced
    // and the drop is reported, never silent.
    let bound = nearest_array_after(bone_base, &report.arrays);
    report.bone_bound = bound.map(|(field, at)| BoneArrayBound {
        field,
        at,
        exact: bone_base + bones.len() as u64 * BONE_LEN as u64 == u64::from(at),
    });
    if let Some((field, at, allowed)) = implied_bone_ceiling(&report.arrays)
        && (allowed as usize) < bones.len()
    {
        let walked = bones.len() as u64;
        let kept = (allowed as usize).max(1);
        bones.truncate(kept);
        issues.push(Issue::BoneArrayOverrun {
            walked,
            kept: kept as u64,
            field,
            at: u64::from(at),
        });
    }

    report.bones = bones;
    // The cap must never read as a complete skeleton: a record that continues
    // the index sequence past the limit is reported rather than dropped.
    if report.bones.len() == MAX_BONES {
        let record = (bone_base as usize) + MAX_BONES * BONE_LEN;
        if u16_at(system, record + 0x48) == Some(MAX_BONES as u16) {
            issues.push(Issue::BeyondLimit {
                field: "bone records",
                limit: MAX_BONES,
            });
        }
    }
    report.inverse_bind = read_inverse_bind(system, base, report.bones.len(), &mut issues);
    report.local_matrices = read_local_matrices(system, base, report.bones.len(), &mut issues);
    report.parent_array = read_parent_array(system, base, report.bones.len(), &mut issues);
    check_array_overlap(&report, report.bones.len(), &mut issues);
    resolve_hierarchy(&mut report, &mut issues);
    check_values(&mut report, &mut issues);
    report.issues = issues;
    report.status = if report.issues.is_empty() {
        "complete"
    } else {
        "partial"
    };
    report
}

/// Reads the inverse-bind array. A missing pointer leaves the array empty and
/// produces no issue: the record is optional and an empty array means the
/// array is not present, not that it is empty data.
fn read_inverse_bind(
    system: &[u8],
    base: u64,
    bones: usize,
    issues: &mut Vec<Issue>,
) -> Vec<Matrix34> {
    let Some(offset) =
        optional_pointer_at(system, base as usize + 0x30, "inverse-bind array", issues)
    else {
        return Vec::new();
    };
    read_matrices(system, offset, bones, "inverse-bind array", issues)
}

/// Reads the local-matrix array. As with the inverse-bind array, a missing
/// pointer leaves the array empty and produces no issue.
fn read_local_matrices(
    system: &[u8],
    base: u64,
    bones: usize,
    issues: &mut Vec<Issue>,
) -> Vec<Matrix34> {
    let Some(offset) =
        optional_pointer_at(system, base as usize + 0x38, "local-matrix array", issues)
    else {
        return Vec::new();
    };
    read_matrices(system, offset, bones, "local-matrix array", issues)
}

fn read_matrices(
    system: &[u8],
    at: u32,
    count: usize,
    field: &'static str,
    issues: &mut Vec<Issue>,
) -> Vec<Matrix34> {
    let base = u64::from(at);
    let size = system.len() as u64;
    let available = if base >= size {
        0
    } else {
        (size - base) / MATRIX_LEN as u64
    };
    let used = (count as u64).min(available) as usize;
    if used < count {
        issues.push(Issue::Clamped {
            field,
            declared: count as u64,
            used: used as u64,
        });
    }
    let mut records = Vec::with_capacity(used);
    for index in 0..used {
        let record = (base as usize) + index * MATRIX_LEN;
        let mut rotation = [0f32; 9];
        for (slot, value) in rotation.iter_mut().enumerate() {
            let row = slot / 3;
            let column = slot % 3;
            *value = f32_at(system, record + 4 * (row * 4 + column));
        }
        records.push(Matrix34 {
            rotation,
            translation: [
                f32_at(system, record + 0x30),
                f32_at(system, record + 0x34),
                f32_at(system, record + 0x38),
            ],
            unknown: f32_at(system, record + 0x3C),
        });
    }
    records
}

fn read_parent_array(
    system: &[u8],
    base: u64,
    bones: usize,
    issues: &mut Vec<Issue>,
) -> Option<Vec<u16>> {
    let offset = optional_pointer_at(system, base as usize + 0x40, "parent array", issues)?;
    let start = u64::from(offset);
    let size = system.len() as u64;
    let available = if start >= size { 0 } else { (size - start) / 2 };
    let used = (bones as u64).min(available) as usize;
    if used < bones {
        issues.push(Issue::Clamped {
            field: "parent array",
            declared: bones as u64,
            used: used as u64,
        });
        return None;
    }
    Some(
        (0..used)
            .map(|index| u16_at(system, start as usize + index * 2).unwrap_or(ROOT_PARENT))
            .collect(),
    )
}

/// Resolves parents, rejects cycles and measures the tree.
fn resolve_hierarchy(report: &mut Report, issues: &mut Vec<Issue>) {
    let count = report.bones.len();
    if let Some(parents) = &report.parent_array {
        for (index, bone) in report.bones.iter().enumerate() {
            if let Some(&array) = parents.get(index)
                && bone.raw_parent != array
            {
                issues.push(Issue::ParentArrayMismatch {
                    bone: index,
                    recorded: bone.raw_parent,
                    array,
                });
            }
        }
    }
    let raws: Vec<u16> = report.bones.iter().map(|bone| bone.raw_parent).collect();
    for (index, raw) in raws.into_iter().enumerate() {
        if raw == ROOT_PARENT {
            continue;
        }
        if raw as usize >= count {
            issues.push(Issue::InvalidParent {
                bone: index,
                parent: raw,
            });
            continue;
        }
        if raw as usize == index {
            issues.push(Issue::SelfParent { bone: index });
            continue;
        }
        report.bones[index].parent = Some(raw as usize);
    }

    // Walk each chain with a bounded path, so a cycle terminates. Only the
    // bones on the cycle itself are marked; a bone that merely leads into a
    // cycle keeps its parent and is reported through the cycle members.
    let mut cyclic = vec![false; count];
    for start in 0..count {
        let mut path = Vec::new();
        let mut current = start;
        let mut steps = 0usize;
        while let Some(parent) = report.bones[current].parent {
            if steps > count {
                break;
            }
            steps += 1;
            if let Some(position) = path.iter().position(|&bone| bone == parent) {
                for &bone in &path[position..] {
                    cyclic[bone] = true;
                }
                cyclic[parent] = true;
                break;
            }
            path.push(current);
            current = parent;
        }
    }
    for (index, is_cyclic) in cyclic.iter().enumerate() {
        if *is_cyclic {
            issues.push(Issue::Cycle { bone: index });
            report.bones[index].parent = None;
        }
    }

    report.roots = (0..count)
        .filter(|&index| report.bones[index].parent.is_none())
        .collect();
    let mut depth = vec![0usize; count];
    for (index, value) in depth.iter_mut().enumerate() {
        let mut current = index;
        let mut steps = 0usize;
        while let Some(parent) = report.bones[current].parent {
            if steps > count {
                break;
            }
            steps += 1;
            current = parent;
        }
        *value = steps;
    }
    report.max_depth = depth.into_iter().max().map_or(0, |value| value + 1);
}

fn check_values(report: &mut Report, issues: &mut Vec<Issue>) {
    for bone in &report.bones {
        for (offset, field, values) in [
            (0x00usize, "rotation", &bone.rotation[..]),
            (0x10, "translation", &bone.translation[..]),
            (0x20, "scale", &bone.scale[..]),
        ] {
            if values.iter().any(|value| !value.is_finite()) {
                issues.push(Issue::NonFinite {
                    bone: bone.index,
                    field,
                    at: bone.index * BONE_LEN + offset,
                });
            }
        }
    }
    for (index, record) in report.inverse_bind.iter().enumerate() {
        if !record.finite() {
            issues.push(Issue::NonFinite {
                bone: index,
                field: "inverse-bind record",
                at: index * MATRIX_LEN,
            });
        }
    }
}

/// Reads a system pointer stored at `at` and reports the field when it does
/// not decode.
fn pointer_at(
    system: &[u8],
    at: usize,
    field: &'static str,
    issues: &mut Vec<Issue>,
) -> Option<u32> {
    let value = u64_at(system, at)?;
    match system_pointer(value) {
        Some(offset) => Some(offset),
        None => {
            issues.push(Issue::Pointer { field, at, value });
            None
        }
    }
}
fn system_pointer(value: u64) -> Option<u32> {
    match Pointer::decode(value) {
        Some(Pointer::System(offset)) => Some(offset),
        _ => None,
    }
}

/// As [`pointer_at`], but a zero word means the record is absent: an optional
/// array that the resource does not store is not an error.
fn optional_pointer_at(
    system: &[u8],
    at: usize,
    field: &'static str,
    issues: &mut Vec<Issue>,
) -> Option<u32> {
    if u64_at(system, at) == Some(0) {
        return None;
    }
    pointer_at(system, at, field, issues)
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

/// A stored `f32`. A missing value is reported as zero only because the caller
/// bounds the record first; a value that cannot be read never appears.
fn f32_at(bytes: &[u8], at: usize) -> f32 {
    bytes
        .get(at..at + 4)
        .map(|value| f32::from_le_bytes(value.try_into().expect("four bytes")))
        .unwrap_or(0.0)
}

/// A printable ASCII name ending at a NUL. A pointer that does not carry a
/// name yields `None` rather than a guess.
fn ascii_string(bytes: &[u8], at: usize) -> Option<String> {
    let tail = bytes.get(at..)?;
    let end = tail.iter().take(MAX_NAME).position(|&byte| byte == 0)?;
    let text = tail.get(..end)?;
    if text.is_empty() || text.iter().any(|&byte| !(0x20..=0x7E).contains(&byte)) {
        return None;
    }
    std::str::from_utf8(text).ok().map(str::to_owned)
}
