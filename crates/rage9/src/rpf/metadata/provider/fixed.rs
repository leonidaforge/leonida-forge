//! Recognition of the fixed transformation tables of the encoded
//! algorithm-`0x10` block operation.
//!
//! The model needs two fixed regions that are independent of the key:
//!
//! - sixteen 256-byte affine permutations, the stage-0 input tables;
//! - sixteen 256-entry little-endian `u32` tables, the encoded round tables.
//!
//! The research established that the round region follows the stage region
//! without padding, that every stage table is an affine bijection of rank 8,
//! and that every round table is injective, has four byte-lane permutations
//! and an affine 8-dimensional image. Recognition scans initialized, readable,
//! non-writable, non-executable sections for that contiguous block. It does
//! not use a fixed address, section name or executable build.
//!
//! The table bytes are game-derived. They are read from the caller's
//! executable at run time and are never copied into the repository. A build
//! whose layout differs fails closed.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::pe::{ExecutableView, Section};

use crate::rpf::metadata::recognize::Limits;

/// Stage-0 table count.
pub const STAGE_TABLE_COUNT: usize = 16;
/// Stage-0 table length in bytes.
pub const STAGE_TABLE_LEN: usize = 256;
/// Round table count.
pub const ROUND_TABLE_COUNT: usize = 16;
/// Round table length in bytes, 256 little-endian `u32` entries.
pub const ROUND_TABLE_LEN: usize = 1024;

const STAGE_BYTES: usize = STAGE_TABLE_COUNT * STAGE_TABLE_LEN;
const ROUND_BYTES: usize = ROUND_TABLE_COUNT * ROUND_TABLE_LEN;
/// The contiguous block recognition looks for.
const BLOCK_BYTES: usize = STAGE_BYTES + ROUND_BYTES;
/// Scan alignment. Section data is at least byte-addressable; 8 keeps the
/// search cheap without assuming the table block starts on a large boundary.
const SCAN_STEP: usize = 8;
/// Raw bytes read per scan step.
const SCAN_CHUNK: usize = 1024 * 1024;
/// Complete affine stage regions the search accepts before failing. Real
/// executables contain many affine tables and shifted windows that pass the
/// cheap prefilter, so this bound only protects against a pathological image.
const MAX_CANDIDATES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedTablesError {
    /// No valid fixed table block was found.
    NotFound,
    /// More than one valid fixed table block was found.
    Ambiguous,
    /// A stage region was found but the block is truncated or violates the
    /// model's table structure.
    Malformed(&'static str),
    /// A limit was exceeded.
    ResourceLimit { what: &'static str, limit: u64 },
    /// The caller cancelled the scan.
    Cancelled,
    /// The executable could not be read.
    Image(&'static str),
}

impl fmt::Display for FixedTablesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixedTablesError::NotFound => f.write_str("no fixed cipher tables found"),
            FixedTablesError::Ambiguous => f.write_str("more than one fixed cipher table block"),
            FixedTablesError::Malformed(reason) => {
                write!(f, "malformed fixed cipher tables: {reason}")
            }
            FixedTablesError::ResourceLimit { what, limit } => {
                write!(f, "the {what} exceeds the limit of {limit}")
            }
            FixedTablesError::Cancelled => f.write_str("cancelled"),
            FixedTablesError::Image(reason) => {
                write!(f, "the executable could not be read: {reason}")
            }
        }
    }
}

impl std::error::Error for FixedTablesError {}

fn resource(what: &'static str, limit: u64) -> FixedTablesError {
    FixedTablesError::ResourceLimit { what, limit }
}

struct Tables {
    stage: [[u8; STAGE_TABLE_LEN]; STAGE_TABLE_COUNT],
    round: [[u32; 256]; ROUND_TABLE_COUNT],
}

/// Validated fixed transformation tables. The bytes are game-derived and are
/// not exposed or printed. Cloning shares them.
#[derive(Clone)]
pub struct FixedTables {
    inner: Arc<Tables>,
}

impl FixedTables {
    /// The stage-0 table at `index`.
    pub(crate) fn stage(&self, index: usize) -> &[u8; STAGE_TABLE_LEN] {
        &self.inner.stage[index]
    }

    /// The round table at `index`.
    pub(crate) fn round(&self, index: usize) -> &[u32; 256] {
        &self.inner.round[index]
    }
}

impl fmt::Debug for FixedTables {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedTables")
            .field("stage_tables", &STAGE_TABLE_COUNT)
            .field("round_tables", &ROUND_TABLE_COUNT)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl FixedTables {
    pub(crate) fn from_parts(
        stage: [[u8; STAGE_TABLE_LEN]; STAGE_TABLE_COUNT],
        round: [[u32; 256]; ROUND_TABLE_COUNT],
    ) -> Self {
        Self {
            inner: Arc::new(Tables { stage, round }),
        }
    }
}

/// Recognizes the fixed transformation tables in `image`.
pub fn recognize_fixed_tables(
    image: &ExecutableView,
    cancel: &AtomicBool,
) -> Result<FixedTables, FixedTablesError> {
    recognize_with(image, cancel, Limits::default())
}

pub(crate) fn recognize_with(
    image: &ExecutableView,
    cancel: &AtomicBool,
    limits: Limits,
) -> Result<FixedTables, FixedTablesError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(FixedTablesError::Cancelled);
    }
    let sections: Vec<&Section> = image
        .sections()
        .iter()
        .filter(|section| {
            section.is_read_only() && section.is_initialized() && !section.is_executable()
        })
        .collect();
    let scan_bytes: u64 = sections
        .iter()
        .map(|section| u64::from(section.raw_size))
        .sum();
    if scan_bytes > limits.scan_bytes {
        return Err(resource("fixed-table scan", limits.scan_bytes));
    }

    let mut valid = Vec::new();
    let mut malformed = None;
    let mut candidates = 0usize;
    let mut offsets = 0u64;
    for section in sections {
        scan_section(
            image,
            cancel,
            section,
            &limits,
            &mut offsets,
            &mut candidates,
            &mut valid,
            &mut malformed,
        )?;
    }

    match valid.len() {
        1 => Ok(valid.pop().expect("one element")),
        0 => Err(malformed.map_or(FixedTablesError::NotFound, FixedTablesError::Malformed)),
        _ => Err(FixedTablesError::Ambiguous),
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_section(
    image: &ExecutableView,
    cancel: &AtomicBool,
    section: &Section,
    limits: &Limits,
    offsets: &mut u64,
    candidates: &mut usize,
    valid: &mut Vec<FixedTables>,
    malformed: &mut Option<&'static str>,
) -> Result<(), FixedTablesError> {
    let size = section.raw_size as usize;
    if size < STAGE_TABLE_LEN {
        return Ok(());
    }
    let base_rva = u64::from(section.virtual_address);
    let mut chunk_start = 0usize;
    while chunk_start + STAGE_TABLE_LEN <= size {
        if cancel.load(Ordering::Relaxed) {
            return Err(FixedTablesError::Cancelled);
        }
        let window = (size - chunk_start).min(SCAN_CHUNK);
        let read_len = (window + STAGE_BYTES).min(size - chunk_start);
        let bytes = image
            .read_rva(base_rva + chunk_start as u64, read_len)
            .map_err(|_| FixedTablesError::Image("a data section cannot be read"))?;

        let mut local = 0usize;
        while local < window {
            if local + STAGE_TABLE_LEN > read_len {
                break;
            }
            let offset = chunk_start + local;
            *offsets += 1;
            if *offsets > limits.scan_offsets {
                return Err(resource("fixed-table scan steps", limits.scan_offsets));
            }

            if !stage_prefilter(&bytes[local..local + STAGE_TABLE_LEN]) {
                local += SCAN_STEP;
                continue;
            }
            // Shifted windows and unrelated tables also pass the cheap
            // prefilter. A complete stage region keeps them from consuming
            // the block-read and validation budget.
            let stage_end = local + STAGE_BYTES;
            if stage_end > read_len {
                break;
            }
            if let Err(reason) = stage_region_ok(&bytes[local..stage_end]) {
                *malformed = Some(reason);
                local += SCAN_STEP;
                continue;
            }
            *candidates += 1;
            if *candidates > MAX_CANDIDATES {
                return Err(resource("fixed-table candidates", MAX_CANDIDATES as u64));
            }
            if offset.checked_add(BLOCK_BYTES).is_none_or(|end| end > size) {
                *malformed = Some("the fixed table block is truncated");
                local += SCAN_STEP;
                continue;
            }
            let block = image
                .read_rva(base_rva + offset as u64, BLOCK_BYTES)
                .map_err(|_| FixedTablesError::Image("the fixed table block cannot be read"))?;
            match validate_block(&block) {
                Ok(tables) => valid.push(tables),
                Err(reason) => *malformed = Some(reason),
            }
            local += SCAN_STEP;
        }
        chunk_start += SCAN_CHUNK;
    }
    Ok(())
}

/// A cheap necessary condition for an affine permutation table. Every affine
/// byte map satisfies `t[x] ^ t[y] ^ t[x^y] == t[0]`, and its first four values
/// are distinct when its linear part has rank 8.
fn stage_prefilter(table: &[u8]) -> bool {
    let t0 = table[0];
    let t1 = table[1];
    let t2 = table[2];
    let t3 = table[3];
    if t0 == t1 || t0 == t2 || t0 == t3 || t1 == t2 || t1 == t3 || t2 == t3 {
        return false;
    }
    t3 == t0 ^ t1 ^ t2
        && table[7] == t0 ^ table[4] ^ table[3]
        && table[15] == t0 ^ table[8] ^ table[7]
        && table[31] == t0 ^ table[16] ^ table[15]
        && table[255] == t0 ^ table[128] ^ table[127]
}

fn validate_block(block: &[u8]) -> Result<FixedTables, &'static str> {
    if block.len() != BLOCK_BYTES {
        return Err("unexpected fixed table block length");
    }

    let stage = stage_region_ok(&block[..STAGE_BYTES])?;

    let mut round = [[0u32; 256]; ROUND_TABLE_COUNT];
    let round_bytes = &block[STAGE_BYTES..];
    for (index, slot) in round.iter_mut().enumerate() {
        let chunk = &round_bytes[index * ROUND_TABLE_LEN..(index + 1) * ROUND_TABLE_LEN];
        for (value, entry) in slot.iter_mut().zip(chunk.as_chunks::<4>().0) {
            *value = u32::from_le_bytes(*entry);
        }
        if !round_table_ok(slot) {
            return Err("a round table is not an injective encoded table");
        }
    }
    if !pairwise_distinct(&round) {
        return Err("two round tables are identical");
    }

    Ok(FixedTables {
        inner: Arc::new(Tables { stage, round }),
    })
}

fn stage_region_ok(
    region: &[u8],
) -> Result<[[u8; STAGE_TABLE_LEN]; STAGE_TABLE_COUNT], &'static str> {
    if region.len() != STAGE_BYTES {
        return Err("unexpected stage region length");
    }
    let mut stage = [[0u8; STAGE_TABLE_LEN]; STAGE_TABLE_COUNT];
    for (index, slot) in stage.iter_mut().enumerate() {
        let table = &region[index * STAGE_TABLE_LEN..(index + 1) * STAGE_TABLE_LEN];
        if !stage_table_ok(table) {
            return Err("a stage-0 table is not an affine permutation");
        }
        slot.copy_from_slice(table);
    }
    if !pairwise_distinct(&stage) {
        return Err("two stage-0 tables are identical");
    }
    Ok(stage)
}

fn stage_table_ok(table: &[u8]) -> bool {
    let constant = table[0];
    let mut columns = [0u8; 8];
    for (bit, column) in columns.iter_mut().enumerate() {
        *column = table[1 << bit] ^ constant;
    }
    if gf2_rank(&columns) != 8 {
        return false;
    }
    (0..256).all(|x| {
        let mut value = constant;
        for (bit, &column) in columns.iter().enumerate() {
            if x & (1 << bit) != 0 {
                value ^= column;
            }
        }
        value == table[x]
    })
}

fn gf2_rank<const N: usize>(values: &[u8; N]) -> usize {
    let mut basis = [0u8; 8];
    for &value in values {
        let mut reduced = value;
        while reduced != 0 {
            let bit = 7 - reduced.leading_zeros() as usize;
            if basis[bit] == 0 {
                basis[bit] = reduced;
                break;
            }
            reduced ^= basis[bit];
        }
    }
    basis.iter().filter(|&&value| value != 0).count()
}

/// A round table is injective, has four byte-lane permutations and an affine
/// 8-dimensional image. The first property follows from the lane check.
fn round_table_ok(table: &[u32; 256]) -> bool {
    for lane in 0..4 {
        let mut seen = [false; 256];
        for &value in table {
            let byte = ((value >> (8 * lane)) & 0xFF) as usize;
            if std::mem::replace(&mut seen[byte], true) {
                return false;
            }
        }
    }

    let mut basis = [0u32; 32];
    let mut rank = 0usize;
    for &value in &table[1..] {
        let mut reduced = value ^ table[0];
        while reduced != 0 {
            let bit = 31 - reduced.leading_zeros() as usize;
            if basis[bit] == 0 {
                basis[bit] = reduced;
                rank += 1;
                break;
            }
            reduced ^= basis[bit];
        }
        if rank > 8 {
            return false;
        }
    }
    rank == 8
}

fn pairwise_distinct<T: PartialEq, const N: usize, const W: usize>(tables: &[[T; W]; N]) -> bool {
    (0..N)
        .all(|left| (left + 1..N).all(|right| tables[left].as_slice() != tables[right].as_slice()))
}
