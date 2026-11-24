//! Structural recognition of the RPF9 cryptographic state registry.
//!
//! A registry is a contiguous run of 24-byte records `{u64 selector, u64
//! state_pointer, u64 state_length}` in an initialized, readable, non-writable,
//! non-executable section. A record is accepted only if its state lies in the
//! image, has length `0x10F4` or `0x20`, and, for `0x10F4`, a nonzero schedule
//! and, for the first records, sixteen permutation final tables. A candidate
//! run needs at least [`MIN_RUN_RECORDS`] records and at least one
//! algorithm-`0x10` state; a strong run needs `limits.min_records` records.
//!
//! Section names are irrelevant. Every maximal run is considered, duplicate
//! selectors invalidate a run, and several strong runs fail as ambiguous
//! instead of one being chosen. A run that reaches the record limit while more
//! valid records follow fails as a resource limit rather than being truncated.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::Error as BinaryError;
use lforge_binary::pe::{ExecutableView, Identity, Section};
use zeroize::Zeroizing;

use super::{DEFAULT_RECORD_LEN, Limits, STATE_LEN, STATE_MAGIC, StateBytes, selector_for};

/// Bytes per registry record.
const RECORD_LEN: u64 = 0x18;
/// Records a run needs to appear as a candidate at all.
const MIN_RUN_RECORDS: usize = 2;
/// Raw bytes read per scan step.
const SCAN_CHUNK: usize = 1024 * 1024;
/// Scan steps between cancellation checks.
const CANCEL_CHECK_OFFSETS: u64 = 4096;
/// Records between cancellation checks while validating one candidate.
const CANCEL_CHECK_RECORDS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// No strong record run was found.
    NotFound,
    /// More than one strong record run was found.
    Ambiguous,
    /// The requested selector has no state.
    NoCompatibleState,
    /// A state does not have the expected structure.
    StateMalformed(&'static str),
    /// A limit was exceeded.
    ResourceLimit { what: &'static str, limit: u64 },
    /// The caller cancelled the scan.
    Cancelled,
    /// The executable could not be read.
    Image(&'static str),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::NotFound => f.write_str("no key registry found"),
            RegistryError::Ambiguous => f.write_str("more than one key registry candidate"),
            RegistryError::NoCompatibleState => f.write_str("no compatible key state"),
            RegistryError::StateMalformed(reason) => write!(f, "malformed key state: {reason}"),
            RegistryError::ResourceLimit { what, limit } => {
                write!(f, "the {what} exceeds the limit of {limit}")
            }
            RegistryError::Cancelled => f.write_str("cancelled"),
            RegistryError::Image(reason) => write!(f, "the executable could not be read: {reason}"),
        }
    }
}

impl std::error::Error for RegistryError {}

fn resource(what: &'static str, limit: u64) -> RegistryError {
    RegistryError::ResourceLimit { what, limit }
}

/// One registry record. Its fields are sensitive and never printed.
#[derive(Clone, Copy)]
struct Record {
    selector: u64,
    state_va: u64,
    state_len: u64,
}

/// A recognized registry. It holds no state bytes: a state is read and
/// revalidated when [`Registry::state_for_key`] asks for it.
#[derive(Clone)]
pub struct Registry {
    image: ExecutableView,
    records: Vec<Record>,
    algorithm_states: usize,
}

impl Registry {
    /// Records in the recognized run, including entries that are not encoded
    /// key states.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Records whose state carries the algorithm-`0x10` magic.
    pub fn algorithm_state_count(&self) -> usize {
        self.algorithm_states
    }

    /// Reads and revalidates the state a selector resolves to. Exactly one
    /// record must match; there is no fallback to another state.
    pub fn state_for_key(
        &self,
        key_id: u32,
        algorithm_id: u8,
        mode: u8,
    ) -> Result<StateBytes, RegistryError> {
        let selector = selector_for(key_id, algorithm_id, mode);
        let record = unique_record(&self.records, selector)?;
        if record.state_len != STATE_LEN as u64 {
            return Err(RegistryError::StateMalformed(
                "the state is not an encoded algorithm-0x10 state",
            ));
        }
        let bytes = Zeroizing::new(
            self.image
                .read_va(record.state_va, STATE_LEN)
                .map_err(|_| RegistryError::StateMalformed("the state cannot be read"))?,
        );
        validate_state(&bytes)?;
        Ok(StateBytes::new(bytes))
    }

    /// The current identity of the executable, for detecting changes after
    /// recognition.
    pub fn identity(&self, cancel: &AtomicBool) -> Result<Identity, BinaryError> {
        self.image.identity(cancel)
    }
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registry")
            .field("records", &self.records.len())
            .field("algorithm_states", &self.algorithm_states)
            .finish_non_exhaustive()
    }
}

fn unique_record(records: &[Record], selector: u64) -> Result<Record, RegistryError> {
    let mut matches = records.iter().filter(|record| record.selector == selector);
    match (matches.next(), matches.next()) {
        (Some(record), None) => Ok(*record),
        (None, _) => Err(RegistryError::NoCompatibleState),
        (Some(_), Some(_)) => Err(RegistryError::Ambiguous),
    }
}

fn validate_state(bytes: &[u8]) -> Result<(), RegistryError> {
    if bytes.len() != STATE_LEN {
        return Err(RegistryError::StateMalformed("unexpected state length"));
    }
    if read_u32(bytes, 0) != Some(STATE_MAGIC) {
        return Err(RegistryError::StateMalformed("unexpected state magic"));
    }
    if !schedule_nonzero(bytes) {
        return Err(RegistryError::StateMalformed("the schedule is zero"));
    }
    if !final_tables_ok(bytes) {
        return Err(RegistryError::StateMalformed(
            "a final-round table is not a permutation",
        ));
    }
    Ok(())
}

fn schedule_nonzero(bytes: &[u8]) -> bool {
    bytes.get(4..4 + 60 * 4).is_some_and(|schedule| {
        schedule
            .as_chunks::<4>()
            .0
            .iter()
            .any(|word| u32::from_le_bytes(*word) != 0)
    })
}

fn final_tables_ok(bytes: &[u8]) -> bool {
    (0..16).all(|index| {
        let start = 0xF4 + 0x100 * index;
        bytes.get(start..start + 0x100).is_some_and(is_permutation)
    })
}

fn is_permutation(table: &[u8]) -> bool {
    if table.len() != 256 {
        return false;
    }
    let mut seen = [false; 256];
    for &byte in table {
        if std::mem::replace(&mut seen[byte as usize], true) {
            return false;
        }
    }
    true
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

fn words(record: &[u8]) -> Option<(u64, u64, u64)> {
    Some((
        read_u64(record, 0)?,
        read_u64(record, 8)?,
        read_u64(record, 16)?,
    ))
}

/// Whether the state at `state_va` has a supported length and structure.
/// `None` means the record ends a run. `tables` reports the final-table check
/// and `magic` the algorithm-`0x10` magic.
struct Check {
    magic: bool,
    tables: bool,
}

fn state_check(image: &ExecutableView, state_va: u64, state_len: u64) -> Option<Check> {
    if state_len != STATE_LEN as u64 && state_len != DEFAULT_RECORD_LEN {
        return None;
    }
    let len = usize::try_from(state_len).ok()?;
    let bytes = Zeroizing::new(image.read_va(state_va, len).ok()?);
    if len != STATE_LEN {
        return Some(Check {
            magic: false,
            tables: true,
        });
    }
    if !schedule_nonzero(&bytes) {
        return None;
    }
    Some(Check {
        magic: read_u32(&bytes, 0) == Some(STATE_MAGIC),
        tables: final_tables_ok(&bytes),
    })
}

/// A maximal run of structurally valid records.
#[derive(Clone, Copy)]
struct Run {
    start_va: u64,
    count: usize,
    magic: usize,
    /// Whether the first two records, the ones a candidate checks tables for,
    /// pass the final-table check.
    prefix_tables: bool,
}

impl Run {
    fn end_va(self) -> u64 {
        self.start_va + self.count as u64 * RECORD_LEN
    }
}

/// The recognized registry of `image`.
pub fn recognize_registry(
    image: &ExecutableView,
    cancel: &AtomicBool,
) -> Result<Registry, RegistryError> {
    recognize_with(image, cancel, Limits::default())
}

pub(crate) fn recognize_with(
    image: &ExecutableView,
    cancel: &AtomicBool,
    limits: Limits,
) -> Result<Registry, RegistryError> {
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
        return Err(resource("read-only scan", limits.scan_bytes));
    }

    let mut candidates = Vec::new();
    let mut offsets = 0u64;
    for section in sections {
        scan_section(
            image,
            cancel,
            &limits,
            section,
            &mut offsets,
            &mut candidates,
        )?;
    }

    // The longest runs win over shorter runs they contain. Runs of equal
    // length are separate candidates, so the selection below stays ambiguous.
    candidates.sort_by_key(|run| std::cmp::Reverse((run.count, run.magic)));
    let mut unique: Vec<Run> = Vec::new();
    for candidate in candidates {
        let contained = unique.iter().any(|longer| {
            longer.start_va <= candidate.start_va
                && candidate.end_va() <= longer.end_va()
                && longer.count > candidate.count
        });
        if !contained {
            unique.push(candidate);
        }
    }

    let mut strong = Vec::new();
    for candidate in unique {
        if candidate.count < limits.min_records || candidate.magic == 0 {
            continue;
        }
        if candidate_holds(image, cancel, candidate)? {
            strong.push(candidate);
        }
    }
    if strong
        .iter()
        .any(|candidate| candidate.magic > limits.algorithm_states)
    {
        return Err(resource(
            "algorithm-0x10 states in one registry run",
            limits.algorithm_states as u64,
        ));
    }

    match strong.as_slice() {
        [] => Err(RegistryError::NotFound),
        [candidate] => recognized(image, cancel, *candidate),
        _ => Err(RegistryError::Ambiguous),
    }
}

/// Scans one section for maximal record runs. Runs at offsets that differ by
/// 8 but not by 24 can overlap, so at most three runs are open at a time: one
/// per `offset % 24`.
fn scan_section(
    image: &ExecutableView,
    cancel: &AtomicBool,
    limits: &Limits,
    section: &Section,
    offsets: &mut u64,
    candidates: &mut Vec<Run>,
) -> Result<(), RegistryError> {
    let raw_size = section.raw_size as usize;
    if raw_size < RECORD_LEN as usize {
        return Ok(());
    }
    let section_rva = u64::from(section.virtual_address);
    let section_va = image
        .image_base()
        .checked_add(section_rva)
        .ok_or(RegistryError::StateMalformed("an address overflows"))?;
    if section_va.checked_add(raw_size as u64).is_none() {
        return Err(RegistryError::StateMalformed("an address overflows"));
    }

    let mut open: [Option<Run>; 3] = [None; 3];
    let mut chunk_start = 0usize;
    while chunk_start + RECORD_LEN as usize <= raw_size {
        let window = (raw_size - chunk_start).min(SCAN_CHUNK);
        let read_len = (window + RECORD_LEN as usize).min(raw_size - chunk_start);
        let bytes = image
            .read_rva(section_rva + chunk_start as u64, read_len)
            .map_err(|_| RegistryError::Image("a section cannot be read"))?;

        let mut local = 0usize;
        while local < window {
            if local + RECORD_LEN as usize > read_len {
                break;
            }
            let offset = chunk_start + local;
            *offsets += 1;
            if *offsets > limits.scan_offsets {
                return Err(resource("registry scan steps", limits.scan_offsets));
            }
            if (*offsets).is_multiple_of(CANCEL_CHECK_OFFSETS) && cancel.load(Ordering::Relaxed) {
                return Err(RegistryError::Cancelled);
            }

            let slot = (offset % RECORD_LEN as usize) / 8;
            let va = section_va + offset as u64;
            let extends =
                open[slot].is_some_and(|run| run.start_va + run.count as u64 * RECORD_LEN == va);
            if !extends && let Some(run) = open[slot].take() {
                emit(run, limits, candidates)?;
            }

            let record = &bytes[local..local + RECORD_LEN as usize];
            let (_, state_va, state_len) =
                words(record).ok_or(RegistryError::StateMalformed("a record is truncated"))?;
            let Some(check) = state_check(image, state_va, state_len) else {
                local += 8;
                continue;
            };

            if extends && let Some(run) = open[slot].as_mut() {
                if run.count == 1 {
                    run.prefix_tables &= check.tables;
                }
                run.count += 1;
                run.magic += usize::from(check.magic);
                if run.count > limits.records {
                    return Err(resource(
                        "registry records in one run",
                        limits.records as u64,
                    ));
                }
            } else {
                open[slot] = Some(Run {
                    start_va: va,
                    count: 1,
                    magic: usize::from(check.magic),
                    prefix_tables: check.tables,
                });
            }
            local += 8;
        }
        chunk_start += SCAN_CHUNK;
    }

    for run in open.into_iter().flatten() {
        emit(run, limits, candidates)?;
    }
    Ok(())
}

fn emit(run: Run, limits: &Limits, candidates: &mut Vec<Run>) -> Result<(), RegistryError> {
    if run.prefix_tables && run.count >= MIN_RUN_RECORDS {
        if candidates.len() >= limits.candidates {
            return Err(resource(
                "registry candidate runs",
                limits.candidates as u64,
            ));
        }
        candidates.push(run);
    }
    Ok(())
}

/// Revalidates every state of a candidate with the final-table check and
/// requires unique selectors.
fn candidate_holds(
    image: &ExecutableView,
    cancel: &AtomicBool,
    run: Run,
) -> Result<bool, RegistryError> {
    let mut selectors = HashSet::with_capacity(run.count);
    for index in 0..run.count {
        if index.is_multiple_of(CANCEL_CHECK_RECORDS) && cancel.load(Ordering::Relaxed) {
            return Err(RegistryError::Cancelled);
        }
        let va = run.start_va + index as u64 * RECORD_LEN;
        let bytes = Zeroizing::new(
            image
                .read_va(va, RECORD_LEN as usize)
                .map_err(|_| RegistryError::StateMalformed("a registry record cannot be read"))?,
        );
        let (selector, state_va, state_len) =
            words(&bytes).ok_or(RegistryError::StateMalformed("a record is truncated"))?;
        if !selectors.insert(selector) {
            return Ok(false);
        }
        if !state_check(image, state_va, state_len).is_some_and(|check| check.tables) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn recognized(
    image: &ExecutableView,
    cancel: &AtomicBool,
    run: Run,
) -> Result<Registry, RegistryError> {
    let mut records = Vec::with_capacity(run.count);
    let mut algorithm_states = 0;
    for index in 0..run.count {
        if index.is_multiple_of(CANCEL_CHECK_RECORDS) && cancel.load(Ordering::Relaxed) {
            return Err(RegistryError::Cancelled);
        }
        let va = run.start_va + index as u64 * RECORD_LEN;
        let bytes = Zeroizing::new(
            image
                .read_va(va, RECORD_LEN as usize)
                .map_err(|_| RegistryError::StateMalformed("a registry record cannot be read"))?,
        );
        let (selector, state_va, state_len) =
            words(&bytes).ok_or(RegistryError::StateMalformed("a record is truncated"))?;
        let check = state_check(image, state_va, state_len).ok_or(
            RegistryError::StateMalformed("a registry state is no longer valid"),
        )?;
        algorithm_states += usize::from(check.magic);
        records.push(Record {
            selector,
            state_va,
            state_len,
        });
    }
    Ok(Registry {
        image: image.clone(),
        records,
        algorithm_states,
    })
}

#[cfg(test)]
pub(super) fn with_records(image: ExecutableView, entries: &[(u64, u64, u64)]) -> Registry {
    Registry {
        image,
        records: entries
            .iter()
            .map(|&(selector, state_va, state_len)| Record {
                selector,
                state_va,
                state_len,
            })
            .collect(),
        algorithm_states: 0,
    }
}
