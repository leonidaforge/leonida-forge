//! Texture dictionary inspection shared by the CLI and the desktop.
//!
//! The parser is [`lforge_rage9::dictionary`]. This module only turns its
//! report into the JSON and field pairs a front end shows, so a dictionary
//! means the same thing in both. No pixel is decoded and no reference is
//! resolved.

use lforge_rage9::dictionary::{self, Error, NameCheck, Report};
use serde_json::{Value, json};

/// Bytes of a record shown by default.
pub const DEFAULT_RECORD_SAMPLE: usize = 64;

fn hex(value: u64) -> String {
    format!("0x{value:016X}")
}

/// A display summary of a dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub hash_count: u16,
    pub value_count: u16,
    pub records: usize,
    pub empty: bool,
    pub partition_ok: bool,
    pub names_checked: usize,
    pub names_matched: usize,
}

impl Summary {
    pub fn of(report: &Report) -> Self {
        Self {
            hash_count: report.hash_count,
            value_count: report.value_count,
            records: report.records.len(),
            empty: report.empty,
            partition_ok: report.checks.partition_ok,
            names_checked: report
                .records
                .iter()
                .filter(|record| record.name_check.name() != "not checked")
                .count(),
            names_matched: report
                .records
                .iter()
                .filter(|record| record.name_check == NameCheck::Matched)
                .count(),
        }
    }
}

/// Whether `system` has the dictionary shape.
pub fn recognise(system: &[u8], graphics_len: u64) -> bool {
    dictionary::parse(system, graphics_len, &dictionary::Limits::default()).is_ok()
}

/// Parses a dictionary and returns the report as a JSON value. `record`
/// selects one record to show in full; `sample` bounds the list.
pub fn report(
    system: &[u8],
    graphics_len: u64,
    record: Option<u32>,
    sample: usize,
) -> Result<Value, String> {
    let report = dictionary::parse(system, graphics_len, &dictionary::Limits::default())
        .map_err(describe)?;
    let sample = sample.clamp(1, dictionary::Limits::default().max_records);
    if let Some(index) = record {
        let found = report.records.iter().find(|item| item.index == index);
        return match found {
            Some(record) => Ok(json!({
                "record": record_json(record),
                "representation": "structural fields only; no pixels are decoded",
            })),
            None => Err(format!(
                "record {index} does not exist; the dictionary holds {}",
                report.records.len()
            )),
        };
    }
    let records: Vec<Value> = report
        .records
        .iter()
        .take(sample)
        .map(record_json)
        .collect();
    Ok(json!({
        "hash_count": report.hash_count,
        "hash_capacity": report.hash_capacity,
        "value_count": report.value_count,
        "value_capacity": report.value_capacity,
        "empty": report.empty,
        "system_size": report.system_len,
        "graphics_size": report.graphics_len,
        "checks": {
            "counts_equal": report.checks.counts_equal,
            "capacities_ok": report.checks.capacities_ok,
            "hash_sorted_unique": report.checks.hash_sorted_unique,
            "value_order_matches_index": report.checks.value_order_matches_index,
            "starts_at_zero": report.checks.starts_at_zero,
            "allocation_duplicate": report.checks.allocation_duplicate,
            "allocation_front_gap": report.checks.allocation_front_gap,
            "allocations_in_bounds": report.checks.allocations_in_bounds,
            "partition_ok": report.checks.partition_ok,
        },
        "hashes": report.hashes,
        "records": {
            "count": report.records.len(),
            "shown": records.len(),
            "items": records,
        },
        "limitations": [
            "the byte scale of the allocation unit count is unknown; the extent is an upper bound",
            "width, height, format id and mip count are read at confirmed positions; their meanings are probable at best",
            "a name hash is a key, not a filename",
            "a hash that occurs in several records is a namespace match, not a resolved texture",
            "the graphics segment is not parsed and no pixel is decoded",
        ],
    }))
}

fn record_json(record: &dictionary::Record) -> Value {
    json!({
        "index": record.index,
        "offset": hex(u64::from(record.at)),
        "allocation_units": record.units,
        "word_0c": record.word_0c,
        "word_10": record.word_10,
        "allocation": match (record.graphics_at, record.extent) {
            (Some(at), Some(extent)) => json!({
                "offset": hex(u64::from(at)),
                "extent": extent,
            }),
            _ => Value::Null,
        },
        "name": {
            "record": record.name_at.map(|at| hex(u64::from(at))),
            "variant": record.name_variant.name(),
            "hash": record.name_hash.map(hex_u32),
            "check": record.name_check.name(),
            "reason": record.name_check.reason(),
            "mismatch": match record.name_check {
                NameCheck::Mismatched { stored, computed } => Some(json!({
                    "stored": hex_u32(stored),
                    "computed": hex_u32(computed),
                })),
                _ => None,
            },
        },
        "width": record.width,
        "height": record.height,
        "format_id": record.format_id,
        "mip_word": record.mip_word,
        "mip_levels": record.mip_levels,
        "neutral": record.neutral,
    })
}

fn hex_u32(value: u32) -> String {
    format!("0x{value:08X}")
}

fn describe(error: Error) -> String {
    match error {
        Error::NotADictionary(step) => {
            format!("not a texture dictionary: {}", step.describe())
        }
        Error::Invalid(reason) => reason,
    }
}
