//! Vehicle body discovery.
//!
//! A vehicle body is a type 3 fragment inside an archive that a top-level row
//! stores. The vehicle archives are the top-level rows of `levels.rpf` whose
//! names do not resolve, so the scan visits those rows only.
//!
//! A fragment is recognised by the names its header carries: `<model>_hi.#ft`,
//! `<model>_mid.#ft` and `<model>.#ft`. The scan decodes a candidate and keeps
//! the model whose header matches the supplied name list.
//!
//! The document holds archive locators and logical sizes. It holds no absolute
//! path and no extracted file, so it can be regenerated on another machine.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use serde_json::{Value, json};

use crate::nested::{self, Selector};
use crate::rows::Listing;

use super::names::{self, Names};

/// The schema of the association document.
pub const BODIES_SCHEMA: &str = "leonida-forge.vehicle-bodies/1";

/// The largest metadata table read for one archive.
const MAX_METADATA: u64 = 256 * 1024 * 1024;
/// The largest fragment decoded while scanning.
const MAX_FRAGMENT: u64 = 64 * 1024 * 1024;
/// The longest header name accepted, in bytes.
const HEADER_WINDOW: usize = 96;

pub struct Options {
    pub archive: PathBuf,
    pub executable: Option<PathBuf>,
    pub names: PathBuf,
    pub output: PathBuf,
    pub min_bytes: u64,
    pub max_root_rows: Option<u32>,
    pub json: bool,
}

/// One verified body association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    pub model: String,
    pub archive_row: u32,
    pub row: u32,
    pub header: String,
    pub logical_size: u64,
    /// Higher is a more detailed body: `_hi` over `_mid` over the base name.
    pub rank: u8,
}

impl Association {
    /// Whether `self` should replace `current` for the same model.
    fn outranks(&self, current: &Self) -> bool {
        self.rank > current.rank
            || (self.rank == current.rank && self.logical_size > current.logical_size)
    }
}

/// The association document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bodies {
    pub models: Vec<Association>,
    /// Root rows inspected.
    pub scanned: u32,
    /// Type 3 rows above the size floor.
    pub candidates: usize,
    /// Candidates decoded and scanned for headers.
    pub decoded: usize,
    /// Rows that could not be read.
    pub failed: usize,
}

pub fn run(options: &Options) -> Result<(), String> {
    let names = names::read(&options.names)?;
    if names.is_empty() {
        return Err(format!(
            "{} holds no vehicle names",
            options.names.display()
        ));
    }
    let bodies = discover(
        &options.archive,
        options.executable.as_deref(),
        &names,
        options.min_bytes,
        options.max_root_rows,
    )?;
    write(&options.output, &bodies, &options.archive, options.json)?;
    if !options.json {
        println!(
            "matched {} of {} names; {} root rows scanned, {} candidates, {} decoded, {} failed",
            bodies.models.len(),
            names.len(),
            bodies.scanned,
            bodies.candidates,
            bodies.decoded,
            bodies.failed
        );
    }
    Ok(())
}

/// Scans `archive` and returns the best body per model, ordered by model name.
pub fn discover(
    archive: &Path,
    executable: Option<&Path>,
    names: &Names,
    min_bytes: u64,
    max_root_rows: Option<u32>,
) -> Result<Bodies, String> {
    let cancel = AtomicBool::new(false);
    let listing = Listing::open(archive, executable, &[], &cancel)?;
    let mut best: BTreeMap<String, Association> = BTreeMap::new();
    let mut scanned = 0u32;
    let mut candidates = 0usize;
    let mut decoded = 0usize;
    let mut failed = 0usize;
    // A vehicle archive can decode to more than half a gigabyte, which is above
    // the nested default, so the scan states its own limits.
    let limits = nested::Limits {
        max_archive_bytes: 2 * 1024 * 1024 * 1024,
        max_chain_bytes: 4 * 1024 * 1024 * 1024,
        ..nested::Limits::default()
    };
    for entry in listing.entries() {
        if let Some(limit) = max_root_rows
            && scanned >= limit
        {
            break;
        }
        let Ok(Some(location)) = entry.location else {
            continue;
        };
        if location.type_id != 0 {
            continue;
        }
        let unresolved = listing
            .row_names(entry.row)
            .map(|row| row.resolution.is_unresolved())
            .unwrap_or(true);
        if !unresolved {
            continue;
        }
        scanned += 1;
        let nested_archive = match nested::resolve_with(
            archive,
            executable,
            &[Selector::Row(entry.row)],
            &cancel,
            &limits,
        ) {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("row {}: {err}", entry.row);
                failed += 1;
                continue;
            }
        };
        let opened =
            match crate::native::open_metadata(&nested_archive.path, MAX_METADATA, executable) {
                Ok(opened) => opened,
                Err(err) => {
                    eprintln!("row {}: {err}", entry.row);
                    failed += 1;
                    continue;
                }
            };
        let alternates = crate::native::Alternates::resolve(&nested_archive.path, &opened.metadata);
        for inner in opened.metadata.entries() {
            let Ok(Some(inner_location)) = inner.location else {
                continue;
            };
            if inner_location.type_id != 3 || inner_location.logical_len < min_bytes {
                continue;
            }
            candidates += 1;
            let bytes = match row_bytes(&opened, &alternates, inner.row) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!("row {}/{}: {err}", entry.row, inner.row);
                    failed += 1;
                    continue;
                }
            };
            decoded += 1;
            for (header, stem, rank) in headers(&bytes) {
                let Some(stem) = model_stem(&stem, names) else {
                    continue;
                };
                let Some(model) = names.get(stem) else {
                    continue;
                };
                let candidate = Association {
                    model: model.to_string(),
                    archive_row: entry.row,
                    row: inner.row,
                    header,
                    logical_size: inner_location.logical_len,
                    rank,
                };
                match best.get(&candidate.model) {
                    Some(current) if !candidate.outranks(current) => {}
                    _ => {
                        best.insert(candidate.model.clone(), candidate);
                    }
                }
            }
        }
    }
    Ok(Bodies {
        models: best.into_values().collect(),
        scanned,
        candidates,
        decoded,
        failed,
    })
}

/// Writes the association document and prints the summary or the document.
fn write(output: &Path, bodies: &Bodies, archive: &Path, json_output: bool) -> Result<(), String> {
    let document = json!({
        "schema": BODIES_SCHEMA,
        "archive": file_label(archive),
        "scanned_root_rows": bodies.scanned,
        "candidates": bodies.candidates,
        "decoded": bodies.decoded,
        "failed": bodies.failed,
        "models": bodies
            .models
            .iter()
            .map(|association| json!({
                "model": association.model,
                "archive_row": association.archive_row,
                "row": association.row,
                "header": association.header,
                "logical_size": association.logical_size,
            }))
            .collect::<Vec<Value>>(),
    });
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    }
    std::fs::write(
        output,
        serde_json::to_vec_pretty(&document).map_err(|err| err.to_string())?,
    )
    .map_err(|err| format!("cannot write {}: {err}", output.display()))?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&document).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "{} models with a body fragment written to {}",
            bodies.models.len(),
            output.display()
        );
    }
    Ok(())
}

/// Reads the association document back.
pub fn read(path: &Path) -> Result<Bodies, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| format!("{} is not JSON: {err}", path.display()))?;
    if value.get("schema").and_then(Value::as_str) != Some(BODIES_SCHEMA) {
        return Err(format!(
            "{} is not a {BODIES_SCHEMA} document",
            path.display()
        ));
    }
    let models = value
        .get("models")
        .and_then(Value::as_array)
        .ok_or("the document has no models array")?;
    let mut bodies = Vec::with_capacity(models.len());
    for entry in models {
        let model = entry
            .get("model")
            .and_then(Value::as_str)
            .ok_or("a model entry has no model")?;
        let archive_row = entry
            .get("archive_row")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("model {model} has no archive_row"))?
            as u32;
        let row = entry
            .get("row")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("model {model} has no row"))? as u32;
        let header = entry
            .get("header")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("model {model} has no header"))?;
        let logical_size = entry
            .get("logical_size")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        bodies.push(Association {
            model: model.to_string(),
            archive_row,
            row,
            header: header.to_string(),
            logical_size,
            rank: header_rank(header),
        });
    }
    bodies.sort_by_key(|association| association.model.to_lowercase());
    Ok(Bodies {
        models: bodies,
        scanned: value
            .get("scanned_root_rows")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32,
        candidates: value.get("candidates").and_then(Value::as_u64).unwrap_or(0) as usize,
        decoded: value.get("decoded").and_then(Value::as_u64).unwrap_or(0) as usize,
        failed: value.get("failed").and_then(Value::as_u64).unwrap_or(0) as usize,
    })
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Reads one row's decoded bytes, through the payload transform when it applies.
pub fn row_bytes(
    opened: &crate::native::Opened,
    alternates: &crate::native::Alternates,
    row: u32,
) -> Result<Vec<u8>, String> {
    let entry = opened.metadata.entry(row).map_err(|err| err.to_string())?;
    let transformed = matches!(entry.payload_transform, Ok(true));
    let payload = match entry.payload(&opened.source, alternates.sources()) {
        Ok(payload) => payload,
        Err(err) if transformed => {
            let Some(stream) = opened.stream.as_ref() else {
                return Err(format!(
                    "the payload transform requires the executable that provided the key state: {err}"
                ));
            };
            crate::native::transformed_payload(&entry, &opened.source, alternates, stream)?
        }
        Err(err) => return Err(format!("the row cannot be read: {err}")),
    };
    if payload.len() > MAX_FRAGMENT {
        return Err(format!(
            "the row holds {} bytes, more than the {MAX_FRAGMENT} byte scan limit",
            payload.len()
        ));
    }
    let mut bytes = Vec::with_capacity(payload.len() as usize);
    let mut reader = std::io::Read::take(payload, MAX_FRAGMENT + 1);
    std::io::Read::read_to_end(&mut reader, &mut bytes)
        .map_err(|err| format!("the row cannot be decoded: {err}"))?;
    if bytes.len() as u64 > MAX_FRAGMENT {
        return Err("the row decoded past the scan limit".to_string());
    }
    Ok(bytes)
}

fn header_rank(header: &str) -> u8 {
    let stem = strip_suffix(header).unwrap_or(header);
    if stem.ends_with("_hi") {
        3
    } else if stem.ends_with("_mid") {
        2
    } else if stem.ends_with("_low") {
        0
    } else {
        1
    }
}

fn strip_suffix(text: &str) -> Option<&str> {
    text.strip_suffix(".#ft")
        .or_else(|| text.strip_suffix("#ft"))
        .or_else(|| text.strip_suffix(".#dr"))
        .or_else(|| text.strip_suffix("#dr"))
}

/// Every header a fragment carries, as `(header, stem, rank)`.
///
/// A header is a name that ends in `#ft` or `#dr`. The scan looks for the
/// marker and walks back over the name characters in front of it, which finds a
/// name inside a longer printable run. The scan is byte-wise: a name table is
/// plain ASCII and a UTF-8 reader would only add cost.
pub fn headers(bytes: &[u8]) -> Vec<(String, String, u8)> {
    let mut found: BTreeMap<String, (String, u8)> = BTreeMap::new();
    for index in 0..bytes.len() {
        let rest = &bytes[index..];
        let Some(marker) = marker_len(rest) else {
            continue;
        };
        let mut end = index;
        if end > 0 && bytes[end - 1] == b'.' {
            end -= 1;
        }
        let mut start = end;
        while start > 0 && is_name_byte(bytes[start - 1]) && end - start < HEADER_WINDOW {
            start -= 1;
        }
        if start == end {
            continue;
        }
        let stem = &bytes[start..end];
        let Ok(stem) = std::str::from_utf8(stem) else {
            continue;
        };
        // A header names one model, so a space or a path disqualifies it.
        if stem.contains(' ') || stem.contains('/') {
            continue;
        }
        let header = std::str::from_utf8(&bytes[start..index + marker]).unwrap_or_default();
        let rank = detail_rank(stem);
        found
            .entry(stem.to_string())
            .and_modify(|entry| {
                if rank > entry.1 {
                    *entry = (header.to_string(), rank);
                }
            })
            .or_insert((header.to_string(), rank));
    }
    found
        .into_iter()
        .map(|(stem, (header, rank))| (header, stem, rank))
        .collect()
}

/// The marker at the start of `bytes`, if there is one.
fn marker_len(bytes: &[u8]) -> Option<usize> {
    if bytes.starts_with(b"#ft") || bytes.starts_with(b"#dr") {
        Some(3)
    } else {
        None
    }
}

fn detail_rank(stem: &str) -> u8 {
    if stem.ends_with("_hi") {
        3
    } else if stem.ends_with("_mid") {
        2
    } else if stem.ends_with("_low") {
        0
    } else {
        1
    }
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b' ')
}

/// The stem a listed model is named by.
///
/// A fragment stem carries its detail suffix, so `akane_hi` resolves to
/// `akane`. One archive prefixes a letter the list does not carry, so a stem
/// whose first character is dropped also matches.
pub fn model_stem<'a>(stem: &'a str, names: &Names) -> Option<&'a str> {
    let base = strip_detail_suffix(stem);
    if names.get(base).is_some() {
        return Some(base);
    }
    let mut characters = base.char_indices();
    characters.next()?;
    let rest = &base[characters.next()?.0..];
    names.get(rest).map(|_| rest)
}

fn strip_detail_suffix(stem: &str) -> &str {
    for suffix in ["_hi", "_mid", "_low"] {
        if let Some(base) = stem.strip_suffix(suffix) {
            return base;
        }
    }
    stem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_headers_are_read_with_their_rank() {
        let bytes = b"\x00\x01akane_hi.#ft\x00blista2_mid.#ft\x00sultan.#ft\x00";
        let found = headers(bytes);
        assert_eq!(found.len(), 3);
        assert!(
            found
                .iter()
                .any(|(header, stem, rank)| header == "akane_hi.#ft"
                    && stem == "akane_hi"
                    && *rank == 3)
        );
        assert!(
            found
                .iter()
                .any(|(_, stem, rank)| stem == "blista2_mid" && *rank == 2)
        );
        assert!(
            found
                .iter()
                .any(|(_, stem, rank)| stem == "sultan" && *rank == 1)
        );
    }

    #[test]
    fn a_path_is_not_a_header() {
        assert!(headers(b"levels/americas/foo.#ft\x00").is_empty());
    }

    #[test]
    fn a_name_without_the_marker_is_ignored() {
        assert!(headers(b"akane_hi.dr\x00").is_empty());
    }

    #[test]
    fn the_detail_suffix_is_stripped_when_matching_a_listed_model() {
        let mut names = Names::default();
        names_insert(&mut names, "akane");
        assert_eq!(model_stem("akane_hi", &names), Some("akane"));
        assert_eq!(model_stem("akane", &names), Some("akane"));
        assert_eq!(model_stem("xakane_hi", &names), Some("akane"));
        assert_eq!(model_stem("blista2_hi", &names), None);
    }

    fn names_insert(names: &mut Names, value: &str) {
        let text = value;
        let read = super::super::names::read_from_text(text);
        *names = read;
    }
}
