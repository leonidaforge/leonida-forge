//! `lforge archive recover`: inspect the entries recovered by scanning an
//! RPF9 archive's data area, and export one of them.
//!
//! Candidates are the entries the shared scanner carves from the data area
//! (see [`lforge_rage9::rpf::scan`]): zlib streams that inflated completely,
//! grouped into files and resources. They are not native table-of-contents
//! entries. Each is identified by the archive offset of its first stream,
//! which the scan always produces for unchanged input, so the id is stable
//! across independent scans.
//!
//! This path is kept separate from native extraction (`archive extract`): it
//! never claims an original name, invents entry metadata or treats a
//! successful decompression as cryptographic authenticity. Observed byte
//! facts are reported apart from the inferred kind and completeness, and a
//! selected candidate is re-decoded and checked against the index before it is
//! written. Only the shared output writer is common to both paths.

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_rage9::Status;
use lforge_rage9::rpf::{self, Entry, Index, Kind};
use serde_json::{Value, json};

use crate::archive;
use crate::output;

const NOTE: &str = "Candidates are entries recovered by scanning the archive data for zlib \
     streams; the encrypted table of contents is not read. They are not native entries. Offsets, \
     ranges, sizes and compression are observed; kind and completeness are inferred. Original \
     names and paths are unknown, and this is not a complete archive inventory.";

const NOTHING: &str = "No zlib streams were found, so there are no recovery candidates. This does \
     not mean the archive is empty.";

/// The schema of a recovery list document. `inferred.kind` uses the
/// corrected kind names; a PSIN payload is `psin`, not `pso`.
const LIST_SCHEMA: &str = "leonida-forge.recovery-list/1";

pub struct Options {
    pub file: PathBuf,
    pub list: bool,
    pub id: Option<u64>,
    pub output: Option<PathBuf>,
    pub overwrite: bool,
    pub no_cache: bool,
    pub json: bool,
}

pub fn run(options: Options) -> Result<(), String> {
    let (index, _) = archive::index(&options.file, options.no_cache)?;
    if options.list {
        return list(&index, options.json);
    }
    // clap guarantees exactly one of --list or --id, and --output with --id.
    let id = options.id.expect("--id required without --list");
    let output = options
        .output
        .as_deref()
        .expect("--output required with --id");
    export(&options.file, &index, id, output, options.overwrite)
}

/// The source byte range the candidate's streams cover: the first stream's
/// offset to the aligned end of the last stream.
fn range(index: &Index, entry: &Entry) -> (u64, u64) {
    let streams = index.entry_streams(entry);
    let start = entry.offset;
    let end = streams
        .last()
        .and_then(|stream| stream.aligned_end())
        .unwrap_or(start);
    (start, end)
}

/// The recognised file signature at the start of the bytes, where there is
/// one. `text` and `binary` candidates have no signature; their kind is a
/// heuristic, not an observed marker.
fn signature(kind: Kind) -> Option<&'static str> {
    kind.is_file_start().then(|| kind.name())
}

/// Why a candidate that is not complete may not hold a whole file.
fn caveat(status: Status) -> Option<&'static str> {
    match status {
        Status::Complete => None,
        Status::Partial => Some("its end was not found, so trailing bytes may be missing"),
        Status::Unverified => {
            Some("it has no file signature and may be a whole file or part of one")
        }
    }
}

fn list(index: &Index, json: bool) -> Result<(), String> {
    let out = io::stdout().lock();
    let mut out = BufWriter::new(out);
    let result = if json {
        list_json(index, &mut out)
    } else {
        list_text(index, &mut out)
    };
    result
        .and_then(|()| out.flush())
        .or_else(archive::ignore_broken_pipe)
        .map_err(|err| format!("cannot write output: {err}"))
}

fn candidate_json(index: &Index, entry: &Entry) -> Value {
    let (start, end) = range(index, entry);
    json!({
        "id": archive::id(entry.offset),
        "observed": {
            "offset": entry.offset,
            "start": start,
            "end": end,
            "compression": "zlib",
            "streams": entry.stream_count(),
            "compressed_size": entry.stored_len,
            "decoded_size": entry.len,
            "signature": signature(entry.kind),
        },
        "inferred": {
            "kind": entry.kind.name(),
            "status": entry.status.name(),
        },
        "exportable": true,
    })
}

fn list_json(index: &Index, out: &mut impl Write) -> io::Result<()> {
    let candidates: Vec<Value> = index
        .entries
        .iter()
        .map(|entry| candidate_json(index, entry))
        .collect();
    let listing = json!({
        "schema": LIST_SCHEMA,
        "note": if index.entries.is_empty() {
            format!("{NOTE} {NOTHING}")
        } else {
            NOTE.to_string()
        },
        "table_of_contents": "encrypted, not read",
        "names": "none recovered; ids are archive offsets",
        "candidates": candidates,
    });
    serde_json::to_writer_pretty(&mut *out, &listing)?;
    writeln!(out)
}

fn list_text(index: &Index, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{NOTE}")?;
    if index.entries.is_empty() {
        writeln!(out, "{NOTHING}")?;
        return Ok(());
    }
    writeln!(out)?;
    writeln!(
        out,
        "{:<12} {:<9} {:<4} {:<11} {:>12} {:>12} {:>7}  range",
        "id", "kind", "sig", "status", "decoded", "compressed", "streams"
    )?;
    for entry in &index.entries {
        let (start, end) = range(index, entry);
        writeln!(
            out,
            "{:<12} {:<9} {:<4} {:<11} {:>12} {:>12} {:>7}  {:#x}..{:#x}",
            archive::id(entry.offset),
            entry.kind.name(),
            if signature(entry.kind).is_some() {
                "yes"
            } else {
                "-"
            },
            entry.status.name(),
            entry.len,
            entry.stored_len,
            entry.stream_count(),
            start,
            end,
        )?;
    }
    Ok(())
}

fn export(
    file: &Path,
    index: &Index,
    offset: u64,
    output: &Path,
    overwrite: bool,
) -> Result<(), String> {
    let entry = index
        .entry_at(offset)
        .ok_or_else(|| missing(index, offset))?;
    if entry.len > output::MAX_OUTPUT {
        return Err(format!(
            "candidate {} holds {} bytes, more than the {} byte output limit",
            archive::id(entry.offset),
            entry.len,
            output::MAX_OUTPUT
        ));
    }
    let source = lforge_binary::Source::open(file)
        .map_err(|err| format!("cannot open {}: {err}", file.display()))?;
    let identifier = archive::id(entry.offset);
    let written = output::write_file(output, overwrite, |writer| {
        // Ctrl+C ends the process and the temporary file is discarded; the
        // flag is accepted so the shape matches the native extraction path.
        let cancel = AtomicBool::new(false);
        rpf::read_entry(source, index, entry, output::MAX_OUTPUT, writer, &cancel)
            .map_err(|err| format!("candidate {identifier} could not be decoded: {err}"))
    })?;
    println!(
        "recovered {} ({}, {}): {written} bytes to {}",
        archive::id(entry.offset),
        entry.kind.name(),
        entry.status.name(),
        output.display()
    );
    if let Some(caveat) = caveat(entry.status) {
        println!("note: this candidate is {}; {caveat}", entry.status.name());
    }
    Ok(())
}

/// Explains why `offset` is not a recovery candidate, distinguishing a
/// resource page or an unrecovered region from an unknown id, so a validation
/// failure never silently falls back to another candidate.
fn missing(index: &Index, offset: u64) -> String {
    let id = archive::id(offset);
    if index.page_at(offset).is_some() {
        format!(
            "{id} is a resource page, not a recovery candidate; export the whole resource by its \
             id, or inspect pages with `archive resource`"
        )
    } else if index.region_at(offset).is_some() {
        format!(
            "{id} is an unrecovered region: bytes that are not zlib streams, not a recovery \
             candidate"
        )
    } else {
        format!("no recovery candidate has the id {id}; run `archive recover --list` to see them")
    }
}
