//! `lforge archive extract`: export one native table-of-contents entry,
//! decoded where its storage is supported.
//!
//! The entry is selected by its row index, as `archive metadata --entries`
//! lists it. Both the archive and the output path are treated as untrusted:
//! the decoded bytes go through [`crate::output::write_file`], which streams
//! them into a temporary file in the destination directory and moves it into
//! place only after the whole entry decoded, so a failed decode leaves no
//! partial final file and nothing is overwritten unless asked for.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use lforge_rage9::rpf::metadata::{Entry, Payload};

use crate::native::{self, Alternates};
use crate::output;

/// Larger table-of-contents areas are not read, as in `archive metadata`.
const MAX_METADATA: u64 = 256 * 1024 * 1024;

pub fn run(
    file: &Path,
    row: u32,
    output: &Path,
    overwrite: bool,
    executable: Option<&Path>,
) -> Result<(), String> {
    let opened = native::open_metadata(file, MAX_METADATA, executable)?;
    let source = opened.source;
    let metadata = opened.metadata;
    let rows = metadata.rows();
    if row >= rows {
        return Err(match rows {
            0 => format!("the table of contents of {} has no rows", file.display()),
            1 => format!("row {row} is out of range: the only row is 0"),
            _ => format!("row {row} is out of range: the rows are 0 to {}", rows - 1),
        });
    }
    let entry = metadata.entry(row).map_err(|err| err.to_string())?;
    output::ensure_not_input(output, &[file])?;
    let alternates = Alternates::resolve(file, &metadata);
    let mut payload = entry
        .payload(&source, alternates.sources())
        .map_err(|err| format!("row {row} cannot be extracted: {err}"))?;
    if payload.len() > output::MAX_OUTPUT {
        return Err(format!(
            "row {row} holds {} bytes, more than the {} byte output limit",
            payload.len(),
            output::MAX_OUTPUT
        ));
    }
    let written = output::write_file(output, overwrite, |writer| {
        decode(&mut payload, writer, output)
    })?;
    println!(
        "extracted row {row} ({}): {written} bytes to {}",
        kind(&entry),
        output.display()
    );
    Ok(())
}

/// Pulls the decoded payload and writes it to `writer`, within the scanner's
/// own decompression limits. Cancellation is accepted so the shape matches the
/// recovery path; Ctrl+C ends the process and the temporary file is discarded.
fn decode(
    payload: &mut Payload,
    writer: &mut dyn std::io::Write,
    output: &Path,
) -> Result<u64, String> {
    let cancel = AtomicBool::new(false);
    let mut buf = vec![0u8; output::BUFFER];
    let mut written = 0u64;
    loop {
        match payload.read_cancellable(&mut buf, &cancel) {
            Ok(0) => break,
            Ok(n) => {
                writer
                    .write_all(&buf[..n])
                    .map_err(|err| output::write_error(output, err))?;
                written += n as u64;
            }
            Err(err) => return Err(format!("row could not be decoded: {err}")),
        }
    }
    Ok(written)
}

/// How the entry's contents are stored, for the summary line.
fn kind(entry: &Entry) -> &'static str {
    if matches!(&entry.chunks, Ok(Some(_))) {
        "chunked"
    } else if matches!(&entry.location, Ok(Some(location)) if location.mode == 1) {
        "raw DEFLATE"
    } else {
        "stored"
    }
}
