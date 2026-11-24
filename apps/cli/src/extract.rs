//! `lforge archive extract`: export one native table-of-contents entry,
//! decoded where its storage is supported.
//!
//! The entry is selected by its row index, as `archive metadata --entries`
//! lists it. Both the archive and the output path are treated as untrusted:
//! output is streamed through a bounded buffer into a temporary file in the
//! destination directory and moved into place only after the whole entry
//! decoded, so a failed decode leaves no partial final file and nothing is
//! overwritten unless asked for.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_rage9::rpf::metadata::{Entry, Payload};

use crate::native::{self, Alternates};

/// Larger table-of-contents areas are not read, as in `archive metadata`.
const MAX_METADATA: u64 = 256 * 1024 * 1024;
/// Caps the bytes written for one entry, mirroring the desktop's per-file
/// read limit.
const MAX_OUTPUT: u64 = 512 * 1024 * 1024;
/// Decoded bytes copied per step.
const BUFFER: usize = 64 * 1024;

pub fn run(file: &Path, row: u32, output: &Path, overwrite: bool) -> Result<(), String> {
    let (source, metadata) = native::open_metadata(file, MAX_METADATA)?;
    let rows = metadata.rows();
    if row >= rows {
        return Err(match rows {
            0 => format!("the table of contents of {} has no rows", file.display()),
            1 => format!("row {row} is out of range: the only row is 0"),
            _ => format!("row {row} is out of range: the rows are 0 to {}", rows - 1),
        });
    }
    let entry = metadata.entry(row).map_err(|err| err.to_string())?;
    let alternates = Alternates::resolve(file, &metadata);
    let mut payload = entry
        .payload(&source, alternates.sources())
        .map_err(|err| format!("row {row} cannot be extracted: {err}"))?;
    if payload.len() > MAX_OUTPUT {
        return Err(format!(
            "row {row} holds {} bytes, more than the {} byte output limit",
            payload.len(),
            MAX_OUTPUT
        ));
    }
    if !overwrite && output.exists() {
        return Err(format!(
            "{} already exists; pass --overwrite to replace it",
            output.display()
        ));
    }
    let written = write_output(output, &mut payload, overwrite)?;
    println!(
        "extracted row {row} ({}): {written} bytes to {}",
        kind(&entry),
        output.display()
    );
    Ok(())
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

/// Streams the payload into a temporary file in the destination directory and
/// moves it into place once it decoded completely. Returns the bytes written.
/// The temporary file is removed on any early return, so a failed decode never
/// leaves a partial final file.
fn write_output(output: &Path, payload: &mut Payload, overwrite: bool) -> Result<u64, String> {
    let dir = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut temp = tempfile::NamedTempFile::new_in(&dir)
        .map_err(|err| format!("cannot create a temporary file in {}: {err}", dir.display()))?;

    // Payloads never yield more than their declared size, and large zlib
    // chunks are spooled by the decoder, so this holds little in memory.
    let cancel = AtomicBool::new(false);
    let mut writer = BufWriter::new(temp.as_file_mut());
    let mut buf = vec![0u8; BUFFER];
    let mut written = 0u64;
    loop {
        match payload.read_cancellable(&mut buf, &cancel) {
            Ok(0) => break,
            Ok(n) => {
                writer
                    .write_all(&buf[..n])
                    .map_err(|err| format!("cannot write {}: {err}", output.display()))?;
                written += n as u64;
            }
            Err(err) => return Err(format!("row could not be decoded: {err}")),
        }
    }
    writer
        .flush()
        .map_err(|err| format!("cannot write {}: {err}", output.display()))?;
    drop(writer);

    let persisted = if overwrite {
        temp.persist(output).map(|_| ())
    } else {
        temp.persist_noclobber(output).map(|_| ())
    };
    persisted.map_err(|err| {
        if !overwrite && err.error.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} already exists; pass --overwrite to replace it",
                output.display()
            )
        } else {
            format!("cannot write {}: {}", output.display(), err.error)
        }
    })?;
    Ok(written)
}
