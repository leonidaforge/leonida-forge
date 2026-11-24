//! Shared output writer for the archive export commands.
//!
//! Both native entry extraction (`archive extract`) and scan-recovery export
//! (`archive recover`) stream their decoded bytes through a temporary file in
//! the destination directory and move it into place only once the whole
//! payload decoded. A failed or cancelled decode leaves no partial final file,
//! and an existing file is replaced only with `overwrite`.

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Caps the bytes written for one output, mirroring the desktop's per-file
/// read limit.
pub const MAX_OUTPUT: u64 = 512 * 1024 * 1024;
/// Decoded bytes copied per step by a pull-based producer.
pub const BUFFER: usize = 64 * 1024;

/// Streams a decoded payload into a temporary file in `output`'s directory and
/// moves it into place once `produce` returns. `produce` writes the whole
/// payload to the writer it is given and returns the number of bytes written.
///
/// The temporary file is removed on any early return, so a failed or cancelled
/// decode never leaves a partial final file. An existing file is replaced only
/// when `overwrite` is set; otherwise the move refuses to clobber it, and the
/// existing bytes are preserved on any decode or finalization failure.
pub fn write_file(
    output: &Path,
    overwrite: bool,
    produce: impl FnOnce(&mut dyn Write) -> Result<u64, String>,
) -> Result<u64, String> {
    if !overwrite && output.exists() {
        return Err(already_exists(output));
    }
    let dir = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut temp = tempfile::NamedTempFile::new_in(&dir)
        .map_err(|err| format!("cannot create a temporary file in {}: {err}", dir.display()))?;

    let mut writer = BufWriter::new(temp.as_file_mut());
    let written = produce(&mut writer)?;
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
            already_exists(output)
        } else {
            format!("cannot write {}: {}", output.display(), err.error)
        }
    })?;
    Ok(written)
}

/// Translates a write error from a producer into a message that names the
/// destination, for producers that write directly to the shared writer.
pub fn write_error(output: &Path, err: std::io::Error) -> String {
    format!("cannot write {}: {err}", output.display())
}

fn already_exists(output: &Path) -> String {
    format!(
        "{} already exists; pass --overwrite to replace it",
        output.display()
    )
}
