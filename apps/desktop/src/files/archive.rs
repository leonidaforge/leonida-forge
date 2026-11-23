//! Archive files that can be browsed like folders.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::SystemTime;

use super::{Entry, rpf, zip};

/// Caps what reading one file from an archive may allocate in memory or on disk.
pub const MAX_READ: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Rpf9,
}

/// The archive format of a file. RPF files must also start with the RPF9
/// signature; only files with an archive extension are opened to check it.
pub fn format(path: &Path) -> Option<Format> {
    let extension = path.extension()?;
    if extension.eq_ignore_ascii_case("zip") {
        Some(Format::Zip)
    } else if extension.eq_ignore_ascii_case("rpf") && has_rpf9_signature(path) {
        Some(Format::Rpf9)
    } else {
        None
    }
}

fn has_rpf9_signature(path: &Path) -> bool {
    let mut signature = [0u8; 4];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut signature))
        .is_ok_and(|()| lforge_rage9::rpf::is_rpf9(&signature))
}

pub fn is_archive(path: &Path) -> bool {
    format(path).is_some()
}

/// Splits a path that continues inside an archive file into the archive and
/// the path within it. Returns `None` for plain filesystem paths. For the
/// archive file itself, the path within it is empty.
pub fn locate(path: &Path) -> Option<(&Path, &Path)> {
    let archive = path
        .ancestors()
        .find(|ancestor| ancestor.is_file() && is_archive(ancestor))?;
    Some((archive, path.strip_prefix(archive).ok()?))
}

fn format_of(archive: &Path) -> io::Result<Format> {
    format(archive).ok_or_else(|| io::Error::other("not a supported archive"))
}

/// Lists the direct children of `inner`.
pub fn list(archive: &Path, inner: &Path) -> io::Result<Vec<Entry>> {
    match format_of(archive)? {
        Format::Zip => zip::list(archive, inner),
        Format::Rpf9 => rpf::list(archive, inner),
    }
}

/// Reads one file from the archive into memory.
pub fn read(archive: &Path, inner: &Path) -> io::Result<Vec<u8>> {
    match format_of(archive)? {
        Format::Zip => zip::read(archive, inner),
        Format::Rpf9 => rpf::read(archive, inner),
    }
}

/// Decompresses one file into an anonymous temporary file, for random access
/// without holding it in memory. Windows deletes the temporary file when its
/// last handle closes, also when the process exits abnormally.
pub fn extract(archive: &Path, inner: &Path) -> io::Result<(File, Option<SystemTime>)> {
    match format_of(archive)? {
        Format::Zip => zip::extract(archive, inner),
        Format::Rpf9 => Ok((rpf::extract(archive, inner)?, None)),
    }
}

pub fn check_size(size: u64, limit: u64) -> io::Result<()> {
    if size > limit {
        return Err(io::Error::other(format!(
            "the file is too large to read from the archive (limit {})",
            super::format_size(limit)
        )));
    }
    Ok(())
}
