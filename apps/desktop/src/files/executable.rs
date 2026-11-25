//! A user-selected game executable, opened read-only.
//!
//! The executable is a file on the user's computer, chosen in the explorer and
//! remembered in the settings. Nothing here depends on a fixed location or a
//! known build: the file is parsed as a PE32+ image and the metadata
//! authentication pipeline decides whether it is compatible (see
//! [`lforge_rage9::rpf::metadata::verify::open_authenticated`]).
//!
//! The path is kept for revalidation only. It is not logged, and no bytes of
//! the executable, key state or address are stored or written.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lforge_binary::pe::{ExecutableView, MAX_FILE_SIZE};

use super::ListingLayout;
use super::archive::{Stamp, file_stamp};

/// Whether a file is unchanged since it was opened: its length and
/// modification time.
#[derive(Clone)]
pub struct Executable {
    path: PathBuf,
    stamp: Stamp,
    view: ExecutableView,
}

/// Maps the PE reader's failures to I/O errors with a message the explorer can
/// show: [`io::ErrorKind::Unsupported`] for a file that is not a usable image,
/// [`io::ErrorKind::InvalidData`] for a malformed one.
fn to_io(err: lforge_binary::pe::Error) -> io::Error {
    use lforge_binary::pe::Error;
    match err {
        Error::Io(err) => err,
        Error::Unsupported(reason) => io::Error::new(io::ErrorKind::Unsupported, reason),
        Error::Malformed(reason) => io::Error::new(io::ErrorKind::InvalidData, reason),
        err @ Error::ResourceLimit { .. } => io::Error::other(err.to_string()),
    }
}

impl Executable {
    /// Opens `path` read-only and parses its PE headers. Reads no section data
    /// beyond the headers, so this is cheap for a large image.
    pub fn open(path: &Path) -> io::Result<Self> {
        let stamp = file_stamp(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the selected file is missing or is not a regular file",
            )
        })?;
        if stamp.0 > MAX_FILE_SIZE {
            return Err(io::Error::other(format!(
                "the executable is larger than the {} byte limit",
                MAX_FILE_SIZE
            )));
        }
        let view = ExecutableView::open(path).map_err(to_io)?;
        Ok(Self {
            path: path.to_path_buf(),
            stamp,
            view,
        })
    }

    /// Whether the file at the recorded path is still the one that was
    /// opened. A moved, truncated or rebuilt executable is not.
    pub fn is_current(&self) -> bool {
        file_stamp(&self.path) == Some(self.stamp)
    }

    /// The read-only image the authentication pipeline reads.
    pub fn view(&self) -> &ExecutableView {
        &self.view
    }

    /// A file name for messages, so errors never show the full local path.
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "the selected executable".to_string())
    }
}

/// Debug output never includes the path, so logs cannot leak where the
/// executable is stored.
impl fmt::Debug for Executable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executable")
            .field("len", &self.stamp.0)
            .finish_non_exhaustive()
    }
}

/// The executable available to one operation, and how RPF9 rows should be
/// listed. Passing it along instead of reaching for a global keeps each read
/// bound to the source and the view it was opened with.
#[derive(Debug, Clone, Default)]
pub struct Access {
    executable: Option<Arc<Executable>>,
    layout: ListingLayout,
}

impl Access {
    /// No executable: stored metadata that needs processing stays unread.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn with(executable: Arc<Executable>) -> Self {
        Self {
            executable: Some(executable),
            layout: ListingLayout::default(),
        }
    }

    /// The same access with the rows listed in `layout`.
    pub fn with_layout(mut self, layout: ListingLayout) -> Self {
        self.layout = layout;
        self
    }

    pub fn layout(&self) -> ListingLayout {
        self.layout
    }

    /// The executable to authenticate with. A configured executable that has
    /// since changed is still returned; callers check [`Executable::is_current`]
    /// and report the change instead of using stale state.
    pub fn executable(&self) -> Option<&Executable> {
        self.executable.as_deref()
    }

    /// The path and stamp of the executable, for cache validation. `None` when
    /// none is configured.
    pub fn identity(&self) -> Option<(PathBuf, Stamp)> {
        self.executable
            .as_ref()
            .map(|executable| (executable.path.clone(), executable.stamp))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;

    use super::*;

    /// A minimal PE32+ x86-64 image: DOS header, PE signature, one
    /// `.rdata` section. Enough for the header reader; it holds no code.
    pub(crate) fn pe_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        // COFF header: machine, 1 section, optional header size 0xF0.
        bytes[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes());
        // Optional header: PE32+, image base, section alignment, size of image.
        let optional = 0x58;
        bytes[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        // One section header after the optional header.
        let section = optional + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes
    }

    #[test]
    fn a_pe_image_is_accepted_and_its_path_is_not_in_debug_output() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("game.exe");
        fs::write(&path, pe_bytes()).unwrap();
        let executable = Executable::open(&path).unwrap();
        assert_eq!(executable.name(), "game.exe");
        assert!(executable.is_current());
        let debug = format!("{executable:?}");
        assert!(debug.contains("Executable"), "{debug}");
        assert!(!debug.contains("game.exe"), "{debug}");
    }

    #[test]
    fn other_files_are_refused_with_a_reason() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing.exe");
        let err = Executable::open(&missing).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let text = temp.path().join("notes.exe");
        fs::write(&text, b"not an executable").unwrap();
        let err = Executable::open(&text).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("DOS header"), "{err}");

        let malformed = temp.path().join("broken.exe");
        let mut bytes = pe_bytes();
        bytes[0x58..0x5A].copy_from_slice(&0x10Bu16.to_le_bytes());
        fs::write(&malformed, bytes).unwrap();
        let err = Executable::open(&malformed).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("PE32+"), "{err}");
    }

    #[test]
    fn a_changed_file_is_no_longer_current() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("game.exe");
        fs::write(&path, pe_bytes()).unwrap();
        let executable = Executable::open(&path).unwrap();
        let mut longer = pe_bytes();
        longer.extend_from_slice(&[0; 16]);
        fs::write(&path, longer).unwrap();
        assert!(!executable.is_current());
        fs::remove_file(&path).unwrap();
        assert!(!executable.is_current());
    }

    #[test]
    fn access_carries_an_optional_executable() {
        let none = Access::none();
        assert!(none.executable().is_none());
        assert!(none.identity().is_none());

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("game.exe");
        fs::write(&path, pe_bytes()).unwrap();
        let executable = Arc::new(Executable::open(&path).unwrap());
        let access = Access::with(executable);
        assert_eq!(access.identity().map(|(path, _)| path), Some(path.clone()));
        assert!(access.executable().is_some_and(Executable::is_current));
    }
}
