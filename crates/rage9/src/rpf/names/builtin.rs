//! The name mappings the application carries.
//!
//! One LUT per namespace is embedded in the binary. A file with the same name
//! beside the executable is read as well and merged after the embedded
//! records, so a newer table can be dropped in without rebuilding. Nothing is
//! read from beside an archive: the file there is a `<archive>.names.txt` table
//! of candidate paths.

use std::path::{Path, PathBuf};

use super::lut::{Lut, LutError};
use super::table::StringTable;

const HASH64_FILE: &str = "rpf9-hash64.lut";
const KEY32_FILE: &str = "rpf9-key32.lut";

/// The file names the application reads beside the executable.
pub const FILES: [&str; 2] = [HASH64_FILE, KEY32_FILE];

const EMBEDDED: [(&str, &[u8]); 2] = [
    (HASH64_FILE, include_bytes!("../../../data/rpf9-hash64.lut")),
    (KEY32_FILE, include_bytes!("../../../data/rpf9-key32.lut")),
];

/// One LUT and what became of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The file name. The embedded record and a file beside the executable
    /// share it.
    pub file: &'static str,
    /// The file the records were read from. `None` for the embedded record.
    pub path: Option<PathBuf>,
    /// Records in the file.
    pub entries: usize,
    /// Records whose name reproduces their key.
    pub verified: usize,
    /// Records the table kept. The rest were exact duplicates.
    pub added: usize,
    /// Why the file was not used.
    pub problem: Option<String>,
}

/// The embedded LUTs and the ones beside the executable, merged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builtin {
    table: StringTable,
    sources: Vec<Source>,
}

impl Builtin {
    /// The embedded tables, then the files of the same names in `dir`.
    pub fn load(dir: Option<&Path>) -> Self {
        let mut builtin = Self::default();
        for (file, bytes) in EMBEDDED {
            builtin.add(file, None, Lut::parse(bytes));
        }
        let Some(dir) = dir else {
            return builtin;
        };
        for file in FILES {
            let path = dir.join(file);
            if path.is_file() {
                builtin.add(file, Some(path.clone()), Lut::read(&path));
            }
        }
        builtin
    }

    /// [`Builtin::load`] for the directory of the running executable.
    pub fn beside_executable() -> Self {
        Self::load(executable_dir().as_deref())
    }

    pub fn table(&self) -> &StringTable {
        &self.table
    }

    /// Every LUT that was found, embedded first.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// The LUTs that could not be used.
    pub fn problems(&self) -> impl Iterator<Item = &Source> {
        self.sources
            .iter()
            .filter(|source| source.problem.is_some())
    }

    pub fn is_empty(&self) -> bool {
        self.table.entries().is_empty()
    }

    fn add(&mut self, file: &'static str, path: Option<PathBuf>, lut: Result<Lut, LutError>) {
        let source = match lut {
            Ok(lut) => Source {
                file,
                path,
                entries: lut.entries().len(),
                verified: lut.verified(),
                added: self.table.merge_lut(&lut),
                problem: None,
            },
            Err(err) => Source {
                file,
                path,
                entries: 0,
                verified: 0,
                added: 0,
                problem: Some(err.to_string()),
            },
        };
        self.sources.push(source);
    }
}

/// The directory of the running executable, the one searched for LUT files.
pub fn executable_dir() -> Option<PathBuf> {
    Some(std::env::current_exe().ok()?.parent()?.to_path_buf())
}

#[cfg(test)]
mod tests;
