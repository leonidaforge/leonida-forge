//! Companion files: the alternate read sources that `B` sub-block 3 lists.
//!
//! Record `i` is the source of entries with read-source index `i`. Payload
//! offsets are the same in every source. A companion begins with a 16-byte
//! header: the bytes `00 00 00 39 56 46 50 52`, then the record's identifier
//! as a little-endian `u64`.
//!
//! Unlike the engine, this checks every bound, refuses names that leave the
//! archive's directory, and tries every record instead of stopping at the
//! first one that cannot be opened.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use lforge_binary::Source;

use super::{Error, Metadata, array, find_sub_block, invalid, u32_at, u64_at};

const SUB_BLOCK: u16 = 3;
const HEADER_LEN: usize = 8;
const RECORD_LEN: usize = 0x108;
const NAME_LEN: usize = 0x100;
/// The first eight bytes of a companion.
pub const MAGIC: [u8; 8] = [0, 0, 0, 0x39, 0x56, 0x46, 0x50, 0x52];

/// One record of sub-block 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Companion {
    /// The read-source index that selects this companion.
    pub index: u32,
    /// The name up to its NUL, or all 0x100 bytes if it has none.
    pub name: Vec<u8>,
    pub terminated: bool,
    /// Expected in bytes 8 to 15 of the companion.
    pub identifier: u64,
}

/// Sub-block 3. Empty if the archive has none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Companions {
    /// Bytes 4 to 7 of the sub-block, which no traced code reads.
    pub unknown_04: [u8; 4],
    pub records: Vec<Companion>,
}

/// Whether a companion can be read from.
#[derive(Debug, Clone)]
pub enum Status {
    Available(Source),
    /// The file does not exist or cannot be opened.
    Missing(String),
    /// The file or its name fails the checks.
    Invalid(String),
    /// The companion cannot be resolved where the archive is, for example
    /// inside another archive, or its name uses unsupported characters.
    Unsupported(String),
}

impl Status {
    pub fn source(&self) -> Option<&Source> {
        match self {
            Status::Available(source) => Some(source),
            _ => None,
        }
    }
}

impl Metadata {
    /// The companion records, in order. The whole sub-block must lie inside
    /// the `B` block.
    pub fn companions(&self) -> Result<Companions, Error> {
        let a_table = self
            .bytes
            .get(self.layout.a_table.clone())
            .unwrap_or_default();
        let Some(offset) = find_sub_block(a_table, SUB_BLOCK) else {
            return Ok(Companions::default());
        };
        let b = &self.layout.b_block;
        let outside = || invalid("B sub-block 3 does not fit in the B block");
        let start = b
            .start
            .checked_add(offset as usize)
            .filter(|start| {
                start
                    .checked_add(HEADER_LEN)
                    .is_some_and(|end| end <= b.end)
            })
            .ok_or_else(outside)?;
        let header = &self.bytes[start..start + HEADER_LEN];
        let count = u32_at(header, 0).ok_or_else(outside)?;
        let unknown_04 = array(header, 4).ok_or_else(outside)?;
        let records = start + HEADER_LEN;
        let end = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(RECORD_LEN))
            .and_then(|len| records.checked_add(len))
            .filter(|end| *end <= b.end)
            .ok_or_else(|| {
                invalid(format!(
                    "B sub-block 3 lists {count} companions, more than fit in the B block"
                ))
            })?;
        let records = self.bytes[records..end]
            .as_chunks::<RECORD_LEN>()
            .0
            .iter()
            .enumerate()
            .map(|(index, record)| {
                let name = &record[..NAME_LEN];
                let nul = name.iter().position(|&b| b == 0);
                Companion {
                    index: index as u32,
                    name: name[..nul.unwrap_or(NAME_LEN)].to_vec(),
                    terminated: nul.is_some(),
                    identifier: u64_at(record, NAME_LEN).unwrap_or_default(),
                }
            })
            .collect();
        Ok(Companions {
            unknown_04,
            records,
        })
    }
}

/// Characters that are not allowed in a component.
fn unsupported_char(c: char) -> bool {
    c.is_control() || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*')
}

impl Companion {
    /// The name as a path relative to the archive's directory. `..` may not
    /// leave that directory.
    fn relative_path(&self) -> Result<PathBuf, Status> {
        if !self.terminated {
            return Err(Status::Invalid("the name is not terminated".into()));
        }
        let name = std::str::from_utf8(&self.name)
            .map_err(|_| Status::Unsupported("the name is not UTF-8".into()))?;
        if name.starts_with(['/', '\\']) {
            return Err(Status::Invalid(format!("the name {name:?} is absolute")));
        }
        let mut parts: Vec<&str> = Vec::new();
        for part in name.split(['/', '\\']) {
            match part {
                "" | "." => {}
                ".." => {
                    if parts.pop().is_none() {
                        return Err(Status::Invalid(format!(
                            "the name {name:?} leaves the archive's directory"
                        )));
                    }
                }
                part if part.chars().any(unsupported_char) => {
                    return Err(Status::Unsupported(format!(
                        "the name {name:?} contains unsupported characters"
                    )));
                }
                part => parts.push(part),
            }
        }
        if parts.is_empty() {
            return Err(Status::Invalid(format!("the name {name:?} names no file")));
        }
        Ok(parts.iter().collect())
    }

    /// Where the companion is expected, in `dir`, the directory of the
    /// archive file. `None` for a name that is refused.
    pub fn path(&self, dir: &Path) -> Option<PathBuf> {
        self.relative_path().ok().map(|relative| dir.join(relative))
    }

    /// Opens the companion in `dir` and checks its header. The file must
    /// resolve, through links, to a regular file inside `dir`.
    pub fn open(&self, dir: &Path) -> Status {
        let relative = match self.relative_path() {
            Ok(relative) => relative,
            Err(status) => return status,
        };
        let path = dir.join(&relative);
        let real = match fs::canonicalize(&path) {
            Ok(real) => real,
            Err(err) => return Status::Missing(format!("{}: {err}", path.display())),
        };
        let root = match fs::canonicalize(dir) {
            Ok(root) => root,
            Err(err) => return Status::Missing(format!("{}: {err}", dir.display())),
        };
        if !real.starts_with(&root) {
            return Status::Invalid(format!(
                "{} resolves to a file outside the archive's directory",
                path.display()
            ));
        }
        if !fs::metadata(&real).is_ok_and(|metadata| metadata.is_file()) {
            return Status::Invalid(format!("{} is not a file", path.display()));
        }
        let source = match Source::open(&real) {
            Ok(source) => source,
            Err(err) => return Status::Missing(format!("{}: {err}", path.display())),
        };
        match self.check(&source) {
            Ok(()) => Status::Available(source),
            Err(reason) => Status::Invalid(format!("{}: {reason}", path.display())),
        }
    }

    /// Checks the 16-byte header.
    pub fn check(&self, source: &Source) -> Result<(), String> {
        let mut header = [0; 16];
        let mut reader = source.clone();
        reader
            .read_exact(&mut header)
            .map_err(|err| match err.kind() {
                io::ErrorKind::UnexpectedEof => "it is shorter than its 16-byte header".to_string(),
                _ => err.to_string(),
            })?;
        if header[..8] != MAGIC {
            return Err("it does not start with the companion signature".into());
        }
        let identifier = u64_at(&header, 8).unwrap_or_default();
        if identifier != self.identifier {
            return Err(format!(
                "its identifier is {identifier:#018x}, not {:#018x}",
                self.identifier
            ));
        }
        Ok(())
    }
}

impl Companions {
    /// Opens every companion of an archive stored in the file `archive`.
    /// The result has one status per record, so index `i` stays record `i`.
    pub fn open(&self, archive: &Path) -> Vec<Status> {
        let dir = match archive.parent() {
            Some(dir) if dir.as_os_str().is_empty() => Path::new("."),
            Some(dir) => dir,
            None => {
                let reason = "the archive file has no directory";
                return vec![Status::Unsupported(reason.into()); self.records.len()];
            }
        };
        self.records.iter().map(|record| record.open(dir)).collect()
    }
}
