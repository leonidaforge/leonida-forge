//! RPF9 archives listed from their own table of contents.
//!
//! Only metadata that the engine reads as stored is used. Metadata that the
//! engine decrypts first is not read; such archives are recovered by
//! scanning instead (see [`super::rpf`]).
//!
//! The table holds hashes of entry names, not names. Each entry is a file
//! named after its row, `Row 00042`, which identifies it within the archive.
//! Original names are shown only where a candidate path from
//! `<archive file>.names.txt`, next to the file on disk, has the entry's
//! hash. Candidate paths are relative to the archive.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use lforge_binary::Source;
use lforge_rage9::rpf::metadata::{Entry as Row, Error, Stored};
use lforge_rage9::rpf::names::{self, Candidate, Matches, MountPrefix, Types};

use super::archive::{Archive, Stamp, check_size};
use super::{Entry, EntryKind, format_bytes_exact, format_size};

/// Larger tables of contents are not read.
const MAX_METADATA: u64 = 64 * 1024 * 1024;
/// Larger candidate files are ignored.
const MAX_NAMES: u64 = 16 * 1024 * 1024;
pub const NAMES_SUFFIX: &str = ".names.txt";

const ROW_NOTE: &str = "Listed from the archive's table of contents. The name is the row \
     number: the table stores a hash of the original name, not the name.";

/// The candidate paths and which rows they name.
struct Names {
    file: PathBuf,
    stamp: Stamp,
    candidates: Vec<Vec<u8>>,
    matches: Option<Matches>,
    /// Why the file was not used.
    problem: Option<String>,
}

pub struct Native {
    rows: Vec<Row>,
    names: Option<Names>,
}

fn names_file(archive: &Archive) -> PathBuf {
    let mut name = archive.root.file_name().unwrap_or_default().to_os_string();
    name.push(NAMES_SUFFIX);
    archive.root.with_file_name(name)
}

fn stamp(path: &Path) -> Option<Stamp> {
    let metadata = fs::metadata(path).ok()?;
    metadata
        .is_file()
        .then(|| (metadata.len(), metadata.modified().ok()))
}

/// Rows whose names can be matched: with a location record and well-formed
/// name fields.
fn matchable(row: &Row) -> bool {
    matches!(row.location, Ok(Some(_))) && row.name_hash.is_ok() && row.name_key.is_ok()
}

impl Names {
    fn read(file: PathBuf, rows: &[Row]) -> Option<Self> {
        let stamp = stamp(&file)?;
        let mut names = Self {
            file,
            stamp,
            candidates: Vec::new(),
            matches: None,
            problem: None,
        };
        if stamp.0 > MAX_NAMES {
            names.problem = Some(format!("it is larger than {}", format_size(MAX_NAMES)));
            return Some(names);
        }
        let mut text = Vec::new();
        if let Err(err) =
            fs::File::open(&names.file).and_then(|file| file.take(MAX_NAMES).read_to_end(&mut text))
        {
            names.problem = Some(err.to_string());
            return Some(names);
        }
        names.candidates = text
            .split(|&b| b == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .filter(|line| !line.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        let candidates: Vec<Candidate> = names
            .candidates
            .iter()
            .map(|c| Candidate::Path(c))
            .collect();
        let rows: Vec<Row> = rows.iter().filter(|row| matchable(row)).cloned().collect();
        match names::match_entries(&rows, &MountPrefix::EMPTY, &Types::default(), &candidates) {
            Ok(matches) => names.matches = Some(matches),
            Err(err) => names.problem = Some(err.to_string()),
        }
        Some(names)
    }
}

/// Maps entry errors to I/O errors: unsupported for encoded entries and
/// unavailable read sources, invalid data for malformed ones.
fn to_io(err: Error) -> io::Error {
    match err {
        Error::Io(err) => err,
        err @ (Error::Encoded { .. } | Error::ReadSource { .. }) => {
            io::Error::new(io::ErrorKind::Unsupported, err.to_string())
        }
        err => io::Error::new(io::ErrorKind::InvalidData, err.to_string()),
    }
}

/// `Row 00042`. Tables have at most 65535 rows.
fn row_name(row: u32) -> String {
    format!("Row {row:05}")
}

/// The row of a name made by [`row_name`]. Other spellings are rejected, so
/// each entry has exactly one path.
fn parse_row_name(name: &str) -> Option<u32> {
    let row = name.strip_prefix("Row ")?.parse().ok()?;
    (row_name(row) == name).then_some(row)
}

fn not_found() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "the path does not exist in the archive",
    )
}

fn hex<T: std::fmt::UpperHex>(value: T, digits: usize) -> String {
    format!("0x{value:0digits$X}")
}

fn size_text(len: u64) -> String {
    format!("{} ({} bytes)", format_size(len), format_bytes_exact(len))
}

impl Native {
    /// The table of contents of `archive`, or why it is not used.
    pub fn read(archive: &Archive) -> Result<Self, Arc<str>> {
        let unreadable =
            |err: Error| Arc::from(format!("The table of contents could not be read: {err}."));
        let stored = Stored::read(&mut archive.source.clone(), MAX_METADATA).map_err(unreadable)?;
        let metadata = match stored.decode() {
            Ok(metadata) => metadata,
            Err(Error::Transformed(_)) => {
                return Err(Arc::from(
                    "The table of contents is encrypted and is not read.",
                ));
            }
            Err(err) => return Err(unreadable(err)),
        };
        let rows: Vec<Row> = metadata.entries().collect();
        let names = Names::read(names_file(archive), &rows);
        Ok(Self { rows, names })
    }

    /// Whether the candidate file is unchanged since the table was read.
    pub fn is_current(&self, archive: &Archive) -> bool {
        let now = stamp(&names_file(archive));
        now == self.names.as_ref().map(|names| names.stamp)
    }

    fn row(&self, inner: &Path) -> Option<&Row> {
        let mut components = inner.components();
        let (Some(Component::Normal(name)), None) = (components.next(), components.next()) else {
            return None;
        };
        let row = parse_row_name(name.to_str()?)?;
        self.rows.get(usize::try_from(row).ok()?)
    }

    fn matched_names(&self, row: u32) -> Option<(Vec<String>, bool)> {
        let names = self.names.as_ref()?;
        let matched = names.matches.as_ref()?.row(row)?;
        let list = matched
            .candidates
            .iter()
            .map(|&n| String::from_utf8_lossy(&names.candidates[n]).into_owned())
            .collect();
        Some((list, matched.ambiguous))
    }

    fn names_text(&self, row: &Row) -> String {
        if !matchable(row) {
            return "Unknown: the row is malformed".to_string();
        }
        match &self.names {
            None => "Unknown".to_string(),
            Some(names) if names.matches.is_none() => {
                format!("Unknown: {} was not used", names.file.display())
            }
            Some(_) => match self.matched_names(row.row) {
                Some((list, _)) if list.is_empty() => {
                    "Unknown: no candidate path has this entry's hash".to_string()
                }
                Some((list, true)) => format!(
                    "Ambiguous: {} (each has this entry's hash)",
                    list.join(", ")
                ),
                Some((list, false)) => list.join(", "),
                None => "Unknown".to_string(),
            },
        }
    }

    fn entry(&self, archive: &Archive, dir: &Path, row: &Row) -> Entry {
        let name = row_name(row.row);
        let location = match &row.location {
            Ok(Some(location)) => Some(location),
            _ => None,
        };
        let kind = match location {
            Some(_) => EntryKind::File,
            None => EntryKind::Unavailable,
        };
        let mut entry = Entry::new(
            name.clone(),
            dir.join(&name),
            kind,
            location.map(|l| l.logical_len),
            None,
        );
        entry.order = Some(row.row.into());
        entry.type_name = match location {
            Some(l) if l.type_id == names::RPF_TYPE => "RPF9 entry, type 0 (rpf)".to_string(),
            Some(l) => format!("RPF9 entry, type {}", l.type_id),
            None => "RPF9 entry, unreadable".to_string(),
        };
        let malformed = |reason: &String| format!("Malformed: {reason}");
        let mut details = vec![
            (
                "Row",
                format!("{} (identifies the entry in this archive)", row.row),
            ),
            ("Names", self.names_text(row)),
        ];
        match &row.name_hash {
            Ok(Some(hash)) => details.push(("Name hash", hex(*hash, 16))),
            Ok(None) => {}
            Err(reason) => details.push(("Name hash", malformed(reason))),
        }
        match &row.name_key {
            Ok(Some(key)) => details.push(("Name key", hex(*key, 8))),
            Ok(None) => {}
            Err(reason) => details.push(("Name key", malformed(reason))),
        }
        match &row.location {
            Ok(Some(l)) => details.extend([
                ("Location record", format!("{:?} layout", l.layout)),
                ("Payload offset", format!("{:#x}", l.payload_offset)),
                ("Stored size", size_text(l.stored_len)),
                (
                    "Compression",
                    match l.mode {
                        0 => "None".to_string(),
                        mode => format!("Mode {mode}, not supported"),
                    },
                ),
            ]),
            Ok(None) => details.push(("Location record", "Missing".to_string())),
            Err(reason) => details.push(("Location record", malformed(reason))),
        }
        match &row.chunks {
            Ok(Some(chunks)) => details.push((
                "Chunks",
                format!(
                    "{} in encoding {}, not supported",
                    chunks.chunks.len(),
                    chunks.encoding
                ),
            )),
            Ok(None) => {}
            Err(reason) => details.push(("Chunks", malformed(reason))),
        }
        match &row.payload_transform {
            Ok(true) => details.push(("Payload transform", "Required, not supported".to_string())),
            Ok(false) => {}
            Err(reason) => details.push(("Payload transform", malformed(reason))),
        }
        details.push((
            "Read source",
            match &row.read_source {
                Ok(None) => "Main".to_string(),
                Ok(Some(index)) => format!("Alternate {index}, not available"),
                Err(reason) => malformed(reason),
            },
        ));
        details.push((
            "Raw bytes",
            match row.raw_source(&archive.source, &[]) {
                Ok(_) => "Available".to_string(),
                Err(err) => format!("Not available: {err}"),
            },
        ));
        details.push(("Source", ROW_NOTE.to_string()));
        entry.details = details;
        entry
    }

    pub fn list(&self, archive: &Archive, inner: &Path) -> io::Result<Vec<Entry>> {
        if self.row(inner).is_some() {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "not a folder"));
        }
        if inner.components().next().is_some() {
            return Err(not_found());
        }
        let dir = archive.path.join(inner);
        Ok(self
            .rows
            .iter()
            .map(|row| self.entry(archive, &dir, row))
            .collect())
    }

    fn raw(&self, archive: &Archive, inner: &Path) -> io::Result<Source> {
        let row = self.row(inner).ok_or_else(not_found)?;
        row.raw_source(&archive.source, &[]).map_err(to_io)
    }

    /// Writes the stored bytes of an entry stored as it is. Encoded entries
    /// and entries read through an alternate source are refused.
    pub fn copy(
        &self,
        archive: &Archive,
        inner: &Path,
        out: &mut dyn Write,
        limit: u64,
    ) -> io::Result<()> {
        let source = self.raw(archive, inner)?;
        check_size(source.len(), limit)?;
        io::copy(&mut source.take(limit), out)?;
        Ok(())
    }

    pub fn raw_source(&self, archive: &Archive, inner: &Path) -> Option<Source> {
        self.raw(archive, inner).ok()
    }

    pub fn file_prefix(&self, inner: &Path) -> Option<PathBuf> {
        let first = inner.components().next()?;
        let prefix = PathBuf::from(first.as_os_str());
        self.row(&prefix).map(|_| prefix)
    }

    pub fn file_len(&self, inner: &Path) -> io::Result<u64> {
        let row = self.row(inner).ok_or_else(not_found)?;
        match &row.location {
            Ok(Some(location)) => Ok(location.logical_len),
            Ok(None) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("row {} has no location record", row.row),
            )),
            Err(reason) => Err(io::Error::new(io::ErrorKind::InvalidData, reason.clone())),
        }
    }

    pub fn describe(&self, archive: &Archive, inner: &Path) -> Option<String> {
        if inner.components().next().is_some() {
            return None;
        }
        let total = self.rows.len();
        let malformed = self
            .rows
            .iter()
            .filter(|row| !matchable(row) || row.chunks.is_err() || row.read_source.is_err())
            .count();
        let mut note = format!(
            "Listed from the archive's table of contents, which is stored unencrypted: {} in \
             table order, named after their row. The signature is not checked.",
            match total {
                1 => "1 entry".to_string(),
                n => format!("{n} entries"),
            }
        );
        if malformed > 0 {
            note.push_str(&format!(
                " {malformed} of them have malformed fields, described with each entry."
            ));
        }
        let file = names_file(archive);
        let file_name = file.file_name().unwrap_or_default().to_string_lossy();
        match &self.names {
            None => note.push_str(&format!(
                " Original names are unknown. Candidate paths relative to the archive, one per \
                 line, can be listed in {file_name} next to the archive file."
            )),
            Some(Names {
                problem: Some(problem),
                ..
            }) => note.push_str(&format!(" {file_name} was not used: {problem}.")),
            Some(names) => {
                let matches = names.matches.as_ref()?;
                let named = matches
                    .rows
                    .iter()
                    .filter(|r| !r.candidates.is_empty())
                    .count();
                let ambiguous = matches.rows.iter().filter(|r| r.ambiguous).count();
                let unresolved = matches.candidates.iter().filter(|c| c.is_err()).count();
                note.push_str(&format!(
                    " {named} of {total} entries are named by the {} candidate paths in \
                     {file_name}; {ambiguous} ambiguously. {unresolved} candidates could not be \
                     resolved, for example because no type is known for their extension.",
                    names.candidates.len()
                ));
            }
        }
        Some(note)
    }
}

#[cfg(test)]
pub(crate) mod tests;
