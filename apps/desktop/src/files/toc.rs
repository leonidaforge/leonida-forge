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
use lforge_rage9::rpf::metadata::{
    ChunkTable, Companion, CompanionStatus, Entry as Row, Error, Metadata, Stored,
};
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

/// The companion files of `B` sub-block 3, opened for an archive that is a
/// file on disk.
struct Companions {
    records: Vec<Companion>,
    statuses: Vec<CompanionStatus>,
    /// The source of each record, `None` where it is not available.
    alternates: Vec<Option<Source>>,
    /// Of each companion file, to notice changes.
    stamps: Vec<Option<Stamp>>,
    /// Why sub-block 3 could not be read.
    problem: Option<String>,
}

impl Companions {
    fn read(archive: &Archive, metadata: &Metadata) -> Self {
        let mut companions = Self {
            records: Vec::new(),
            statuses: Vec::new(),
            alternates: Vec::new(),
            stamps: Vec::new(),
            problem: None,
        };
        let list = match metadata.companions() {
            Ok(list) => list,
            Err(err) => {
                companions.problem = Some(err.to_string());
                return companions;
            }
        };
        let dir = companion_dir(archive);
        companions.statuses = match &dir {
            Some(_) => list.open(&archive.path),
            None => {
                let reason = "the archive is stored in another archive, so there is no                      directory to find companion files in";
                vec![CompanionStatus::Unsupported(reason.into()); list.records.len()]
            }
        };
        companions.records = list.records;
        companions.alternates = companions
            .statuses
            .iter()
            .map(|status| status.source().cloned())
            .collect();
        companions.stamps = companion_stamps(dir.as_deref(), &companions.records);
        companions
    }

    fn text(&self, index: u32) -> String {
        let Some(record) = self.records.get(index as usize) else {
            return match &self.problem {
                Some(problem) => format!("Companion {index}, not readable: {problem}"),
                None => format!("Companion {index}, not listed by the archive"),
            };
        };
        let name = String::from_utf8_lossy(&record.name);
        match self.statuses.get(index as usize) {
            Some(CompanionStatus::Available(_)) => format!("Companion {index} ({name}), available"),
            Some(CompanionStatus::Missing(reason)) => {
                format!("Companion {index} ({name}), missing: {reason}")
            }
            Some(CompanionStatus::Invalid(reason)) => {
                format!("Companion {index} ({name}), invalid: {reason}")
            }
            Some(CompanionStatus::Unsupported(reason)) => {
                format!("Companion {index} ({name}), not supported: {reason}")
            }
            None => format!("Companion {index} ({name}), not opened"),
        }
    }
}

/// The directory companion files are resolved in: that of the archive file
/// on disk. An archive stored in another archive has none.
fn companion_dir(archive: &Archive) -> Option<PathBuf> {
    (archive.depth == 1)
        .then(|| archive.path.parent().map(Path::to_path_buf))
        .flatten()
}

fn companion_stamps(dir: Option<&Path>, records: &[Companion]) -> Vec<Option<Stamp>> {
    records
        .iter()
        .map(|record| {
            dir.and_then(|dir| record.path(dir))
                .and_then(|path| stamp(&path))
        })
        .collect()
}

pub struct Native {
    rows: Vec<Row>,
    names: Option<Names>,
    companions: Companions,
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
        err @ (Error::Encoded { .. } | Error::ReadSource { .. } | Error::Undecodable { .. }) => {
            io::Error::new(io::ErrorKind::Unsupported, err.to_string())
        }
        err => io::Error::new(io::ErrorKind::InvalidData, err.to_string()),
    }
}

/// How many chunks, and how they are stored.
fn chunk_text(table: &ChunkTable) -> String {
    let zlib = table.chunks.iter().filter(|c| c.is_compressed()).count();
    let copied = table.chunks.len() - zlib;
    format!(
        "{} in encoding {}: {zlib} zlib, {copied} copied",
        table.chunks.len(),
        table.encoding
    )
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
        let mut source = archive.source.clone();
        // Decides from the header, and at most the A table, whether the
        // stored bytes can be used, before reading all of them.
        let probe = Stored::probe(&mut source).map_err(unreadable)?;
        if let Some(reason) = probe.unsupported() {
            return Err(Arc::from(format!(
                "The table of contents is not read: {reason}."
            )));
        }
        #[cfg(test)]
        tests::FULL_READS.with(|reads| reads.set(reads.get() + 1));
        let stored = Stored::read(&mut source, MAX_METADATA).map_err(unreadable)?;
        let metadata = stored.decode().map_err(unreadable)?;
        let rows: Vec<Row> = metadata.entries().collect();
        let names = Names::read(names_file(archive), &rows);
        let companions = Companions::read(archive, &metadata);
        Ok(Self {
            rows,
            names,
            companions,
        })
    }

    /// Whether the candidate file and the companion files are unchanged
    /// since the table was read.
    pub fn is_current(&self, archive: &Archive) -> bool {
        let names = stamp(&names_file(archive));
        let records = &self.companions.records;
        names == self.names.as_ref().map(|names| names.stamp)
            && companion_stamps(companion_dir(archive).as_deref(), records)
                == self.companions.stamps
    }

    /// Whether the entry at `inner` is read through a companion file.
    pub fn reads_companion(&self, inner: &Path) -> bool {
        self.row(inner)
            .is_some_and(|row| matches!(row.read_source, Ok(Some(_))))
    }

    fn alternates(&self) -> &[Option<Source>] {
        &self.companions.alternates
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
                    match (&row.chunks, l.mode) {
                        (Ok(Some(_)), mode) => {
                            format!("In chunks (mode {mode} is not used with a chunk table)")
                        }
                        (_, 0) => "None".to_string(),
                        (_, 1) => "Raw DEFLATE".to_string(),
                        (_, mode) => format!("Mode {mode}, not supported"),
                    },
                ),
            ]),
            Ok(None) => details.push(("Location record", "Missing".to_string())),
            Err(reason) => details.push(("Location record", malformed(reason))),
        }
        match &row.chunks {
            Ok(Some(chunks)) => details.push(("Chunks", chunk_text(chunks))),
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
                Ok(Some(index)) => self.companions.text(*index),
                Err(reason) => malformed(reason),
            },
        ));
        details.push((
            "Contents",
            match row.payload(&archive.source, self.alternates()) {
                Ok(_) if row.raw_source(&archive.source, self.alternates()).is_ok() => {
                    "Readable as stored".to_string()
                }
                Ok(_) => "Readable, decoded when read".to_string(),
                Err(err) => format!("Not readable: {err}"),
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
        row.raw_source(&archive.source, self.alternates())
            .map_err(to_io)
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
        let row = self.row(inner).ok_or_else(not_found)?;
        let payload = row
            .payload(&archive.source, self.alternates())
            .map_err(to_io)?;
        check_size(payload.len(), limit)?;
        // A payload never yields more than its declared size.
        io::copy(&mut payload.take(limit), out)?;
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
        let companions = &self.companions;
        if let Some(problem) = &companions.problem {
            note.push_str(&format!(
                " Its list of companion files could not be read: {problem}."
            ));
        } else if !companions.records.is_empty() {
            let count = |kind: fn(&CompanionStatus) -> bool| {
                companions.statuses.iter().filter(|s| kind(s)).count()
            };
            note.push_str(&format!(
                " It lists {} companion files: {} available, {} missing, {} invalid, {} not \
                 supported.",
                companions.records.len(),
                count(|s| matches!(s, CompanionStatus::Available(_))),
                count(|s| matches!(s, CompanionStatus::Missing(_))),
                count(|s| matches!(s, CompanionStatus::Invalid(_))),
                count(|s| matches!(s, CompanionStatus::Unsupported(_))),
            ));
        }
        Some(note)
    }
}

#[cfg(test)]
pub(crate) mod tests;
