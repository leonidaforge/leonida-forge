//! RPF9 archives listed from their own table of contents.
//!
//! Metadata that the engine reads as stored is used directly. Metadata that the
//! engine processes first is used only after it authenticated against a local
//! executable (see [`super::rpf`]), or recovered by scanning instead.
//!
//! The table holds hashes of entry names, not names. Each entry keeps its row
//! number as its stable path, `Row 00042`, and is labelled with a verified
//! unambiguous resolved name, otherwise the stored key in canonical form.
//! A verified name that is a safe relative path is shown as folders; every
//! other row is listed after them in [`UNNAMED`]. Names come from the LUT files
//! embedded in the application and read beside the executable, and from the
//! local table `<archive file>.names.txt` next to the file on disk. That table
//! holds candidate paths relative to the archive, or explicit
//! `hash64:HASH<TAB>name` and `key32:HASH<TAB>name` mappings. Names are display
//! data only: entry paths stay the row names.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_rage9::rpf::metadata::transform::{Algorithm, CipherDescriptor};
use lforge_rage9::rpf::metadata::verify::VerifyReport;
use lforge_rage9::rpf::metadata::{
    ChunkTable, Companion, CompanionStatus, Entry as Row, Error, Metadata, Stored,
};
use lforge_rage9::rpf::names::{
    self, Builtin, CandidateOutcome, Class, Key, MountPrefix, Provenance, Resolution,
    ResolutionSet, Resolver, StringTable, Types, builtin,
};

use super::archive::{Archive, Dependency, Stamp, check_size, file_stamp};
use super::{Entry, EntryKind, ListingLayout, count, folder, format_bytes_exact, format_size};

/// Larger tables of contents are not read.
const MAX_METADATA: u64 = 64 * 1024 * 1024;
pub const NAMES_SUFFIX: &str = ".names.txt";
/// The folder that holds the rows a verified relative path cannot place.
pub const UNNAMED: &str = "Unnamed Entries";

const ROW_NOTE: &str = "Listed from the archive's table of contents. The label is a verified \
     unambiguous name, otherwise the stored key; the row number identifies the entry.";

/// Why the stored table of contents cannot be read as it is.
#[derive(Debug, Clone)]
/// The two cases are kept apart on purpose: one is solved by a compatible
/// executable, the other only by scanning or not at all.
pub enum Unreadable {
    /// The engine processes the metadata before reading it. A local executable
    /// can authenticate and decode it.
    Processed(Arc<str>),
    /// The stored metadata is not usable, whatever executable is supplied.
    Malformed(Arc<str>),
}

impl Unreadable {
    pub fn reason(&self) -> &Arc<str> {
        match self {
            Unreadable::Processed(reason) | Unreadable::Malformed(reason) => reason,
        }
    }
}

/// How the listed table of contents was obtained.
#[derive(Debug, Clone)]
pub enum Authentication {
    /// The archive needs no processing pass: the stored bytes are the table the
    /// engine reads. The signature has not been checked.
    Unencrypted,
    /// The signature verified against the selected executable and the
    /// processed metadata decoded. This authenticates the table, not the
    /// payloads it describes.
    Authenticated(VerifyReport),
}

impl Authentication {
    /// The short status shown with each entry and in the folder note.
    pub fn text(&self) -> String {
        match self {
            Authentication::Unencrypted => {
                "Unencrypted: the archive needs no processing pass, and the signature is not \
                 checked."
                    .to_string()
            }
            Authentication::Authenticated(report) => format!(
                "Authenticated: the signature over this table verified against the selected \
                 executable (stage {}). It covers the metadata, not the payloads.",
                report.stage
            ),
        }
    }
}
/// The names applied to the rows: the built-in LUTs and what resolves to what.
struct Names {
    /// The local table next to the archive, when there is one.
    file: Option<PathBuf>,
    /// Of `file`, to notice changes.
    stamp: Option<Stamp>,
    /// The local entries first, then the built-in ones.
    table: StringTable,
    /// Entries of `table` that the local file contributed.
    local: usize,
    matches: ResolutionSet,
    /// Why the local file was not used.
    problem: Option<String>,
    /// The built-in LUTs that were found.
    builtin: Vec<builtin::Source>,
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
                .and_then(|path| file_stamp(&path))
        })
        .collect()
}

pub struct Native {
    rows: Vec<Row>,
    names: Option<Names>,
    /// Where each row is listed, from the verified relative paths.
    layout: Layout,
    companions: Companions,
    authentication: Authentication,
    types: Types,
    /// Present when the metadata was authenticated; it can build
    /// payload-transform blocks.
    stream: Option<lforge_rage9::rpf::metadata::provider::RecognizedSource>,
}

fn names_file(archive: &Archive) -> PathBuf {
    let mut name = archive.root.file_name().unwrap_or_default().to_os_string();
    name.push(NAMES_SUFFIX);
    archive.root.with_file_name(name)
}

/// The built-in name tables, read once.
fn builtin() -> &'static Builtin {
    static BUILTIN: OnceLock<Builtin> = OnceLock::new();
    BUILTIN.get_or_init(Builtin::beside_executable)
}

/// Rows whose names can be matched: with a location record and well-formed
/// name fields.
fn matchable(row: &Row) -> bool {
    matches!(row.location, Ok(Some(_))) && row.name_hash.is_ok() && row.name_key.is_ok()
}

impl Names {
    fn read(archive: &Archive, rows: &[Row], types: &Types) -> Option<Self> {
        Self::read_with(archive, rows, types, builtin())
    }

    /// Reads the local table of `archive` and resolves the rows with it and
    /// with `builtin`.
    fn read_with(
        archive: &Archive,
        rows: &[Row],
        types: &Types,
        builtin: &Builtin,
    ) -> Option<Self> {
        let file = names_file(archive);
        let file = file.is_file().then_some(file);
        let mut table = StringTable::default();
        let mut problem = None;
        if let Some(file) = &file {
            match read_name_file(file) {
                Ok((bytes, truncated)) => {
                    if is_lut(&bytes) {
                        problem = Some(
                            "a LUT is only read from the built-in tables and from beside the \
                             executable; the table next to an archive is a .names.txt name table"
                                .to_string(),
                        );
                    } else {
                        table.merge(StringTable::parse(&bytes, truncated));
                    }
                }
                Err(err) => problem = Some(err.to_string()),
            }
        }
        let local = table.entries().len();
        table.merge(builtin.table().clone());
        if table.entries().is_empty() {
            return None;
        }
        let matches = Resolver::new(&table, types, MountPrefix::EMPTY).resolve(rows);
        Some(Self {
            stamp: file.as_deref().and_then(file_stamp),
            file,
            table,
            local,
            matches,
            problem,
            builtin: builtin.sources().to_vec(),
        })
    }

    /// A verified unambiguous name of the row, if the tables have one.
    fn verified_name(&self, row: u32) -> Option<&str> {
        match &self.matches.row(row)?.resolution {
            Resolution::Resolved(names) => names
                .iter()
                .find(|name| name.verified)
                .map(|name| name.text.as_str()),
            Resolution::Ambiguous(_) | Resolution::Unresolved => None,
        }
    }
}

/// Where one row is listed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Placement {
    /// Folder components, empty for the archive root.
    folder: Vec<String>,
    /// The visible file name, with only a confirmed extension.
    label: String,
}

/// The virtual folders the verified relative paths describe.
///
/// The archive stores hashes of paths, not folders. A row whose verified
/// unambiguous name is a safe relative path is listed under that path; every
/// other row is listed in [`UNNAMED`]. Nothing here changes a row's identity:
/// an entry's path stays `<folder>/Row NNNNN`, so each row has exactly one
/// path.
#[derive(Debug, Default)]
struct Layout {
    /// By row number, `None` for a row in the unnamed folder.
    placements: Vec<Option<Placement>>,
    /// Folder components, including the root as the empty list.
    folders: BTreeMap<Vec<String>, VirtualFolder>,
    /// Row numbers without a usable path, in row order.
    unnamed: Vec<usize>,
    /// Whether any row has a usable path. Without one, the rows are listed at
    /// the archive root instead of inside a folder that would hold them all.
    grouped: bool,
}

#[derive(Debug, Default)]
struct VirtualFolder {
    /// Row numbers listed directly in this folder.
    rows: Vec<usize>,
    /// Child folders by folded name, so `DATA` and `data` are one folder.
    /// The value is the spelling of the first name that was placed here.
    subfolders: BTreeMap<String, String>,
}

impl Layout {
    fn build(rows: &[Row], names: Option<&Names>) -> Self {
        let mut layout = Self {
            placements: vec![None; rows.len()],
            ..Self::default()
        };
        layout.folders.insert(Vec::new(), VirtualFolder::default());
        for row in rows {
            let Some(name) = names.and_then(|names| names.verified_name(row.row)) else {
                continue;
            };
            let Some((folder, label)) = placement(name, row.type_id()) else {
                continue;
            };
            let Some(position) = usize::try_from(row.row).ok().filter(|&p| p < rows.len()) else {
                continue;
            };
            // The engine folds case and `\` in a path, so folder spellings
            // that fold alike are one folder. The first spelling is kept.
            let mut path: Vec<String> = Vec::new();
            for component in &folder {
                let folded = folded(component);
                let existing = layout
                    .folders
                    .get(&path)
                    .and_then(|parent| parent.subfolders.get(&folded))
                    .cloned();
                let display = match existing {
                    Some(display) => display,
                    None => {
                        let display = component.clone();
                        layout
                            .folders
                            .entry(path.clone())
                            .or_default()
                            .subfolders
                            .insert(folded, display.clone());
                        display
                    }
                };
                path.push(display);
            }
            layout
                .folders
                .entry(path.clone())
                .or_default()
                .rows
                .push(position);
            layout.placements[position] = Some(Placement {
                folder: path,
                label,
            });
        }
        layout.unnamed = (0..rows.len())
            .filter(|&position| layout.placements[position].is_none())
            .collect();
        layout.grouped = layout.unnamed.len() < rows.len();
        layout
    }
}

/// The folder and file name a verified name describes, or `None` when it is
/// not a safe relative path.
fn placement(name: &str, type_id: Option<u8>) -> Option<(Vec<String>, String)> {
    let parts = names::relative_path(name)?;
    let (label, folder) = parts.split_last()?;
    let folder: Vec<String> = folder.iter().map(|part| (*part).to_string()).collect();
    // The folder of the unnamed group is reserved.
    if folder
        .first()
        .is_some_and(|part| folded(part) == folded(UNNAMED))
    {
        return None;
    }
    Some((folder, with_extension(label, type_id)))
}

/// The spelling two folder components are compared by: the engine folds ASCII
/// upper case to lower case, so `DATA` and `data` are the same folder.
fn folded(part: &str) -> String {
    part.to_ascii_lowercase()
}

/// The components of `path` as text, or `None` when one is not UTF-8.
fn path_parts(path: &Path) -> Option<Vec<&str>> {
    path.iter().map(|part| part.to_str()).collect()
}

fn read_name_file(path: &Path) -> io::Result<(Vec<u8>, bool)> {
    let limit = names::table::MAX_BYTES.max(names::lut::MAX_BYTES);
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    let truncated = bytes.len() as u64 > limit;
    if truncated {
        bytes.truncate(limit as usize);
    }
    Ok((bytes, truncated))
}

fn is_lut(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8_lossy(bytes)
        .trim_start()
        .starts_with("# leonida-forge-lut:")
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

/// The descriptor the engine would use for a payload transform. This build does
/// not implement its algorithm, so the value is shown, not decoded.
fn cipher_text(cipher: &CipherDescriptor) -> String {
    match Algorithm::of(cipher.kind) {
        Ok(algorithm) => format!(
            "type {:#x}, algorithm {:#x}, key id 0x{:08X}",
            cipher.kind,
            algorithm.id(),
            cipher.key_id
        ),
        Err(_) => format!(
            "type {:#x}, invalid cipher type, key id 0x{:08X}",
            cipher.kind, cipher.key_id
        ),
    }
}

fn bytes_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn with_extension(name: &str, type_id: Option<u8>) -> String {
    if type_id != Some(names::RPF_TYPE) {
        return name.to_string();
    }
    let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);
    if basename.contains('.') {
        return name.to_string();
    }
    format!("{name}.rpf")
}

fn hex<T: std::fmt::UpperHex>(value: T, digits: usize) -> String {
    format!("0x{value:0digits$X}")
}

fn size_text(len: u64) -> String {
    format!("{} ({} bytes)", format_size(len), format_bytes_exact(len))
}

impl Native {
    /// The table of contents of `archive`, or why it is not used.
    pub fn read(archive: &Archive) -> Result<Self, Unreadable> {
        let unreadable = |err: Error| {
            Unreadable::Malformed(Arc::from(format!(
                "The table of contents could not be read: {err}."
            )))
        };
        let mut source = archive.source.clone();
        // Decides from the header, and at most the A table, whether the
        // stored bytes can be used, before reading all of them.
        let probe = Stored::probe(&mut source).map_err(unreadable)?;
        if let Some(reason) = probe.unsupported() {
            return Err(Unreadable::Processed(Arc::from(format!(
                "The table of contents is processed before use: {reason}."
            ))));
        }
        if !probe.processing.is_none() {
            return Err(Unreadable::Processed(Arc::from(
                "The table of contents is processed before use, and a local executable is needed \
                 to authenticate it.",
            )));
        }
        #[cfg(test)]
        tests::FULL_READS.with(|reads| reads.set(reads.get() + 1));
        let stored = Stored::read(&mut source, MAX_METADATA).map_err(unreadable)?;
        let metadata = stored.decode().map_err(|err| match err {
            Error::Transformed(_) => Unreadable::Processed(Arc::from(
                "The table of contents is processed before use, and a local executable is needed \
                 to authenticate it.",
            )),
            err => unreadable(err),
        })?;
        Ok(Self::from_metadata(
            archive,
            metadata,
            Authentication::Unencrypted,
            None,
        ))
    }

    /// The table of contents authenticated by a local executable. The caller
    /// only gets an [`AuthenticatedMetadata`] from a passing signature check,
    /// so no unverified metadata can be listed as native entries.
    ///
    /// [`AuthenticatedMetadata`]: lforge_rage9::rpf::metadata::verify::AuthenticatedMetadata
    pub fn from_authenticated(
        archive: &Archive,
        metadata: Metadata,
        report: VerifyReport,
        stream: lforge_rage9::rpf::metadata::provider::RecognizedSource,
    ) -> Self {
        Self::from_metadata(
            archive,
            metadata,
            Authentication::Authenticated(report),
            Some(stream),
        )
    }

    fn from_metadata(
        archive: &Archive,
        metadata: Metadata,
        authentication: Authentication,
        stream: Option<lforge_rage9::rpf::metadata::provider::RecognizedSource>,
    ) -> Self {
        let rows: Vec<Row> = metadata.entries().collect();
        let types = Types::default();
        let names = Names::read(archive, &rows, &types);
        let layout = Layout::build(&rows, names.as_ref());
        let companions = Companions::read(archive, &metadata);
        Self {
            rows,
            names,
            layout,
            companions,
            authentication,
            types,
            stream,
        }
    }

    /// Whether the local name table and the companion files are unchanged
    /// since the table was read.
    pub fn is_current(&self, archive: &Archive) -> bool {
        let current = names_file(archive);
        let current = current.is_file().then_some(current);
        let names_current = match &self.names {
            None => current.is_none(),
            Some(names) => {
                names.file == current && names.file.as_deref().and_then(file_stamp) == names.stamp
            }
        };
        let records = &self.companions.records;
        names_current
            && companion_stamps(companion_dir(archive).as_deref(), records)
                == self.companions.stamps
    }

    /// The companion file the entry at `inner` is read through, with its
    /// stamp when it was opened.
    pub fn dependencies(&self, archive: &Archive, inner: &Path) -> Vec<Dependency> {
        let Some(Ok(Some(index))) = self.row(inner).map(|row| &row.read_source) else {
            return Vec::new();
        };
        let index = *index as usize;
        let companions = &self.companions;
        let available = matches!(
            companions.statuses.get(index),
            Some(CompanionStatus::Available(_))
        );
        let path = companion_dir(archive)
            .zip(companions.records.get(index))
            .and_then(|(dir, record)| record.path(&dir));
        match (available, path) {
            (true, Some(path)) => {
                let stamp = companions.stamps.get(index).copied().flatten();
                vec![(path, stamp)]
            }
            _ => Vec::new(),
        }
    }

    fn alternates(&self) -> &[Option<Source>] {
        &self.companions.alternates
    }

    fn row(&self, inner: &Path) -> Option<&Row> {
        let parts = path_parts(inner)?;
        let (name, folder) = parts.split_last()?;
        let row = self
            .rows
            .get(usize::try_from(parse_row_name(name)?).ok()?)?;
        let placement = self
            .layout
            .placements
            .get(usize::try_from(row.row).ok()?)?
            .as_ref();
        let matches = match placement {
            Some(placement) => placement
                .folder
                .iter()
                .map(String::as_str)
                .eq(folder.iter().copied()),
            None if self.layout.grouped => folder.len() == 1 && folder[0] == UNNAMED,
            None => folder.is_empty(),
        };
        matches.then_some(row)
    }

    fn resolution(&self, row: u32) -> Option<&Resolution> {
        self.names
            .as_ref()?
            .matches
            .row(row)
            .map(|names| &names.resolution)
    }

    fn names_text(&self, row: &Row) -> String {
        if !matchable(row) {
            return "Unknown: the row is malformed".to_string();
        }
        if self.names.is_none() {
            return "Unknown".to_string();
        }
        match self.resolution(row.row) {
            Some(Resolution::Resolved(list)) => list
                .iter()
                .map(|name| name.text.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            Some(Resolution::Ambiguous(list)) => format!(
                "Ambiguous: {} (each has this entry's hash)",
                list.iter()
                    .map(|name| name.text.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Some(Resolution::Unresolved) | None => {
                "Unknown: no candidate path or declared name has this entry's hash".to_string()
            }
        }
    }

    /// The visible name of the row at `index`: the file name its verified
    /// relative path ends in, else the stored key in canonical form.
    fn label(&self, index: usize) -> String {
        match &self.layout.placements[index] {
            Some(placement) => placement.label.clone(),
            None => self.key_label(&self.rows[index]),
        }
    }

    /// The stored key of the row in canonical form, with only a confirmed
    /// extension.
    fn key_label(&self, row: &Row) -> String {
        let hash = row.name_hash.as_ref().ok().and_then(|value| *value);
        let key = row.name_key.as_ref().ok().and_then(|value| *value);
        let stored = match row.type_id().and_then(|type_id| self.types.class(type_id)) {
            Some(Class::Hash64) => hash.map(Key::Hash64),
            Some(Class::Key32) => key.map(Key::Key32),
            _ => match (hash, key) {
                (Some(hash), _) => Some(Key::Hash64(hash)),
                (None, Some(key)) => Some(Key::Key32(key)),
                _ => None,
            },
        };
        match stored {
            Some(key) => with_extension(&key.canonical(), row.type_id()),
            None => row_name(row.row),
        }
    }

    /// Where the displayed names came from, and whether their keys were
    /// verified by hashing.
    fn names_source_text(&self, row: &Row) -> String {
        let Some(Resolution::Resolved(names) | Resolution::Ambiguous(names)) =
            self.resolution(row.row)
        else {
            return "None".to_string();
        };
        let paths = names
            .iter()
            .filter(|name| name.provenance == Provenance::CandidatePath)
            .count();
        let verified = names
            .iter()
            .filter(|name| name.provenance == Provenance::UserMapping && name.verified)
            .count();
        let unconfirmed = names
            .iter()
            .filter(|name| name.provenance == Provenance::UserMapping && !name.verified)
            .count();
        match (paths > 0, verified > 0, unconfirmed > 0) {
            (true, false, false) => "Candidate path, verified by hash".to_string(),
            (false, true, false) => "User mapping, verified by hash".to_string(),
            (false, false, true) => "User mapping, unconfirmed".to_string(),
            (false, true, true) => "User mappings, verified and unconfirmed".to_string(),
            _ => "Candidate paths and user mappings".to_string(),
        }
    }

    /// The folder the row is listed in: the one its verified relative path
    /// describes, the unnamed group, or the archive root. This is the folder
    /// its path points into in both layouts, so a row's path is stable when
    /// the layout changes.
    fn row_dir(&self, archive: &Archive, index: usize) -> PathBuf {
        match &self.layout.placements[index] {
            Some(placement) => {
                let mut dir = archive.path.clone();
                for component in &placement.folder {
                    dir.push(component);
                }
                dir
            }
            None if self.layout.grouped => archive.path.join(UNNAMED),
            None => archive.path.clone(),
        }
    }

    fn entry(&self, archive: &Archive, index: usize) -> Entry {
        let row = &self.rows[index];
        let path_name = row_name(row.row);
        let label = self.label(index);
        let dir = self.row_dir(archive, index);
        let location = match &row.location {
            Ok(Some(location)) => Some(location),
            _ => None,
        };
        let kind = match location {
            Some(_) => EntryKind::File,
            None => EntryKind::Unavailable,
        };
        let mut entry = Entry::new(
            label,
            dir.join(&path_name),
            kind,
            location.map(|l| l.logical_len),
            None,
        );
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
            ("Metadata", self.authentication.text()),
            ("Names", self.names_text(row)),
            ("Name source", self.names_source_text(row)),
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
                (
                    "Type ID",
                    format!("{} (meaning not established)", l.type_id),
                ),
                ("Payload offset", format!("{:#x}", l.payload_offset)),
                ("Logical size", size_text(l.logical_len)),
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
            Ok(true) => {
                details.push((
                    "Payload transform",
                    if self.stream.is_some() {
                        "Decoded with the executable's key state".to_string()
                    } else {
                        "Required, not supported".to_string()
                    },
                ));
                match &row.payload_cipher {
                    Ok(Some(cipher)) => {
                        details.push(("Transform cipher", cipher_text(cipher)));
                        details.push(("Transform parameter", bytes_text(&cipher.parameter)));
                    }
                    Ok(None) => details.push(("Transform cipher", "Not stored".to_string())),
                    Err(reason) => details.push(("Transform cipher", malformed(reason))),
                }
            }
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
                Err(_) if matches!(row.payload_transform, Ok(true)) && self.stream.is_some() => {
                    "Readable after the payload transform".to_string()
                }
                Err(err) => format!("Not readable: {err}"),
            },
        ));
        details.push(("Source", ROW_NOTE.to_string()));
        entry.details = details;
        entry
    }

    pub fn list(
        &self,
        archive: &Archive,
        inner: &Path,
        layout: ListingLayout,
    ) -> io::Result<Vec<Entry>> {
        if self.row(inner).is_some() {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "not a folder"));
        }
        let parts = path_parts(inner).ok_or_else(not_found)?;
        let dir = archive.path.join(inner);
        if layout == ListingLayout::Flat && parts.is_empty() {
            // One list of every row, without opening the virtual folders.
            return Ok((0..self.rows.len())
                .map(|index| self.entry(archive, index))
                .collect());
        }
        if !self.layout.grouped {
            // No row has a usable path, so the rows are listed at the root.
            if !parts.is_empty() {
                return Err(not_found());
            }
            return Ok(self.unnamed(archive));
        }
        if parts.len() == 1 && parts[0] == UNNAMED {
            return Ok(self.unnamed(archive));
        }
        let key: Vec<String> = parts.iter().map(|part| (*part).to_string()).collect();
        let current = self.layout.folders.get(&key).ok_or_else(not_found)?;
        let mut entries: Vec<Entry> = current
            .subfolders
            .values()
            .map(|name| {
                let mut path = key.clone();
                path.push(name.clone());
                let contents = self
                    .layout
                    .folders
                    .get(&path)
                    .map_or(0, |folder| folder.rows.len());
                folder(&dir, name, count(contents, "entry", "entries"))
            })
            .collect();
        entries.extend(current.rows.iter().map(|&index| self.entry(archive, index)));
        if key.is_empty() && !self.layout.unnamed.is_empty() {
            let mut group = folder(
                &dir,
                UNNAMED,
                count(self.layout.unnamed.len(), "entry", "entries"),
            );
            group.last = true;
            entries.push(group);
        }
        Ok(entries)
    }

    /// The rows a verified relative path cannot place, in row order.
    fn unnamed(&self, archive: &Archive) -> Vec<Entry> {
        self.layout
            .unnamed
            .iter()
            .map(|&index| self.entry(archive, index))
            .collect()
    }

    fn raw(&self, archive: &Archive, inner: &Path) -> io::Result<Source> {
        let row = self.row(inner).ok_or_else(not_found)?;
        row.raw_source(&archive.source, self.alternates())
            .map_err(to_io)
    }

    /// Decodes a row behind the payload transform with the authenticated
    /// executable state. `None` when the archive has no such state.
    fn transformed(&self, archive: &Archive, row: &Row, limit: u64) -> io::Result<Option<Vec<u8>>> {
        let Some(stream) = &self.stream else {
            return Ok(None);
        };
        let location = match &row.location {
            Ok(Some(location)) => *location,
            Ok(None) => return Err(not_found()),
            Err(reason) => return Err(to_io(Error::Invalid(reason.clone()))),
        };
        let table = match &row.chunks {
            Ok(Some(table)) => table,
            Ok(None) => return Err(not_found()),
            Err(reason) => return Err(to_io(Error::Invalid(reason.clone()))),
        };
        let cipher = match &row.payload_cipher {
            Ok(Some(cipher)) => cipher,
            Ok(None) => return Err(not_found()),
            Err(reason) => return Err(to_io(Error::Invalid(reason.clone()))),
        };
        if location.stored_len > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored row exceeds the output limit",
            ));
        }
        let read_source: &Source = match &row.read_source {
            Ok(None) => &archive.source,
            Ok(Some(index)) => self
                .alternates()
                .get(*index as usize)
                .and_then(|source| source.as_ref())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing companion"))?,
            Err(reason) => return Err(to_io(Error::Invalid(reason.clone()))),
        };
        let mut stored = read_source.slice(location.payload_offset, location.stored_len)?;
        let mut bytes = Vec::with_capacity(location.stored_len as usize);
        stored.read_to_end(&mut bytes)?;
        let blocks = stream.stream_blocks(cipher.key_id);
        lforge_rage9::rpf::metadata::provider::decode_transformed(
            &bytes,
            table,
            location.logical_len,
            cipher,
            &blocks,
        )
        .map(Some)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
    }

    /// Writes the contents of an entry, decoded where that is supported.
    /// Entries that cannot be read, also through an unavailable companion,
    /// are refused. Decoding stops once `cancel` is set.
    pub fn copy(
        &self,
        archive: &Archive,
        inner: &Path,
        out: &mut dyn Write,
        limit: u64,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        let row = self.row(inner).ok_or_else(not_found)?;
        let mut payload = match row.payload(&archive.source, self.alternates()) {
            Ok(payload) => payload,
            Err(err) if matches!(row.payload_transform, Ok(true)) => {
                if let Some(bytes) = self.transformed(archive, row, limit)? {
                    check_size(bytes.len() as u64, limit)?;
                    out.write_all(&bytes)?;
                    return Ok(());
                }
                return Err(to_io(err));
            }
            Err(err) => return Err(to_io(err)),
        };
        check_size(payload.len(), limit)?;
        // A payload never yields more than its declared size. `io::copy`
        // would retry the `Interrupted` that cancellation returns.
        let mut buf = vec![0; 64 * 1024];
        loop {
            match payload.read_cancellable(&mut buf, cancel)? {
                0 => return Ok(()),
                n => out.write_all(&buf[..n])?,
            }
        }
    }

    pub fn raw_source(&self, archive: &Archive, inner: &Path) -> Option<Source> {
        self.raw(archive, inner).ok()
    }

    pub fn file_prefix(&self, inner: &Path) -> Option<PathBuf> {
        let mut prefix = PathBuf::new();
        for component in inner.components() {
            prefix.push(component);
            if self.row(&prefix).is_some() {
                return Some(prefix);
            }
        }
        None
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

    pub fn describe(
        &self,
        archive: &Archive,
        inner: &Path,
        layout: ListingLayout,
    ) -> Option<String> {
        let parts = path_parts(inner)?;
        if parts.is_empty() && layout == ListingLayout::Flat {
            return Some(format!(
                "All {} of the archive's rows in one list, labelled by a verified name or by the \
                 stored key. Switch to the folders view to see the verified relative paths as \
                 folders. Row numbers remain the entry paths.",
                count(self.rows.len(), "row", "rows")
            ));
        }
        if !parts.is_empty() {
            if self.layout.grouped && parts.len() == 1 && parts[0] == UNNAMED {
                return Some(format!(
                    "{} without a verified relative path, labelled by their stored key. The \
                     archive stores no names or folders; each entry's details keep the stored \
                     hash, the key and any candidate names.",
                    count(self.layout.unnamed.len(), "row", "rows")
                ));
            }
            let key: Vec<String> = parts.iter().map(|part| (*part).to_string()).collect();
            return self.layout.folders.contains_key(&key).then(|| {
                "Reconstructed from the relative path a verified name describes. The archive \
                 stores neither names nor folders, and an entry's path stays its row number."
                    .to_string()
            });
        }
        let total = self.rows.len();
        let malformed = self
            .rows
            .iter()
            .filter(|row| !matchable(row) || row.chunks.is_err() || row.read_source.is_err())
            .count();
        let provenance = match &self.authentication {
            Authentication::Unencrypted => {
                "which is stored unencrypted, so its signature is not checked".to_string()
            }
            Authentication::Authenticated(report) => format!(
                "after its signature verified against the selected executable (stage {}), so the \
                 entries are authentic",
                report.stage
            ),
        };
        let mut note = format!(
            "Listed from the archive's table of contents, {}: {} in table order, labelled by a \
             verified name or by the stored key. Row numbers remain the entry paths. The \
             signature covers the metadata, not the payloads.",
            provenance,
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
            Some(names) => {
                if let Some(problem) = &names.problem {
                    note.push_str(&format!(" {file_name} was not used: {problem}."));
                }
                for source in names.builtin.iter().filter(|s| s.problem.is_some()) {
                    note.push_str(&format!(
                        " The built-in {} could not be used: {}.",
                        source.file,
                        source.problem.as_deref().unwrap_or_default()
                    ));
                }
                let resolved = &names.matches;
                let named = resolved
                    .rows
                    .iter()
                    .filter(|r| !r.resolution.names().is_empty())
                    .count();
                let ambiguous = resolved
                    .rows
                    .iter()
                    .filter(|r| r.resolution.is_ambiguous())
                    .count();
                let unresolved = resolved
                    .candidates
                    .iter()
                    .filter(|candidate| {
                        candidate.provenance == Provenance::CandidatePath
                            && matches!(&candidate.outcome, CandidateOutcome::Unresolved(_))
                    })
                    .count();
                let paths = names.table.candidates();
                let mappings = names.local - paths;
                let builtin = names
                    .builtin
                    .iter()
                    .map(|source| source.added)
                    .sum::<usize>();
                let mut sentence = format!(" {named} of {total} entries are named");
                if paths > 0 || mappings > 0 {
                    let source = match (paths, mappings) {
                        (paths, 0) => format!("{paths} candidate paths"),
                        (0, mappings) => format!("{mappings} name mappings"),
                        (paths, mappings) => {
                            format!("{paths} candidate paths and {mappings} name mappings")
                        }
                    };
                    sentence.push_str(&format!(" by the {source} in {file_name}"));
                    sentence.push_str(&format!(" and by {builtin} built-in name mappings"));
                } else {
                    sentence.push_str(&format!(" by {builtin} built-in name mappings"));
                }
                note.push_str(&sentence);
                note.push_str(&format!(
                    "; {ambiguous} ambiguously. {unresolved} candidates could not be resolved, for \
                     example because no type is known for their extension."
                ));
                if mappings > 0 {
                    let verified = resolved
                        .candidates
                        .iter()
                        .filter(|candidate| {
                            candidate.index < names.local
                                && candidate.provenance == Provenance::UserMapping
                                && candidate.verified
                        })
                        .count();
                    let unconfirmed = mappings - verified;
                    note.push_str(&format!(
                        " {verified} of {mappings} name mappings are verified by hash; \
                         {unconfirmed} {} unconfirmed.",
                        if unconfirmed == 1 { "is" } else { "are" }
                    ));
                }
                if names.table.skipped() > 0 {
                    let skipped = names.table.skipped();
                    note.push_str(&format!(
                        " {skipped} {} not a valid entry.",
                        if skipped == 1 {
                            "line was"
                        } else {
                            "lines were"
                        }
                    ));
                }
                if names.table.duplicates() > 0 {
                    let duplicates = names.table.duplicates();
                    note.push_str(&format!(
                        " {duplicates} duplicate {} dropped.",
                        if duplicates == 1 {
                            "line was"
                        } else {
                            "lines were"
                        }
                    ));
                }
                if names.table.truncated() {
                    note.push_str(" The table was cut at its size limit.");
                }
            }
        }
        if self.layout.grouped {
            note.push_str(" Verified relative paths are shown as folders.");
            let unnamed = self.layout.unnamed.len();
            if unnamed > 0 {
                note.push_str(&format!(
                    " The {} without one are at the end in {UNNAMED}.",
                    count(unnamed, "row", "rows")
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
