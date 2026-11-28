//! Bounded traversal into archives stored in archives.
//!
//! Every selector names one entry of the current archive: `row:N` a native
//! RPF9 row, `zip:N` a ZIP entry by central-directory index. The entry's
//! decoded payload must itself be an archive, recognised from its contents.
//! It is written to an anonymous temporary file and becomes the current
//! archive. Nothing is recognised from a file name.
//!
//! Every level enforces the same limits: nesting depth, decoded size, a
//! cumulative byte budget, entry and metadata counts, checked offsets,
//! cancellation and temporary-file cleanup. An RPF9 archive at any level is
//! opened through the same metadata verification pipeline as a top-level one.

use std::fmt;
use std::io::Write;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::Source;
use lforge_core::archive::{self, Format, Identified};
use lforge_core::resource::{EntryId, Locator, ResourcePath};
use lforge_core::zip as zip_archive;
use lforge_rage9::rpf::metadata::Payload;
use serde_json::{Value, json};

use crate::native::Authentication;

/// The default cap on the decoded size of one intermediate archive.
pub const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

/// Caps one traversal. The defaults are what the commands use.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Archives in a chain, counting the file the chain starts at.
    pub max_depth: usize,
    /// Caps the decoded size of one intermediate archive.
    pub max_archive_bytes: u64,
    /// Caps the bytes decompressed along one chain.
    pub max_chain_bytes: u64,
    /// Caps the rows of an RPF9 archive and the entries of a ZIP archive.
    pub max_entries: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_archive_bytes: MAX_ARCHIVE_BYTES,
            max_chain_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 1 << 20,
        }
    }
}

/// Bytes copied per step.
const COPY_LEN: usize = 64 * 1024;

/// How to step into the current archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selector {
    /// A native RPF9 row index.
    Row(u32),
    /// A ZIP central-directory index.
    Zip(usize),
}

impl Selector {
    pub fn label(&self) -> String {
        match *self {
            Selector::Row(row) => format!("row:{row}"),
            Selector::Zip(index) => format!("zip:{index}"),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Selector::Row(_) => "row",
            Selector::Zip(_) => "zip",
        }
    }

    fn index(&self) -> u64 {
        match *self {
            Selector::Row(row) => u64::from(row),
            Selector::Zip(index) => index as u64,
        }
    }

    /// `row` or `zip`, the selector's kind.
    pub fn selector_kind(&self) -> &'static str {
        self.kind()
    }

    /// The row or central-directory index the selector names.
    pub fn selector_index(&self) -> u64 {
        self.index()
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

impl FromStr for Selector {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some((kind, value)) = text.split_once(':') else {
            return Err(format!(
                "'{text}' is not a selector; use row:N for an RPF9 row or zip:N for a ZIP entry"
            ));
        };
        let index = lforge_binary::parse_offset(value)?;
        match kind {
            "row" => u32::try_from(index)
                .map(Selector::Row)
                .map_err(|_| format!("'row:{value}' is not a row index")),
            "zip" | "zip-index" => usize::try_from(index)
                .map(Selector::Zip)
                .map_err(|_| format!("'{kind}:{value}' is not a ZIP entry index")),
            other => Err(format!(
                "'{other}' is not a selector kind; use row:N or zip:N"
            )),
        }
    }
}

/// One archive entered from its parent.
#[derive(Debug, Clone)]
pub struct Level {
    pub selector: Selector,
    /// The canonical path of the archive this level entered: the root file and
    /// every nested archive above it, ending with this entry.
    pub resource: ResourcePath,
    /// The format of the archive that was entered, as recognised from its
    /// contents.
    pub format: Format,
    /// Decoded payload size of the entry that holds the archive.
    pub size: u64,
    /// The ZIP entry name, display only. `None` for an RPF9 row, which has no
    /// recovered path.
    pub name: Option<String>,
    /// How the RPF9 table of contents was obtained. `None` for a ZIP level.
    pub authentication: Option<Authentication>,
}

/// A file that may continue into archives, with the chain that reached it.
#[derive(Debug)]
pub struct Resolved {
    pub path: std::path::PathBuf,
    pub format: Format,
    /// The file the chain starts at, as given by the caller.
    pub root: std::path::PathBuf,
    pub root_format: Format,
    pub chain: Vec<Level>,
    /// Bytes decompressed along the chain.
    pub budget_used: u64,
    /// Keeps the last temporary file alive until the caller is done with it.
    _temp: Option<tempfile::TempPath>,
}

impl Resolved {
    /// The canonical path of the archive the chain resolved to.
    pub fn resource(&self) -> ResourcePath {
        self.chain
            .last()
            .map(|level| level.resource.clone())
            .unwrap_or_else(|| ResourcePath::root(crate::rows::table_name(&self.root)))
    }

    /// The provenance block of an inspection document.
    pub fn provenance_json(&self, selection: Value, representation: Value) -> Value {
        let chain: Vec<Value> = self
            .chain
            .iter()
            .map(|level| {
                let mut step = json!({
                    "selector": level.selector.label(),
                    "selector_kind": level.selector.kind(),
                    "selector_index": level.selector.index(),
                    "resource": {
                        "display": level.resource.display(),
                        "identity": level.resource.identity(),
                        "limitations": level.resource.limitations(),
                    },
                    "format": level.format.name(),
                    "format_id": level.format.name().to_lowercase(),
                    "entry": {
                        "size": level.size,
                        "name": level.name,
                        "representation": "logical",
                    },
                });
                if let Some(authentication) = &level.authentication {
                    step["authentication"] = crate::rows::authentication_json(authentication);
                }
                step
            })
            .collect();
        json!({
            "depth": self.chain.len(),
            "decoded_bytes": self.budget_used,
            "trust": {
                "metadata": "see chain[].authentication",
                "payload": "not_authenticated",
                "note": "a valid metadata signature does not authenticate payload bytes",
            },
            "root": {
                "kind": "file",
                "name": self
                    .root
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
                "format": self.root_format.name(),
                "format_id": self.root_format.name().to_lowercase(),
            },
            "chain": chain,
            "selection": selection,
            "representation": representation,
        })
    }
}

/// Resolves `enters` from `file`, one archive at a time, with the default
/// limits. The final archive is `path`, a temporary file when at least one
/// selector was applied.
pub fn resolve(
    file: &std::path::Path,
    executable: Option<&std::path::Path>,
    enters: &[Selector],
    cancel: &AtomicBool,
) -> Result<Resolved, String> {
    resolve_with(file, executable, enters, cancel, &Limits::default())
}

/// [`resolve`] with explicit limits.
pub fn resolve_with(
    file: &std::path::Path,
    executable: Option<&std::path::Path>,
    enters: &[Selector],
    cancel: &AtomicBool,
    limits: &Limits,
) -> Result<Resolved, String> {
    let root_format = identify_path(file)?;
    if enters.len() >= limits.max_depth {
        return Err(format!(
            "at most {} archives can be nested; {} selectors were given",
            limits.max_depth - 1,
            enters.len()
        ));
    }
    let mut current = Current {
        path: file.to_path_buf(),
        format: root_format,
        resource: ResourcePath::root(crate::rows::table_name(file)),
        temp: None,
    };
    let mut chain = Vec::with_capacity(enters.len());
    let mut used = 0u64;
    for &selector in enters {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        let step = enter(&current, selector, executable, cancel, used, limits)?;
        used = add_budget(used, step.size, limits.max_chain_bytes)?;
        chain.push(step.level.clone());
        current = Current {
            path: step.path,
            format: step.format,
            resource: step.level.resource,
            temp: step.temp,
        };
    }
    Ok(Resolved {
        path: current.path,
        format: current.format,
        root: file.to_path_buf(),
        root_format,
        chain,
        budget_used: used,
        _temp: current.temp,
    })
}

/// Adds one decoded archive to the cumulative budget. Checked, so an
/// overflowing size is refused rather than wrapping.
fn add_budget(used: u64, size: u64, limit: u64) -> Result<u64, String> {
    let total = used
        .checked_add(size)
        .ok_or_else(|| "the decoded byte budget overflowed".to_string())?;
    if total > limit {
        return Err(format!(
            "the archives on this path would decompress to more than {limit} bytes"
        ));
    }
    Ok(total)
}

struct Current {
    path: std::path::PathBuf,
    format: Format,
    /// The canonical path of the archive at `path`.
    resource: ResourcePath,
    temp: Option<tempfile::TempPath>,
}

struct Step {
    level: Level,
    path: std::path::PathBuf,
    format: Format,
    size: u64,
    temp: Option<tempfile::TempPath>,
}

fn identify_path(path: &std::path::Path) -> Result<Format, String> {
    let mut source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    match archive::identify(&mut source)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?
    {
        Identified::Archive(format) => Ok(format),
        Identified::Invalid { format, reason } => Err(format!(
            "{} is not a valid {format} archive: {reason}",
            path.display()
        )),
        Identified::Unknown => Err(format!(
            "{} is not an archive in a supported format",
            path.display()
        )),
    }
}

fn enter(
    current: &Current,
    selector: Selector,
    executable: Option<&std::path::Path>,
    cancel: &AtomicBool,
    used: u64,
    limits: &Limits,
) -> Result<Step, String> {
    match (current.format, selector) {
        (Format::Rpf9, Selector::Row(row)) => {
            enter_row(current, row, executable, cancel, used, limits)
        }
        (Format::Rpf9, Selector::Zip(_)) => Err(
            "the current archive is RPF9; use a row:N selector to enter one of its rows"
                .to_string(),
        ),
        (Format::Zip, Selector::Zip(index)) => enter_zip(current, index, cancel, used, limits),
        (Format::Zip, Selector::Row(_)) => Err(
            "the current archive is ZIP; use a zip:N selector to enter one of its entries"
                .to_string(),
        ),
    }
}

fn enter_row(
    current: &Current,
    row: u32,
    executable: Option<&std::path::Path>,
    cancel: &AtomicBool,
    used: u64,
    limits: &Limits,
) -> Result<Step, String> {
    // The row records and the name tables come from the same listing the
    // read-only commands print, so an entered archive is named the same way.
    let listing = crate::rows::Listing::open(&current.path, executable, &[], cancel)?;
    let rows = listing.entries().len();
    if u64::try_from(rows).unwrap_or(u64::MAX) > limits.max_entries {
        return Err(format!(
            "the table of contents of {} has {rows} rows, more than the {} row limit",
            current.path.display(),
            limits.max_entries
        ));
    }
    let position = usize::try_from(row)
        .ok()
        .filter(|&position| position < rows);
    let Some(position) = position else {
        return Err(match rows {
            0 => "the nested archive has no rows".to_string(),
            1 => "row 0 is the only row of the nested archive; the selector is out of range"
                .to_string(),
            _ => format!(
                "the nested archive has {rows} rows, numbered 0 to {}",
                rows - 1
            ),
        });
    };
    let entry = &listing.entries()[position];
    let entry_id = listing
        .entry_id(position)
        .cloned()
        .expect("every row has an identity");
    let resource = current.resource.clone().push(entry_id);
    let alternates = listing.alternates();
    let payload = entry
        .payload(&listing.opened().source, alternates.sources())
        .map_err(|err| format!("{} cannot be decoded: {err}", resource.display()))?;
    let size = payload.len();
    if size > limits.max_archive_bytes {
        return Err(format!(
            "{} decodes to {size} bytes, more than the {} byte limit",
            resource.display(),
            limits.max_archive_bytes
        ));
    }
    let room = limits.max_chain_bytes.saturating_sub(used);
    if size > room {
        return Err(format!(
            "the archives on this path would decompress to more than {} bytes",
            limits.max_chain_bytes
        ));
    }
    let (source, temp) = spool_payload(payload, size, cancel)?;
    let (temp, format) = identify_temp(source, temp, &resource.display())?;
    let path = temp.to_path_buf();
    Ok(Step {
        level: Level {
            selector: Selector::Row(row),
            resource,
            format,
            size,
            name: None,
            authentication: Some(listing.opened().authentication.clone()),
        },
        path,
        format,
        size,
        temp: Some(temp),
    })
}

fn enter_zip(
    current: &Current,
    index: usize,
    cancel: &AtomicBool,
    used: u64,
    limits: &Limits,
) -> Result<Step, String> {
    let mut source = Source::open(&current.path)
        .map_err(|err| format!("cannot open {}: {err}", current.path.display()))?;
    let len = source.len();
    // The central directory keeps every record, so `index` is the record's
    // position even when several records share a name.
    let zip = zip_archive::Archive::read(
        &mut source,
        &zip_archive::Limits {
            max_entries: limits.max_entries,
            ..zip_archive::Limits::default()
        },
        cancel,
    )
    .map_err(|err| format!("cannot read the ZIP archive: {err}"))?;
    let entry = zip.entry(index).map_err(|err| err.to_string())?;
    if entry.is_dir() {
        return Err(format!("ZIP entry {index} is a directory, not a file"));
    }
    if entry.is_encrypted() {
        return Err(format!(
            "ZIP entry {index} is encrypted; its payload cannot be decoded"
        ));
    }
    let size = entry.uncompressed_size;
    if size > limits.max_archive_bytes {
        return Err(format!(
            "ZIP entry {index} decodes to {size} bytes, more than the {} byte limit",
            limits.max_archive_bytes
        ));
    }
    let room = limits.max_chain_bytes.saturating_sub(used);
    if size > room {
        return Err(format!(
            "the archives on this path would decompress to more than {} bytes",
            limits.max_chain_bytes
        ));
    }
    let (source, temp) = spool_entry(&zip, &mut source, len, entry, size, cancel)?;
    let (temp, format) = identify_temp(source, temp, &entry.name)?;
    let path = temp.to_path_buf();
    let entry_id = EntryId::named(entry.name.clone(), None, Locator::Zip(index));
    Ok(Step {
        level: Level {
            selector: Selector::Zip(index),
            resource: current.resource.clone().push(entry_id),
            format,
            size,
            name: Some(entry.name.clone()),
            authentication: None,
        },
        path,
        format,
        size,
        temp: Some(temp),
    })
}

/// Identifies the temporary file as an archive and returns the handle that
/// keeps it alive.
fn identify_temp(
    mut source: Source,
    temp: tempfile::TempPath,
    what: &str,
) -> Result<(tempfile::TempPath, Format), String> {
    let result =
        archive::identify(&mut source).map_err(|err| format!("cannot read the {what}: {err}"))?;
    match result {
        Identified::Archive(format) => Ok((temp, format)),
        Identified::Invalid { format, reason } => Err(format!(
            "the {what} is not a valid {format} archive: {reason}"
        )),
        Identified::Unknown => Err(format!(
            "the {what} is not an archive in a supported format"
        )),
    }
}

fn spool_payload(
    mut payload: Payload,
    size: u64,
    cancel: &AtomicBool,
) -> Result<(Source, tempfile::TempPath), String> {
    let mut file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("cannot create a temporary file: {err}"))?;
    let mut buf = vec![0; COPY_LEN];
    let mut written = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".to_string());
        }
        let n = payload
            .read_cancellable(&mut buf, cancel)
            .map_err(|err| format!("cannot decode the nested archive: {err}"))?;
        if n == 0 {
            break;
        }
        written = written
            .checked_add(n as u64)
            .ok_or_else(|| "the decoded size overflowed".to_string())?;
        if written > size {
            return Err("the decoded payload is larger than its declared size".to_string());
        }
        file.write_all(&buf[..n])
            .map_err(|err| format!("cannot write the temporary file: {err}"))?;
    }
    if written != size {
        return Err(format!(
            "the decoded payload holds {written} bytes, not its declared {size}"
        ));
    }
    let (file, path) = file.into_parts();
    let source = Source::from_file(file)
        .map_err(|err| format!("cannot reopen the temporary file: {err}"))?;
    Ok((source, path))
}

fn spool_entry(
    zip: &zip_archive::Archive,
    reader: &mut Source,
    len: u64,
    entry: &zip_archive::Entry,
    size: u64,
    cancel: &AtomicBool,
) -> Result<(Source, tempfile::TempPath), String> {
    let mut file = tempfile::NamedTempFile::new()
        .map_err(|err| format!("cannot create a temporary file: {err}"))?;
    zip.decode_entry(reader, len, entry, cancel, size, &mut file)
        .map_err(|err| format!("the ZIP entry cannot be decoded: {err}"))?;
    let (file, path) = file.into_parts();
    let source = Source::from_file(file)
        .map_err(|err| format!("cannot reopen the temporary file: {err}"))?;
    Ok((source, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpf9() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x40];
        bytes[..4].copy_from_slice(b"9FPR");
        bytes[4..8].copy_from_slice(&0x40u32.to_le_bytes());
        bytes
    }

    fn zip_bytes(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut out);
        for (name, data) in files {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
        out.into_inner()
    }

    fn write(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.bin");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn parses_selectors_without_ambiguity() {
        assert_eq!("row:12".parse::<Selector>(), Ok(Selector::Row(12)));
        assert_eq!("row:0x10".parse::<Selector>(), Ok(Selector::Row(16)));
        assert_eq!("zip:3".parse::<Selector>(), Ok(Selector::Zip(3)));
        assert_eq!("zip-index:3".parse::<Selector>(), Ok(Selector::Zip(3)));
        assert!("12".parse::<Selector>().is_err());
        assert!("entry:1".parse::<Selector>().is_err());
        assert!("row:nope".parse::<Selector>().is_err());
        assert!("row:-1".parse::<Selector>().is_err());
    }

    #[test]
    fn the_cumulative_budget_is_checked() {
        assert_eq!(add_budget(1, 2, 3), Ok(3));
        assert!(add_budget(2, 2, 3).is_err());
        assert!(add_budget(u64::MAX, 1, u64::MAX).is_err());
    }

    #[test]
    fn refuses_a_chain_deeper_than_the_limit() {
        let (_dir, path) = write(&rpf9());
        let cancel = AtomicBool::new(false);
        let limits = Limits {
            max_depth: 2,
            ..Limits::default()
        };
        let enters = [Selector::Row(0), Selector::Row(0)];
        let err = resolve_with(&path, None, &enters, &cancel, &limits).unwrap_err();
        assert!(err.contains("at most 1 archives"), "{err}");
    }

    #[test]
    fn refuses_an_archive_with_too_many_entries() {
        let (_dir, path) = write(&zip_bytes(&[("a", b"one"), ("b", b"two")]));
        let cancel = AtomicBool::new(false);
        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        let err = resolve_with(&path, None, &[Selector::Zip(0)], &cancel, &limits).unwrap_err();
        assert!(err.contains("more than the 1 entry limit"), "{err}");
    }
}
