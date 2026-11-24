//! Shared helpers for the archive commands that read the native table of
//! contents directly, rather than the scan-recovered index.
//!
//! Companion resolution reuses the rage9 primitives the desktop uses, without
//! a dependency on desktop UI code: [`Metadata::companions`] parses `B`
//! sub-block 3 and [`Companions::open`] opens each record in the archive's
//! directory with its path-traversal, symlink and header checks.

use std::path::Path;

use lforge_binary::Source;
use lforge_rage9::rpf;
use lforge_rage9::rpf::metadata::{Companion, CompanionStatus, Metadata, Stored};

/// Opens `path`, reads the RPF9 header and decodes the native table of
/// contents. Metadata that the engine processes before use (an encrypted or
/// otherwise transformed area) is rejected with the reason, as are malformed
/// or oversized areas. `limit` caps the metadata area read into memory.
pub fn open_metadata(path: &Path, limit: u64) -> Result<(Source, Metadata), String> {
    let mut source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    rpf::read_header(&mut source).map_err(|err| format!("{}: {err}", path.display()))?;
    // The header, and at most the A table, decide whether the stored bytes can
    // be used before all of them are read.
    let probe =
        Stored::probe(&mut source.clone()).map_err(|err| format!("{}: {err}", path.display()))?;
    if let Some(reason) = probe.unsupported() {
        return Err(format!(
            "the table of contents of {} is not read: {reason}",
            path.display()
        ));
    }
    let metadata = Stored::read(&mut source.clone(), limit)
        .and_then(Stored::decode)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok((source, metadata))
}

/// The alternate read sources of an archive, resolved from `B` sub-block 3.
/// One entry per companion record, in record order; `None` where the companion
/// is not available, so an entry read through it is refused rather than read
/// from the main archive.
pub struct Alternates {
    pub records: Vec<Companion>,
    pub statuses: Vec<CompanionStatus>,
    sources: Vec<Option<Source>>,
    /// Why sub-block 3 could not be read, if it is malformed.
    pub problem: Option<String>,
}

impl Alternates {
    /// Resolves the companions of `archive`, a file on disk, against its own
    /// directory. The archive is never opened as a companion source.
    pub fn resolve(archive: &Path, metadata: &Metadata) -> Self {
        let list = match metadata.companions() {
            Ok(list) => list,
            Err(err) => {
                return Self {
                    records: Vec::new(),
                    statuses: Vec::new(),
                    sources: Vec::new(),
                    problem: Some(err.to_string()),
                };
            }
        };
        let statuses = list.open(archive);
        let sources = statuses
            .iter()
            .map(|status| status.source().cloned())
            .collect();
        Self {
            records: list.records,
            statuses,
            sources,
            problem: None,
        }
    }

    pub fn sources(&self) -> &[Option<Source>] {
        &self.sources
    }
}
