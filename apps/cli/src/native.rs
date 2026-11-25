//! Shared helpers for the archive commands that read the native table of
//! contents directly, rather than the scan-recovered index.
//!
//! Companion resolution reuses the rage9 primitives the desktop uses, without
//! a dependency on desktop UI code: [`Metadata::companions`] parses `B`
//! sub-block 3 and [`Companions::open`] opens each record in the archive's
//! directory with its path-traversal, symlink and header checks.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_binary::pe::ExecutableView;
use lforge_rage9::rpf;
use lforge_rage9::rpf::metadata::verify::{
    OpenReport, VerifyOutcome, VerifyReport, open_authenticated,
};
use lforge_rage9::rpf::metadata::{Companion, CompanionStatus, Metadata, Stored};

/// How the native table of contents was obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// The archive has no processing pass, so its stored metadata is the
    /// table the engine reads.
    NotApplicable,
    /// The signature verified and steps 4 and 5 decoded the metadata.
    Authenticated(VerifyReport),
}

impl Authentication {
    pub fn status(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Authenticated(_) => "authenticated",
        }
    }

    pub fn report(&self) -> Option<&VerifyReport> {
        match self {
            Self::NotApplicable => None,
            Self::Authenticated(report) => Some(report),
        }
    }
}

/// An opened archive and the native table of contents the engine would read.
pub struct Opened {
    pub source: Source,
    pub metadata: Metadata,
    pub authentication: Authentication,
}

/// Opens `path`, reads the RPF9 header and decodes the native table of
/// contents.
///
/// Unprocessed metadata is decoded directly. Encrypted metadata requires an
/// `executable` and is used only after the signature verifies. Malformed or
/// oversized metadata is rejected. `limit` caps the metadata area read into
/// memory.
pub fn open_metadata(path: &Path, limit: u64, executable: Option<&Path>) -> Result<Opened, String> {
    open_metadata_cancellable(path, limit, executable, &AtomicBool::new(false))
}

/// [`open_metadata`] with a cancellation flag. Cancellation is checked before
/// expensive reads and passed to the authentication path.
pub fn open_metadata_cancellable(
    path: &Path,
    limit: u64,
    executable: Option<&Path>,
    cancel: &AtomicBool,
) -> Result<Opened, String> {
    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
        return Err("cancelled".to_string());
    }
    let mut source =
        Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    rpf::read_header(&mut source).map_err(|err| format!("{}: {err}", path.display()))?;
    // The header, and at most the A table, decide whether the stored bytes can
    // be used before all of them are read.
    let probe =
        Stored::probe(&mut source.clone()).map_err(|err| format!("{}: {err}", path.display()))?;
    if probe.processing.is_none() {
        let metadata = Stored::read(&mut source.clone(), limit)
            .and_then(Stored::decode)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        return Ok(Opened {
            source,
            metadata,
            authentication: Authentication::NotApplicable,
        });
    }
    let Some(executable) = executable else {
        let reason = probe
            .unsupported()
            .unwrap_or_else(|| "the metadata is processed".to_string());
        return Err(format!(
            "the table of contents of {} is not read: it is processed and requires --executable: {reason}",
            path.display()
        ));
    };
    let view = ExecutableView::open(executable)
        .map_err(|err| format!("cannot open {}: {err}", executable.display()))?;
    let open: OpenReport = open_authenticated(&mut source.clone(), &view, cancel)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let report = open.report;
    let Some(authenticated) = open.authenticated else {
        return Err(format!(
            "the table of contents of {} is not authenticated: {} (stage {})",
            path.display(),
            report.outcome,
            report.stage
        ));
    };
    if report.outcome != VerifyOutcome::MetadataDecodedAuthenticated {
        return Err(format!(
            "the table of contents of {} is not authenticated: {} (stage {})",
            path.display(),
            report.outcome,
            report.stage
        ));
    }
    Ok(Opened {
        source,
        metadata: authenticated.into_metadata(),
        authentication: Authentication::Authenticated(report),
    })
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
