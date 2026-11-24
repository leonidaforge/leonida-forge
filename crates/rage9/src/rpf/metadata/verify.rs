//! Full RPF9 metadata verification.
//!
//! The sequence follows the engine:
//!
//! 1. Step 1 decrypts the static A and B spans with the selected provider.
//! 2. Step 2 verifies the signature over the post-step-1 metadata spans.
//! 3. Steps 4 and 5 decrypt the primary and secondary areas with the
//!    archive's sub-block 1 descriptor.
//!
//! Only a successful signature check reports authenticated metadata. A
//! successful step 4/5 pass without a signature is reported as decoded but
//! unverified.

use std::fmt;
use std::io::{Read, Seek};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::pe::ExecutableView;

use super::probe::ATableSummary;
use super::provider::{EncodedAesError, FixedTablesError, SelectionError, select_source};
use super::recognize::{DescriptorError, RecognitionError, RegistryError};
use super::signature::{self, SignatureError};
use super::transform::Error as CipherError;
use super::{Error as MetadataError, Stored, step1_a_span};

/// Larger metadata areas are not read.
pub const MAX_METADATA: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureOutcome {
    /// The signature was not checked.
    NotPerformed,
    /// The signature exists but cannot be checked.
    Unavailable(&'static str),
    Valid,
    Invalid,
    /// A record or scheme that is not supported.
    Unsupported(&'static str),
}

impl SignatureOutcome {
    pub fn is_valid(&self) -> bool {
        matches!(self, SignatureOutcome::Valid)
    }
}

impl fmt::Display for SignatureOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureOutcome::NotPerformed => f.write_str("not performed"),
            SignatureOutcome::Unavailable(reason) => write!(f, "unavailable: {reason}"),
            SignatureOutcome::Valid => f.write_str("valid"),
            SignatureOutcome::Invalid => f.write_str("invalid"),
            SignatureOutcome::Unsupported(reason) => write!(f, "unsupported: {reason}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    NotApplicable,
    ATableImplausible(&'static str),
    ATableAmbiguous,
    RegistryUnsupported(&'static str),
    DescriptorUnsupported(&'static str),
    StateUnsupported(&'static str),
    FixedTablesUnsupported(&'static str),
    BlockUnsupported(&'static str),
    /// Steps 4 and 5 succeeded, but no signature verified.
    MetadataDecodedUnverified,
    /// Steps 4 and 5 succeeded and the signature verified.
    MetadataDecodedAuthenticated,
    /// The signature did not verify.
    SignatureInvalid,
    /// A signature exists but could not be checked.
    AuthenticationUnavailable(&'static str),
    /// A later transformation is not supported.
    UnsupportedTransformation(&'static str),
    MalformedMetadata(&'static str),
    Cancelled,
    ResourceLimit {
        what: &'static str,
        limit: u64,
    },
}

impl VerifyOutcome {
    pub fn is_authenticated(&self) -> bool {
        matches!(self, VerifyOutcome::MetadataDecodedAuthenticated)
    }
}

impl fmt::Display for VerifyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyOutcome::NotApplicable => f.write_str("not applicable"),
            VerifyOutcome::ATableImplausible(reason) => {
                write!(f, "A table implausible: {reason}")
            }
            VerifyOutcome::ATableAmbiguous => f.write_str("more than one plausible A table"),
            VerifyOutcome::RegistryUnsupported(reason) => {
                write!(f, "registry unsupported: {reason}")
            }
            VerifyOutcome::DescriptorUnsupported(reason) => {
                write!(f, "descriptor unsupported: {reason}")
            }
            VerifyOutcome::StateUnsupported(reason) => write!(f, "state unsupported: {reason}"),
            VerifyOutcome::FixedTablesUnsupported(reason) => {
                write!(f, "fixed tables unsupported: {reason}")
            }
            VerifyOutcome::BlockUnsupported(reason) => {
                write!(f, "block unsupported: {reason}")
            }
            VerifyOutcome::MetadataDecodedUnverified => {
                f.write_str("metadata decoded but unverified")
            }
            VerifyOutcome::MetadataDecodedAuthenticated => {
                f.write_str("metadata decoded and signature verified")
            }
            VerifyOutcome::SignatureInvalid => f.write_str("signature invalid"),
            VerifyOutcome::AuthenticationUnavailable(reason) => {
                write!(f, "authentication unavailable: {reason}")
            }
            VerifyOutcome::UnsupportedTransformation(reason) => {
                write!(f, "unsupported transformation: {reason}")
            }
            VerifyOutcome::MalformedMetadata(reason) => {
                write!(f, "malformed metadata: {reason}")
            }
            VerifyOutcome::Cancelled => f.write_str("cancelled"),
            VerifyOutcome::ResourceLimit { what, limit } => {
                write!(f, "the {what} exceeds the limit of {limit}")
            }
        }
    }
}

/// The result of a full verification attempt. It contains no decrypted bytes,
/// key identifiers, IVs or key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub outcome: VerifyOutcome,
    /// The earliest failing stage, or `"complete"`.
    pub stage: &'static str,
    pub a_table: Option<ATableSummary>,
    pub candidates: usize,
    pub selected_candidate: Option<usize>,
    pub signature: SignatureOutcome,
    /// `None` when steps 4 and 5 were not attempted; `Some(false)` when there
    /// was no sub-block 1 descriptor; `Some(true)` when they ran.
    pub archive_pass: Option<bool>,
}

impl VerifyReport {
    fn not_applicable() -> Self {
        Self {
            outcome: VerifyOutcome::NotApplicable,
            stage: "header",
            a_table: None,
            candidates: 0,
            selected_candidate: None,
            signature: SignatureOutcome::NotPerformed,
            archive_pass: None,
        }
    }
}

/// A failure that prevents a report: the archive header or layout is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Archive(&'static str),
    Read(&'static str),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Archive(reason) => write!(f, "the archive is not usable: {reason}"),
            VerifyError::Read(reason) => write!(f, "the archive could not be read: {reason}"),
        }
    }
}

impl std::error::Error for VerifyError {}

fn archive_error(error: MetadataError) -> VerifyError {
    let reason = match error {
        MetadataError::TooLarge { .. } => "the metadata area is too large",
        MetadataError::Io(_) => "the metadata area cannot be read",
        _ => "the header or metadata layout is invalid",
    };
    VerifyError::Archive(reason)
}

/// Runs step 1, signature verification and steps 4 and 5 on an archive.
///
/// The archive is read-only. The report distinguishes structural decoding from
/// cryptographic authentication.
pub fn verify_archive(
    archive: &mut (impl Read + Seek),
    executable: &ExecutableView,
    cancel: &AtomicBool,
) -> Result<VerifyReport, VerifyError> {
    let probe = Stored::probe(archive).map_err(archive_error)?;
    if probe.prefix.selector == 0 {
        return Ok(VerifyReport::not_applicable());
    }
    let stored = Stored::read(archive, MAX_METADATA).map_err(archive_error)?;
    let a_span = step1_a_span(&stored.prefix, &stored.layout)
        .map_err(|_| VerifyError::Archive("the step-1 A span is invalid"))?;
    let a_bytes = stored.bytes().get(a_span).ok_or(VerifyError::Archive(
        "the step-1 A span lies outside the metadata",
    ))?;

    let selection = match select_source(
        a_bytes,
        stored.prefix.a_records,
        stored.prefix.b_len,
        executable,
        stored.prefix.selector,
        cancel,
    ) {
        Ok(selection) => selection,
        Err(error) => return Ok(selection_failure(error)),
    };
    let mut report = VerifyReport {
        outcome: VerifyOutcome::ATableImplausible("the A table was not checked"),
        stage: "a_table",
        a_table: Some(selection.a_table),
        candidates: selection.candidates,
        selected_candidate: Some(selection.selected),
        signature: SignatureOutcome::NotPerformed,
        archive_pass: None,
    };

    let (mut bytes, _) = match stored.decrypt_step1(&selection.source) {
        Ok(decoded) => decoded,
        Err(error) => return Ok(metadata_failure(error, report, "step1")),
    };
    if cancel.load(Ordering::Relaxed) {
        report.outcome = VerifyOutcome::Cancelled;
        report.stage = "step1";
        return Ok(report);
    }

    let (signature_state, signature_outcome) = check_signature(&stored, &bytes, executable, cancel);
    report.signature = signature_state;
    if let Some(outcome) = signature_outcome {
        report.outcome = outcome;
        report.stage = "signature";
        return Ok(report);
    }

    if let Some(skipped) = match stored.decrypt_archive(&mut bytes, &selection.source) {
        Ok(skipped) => skipped,
        Err(error) => return Ok(metadata_failure(error, report, "archive_pass")),
    } {
        report.archive_pass = Some(true);
        report.stage = if skipped {
            "archive_pass_identity"
        } else {
            "archive_pass"
        };
        report.outcome = if report.signature.is_valid() {
            VerifyOutcome::MetadataDecodedAuthenticated
        } else {
            VerifyOutcome::MetadataDecodedUnverified
        };
    } else {
        report.archive_pass = Some(false);
        report.stage = "archive_descriptor";
        report.outcome = if report.signature.is_valid() {
            VerifyOutcome::MetadataDecodedAuthenticated
        } else {
            VerifyOutcome::MetadataDecodedUnverified
        };
    }
    Ok(report)
}

/// Returns the signature state and, on a terminal failure, the report outcome.
fn check_signature(
    stored: &Stored,
    bytes: &[u8],
    executable: &ExecutableView,
    cancel: &AtomicBool,
) -> (SignatureOutcome, Option<VerifyOutcome>) {
    let record = match signature::record(stored, bytes) {
        Ok(record) => record,
        Err(SignatureError::Missing) => {
            return (
                SignatureOutcome::Unavailable("no signature record"),
                Some(VerifyOutcome::AuthenticationUnavailable(
                    "no signature record",
                )),
            );
        }
        Err(SignatureError::UnsupportedMessageType(_)) => {
            return (
                SignatureOutcome::Unsupported("unsupported message type"),
                Some(VerifyOutcome::UnsupportedTransformation(
                    "unsupported signature message type",
                )),
            );
        }
        Err(SignatureError::Cancelled) => {
            return (
                SignatureOutcome::NotPerformed,
                Some(VerifyOutcome::Cancelled),
            );
        }
        Err(SignatureError::ResourceLimit { what, limit }) => {
            return (
                SignatureOutcome::NotPerformed,
                Some(VerifyOutcome::ResourceLimit { what, limit }),
            );
        }
        Err(SignatureError::Malformed(reason)) => {
            return (
                SignatureOutcome::Unavailable(reason),
                Some(VerifyOutcome::MalformedMetadata(reason)),
            );
        }
        Err(_) => {
            return (
                SignatureOutcome::Unavailable("the signature record is unusable"),
                Some(VerifyOutcome::AuthenticationUnavailable(
                    "the signature record is unusable",
                )),
            );
        }
    };
    let spans = match signature::message_spans(stored, &record) {
        Ok(spans) => spans,
        Err(SignatureError::Cancelled) => {
            return (
                SignatureOutcome::NotPerformed,
                Some(VerifyOutcome::Cancelled),
            );
        }
        Err(SignatureError::ResourceLimit { what, limit }) => {
            return (
                SignatureOutcome::NotPerformed,
                Some(VerifyOutcome::ResourceLimit { what, limit }),
            );
        }
        Err(_) => {
            return (
                SignatureOutcome::Unavailable("the signed spans are unusable"),
                Some(VerifyOutcome::MalformedMetadata(
                    "the signed spans are unusable",
                )),
            );
        }
    };
    let message = signature::message(bytes, &spans);
    let key = match signature::resolve_public_key(executable, record.key_id, cancel) {
        Ok(key) => key,
        Err(SignatureError::Cancelled) => {
            return (
                SignatureOutcome::NotPerformed,
                Some(VerifyOutcome::Cancelled),
            );
        }
        Err(SignatureError::ResourceLimit { what, limit }) => {
            return (
                SignatureOutcome::NotPerformed,
                Some(VerifyOutcome::ResourceLimit { what, limit }),
            );
        }
        Err(SignatureError::KeyNotFound) => {
            return (SignatureOutcome::Unavailable("no verification key"), None);
        }
        Err(SignatureError::KeyAmbiguous) => {
            return (
                SignatureOutcome::Unavailable("more than one verification key"),
                None,
            );
        }
        Err(SignatureError::KeyMalformed(reason)) => {
            return (SignatureOutcome::Unavailable(reason), None);
        }
        Err(SignatureError::Image(_)) => {
            return (
                SignatureOutcome::Unavailable("the executable could not be read"),
                None,
            );
        }
        Err(_) => {
            return (
                SignatureOutcome::Unavailable("the verification key is unusable"),
                None,
            );
        }
    };
    let signature_bytes = bytes.get(record.signature.clone()).unwrap_or_default();
    match signature::verify_message(&key, &message, signature_bytes) {
        Ok(()) => (SignatureOutcome::Valid, None),
        Err(SignatureError::Invalid) => (
            SignatureOutcome::Invalid,
            Some(VerifyOutcome::SignatureInvalid),
        ),
        Err(SignatureError::Cancelled) => (
            SignatureOutcome::NotPerformed,
            Some(VerifyOutcome::Cancelled),
        ),
        Err(SignatureError::ResourceLimit { what, limit }) => (
            SignatureOutcome::NotPerformed,
            Some(VerifyOutcome::ResourceLimit { what, limit }),
        ),
        Err(_) => (
            SignatureOutcome::Unavailable("the signature could not be verified"),
            None,
        ),
    }
}

fn selection_failure(error: SelectionError) -> VerifyReport {
    let (outcome, stage) = match error {
        SelectionError::Recognition(RecognitionError::Registry(error)) => registry_failure(error),
        SelectionError::Recognition(RecognitionError::Descriptor(error)) => {
            descriptor_failure(error)
        }
        SelectionError::FixedTables(error) => fixed_failure(error),
        SelectionError::Block(EncodedAesError::InvalidState(reason)) => {
            (VerifyOutcome::BlockUnsupported(reason), "block")
        }
        SelectionError::Cipher(error) => cipher_outcome(error),
        SelectionError::NoPlausible => (
            VerifyOutcome::ATableImplausible(
                "no fixed table candidate produced a plausible A table",
            ),
            "a_table",
        ),
        SelectionError::Ambiguous => (VerifyOutcome::ATableAmbiguous, "a_table"),
        SelectionError::Cancelled => (VerifyOutcome::Cancelled, "selection"),
    };
    VerifyReport {
        outcome,
        stage,
        a_table: None,
        candidates: 0,
        selected_candidate: None,
        signature: SignatureOutcome::NotPerformed,
        archive_pass: None,
    }
}

fn registry_failure(error: RegistryError) -> (VerifyOutcome, &'static str) {
    match error {
        RegistryError::ResourceLimit { what, limit } => {
            (VerifyOutcome::ResourceLimit { what, limit }, "registry")
        }
        RegistryError::Cancelled => (VerifyOutcome::Cancelled, "registry"),
        RegistryError::NotFound => (
            VerifyOutcome::RegistryUnsupported("no key registry was found"),
            "registry",
        ),
        RegistryError::Ambiguous => (
            VerifyOutcome::RegistryUnsupported("more than one key registry was found"),
            "registry",
        ),
        RegistryError::NoCompatibleState => (
            VerifyOutcome::StateUnsupported("no compatible key state"),
            "state",
        ),
        RegistryError::StateMalformed(reason) => (VerifyOutcome::StateUnsupported(reason), "state"),
        RegistryError::Image(_) => (
            VerifyOutcome::RegistryUnsupported("the executable could not be read"),
            "registry",
        ),
    }
}

fn descriptor_failure(error: DescriptorError) -> (VerifyOutcome, &'static str) {
    match error {
        DescriptorError::ResourceLimit { what, limit } => {
            (VerifyOutcome::ResourceLimit { what, limit }, "descriptor")
        }
        DescriptorError::Cancelled => (VerifyOutcome::Cancelled, "descriptor"),
        DescriptorError::NoCompatibleState
        | DescriptorError::StateAmbiguous
        | DescriptorError::StateMalformed => (
            VerifyOutcome::StateUnsupported("the descriptor's key state is not usable"),
            "state",
        ),
        DescriptorError::UnsupportedCipher => (
            VerifyOutcome::DescriptorUnsupported("the cipher type is not supported"),
            "descriptor",
        ),
        DescriptorError::UnsupportedLayout(reason) => {
            (VerifyOutcome::DescriptorUnsupported(reason), "descriptor")
        }
        DescriptorError::MalformedParameter
        | DescriptorError::MalformedObject
        | DescriptorError::WriterNotFound
        | DescriptorError::WriterAmbiguous
        | DescriptorError::DescriptorNotFound
        | DescriptorError::DescriptorAmbiguous
        | DescriptorError::AmbiguousMapping
        | DescriptorError::Image(_) => (
            VerifyOutcome::DescriptorUnsupported("the descriptor was not recognized"),
            "descriptor",
        ),
    }
}

fn fixed_failure(error: FixedTablesError) -> (VerifyOutcome, &'static str) {
    match error {
        FixedTablesError::ResourceLimit { what, limit } => {
            (VerifyOutcome::ResourceLimit { what, limit }, "fixed_tables")
        }
        FixedTablesError::Cancelled => (VerifyOutcome::Cancelled, "fixed_tables"),
        FixedTablesError::NotFound => (
            VerifyOutcome::FixedTablesUnsupported("no fixed cipher tables were found"),
            "fixed_tables",
        ),
        FixedTablesError::Ambiguous => (
            VerifyOutcome::FixedTablesUnsupported("more than one fixed table block was found"),
            "fixed_tables",
        ),
        FixedTablesError::Malformed(reason) => (
            VerifyOutcome::FixedTablesUnsupported(reason),
            "fixed_tables",
        ),
        FixedTablesError::Image(_) => (
            VerifyOutcome::FixedTablesUnsupported("the executable could not be read"),
            "fixed_tables",
        ),
    }
}

fn cipher_outcome(error: CipherError) -> (VerifyOutcome, &'static str) {
    match error {
        CipherError::Unaligned(_) | CipherError::OutOfBounds { .. } => (
            VerifyOutcome::MalformedMetadata("a cipher span is not usable"),
            "cipher",
        ),
        CipherError::NoKey(_) | CipherError::NoStaticDescriptor(_) => (
            VerifyOutcome::BlockUnsupported("the key state did not build a block"),
            "block",
        ),
        CipherError::Unsupported { .. } | CipherError::InvalidType(_) => (
            VerifyOutcome::UnsupportedTransformation("the cipher type is not supported"),
            "cipher",
        ),
    }
}

fn metadata_failure(
    error: MetadataError,
    mut report: VerifyReport,
    failed_stage: &'static str,
) -> VerifyReport {
    let (outcome, stage) = match error {
        MetadataError::Cipher(error) => cipher_outcome(error),
        MetadataError::TooLarge { .. } => (
            VerifyOutcome::ResourceLimit {
                what: "metadata",
                limit: MAX_METADATA,
            },
            failed_stage,
        ),
        MetadataError::Transformed(_) => (
            VerifyOutcome::UnsupportedTransformation("a metadata pass is not modelled"),
            failed_stage,
        ),
        MetadataError::Invalid(_) => (
            VerifyOutcome::MalformedMetadata("the metadata layout is invalid"),
            failed_stage,
        ),
        _ => (
            VerifyOutcome::MalformedMetadata("the metadata could not be transformed"),
            failed_stage,
        ),
    };
    report.outcome = outcome;
    report.stage = stage;
    report
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use lforge_binary::Source;
    use lforge_binary::pe::ExecutableView;

    use super::verify_archive;

    #[test]
    #[ignore = "set LEONIDA_FORGE_EXECUTABLE and LEONIDA_FORGE_ARCHIVE to local files to run"]
    fn local_full_verification_smoke_test() {
        let Some(executable) = std::env::var_os("LEONIDA_FORGE_EXECUTABLE") else {
            panic!("set LEONIDA_FORGE_EXECUTABLE to a local executable to run this test");
        };
        let Some(archive) = std::env::var_os("LEONIDA_FORGE_ARCHIVE") else {
            panic!("set LEONIDA_FORGE_ARCHIVE to a local archive to run this test");
        };
        let image = ExecutableView::open(std::path::Path::new(&executable)).unwrap();
        let mut source = Source::open(std::path::Path::new(&archive)).unwrap();
        let report = verify_archive(&mut source, &image, &AtomicBool::new(false)).unwrap();
        eprintln!("outcome: {}", report.outcome);
        eprintln!("stage: {}", report.stage);
        eprintln!("signature: {}", report.signature);
        eprintln!("A table: {:?}", report.a_table);
        eprintln!("candidates: {}", report.candidates);
        eprintln!("selected: {:?}", report.selected_candidate);
        eprintln!("archive pass: {:?}", report.archive_pass);
    }
}
