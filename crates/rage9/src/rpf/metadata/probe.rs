//! The bounded `A`-table compatibility probe.
//!
//! The probe answers one question: does the recognized key provider decrypt
//! the archive's step-1 `A` span into records the layout accepts? It reads the
//! header, the exact step-1 `A` span and nothing else of the metadata area. It
//! stops after step 1. Archive processing, signature verification and RSA
//! authentication are not performed.
//!
//! A passing probe is structural evidence only. It says that one ciphertext
//! span decoded into a plausible table under the recognized key; it does not
//! authenticate the archive or prove the key is the shipping key. A failing
//! probe is likewise not proof of a wrong key: a different build, a different
//! registry layout or an unsupported construct fails the same way.

use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Seek};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::pe::ExecutableView;

use super::provider::{
    EncodedAesError, FixedTablesError, RecognizedSource, SourceError, recognize_fixed_tables,
};
use super::recognize::{
    DescriptorError, Limits, RecognitionError, Recognized, RegistryError, STATIC_STEP1_MODE,
    provider_for, recognize_descriptor, recognize_registry,
};
use super::transform::{Cipher, CipherDescriptor, CipherSource};
use super::{Error as MetadataError, Stored, check_span_formulas, read_range, step1_a_span};

/// The probe reads at most this many bytes of the metadata area.
pub const MAX_PROBE_BYTES: u64 = 1024 * 1024;

/// What the probe did and did not verify.
pub const AUTHENTICATION: &str = "not performed";

/// Where the probe stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The header selects no static pass.
    NotApplicable,
    /// The archive's step-1 layout is not usable.
    ArchiveUnsupported(&'static str),
    /// The executable's key registry was not recognized.
    RegistryUnsupported(&'static str),
    /// The executable's static descriptor was not recognized.
    DescriptorUnsupported(&'static str),
    /// The descriptor's key state is missing, ambiguous or malformed.
    StateUnsupported(&'static str),
    /// The executable's fixed transformation tables were not recognized.
    FixedTablesUnsupported(&'static str),
    /// The encoded block operation could not be built or run.
    BlockUnsupported(&'static str),
    /// The decrypted `A` span is not a plausible table.
    Implausible(&'static str),
    /// The decrypted `A` span is a plausible table.
    Plausible,
    /// The caller cancelled the probe.
    Cancelled,
    /// A bound was exceeded before the probe read the span.
    ResourceLimit { what: &'static str, limit: u64 },
}

impl fmt::Display for ProbeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeOutcome::NotApplicable => f.write_str("not applicable"),
            ProbeOutcome::ArchiveUnsupported(reason) => {
                write!(f, "unsupported archive: {reason}")
            }
            ProbeOutcome::RegistryUnsupported(reason) => {
                write!(f, "unsupported key registry: {reason}")
            }
            ProbeOutcome::DescriptorUnsupported(reason) => {
                write!(f, "unsupported static descriptor: {reason}")
            }
            ProbeOutcome::StateUnsupported(reason) => {
                write!(f, "unsupported key state: {reason}")
            }
            ProbeOutcome::FixedTablesUnsupported(reason) => {
                write!(f, "unsupported fixed tables: {reason}")
            }
            ProbeOutcome::BlockUnsupported(reason) => {
                write!(f, "unsupported block operation: {reason}")
            }
            ProbeOutcome::Implausible(reason) => write!(f, "implausible A table: {reason}"),
            ProbeOutcome::Plausible => f.write_str("plausible A table"),
            ProbeOutcome::Cancelled => f.write_str("cancelled"),
            ProbeOutcome::ResourceLimit { what, limit } => {
                write!(f, "the {what} exceeds the limit of {limit}")
            }
        }
    }
}

impl ProbeOutcome {
    /// Whether the probe completed and the `A` table is plausible.
    pub fn is_plausible(&self) -> bool {
        *self == ProbeOutcome::Plausible
    }

    /// Whether the archive needs no static pass, so the probe does not apply.
    pub fn is_not_applicable(&self) -> bool {
        *self == ProbeOutcome::NotApplicable
    }
}

/// The static descriptor the probe used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorInfo {
    pub index: u8,
    pub kind: u16,
    pub algorithm_id: u8,
    pub provider: u8,
}

/// Counts of a plausible decrypted `A` table. The records themselves are not
/// reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ATableSummary {
    pub records: usize,
    /// Records whose identifier is one of the known sub-block identifiers.
    pub known_ids: usize,
}

/// The probe's report. It contains no paths, key identifiers, key bytes or
/// decrypted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub outcome: ProbeOutcome,
    pub selector: u8,
    pub static_pass: bool,
    pub a_records: u16,
    pub b_size: u32,
    pub registry_records: Option<usize>,
    pub registry_algorithm_states: Option<usize>,
    pub descriptor: Option<DescriptorInfo>,
    pub state_identified: bool,
    pub fixed_tables: bool,
    pub block_initialized: bool,
    pub a_table: Option<ATableSummary>,
    pub authentication: &'static str,
}

impl ProbeReport {
    fn new(prefix: super::Prefix) -> Self {
        Self {
            outcome: ProbeOutcome::NotApplicable,
            selector: prefix.selector,
            static_pass: prefix.selector != 0,
            a_records: prefix.a_records,
            b_size: prefix.b_len,
            registry_records: None,
            registry_algorithm_states: None,
            descriptor: None,
            state_identified: false,
            fixed_tables: false,
            block_initialized: false,
            a_table: None,
            authentication: AUTHENTICATION,
        }
    }
}

/// A failure that leaves no report: the archive could not be read or parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// The header or metadata layout is not readable.
    Archive(&'static str),
    /// The step-1 span could not be read.
    Read(&'static str),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Archive(reason) => write!(f, "the archive is not usable: {reason}"),
            ProbeError::Read(reason) => write!(f, "the archive could not be read: {reason}"),
        }
    }
}

impl std::error::Error for ProbeError {}

fn archive_error(error: MetadataError) -> ProbeError {
    let reason = match error {
        MetadataError::TooLarge { .. } => "the metadata area is too large",
        MetadataError::Io(_) => "the metadata area cannot be read",
        _ => "the header or metadata layout is invalid",
    };
    ProbeError::Archive(reason)
}

fn cancelled(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::Relaxed)
}

/// Probes one archive with the key provider recognized in `executable`.
///
/// It reads the header, validates the step-1 span formulas and reads only the
/// step-1 `A` span, at most [`MAX_PROBE_BYTES`]. The `B` block and the rest of
/// the metadata area stay unread.
pub fn probe(
    archive: &mut (impl Read + Seek),
    executable: &ExecutableView,
    cancel: &AtomicBool,
) -> Result<ProbeReport, ProbeError> {
    probe_with_limit(archive, executable, cancel, MAX_PROBE_BYTES)
}

pub(crate) fn probe_with_limit(
    archive: &mut (impl Read + Seek),
    executable: &ExecutableView,
    cancel: &AtomicBool,
    max_probe_bytes: u64,
) -> Result<ProbeReport, ProbeError> {
    let stored = Stored::probe(archive).map_err(archive_error)?;
    let mut report = ProbeReport::new(stored.prefix);
    if !report.static_pass {
        return Ok(report);
    }

    check_span_formulas(&stored.prefix, &stored.layout)
        .map_err(|_| ProbeError::Archive("the cipher spans disagree with the layout"))?;
    let span = step1_a_span(&stored.prefix, &stored.layout)
        .map_err(|_| ProbeError::Archive("the step-1 A span is invalid"))?;
    if span.len() as u64 > max_probe_bytes {
        report.outcome = ProbeOutcome::ResourceLimit {
            what: "step-1 A span bytes",
            limit: max_probe_bytes,
        };
        return Ok(report);
    }
    if cancelled(cancel) {
        report.outcome = ProbeOutcome::Cancelled;
        return Ok(report);
    }

    let registry = match recognize_registry(executable, cancel) {
        Ok(registry) => registry,
        Err(error) => {
            report.outcome = registry_outcome(error);
            return Ok(report);
        }
    };
    report.registry_records = Some(registry.record_count());
    report.registry_algorithm_states = Some(registry.algorithm_state_count());
    if cancelled(cancel) {
        report.outcome = ProbeOutcome::Cancelled;
        return Ok(report);
    }

    let descriptor = match recognize_descriptor(
        executable,
        stored.prefix.selector,
        cancel,
        Limits::default(),
    ) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            report.outcome = descriptor_outcome(error);
            return Ok(report);
        }
    };
    let algorithm = match descriptor.algorithm() {
        Ok(algorithm) => algorithm,
        Err(_) => {
            report.outcome =
                ProbeOutcome::DescriptorUnsupported("the cipher type is not supported");
            return Ok(report);
        }
    };
    report.descriptor = Some(DescriptorInfo {
        index: descriptor.index(),
        kind: descriptor.kind(),
        algorithm_id: algorithm.id(),
        provider: provider_for(algorithm.id(), STATIC_STEP1_MODE),
    });
    if cancelled(cancel) {
        report.outcome = ProbeOutcome::Cancelled;
        return Ok(report);
    }

    if let Err(error) =
        registry.state_for_key(descriptor.key_id(), algorithm.id(), STATIC_STEP1_MODE)
    {
        report.outcome = state_outcome(error);
        return Ok(report);
    }
    report.state_identified = true;
    if cancelled(cancel) {
        report.outcome = ProbeOutcome::Cancelled;
        return Ok(report);
    }

    let tables = match recognize_fixed_tables(executable, cancel) {
        Ok(tables) => tables,
        Err(error) => {
            report.outcome = fixed_tables_outcome(error);
            return Ok(report);
        }
    };
    report.fixed_tables = true;
    if cancelled(cancel) {
        report.outcome = ProbeOutcome::Cancelled;
        return Ok(report);
    }

    let recognized = match Recognized::from_parts(registry, descriptor) {
        Ok(recognized) => recognized,
        Err(_) => {
            report.outcome =
                ProbeOutcome::DescriptorUnsupported("the static descriptor is invalid");
            return Ok(report);
        }
    };
    let source = match RecognizedSource::from_parts(recognized, tables) {
        Ok(source) => source,
        Err(error) => {
            report.outcome = source_outcome(error);
            if matches!(report.outcome, ProbeOutcome::StateUnsupported(_)) {
                report.state_identified = false;
            }
            return Ok(report);
        }
    };
    report.block_initialized = true;

    let mut bytes = read_range(archive, span)
        .map_err(|_| ProbeError::Read("the step-1 A span could not be read"))?;
    let index = stored.prefix.selector >> 1;
    let Some(descriptor) = step1_descriptor(&source, index) else {
        report.outcome = ProbeOutcome::BlockUnsupported("the static descriptor is not available");
        return Ok(report);
    };
    let mut cipher = match Cipher::new(&descriptor, |key_id| {
        source.cbc_block_for(descriptor.kind, key_id)
    }) {
        Ok(cipher) => cipher,
        Err(_) => {
            report.outcome = ProbeOutcome::BlockUnsupported("the key state did not build a block");
            return Ok(report);
        }
    };
    let span_len = bytes.len();
    let a_span = 0..span_len;
    if let Err(error) = cipher.run(&mut bytes, std::slice::from_ref(&a_span)) {
        report.outcome = block_run_outcome(error);
        return Ok(report);
    }

    match validate_a_table(
        &bytes,
        usize::from(stored.prefix.a_records),
        stored.prefix.b_len,
    ) {
        Ok(summary) => {
            report.a_table = Some(summary);
            report.outcome = ProbeOutcome::Plausible;
        }
        Err(reason) => report.outcome = ProbeOutcome::Implausible(reason),
    }
    Ok(report)
}

fn step1_descriptor<S: CipherSource>(source: &S, index: u8) -> Option<CipherDescriptor> {
    let kind = source.static_kind(index)?;
    let (key_id, parameter) = source.static_descriptor(index)?;
    Some(CipherDescriptor {
        key_id,
        kind,
        parameter,
    })
}

fn block_run_outcome(error: super::transform::Error) -> ProbeOutcome {
    use super::transform::Error;
    match error {
        Error::Unaligned(_) | Error::OutOfBounds { .. } => {
            ProbeOutcome::ArchiveUnsupported("the step-1 A span is not block aligned")
        }
        _ => ProbeOutcome::BlockUnsupported("the cipher did not process the A span"),
    }
}

fn registry_outcome(error: RegistryError) -> ProbeOutcome {
    match error {
        RegistryError::ResourceLimit { what, limit } => ProbeOutcome::ResourceLimit { what, limit },
        RegistryError::Cancelled => ProbeOutcome::Cancelled,
        RegistryError::NotFound => ProbeOutcome::RegistryUnsupported("no key registry was found"),
        RegistryError::Ambiguous => {
            ProbeOutcome::RegistryUnsupported("more than one key registry was found")
        }
        RegistryError::NoCompatibleState => {
            ProbeOutcome::RegistryUnsupported("the registry has no compatible state")
        }
        RegistryError::StateMalformed(reason) => ProbeOutcome::RegistryUnsupported(reason),
        RegistryError::Image(_) => {
            ProbeOutcome::RegistryUnsupported("the executable could not be read")
        }
    }
}

fn state_outcome(error: RegistryError) -> ProbeOutcome {
    match error {
        RegistryError::ResourceLimit { what, limit } => ProbeOutcome::ResourceLimit { what, limit },
        RegistryError::Cancelled => ProbeOutcome::Cancelled,
        RegistryError::NoCompatibleState | RegistryError::NotFound => {
            ProbeOutcome::StateUnsupported("no compatible key state")
        }
        RegistryError::Ambiguous => {
            ProbeOutcome::StateUnsupported("more than one compatible key state")
        }
        RegistryError::StateMalformed(reason) => ProbeOutcome::StateUnsupported(reason),
        RegistryError::Image(_) => {
            ProbeOutcome::StateUnsupported("the key state could not be read")
        }
    }
}

fn descriptor_outcome(error: DescriptorError) -> ProbeOutcome {
    use DescriptorError as E;
    match error {
        E::ResourceLimit { what, limit } => ProbeOutcome::ResourceLimit { what, limit },
        E::Cancelled => ProbeOutcome::Cancelled,
        E::WriterNotFound => {
            ProbeOutcome::DescriptorUnsupported("the descriptor writer was not found")
        }
        E::WriterAmbiguous => {
            ProbeOutcome::DescriptorUnsupported("more than one descriptor writer was found")
        }
        E::DescriptorNotFound => {
            ProbeOutcome::DescriptorUnsupported("no descriptor for the archive selector")
        }
        E::DescriptorAmbiguous => {
            ProbeOutcome::DescriptorUnsupported("more than one descriptor for the archive selector")
        }
        E::AmbiguousMapping => {
            ProbeOutcome::DescriptorUnsupported("a descriptor path maps to several indices")
        }
        E::UnsupportedCipher => {
            ProbeOutcome::DescriptorUnsupported("the cipher type is not supported")
        }
        E::MalformedParameter => {
            ProbeOutcome::DescriptorUnsupported("the descriptor parameter is malformed")
        }
        E::MalformedObject => {
            ProbeOutcome::DescriptorUnsupported("the descriptor object is malformed")
        }
        E::UnsupportedLayout(reason) => ProbeOutcome::DescriptorUnsupported(reason),
        E::NoCompatibleState | E::StateAmbiguous | E::StateMalformed => {
            ProbeOutcome::DescriptorUnsupported("the descriptor's key state is not usable")
        }
        E::Image(_) => ProbeOutcome::DescriptorUnsupported("the executable could not be read"),
    }
}

fn fixed_tables_outcome(error: FixedTablesError) -> ProbeOutcome {
    use FixedTablesError as E;
    match error {
        E::ResourceLimit { what, limit } => ProbeOutcome::ResourceLimit { what, limit },
        E::Cancelled => ProbeOutcome::Cancelled,
        E::NotFound => ProbeOutcome::FixedTablesUnsupported("no fixed cipher tables were found"),
        E::Ambiguous => {
            ProbeOutcome::FixedTablesUnsupported("more than one fixed table block was found")
        }
        E::Malformed(reason) => ProbeOutcome::FixedTablesUnsupported(reason),
        E::Image(_) => ProbeOutcome::FixedTablesUnsupported("the executable could not be read"),
    }
}

fn source_outcome(error: SourceError) -> ProbeOutcome {
    match error {
        SourceError::Recognition(RecognitionError::Registry(error)) => state_outcome(error),
        SourceError::Recognition(RecognitionError::Descriptor(_)) => {
            ProbeOutcome::DescriptorUnsupported("the static descriptor is invalid")
        }
        SourceError::FixedTables(error) => fixed_tables_outcome(error),
        SourceError::Block(EncodedAesError::InvalidState(reason)) => {
            ProbeOutcome::BlockUnsupported(reason)
        }
    }
}

/// Checks a decrypted `A` span. Records are 8 bytes: a nonzero, unique `u16`
/// identifier, two unchecked bytes, then a `u32` offset that MUST lie inside
/// the `B` block. At least one record MUST use a known sub-block identifier.
/// The engine does not require padding bytes to be zero, and neither does
/// this check.
fn validate_a_table(
    bytes: &[u8],
    records: usize,
    b_len: u32,
) -> Result<ATableSummary, &'static str> {
    if records == 0 {
        return Err("the A table has no records");
    }
    let needed = records
        .checked_mul(8)
        .ok_or("the A record count overflows")?;
    let table = bytes
        .get(..needed)
        .ok_or("the decrypted A span is shorter than the A table")?;
    let mut ids = HashSet::with_capacity(records);
    let mut known = 0;
    for record in table.as_chunks::<8>().0 {
        let id = u16::from_le_bytes([record[0], record[1]]);
        if id == 0 {
            return Err("an A record has a zero identifier");
        }
        if !ids.insert(id) {
            return Err("two A records share an identifier");
        }
        let offset = u32::from_le_bytes([record[4], record[5], record[6], record[7]]);
        if offset >= b_len {
            return Err("an A record points outside the B block");
        }
        if matches!(id, 1 | 2 | 3 | 6 | 9) {
            known += 1;
        }
    }
    if known == 0 {
        return Err("no A record references a known sub-block");
    }
    Ok(ATableSummary {
        records,
        known_ids: known,
    })
}

#[cfg(test)]
mod tests {
    use super::validate_a_table;

    fn record(id: u16, offset: u32) -> [u8; 8] {
        let mut record = [0u8; 8];
        record[0..2].copy_from_slice(&id.to_le_bytes());
        record[4..8].copy_from_slice(&offset.to_le_bytes());
        record
    }

    fn table(records: &[[u8; 8]]) -> Vec<u8> {
        records.iter().flatten().copied().collect()
    }

    #[test]
    fn accepts_a_well_formed_table() {
        let bytes = table(&[record(1, 0), record(2, 0x20), record(9, 0x40)]);
        let summary = validate_a_table(&bytes, 3, 0x100).unwrap();
        assert_eq!(summary.records, 3);
        assert_eq!(summary.known_ids, 3);
    }

    #[test]
    fn ignores_the_unchecked_bytes_and_padding() {
        let mut bytes = table(&[record(2, 0)]);
        bytes[2] = 0xFF;
        bytes[3] = 0xFF;
        bytes.extend_from_slice(&[0xAA; 8]);
        assert!(validate_a_table(&bytes, 1, 0x10).is_ok());
    }

    #[test]
    fn rejects_an_empty_table() {
        assert_eq!(
            validate_a_table(&[], 0, 0x10),
            Err("the A table has no records")
        );
    }

    #[test]
    fn rejects_a_zero_identifier() {
        let bytes = table(&[record(0, 0)]);
        assert_eq!(
            validate_a_table(&bytes, 1, 0x10),
            Err("an A record has a zero identifier")
        );
    }

    #[test]
    fn rejects_a_duplicate_identifier() {
        let bytes = table(&[record(1, 0), record(1, 8)]);
        assert_eq!(
            validate_a_table(&bytes, 2, 0x10),
            Err("two A records share an identifier")
        );
    }

    #[test]
    fn rejects_an_offset_outside_b() {
        let bytes = table(&[record(1, 0x10)]);
        assert_eq!(
            validate_a_table(&bytes, 1, 0x10),
            Err("an A record points outside the B block")
        );
    }

    #[test]
    fn rejects_a_table_without_a_known_identifier() {
        let bytes = table(&[record(4, 0), record(5, 8)]);
        assert_eq!(
            validate_a_table(&bytes, 2, 0x10),
            Err("no A record references a known sub-block")
        );
    }

    #[test]
    fn rejects_a_truncated_span() {
        let bytes = table(&[record(1, 0)]);
        assert_eq!(
            validate_a_table(&bytes, 2, 0x10),
            Err("the decrypted A span is shorter than the A table")
        );
    }
}
