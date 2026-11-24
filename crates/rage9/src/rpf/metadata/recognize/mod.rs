//! Recognition of the RPF9 cryptographic state registry and the static cipher
//! descriptor in a locally supplied executable.
//!
//! The executable path is always a caller argument. Recognition is structural:
//! it scans the PE image for a record array whose entries resolve to valid
//! encoded key states, and it finds the static descriptor by decoding the
//! function that builds it. No address, selector, key identifier or initial
//! vector is fixed.
//!
//! Recognition has been verified for one executable build only. A different
//! build may change the registry layout, the descriptor writer or the builder
//! control flow; each of those fails closed with a diagnostic rather than
//! falling back to a guess.
//!
//! Nothing here decrypts archive metadata. A recognized registry and a
//! recognized descriptor mean that a compatible state exists, not that any
//! archive was decoded or authenticated.
//!
//! # Privacy
//!
//! State bytes are read on demand and never stored in [`Registry`]. A call
//! that needs the bytes returns a [`StateBytes`], which is zeroized on drop.
//! Diagnostics contain counts and static reasons only: no state bytes, no
//! selector, no pointer or initial vector. Zeroization covers the owned copy;
//! it cannot erase bytes that the operating system or allocator copied
//! elsewhere.
//!
//! [`StateBytes`]: crate::rpf::metadata::recognize::StateBytes

use std::fmt;
use std::sync::atomic::AtomicBool;

use lforge_binary::pe::{ExecutableView, Identity};
use zeroize::Zeroizing;

use super::transform::Algorithm;

mod descriptor;
mod registry;
#[cfg(test)]
mod tests;

pub(crate) use descriptor::recognize_descriptor;
pub use descriptor::{DescriptorError, recognize_static_descriptor};
pub use registry::{Registry, RegistryError, recognize_registry};

/// Length of an encoded algorithm-0x10 key state.
pub const STATE_LEN: usize = 0x10F4;
/// Magic of an encoded algorithm-0x10 key state.
pub const STATE_MAGIC: u32 = 0x4E3B_9B8E;
/// Length of a registry entry that is not an encoded key state.
pub const DEFAULT_RECORD_LEN: u64 = 0x20;
/// The algorithm of encoded AES-256 decryption.
pub const ALGORITHM_CBC: u8 = 0x10;
/// The step-1 cipher mode of the static descriptor, fixed by the engine's
/// descriptor initializer. The archive selector chooses the descriptor index,
/// not the mode, and the selector's parity does not imply it.
pub const STATIC_STEP1_MODE: u8 = 1;

/// The provider a key selector carries for `algorithm_id` in `mode`, or 0 for
/// an algorithm the engine does not dispatch this way.
pub fn provider_for(algorithm_id: u8, mode: u8) -> u8 {
    if (0x10..=0x15).contains(&algorithm_id) {
        if mode == 0 { 3 } else { 2 }
    } else {
        0
    }
}

/// The algorithm and provider selector of `key_id`.
pub(crate) fn selector_for(key_id: u32, algorithm_id: u8, mode: u8) -> u64 {
    let provider = u64::from(provider_for(algorithm_id, mode));
    (u64::from(key_id) << 32) | (provider << 24)
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// Whether the 60-word schedule has at least one nonzero word.
pub(crate) fn schedule_nonzero(bytes: &[u8]) -> bool {
    bytes.get(4..4 + 60 * 4).is_some_and(|schedule| {
        schedule
            .as_chunks::<4>()
            .0
            .iter()
            .any(|word| u32::from_le_bytes(*word) != 0)
    })
}

/// Whether all sixteen final-round tables are permutations of `0..=255`.
pub(crate) fn final_tables_ok(bytes: &[u8]) -> bool {
    (0..16).all(|index| {
        let start = 0xF4 + 0x100 * index;
        bytes.get(start..start + 0x100).is_some_and(is_permutation)
    })
}

pub(crate) fn is_permutation(table: &[u8]) -> bool {
    if table.len() != 256 {
        return false;
    }
    let mut seen = [false; 256];
    for &byte in table {
        if std::mem::replace(&mut seen[byte as usize], true) {
            return false;
        }
    }
    true
}

/// The structure an encoded algorithm-`0x10` key state must have: exact
/// length, magic, nonzero schedule and sixteen permutation final tables.
pub(crate) fn validate_encoded_state(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() != STATE_LEN {
        return Err("unexpected state length");
    }
    if read_u32(bytes, 0) != Some(STATE_MAGIC) {
        return Err("unexpected state magic");
    }
    if !schedule_nonzero(bytes) {
        return Err("the schedule is zero");
    }
    if !final_tables_ok(bytes) {
        return Err("a final-round table is not a permutation");
    }
    Ok(())
}

/// An owned copy of an encoded key state. It is zeroized when dropped.
///
/// The executable reader copies the bytes. Zeroization clears this owned
/// buffer; it does not promise that the operating system, the file cache or a
/// previous allocator did not copy the bytes elsewhere. Never write the state
/// anywhere.
pub struct StateBytes(Zeroizing<Vec<u8>>);

impl StateBytes {
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for StateBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the bytes, magic, schedule or tables.
        write!(f, "StateBytes({} bytes)", self.0.len())
    }
}

/// Resource limits of the registry scan and the descriptor analysis. The
/// defaults are the researched limits; tests lower them instead of building
/// multi-hundred-megabyte fixtures.
///
/// The function limits are implementation bounds, not researched recognition
/// rules: they keep the decode of one exception-table range bounded.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// Total raw bytes of the sections a registry scan reads.
    pub scan_bytes: u64,
    /// Eight-byte steps a registry scan takes.
    pub scan_offsets: u64,
    /// Records in one contiguous run.
    pub records: usize,
    /// Algorithm-0x10 states in one candidate run.
    pub algorithm_states: usize,
    /// Maximal record runs in the whole image.
    pub candidates: usize,
    /// Records a run needs to be a strong registry candidate.
    pub min_records: usize,
    /// Bytes of one decoded function.
    pub function_bytes: usize,
    /// Instructions of one decoded function.
    pub function_instructions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            scan_bytes: 256 * 1024 * 1024,
            scan_offsets: 33_554_432,
            records: 4096,
            algorithm_states: 64,
            candidates: 10_000,
            min_records: 5,
            function_bytes: 1024 * 1024,
            function_instructions: 65_536,
        }
    }
}

/// A recognized static cipher descriptor: the executable's step-1 key
/// identifier, cipher type and initial vector for one archive selector.
///
/// The fields are sensitive. [`Debug`] prints only the descriptor index and
/// the cipher type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StaticDescriptor {
    index: u8,
    key_id: u32,
    kind: u16,
    parameter: [u8; 16],
}

impl StaticDescriptor {
    pub(crate) fn new(index: u8, key_id: u32, kind: u16, parameter: [u8; 16]) -> Self {
        Self {
            index,
            key_id,
            kind,
            parameter,
        }
    }

    /// The descriptor index, `archive_selector >> 1`.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The key identifier the descriptor selects in the registry.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The cipher type, which maps to algorithm [`ALGORITHM_CBC`].
    pub fn kind(&self) -> u16 {
        self.kind
    }

    /// The 16-byte step-1 initial vector.
    pub fn parameter(&self) -> &[u8; 16] {
        &self.parameter
    }

    /// The algorithm the cipher type selects.
    pub fn algorithm(&self) -> Result<Algorithm, super::transform::Error> {
        Algorithm::of(self.kind)
    }
}

impl fmt::Debug for StaticDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key identifier and the parameter stay out of diagnostics.
        f.debug_struct("StaticDescriptor")
            .field("index", &self.index)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Which recognition stage failed.
#[derive(Debug)]
pub enum RecognitionError {
    Registry(RegistryError),
    Descriptor(DescriptorError),
}

impl fmt::Display for RecognitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecognitionError::Registry(err) => write!(f, "key registry: {err}"),
            RecognitionError::Descriptor(err) => write!(f, "static cipher descriptor: {err}"),
        }
    }
}

impl std::error::Error for RecognitionError {}

impl From<RegistryError> for RecognitionError {
    fn from(err: RegistryError) -> Self {
        RecognitionError::Registry(err)
    }
}

impl From<DescriptorError> for RecognitionError {
    fn from(err: DescriptorError) -> Self {
        RecognitionError::Descriptor(err)
    }
}

/// A recognized registry together with the static descriptor of one archive
/// selector and a verified compatible state.
///
/// [`RecognizedSource`] pairs this with the fixed tables and builds the
/// encoded block operation. This type reports recognition only; no archive
/// metadata was decrypted or authenticated.
///
/// [`RecognizedSource`]: crate::rpf::metadata::provider::RecognizedSource
pub struct Recognized {
    registry: Registry,
    descriptor: StaticDescriptor,
    /// The algorithm identifier of the descriptor's cipher type, which is not
    /// the raw cipher type when several types select one algorithm.
    algorithm: u8,
}

impl Recognized {
    /// Recognizes the registry, then the static descriptor `archive_selector`
    /// selects, and verifies that exactly one compatible state exists.
    pub fn recognize(
        image: &ExecutableView,
        archive_selector: u8,
        cancel: &AtomicBool,
    ) -> Result<Self, RecognitionError> {
        let registry = recognize_registry(image, cancel)?;
        let descriptor = recognize_static_descriptor(image, &registry, archive_selector, cancel)?;
        Ok(Self::from_parts(registry, descriptor)?)
    }

    /// Pairs an already recognized registry with an already extracted
    /// descriptor. The caller MUST have verified the compatible state.
    pub(crate) fn from_parts(
        registry: Registry,
        descriptor: StaticDescriptor,
    ) -> Result<Self, DescriptorError> {
        let algorithm = descriptor
            .algorithm()
            .map_err(|_| DescriptorError::UnsupportedCipher)?
            .id();
        Ok(Self {
            registry,
            descriptor,
            algorithm,
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn descriptor(&self) -> &StaticDescriptor {
        &self.descriptor
    }

    /// The algorithm identifier the engine's key selector carries.
    pub fn algorithm_id(&self) -> u8 {
        self.algorithm
    }

    /// The provider the engine selects for this algorithm and mode.
    pub fn provider(&self) -> u8 {
        provider_for(self.algorithm, STATIC_STEP1_MODE)
    }

    /// The step-1 cipher mode, which the engine fixes at
    /// [`STATIC_STEP1_MODE`].
    pub fn mode(&self) -> u8 {
        STATIC_STEP1_MODE
    }

    /// Re-reads and revalidates the compatible encoded key state. Nothing is
    /// cached from recognition.
    pub fn state(&self) -> Result<StateBytes, RegistryError> {
        self.registry
            .state_for_key(self.descriptor.key_id, self.algorithm, STATIC_STEP1_MODE)
    }

    /// The current SHA-256 identity of the executable. Use it to detect that
    /// the file changed after recognition.
    pub fn identity(&self, cancel: &AtomicBool) -> Result<Identity, lforge_binary::Error> {
        self.registry.identity(cancel)
    }
}

impl fmt::Debug for Recognized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recognized")
            .field("registry", &self.registry)
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}
