//! A [`CipherSource`] backed by the executable's recognized key provider.
//!
//! The source joins the three recognized parts: the key registry, the static
//! descriptor of one archive selector and the fixed transformation tables. It
//! resolves the descriptor's encoded key state on demand, validates it and
//! builds the algorithm-`0x10` block operation. Nothing is cached, so a
//! rotation that changes the registry takes effect immediately.
//!
//! The source is inert. It does not read archives, authenticate anything or
//! expose key material. Only the A-table probe and, later, a signature verifier
//! drive it.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::pe::ExecutableView;

use super::block::{EncodedAesBlock, EncodedAesError};
use super::fixed::{FixedTables, FixedTablesError, recognize_candidates, recognize_fixed_tables};
use crate::rpf::metadata::probe::{ATableSummary, validate_a_table};
use crate::rpf::metadata::recognize::{
    Limits, RecognitionError, Recognized, STATIC_STEP1_MODE, StaticDescriptor,
};
use crate::rpf::metadata::transform::{
    Algorithm, Block, Cipher, CipherDescriptor, CipherSource, Error as CipherError,
};

#[derive(Debug)]
pub enum SourceError {
    Recognition(RecognitionError),
    FixedTables(FixedTablesError),
    Block(EncodedAesError),
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceError::Recognition(err) => err.fmt(f),
            SourceError::FixedTables(err) => err.fmt(f),
            SourceError::Block(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for SourceError {}

impl From<RecognitionError> for SourceError {
    fn from(err: RecognitionError) -> Self {
        SourceError::Recognition(err)
    }
}

impl From<FixedTablesError> for SourceError {
    fn from(err: FixedTablesError) -> Self {
        SourceError::FixedTables(err)
    }
}

impl From<EncodedAesError> for SourceError {
    fn from(err: EncodedAesError) -> Self {
        SourceError::Block(err)
    }
}

/// A recognized key provider that can build block operations for its keys.
/// Construction requires a unique structurally valid fixed-table block; an
/// image with several is rejected as ambiguous. The archive probe selects
/// among them by the decrypted A table.
pub struct RecognizedSource {
    recognized: Recognized,
    tables: FixedTables,
}

impl RecognizedSource {
    /// Recognizes the registry, the static descriptor of `archive_selector`,
    /// the compatible key state and the fixed tables.
    pub fn recognize(
        image: &ExecutableView,
        archive_selector: u8,
        cancel: &AtomicBool,
    ) -> Result<Self, SourceError> {
        let recognized = Recognized::recognize(image, archive_selector, cancel)?;
        let tables = recognize_fixed_tables(image, cancel)?;
        Self::from_parts(recognized, tables)
    }

    /// Joins already recognized parts after validating the descriptor's state.
    pub(crate) fn from_parts(
        recognized: Recognized,
        tables: FixedTables,
    ) -> Result<Self, SourceError> {
        let state = recognized.state().map_err(RecognitionError::Registry)?;
        EncodedAesBlock::new(state, tables.clone())?;
        Ok(Self { recognized, tables })
    }

    pub fn descriptor(&self) -> &StaticDescriptor {
        self.recognized.descriptor()
    }

    /// The algorithm identifier the engine's key selector carries.
    pub fn algorithm_id(&self) -> u8 {
        self.recognized.algorithm_id()
    }

    /// The provider the engine selects for this algorithm and mode.
    pub fn provider(&self) -> u8 {
        self.recognized.provider()
    }

    /// The step-1 cipher mode, which the engine fixes.
    pub fn mode(&self) -> u8 {
        self.recognized.mode()
    }
}

impl CipherSource for RecognizedSource {
    type Block = EncodedAesBlock;

    fn static_descriptor(&self, index: u8) -> Option<(u32, Block)> {
        let descriptor = self.recognized.descriptor();
        (index == descriptor.index()).then(|| (descriptor.key_id(), *descriptor.parameter()))
    }

    fn static_kind(&self, index: u8) -> Option<u16> {
        let descriptor = self.recognized.descriptor();
        (index == descriptor.index()).then(|| descriptor.kind())
    }

    fn cbc_block(&self, key_id: u32) -> Option<Self::Block> {
        self.cbc_block_for(self.recognized.descriptor().kind(), key_id)
    }

    fn cbc_block_for(&self, kind: u16, key_id: u32) -> Option<Self::Block> {
        let algorithm = match Algorithm::of(kind) {
            Ok(algorithm @ Algorithm::Cbc) => algorithm,
            _ => return None,
        };
        let state = self
            .recognized
            .registry()
            .state_for_key(key_id, algorithm.id(), STATIC_STEP1_MODE)
            .ok()?;
        EncodedAesBlock::new(state, self.tables.clone()).ok()
    }
}

impl fmt::Debug for RecognizedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key identifier, the parameter and the state stay out of
        // diagnostics.
        f.debug_struct("RecognizedSource")
            .field("descriptor", self.recognized.descriptor())
            .field("algorithm_id", &self.recognized.algorithm_id())
            .field("provider", &self.recognized.provider())
            .field("mode", &self.recognized.mode())
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}

/// A recognized source selected by the step-1 A table.
pub(crate) struct Selection {
    pub source: RecognizedSource,
    pub a_table: ATableSummary,
    pub candidates: usize,
    pub selected: usize,
}

#[derive(Debug)]
pub(crate) enum SelectionError {
    Recognition(RecognitionError),
    FixedTables(FixedTablesError),
    Block(EncodedAesError),
    Cipher(CipherError),
    NoPlausible,
    Ambiguous,
    Cancelled,
}

/// Tries every structurally valid fixed-table block with the recognized state
/// and selects the unique one that turns `a_span` into a plausible A table.
/// The A span MUST be the exact step-1 A ciphertext span.
pub(crate) fn select_source(
    a_span: &[u8],
    a_records: u16,
    b_len: u32,
    image: &ExecutableView,
    archive_selector: u8,
    cancel: &AtomicBool,
) -> Result<Selection, SelectionError> {
    let recognized = Recognized::recognize(image, archive_selector, cancel)
        .map_err(SelectionError::Recognition)?;
    let candidates = recognize_candidates(image, cancel, Limits::default())
        .map_err(SelectionError::FixedTables)?;
    let descriptor = *recognized.descriptor();
    let kind = descriptor.kind();
    let cipher_descriptor = CipherDescriptor {
        key_id: descriptor.key_id(),
        kind,
        parameter: *descriptor.parameter(),
    };
    let mut plausible = Vec::new();
    for (index, tables) in candidates.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err(SelectionError::Cancelled);
        }
        let source =
            RecognizedSource::from_parts(recognized.clone(), tables.clone()).map_err(|error| {
                match error {
                    SourceError::Recognition(error) => SelectionError::Recognition(error),
                    SourceError::FixedTables(error) => SelectionError::FixedTables(error),
                    SourceError::Block(error) => SelectionError::Block(error),
                }
            })?;
        let mut plain = a_span.to_vec();
        let mut cipher = Cipher::new(&cipher_descriptor, |key_id| {
            source.cbc_block_for(kind, key_id)
        })
        .map_err(SelectionError::Cipher)?;
        let span = 0..plain.len();
        cipher
            .run(&mut plain, std::slice::from_ref(&span))
            .map_err(SelectionError::Cipher)?;
        if let Ok(summary) = validate_a_table(&plain, usize::from(a_records), b_len) {
            plausible.push((index, source, summary));
        }
    }
    match plausible.len() {
        0 => Err(SelectionError::NoPlausible),
        1 => {
            let (selected, source, a_table) = plausible.pop().expect("one selection");
            Ok(Selection {
                source,
                a_table,
                candidates: candidates.len(),
                selected,
            })
        }
        _ => Err(SelectionError::Ambiguous),
    }
}
