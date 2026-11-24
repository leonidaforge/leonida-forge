//! The encoded algorithm-`0x10` block operation and its fixed tables.
//!
//! This module completes the fixed-transform side of the key provider: it
//! recognizes and validates the executable's stage-0 affine tables and encoded
//! round tables, and decrypts one 16-byte block with a recognized key state.
//!
//! It deliberately stops before archive processing. [`RecognizedSource`]
//! joins these parts for the bounded A-table probe, but no signature is
//! verified and no normal archive path uses it. A successfully initialized
//! block does not mean that any RPF9 archive has been decrypted or
//! authenticated.
//!
//! The table bytes are game-derived. They are read from the caller's
//! executable and are not reproduced in the repository. Tests build their own
//! synthetic tables and states; no real key material is used.

mod block;
mod fixed;
mod source;
#[cfg(test)]
pub(crate) mod synthetic;
#[cfg(test)]
mod tests;

pub use block::{EncodedAesBlock, EncodedAesError};
pub(crate) use fixed::recognize_candidates as recognize_fixed_table_candidates;
#[cfg(test)]
pub(crate) use fixed::recognize_with as recognize_fixed_tables_with;
pub use fixed::{
    FixedTables, FixedTablesError, ROUND_TABLE_LEN, STAGE_TABLE_LEN, recognize_fixed_tables,
};
pub use source::{RecognizedSource, SourceError};
