//! The concrete encoded algorithm-`0x10` block operation.
//!
//! The operation is table-driven and consumes one 16-byte block in place. It
//! uses the validated fixed tables and the recognized key state: the 240-byte
//! schedule and the sixteen key-dependent final-round tables. It does not use
//! a standard AES implementation and does not interpret the schedule as a raw
//! AES key schedule.
//!
//! The round structure, byte and word order follow the instruction-grounded
//! research for build e95020b2. Thirteen table rounds run after the stage-0
//! affine tables and the whitening words, then a substitution-only final round
//! writes the output through a fixed byte permutation.
//!
//! A block holds its state until it is dropped. The state is zeroized by
//! [`StateBytes`]; the transient round state and schedule words are zeroized
//! where they are owned copies. This does not promise that OS, allocator or
//! earlier stack frames left no copies. Nothing here logs, serializes or
//! transmits the state.

use std::fmt;

use zeroize::Zeroize;

use super::fixed::FixedTables;
use crate::rpf::metadata::recognize::{StateBytes, validate_encoded_state};
use crate::rpf::metadata::transform::{Block, BlockDecrypt};

/// Round count after the stage-0 pass.
const ROUNDS: usize = 13;
/// Output byte `p` of the final round takes input byte `m` for `p = P[m]`.
const FINAL_PERMUTATION: [usize; 16] = [15, 10, 5, 0, 3, 14, 9, 4, 7, 2, 13, 8, 11, 6, 1, 12];
/// State offsets.
const SCHEDULE_OFFSET: usize = 4;
const FINAL_TABLES_OFFSET: usize = 0xF4;
const TABLE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodedAesError {
    /// The state is not a valid encoded algorithm-`0x10` state.
    InvalidState(&'static str),
}

impl fmt::Display for EncodedAesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodedAesError::InvalidState(reason) => {
                write!(f, "invalid encoded key state: {reason}")
            }
        }
    }
}

impl std::error::Error for EncodedAesError {}

/// The encoded algorithm-`0x10` block operation for one key state.
///
/// It is not a standard AES cipher: the schedule is the executable's encoded
/// schedule and the final tables are key-dependent. The object holds one
/// validated state, zeroized when dropped, plus shared non-secret tables.
pub struct EncodedAesBlock {
    state: StateBytes,
    tables: FixedTables,
}

impl EncodedAesBlock {
    /// Validates `state` and prepares the operation. The state must have the
    /// exact length, algorithm-`0x10` magic, nonzero schedule and sixteen
    /// permutation final-round tables.
    pub fn new(state: StateBytes, tables: FixedTables) -> Result<Self, EncodedAesError> {
        validate_encoded_state(state.as_slice()).map_err(EncodedAesError::InvalidState)?;
        Ok(Self { state, tables })
    }

    fn schedule_word(&self, index: usize) -> u32 {
        let start = SCHEDULE_OFFSET + 4 * index;
        let bytes: [u8; 4] = self.state.as_slice()[start..start + 4]
            .try_into()
            .expect("validated state length");
        u32::from_le_bytes(bytes)
    }

    fn final_table(&self, index: usize) -> &[u8] {
        let start = FINAL_TABLES_OFFSET + TABLE_LEN * index;
        &self.state.as_slice()[start..start + TABLE_LEN]
    }
}

impl BlockDecrypt for EncodedAesBlock {
    fn decrypt_block(&self, block: &mut Block) {
        let mut state = [0u8; 16];

        // Stage 0: affine table per byte, packed most-significant first, with
        // the four whitening words XORed little-endian.
        for word in 0..4 {
            let mut key = self.schedule_word(word);
            for lane in 0..4 {
                let index = 4 * word + (3 - lane);
                state[4 * word + lane] =
                    self.tables.stage(index)[block[index] as usize] ^ (key >> (8 * lane)) as u8;
            }
            key.zeroize();
        }

        // Thirteen encoded rounds. The table for output word `i` from input
        // word `j` is `4*j + ((i-j) mod 4)`, applied to lane
        // `(j-i-1) mod 4`.
        let mut next = [0u8; 16];
        for round in 0..ROUNDS {
            for word in 0..4 {
                let mut accumulator = self.schedule_word(4 + 4 * round + word);
                for source in 0..4 {
                    let lane = (source + 3 - word) % 4;
                    let table = 4 * source + (word + 4 - source) % 4;
                    accumulator ^= self.tables.round(table)[state[4 * source + lane] as usize];
                }
                for lane in 0..4 {
                    next[4 * word + lane] = (accumulator >> (8 * lane)) as u8;
                }
                accumulator.zeroize();
            }
            state = next;
        }

        // Final round: substitution only, through the key-dependent tables,
        // with the fixed output byte permutation.
        let mut output = [0u8; 16];
        for source in 0..16 {
            let target = FINAL_PERMUTATION[source];
            output[target] = self.final_table(target)[state[source] as usize];
        }
        state.zeroize();
        next.zeroize();
        *block = output;
    }
}

impl fmt::Debug for EncodedAesBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print no state bytes, schedule or tables.
        f.debug_struct("EncodedAesBlock")
            .field("state_len", &self.state.len())
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}
