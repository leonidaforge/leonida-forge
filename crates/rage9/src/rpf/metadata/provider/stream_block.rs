//! The concrete encoded algorithm-`0x11` keystream block operation.
//!
//! The operation is the counter-mode generator of the payload transform. It
//! consumes one 16-byte counter block in place and writes the keystream block
//! that the stream layer XORs with the stored bytes.
//!
//! The structure follows the instruction-grounded research for build
//! e95020b2: sixteen affine stage tables, thirteen encoded rounds, and a
//! substitution-only final round through sixteen key-dependent tables with the
//! AES shift-rows byte permutation. The schedule is the state's 60 little-endian
//! words. The fixed tables are read from the caller's executable at run time and
//! are never copied into the repository.
//!
//! A block holds its state until it is dropped. The state is zeroized by
//! [`StateBytes`]; the transient round state and schedule words are zeroized
//! where they are owned copies.

use std::fmt;

use zeroize::Zeroize;

use super::fixed::FixedTables;
use crate::rpf::metadata::recognize::{StateBytes, validate_stream_state};
use crate::rpf::metadata::transform::{Block, BlockDecrypt};

/// Rounds after the stage pass.
const ROUNDS: usize = 13;
/// State offsets.
const SCHEDULE_OFFSET: usize = 4;
const FINAL_TABLES_OFFSET: usize = 0xF4;
const TABLE_LEN: usize = 256;

/// Output byte `p` takes input `(word, byte)` from the final round.
const FINAL_ORDER: [(usize, usize); 16] = [
    (0, 0),
    (1, 1),
    (2, 2),
    (3, 3),
    (1, 0),
    (2, 1),
    (3, 2),
    (0, 3),
    (2, 0),
    (3, 1),
    (0, 2),
    (1, 3),
    (3, 0),
    (0, 1),
    (1, 2),
    (2, 3),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodedStreamError {
    /// The state is not a valid encoded algorithm-`0x11` state.
    InvalidState(&'static str),
}

impl fmt::Display for EncodedStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodedStreamError::InvalidState(reason) => {
                write!(f, "invalid encoded stream key state: {reason}")
            }
        }
    }
}

impl std::error::Error for EncodedStreamError {}

/// The encoded algorithm-`0x11` keystream block operation for one key state.
pub struct EncodedStreamBlock {
    state: StateBytes,
    tables: FixedTables,
}

impl EncodedStreamBlock {
    /// Validates `state` and prepares the operation.
    pub fn new(state: StateBytes, tables: FixedTables) -> Result<Self, EncodedStreamError> {
        validate_stream_state(state.as_slice()).map_err(EncodedStreamError::InvalidState)?;
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

impl BlockDecrypt for EncodedStreamBlock {
    fn decrypt_block(&self, block: &mut Block) {
        let mut words = [0u32; 4];

        // Stage pass: each input byte is mapped through its affine table and
        // packed most-significant first, then the schedule word is XORed.
        for (word, slot) in words.iter_mut().enumerate() {
            let mut value = 0u32;
            for lane in 0..4 {
                let index = 4 * word + lane;
                value = (value << 8) | u32::from(self.tables.stage(index)[block[index] as usize]);
            }
            *slot = value ^ self.schedule_word(word);
        }

        let mut next = [0u32; 4];
        for round in 0..ROUNDS {
            let [a, b, c, d] = words;
            let base = 4 + 4 * round;
            next[0] = self.tables.round(5)[byte(b, 1) as usize]
                ^ self.tables.round(10)[byte(c, 2) as usize]
                ^ self.tables.round(0)[byte(a, 0) as usize]
                ^ self.tables.round(15)[byte(d, 3) as usize]
                ^ self.schedule_word(base);
            next[1] = self.tables.round(14)[byte(d, 2) as usize]
                ^ self.tables.round(9)[byte(c, 1) as usize]
                ^ self.tables.round(4)[byte(b, 0) as usize]
                ^ self.tables.round(3)[byte(a, 3) as usize]
                ^ self.schedule_word(base + 1);
            next[2] = self.tables.round(13)[byte(d, 1) as usize]
                ^ self.tables.round(2)[byte(a, 2) as usize]
                ^ self.tables.round(8)[byte(c, 0) as usize]
                ^ self.tables.round(7)[byte(b, 3) as usize]
                ^ self.schedule_word(base + 2);
            next[3] = self.tables.round(6)[byte(b, 2) as usize]
                ^ self.tables.round(1)[byte(a, 1) as usize]
                ^ self.tables.round(12)[byte(d, 0) as usize]
                ^ self.tables.round(11)[byte(c, 3) as usize]
                ^ self.schedule_word(base + 3);
            words = next;
        }

        let mut output = [0u8; 16];
        for (target, &(word, index)) in FINAL_ORDER.iter().enumerate() {
            output[target] = self.final_table(target)[byte(words[word], index) as usize];
        }
        words.zeroize();
        next.zeroize();
        *block = output;
    }
}

impl fmt::Debug for EncodedStreamBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedStreamBlock")
            .field("state_len", &self.state.len())
            .field("tables", &self.tables)
            .finish_non_exhaustive()
    }
}

fn byte(word: u32, index: usize) -> u8 {
    (word >> (8 * (3 - index))) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpf::metadata::provider::FixedTables;
    use zeroize::Zeroizing;

    fn state(magic: u32) -> StateBytes {
        let mut bytes = vec![0u8; crate::rpf::metadata::recognize::STATE_LEN];
        bytes[0..4].copy_from_slice(&magic.to_le_bytes());
        // A nonzero synthetic schedule, word i = i + 1.
        for word in 0..60 {
            bytes[4 + 4 * word..8 + 4 * word].copy_from_slice(&((word as u32) + 1).to_le_bytes());
        }
        for table in 0..16 {
            for value in 0..256 {
                bytes[0xF4 + 0x100 * table + value] = value as u8;
            }
        }
        StateBytes::new(Zeroizing::new(bytes))
    }

    fn tables() -> FixedTables {
        let mut stage = [[0u8; 256]; 16];
        for table in &mut stage {
            for (value, slot) in table.iter_mut().enumerate() {
                *slot = value as u8;
            }
        }
        let mut round = [[0u32; 256]; 16];
        for (index, table) in round.iter_mut().enumerate() {
            for (value, slot) in table.iter_mut().enumerate() {
                *slot = ((value as u32) * 0x0101_0101) ^ ((index as u32) * 0x1111_1111);
            }
        }
        FixedTables::from_parts(stage, round)
    }

    #[test]
    fn rejects_the_other_state_magic() {
        assert!(EncodedStreamBlock::new(state(0x4E3B_9B8E), tables()).is_err());
    }

    #[test]
    fn block_matches_the_transcribed_round_model() {
        let block = EncodedStreamBlock::new(state(0x2718_CE5D), tables()).unwrap();
        let mut input = [0u8; 16];
        for (index, byte) in input.iter_mut().enumerate() {
            *byte = index as u8;
        }
        // Synthetic schedule, identity stage and final tables, and the round
        // tables above. Generated by the independent reference transcription.
        block.decrypt_block(&mut input);
        assert_eq!(
            input,
            [
                0x28, 0x2d, 0x2e, 0x17, 0x2d, 0x2e, 0x2f, 0x1d, 0x2e, 0x2f, 0x28, 0x1b, 0x2f, 0x28,
                0x2d, 0x19
            ]
        );
    }
}
