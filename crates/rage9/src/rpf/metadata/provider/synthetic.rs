//! Synthetic encoded AES-256 instances and a standard AES-256 reference for
//! tests. No game table, key or executable-derived byte appears here.
//!
//! The encoded instance is built by inverting the researched model with a
//! chosen byte encoding. It is a genuine encoded AES-256 decryption only
//! because the constructed tables and state satisfy the model's equations; the
//! tests check the result against the standard algorithm and published
//! vectors.

use zeroize::Zeroizing;

use super::fixed::{FixedTables, ROUND_TABLE_COUNT, STAGE_TABLE_COUNT, STAGE_TABLE_LEN};
use crate::rpf::metadata::recognize::{STATE_LEN, STATE_MAGIC, StateBytes};

const FINAL_PERMUTATION: [usize; 16] = [15, 10, 5, 0, 3, 14, 9, 4, 7, 2, 13, 8, 11, 6, 1, 12];

/// FIPS-197 Appendix C.3 AES-256 key, plaintext and ciphertext.
pub(crate) const FIPS_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
pub(crate) const FIPS_PLAINTEXT: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
pub(crate) const FIPS_CIPHERTEXT: [u8; 16] = [
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
];
const INVMIX: [[u8; 4]; 4] = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e],
];
/// Sixteen distinct nonzero linear byte encodings, one per state position.
const ENCODING: [u8; 16] = [
    0x1b, 0x8e, 0x53, 0xc7, 0x2d, 0x74, 0xe1, 0x4a, 0x9f, 0x36, 0x62, 0xd5, 0x0b, 0xf8, 0x25, 0xa3,
];

fn gmul(a: u8, b: u8) -> u8 {
    let mut a = u16::from(a);
    let mut b = u16::from(b);
    let mut result = 0u16;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= 0x11b;
        }
    }
    result as u8
}

fn xtime(a: u8) -> u8 {
    gmul(a, 2)
}

fn boxes() -> ([u8; 256], [u8; 256]) {
    let mut inverse = [0u8; 256];
    for x in 1..256u16 {
        for y in 1..256u16 {
            if gmul(x as u8, y as u8) == 1 {
                inverse[x as usize] = y as u8;
                break;
            }
        }
    }
    let mut sbox = [0u8; 256];
    for (x, slot) in sbox.iter_mut().enumerate() {
        let i = inverse[x];
        *slot =
            i ^ i.rotate_left(1) ^ i.rotate_left(2) ^ i.rotate_left(3) ^ i.rotate_left(4) ^ 0x63;
    }
    let mut invsbox = [0u8; 256];
    for (x, &value) in sbox.iter().enumerate() {
        invsbox[value as usize] = x as u8;
    }
    (sbox, invsbox)
}

fn inverse_byte(value: u8) -> u8 {
    for candidate in 1..256u16 {
        if gmul(value, candidate as u8) == 1 {
            return candidate as u8;
        }
    }
    0
}

fn encoding(word: usize, lane: usize) -> u8 {
    ENCODING[4 * word + lane]
}

fn from_aes(block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for word in 0..4 {
        for lane in 0..4 {
            out[4 * word + lane] = block[4 * word + (3 - lane)];
        }
    }
    out
}

pub(crate) fn round_keys(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let (sbox, _) = boxes();
    let mut words = [[0u8; 4]; 60];
    for index in 0..8 {
        words[index].copy_from_slice(&key[4 * index..4 * index + 4]);
    }
    let mut rcon = 1u8;
    for index in 8..60 {
        let mut temp = words[index - 1];
        if index % 8 == 0 {
            temp = [
                sbox[temp[1] as usize] ^ rcon,
                sbox[temp[2] as usize],
                sbox[temp[3] as usize],
                sbox[temp[0] as usize],
            ];
            rcon = xtime(rcon);
        } else if index % 8 == 4 {
            temp = temp.map(|byte| sbox[byte as usize]);
        }
        for lane in 0..4 {
            words[index][lane] = words[index - 8][lane] ^ temp[lane];
        }
    }

    let mut rounds = [[0u8; 16]; 15];
    for (round, block) in rounds.iter_mut().enumerate() {
        for column in 0..4 {
            block[4 * column..4 * column + 4].copy_from_slice(&words[4 * round + column]);
        }
    }
    rounds
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let current = *state;
    for column in 0..4 {
        for row in 0..4 {
            state[4 * column + row] = current[4 * ((column + 4 - row) % 4) + row];
        }
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let current = *state;
    for column in 0..4 {
        for row in 0..4 {
            state[4 * column + row] = current[4 * ((column + row) % 4) + row];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    let current = *state;
    for column in 0..4 {
        let bytes = &current[4 * column..4 * column + 4];
        state[4 * column] = gmul(bytes[0], 2) ^ gmul(bytes[1], 3) ^ bytes[2] ^ bytes[3];
        state[4 * column + 1] = bytes[0] ^ gmul(bytes[1], 2) ^ gmul(bytes[2], 3) ^ bytes[3];
        state[4 * column + 2] = bytes[0] ^ bytes[1] ^ gmul(bytes[2], 2) ^ gmul(bytes[3], 3);
        state[4 * column + 3] = gmul(bytes[0], 3) ^ bytes[1] ^ bytes[2] ^ gmul(bytes[3], 2);
    }
}

pub(crate) fn inv_mix_columns(state: &mut [u8; 16]) {
    let current = *state;
    for column in 0..4 {
        let bytes = &current[4 * column..4 * column + 4];
        state[4 * column] =
            gmul(bytes[0], 14) ^ gmul(bytes[1], 11) ^ gmul(bytes[2], 13) ^ gmul(bytes[3], 9);
        state[4 * column + 1] =
            gmul(bytes[0], 9) ^ gmul(bytes[1], 14) ^ gmul(bytes[2], 11) ^ gmul(bytes[3], 13);
        state[4 * column + 2] =
            gmul(bytes[0], 13) ^ gmul(bytes[1], 9) ^ gmul(bytes[2], 14) ^ gmul(bytes[3], 11);
        state[4 * column + 3] =
            gmul(bytes[0], 11) ^ gmul(bytes[1], 13) ^ gmul(bytes[2], 9) ^ gmul(bytes[3], 14);
    }
}

/// Standard AES-256 decryption, the equivalent inverse cipher. It shares no
/// code with the encoded block operation.
pub(crate) fn reference_decrypt(key: &[u8; 32], block: &mut [u8; 16]) {
    let (_, invsbox) = boxes();
    let round_keys = round_keys(key);
    for (byte, key_byte) in block.iter_mut().zip(&round_keys[14]) {
        *byte ^= key_byte;
    }
    for round in (1..=13).rev() {
        inv_shift_rows(block);
        for byte in block.iter_mut() {
            *byte = invsbox[*byte as usize];
        }
        for (byte, key_byte) in block.iter_mut().zip(&round_keys[round]) {
            *byte ^= key_byte;
        }
        inv_mix_columns(block);
    }
    inv_shift_rows(block);
    for byte in block.iter_mut() {
        *byte = invsbox[*byte as usize];
    }
    for (byte, key_byte) in block.iter_mut().zip(&round_keys[0]) {
        *byte ^= key_byte;
    }
}

/// Standard AES-256 encryption. Tests use it to build archive ciphertext that
/// the encoded block operation must decrypt. It shares no code with the
/// encoded instance.
pub(crate) fn reference_encrypt(key: &[u8; 32], block: &mut [u8; 16]) {
    let (sbox, _) = boxes();
    let round_keys = round_keys(key);
    for (byte, key_byte) in block.iter_mut().zip(&round_keys[0]) {
        *byte ^= key_byte;
    }
    for round_key in round_keys.iter().take(14).skip(1) {
        for byte in block.iter_mut() {
            *byte = sbox[*byte as usize];
        }
        shift_rows(block);
        mix_columns(block);
        for (byte, key_byte) in block.iter_mut().zip(round_key) {
            *byte ^= key_byte;
        }
    }
    for byte in block.iter_mut() {
        *byte = sbox[*byte as usize];
    }
    shift_rows(block);
    for (byte, key_byte) in block.iter_mut().zip(&round_keys[14]) {
        *byte ^= key_byte;
    }
}

/// A self-consistent synthetic encoded AES-256 instance.
pub(crate) struct Synthetic {
    stage: [[u8; STAGE_TABLE_LEN]; STAGE_TABLE_COUNT],
    round: [[u32; 256]; ROUND_TABLE_COUNT],
    state: Vec<u8>,
}

impl Synthetic {
    pub(crate) fn fixed_tables(&self) -> FixedTables {
        FixedTables::from_parts(self.stage, self.round)
    }

    pub(crate) fn fixed_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STAGE_TABLE_COUNT * STAGE_TABLE_LEN + 16 * 1024);
        for table in &self.stage {
            bytes.extend_from_slice(table);
        }
        for table in &self.round {
            for value in table {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    pub(crate) fn state_bytes(&self) -> StateBytes {
        StateBytes::new(Zeroizing::new(self.state.clone()))
    }

    pub(crate) fn raw_state(&self) -> &[u8] {
        &self.state
    }
}

/// Builds the encoded fixed tables and key state for `key` with the chosen
/// byte encoding.
pub(crate) fn instance(key: &[u8; 32]) -> Synthetic {
    let (_, invsbox) = boxes();

    let mut stage = [[0u8; STAGE_TABLE_LEN]; STAGE_TABLE_COUNT];
    for word in 0..4 {
        for lane in 0..4 {
            let index = 4 * word + (3 - lane);
            let encoding = encoding(word, lane);
            for (x, slot) in stage[index].iter_mut().enumerate() {
                *slot = gmul(encoding, x as u8);
            }
        }
    }

    let mut round = [[0u32; 256]; ROUND_TABLE_COUNT];
    for (index, table) in round.iter_mut().enumerate() {
        let word = index / 4;
        let delta = index % 4;
        let output_word = (word + delta) % 4;
        let source_lane = (3 - delta) % 4;
        let decoding = inverse_byte(encoding(word, source_lane));
        for (x, slot) in table.iter_mut().enumerate() {
            let logical = invsbox[gmul(decoding, x as u8) as usize];
            let mut value = 0u32;
            for lane in 0..4 {
                let coefficient = INVMIX[3 - lane][delta];
                let encoded = gmul(encoding(output_word, lane), gmul(coefficient, logical));
                value |= u32::from(encoded) << (8 * lane);
            }
            *slot = value;
        }
    }

    let round_keys = round_keys(key);
    let mut schedule = [0u32; 60];

    let whitening = from_aes(&round_keys[14]);
    for word in 0..4 {
        for lane in 0..4 {
            let byte = gmul(encoding(word, lane), whitening[4 * word + lane]);
            schedule[word] |= u32::from(byte) << (8 * lane);
        }
    }

    for round_index in 0..13 {
        let mut mixed = round_keys[13 - round_index];
        inv_mix_columns(&mut mixed);
        let mixed = from_aes(&mixed);
        for word in 0..4 {
            for lane in 0..4 {
                let byte = gmul(encoding(word, lane), mixed[4 * word + lane]);
                schedule[4 + 4 * round_index + word] |= u32::from(byte) << (8 * lane);
            }
        }
    }

    let mut final_tables = [[0u8; 256]; 16];
    for (source, &target) in FINAL_PERMUTATION.iter().enumerate() {
        let word = source / 4;
        let lane = source % 4;
        let decoding = inverse_byte(encoding(word, lane));
        for (x, slot) in final_tables[target].iter_mut().enumerate() {
            *slot = invsbox[gmul(decoding, x as u8) as usize] ^ round_keys[0][target];
        }
    }

    let mut state = Vec::with_capacity(STATE_LEN);
    state.extend_from_slice(&STATE_MAGIC.to_le_bytes());
    for word in schedule {
        state.extend_from_slice(&word.to_le_bytes());
    }
    for table in &final_tables {
        state.extend_from_slice(table);
    }
    assert_eq!(state.len(), STATE_LEN);

    Synthetic {
        stage,
        round,
        state,
    }
}
