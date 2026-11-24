//! Block-operation tests over synthetic keys, states and tables.
//!
//! The encoded instance is generated from a standard AES-256 key by inverting
//! the researched model. The expected plaintexts come from published AES
//! vectors and from a separate standard AES-256 decryption, not from the
//! encoded implementation.

use zeroize::Zeroizing;

use super::synthetic::{self, reference_decrypt};
use super::*;
use crate::rpf::metadata::recognize::StateBytes;
use crate::rpf::metadata::transform::{BlockDecrypt, Cbc};

const NIST_KEY: [u8; 32] = [
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
];
const NIST_IV: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const NIST_CIPHERTEXT: [[u8; 16]; 4] = [
    [
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb,
        0xd6,
    ],
    [
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c,
        0x7d,
    ],
    [
        0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14,
        0x61,
    ],
    [
        0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d,
        0x1b,
    ],
];
const NIST_PLAINTEXT: [[u8; 16]; 4] = [
    [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ],
    [
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e,
        0x51,
    ],
    [
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52,
        0xef,
    ],
    [
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37,
        0x10,
    ],
];

fn block_for(key: &[u8; 32]) -> EncodedAesBlock {
    let synthetic = synthetic::instance(key);
    EncodedAesBlock::new(synthetic.state_bytes(), synthetic.fixed_tables()).unwrap()
}

fn tables() -> FixedTables {
    synthetic::instance(&synthetic::FIPS_KEY).fixed_tables()
}

fn state_from(mut mutate: impl FnMut(&mut Vec<u8>)) -> StateBytes {
    let synthetic = synthetic::instance(&synthetic::FIPS_KEY);
    let mut raw = synthetic.raw_state().to_vec();
    mutate(&mut raw);
    StateBytes::new(Zeroizing::new(raw))
}

#[test]
fn reference_passes_the_published_vectors() {
    let mut block = synthetic::FIPS_CIPHERTEXT;
    reference_decrypt(&synthetic::FIPS_KEY, &mut block);
    assert_eq!(block, synthetic::FIPS_PLAINTEXT);

    let mut previous = NIST_IV;
    for (index, ciphertext) in NIST_CIPHERTEXT.iter().enumerate() {
        let mut plaintext = *ciphertext;
        reference_decrypt(&NIST_KEY, &mut plaintext);
        for (byte, chain) in plaintext.iter_mut().zip(&previous) {
            *byte ^= chain;
        }
        assert_eq!(plaintext, NIST_PLAINTEXT[index]);
        previous = *ciphertext;
    }
}

#[test]
fn decrypts_the_fips_197_aes_256_vector() {
    let block = block_for(&synthetic::FIPS_KEY);
    let mut value = synthetic::FIPS_CIPHERTEXT;
    block.decrypt_block(&mut value);
    assert_eq!(value, synthetic::FIPS_PLAINTEXT);
}

#[test]
fn decrypts_the_nist_cbc_vector_through_cbc() {
    let block = block_for(&NIST_KEY);
    let mut data: Vec<u8> = NIST_CIPHERTEXT.concat();
    let mut cbc = Cbc::new(block, NIST_IV);
    cbc.update(&mut data).unwrap();
    assert_eq!(data, NIST_PLAINTEXT.concat());
}

#[test]
fn matches_standard_aes_on_deterministic_blocks() {
    for key in [synthetic::FIPS_KEY, NIST_KEY, [0x5a; 32]] {
        let block = block_for(&key);
        for index in 0..24usize {
            let mut input = [0u8; 16];
            for (offset, byte) in input.iter_mut().enumerate() {
                *byte = (index * 37 + offset * 13 + 5) as u8;
            }
            let mut expected = input;
            reference_decrypt(&key, &mut expected);
            let mut actual = input;
            block.decrypt_block(&mut actual);
            assert_eq!(actual, expected, "block {index}");
        }
    }
}

#[test]
fn rejects_a_state_with_the_wrong_length() {
    let error = EncodedAesBlock::new(state_from(|raw| raw.truncate(0x1000)), tables()).unwrap_err();
    assert_eq!(
        error,
        EncodedAesError::InvalidState("unexpected state length")
    );
}

#[test]
fn rejects_a_state_with_the_wrong_magic() {
    let error = EncodedAesBlock::new(state_from(|raw| raw[0] ^= 0xFF), tables()).unwrap_err();
    assert_eq!(
        error,
        EncodedAesError::InvalidState("unexpected state magic")
    );
}

#[test]
fn rejects_a_zero_schedule() {
    let error =
        EncodedAesBlock::new(state_from(|raw| raw[4..4 + 240].fill(0)), tables()).unwrap_err();
    assert_eq!(error, EncodedAesError::InvalidState("the schedule is zero"));
}

#[test]
fn rejects_a_non_permutation_final_table() {
    let error =
        EncodedAesBlock::new(state_from(|raw| raw[0xF4 + 1] = raw[0xF4]), tables()).unwrap_err();
    assert_eq!(
        error,
        EncodedAesError::InvalidState("a final-round table is not a permutation")
    );
}

#[test]
fn debug_does_not_print_state() {
    let synthetic = synthetic::instance(&synthetic::FIPS_KEY);
    let block = EncodedAesBlock::new(synthetic.state_bytes(), synthetic.fixed_tables()).unwrap();
    let debug = format!("{block:?}");
    assert!(debug.contains("state_len: 4340"));
    assert!(!debug.contains("schedule"));
    // Only the length and table counts are printed.
    assert!(debug.len() < 160);
}

#[test]
fn fixed_tables_debug_does_not_print_bytes() {
    let debug = format!("{:?}", tables());
    assert!(debug.contains("stage_tables"));
    assert!(debug.len() < 120);
}
