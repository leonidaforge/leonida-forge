//! Tests with a synthetic block operation. It is not the engine's.

use std::cell::Cell;

use super::*;

/// XORs a key, then rotates byte positions, so block order and IV mistakes
/// show up in the output.
#[derive(Debug, Clone)]
pub(crate) struct Toy {
    pub(crate) key: Block,
}

impl Toy {
    pub(crate) fn encrypt_block(&self, block: &mut Block) {
        block.rotate_right(3);
        for (byte, key) in block.iter_mut().zip(&self.key) {
            *byte ^= key;
        }
    }

    /// CBC encryption, the inverse of [`Cbc::update`] from `iv`.
    pub(crate) fn encrypt(&self, iv: Block, data: &mut [u8]) {
        let mut previous = iv;
        for block in data.as_chunks_mut::<BLOCK_LEN>().0 {
            for (byte, iv) in block.iter_mut().zip(&previous) {
                *byte ^= iv;
            }
            self.encrypt_block(block);
            previous = *block;
        }
    }
}

impl BlockDecrypt for Toy {
    fn decrypt_block(&self, block: &mut Block) {
        for (byte, key) in block.iter_mut().zip(&self.key) {
            *byte ^= key;
        }
        block.rotate_left(3);
    }
}

const KEY: Block = *b"synthetic key 01";
const IV: Block = [0xA5; BLOCK_LEN];

fn toy() -> Toy {
    Toy { key: KEY }
}

fn plain(len: usize) -> Vec<u8> {
    (0..len).map(|n| (n * 7 + 1) as u8).collect()
}

fn descriptor(kind: u16) -> CipherDescriptor {
    CipherDescriptor {
        key_id: 0x1234,
        kind,
        parameter: IV,
    }
}

fn cipher(kind: u16) -> Result<Cipher<Toy>, Error> {
    Cipher::new(&descriptor(kind), |key_id| (key_id == 0x1234).then(toy))
}

#[test]
fn parses_cipher_descriptors() {
    let mut bytes = vec![0x78, 0x56, 0x34, 0x12, 0x10, 0x00];
    bytes.extend(0..16u8);
    let descriptor = CipherDescriptor::parse(&bytes).unwrap();
    assert_eq!(descriptor.key_id, 0x1234_5678);
    assert_eq!(descriptor.kind, 16);
    assert_eq!(descriptor.parameter, core::array::from_fn(|n| n as u8));
    assert_eq!(
        CipherDescriptor::parse(&bytes[..CipherDescriptor::LEN - 1]),
        None
    );
}

#[test]
fn maps_cipher_types_to_algorithms() {
    let expected = |kind: u16| match kind {
        0 | 9 => Ok(Algorithm::Identity),
        1 => Ok(Algorithm::Untraced(1)),
        2 => Ok(Algorithm::Untraced(2)),
        3..=5 | 10..=12 | 16 => Ok(Algorithm::Cbc),
        6..=8 | 18 => Ok(Algorithm::Untraced(0x12)),
        13..=15 => Err(Error::InvalidType(kind)),
        17 => Ok(Algorithm::Untraced(0x11)),
        _ => Ok(Algorithm::Identity),
    };
    for kind in (0..=20).chain([0xFF, u16::MAX]) {
        assert_eq!(Algorithm::of(kind), expected(kind), "type {kind}");
    }
    assert_eq!([0, 1, 2, 3, 4, 5].map(static_kind), [0, 3, 0, 0, 16, 0]);
}

#[test]
fn cipher_source_defaults_delegate() {
    // A source that implements only the required methods gets the additive
    // behavior from the trait defaults.
    struct Basic;
    impl CipherSource for Basic {
        type Block = Toy;
        fn static_descriptor(&self, _: u8) -> Option<(u32, Block)> {
            Some((0x1234, IV))
        }
        fn cbc_block(&self, key_id: u32) -> Option<Toy> {
            (key_id == 0x1234).then(toy)
        }
    }
    let source = Basic;
    // static_kind defaults to the current-build free function.
    assert_eq!(source.static_kind(4), Some(static_kind(4)));
    assert_eq!(source.static_kind(1), Some(3));
    // cbc_block_for defaults to cbc_block and ignores the kind.
    assert!(source.cbc_block_for(16, 0x1234).is_some());
    assert!(source.cbc_block_for(3, 0x1234).is_some());
    assert!(source.cbc_block_for(16, 0x4321).is_none());
}

#[test]
fn per_span_reset_types() {
    for kind in 0..=20 {
        assert_eq!(descriptor(kind).resets_per_span(), matches!(kind, 3..=5));
    }
}

#[test]
fn refuses_untraced_and_invalid_types() {
    for (kind, algorithm) in [(1, 1), (2, 2), (6, 0x12), (8, 0x12), (17, 0x11), (18, 0x12)] {
        let called = Cell::new(false);
        let result = Cipher::new(&descriptor(kind), |_| {
            called.set(true);
            Some(toy())
        });
        assert_eq!(result.err(), Some(Error::Unsupported { kind, algorithm }));
        assert!(!called.get());
    }
    for kind in 13..=15 {
        assert_eq!(cipher(kind).err(), Some(Error::InvalidType(kind)));
    }
}

#[test]
fn identity_leaves_data_unchanged() {
    for kind in [0, 9, 19, u16::MAX] {
        let called = Cell::new(false);
        let mut cipher = Cipher::<Toy>::new(&descriptor(kind), |_| {
            called.set(true);
            None
        })
        .unwrap();
        assert!(!called.get());
        let mut data = plain(37);
        cipher.run(&mut data, &[0..5, 5..37, 3..3]).unwrap();
        cipher.update(&mut data[1..2]).unwrap();
        assert_eq!(data, plain(37));
    }
}

#[test]
fn fails_initialization_without_a_key() {
    let result = Cipher::new(&descriptor(16), |_| None::<Toy>);
    assert_eq!(result.err(), Some(Error::NoKey(0x1234)));
}

#[test]
fn decrypts_one_block() {
    let stored: Block = core::array::from_fn(|n| n as u8);
    let mut expected = stored;
    toy().decrypt_block(&mut expected);
    for (byte, iv) in expected.iter_mut().zip(&IV) {
        *byte ^= iv;
    }
    let mut data = stored;
    Cbc::new(toy(), IV).update(&mut data).unwrap();
    assert_eq!(data, expected);
}

#[test]
fn decrypts_in_place_against_a_reference() {
    let mut data = plain(5 * BLOCK_LEN);
    toy().encrypt(IV, &mut data);
    let stored = data.clone();
    Cbc::new(toy(), IV).update(&mut data).unwrap();
    assert_eq!(data, plain(5 * BLOCK_LEN));
    // Each block depends on the stored block before it, not the output.
    let mut second = stored[BLOCK_LEN..2 * BLOCK_LEN].to_vec();
    let iv: Block = stored[..BLOCK_LEN].try_into().unwrap();
    Cbc::new(toy(), iv).update(&mut second).unwrap();
    assert_eq!(second, &plain(5 * BLOCK_LEN)[BLOCK_LEN..2 * BLOCK_LEN]);
}

#[test]
fn chains_across_updates() {
    let mut data = plain(6 * BLOCK_LEN);
    toy().encrypt(IV, &mut data);
    let mut cbc = Cbc::new(toy(), IV);
    let (first, rest) = data.split_at_mut(BLOCK_LEN);
    cbc.update(first).unwrap();
    cbc.update(&mut []).unwrap();
    let (second, third) = rest.split_at_mut(3 * BLOCK_LEN);
    cbc.update(second).unwrap();
    cbc.update(third).unwrap();
    assert_eq!(data, plain(6 * BLOCK_LEN));
}

#[test]
fn reset_restores_the_initial_iv() {
    let mut block = plain(BLOCK_LEN);
    toy().encrypt(IV, &mut block);
    let mut cbc = Cbc::new(toy(), IV);
    let mut other = plain(2 * BLOCK_LEN);
    cbc.update(&mut other).unwrap();
    cbc.reset();
    cbc.update(&mut block).unwrap();
    assert_eq!(block, plain(BLOCK_LEN));
}

#[test]
fn rejects_unaligned_input_unchanged() {
    let mut data = plain(2 * BLOCK_LEN);
    toy().encrypt(IV, &mut data);
    let stored = data.clone();
    let mut cbc = Cbc::new(toy(), IV);
    for len in [1, BLOCK_LEN - 1, BLOCK_LEN + 1] {
        assert_eq!(cbc.update(&mut data[..len]), Err(Error::Unaligned(len)));
    }
    assert_eq!(data, stored);
    // The IV did not advance either.
    cbc.update(&mut data).unwrap();
    assert_eq!(data, plain(2 * BLOCK_LEN));
}

#[test]
fn continuous_types_chain_spans() {
    let mut data = plain(4 * BLOCK_LEN);
    toy().encrypt(IV, &mut data[..BLOCK_LEN]);
    toy().encrypt(IV, &mut data[BLOCK_LEN..]);
    let mut chained = plain(4 * BLOCK_LEN);
    toy().encrypt(IV, &mut chained);

    for kind in [10, 11, 12, 16] {
        let mut buffer = chained.clone();
        cipher(kind)
            .unwrap()
            .run(&mut buffer, &[0..BLOCK_LEN, BLOCK_LEN..4 * BLOCK_LEN])
            .unwrap();
        assert_eq!(buffer, plain(4 * BLOCK_LEN), "type {kind}");
    }
    for kind in [3, 4, 5] {
        let mut buffer = data.clone();
        cipher(kind)
            .unwrap()
            .run(&mut buffer, &[0..BLOCK_LEN, BLOCK_LEN..4 * BLOCK_LEN])
            .unwrap();
        assert_eq!(buffer, plain(4 * BLOCK_LEN), "type {kind}");
    }
}

#[test]
fn run_finalizes_at_the_end() {
    let mut data = plain(2 * BLOCK_LEN);
    toy().encrypt(IV, &mut data);
    let mut cipher = cipher(16).unwrap();
    let whole = 0..data.len();
    let spans = [whole];
    let mut first = data.clone();
    cipher.run(&mut first, &spans).unwrap();
    let mut second = data.clone();
    cipher.run(&mut second, &spans).unwrap();
    assert_eq!(first, second);
    cipher.run(&mut second, &[]).unwrap();
    let mut empty = Vec::new();
    let nothing = 0..0;
    cipher.run(&mut empty, &[nothing]).unwrap();
}

#[test]
fn checks_every_span_before_processing() {
    let mut data = plain(4 * BLOCK_LEN);
    toy().encrypt(IV, &mut data);
    let stored = data.clone();
    let len = data.len();
    let cases = [
        (
            vec![0..BLOCK_LEN, BLOCK_LEN..BLOCK_LEN + 3],
            Error::Unaligned(3),
        ),
        (
            vec![0..BLOCK_LEN, 0..len + BLOCK_LEN],
            Error::OutOfBounds {
                span: 0..len + BLOCK_LEN,
                len,
            },
        ),
        (
            vec![0..BLOCK_LEN, Range { start: 32, end: 16 }],
            Error::OutOfBounds {
                span: Range { start: 32, end: 16 },
                len,
            },
        ),
    ];
    let mut cipher = cipher(16).unwrap();
    for (spans, error) in cases {
        assert_eq!(cipher.run(&mut data, &spans), Err(error));
        assert_eq!(data, stored);
    }
    let whole = 0..len;
    cipher.run(&mut data, &[whole]).unwrap();
    assert_eq!(data, plain(len));
}
