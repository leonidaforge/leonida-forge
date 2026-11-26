use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;

use super::test_support::{build, entry};
use super::{Status, Store, is_store};

fn source(bytes: &[u8]) -> Source {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    Source::from_file(file).unwrap()
}

fn open(bytes: &[u8]) -> Store {
    Store::open(source(bytes)).unwrap()
}

fn rgba_pixels() -> Vec<u8> {
    vec![
        255, 0, 0, 255, // red
        0, 255, 0, 255, // green
        0, 0, 255, 255, // blue
        255, 255, 255, 128, // translucent white
    ]
}

#[test]
fn recognises_and_lists_one_rgba_texture() {
    let block = rgba_pixels();
    let bytes = build(std::slice::from_ref(&block), &[entry(2, 2, 28, 2, 1)]);
    assert!(is_store(&bytes));
    let store = open(&bytes);
    assert_eq!(store.len(), 1);
    let texture = &store.textures()[0];
    assert_eq!((texture.width, texture.height), (2, 2));
    assert_eq!(texture.format.name, "RGBA8");
    assert_eq!(texture.status, Status::Decodable);
    assert_eq!(texture.level0_len, Some(16));
    assert_eq!(texture.levels.len(), 1);
}

#[test]
fn rgab8_pixels_keep_their_channels() {
    let bytes = build(&[rgba_pixels()], &[entry(2, 2, 28, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).expect("decode");
    assert_eq!((image.width, image.height), (2, 2));
    assert_eq!(image.rgba, rgba_pixels());
}

#[test]
fn bc1_decodes_a_solid_block() {
    // c0 = red, c1 = black, every index selects c0.
    let block = vec![0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let bytes = build(&[block], &[entry(4, 4, 71, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    assert_eq!((image.width, image.height), (4, 4));
    for pixel in image.rgba.as_chunks::<4>().0 {
        assert_eq!(pixel, &[255, 0, 0, 255]);
    }
}

#[test]
fn bc1_keeps_the_one_bit_transparent_branch() {
    // c0 = 0, c1 = 0xFFFF, every index is 3: the transparent branch.
    let block = vec![0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let bytes = build(&[block], &[entry(4, 4, 71, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    for pixel in image.rgba.as_chunks::<4>().0 {
        assert_eq!(pixel, &[0, 0, 0, 0]);
    }
}

#[test]
fn bc4_decodes_a_solid_block() {
    let block = vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let bytes = build(&[block], &[entry(4, 4, 80, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    for pixel in image.rgba.as_chunks::<4>().0 {
        assert_eq!(pixel, &[255, 255, 255, 255]);
    }
}

#[test]
fn unsupported_formats_are_reported_not_decoded() {
    let bytes = build(&[vec![0; 16]], &[entry(4, 4, 98, 2, 1)]);
    let store = open(&bytes);
    let texture = &store.textures()[0];
    assert!(matches!(texture.status, Status::Unsupported(_)));
    assert!(store.decode(0, 0, &AtomicBool::new(false)).is_err());
}

#[test]
fn a_texture_larger_than_the_limit_is_invalid() {
    let bytes = build(&[vec![0; 16]], &[entry(16384, 16384, 28, 2, 1)]);
    let store = open(&bytes);
    let texture = &store.textures()[0];
    assert!(
        matches!(texture.status, Status::Invalid(_)),
        "{:?}",
        texture.status
    );
}

#[test]
fn a_descriptor_without_a_block_start_is_invalid() {
    let bytes = build(&[rgba_pixels()], &[entry(2, 2, 28, 2, 0)]);
    let store = open(&bytes);
    assert!(matches!(store.textures()[0].status, Status::Invalid(_)));
    assert!(store.textures()[0].range_error.is_some());
}

#[test]
fn a_missing_level_is_not_decoded() {
    let bytes = build(&[rgba_pixels()], &[entry(2, 2, 28, 2, 1)]);
    let store = open(&bytes);
    assert!(store.decode(0, 1, &AtomicBool::new(false)).is_err());
}

#[test]
fn a_dictionary_enumerates_every_entry() {
    let first = vec![1u8; 32 * 32 * 4];
    let second = vec![2u8; 32 * 32 * 4];
    let bytes = build(
        &[first, second],
        &[entry(32, 32, 28, 2, 1), entry(32, 32, 28, 2, 2)],
    );
    let store = open(&bytes);
    assert_eq!(store.len(), 2);
    assert_eq!(store.textures()[0].index, 0);
    assert_eq!(store.textures()[1].index, 1);
    let cancel = AtomicBool::new(false);
    assert_eq!(store.decode(0, 0, &cancel).unwrap().rgba[0], 1);
    assert_eq!(store.decode(1, 0, &cancel).unwrap().rgba[0], 2);
}

#[test]
fn a_non_2d_kind_is_reported() {
    let bytes = build(&[rgba_pixels()], &[entry(2, 2, 28, 4, 1)]);
    let store = open(&bytes);
    assert!(matches!(store.textures()[0].status, Status::Unsupported(_)));
}

#[test]
fn a_non_rds5_file_is_rejected() {
    let err = Store::open(source(b"not a store")).unwrap_err();
    assert!(matches!(err, super::Error::NotRds5));
}
