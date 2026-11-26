use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;

use super::test_support::{build, entry, entry_tiled, tiled};
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
    assert_eq!(texture.level0_len, Some(4096));
    assert_eq!(texture.levels.len(), 1);
    // The synthetic page holds one 4 KiB tile and the level starts at its
    // first element.
    assert_eq!(texture.levels[0].offset, 0);
}

#[test]
fn rgab8_pixels_keep_their_channels() {
    let block = tiled(&rgba_pixels(), 2, 2, 28, 1);
    let bytes = build(&[block], &[entry(2, 2, 28, 2, 1)]);
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
fn a_tiled_rds5_level_is_deswizzled_from_its_4k_tile() {
    // One solid BC1 block at the first element of a 4 KiB tile. The rest of
    // the tile is padding, which the deswizzle drops.
    let mut tiled = vec![0u8; 0x1000];
    tiled[..8].copy_from_slice(&[0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let bytes = build(&[tiled], &[entry_tiled(4, 4, 71, 2, 1, 1)]);
    let store = open(&bytes);
    let level = store
        .level(0, 0, &AtomicBool::new(false))
        .expect("tiled level");
    assert!(level.swizzled);
    assert_eq!(level.data.len(), 8);
    let image = level.decode().unwrap();
    assert_eq!((image.width, image.height), (4, 4));
    for pixel in image.rgba.as_chunks::<4>().0 {
        assert_eq!(pixel, &[255, 0, 0, 255]);
    }
}

#[test]
fn tile_mode_zero_uses_the_64k_tile_grid() {
    let mut tiled = vec![0u8; 0x10000];
    tiled[..8].copy_from_slice(&[0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let bytes = build(&[tiled], &[entry_tiled(4, 4, 71, 2, 1, 0)]);
    let store = open(&bytes);
    let level = store
        .level(0, 0, &AtomicBool::new(false))
        .expect("64 KiB tiled level");
    assert!(level.swizzled);
    assert_eq!(level.data.len(), 8);
    let image = level.decode().unwrap();
    for pixel in image.rgba.as_chunks::<4>().0 {
        assert_eq!(pixel, &[255, 0, 0, 255]);
    }
}

#[test]
fn an_unestablished_tile_mode_is_unsupported() {
    let bytes = build(&[vec![0u8; 0x1000]], &[entry_tiled(4, 4, 71, 2, 1, 9)]);
    let store = open(&bytes);
    let texture = &store.textures()[0];
    assert!(
        matches!(&texture.status, Status::Unsupported(reason) if reason.contains("tile mode 9")),
        "{:?}",
        texture.status
    );
    assert!(store.level(0, 0, &AtomicBool::new(false)).is_err());
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
fn bc3_decodes_a_solid_block() {
    // Alpha 255 everywhere, then a BC1 red block.
    let block = vec![
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    for format in [77, 78] {
        let bytes = build(std::slice::from_ref(&block), &[entry(4, 4, format, 2, 1)]);
        let store = open(&bytes);
        let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
        for pixel in image.rgba.as_chunks::<4>().0 {
            assert_eq!(pixel, &[255, 0, 0, 255], "format {format}");
        }
    }
}

#[test]
fn bc5_decodes_a_solid_two_plane_block() {
    let block = vec![
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let bytes = build(&[block], &[entry(4, 4, 83, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    for pixel in image.rgba.as_chunks::<4>().0 {
        assert_eq!(pixel, &[255, 255, 255, 255]);
    }
}

#[test]
fn r16_float_clamps_to_the_preview_range() {
    let mut data = Vec::new();
    for value in [0.0f32, 0.5, 1.0, 2.0] {
        data.extend_from_slice(&half::f16::from_f32(value).to_bits().to_le_bytes());
    }
    let block = tiled(&data, 2, 2, 54, 1);
    let bytes = build(&[block], &[entry(2, 2, 54, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    assert_eq!(
        image.rgba,
        vec![
            0, 0, 0, 255, 128, 128, 128, 255, 255, 255, 255, 255, 255, 255, 255, 255
        ]
    );
}

#[test]
fn r16_float_maps_non_finite_and_negative_values_to_zero() {
    let mut data = Vec::new();
    for value in [-1.0f32, f32::NAN, f32::INFINITY, 0.25] {
        data.extend_from_slice(&half::f16::from_f32(value).to_bits().to_le_bytes());
    }
    let block = tiled(&data, 2, 2, 54, 1);
    let bytes = build(&[block], &[entry(2, 2, 54, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    assert_eq!(
        image.rgba,
        vec![0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0, 255, 64, 64, 64, 255]
    );
}

#[test]
fn small_compressed_dimensions_decode() {
    for (width, height) in [(1u32, 1u32), (4, 1), (13, 1), (4, 4), (5, 3), (17, 9)] {
        let block = [0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut linear = Vec::new();
        for _ in 0..width.div_ceil(4) * height.div_ceil(4) {
            linear.extend_from_slice(&block);
        }
        let block = tiled(&linear, width, height, 71, 1);
        let bytes = build(&[block], &[entry(width, height, 71, 2, 1)]);
        let store = open(&bytes);
        let image = store
            .decode(0, 0, &AtomicBool::new(false))
            .unwrap_or_else(|err| panic!("{width}x{height}: {err}"));
        assert_eq!((image.width, image.height), (width, height));
        for pixel in image.rgba.as_chunks::<4>().0 {
            assert_eq!(pixel, &[255, 0, 0, 255], "{width}x{height}");
        }
    }
}

#[test]
fn unsupported_formats_are_reported_not_decoded() {
    let bytes = build(&[vec![0; 16]], &[entry(4, 4, 10, 2, 1)]);
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

fn push_bits(bits: &mut Vec<u8>, value: u32, count: u32) {
    for shift in 0..count {
        bits.push(((value >> shift) & 1) as u8);
    }
}

/// Builds a BC7 mode-6 block from eight-bit endpoint and 4-bit selector
/// values. The layout is the one Microsoft documents for mode 6: a 7-bit mode
/// prefix, RGBA endpoint pairs with a shared p-bit, then the anchor index in
/// three bits and fifteen 4-bit indices.
fn bc7_mode6(endpoint0: [u8; 4], endpoint1: [u8; 4], selectors: [u8; 16]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(128);
    push_bits(&mut bits, 1 << 6, 7);
    for channel in 0..4 {
        push_bits(&mut bits, u32::from(endpoint0[channel] >> 1), 7);
        push_bits(&mut bits, u32::from(endpoint1[channel] >> 1), 7);
    }
    push_bits(&mut bits, u32::from(endpoint0[0] & 1), 1);
    push_bits(&mut bits, u32::from(endpoint1[0] & 1), 1);
    push_bits(&mut bits, u32::from(selectors[0]), 3);
    for selector in &selectors[1..] {
        push_bits(&mut bits, u32::from(*selector), 4);
    }
    assert_eq!(bits.len(), 128, "mode 6 must fill one BC7 block");
    let mut block = vec![0u8; 16];
    for (index, bit) in bits.iter().enumerate() {
        block[index / 8] |= bit << (index % 8);
    }
    block
}

fn bc7_interpolate(endpoint0: u8, endpoint1: u8, selector: u8) -> u8 {
    const WEIGHTS: [u32; 16] = [0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64];
    let weight = WEIGHTS[selector as usize];
    (((64 - weight) * u32::from(endpoint0) + weight * u32::from(endpoint1) + 32) / 64) as u8
}

#[test]
fn bc7_decodes_a_solid_mode6_block() {
    let block = bc7_mode6([255, 255, 255, 255], [255, 255, 255, 255], [0; 16]);
    let bytes = build(&[block], &[entry(4, 4, 98, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    for pixel in image.rgba.as_chunks::<4>().0 {
        assert_eq!(pixel, &[255, 255, 255, 255]);
    }
}

fn embedded_resource(
    width: u16,
    height: u16,
    format: u8,
    swizzle: u8,
    mips: u16,
    graphics: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut system = vec![0u8; 0x100];
    // A plausible drawable texture record.
    system[0x0E..0x10].copy_from_slice(&8u16.to_le_bytes());
    system[0x18..0x20].copy_from_slice(&0x6000_0000u64.to_le_bytes());
    system[0x30..0x38].copy_from_slice(&0x5000_0080u64.to_le_bytes());
    system[0x38..0x3A].copy_from_slice(&width.to_le_bytes());
    system[0x3A..0x3C].copy_from_slice(&height.to_le_bytes());
    system[0x3F] = format;
    system[0x40] = swizzle;
    system[0x42..0x44].copy_from_slice(&mips.to_le_bytes());
    // Name record with the 64-bit store key.
    system[0x88..0x90].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
    (system, graphics.to_vec())
}

#[test]
fn an_embedded_one_row_bc1_texture_is_valid() {
    let block = [
        0x00, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let (system, graphics) = embedded_resource(5, 1, 71, 0, 1, &block);
    let textures = super::embedded_textures(&system, &graphics);
    assert_eq!(textures.len(), 1, "the record is found");
    assert_eq!((textures[0].info.width, textures[0].info.height), (5, 1));
    assert!(textures[0].info.status.is_decodable());
    let level = super::decode_embedded(&graphics, &textures[0], 0, &AtomicBool::new(false))
        .expect("one-row block decodes");
    assert_eq!((level.width, level.height), (5, 1));
    assert_eq!(level.data.len(), 16);
    let image = level.decode().unwrap();
    assert_eq!((image.width, image.height), (5, 1));
}

#[test]
fn an_embedded_rgba_record_is_reconstructed() {
    let pixels = rgba_pixels();
    let (system, graphics) = embedded_resource(2, 2, 28, 0, 1, &pixels);
    let textures = super::embedded_textures(&system, &graphics);
    assert_eq!(textures.len(), 1);
    let level = super::decode_embedded(&graphics, &textures[0], 0, &AtomicBool::new(false))
        .expect("embedded RGBA decodes");
    assert_eq!(level.data, pixels);
    assert_eq!(level.decode().unwrap().rgba, pixels);
}

#[test]
fn bc7_interpolates_mode6_endpoints_and_alpha() {
    let endpoint0 = [0, 0, 0, 0];
    let endpoint1 = [254, 0, 0, 254];
    let selectors: [u8; 16] = std::array::from_fn(|index| index as u8);
    let block = bc7_mode6(endpoint0, endpoint1, selectors);
    let bytes = build(&[block], &[entry(4, 4, 98, 2, 1)]);
    let store = open(&bytes);
    let image = store.decode(0, 0, &AtomicBool::new(false)).unwrap();
    for (index, pixel) in image.rgba.as_chunks::<4>().0.iter().enumerate() {
        let red = bc7_interpolate(endpoint0[0], endpoint1[0], selectors[index]);
        assert_eq!(pixel, &[red, 0, 0, red], "selector {index}");
    }
    assert_eq!(image.rgba[15 * 4], 254);
    assert_eq!(image.rgba[15 * 4 + 3], 254);
}

/// Reproducible census for the 64 KiB layout claim. It scans every `.ttpf`
/// store below the selected game root and compares the descriptor range with
/// the 64 KiB mip-chain total for simple 2D, supported tile-0 textures.
#[test]
#[ignore = "requires LF_TEST_GAME_ROOT"]
fn tile_zero_64k_corpus_census() {
    let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
    let ttdb = std::path::Path::new(&root).join("data").join("ttdb");
    let set = super::StoreSet::scan(&ttdb).expect("scan");
    let mut selected = 0usize;
    let mut exact = 0usize;
    let mut fit = 0usize;
    for store_index in 0..set.len() {
        let store = set.open(store_index).expect("open store");
        for info in store.textures() {
            if info.kind != 2 || info.tile_mode != 0 || info.format.codec.is_none() {
                continue;
            }
            if info.array_size != 1 {
                continue;
            }
            if info.width == 0 || info.height == 0 {
                continue;
            }
            let Some(total) = d64k_total(
                info.width,
                info.height,
                info.format.codec.unwrap(),
                info.mip_field,
            ) else {
                continue;
            };
            selected += 1;
            if total == info.encoded_len {
                exact += 1;
            }
            if total <= info.encoded_len {
                fit += 1;
            }
        }
    }
    eprintln!("corpus: {} stores", set.len());
    eprintln!("selected={selected} exact={exact} fit={fit}");
    assert_eq!(selected, 38542);
    assert_eq!(exact, 38303);
    assert_eq!(fit, 38542);
}

fn d64k_total(width: u32, height: u32, codec: super::Codec, mip_field: u8) -> Option<u64> {
    let (tw, th, bpe): (u32, u32, u32) = match codec {
        super::Codec::Rgba8 => (128, 128, 4),
        super::Codec::R16Float => (256, 128, 2),
        super::Codec::Bc1 | super::Codec::Bc4 => (128, 64, 8),
        super::Codec::Bc3 | super::Codec::Bc5 | super::Codec::Bc7 => (64, 64, 16),
    };
    let mips = u32::from(mip_field) + 1;
    let block_bytes = u64::from(tw) * u64::from(th) * u64::from(bpe);
    let max_tail = 12u32;
    let tail_width = tw / 2;
    let tail_height = th;
    let dims: Vec<(u32, u32)> = (0..mips)
        .map(|mip| {
            let w = (width >> mip).max(1);
            let h = (height >> mip).max(1);
            match codec {
                super::Codec::Rgba8 | super::Codec::R16Float => (w, h),
                _ => (w.div_ceil(4), h.div_ceil(4)),
            }
        })
        .collect();
    let first = if mips == 1 {
        1
    } else {
        dims.iter()
            .enumerate()
            .position(|(index, &(w, h))| {
                w <= tail_width && h <= tail_height && mips - index as u32 <= max_tail
            })
            .unwrap_or(mips as usize)
    };
    let mut total = if first < mips as usize {
        block_bytes
    } else {
        0
    };
    for &(w, h) in dims.iter().take(first).rev() {
        total += u64::from(w.div_ceil(tw) * tw) * u64::from(h.div_ceil(th) * th) * u64::from(bpe);
    }
    Some(total)
}
