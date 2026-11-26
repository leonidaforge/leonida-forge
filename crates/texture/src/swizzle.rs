//! Deswizzle for native texture allocations that carry the tiled flag.
//!
//! A tiled allocation is a grid of 4 KiB tiles. One tile holds a rectangular
//! group of elements; an element is one 4 x 4 block for a block format and one
//! texel for an uncompressed format. The element order inside a tile is a bit
//! interleave of the local x and y coordinates, not row-major.

use super::{Codec, Error};

#[derive(Clone, Copy)]
enum Axis {
    X,
    Y,
}

/// Order of the coordinate bits inside a tile, least significant first.
/// `(Axis::Y, 0)` means the lowest bit of the local y coordinate.
const ORDER_16: &[(Axis, u8)] = &[
    (Axis::Y, 0),
    (Axis::Y, 1),
    (Axis::X, 0),
    (Axis::X, 1),
    (Axis::Y, 2),
    (Axis::X, 2),
    (Axis::Y, 3),
    (Axis::X, 3),
];

const ORDER_8: &[(Axis, u8)] = &[
    (Axis::X, 0),
    (Axis::Y, 0),
    (Axis::Y, 1),
    (Axis::X, 1),
    (Axis::X, 2),
    (Axis::Y, 2),
    (Axis::X, 3),
    (Axis::Y, 3),
    (Axis::X, 4),
];

const ORDER_4: &[(Axis, u8)] = &[
    (Axis::X, 0),
    (Axis::X, 1),
    (Axis::Y, 0),
    (Axis::Y, 1),
    (Axis::Y, 2),
    (Axis::X, 2),
    (Axis::Y, 3),
    (Axis::X, 3),
    (Axis::Y, 4),
    (Axis::X, 4),
];

const ORDER_2: &[(Axis, u8)] = &[
    (Axis::X, 0),
    (Axis::X, 1),
    (Axis::X, 2),
    (Axis::Y, 0),
    (Axis::Y, 1),
    (Axis::Y, 2),
    (Axis::X, 3),
    (Axis::Y, 3),
    (Axis::X, 4),
    (Axis::Y, 4),
    (Axis::X, 5),
];

const D64K_16: &[(Axis, u8)] = &[
    (Axis::X, 0),
    (Axis::Y, 0),
    (Axis::X, 1),
    (Axis::Y, 1),
    (Axis::Y, 2),
    (Axis::X, 2),
    (Axis::Y, 3),
    (Axis::X, 3),
    (Axis::Y, 4),
    (Axis::X, 4),
    (Axis::Y, 5),
    (Axis::X, 5),
];

const D64K_8: &[(Axis, u8)] = &[
    (Axis::X, 0),
    (Axis::Y, 0),
    (Axis::X, 1),
    (Axis::X, 2),
    (Axis::Y, 1),
    (Axis::Y, 2),
    (Axis::X, 3),
    (Axis::Y, 3),
    (Axis::X, 4),
    (Axis::Y, 4),
    (Axis::X, 5),
    (Axis::Y, 5),
    (Axis::X, 6),
];

const D64K_4: &[(Axis, u8)] = &[
    (Axis::X, 0),
    (Axis::X, 1),
    (Axis::Y, 0),
    (Axis::Y, 1),
    (Axis::X, 2),
    (Axis::Y, 2),
    (Axis::Y, 3),
    (Axis::X, 3),
    (Axis::Y, 4),
    (Axis::X, 4),
    (Axis::Y, 5),
    (Axis::X, 5),
    (Axis::Y, 6),
    (Axis::X, 6),
];

const D64K_2: &[(Axis, u8)] = &[
    (Axis::X, 0),
    (Axis::X, 1),
    (Axis::X, 2),
    (Axis::Y, 0),
    (Axis::Y, 1),
    (Axis::Y, 2),
    (Axis::X, 3),
    (Axis::Y, 3),
    (Axis::X, 4),
    (Axis::Y, 4),
    (Axis::X, 5),
    (Axis::Y, 5),
    (Axis::X, 6),
    (Axis::Y, 6),
    (Axis::X, 7),
];

/// The native tiled allocation layouts. `S4k` is the 4 KiB grid used by the
/// sampled native dictionaries and RDS5 tile modes 1..3. `D64k` is the 64 KiB
/// grid used by RDS5 tile mode 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Swizzle {
    S4k,
    D64k,
}

/// Elements per tile edge and bytes per element for one codec.
fn geometry(swizzle: Swizzle, codec: Codec) -> (usize, usize, usize, &'static [(Axis, u8)]) {
    match (swizzle, codec) {
        (Swizzle::S4k, Codec::Rgba8) => (32, 32, 4, ORDER_4),
        (Swizzle::S4k, Codec::R16Float) => (64, 32, 2, ORDER_2),
        (Swizzle::S4k, Codec::Bc1 | Codec::Bc4) => (32, 16, 8, ORDER_8),
        (Swizzle::S4k, Codec::Bc3 | Codec::Bc5 | Codec::Bc7) => (16, 16, 16, ORDER_16),
        (Swizzle::D64k, Codec::Rgba8) => (128, 128, 4, D64K_4),
        (Swizzle::D64k, Codec::R16Float) => (256, 128, 2, D64K_2),
        (Swizzle::D64k, Codec::Bc1 | Codec::Bc4) => (128, 64, 8, D64K_8),
        (Swizzle::D64k, Codec::Bc3 | Codec::Bc5 | Codec::Bc7) => (64, 64, 16, D64K_16),
    }
}

fn element_grid(codec: Codec, width: u32, height: u32) -> (usize, usize) {
    let (w, h) = (
        usize::try_from(width).unwrap_or(0),
        usize::try_from(height).unwrap_or(0),
    );
    match codec {
        Codec::Rgba8 | Codec::R16Float => (w, h),
        Codec::Bc1 | Codec::Bc3 | Codec::Bc4 | Codec::Bc5 | Codec::Bc7 => {
            (w.div_ceil(4), h.div_ceil(4))
        }
    }
}

/// Bytes a tiled allocation needs for one level, including the padding to
/// whole tiles.
pub(crate) fn padded_len(swizzle: Swizzle, codec: Codec, width: u32, height: u32) -> u64 {
    let (tw, th, bytes, _) = geometry(swizzle, codec);
    let (ew, eh) = element_grid(codec, width, height);
    let pw = ew.div_ceil(tw) * tw;
    let ph = eh.div_ceil(th) * th;
    (pw as u64) * (ph as u64) * (bytes as u64)
}

/// Position of one element inside its tile.
fn element_index(lx: usize, ly: usize, order: &[(Axis, u8)]) -> usize {
    let mut index = 0;
    for (position, &(axis, bit)) in order.iter().enumerate() {
        let value = match axis {
            Axis::X => (lx >> bit) & 1,
            Axis::Y => (ly >> bit) & 1,
        };
        index |= value << position;
    }
    index
}

/// Reorders a tiled level into the row-major element order the decoders read.
/// The padding tiles are dropped; the result is exactly one level.
pub(crate) fn deswizzle(
    swizzle: Swizzle,
    raw: &[u8],
    width: u32,
    height: u32,
    codec: Codec,
) -> Result<Vec<u8>, Error> {
    let (tw, th, bytes, order) = geometry(swizzle, codec);
    let (ew, eh) = element_grid(codec, width, height);
    if ew == 0 || eh == 0 {
        return Err(Error::Invalid("the level has no elements".into()));
    }
    let pw = ew.div_ceil(tw) * tw;
    let ph = eh.div_ceil(th) * th;
    let needed = pw * ph * bytes;
    if raw.len() < needed {
        return Err(Error::Invalid(format!(
            "the tiled level needs {needed} bytes but the allocation holds {}",
            raw.len()
        )));
    }
    let tiles_x = pw / tw;
    let mut out = vec![0u8; ew * eh * bytes];
    for y in 0..eh {
        for x in 0..ew {
            let tile = (y / th) * tiles_x + (x / tw);
            let element = element_index(x % tw, y % th, order);
            let src = (tile * tw * th + element) * bytes;
            let dst = (y * ew + x) * bytes;
            out[dst..dst + bytes].copy_from_slice(&raw[src..src + bytes]);
        }
    }
    Ok(out)
}

/// Reorders a row-major level into the native tiled element order. Used by
/// tests and fixtures; the viewer only deswizzles.
#[cfg(test)]
pub(crate) fn swizzle(
    swizzle: Swizzle,
    linear: &[u8],
    width: u32,
    height: u32,
    codec: Codec,
) -> Vec<u8> {
    let (tw, th, bytes, order) = geometry(swizzle, codec);
    let (ew, eh) = element_grid(codec, width, height);
    let pw = ew.div_ceil(tw) * tw;
    let ph = eh.div_ceil(th) * th;
    let tiles_x = pw / tw;
    let mut raw = vec![0u8; pw * ph * bytes];
    for y in 0..eh {
        for x in 0..ew {
            let tile = (y / th) * tiles_x + (x / tw);
            let element = element_index(x % tw, y % th, order);
            let src = (y * ew + x) * bytes;
            let dst = (tile * tw * th + element) * bytes;
            raw[dst..dst + bytes].copy_from_slice(&linear[src..src + bytes]);
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    fn swizzle_with(
        swizzle: Swizzle,
        linear: &[u8],
        width: u32,
        height: u32,
        codec: Codec,
    ) -> Vec<u8> {
        let (tw, th, bytes, order) = geometry(swizzle, codec);
        let (ew, eh) = element_grid(codec, width, height);
        let pw = ew.div_ceil(tw) * tw;
        let ph = eh.div_ceil(th) * th;
        let tiles_x = pw / tw;
        let mut raw = vec![0u8; pw * ph * bytes];
        for y in 0..eh {
            for x in 0..ew {
                let tile = (y / th) * tiles_x + (x / tw);
                let element = element_index(x % tw, y % th, order);
                let src = (y * ew + x) * bytes;
                let dst = (tile * tw * th + element) * bytes;
                raw[dst..dst + bytes].copy_from_slice(&linear[src..src + bytes]);
            }
        }
        raw
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|value| value as u8).collect()
    }

    #[test]
    fn the_element_order_is_a_bijection() {
        for swizzle in [Swizzle::S4k, Swizzle::D64k] {
            for codec in [
                Codec::Rgba8,
                Codec::R16Float,
                Codec::Bc1,
                Codec::Bc3,
                Codec::Bc4,
                Codec::Bc5,
                Codec::Bc7,
            ] {
                let (tw, th, _, order) = geometry(swizzle, codec);
                let mut seen = vec![false; tw * th];
                for y in 0..th {
                    for x in 0..tw {
                        let index = element_index(x, y, order);
                        assert!(!seen[index], "{swizzle:?} {codec:?} repeats an index");
                        seen[index] = true;
                    }
                }
            }
        }
    }

    #[test]
    fn the_sixteen_byte_order_places_the_expected_positions() {
        let order = ORDER_16;
        assert_eq!(element_index(0, 0, order), 0);
        assert_eq!(element_index(0, 1, order), 1);
        assert_eq!(element_index(0, 2, order), 2);
        assert_eq!(element_index(1, 0, order), 4);
        assert_eq!(element_index(1, 1, order), 5);
        assert_eq!(element_index(2, 0, order), 8);
        assert_eq!(element_index(4, 0, order), 32);
        assert_eq!(element_index(0, 4, order), 16);
        assert_eq!(element_index(8, 0, order), 128);
    }

    #[test]
    fn the_eight_byte_order_places_the_expected_positions() {
        let order = ORDER_8;
        assert_eq!(element_index(0, 0, order), 0);
        assert_eq!(element_index(1, 0, order), 1);
        assert_eq!(element_index(0, 1, order), 2);
        assert_eq!(element_index(0, 2, order), 4);
        assert_eq!(element_index(2, 0, order), 8);
        assert_eq!(element_index(4, 0, order), 16);
        assert_eq!(element_index(0, 4, order), 32);
        assert_eq!(element_index(8, 0, order), 64);
        assert_eq!(element_index(0, 8, order), 128);
        assert_eq!(element_index(16, 0, order), 256);
    }

    #[test]
    fn the_four_byte_order_places_the_expected_positions() {
        let order = ORDER_4;
        assert_eq!(element_index(0, 0, order), 0);
        assert_eq!(element_index(1, 0, order), 1);
        assert_eq!(element_index(2, 0, order), 2);
        assert_eq!(element_index(0, 1, order), 4);
        assert_eq!(element_index(0, 2, order), 8);
        assert_eq!(element_index(4, 0, order), 32);
        assert_eq!(element_index(0, 4, order), 16);
        assert_eq!(element_index(0, 8, order), 64);
        assert_eq!(element_index(8, 0, order), 128);
        assert_eq!(element_index(0, 16, order), 256);
        assert_eq!(element_index(16, 0, order), 512);
    }

    #[test]
    fn a_tiled_level_round_trips() {
        for swizzle in [Swizzle::S4k, Swizzle::D64k] {
            for (codec, width, height) in [
                (Codec::Bc7, 12, 12),
                (Codec::Bc1, 12, 8),
                (Codec::Bc3, 5, 9),
                (Codec::Bc5, 65, 33),
                (Codec::Rgba8, 40, 36),
                (Codec::R16Float, 70, 40),
            ] {
                let len = codec.level_len(width, height) as usize;
                let linear = pattern(len);
                let raw = swizzle_with(swizzle, &linear, width, height, codec);
                assert_eq!(
                    deswizzle(swizzle, &raw, width, height, codec).unwrap(),
                    linear,
                    "{swizzle:?} {codec:?} {width}x{height}"
                );
            }
        }
    }

    #[test]
    fn padding_tiles_are_dropped() {
        let raw = pattern(4096);
        let out = deswizzle(Swizzle::S4k, &raw, 4, 4, Codec::Bc7).unwrap();
        assert_eq!(out.len(), 16);
        let raw = pattern(65536);
        let out = deswizzle(Swizzle::D64k, &raw, 4, 4, Codec::Bc7).unwrap();
        assert_eq!(out.len(), 16);
    }

    #[test]
    fn the_padded_size_covers_whole_tiles() {
        assert_eq!(padded_len(Swizzle::S4k, Codec::Bc7, 1920, 1080), 2_088_960);
        assert_eq!(padded_len(Swizzle::S4k, Codec::Bc7, 1024, 512), 524_288);
        assert_eq!(padded_len(Swizzle::S4k, Codec::Bc1, 1920, 1080), 1_044_480);
        assert_eq!(padded_len(Swizzle::S4k, Codec::Rgba8, 4, 4), 32 * 32 * 4);
        assert_eq!(padded_len(Swizzle::D64k, Codec::Bc7, 4, 4), 65_536);
        assert_eq!(padded_len(Swizzle::D64k, Codec::Bc1, 4, 4), 65_536);
    }

    #[test]
    fn a_short_tiled_level_is_rejected() {
        let err = deswizzle(Swizzle::S4k, &[0u8; 4095], 4, 4, Codec::Bc7).unwrap_err();
        assert!(err.to_string().contains("tiled level"), "{err}");
        let err = deswizzle(Swizzle::D64k, &[0u8; 65_535], 4, 4, Codec::Bc7).unwrap_err();
        assert!(err.to_string().contains("tiled level"), "{err}");
    }
}
