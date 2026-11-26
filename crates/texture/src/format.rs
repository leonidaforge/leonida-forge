//! Pixel format ids observed in texture stores and dictionaries.
//!
//! The id is a descriptor field. The readings below are the ones that reproduce
//! the encoded sizes and produce usable images in the sampled assets; an id
//! outside this table is reported without a pixel interpretation.

/// The decoding path for one pixel format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Four linear bytes per texel, in R, G, B, A order.
    Rgba8,
    /// Two bytes per texel, IEEE 754 binary16.
    R16Float,
    /// 8 bytes per 4 x 4 block, BC1.
    Bc1,
    /// 16 bytes per 4 x 4 block, BC3.
    Bc3,
    /// 8 bytes per 4 x 4 block, BC4.
    Bc4,
    /// 16 bytes per 4 x 4 block, two BC4 planes (BC5).
    Bc5,
    /// 16 bytes per 4 x 4 block, BC7.
    Bc7,
}

impl Codec {
    /// Bytes one level of `width` x `height` needs.
    pub fn level_len(self, width: u32, height: u32) -> u64 {
        let width = u64::from(width.max(1));
        let height = u64::from(height.max(1));
        match self {
            Codec::Rgba8 => width * height * 4,
            Codec::R16Float => width * height * 2,
            Codec::Bc1 | Codec::Bc4 => width.div_ceil(4) * height.div_ceil(4) * 8,
            Codec::Bc3 | Codec::Bc5 | Codec::Bc7 => width.div_ceil(4) * height.div_ceil(4) * 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub id: u8,
    pub name: &'static str,
    /// `None` when the id's pixel layout is not established.
    pub codec: Option<Codec>,
    /// Whether the stored colours are sRGB encoded. The format id is the
    /// evidence; an unknown id is treated as linear.
    pub srgb: bool,
    pub detail: &'static str,
}

impl PixelFormat {
    pub fn is_supported(self) -> bool {
        self.codec.is_some()
    }
}

pub fn pixel_format(id: u8) -> PixelFormat {
    match id {
        28 => PixelFormat {
            id,
            name: "RGBA8",
            codec: Some(Codec::Rgba8),
            srgb: false,
            detail: "four linear bytes per texel; the sampled images decode as R, G, B, A",
        },
        29 => PixelFormat {
            id,
            name: "RGBA8_SRGB",
            codec: Some(Codec::Rgba8),
            srgb: true,
            detail: "four sRGB bytes per texel; observed in an embedded drawable tint palette",
        },
        54 => PixelFormat {
            id,
            name: "R16_FLOAT",
            codec: Some(Codec::R16Float),
            srgb: false,
            detail: "candidate reading: one binary16 value per texel, clamped to [0, 1]; no simple-2D sample confirms it",
        },
        71 => PixelFormat {
            id,
            name: "BC1",
            codec: Some(Codec::Bc1),
            srgb: false,
            detail: "8 bytes per 4 x 4 block, row-major; the BC1 candidate passes the mip comparison",
        },
        72 => PixelFormat {
            id,
            name: "BC1_SRGB",
            codec: Some(Codec::Bc1),
            srgb: true,
            detail: "8 bytes per 4 x 4 block, row-major; sRGB colour",
        },
        77 => PixelFormat {
            id,
            name: "BC3",
            codec: Some(Codec::Bc3),
            srgb: false,
            detail: "16 bytes per 4 x 4 block, BC3 alpha and colour; the sampled glyphs decode after the tiled reorder",
        },
        80 => PixelFormat {
            id,
            name: "BC4",
            codec: Some(Codec::Bc4),
            srgb: false,
            detail: "8 bytes per 4 x 4 block, row-major single channel",
        },
        83 => PixelFormat {
            id,
            name: "BC5",
            codec: Some(Codec::Bc5),
            srgb: false,
            detail: "two 8-byte BC4 planes per 4 x 4 block; decoded as X, Y, 255",
        },
        98 => PixelFormat {
            id,
            name: "BC7",
            codec: Some(Codec::Bc7),
            srgb: false,
            detail: "16 bytes per 4 x 4 block; the sampled UI and photo records decode after the tiled reorder",
        },
        99 => PixelFormat {
            id,
            name: "BC7_SRGB",
            codec: Some(Codec::Bc7),
            srgb: true,
            detail: "16 bytes per 4 x 4 block; sRGB colour",
        },
        _ => PixelFormat {
            id,
            name: "unknown",
            codec: None,
            srgb: false,
            detail: "no pixel layout is established for this format id",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_sizes_follow_the_block_grid() {
        assert_eq!(Codec::Rgba8.level_len(2, 2), 16);
        assert_eq!(Codec::Rgba8.level_len(17, 5), 340);
        assert_eq!(Codec::R16Float.level_len(2, 2), 8);
        assert_eq!(Codec::Bc1.level_len(4, 4), 8);
        assert_eq!(Codec::Bc1.level_len(5, 1), 16);
        assert_eq!(Codec::Bc3.level_len(8, 8), 64);
        assert_eq!(Codec::Bc4.level_len(8, 8), 32);
        assert_eq!(Codec::Bc5.level_len(4, 4), 16);
        assert_eq!(Codec::Bc7.level_len(4, 4), 16);
    }

    #[test]
    fn only_observed_formats_are_decodable() {
        for id in [28, 29, 54, 71, 72, 77, 80, 83, 98, 99] {
            assert!(pixel_format(id).is_supported(), "{id}");
        }
        for id in [10, 87, 95, 255] {
            assert!(!pixel_format(id).is_supported(), "{id}");
        }
    }
}
