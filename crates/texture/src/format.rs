//! Pixel format ids observed in texture stores.
//!
//! The id is a descriptor field. The names and codecs below are the readings
//! that decode the sampled stores into usable images; an id outside this table
//! is reported without a pixel interpretation.

/// The decoding path for one pixel format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Four linear bytes per texel, in R, G, B, A order.
    Rgba8,
    /// 8 bytes per 4 × 4 block, BC1 row-major.
    Bc1,
    /// 8 bytes per 4 × 4 block, BC4 row-major.
    Bc4,
    /// Two 8-byte BC4 planes per 4 × 4 block.
    Bc5,
}

impl Codec {
    /// Bytes one level of `width` × `height` needs.
    pub fn level_len(self, width: u32, height: u32) -> u64 {
        let width = u64::from(width.max(1));
        let height = u64::from(height.max(1));
        match self {
            Codec::Rgba8 => width * height * 4,
            Codec::Bc1 | Codec::Bc4 => width.div_ceil(4) * height.div_ceil(4) * 8,
            Codec::Bc5 => width.div_ceil(4) * height.div_ceil(4) * 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub id: u8,
    pub name: &'static str,
    /// `None` when the id's pixel layout is not established.
    pub codec: Option<Codec>,
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
            detail: "four linear bytes per texel; the sampled images decode as R, G, B, A",
        },
        71 | 72 => PixelFormat {
            id,
            name: "BC1",
            codec: Some(Codec::Bc1),
            detail: "8 bytes per 4 × 4 block, row-major; the BC1 candidate passes the mip comparison",
        },
        80 => PixelFormat {
            id,
            name: "BC4",
            codec: Some(Codec::Bc4),
            detail: "8 bytes per 4 × 4 block, row-major single channel",
        },
        83 => PixelFormat {
            id,
            name: "BC5",
            codec: Some(Codec::Bc5),
            detail: "two 8-byte BC4 planes per 4 × 4 block; decoded as X, Y, 255",
        },
        _ => PixelFormat {
            id,
            name: "unknown",
            codec: None,
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
        assert_eq!(Codec::Bc1.level_len(4, 4), 8);
        assert_eq!(Codec::Bc1.level_len(5, 1), 16);
        assert_eq!(Codec::Bc4.level_len(8, 8), 32);
        assert_eq!(Codec::Bc5.level_len(4, 4), 16);
    }

    #[test]
    fn only_observed_formats_are_decodable() {
        for id in [28, 71, 72, 80, 83] {
            assert!(pixel_format(id).is_supported(), "{id}");
        }
        for id in [54, 77, 98, 99, 255] {
            assert!(!pixel_format(id).is_supported(), "{id}");
        }
    }
}
