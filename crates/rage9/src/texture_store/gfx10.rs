//! AMD Gfx10 thin-2D texture layout used by the `.ttpf` stores.
//!
//! The layout is a port of the public addrlib equations documented by the
//! ttpfs viewers: a 4 KiB or 64 KiB block with a fixed element-bit order,
//! blocks stored row-major, mips smallest first, and a shared 4 KiB tail for
//! the smallest mips. Only the parts needed to read mip 0 of a 2D surface are
//! implemented; volumes and cube-copy chains are rejected.

const X: u8 = 0;
const Y: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Swizzle {
    /// `SW_4KB_S`.
    S4k,
    /// `SW_64KB_D`.
    D64k,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MipPlace {
    pub width: u32,
    pub height: u32,
    pub offset: u64,
    /// Origin inside the shared tail block, in elements.
    pub tail: Option<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct Layout {
    equation: &'static [(u8, u8)],
    pub bpe: u32,
    pub block_width: u32,
    pub block_height: u32,
    pub block_bytes: u64,
    pub mips: Vec<MipPlace>,
    pub slices: u32,
    pub total: u64,
    slice_bytes: u64,
}

fn equation(swizzle: Swizzle, bpe: u32) -> Option<&'static [(u8, u8)]> {
    Some(match (swizzle, bpe) {
        (Swizzle::S4k, 16) => &[
            (Y, 0),
            (Y, 1),
            (X, 0),
            (X, 1),
            (Y, 2),
            (X, 2),
            (Y, 3),
            (X, 3),
        ],
        (Swizzle::S4k, 8) => &[
            (X, 0),
            (Y, 0),
            (Y, 1),
            (X, 1),
            (X, 2),
            (Y, 2),
            (X, 3),
            (Y, 3),
            (X, 4),
        ],
        (Swizzle::D64k, 16) => &[
            (X, 0),
            (Y, 0),
            (X, 1),
            (Y, 1),
            (Y, 2),
            (X, 2),
            (Y, 3),
            (X, 3),
            (Y, 4),
            (X, 4),
            (Y, 5),
            (X, 5),
        ],
        (Swizzle::D64k, 8) => &[
            (X, 0),
            (Y, 0),
            (X, 1),
            (X, 2),
            (Y, 1),
            (Y, 2),
            (X, 3),
            (Y, 3),
            (X, 4),
            (Y, 4),
            (X, 5),
            (Y, 5),
            (X, 6),
        ],
        (Swizzle::S4k, 4) => &[
            (X, 0),
            (X, 1),
            (Y, 0),
            (Y, 1),
            (Y, 2),
            (X, 2),
            (Y, 3),
            (X, 3),
            (Y, 4),
            (X, 4),
        ],
        (Swizzle::D64k, 4) => &[
            (X, 0),
            (X, 1),
            (Y, 0),
            (Y, 1),
            (X, 2),
            (Y, 2),
            (Y, 3),
            (X, 3),
            (Y, 4),
            (X, 4),
            (Y, 5),
            (X, 5),
            (Y, 6),
            (X, 6),
        ],
        (Swizzle::S4k, 2) => &[
            (X, 0),
            (X, 1),
            (X, 2),
            (Y, 0),
            (Y, 1),
            (Y, 2),
            (X, 3),
            (Y, 3),
            (X, 4),
            (Y, 4),
            (X, 5),
        ],
        (Swizzle::D64k, 2) => &[
            (X, 0),
            (X, 1),
            (X, 2),
            (Y, 0),
            (Y, 1),
            (Y, 2),
            (X, 3),
            (Y, 3),
            (X, 4),
            (Y, 4),
            (X, 5),
            (Y, 5),
            (X, 6),
            (Y, 6),
            (X, 7),
        ],
        (Swizzle::S4k, 1) => &[
            (X, 0),
            (X, 1),
            (X, 2),
            (X, 3),
            (Y, 0),
            (Y, 1),
            (Y, 2),
            (Y, 3),
            (Y, 4),
            (X, 4),
            (Y, 5),
            (X, 5),
        ],
        (Swizzle::D64k, 1) => &[
            (X, 0),
            (X, 1),
            (X, 2),
            (Y, 1),
            (Y, 0),
            (Y, 2),
            (X, 3),
            (Y, 3),
            (Y, 4),
            (X, 4),
            (Y, 5),
            (X, 5),
            (Y, 6),
            (X, 6),
            (Y, 7),
            (X, 7),
        ],
        _ => return None,
    })
}

impl Layout {
    /// `width` and `height` are in elements (BC blocks for a block format).
    pub fn new(swizzle: Swizzle, width: u32, height: u32, mips: u32, bpe: u32) -> Option<Self> {
        if width == 0 || height == 0 || mips == 0 || mips > 32 {
            return None;
        }
        let equation = equation(swizzle, bpe)?;
        let nx = equation.iter().filter(|(axis, _)| *axis == X).count() as u32;
        let block_width = 1u32 << nx;
        let block_height = 1u32 << (equation.len() as u32 - nx);
        let block_bytes = u64::from(block_width) * u64::from(block_height) * u64::from(bpe);
        let log2 = 63 - block_bytes.leading_zeros();
        let max_tail = if log2 <= 11 {
            1 + (1 << (log2 - 9))
        } else {
            log2 - 4
        };
        let tail_width = block_width / 2;
        let tail_height = block_height;
        let mip_count = mips.max(1);
        let dims: Vec<(u32, u32)> = (0..mip_count)
            .map(|mip| ((width >> mip).max(1), (height >> mip).max(1)))
            .collect();
        let first = if mip_count == 1 {
            1
        } else {
            dims.iter()
                .enumerate()
                .position(|(index, &(w, h))| {
                    w <= tail_width && h <= tail_height && mip_count - index as u32 <= max_tail
                })
                .unwrap_or(mip_count as usize)
        };
        let mut places: Vec<MipPlace> = dims
            .iter()
            .map(|&(width, height)| MipPlace {
                width,
                height,
                offset: 0,
                tail: None,
            })
            .collect();
        let mut offset = if first < mip_count as usize {
            block_bytes
        } else {
            0
        };
        for index in (0..first).rev() {
            let (w, h) = dims[index];
            places[index].offset = offset;
            offset += u64::from(w.div_ceil(block_width) * block_width)
                * u64::from(h.div_ceil(block_height) * block_height)
                * u64::from(bpe);
        }
        let tail_unit = match bpe {
            16 => (4, 4),
            8 => (8, 4),
            4 => (8, 8),
            2 => (16, 8),
            _ => (16, 16),
        };
        for (index, place) in places.iter_mut().enumerate().skip(first) {
            let m = max_tail - 1 - (index - first) as u32;
            let tail_offset: u32 = if m > 6 { 16 << m } else { m << 8 };
            let mut x = 0u32;
            let mut y = 0u32;
            for bit in 0..6 {
                x |= ((tail_offset >> (9 + 2 * bit)) & 1) << bit;
                y |= ((tail_offset >> (8 + 2 * bit)) & 1) << bit;
            }
            place.offset = 0;
            place.tail = Some((x * tail_unit.0, y * tail_unit.1));
        }
        Some(Self {
            equation,
            bpe,
            block_width,
            block_height,
            block_bytes,
            mips: places,
            slices: 1,
            total: offset,
            slice_bytes: offset,
        })
    }

    /// Repeats the layout for `slices` array elements; slice 0 follows all
    /// lower-resolution levels of every slice.
    pub fn with_slices(mut self, slices: u32) -> Self {
        let slices = slices.max(1);
        self.total = self.slice_bytes * u64::from(slices);
        self.slices = slices;
        self
    }

    fn level_bytes(&self, mip: usize) -> u64 {
        let place = &self.mips[mip];
        match place.tail {
            Some(_) => self.block_bytes,
            None => {
                u64::from(place.width.div_ceil(self.block_width) * self.block_width)
                    * u64::from(place.height.div_ceil(self.block_height) * self.block_height)
                    * u64::from(self.bpe)
            }
        }
    }

    fn level_start(&self, mip: usize, slice: u32) -> u64 {
        let base = match self.mips[mip].tail {
            Some(_) => 0,
            None => self.mips[mip].offset * u64::from(self.slices),
        };
        base + u64::from(slice) * self.level_bytes(mip)
    }

    fn in_block(&self, x: u32, y: u32, z: u32) -> u64 {
        let mut address = 0u64;
        for (bit, &(axis, coordinate_bit)) in self.equation.iter().enumerate() {
            let value = match axis {
                X => x,
                Y => y,
                _ => z,
            };
            address |= u64::from((value >> coordinate_bit) & 1) << bit;
        }
        address
    }

    /// Byte range `[start, end)` of slice 0 of `mip`.
    pub fn mip_span(&self, mip: usize) -> Option<(u64, u64)> {
        if mip >= self.mips.len() {
            return None;
        }
        let start = self.level_start(mip, 0);
        Some((start, start + self.level_bytes(mip)))
    }

    pub fn address(&self, mip: usize, slice: u32, x: u32, y: u32) -> Option<u64> {
        let place = self.mips.get(mip)?;
        if slice >= self.slices {
            return None;
        }
        let base = self.level_start(mip, slice);
        match place.tail {
            Some((origin_x, origin_y)) => {
                Some(base + self.in_block(x + origin_x, y + origin_y, 0) * u64::from(self.bpe))
            }
            None => {
                let pitch = u64::from(place.width.div_ceil(self.block_width));
                let block =
                    u64::from(y / self.block_height) * pitch + u64::from(x / self.block_width);
                Some(
                    base + block * self.block_bytes
                        + self.in_block(x % self.block_width, y % self.block_height, 0)
                            * u64::from(self.bpe),
                )
            }
        }
    }

    /// Untiles slice 0 of `mip` into row-major elements. Missing source bytes
    /// stay zero.
    pub fn untile(&self, source: &[u8], mip: usize) -> Option<Vec<u8>> {
        let place = self.mips.get(mip)?;
        let bpe = self.bpe as usize;
        let mut out = vec![0u8; usize::try_from(place.width * place.height).ok()? * bpe];
        for y in 0..place.height {
            for x in 0..place.width {
                let source_offset = self.address(mip, 0, x, y)? as usize;
                let destination =
                    (u64::from(y) * u64::from(place.width) + u64::from(x)) as usize * bpe;
                if let Some(bytes) = source.get(source_offset..source_offset + bpe) {
                    out[destination..destination + bpe].copy_from_slice(bytes);
                }
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_sizes_match_store_spacing() {
        assert_eq!(Layout::new(Swizzle::S4k, 16, 16, 6, 8).unwrap().total, 4096);
        let layout = Layout::new(Swizzle::S4k, 32, 32, 7, 8).unwrap();
        assert_eq!(layout.total, 12288);
        assert_eq!(layout.mips[0].offset, 4096);
        assert_eq!(layout.mips[1].tail, Some((16, 0)));
    }

    #[test]
    fn single_mip_starts_at_offset_zero() {
        let layout = Layout::new(Swizzle::S4k, 16, 8, 1, 4).unwrap();
        assert_eq!((layout.mips[0].offset, layout.mips[0].tail), (0, None));
        assert_eq!(layout.address(0, 0, 1, 0), Some(4));
        assert_eq!(layout.address(0, 0, 0, 1), Some(16));
    }

    #[test]
    fn round_trip_places_each_element() {
        let layout = Layout::new(Swizzle::S4k, 8, 8, 1, 4).unwrap();
        let mut tiled = vec![0u8; layout.total as usize];
        for y in 0..8 {
            for x in 0..8 {
                let at = layout.address(0, 0, x, y).unwrap() as usize;
                tiled[at..at + 4].copy_from_slice(&[x as u8, y as u8, 0, 255]);
            }
        }
        let linear = layout.untile(&tiled, 0).unwrap();
        assert_eq!(&linear[(3 * 8 + 5) * 4..][..4], &[5, 3, 0, 255]);
    }

    #[test]
    fn rejects_unknown_element_sizes() {
        assert!(Layout::new(Swizzle::S4k, 16, 16, 1, 3).is_none());
        assert!(Layout::new(Swizzle::S4k, 0, 16, 1, 4).is_none());
    }
}
