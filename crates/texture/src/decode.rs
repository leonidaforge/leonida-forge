//! Block and linear pixel decoders.

use super::{Codec, Error, MAX_EDGE, MAX_PIXELS};

pub(crate) fn decode(codec: Codec, data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
        return Err(Error::Invalid(format!(
            "the decoded dimensions are {width} × {height}"
        )));
    }
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(Error::Invalid(format!(
            "{width} × {height} exceeds the {MAX_PIXELS}-pixel limit"
        )));
    }
    match codec {
        Codec::Rgba8 => linear(data, width, height),
        Codec::Bc1 => bc1(data, width, height),
        Codec::Bc4 => bc4(data, width, height),
        Codec::Bc5 => bc5(data, width, height),
    }
}

fn needed(codec: Codec, width: u32, height: u32) -> u64 {
    codec.level_len(width, height)
}

fn check(data: &[u8], need: u64) -> Result<(), Error> {
    if (data.len() as u64) < need {
        return Err(Error::Invalid(format!(
            "the level needs {need} bytes but the range holds {}",
            data.len()
        )));
    }
    Ok(())
}

fn linear(data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let need = needed(Codec::Rgba8, width, height);
    check(data, need)?;
    let len = usize::try_from(need).map_err(|_| Error::Invalid("the size overflows".into()))?;
    Ok(data[..len].to_vec())
}

fn bc1(data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let need = needed(Codec::Bc1, width, height);
    check(data, need)?;
    let bw = width.div_ceil(4) as usize;
    let bh = height.div_ceil(4) as usize;
    let mut out = vec![0u8; width as usize * height as usize * 4];
    for by in 0..bh {
        for bx in 0..bw {
            let at = (by * bw + bx) * 8;
            let block = &data[at..at + 8];
            let pixels = bc1_block(block);
            for (i, pixel) in pixels.iter().enumerate() {
                let x = bx * 4 + i % 4;
                let y = by * 4 + i / 4;
                if x < width as usize && y < height as usize {
                    let o = (y * width as usize + x) * 4;
                    out[o..o + 4].copy_from_slice(pixel);
                }
            }
        }
    }
    Ok(out)
}

fn bc1_block(block: &[u8]) -> [[u8; 4]; 16] {
    let c0 = u16::from(block[0]) | u16::from(block[1]) << 8;
    let c1 = u16::from(block[2]) | u16::from(block[3]) << 8;
    let p0 = rgb565(c0);
    let p1 = rgb565(c1);
    let (palette, transparent): ([[u8; 4]; 4], [bool; 4]) = if c0 > c1 {
        (
            [p0, p1, mix(p0, p1, 2, 1, 3), mix(p0, p1, 1, 2, 3)],
            [false; 4],
        )
    } else {
        (
            [p0, p1, mix(p0, p1, 1, 1, 2), [0, 0, 0, 255]],
            [false, false, false, true],
        )
    };
    let indices = u32::from(block[4])
        | u32::from(block[5]) << 8
        | u32::from(block[6]) << 16
        | u32::from(block[7]) << 24;
    let mut out = [[0u8; 4]; 16];
    for (i, pixel) in out.iter_mut().enumerate() {
        let index = ((indices >> (2 * i)) & 0x3) as usize;
        *pixel = palette[index];
        if transparent[index] {
            pixel[3] = 0;
        }
    }
    out
}

fn rgb565(value: u16) -> [u8; 4] {
    let r = (value >> 11) & 0x1F;
    let g = (value >> 5) & 0x3F;
    let b = value & 0x1F;
    [
        ((r << 3) | (r >> 2)) as u8,
        ((g << 2) | (g >> 4)) as u8,
        ((b << 3) | (b >> 2)) as u8,
        255,
    ]
}

fn mix(a: [u8; 4], b: [u8; 4], a_weight: u16, b_weight: u16, divisor: u16) -> [u8; 4] {
    [
        ((u16::from(a[0]) * a_weight + u16::from(b[0]) * b_weight) / divisor) as u8,
        ((u16::from(a[1]) * a_weight + u16::from(b[1]) * b_weight) / divisor) as u8,
        ((u16::from(a[2]) * a_weight + u16::from(b[2]) * b_weight) / divisor) as u8,
        255,
    ]
}

fn bc4(data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let need = needed(Codec::Bc4, width, height);
    check(data, need)?;
    let bw = width.div_ceil(4) as usize;
    let bh = height.div_ceil(4) as usize;
    let mut out = vec![0u8; width as usize * height as usize * 4];
    for by in 0..bh {
        for bx in 0..bw {
            let at = (by * bw + bx) * 8;
            let values = bc4_block(&data[at..at + 8]);
            for (i, value) in values.iter().enumerate() {
                let x = bx * 4 + i % 4;
                let y = by * 4 + i / 4;
                if x < width as usize && y < height as usize {
                    let o = (y * width as usize + x) * 4;
                    out[o] = *value;
                    out[o + 1] = *value;
                    out[o + 2] = *value;
                    out[o + 3] = 255;
                }
            }
        }
    }
    Ok(out)
}

fn bc4_block(block: &[u8]) -> [u8; 16] {
    let a0 = block[0];
    let a1 = block[1];
    let palette = if a0 > a1 {
        let mut palette = [0u8; 8];
        palette[0] = a0;
        palette[1] = a1;
        for i in 1..7u16 {
            palette[i as usize + 1] = (((7 - i) * u16::from(a0) + i * u16::from(a1)) / 7) as u8;
        }
        palette
    } else {
        [
            a0,
            a1,
            ((4 * u16::from(a0) + u16::from(a1)) / 5) as u8,
            ((3 * u16::from(a0) + 2 * u16::from(a1)) / 5) as u8,
            ((2 * u16::from(a0) + 3 * u16::from(a1)) / 5) as u8,
            ((u16::from(a0) + 4 * u16::from(a1)) / 5) as u8,
            0,
            255,
        ]
    };
    let mut bits = 0u64;
    for (i, byte) in block[2..8].iter().enumerate() {
        bits |= u64::from(*byte) << (8 * i);
    }
    let mut out = [0u8; 16];
    for (i, value) in out.iter_mut().enumerate() {
        *value = palette[((bits >> (3 * i)) & 0x7) as usize];
    }
    out
}

fn bc5(data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let need = needed(Codec::Bc5, width, height);
    check(data, need)?;
    let bw = width.div_ceil(4) as usize;
    let bh = height.div_ceil(4) as usize;
    let mut out = vec![0u8; width as usize * height as usize * 4];
    for by in 0..bh {
        for bx in 0..bw {
            let at = (by * bw + bx) * 16;
            let x_values = bc4_block(&data[at..at + 8]);
            let y_values = bc4_block(&data[at + 8..at + 16]);
            for i in 0..16 {
                let x = bx * 4 + i % 4;
                let y = by * 4 + i / 4;
                if x < width as usize && y < height as usize {
                    let o = (y * width as usize + x) * 4;
                    out[o] = x_values[i];
                    out[o + 1] = y_values[i];
                    out[o + 2] = 255;
                    out[o + 3] = 255;
                }
            }
        }
    }
    Ok(out)
}
