//! Linear and block pixel decoders.

use super::{Codec, Error, MAX_EDGE, MAX_PIXELS};

pub(crate) fn decode(codec: Codec, data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
        return Err(Error::Invalid(format!(
            "the decoded dimensions are {width} x {height}"
        )));
    }
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(Error::Invalid(format!(
            "{width} x {height} exceeds the {MAX_PIXELS}-pixel limit"
        )));
    }
    match codec {
        Codec::Rgba8 => linear_rgba8(data, width, height),
        Codec::R16Float => r16_float(data, width, height),
        Codec::Bc1 => compressed(data, width, height, 8, bc1_block),
        Codec::Bc3 => compressed(data, width, height, 16, bc3_block),
        Codec::Bc4 => compressed_r8(data, width, height, 8, bc4_block),
        Codec::Bc5 => compressed_rg8(data, width, height, 16, bc5_block),
        Codec::Bc7 => compressed(data, width, height, 16, bc7_block),
    }
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

fn linear_rgba8(data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let need = Codec::Rgba8.level_len(width, height);
    check(data, need)?;
    let len = usize::try_from(need).map_err(|_| Error::Invalid("the size overflows".into()))?;
    Ok(data[..len].to_vec())
}

fn r16_float(data: &[u8], width: u32, height: u32) -> Result<Vec<u8>, Error> {
    let need = Codec::R16Float.level_len(width, height);
    check(data, need)?;
    let pixels = width as usize * height as usize;
    let mut out = vec![0u8; pixels * 4];
    for i in 0..pixels {
        let bits = u16::from(data[i * 2]) | u16::from(data[i * 2 + 1]) << 8;
        let value = half::f16::from_bits(bits).to_f32();
        let value = if value.is_finite() {
            (value.clamp(0., 1.) * 255.).round() as u8
        } else {
            0
        };
        out[i * 4] = value;
        out[i * 4 + 1] = value;
        out[i * 4 + 2] = value;
        out[i * 4 + 3] = 255;
    }
    Ok(out)
}

fn compressed(
    data: &[u8],
    width: u32,
    height: u32,
    block_len: u32,
    decode: fn(&[u8]) -> [u8; 64],
) -> Result<Vec<u8>, Error> {
    let need = block_len_need(width, height, block_len);
    check(data, need)?;
    let bw = width.div_ceil(4) as usize;
    let bh = height.div_ceil(4) as usize;
    let mut out = vec![0u8; width as usize * height as usize * 4];
    let stride = block_len as usize;
    for by in 0..bh {
        for bx in 0..bw {
            let at = (by * bw + bx) * stride;
            let block = decode(&data[at..at + stride]);
            for i in 0..16 {
                let x = bx * 4 + i % 4;
                let y = by * 4 + i / 4;
                if x < width as usize && y < height as usize {
                    let o = (y * width as usize + x) * 4;
                    out[o..o + 4].copy_from_slice(&block[i * 4..i * 4 + 4]);
                }
            }
        }
    }
    Ok(out)
}

fn compressed_r8(
    data: &[u8],
    width: u32,
    height: u32,
    block_len: u32,
    decode: fn(&[u8]) -> [u8; 16],
) -> Result<Vec<u8>, Error> {
    let need = block_len_need(width, height, block_len);
    check(data, need)?;
    let bw = width.div_ceil(4) as usize;
    let bh = height.div_ceil(4) as usize;
    let mut out = vec![0u8; width as usize * height as usize * 4];
    let stride = block_len as usize;
    for by in 0..bh {
        for bx in 0..bw {
            let at = (by * bw + bx) * stride;
            let block = decode(&data[at..at + stride]);
            for (i, value) in block.iter().enumerate() {
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

fn compressed_rg8(
    data: &[u8],
    width: u32,
    height: u32,
    block_len: u32,
    decode: fn(&[u8]) -> [u8; 32],
) -> Result<Vec<u8>, Error> {
    let need = block_len_need(width, height, block_len);
    check(data, need)?;
    let bw = width.div_ceil(4) as usize;
    let bh = height.div_ceil(4) as usize;
    let mut out = vec![0u8; width as usize * height as usize * 4];
    let stride = block_len as usize;
    for by in 0..bh {
        for bx in 0..bw {
            let at = (by * bw + bx) * stride;
            let block = decode(&data[at..at + stride]);
            for i in 0..16 {
                let x = bx * 4 + i % 4;
                let y = by * 4 + i / 4;
                if x < width as usize && y < height as usize {
                    let o = (y * width as usize + x) * 4;
                    out[o] = block[i * 2];
                    out[o + 1] = block[i * 2 + 1];
                    out[o + 2] = 255;
                    out[o + 3] = 255;
                }
            }
        }
    }
    Ok(out)
}

fn block_len_need(width: u32, height: u32, block_len: u32) -> u64 {
    width.div_ceil(4) as u64 * height.div_ceil(4) as u64 * u64::from(block_len)
}

fn bc1_block(block: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    bcdec_rs::bc1(block, &mut out, 16);
    out
}

fn bc3_block(block: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    bcdec_rs::bc3(block, &mut out, 16);
    out
}

fn bc7_block(block: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    bcdec_rs::bc7(block, &mut out, 16);
    out
}

fn bc4_block(block: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    bcdec_rs::bc4(block, &mut out, 4, false);
    out
}

fn bc5_block(block: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    bcdec_rs::bc5(block, &mut out, 8, false);
    out
}
