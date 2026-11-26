//! GPU texture creation, including a CPU fallback for block-compressed data
//! when the adapter cannot sample the format directly.

use lforge_scene::{Texture, TextureFormat};
use wgpu::util::DeviceExt;

use crate::Error;

pub(crate) struct GpuTexture {
    pub(crate) view: wgpu::TextureView,
}

/// Whether the adapter can sample the block-compressed format directly.
fn compressed_supported(format: TextureFormat, features: wgpu::Features) -> bool {
    if !format.is_compressed() {
        return true;
    }
    features.contains(wgpu::Features::TEXTURE_COMPRESSION_BC)
}

pub(crate) fn upload(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    texture: &Texture,
) -> Result<GpuTexture, Error> {
    texture
        .validate()
        .map_err(|reason| Error::Texture(format!("{}: {reason}", texture.name)))?;
    if compressed_supported(texture.format, device.features()) {
        upload_compressed(device, queue, texture)
    } else {
        upload_decoded(device, queue, texture)
    }
}

fn wgpu_format(format: TextureFormat) -> wgpu::TextureFormat {
    match format {
        TextureFormat::Rgba8Unorm => wgpu::TextureFormat::Rgba8Unorm,
        TextureFormat::Rgba8UnormSrgb => wgpu::TextureFormat::Rgba8UnormSrgb,
        TextureFormat::Bgra8Unorm => wgpu::TextureFormat::Bgra8Unorm,
        TextureFormat::Bgra8UnormSrgb => wgpu::TextureFormat::Bgra8UnormSrgb,
        TextureFormat::R8Unorm => wgpu::TextureFormat::R8Unorm,
        TextureFormat::Rg8Unorm => wgpu::TextureFormat::Rg8Unorm,
        TextureFormat::R16Unorm => wgpu::TextureFormat::R16Unorm,
        TextureFormat::Rgba16Unorm => wgpu::TextureFormat::Rgba16Unorm,
        TextureFormat::R16Float => wgpu::TextureFormat::R16Float,
        TextureFormat::Rgba16Float => wgpu::TextureFormat::Rgba16Float,
        TextureFormat::R32Float => wgpu::TextureFormat::R32Float,
        TextureFormat::Rgb10a2Unorm => wgpu::TextureFormat::Rgb10a2Unorm,
        TextureFormat::Bc1Unorm => wgpu::TextureFormat::Bc1RgbaUnorm,
        TextureFormat::Bc1UnormSrgb => wgpu::TextureFormat::Bc1RgbaUnormSrgb,
        TextureFormat::Bc3Unorm => wgpu::TextureFormat::Bc3RgbaUnorm,
        TextureFormat::Bc3UnormSrgb => wgpu::TextureFormat::Bc3RgbaUnormSrgb,
        TextureFormat::Bc4Unorm => wgpu::TextureFormat::Bc4RUnorm,
        TextureFormat::Bc5Unorm => wgpu::TextureFormat::Bc5RgUnorm,
        TextureFormat::Bc6hUf16 => wgpu::TextureFormat::Bc6hRgbUfloat,
        TextureFormat::Bc7Unorm => wgpu::TextureFormat::Bc7RgbaUnorm,
        TextureFormat::Bc7UnormSrgb => wgpu::TextureFormat::Bc7RgbaUnormSrgb,
    }
}

fn create_texture(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    label: &str,
    width: u32,
    height: u32,
    format: wgpu::TextureFormat,
    data: &[u8],
) -> GpuTexture {
    let texture = device.create_texture_with_data(
        queue,
        &wgpu::TextureDescriptor {
            label: Some(label),
            size: wgpu::Extent3d {
                width,
                height,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        },
        wgpu::util::TextureDataOrder::LayerMajor,
        data,
    );
    GpuTexture {
        view: texture.create_view(&Default::default()),
    }
}

fn upload_compressed(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    texture: &Texture,
) -> Result<GpuTexture, Error> {
    let format = wgpu_format(texture.format);
    Ok(create_texture(
        device,
        queue,
        &texture.name,
        texture.width,
        texture.height,
        format,
        &texture.data,
    ))
}

/// Expands block-compressed data to RGBA8 for adapters without BC support.
fn decode_rgba8(texture: &Texture) -> Result<Vec<u8>, Error> {
    let (width, height) = (texture.width as usize, texture.height as usize);
    if width == 0 || height == 0 || width > 16384 || height > 16384 {
        return Err(Error::Texture(format!(
            "{}: unsupported decode size {width}x{height}",
            texture.name
        )));
    }
    let rgba = match texture.format {
        TextureFormat::Bc1Unorm | TextureFormat::Bc1UnormSrgb => {
            decode_blocks(texture, 8, Channels::Rgba, |block, out| {
                bcdec_rs::bc1(block, out, 16)
            })?
        }
        TextureFormat::Bc3Unorm | TextureFormat::Bc3UnormSrgb => {
            decode_blocks(texture, 16, Channels::Rgba, |block, out| {
                bcdec_rs::bc3(block, out, 16)
            })?
        }
        TextureFormat::Bc4Unorm => decode_blocks(texture, 8, Channels::Red, |block, out| {
            bcdec_rs::bc4(block, out, 4, false)
        })?,
        TextureFormat::Bc5Unorm => decode_blocks(texture, 16, Channels::RedGreen, |block, out| {
            bcdec_rs::bc5(block, out, 8, false)
        })?,
        TextureFormat::Bc6hUf16 => decode_bc6h(texture)?,
        TextureFormat::Bc7Unorm | TextureFormat::Bc7UnormSrgb => {
            decode_blocks(texture, 16, Channels::Rgba, |block, out| {
                bcdec_rs::bc7(block, out, 16)
            })?
        }
        other => {
            return Err(Error::Texture(format!(
                "{}: no decoder for {other:?}",
                texture.name
            )));
        }
    };
    Ok(rgba)
}

#[derive(Clone, Copy)]
enum Channels {
    Red,
    RedGreen,
    Rgba,
}

impl Channels {
    fn byte_len(self) -> usize {
        match self {
            Channels::Red => 1,
            Channels::RedGreen => 2,
            Channels::Rgba => 4,
        }
    }
}

fn decode_blocks(
    texture: &Texture,
    block_len: usize,
    channels: Channels,
    decode: impl Fn(&[u8], &mut [u8]),
) -> Result<Vec<u8>, Error> {
    let width = texture.width as usize;
    let height = texture.height as usize;
    let blocks_x = width.div_ceil(4);
    let blocks_y = height.div_ceil(4);
    let need = blocks_x * blocks_y * block_len;
    if texture.data.len() < need {
        return Err(Error::Texture(format!(
            "{}: the compressed level needs {need} bytes but holds {}",
            texture.name,
            texture.data.len()
        )));
    }
    let mut rgba = vec![0u8; width * height * 4];
    let stride = channels.byte_len();
    let mut block = vec![0u8; 16 * stride];
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let at = (by * blocks_x + bx) * block_len;
            decode(&texture.data[at..at + block_len], &mut block);
            for i in 0..16 {
                let x = bx * 4 + i % 4;
                let y = by * 4 + i / 4;
                if x >= width || y >= height {
                    continue;
                }
                let source = i * stride;
                let target = (y * width + x) * 4;
                match channels {
                    Channels::Rgba => {
                        rgba[target..target + 4].copy_from_slice(&block[source..source + 4]);
                    }
                    Channels::Red => {
                        let value = block[source];
                        rgba[target] = value;
                        rgba[target + 1] = value;
                        rgba[target + 2] = value;
                        rgba[target + 3] = 255;
                    }
                    Channels::RedGreen => {
                        let r = block[source];
                        let g = block[source + 1];
                        // BC5 leaves blue unset; reconstruct the tangent-space
                        // z component of the normal map the format stores.
                        let x = r as f32 / 127.5 - 1.0;
                        let y = g as f32 / 127.5 - 1.0;
                        let z = (1.0 - x * x - y * y).max(0.0).sqrt();
                        rgba[target] = r;
                        rgba[target + 1] = g;
                        rgba[target + 2] =
                            ((z * 0.5 + 0.5) * 255.0).round().clamp(0.0, 255.0) as u8;
                        rgba[target + 3] = 255;
                    }
                }
            }
        }
    }
    Ok(rgba)
}

fn decode_bc6h(texture: &Texture) -> Result<Vec<u8>, Error> {
    let width = texture.width as usize;
    let height = texture.height as usize;
    let blocks_x = width.div_ceil(4);
    let blocks_y = height.div_ceil(4);
    let need = blocks_x * blocks_y * 16;
    if texture.data.len() < need {
        return Err(Error::Texture(format!(
            "{}: the compressed level needs {need} bytes but holds {}",
            texture.name,
            texture.data.len()
        )));
    }
    let mut rgba = vec![0u8; width * height * 4];
    let mut block = [0u16; 16 * 3];
    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let at = (by * blocks_x + bx) * 16;
            bcdec_rs::bc6h_half(&texture.data[at..at + 16], &mut block, 4 * 3, false);
            for i in 0..16 {
                let x = bx * 4 + i % 4;
                let y = by * 4 + i / 4;
                if x >= width || y >= height {
                    continue;
                }
                let target = (y * width + x) * 4;
                for channel in 0..3 {
                    let value = half::f16::from_bits(block[i * 3 + channel]).to_f32();
                    rgba[target + channel] = if value.is_finite() {
                        (value.clamp(0.0, 1.0) * 255.0).round() as u8
                    } else {
                        0
                    };
                }
                rgba[target + 3] = 255;
            }
        }
    }
    Ok(rgba)
}

fn upload_decoded(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    texture: &Texture,
) -> Result<GpuTexture, Error> {
    if !texture.format.is_compressed() {
        let format = wgpu_format(texture.format);
        return Ok(create_texture(
            device,
            queue,
            &texture.name,
            texture.width,
            texture.height,
            format,
            &texture.data,
        ));
    }
    let rgba = decode_rgba8(texture)?;
    let format = if texture.format.is_srgb() {
        wgpu::TextureFormat::Rgba8UnormSrgb
    } else {
        wgpu::TextureFormat::Rgba8Unorm
    };
    Ok(create_texture(
        device,
        queue,
        &texture.name,
        texture.width,
        texture.height,
        format,
        &rgba,
    ))
}
