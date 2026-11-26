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
    let mut image = vec![0u32; width * height];
    let result = match texture.format {
        TextureFormat::Bc1Unorm | TextureFormat::Bc1UnormSrgb => {
            texture2ddecoder::decode_bc1(&texture.data, width, height, &mut image)
        }
        TextureFormat::Bc3Unorm | TextureFormat::Bc3UnormSrgb => {
            texture2ddecoder::decode_bc3(&texture.data, width, height, &mut image)
        }
        TextureFormat::Bc4Unorm => {
            texture2ddecoder::decode_bc4(&texture.data, width, height, &mut image)
        }
        TextureFormat::Bc5Unorm => {
            texture2ddecoder::decode_bc5(&texture.data, width, height, &mut image)
        }
        TextureFormat::Bc6hUf16 => {
            texture2ddecoder::decode_bc6_unsigned(&texture.data, width, height, &mut image)
        }
        TextureFormat::Bc7Unorm | TextureFormat::Bc7UnormSrgb => {
            texture2ddecoder::decode_bc7(&texture.data, width, height, &mut image)
        }
        other => {
            return Err(Error::Texture(format!(
                "{}: no decoder for {other:?}",
                texture.name
            )));
        }
    };
    result.map_err(|reason| Error::Texture(format!("{}: {reason}", texture.name)))?;
    let mut rgba = Vec::with_capacity(width * height * 4);
    for pixel in image {
        let r = ((pixel >> 16) & 0xFF) as u8;
        let g = ((pixel >> 8) & 0xFF) as u8;
        let mut b = (pixel & 0xFF) as u8;
        let a = ((pixel >> 24) & 0xFF) as u8;
        if texture.format == TextureFormat::Bc5Unorm {
            // BC5 leaves blue at zero; reconstruct the tangent-space z
            // component of the normal map the format usually stores.
            let x = r as f32 / 127.5 - 1.0;
            let y = g as f32 / 127.5 - 1.0;
            let z = (1.0 - x * x - y * y).max(0.0).sqrt();
            b = ((z * 0.5 + 0.5) * 255.0).round().clamp(0.0, 255.0) as u8;
        }
        rgba.extend_from_slice(&[r, g, b, a]);
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
