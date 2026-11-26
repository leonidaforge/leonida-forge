//! Image decoding for previews and the image viewer.

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use gpui::RenderImage;
use image::{DynamicImage, Frame, ImageFormat, ImageReader, RgbaImage};

use super::shell::Bitmap;

pub struct DecodedImage {
    pub image: Arc<RenderImage>,
    /// Dimensions of the source image, not of the decoded data.
    pub width: u32,
    pub height: u32,
}

/// Decodes the image at full resolution. The file may be inside an archive.
pub fn load(path: &Path, access: &super::Access) -> Result<DecodedImage, String> {
    let bytes = super::read_with(path, access).map_err(|err| err.to_string())?;
    let image = reader(&bytes)?.decode().map_err(|err| err.to_string())?;
    let (width, height) = (image.width(), image.height());
    Ok(DecodedImage {
        image: rgba_to_render_image(image.into_rgba8()),
        width,
        height,
    })
}

/// Decodes a thumbnail that fits in `max_side` × `max_side`.
///
/// JPEGs are decoded at a reduced scale, so large photos are never decoded in
/// full. PNG has no reduced decoding, so it is decoded fully and then scaled.
pub fn load_thumbnail(
    path: &Path,
    max_side: u32,
    access: &super::Access,
) -> Result<DecodedImage, String> {
    let bytes = super::read_with(path, access).map_err(|err| err.to_string())?;
    let (width, height) = reader(&bytes)?
        .into_dimensions()
        .map_err(|err| err.to_string())?;
    let image = match reader(&bytes)?.format() {
        Some(ImageFormat::Jpeg) => decode_scaled_jpeg(&bytes, max_side)?,
        _ => reader(&bytes)?.decode().map_err(|err| err.to_string())?,
    };
    let thumbnail = if image.width() > max_side || image.height() > max_side {
        image.thumbnail(max_side, max_side)
    } else {
        image
    };
    Ok(DecodedImage {
        image: rgba_to_render_image(thumbnail.into_rgba8()),
        width,
        height,
    })
}

/// Reads only the image header of a file on disk.
pub fn dimensions(path: &Path) -> Option<(u32, u32)> {
    ImageReader::open(path)
        .ok()?
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()
}

/// Shell bitmaps are already in the BGRA layout GPUI expects.
pub fn bitmap_to_render_image(bitmap: Bitmap) -> Arc<RenderImage> {
    let buffer = RgbaImage::from_raw(bitmap.width, bitmap.height, bitmap.pixels)
        .expect("shell bitmaps hold width * height * 4 bytes");
    Arc::new(RenderImage::new([Frame::new(buffer)]))
}

fn reader(bytes: &[u8]) -> Result<ImageReader<Cursor<&[u8]>>, String> {
    ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|err| err.to_string())
}

fn decode_scaled_jpeg(bytes: &[u8], max_side: u32) -> Result<DynamicImage, String> {
    let mut decoder = jpeg_decoder::Decoder::new(bytes);
    let side = u16::try_from(max_side).unwrap_or(u16::MAX);
    decoder.scale(side, side).map_err(|err| err.to_string())?;
    let pixels = decoder.decode().map_err(|err| err.to_string())?;
    let info = decoder.info().ok_or("missing JPEG header")?;
    let (width, height) = (u32::from(info.width), u32::from(info.height));
    let image = match info.pixel_format {
        jpeg_decoder::PixelFormat::RGB24 => {
            image::RgbImage::from_raw(width, height, pixels).map(DynamicImage::ImageRgb8)
        }
        jpeg_decoder::PixelFormat::L8 => {
            image::GrayImage::from_raw(width, height, pixels).map(DynamicImage::ImageLuma8)
        }
        // CMYK and 16-bit JPEGs are rare; let the regular decoder handle them.
        _ => return reader(bytes)?.decode().map_err(|err| err.to_string()),
    };
    image.ok_or_else(|| "JPEG data does not match its header".to_string())
}

/// Builds a GPUI image from RGBA bytes. GPUI expects BGRA, so red and blue
/// are swapped here. The length must be `width * height * 4`.
pub fn render_rgba(rgba: Vec<u8>, width: u32, height: u32) -> Result<Arc<RenderImage>, String> {
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| "the image dimensions overflow".to_string())?;
    if rgba.len() != expected {
        return Err(format!(
            "the image holds {} bytes, not the {expected} its dimensions need",
            rgba.len()
        ));
    }
    let mut image = RgbaImage::from_raw(width, height, rgba)
        .ok_or_else(|| "the image dimensions do not match its bytes".to_string())?;
    for pixel in image.pixels_mut() {
        pixel.0.swap(0, 2);
    }
    Ok(Arc::new(RenderImage::new([Frame::new(image)])))
}

/// GPUI expects BGRA pixels.
fn rgba_to_render_image(rgba: RgbaImage) -> Arc<RenderImage> {
    let (width, height) = rgba.dimensions();
    render_rgba(rgba.into_raw(), width, height)
        .expect("an RgbaImage holds width * height * 4 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, Rgba};

    #[test]
    fn png_thumbnail_keeps_source_dimensions_and_aspect() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("wide.png");
        ImageBuffer::from_pixel(400, 100, Rgba([255u8, 0, 0, 255]))
            .save(&path)
            .unwrap();

        let thumbnail = load_thumbnail(&path, 64, &super::super::Access::none()).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (400, 100));
        let size = thumbnail.image.size(0);
        assert_eq!((size.width.0, size.height.0), (64, 16));
        // GPUI expects BGRA, so red is stored third.
        assert_eq!(
            &thumbnail.image.as_bytes(0).unwrap()[..4],
            &[0, 0, 255, 255]
        );
    }

    #[test]
    fn jpeg_thumbnail_is_decoded_at_reduced_scale() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("photo.jpg");
        ImageBuffer::from_pixel(1024, 512, Rgb([10u8, 200, 30]))
            .save(&path)
            .unwrap();

        let thumbnail = load_thumbnail(&path, 128, &super::super::Access::none()).unwrap();
        assert_eq!((thumbnail.width, thumbnail.height), (1024, 512));
        let size = thumbnail.image.size(0);
        assert_eq!((size.width.0, size.height.0), (128, 64));
    }

    #[test]
    fn rgba_render_image_swaps_channels_and_checks_length() {
        let image = render_rgba(vec![10, 20, 30, 40], 1, 1).unwrap();
        assert_eq!(&image.as_bytes(0).unwrap()[..4], &[30, 20, 10, 40]);
        assert!(render_rgba(vec![0; 3], 1, 1).is_err());
    }

    #[test]
    fn full_load_and_errors() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("small.png");
        ImageBuffer::from_pixel(3, 2, Rgba([0u8, 0, 0, 255]))
            .save(&path)
            .unwrap();
        let image = load(&path, &super::super::Access::none()).unwrap();
        assert_eq!((image.width, image.height), (3, 2));

        let broken = temp.path().join("broken.png");
        std::fs::write(&broken, b"not a png").unwrap();
        assert!(load_thumbnail(&broken, 64, &super::super::Access::none()).is_err());
        assert!(
            load(
                &temp.path().join("missing.png"),
                &super::super::Access::none()
            )
            .is_err()
        );
    }
}
