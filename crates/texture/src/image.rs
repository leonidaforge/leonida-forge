//! A decoded RGBA image and its thumbnail.

/// One decoded texture level in R, G, B, A byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub width: u32,
    pub height: u32,
    pub level: u32,
    pub rgba: Vec<u8>,
}

impl Image {
    /// Scales the image so neither edge exceeds `max_side`. The average of
    /// each source rectangle is used, so the thumbnail does not alias as
    /// strongly as a nearest-neighbour reduction.
    pub fn thumbnail(&self, max_side: u32) -> Image {
        if max_side == 0 || (self.width <= max_side && self.height <= max_side) {
            return self.clone();
        }
        let scale = f64::from(max_side) / f64::from(self.width.max(self.height));
        let width = ((f64::from(self.width) * scale).round() as u32).max(1);
        let height = ((f64::from(self.height) * scale).round() as u32).max(1);
        let mut rgba = vec![0u8; width as usize * height as usize * 4];
        for y in 0..height {
            let y0 = (u64::from(y) * u64::from(self.height) / u64::from(height)) as u32;
            let y1 = ((u64::from(y + 1) * u64::from(self.height) / u64::from(height)) as u32)
                .max(y0 + 1)
                .min(self.height);
            for x in 0..width {
                let x0 = (u64::from(x) * u64::from(self.width) / u64::from(width)) as u32;
                let x1 = ((u64::from(x + 1) * u64::from(self.width) / u64::from(width)) as u32)
                    .max(x0 + 1)
                    .min(self.width);
                let mut sum = [0u64; 4];
                let mut count = 0u64;
                for sy in y0..y1 {
                    for sx in x0..x1 {
                        let at = (sy as usize * self.width as usize + sx as usize) * 4;
                        for (channel, value) in sum.iter_mut().enumerate() {
                            *value += u64::from(self.rgba[at + channel]);
                        }
                        count += 1;
                    }
                }
                let at = (y as usize * width as usize + x as usize) * 4;
                for (channel, value) in sum.iter().enumerate() {
                    rgba[at + channel] = (value / count.max(1)) as u8;
                }
            }
        }
        Image {
            width,
            height,
            level: self.level,
            rgba,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbnail_keeps_the_aspect_ratio() {
        let image = Image {
            width: 400,
            height: 100,
            level: 0,
            rgba: vec![255; 400 * 100 * 4],
        };
        let thumbnail = image.thumbnail(64);
        assert_eq!((thumbnail.width, thumbnail.height), (64, 16));
        assert_eq!(thumbnail.rgba.len(), 64 * 16 * 4);
    }

    #[test]
    fn thumbnail_averages_source_pixels() {
        let mut rgba = vec![0u8; 4 * 4 * 4];
        for pixel in rgba.as_chunks_mut::<4>().0 {
            pixel.copy_from_slice(&[10, 20, 30, 255]);
        }
        let image = Image {
            width: 4,
            height: 4,
            level: 0,
            rgba,
        };
        let thumbnail = image.thumbnail(2);
        assert_eq!((thumbnail.width, thumbnail.height), (2, 2));
        assert_eq!(&thumbnail.rgba[..4], &[10, 20, 30, 255]);
    }

    #[test]
    fn small_images_are_not_enlarged() {
        let image = Image {
            width: 8,
            height: 4,
            level: 0,
            rgba: vec![0; 8 * 4 * 4],
        };
        let thumbnail = image.thumbnail(64);
        assert_eq!((thumbnail.width, thumbnail.height), (8, 4));
    }
}
