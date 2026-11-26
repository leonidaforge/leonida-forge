//! Native RAGE texture dictionaries: a system segment with the dictionary
//! grammar and a graphics segment with one allocation per record.

use std::sync::atomic::AtomicBool;

use lforge_binary::{Source, read_at};
use lforge_rage9::dictionary;

use super::{
    Codec, Error, Image, LevelInfo, MAX_EDGE, MAX_PIXELS, Status, TextureInfo, decode, pixel_format,
};

/// A type-5 RAGE resource whose system segment passes the dictionary grammar.
#[derive(Debug, Clone)]
pub struct DictionaryStore {
    graphics: Source,
    graphics_len: u64,
    system_len: u64,
    textures: Vec<TextureInfo>,
}

impl DictionaryStore {
    /// Parses `system_len` bytes of `source` as the system segment and slices
    /// the rest as the graphics segment. No image data is decoded here.
    pub fn open(source: Source, system_len: u64) -> Result<Self, Error> {
        if system_len == 0 || system_len > source.len() {
            return Err(Error::Invalid(format!(
                "the system segment is {system_len} bytes in a {}-byte resource",
                source.len()
            )));
        }
        let system = read_at(&mut source.clone(), 0, system_len as usize)
            .map_err(|err| Error::Invalid(format!("cannot read the system segment: {err}")))?;
        let graphics_len = source.len() - system_len;
        let report = dictionary::parse(&system, graphics_len, &dictionary::Limits::default())
            .map_err(|err| match err {
                dictionary::Error::NotADictionary(step) => Error::NotDictionary(step.describe()),
                dictionary::Error::Invalid(reason) => Error::Invalid(reason),
            })?;
        let graphics = source
            .slice(system_len, graphics_len)
            .map_err(|err| Error::Invalid(format!("cannot slice the graphics segment: {err}")))?;
        let textures = report.records.iter().map(texture_info).collect::<Vec<_>>();
        Ok(Self {
            graphics,
            graphics_len,
            system_len,
            textures,
        })
    }

    pub fn textures(&self) -> &[TextureInfo] {
        &self.textures
    }

    pub fn system_len(&self) -> u64 {
        self.system_len
    }

    pub fn graphics_len(&self) -> u64 {
        self.graphics_len
    }

    /// Decodes one stored level. Only layer zero exists for the sampled
    /// dictionaries.
    pub fn decode(
        &self,
        index: u32,
        level: u32,
        layer: u32,
        cancel: &AtomicBool,
    ) -> Result<Image, Error> {
        if layer != 0 {
            return Err(Error::Invalid(format!(
                "texture {index} has no array layer {layer}"
            )));
        }
        let info = self
            .textures
            .get(index as usize)
            .ok_or_else(|| Error::Invalid(format!("texture {index} does not exist")))?;
        if !info.status.is_decodable() {
            return Err(Error::Unsupported(
                info.status
                    .reason()
                    .unwrap_or("the texture cannot be decoded")
                    .to_string(),
            ));
        }
        let level_info = info
            .levels
            .iter()
            .find(|candidate| candidate.level == level)
            .ok_or_else(|| Error::Invalid(format!("texture {index} has no mip level {level}")))?;
        let at = info
            .allocation
            .ok_or_else(|| Error::Invalid(format!("texture {index} has no allocation")))?
            .checked_add(level_info.offset)
            .ok_or_else(|| Error::Invalid("the allocation offset overflows".into()))?;
        let end = at
            .checked_add(level_info.encoded_len)
            .ok_or_else(|| Error::Invalid("the level range overflows".into()))?;
        if end > self.graphics_len {
            return Err(Error::Invalid(format!(
                "level {level} of texture {index} ends at {end:#x}, past the {:#x}-byte graphics segment",
                self.graphics_len
            )));
        }
        let bytes = read_at(
            &mut self.graphics.clone(),
            at,
            level_info.encoded_len as usize,
        )
        .map_err(|err| Error::Invalid(format!("cannot read texture {index}: {err}")))?;
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let codec = info
            .format
            .codec
            .ok_or_else(|| Error::Unsupported("the pixel format is not supported".into()))?;
        let rgba = decode::decode(codec, &bytes, level_info.width, level_info.height)?;
        Ok(Image {
            width: level_info.width,
            height: level_info.height,
            level,
            rgba,
        })
    }

    pub fn thumbnail(
        &self,
        index: u32,
        max_side: u32,
        cancel: &AtomicBool,
    ) -> Result<Image, Error> {
        Ok(self.decode(index, 0, 0, cancel)?.thumbnail(max_side))
    }
}

fn texture_info(record: &dictionary::Record) -> TextureInfo {
    let format = pixel_format(record.format_id);
    let level0_len = format
        .codec
        .map(|codec| codec.level_len(u32::from(record.width), u32::from(record.height)));
    let extent = record.extent.unwrap_or(0);
    let (status, levels) = classify(record, format, extent, level0_len);
    let name = record
        .name
        .clone()
        .filter(|_| record.name_check == dictionary::NameCheck::Matched)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("Texture {}", record.index));
    TextureInfo {
        index: record.index,
        name,
        key: record
            .name_hash
            .map(u64::from)
            .unwrap_or(u64::from(record.index)),
        container: "RAGE dictionary",
        width: u32::from(record.width),
        height: u32::from(record.height),
        format,
        flags: 0,
        kind: 2,
        tile_mode: 0,
        array_size: 1,
        mip_field: record.mip_levels.min(255) as u8,
        encoded_len: extent,
        level0_len,
        levels,
        status,
        range_error: None,
        allocation: record.graphics_at.map(u64::from),
    }
}

fn classify(
    record: &dictionary::Record,
    format: super::PixelFormat,
    extent: u64,
    level0_len: Option<u64>,
) -> (Status, Vec<LevelInfo>) {
    let width = u32::from(record.width);
    let height = u32::from(record.height);
    if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
        return (
            Status::Invalid(format!("the record declares {width} x {height}")),
            Vec::new(),
        );
    }
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return (
            Status::Invalid(format!(
                "{width} x {height} exceeds the {MAX_PIXELS}-pixel limit"
            )),
            Vec::new(),
        );
    }
    let Some(codec) = format.codec else {
        return (
            Status::Unsupported(format!(
                "format id {} has no established pixel layout",
                format.id
            )),
            Vec::new(),
        );
    };
    let Some(level0_len) = level0_len else {
        return (
            Status::Invalid("the level size is unknown".into()),
            Vec::new(),
        );
    };
    if record.graphics_at.is_none() {
        return (
            Status::Invalid("the record has no allocation".into()),
            Vec::new(),
        );
    }
    if extent < level0_len {
        return (
            Status::Invalid(format!(
                "the allocation holds {extent} bytes, less than level 0's {level0_len}"
            )),
            Vec::new(),
        );
    }
    let levels = plan_levels(codec, width, height, extent, record.mip_levels);
    if levels.is_empty() {
        return (
            Status::Invalid("no mip level fits the allocation".into()),
            Vec::new(),
        );
    }
    (Status::Decodable, levels)
}

/// Native dictionary mip counts are the low 15 bits of the mip word. A count
/// of one is the common case; larger values are accepted only while each
/// level fits the allocation.
fn plan_levels(
    codec: Codec,
    width: u32,
    height: u32,
    extent: u64,
    mip_levels: u16,
) -> Vec<LevelInfo> {
    let count = u32::from(mip_levels.max(1));
    let mut offset = 0u64;
    let mut levels = Vec::new();
    for level in 0..count {
        let level_width = (width >> level).max(1);
        let level_height = (height >> level).max(1);
        let encoded_len = codec.level_len(level_width, level_height);
        if offset
            .checked_add(encoded_len)
            .is_none_or(|end| end > extent)
        {
            break;
        }
        levels.push(LevelInfo {
            level,
            width: level_width,
            height: level_height,
            encoded_len,
            offset,
        });
        offset += encoded_len;
    }
    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_mip_is_planned_from_the_mip_word() {
        let levels = plan_levels(Codec::Bc7, 1024, 512, 524_288, 1);
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].encoded_len, 524_288);
        assert_eq!(levels[0].offset, 0);
    }

    #[test]
    fn levels_stop_before_the_allocation_ends() {
        // BC1 8 x 8 is 32 bytes; its 4 x 4 mip is 8 bytes. An allocation of
        // 40 bytes holds exactly two levels.
        let levels = plan_levels(Codec::Bc1, 8, 8, 40, 4);
        assert_eq!(levels.len(), 2);
        assert_eq!((levels[1].width, levels[1].height), (4, 4));
        assert_eq!(levels[1].offset, 32);
    }

    #[test]
    fn an_allocation_smaller_than_level_zero_plans_nothing() {
        assert!(plan_levels(Codec::Bc1, 8, 8, 31, 4).is_empty());
    }
}
