//! Textures embedded directly in a drawable resource.
//!
//! A drawable's shader points at the same `0x70`-byte texture record a native
//! dictionary uses. The record is not part of a dictionary root, so the
//! allocation extent comes from the next embedded record's graphics start, or
//! from the graphics end. This module parses and reconstructs those records
//! through the shared native record and swizzle code.

use std::sync::atomic::{AtomicBool, Ordering};

use lforge_rage9::dictionary::{self, NameCheck};

use super::dictionary::classify;
use super::{Error, MAX_EDGE, MAX_PIXELS, SourceLevel, TextureInfo, pixel_format, swizzle};

/// One texture record embedded in a drawable resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedTexture {
    pub key: u64,
    pub info: TextureInfo,
    record: dictionary::Record,
}

impl EmbeddedTexture {
    pub fn info(&self) -> &TextureInfo {
        &self.info
    }
}

/// Finds the plausible embedded texture records in a resource. A record is
/// accepted only when its `0x70` shape, graphics pointer, dimensions and key
/// are readable; nothing is guessed from a shader name.
pub fn embedded_textures(system: &[u8], graphics: &[u8]) -> Vec<EmbeddedTexture> {
    let limit = system.len().saturating_sub(dictionary::RECORD_LEN as usize);
    let mut parsed = Vec::new();
    let mut at = 0usize;
    while at <= limit {
        let Some(word) = u16_at(system, at + 0x0E) else {
            break;
        };
        if word == 8
            && let Ok(record) = dictionary::record_at(system, at as u32, parsed.len() as u32, None)
            && record.graphics_at.is_some()
            && record.format_id != 0
            && record.width > 0
            && record.height > 0
            && u32::from(record.width) <= MAX_EDGE
            && u32::from(record.height) <= MAX_EDGE
            && u64::from(record.width) * u64::from(record.height) <= MAX_PIXELS
        {
            parsed.push(record);
            at += dictionary::RECORD_LEN as usize;
            continue;
        }
        at += 8;
    }

    let mut starts: Vec<u64> = parsed
        .iter()
        .filter_map(|record| record.graphics_at.map(u64::from))
        .collect();
    starts.sort_unstable();
    starts.dedup();

    let mut out = Vec::with_capacity(parsed.len());
    for mut record in parsed {
        let Some(graphics_at) = record.graphics_at else {
            continue;
        };
        let Some(key) = embedded_key(system, &record) else {
            continue;
        };
        let start = u64::from(graphics_at);
        let next = starts
            .iter()
            .find(|&&candidate| candidate > start)
            .copied()
            .unwrap_or(graphics.len() as u64);
        let extent = next.saturating_sub(start).min(graphics.len() as u64);
        record.extent = Some(extent);
        let info = info(&record, key, extent);
        out.push(EmbeddedTexture { key, info, record });
    }
    out
}

/// Reconstructs one embedded level without decoding pixels.
pub fn decode_embedded(
    graphics: &[u8],
    texture: &EmbeddedTexture,
    level: u32,
    cancel: &AtomicBool,
) -> Result<SourceLevel, Error> {
    let info = &texture.info;
    if !info.status.is_decodable() {
        return Err(Error::Unsupported(
            info.status
                .reason()
                .unwrap_or("the embedded texture cannot be decoded")
                .to_string(),
        ));
    }
    let level_info = info
        .levels
        .iter()
        .find(|candidate| candidate.level == level)
        .ok_or_else(|| {
            Error::Unsupported(format!(
                "embedded texture {} has no established mip level {level}",
                info.index
            ))
        })?;
    let start = info
        .allocation
        .ok_or_else(|| Error::Invalid("the embedded texture has no allocation".into()))?
        .checked_add(level_info.offset)
        .ok_or_else(|| Error::Invalid("the embedded allocation offset overflows".into()))?;
    let end = start
        .checked_add(level_info.encoded_len)
        .ok_or_else(|| Error::Invalid("the embedded level range overflows".into()))?;
    if end > graphics.len() as u64 {
        return Err(Error::Invalid(format!(
            "embedded level {level} ends at {end:#x}, past the {} byte graphics segment",
            graphics.len()
        )));
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let bytes = graphics[start as usize..end as usize].to_vec();
    let codec = info
        .format
        .codec
        .ok_or_else(|| Error::Unsupported("the pixel format is not supported".into()))?;
    let swizzled = info.tile_mode != 0;
    let data = if swizzled {
        swizzle::deswizzle(
            swizzle::Swizzle::S4k,
            &bytes,
            level_info.width,
            level_info.height,
            codec,
        )?
    } else {
        bytes
    };
    Ok(SourceLevel {
        width: level_info.width,
        height: level_info.height,
        level,
        format: info.format,
        data,
        swizzled,
    })
}

fn info(record: &dictionary::Record, key: u64, extent: u64) -> TextureInfo {
    let format = pixel_format(record.format_id);
    let level0_len = format
        .codec
        .map(|codec| codec.level_len(u32::from(record.width), u32::from(record.height)));
    let (status, levels) = classify(record, format, extent, level0_len);
    let name = record
        .name
        .clone()
        .filter(|_| record.name_check == NameCheck::Matched)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("Embedded texture {}", record.index));
    TextureInfo {
        index: record.index,
        name,
        key,
        container: "Embedded drawable texture",
        width: u32::from(record.width),
        height: u32::from(record.height),
        format,
        format_basis: "embedded drawable record; same 16-byte descriptor and native allocation rules",
        flags: 0,
        kind: 2,
        tile_mode: record.swizzle,
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

fn embedded_key(system: &[u8], record: &dictionary::Record) -> Option<u64> {
    let at = record.name_at? as usize;
    Some(u64::from_le_bytes(
        system.get(at + 8..at + 16)?.try_into().ok()?,
    ))
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}
