//! Decoding and access for the texture stores the game ships as `.ttpf`.
//!
//! A store is an RDS5 container whose ETPF chunk holds one descriptor per
//! texture. This crate turns a container into texture metadata and decodes the
//! pixels of one requested level. It is independent of the desktop UI: the
//! viewer, a renderer and an exporter can share it.
//!
//! The established chain stops at the decoded bytes of a descriptor. The
//! format ids below are the ones whose bytes form usable images in the sampled
//! stores; every other id is reported as unsupported rather than guessed.

mod cache;
mod decode;
mod dictionary;
mod embedded;
mod format;
mod image;
mod set;
mod swizzle;
#[cfg(test)]
mod tests;

pub use cache::ImageCache;
pub use dictionary::DictionaryStore;
pub use embedded::{EmbeddedTexture, decode_embedded, embedded_textures};
pub use format::{Codec, PixelFormat, pixel_format};
pub use image::Image;
pub use set::StoreSet;

use std::fmt;
use std::io::{self, Read, Seek};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_rage9::rds5::{self, Container, DescriptorRange, Limits};

/// The largest edge a decoded texture may have.
pub const MAX_EDGE: u32 = 16 * 1024;
/// The largest pixel count a decoded texture may have.
pub const MAX_PIXELS: u64 = 64 * 1024 * 1024;
/// The cumulative decoded bytes one texture may produce.
const MAX_TEXTURE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    NotRds5,
    /// The system segment does not have the dictionary grammar.
    NotDictionary(&'static str),
    /// A format, kind or layout that this crate does not decode.
    Unsupported(String),
    /// Bytes that do not satisfy the format or size contract.
    Invalid(String),
    Io(io::Error),
    Cancelled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotRds5 => f.write_str("not an RDS5 texture store"),
            Error::NotDictionary(reason) => f.write_str(reason),
            Error::Unsupported(reason) => f.write_str(reason),
            Error::Invalid(reason) => f.write_str(reason),
            Error::Io(err) => err.fmt(f),
            Error::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<rds5::Error> for Error {
    fn from(err: rds5::Error) -> Self {
        match err {
            rds5::Error::NotRds5 => Error::NotRds5,
            rds5::Error::Cancelled => Error::Cancelled,
            rds5::Error::Io(err) => Error::Io(err),
            rds5::Error::Invalid(reason) => Error::Invalid(reason),
        }
    }
}

/// Whether the bytes start an RDS5 store.
pub fn is_store(head: &[u8]) -> bool {
    rds5::is_rds5(head)
}

/// What can be done with one texture entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Decodable,
    /// A confirmed format whose pixel layout is not established, or a kind
    /// that is not a simple 2D image.
    Unsupported(String),
    /// Metadata or encoded bytes that do not satisfy their own contract.
    Invalid(String),
}

impl Status {
    pub fn is_decodable(&self) -> bool {
        matches!(self, Status::Decodable)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Status::Decodable => None,
            Status::Unsupported(reason) | Status::Invalid(reason) => Some(reason),
        }
    }
}

/// One decoded level that the encoded range can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelInfo {
    pub level: u32,
    pub width: u32,
    pub height: u32,
    /// Bytes this level needs.
    pub encoded_len: u64,
    /// Offset of the level in the reconstructed range.
    pub offset: u64,
}

/// One source level after storage reconstruction, before pixel decoding.
///
/// Block-compressed data is row-major blocks, already untiled. The renderer
/// can upload it directly when the graphics backend samples that format;
/// otherwise [`SourceLevel::decode`] produces RGBA8 through the shared CPU
/// decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLevel {
    pub width: u32,
    pub height: u32,
    pub level: u32,
    pub format: PixelFormat,
    /// Row-major blocks for a compressed format, texels otherwise.
    pub data: Vec<u8>,
    /// Whether the source allocation was stored in native tiles and has been
    /// reconstructed to row-major before this value was returned.
    pub swizzled: bool,
}

impl SourceLevel {
    pub fn codec(&self) -> Option<Codec> {
        self.format.codec
    }

    /// Decodes the reconstructed source to RGBA8.
    pub fn decode(&self) -> Result<Image, Error> {
        let codec = self
            .format
            .codec
            .ok_or_else(|| Error::Unsupported("the pixel format is not supported".into()))?;
        let rgba = decode::decode(codec, &self.data, self.width, self.height)?;
        Ok(Image {
            width: self.width,
            height: self.height,
            level: self.level,
            rgba,
        })
    }
}

/// Metadata for one descriptor, without image data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureInfo {
    pub index: u32,
    /// The displayed name. RDS5 stores have none, so this is synthesized from
    /// the index; a native dictionary uses the stored name when it is readable.
    pub name: String,
    /// The descriptor's 8-byte key. Its meaning is not established.
    pub key: u64,
    /// Which container supplied the texture.
    pub container: &'static str,
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    /// How the format reading is supported for this container.
    pub format_basis: &'static str,
    pub flags: u8,
    pub kind: u8,
    pub tile_mode: u8,
    pub array_size: u32,
    /// The raw descriptor mip word. Its relation to a level count is not
    /// established.
    pub mip_field: u8,
    /// The virtual length of the descriptor's block range.
    pub encoded_len: u64,
    /// The bytes of the first level when the range holds it.
    pub level0_len: Option<u64>,
    pub levels: Vec<LevelInfo>,
    pub status: Status,
    /// The descriptor range could not be read.
    pub range_error: Option<String>,
    /// Offset of the texture's allocation in the graphics segment, for a
    /// native dictionary. `None` for an RDS5 descriptor.
    pub allocation: Option<u64>,
}

impl TextureInfo {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dimensions(&self) -> String {
        format!("{} × {}", self.width, self.height)
    }
}

/// A texture source that the viewer can browse and decode without knowing its
/// container format.
#[derive(Debug, Clone)]
pub enum TextureStore {
    Rds5(Store),
    Dictionary(DictionaryStore),
}

impl TextureStore {
    pub fn textures(&self) -> &[TextureInfo] {
        match self {
            TextureStore::Rds5(store) => store.textures(),
            TextureStore::Dictionary(store) => store.textures(),
        }
    }

    pub fn len(&self) -> usize {
        self.textures().len()
    }

    pub fn is_empty(&self) -> bool {
        self.textures().is_empty()
    }

    /// Reconstructs one source level without decoding it to RGBA8.
    pub fn level(
        &self,
        index: u32,
        level: u32,
        layer: u32,
        cancel: &AtomicBool,
    ) -> Result<SourceLevel, Error> {
        match self {
            TextureStore::Rds5(store) => {
                if layer != 0 {
                    return Err(Error::Invalid(format!(
                        "texture {index} has no array layer {layer}"
                    )));
                }
                store.level(index, level, cancel)
            }
            TextureStore::Dictionary(store) => store.level(index, level, layer, cancel),
        }
    }

    pub fn decode(
        &self,
        index: u32,
        level: u32,
        layer: u32,
        cancel: &AtomicBool,
    ) -> Result<Image, Error> {
        self.level(index, level, layer, cancel)?.decode()
    }

    pub fn thumbnail(
        &self,
        index: u32,
        max_side: u32,
        cancel: &AtomicBool,
    ) -> Result<Image, Error> {
        match self {
            TextureStore::Rds5(store) => store.thumbnail(index, max_side, cancel),
            TextureStore::Dictionary(store) => store.thumbnail(index, max_side, cancel),
        }
    }
}

/// An RDS5 store opened for metadata and pixel reads.
#[derive(Debug, Clone)]
pub struct Store {
    source: Source,
    container: Container,
    textures: Vec<TextureInfo>,
    key_count: usize,
}

impl Store {
    /// Reads the container structure, descriptor table and keys. No block is
    /// decoded here.
    pub fn open(source: Source) -> Result<Self, Error> {
        let mut reader = source.clone();
        let len = reader.len();
        let mut head = [0u8; 16];
        let read = reader.read(&mut head).unwrap_or(0);
        if !is_store(&head[..read]) {
            return Err(Error::NotRds5);
        }
        reader.seek(io::SeekFrom::Start(0))?;
        let container = Container::read(
            &mut reader,
            len,
            &Limits::default(),
            &AtomicBool::new(false),
        )?;
        let entries = container.entries(&mut reader, 0, container.entry_count)?;
        let keys = container.keys(&mut reader).unwrap_or_default();
        let key_count = keys.len();
        let mut textures = Vec::with_capacity(entries.len());
        for entry in &entries {
            let range = rds5::descriptor_range(&mut reader, &container, entry.index);
            let key = keys.get(entry.index as usize).copied().unwrap_or(0);
            textures.push(info(entry, key, range));
        }
        Ok(Self {
            source,
            container,
            textures,
            key_count,
        })
    }

    pub fn textures(&self) -> &[TextureInfo] {
        &self.textures
    }

    pub fn len(&self) -> usize {
        self.textures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.textures.is_empty()
    }

    /// The number of keys read from the key table.
    pub fn key_count(&self) -> usize {
        self.key_count
    }

    pub fn source_len(&self) -> u64 {
        self.source.len()
    }

    pub fn version(&self) -> u32 {
        self.container.version
    }

    /// Reconstructs one level of one texture without decoding pixels. The
    /// work runs on the caller's thread; pass a cancellation flag when it runs
    /// on a background thread.
    pub fn level(&self, index: u32, level: u32, cancel: &AtomicBool) -> Result<SourceLevel, Error> {
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
            .ok_or_else(|| {
                Error::Unsupported(format!(
                    "texture {index} has no established mip level {level}"
                ))
            })?;
        let (offset, len) = (level_info.offset, level_info.encoded_len);
        let end = offset
            .checked_add(len)
            .ok_or_else(|| Error::Invalid("the level range overflows".into()))?;
        if end > MAX_TEXTURE_BYTES {
            return Err(Error::Invalid(format!(
                "level {level} needs {end} bytes, more than the {MAX_TEXTURE_BYTES}-byte decode limit"
            )));
        }
        let mut container = self.container.clone();
        container.decoded_total = 0;
        let mut source = self.source.clone();
        let mut bytes = Vec::with_capacity(end as usize);
        rds5::reconstruct_texture(
            &mut source,
            &mut container,
            index,
            &Limits {
                max_total_len: MAX_TEXTURE_BYTES,
                ..Limits::default()
            },
            cancel,
            |chunk| {
                let remaining = end.saturating_sub(bytes.len() as u64);
                let take = remaining.min(chunk.len() as u64) as usize;
                bytes.extend_from_slice(&chunk[..take]);
                Ok(())
            },
        )?;
        if (bytes.len() as u64) < end {
            return Err(Error::Invalid(format!(
                "the range holds {} bytes, less than level {level}'s bytes {offset:#x}..{end:#x}",
                bytes.len()
            )));
        }
        let start = offset as usize;
        let codec = info
            .format
            .codec
            .ok_or_else(|| Error::Unsupported("the pixel format is not supported".into()))?;
        let swizzle = rds5_swizzle(info.tile_mode).ok_or_else(|| {
            Error::Unsupported(format!("tile mode {} is not decoded", info.tile_mode))
        })?;
        let swizzled = true;
        let data = swizzle::deswizzle(
            swizzle,
            &bytes[start..start + len as usize],
            level_info.width,
            level_info.height,
            codec,
        )?;
        Ok(SourceLevel {
            width: level_info.width,
            height: level_info.height,
            level,
            format: info.format,
            data,
            swizzled,
        })
    }

    /// Decodes one level to RGBA8.
    pub fn decode(&self, index: u32, level: u32, cancel: &AtomicBool) -> Result<Image, Error> {
        self.level(index, level, cancel)?.decode()
    }

    /// Decodes a level and scales it into a thumbnail.
    pub fn thumbnail(
        &self,
        index: u32,
        max_side: u32,
        cancel: &AtomicBool,
    ) -> Result<Image, Error> {
        let image = self.decode(index, 0, cancel)?;
        Ok(image.thumbnail(max_side))
    }
}

/// How the pixel reading for an RDS5 format id is supported. The store samples
/// validate formats 28 and 80 as images; the other mappings are size fits or
/// observations that still need an independent check.
fn rds5_format_basis(id: u8) -> &'static str {
    match id {
        28 | 80 => "validated in the sampled RDS5 store",
        71 | 72 | 77 | 83 | 98 | 99 => "probable: size fit or image observation",
        54 => "candidate: no simple-2D sample",
        _ => "unsupported",
    }
}

fn rds5_swizzle(tile_mode: u8) -> Option<swizzle::Swizzle> {
    match tile_mode {
        0 => Some(swizzle::Swizzle::D64k),
        1..=3 => Some(swizzle::Swizzle::S4k),
        _ => None,
    }
}

fn info(entry: &rds5::Entry, key: u64, range: Result<DescriptorRange, rds5::Error>) -> TextureInfo {
    let format = pixel_format(entry.format_id());
    let (encoded_len, range_error) = match &range {
        Ok(range) => (range.virtual_len, None),
        Err(err) => (0, Some(err.to_string())),
    };
    let level0_len = format.codec.filter(|_| encoded_len > 0).map(|codec| {
        let swizzle = rds5_swizzle(entry.tile_mode());
        match swizzle {
            // A tiled allocation stores whole tiles; level 0 is the padded
            // grid, not the unpadded row-major size.
            Some(swizzle) => swizzle::padded_len(swizzle, codec, entry.width(), entry.height()),
            None => codec.level_len(entry.width(), entry.height()),
        }
    });
    let (status, levels) = classify(entry, format, encoded_len, level0_len);
    TextureInfo {
        index: entry.index,
        name: format!("Texture {}", entry.index),
        key,
        container: "RDS5 store",
        width: entry.width(),
        height: entry.height(),
        format,
        format_basis: rds5_format_basis(entry.format_id()),
        flags: entry.flags(),
        kind: entry.kind(),
        tile_mode: entry.tile_mode(),
        array_size: entry.array_size(),
        mip_field: entry.mip(),
        encoded_len,
        level0_len,
        levels,
        status,
        range_error,
        allocation: None,
    }
}

fn classify(
    entry: &rds5::Entry,
    format: PixelFormat,
    encoded_len: u64,
    level0_len: Option<u64>,
) -> (Status, Vec<LevelInfo>) {
    if entry.width() == 0 || entry.height() == 0 {
        return (
            Status::Invalid("the descriptor declares a zero dimension".into()),
            Vec::new(),
        );
    }
    if entry.width() > MAX_EDGE || entry.height() > MAX_EDGE {
        return (
            Status::Invalid(format!(
                "{} × {} exceeds the {MAX_EDGE}-pixel edge limit",
                entry.width(),
                entry.height()
            )),
            Vec::new(),
        );
    }
    let pixels = u64::from(entry.width()) * u64::from(entry.height());
    if pixels > MAX_PIXELS {
        return (
            Status::Invalid(format!(
                "{pixels} pixels exceed the {MAX_PIXELS}-pixel limit"
            )),
            Vec::new(),
        );
    }
    if format.codec.is_none() {
        return (
            Status::Unsupported(format!(
                "format id {} has no established pixel layout",
                format.id
            )),
            Vec::new(),
        );
    }
    if rds5_swizzle(entry.tile_mode()).is_none() {
        return (
            Status::Unsupported(format!(
                "tile mode {} has no established layout",
                entry.tile_mode()
            )),
            Vec::new(),
        );
    }
    if entry.kind() != 2 {
        return (
            Status::Unsupported(format!("kind {} is not a simple 2D texture", entry.kind())),
            Vec::new(),
        );
    }
    if entry.array_size() != 1 {
        return (
            Status::Unsupported(format!(
                "an array of {} slices is not decoded",
                entry.array_size()
            )),
            Vec::new(),
        );
    }
    let Some(level0_len) = level0_len else {
        return (
            Status::Invalid("the descriptor range could not be read".into()),
            Vec::new(),
        );
    };
    if encoded_len < level0_len {
        return (
            Status::Invalid(format!(
                "the range holds {encoded_len} bytes, less than level 0's {level0_len} bytes"
            )),
            Vec::new(),
        );
    }
    let level = LevelInfo {
        level: 0,
        width: entry.width(),
        height: entry.height(),
        encoded_len: level0_len,
        // Levels are stored smallest mip first and the stream is right-aligned
        // in the descriptor range. Level 0 is therefore at the end.
        offset: encoded_len - level0_len,
    };
    (Status::Decodable, vec![level])
}

#[cfg(test)]
mod test_support;
