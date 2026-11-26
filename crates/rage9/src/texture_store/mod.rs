//! Read-only access to the `.ttpf` texture stores under a game installation.
//!
//! A store is the RDS5 container documented in the research repository: a
//! chunk table, an ETPF descriptor block and a virtual address space. The
//! index reads only headers and descriptors; pixel bytes are read on demand
//! for the requested texture. Only stored and zlib chunks are decoded. A
//! texture whose mip 0 falls in an undecoded chunk falls back to the largest
//! mip that is fully readable, and the source string says so.

mod gfx10;

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use lforge_scene::{Texture, TextureFormat};

use gfx10::{Layout, Swizzle};

pub const STORE_EXTENSION: &str = "ttpf";
/// Bound on the stores scanned below one root.
const MAX_STORES: usize = 512;
const MAX_DEPTH: usize = 8;
const MAX_DESCRIPTORS: usize = 4_000_000;
const MAX_CHUNKS: usize = 8_000_000;
const MAX_TEXTURE_DIMENSION: u32 = 16384;
const CHUNK_UNIT: u64 = 0x4000;
const VIRTUAL_BASE: u64 = 0x1000;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NotAStore(String),
    Malformed(String),
    Unsupported(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::NotAStore(path) => write!(f, "{path} is not an RDS5 texture store"),
            Self::Malformed(reason) => write!(f, "malformed texture store: {reason}"),
            Self::Unsupported(reason) => write!(f, "unsupported texture: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// One ETPF descriptor and the store it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreTextureRef {
    pub store: usize,
    pub index: usize,
    pub hash: u64,
    pub width: u32,
    pub height: u32,
    pub dxgi_format: u32,
    pub mip_levels: u32,
    pub tile_mode: u32,
    pub slices: u32,
    pub virtual_start: u64,
    pub label: String,
}

impl StoreTextureRef {
    pub fn describe(&self) -> String {
        format!(
            "{}#{} {}x{} DXGI {}",
            self.label, self.index, self.width, self.height, self.dxgi_format
        )
    }
}

#[derive(Debug)]
pub enum Resolution {
    Missing,
    Unique(StoreTextureRef),
    /// Several stores or descriptors carry the same key. The caller must not
    /// pick one silently.
    Ambiguous(Vec<StoreTextureRef>),
}

#[derive(Debug)]
struct Chunk {
    file_start: u64,
    file_end: u64,
    virtual_start: u64,
    virtual_end: u64,
    codec: u8,
    pad: u64,
}

#[derive(Debug)]
struct Store {
    path: PathBuf,
    label: String,
    length: u64,
    chunks: Vec<Chunk>,
    textures: Vec<StoreTextureRef>,
}

impl Store {
    fn open(path: &Path, index: usize) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        let mut header = [0u8; 24];
        file.read_exact(&mut header)?;
        if &header[..4] != b"RDS5" {
            return Err(Error::NotAStore(path.display().to_string()));
        }
        let entries = u32::from_le_bytes(header[4..8].try_into().expect("four bytes")) as usize;
        if entries == 0 || entries > MAX_CHUNKS {
            return Err(Error::Malformed(format!("{entries} chunk-table entries")));
        }
        let table_len = entries
            .checked_sub(1)
            .and_then(|count| count.checked_mul(8))
            .ok_or_else(|| Error::Malformed("chunk table size overflows".into()))?;
        let mut table = vec![0u8; table_len];
        file.seek(SeekFrom::Start(0x18))?;
        file.read_exact(&mut table)?;
        let mut boundaries = Vec::with_capacity(entries);
        for entry in table.as_chunks::<8>().0 {
            let a = u32::from_le_bytes(entry[0..4].try_into().expect("four bytes"));
            let b = u32::from_le_bytes(entry[4..8].try_into().expect("four bytes"));
            boundaries.push((
                u64::from(a & 0x03FF_FFFF) << 8,
                VIRTUAL_BASE
                    + u64::from(b & 0xF_FFFF) * CHUNK_UNIT
                    + u64::from(a >> 30) * VIRTUAL_BASE,
                ((a >> 26) & 0xF) as u8,
                u64::from(b >> 20),
            ));
        }
        if boundaries.is_empty() {
            return Err(Error::Malformed("empty chunk table".into()));
        }
        let mut chunks = Vec::with_capacity(boundaries.len() - 1);
        for pair in boundaries.windows(2) {
            let (file_start, virtual_start, codec, pad) = pair[0];
            let (file_end, virtual_end, _, _) = pair[1];
            if file_start >= file_end || file_end > length || virtual_start >= virtual_end {
                return Err(Error::Malformed(format!(
                    "chunk {file_start:#x}..{file_end:#x} or virtual {virtual_start:#x}..{virtual_end:#x} is inconsistent"
                )));
            }
            chunks.push(Chunk {
                file_start,
                file_end,
                virtual_start,
                virtual_end,
                codec,
                pad,
            });
        }
        let etpf_offset = ((0x10 + 8 * entries + 0xFF) & !0xFF) as u64;
        if etpf_offset + 16 > length {
            return Err(Error::Malformed("ETPF block is outside the file".into()));
        }
        file.seek(SeekFrom::Start(etpf_offset))?;
        let mut etpf = [0u8; 16];
        file.read_exact(&mut etpf)?;
        if &etpf[..4] != b"ETPF" {
            return Err(Error::Malformed("missing ETPF block".into()));
        }
        let count = u32::from_le_bytes(etpf[8..12].try_into().expect("four bytes")) as usize;
        if count > MAX_DESCRIPTORS {
            return Err(Error::Malformed(format!("{count} ETPF descriptors")));
        }
        let body_len = count
            .checked_mul(16)
            .and_then(|body| body.checked_add(count.checked_mul(8)?))
            .ok_or_else(|| Error::Malformed("ETPF size overflows".into()))?;
        if etpf_offset + 16 + body_len as u64 > length {
            return Err(Error::Malformed(
                "ETPF descriptors are outside the file".into(),
            ));
        }
        let mut body = vec![0u8; body_len];
        file.read_exact(&mut body)?;
        let label = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let mut textures = Vec::with_capacity(count);
        for descriptor in 0..count {
            let d0 = u32::from_le_bytes(
                body[descriptor * 16..descriptor * 16 + 4]
                    .try_into()
                    .expect("four bytes"),
            );
            let d1 = u32::from_le_bytes(
                body[descriptor * 16 + 4..descriptor * 16 + 8]
                    .try_into()
                    .expect("four bytes"),
            );
            let location = u64::from_le_bytes(
                body[descriptor * 16 + 8..descriptor * 16 + 16]
                    .try_into()
                    .expect("eight bytes"),
            );
            let hash = u64::from_le_bytes(
                body[count * 16 + descriptor * 8..count * 16 + descriptor * 8 + 8]
                    .try_into()
                    .expect("eight bytes"),
            );
            let width = (d0 & 0x3FFF) + 1;
            let height = ((d0 >> 14) & 0x3FFF) + 1;
            let mip_field = d0 >> 28;
            let dxgi_format = (d1 >> 3) & 0x7F;
            let kind = (d1 >> 20) & 0xF;
            let tile_mode = (d1 >> 24) & 0xF;
            let slices = ((d1 >> 10) & 0x3FF) + 1;
            let mip_levels = match tile_mode {
                9..=12 => {
                    let full = 32 - width.max(height).leading_zeros();
                    (mip_field + tile_mode - 9).clamp(1, full)
                }
                1 if mip_field == 1 => 1,
                _ => mip_field + 1,
            };
            if width > MAX_TEXTURE_DIMENSION || height > MAX_TEXTURE_DIMENSION {
                continue;
            }
            if !matches!(kind, 2 | 10) {
                continue;
            }
            let virtual_start = (location & 0x1F_FFFF) * 0x1000 + VIRTUAL_BASE;
            textures.push(StoreTextureRef {
                store: index,
                index: descriptor,
                hash,
                width,
                height,
                dxgi_format,
                mip_levels,
                tile_mode,
                slices,
                virtual_start,
                label: label.clone(),
            });
        }
        Ok(Self {
            path: path.to_path_buf(),
            label,
            length,
            chunks,
            textures,
        })
    }

    fn range_supported(&self, start: u64, len: u64) -> bool {
        let end = start.saturating_add(len);
        !self.chunks.iter().any(|chunk| {
            chunk.virtual_end > start && chunk.virtual_start < end && !matches!(chunk.codec, 0 | 8)
        })
    }

    fn first_unsupported(&self, start: u64, len: u64) -> Option<u8> {
        let end = start.saturating_add(len);
        self.chunks
            .iter()
            .find(|chunk| {
                chunk.virtual_end > start
                    && chunk.virtual_start < end
                    && !matches!(chunk.codec, 0 | 8)
            })
            .map(|chunk| chunk.codec)
    }

    fn read_range(&self, start: u64, len: u64) -> Result<Vec<u8>, Error> {
        let end = start
            .checked_add(len)
            .ok_or_else(|| Error::Unsupported("virtual range overflows".into()))?;
        if len == 0 || len > MAX_TEXTURE_BYTES {
            return Err(Error::Unsupported(format!(
                "virtual range of {len} bytes is outside the supported limit"
            )));
        }
        if let Some(codec) = self.first_unsupported(start, len) {
            return Err(Error::Unsupported(format!(
                "{} chunk codec {codec:#04x} is not decoded",
                self.label
            )));
        }
        let mut out = vec![0u8; len as usize];
        let mut file = File::open(&self.path)?;
        for chunk in &self.chunks {
            if chunk.virtual_end <= start || chunk.virtual_start >= end {
                continue;
            }
            let stored_len = chunk
                .file_end
                .checked_sub(chunk.file_start)
                .and_then(|len| len.checked_sub(chunk.pad))
                .ok_or_else(|| Error::Malformed("chunk pad exceeds its length".into()))?;
            if chunk.file_end > self.length {
                return Err(Error::Malformed("chunk is outside the store".into()));
            }
            file.seek(SeekFrom::Start(chunk.file_start))?;
            let mut stored = vec![0u8; stored_len as usize];
            file.read_exact(&mut stored)?;
            let raw = match chunk.codec {
                0 => stored,
                8 => {
                    let mut decoded = Vec::new();
                    ZlibDecoder::new(&stored[..]).read_to_end(&mut decoded)?;
                    decoded
                }
                codec => {
                    return Err(Error::Unsupported(format!(
                        "{} chunk codec {codec:#04x} is not decoded",
                        self.label
                    )));
                }
            };
            let from = start.max(chunk.virtual_start);
            let to = end.min(chunk.virtual_end);
            if to <= from {
                continue;
            }
            let source_start = (from - chunk.virtual_start) as usize;
            let source_end = (to - chunk.virtual_start) as usize;
            if source_end > raw.len() {
                return Err(Error::Malformed(format!(
                    "{} chunk decodes to {} bytes, {source_end} are addressed",
                    self.label,
                    raw.len()
                )));
            }
            out[(from - start) as usize..(to - start) as usize]
                .copy_from_slice(&raw[source_start..source_end]);
        }
        Ok(out)
    }
}

const MAX_TEXTURE_BYTES: u64 = 512 << 20;

/// All stores found below one root, with one lookup table per key.
#[derive(Debug)]
pub struct TextureStoreIndex {
    stores: Vec<Store>,
    by_hash: HashMap<u64, Vec<usize>>,
    root: PathBuf,
}

impl TextureStoreIndex {
    /// Scans `root` recursively for `.ttpf` files and reads their descriptors.
    /// Pixel data is not read.
    pub fn scan(root: &Path) -> Result<Self, Error> {
        let mut paths = Vec::new();
        collect_stores(root, 0, &mut paths)?;
        paths.sort();
        paths.truncate(MAX_STORES);
        let mut stores = Vec::with_capacity(paths.len());
        let mut by_hash: HashMap<u64, Vec<usize>> = HashMap::new();
        for (index, path) in paths.iter().enumerate() {
            let store = Store::open(path, index)?;
            for (position, texture) in store.textures.iter().enumerate() {
                by_hash
                    .entry(texture.hash)
                    .or_default()
                    .push(index * MAX_DESCRIPTORS + position);
            }
            stores.push(store);
        }
        Ok(Self {
            stores,
            by_hash,
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn store_count(&self) -> usize {
        self.stores.len()
    }

    pub fn texture_count(&self) -> usize {
        self.stores.iter().map(|store| store.textures.len()).sum()
    }

    pub fn resolve(&self, key: u64) -> Resolution {
        let Some(entries) = self.by_hash.get(&key) else {
            return Resolution::Missing;
        };
        let mut matches = Vec::with_capacity(entries.len());
        for entry in entries {
            let store = entry / MAX_DESCRIPTORS;
            let position = entry % MAX_DESCRIPTORS;
            if let Some(texture) = self
                .stores
                .get(store)
                .and_then(|store| store.textures.get(position))
            {
                matches.push(texture.clone());
            }
        }
        match matches.len() {
            0 => Resolution::Missing,
            1 => Resolution::Unique(matches.remove(0)),
            _ => Resolution::Ambiguous(matches),
        }
    }

    pub fn decode(&self, reference: &StoreTextureRef) -> Result<Texture, Error> {
        let store = self
            .stores
            .get(reference.store)
            .ok_or_else(|| Error::Unsupported("store index is stale".into()))?;
        let format = format_for_dxgi(reference.dxgi_format)?;
        let swizzle = match reference.tile_mode {
            0 => Swizzle::D64k,
            1..=3 => Swizzle::S4k,
            mode => {
                return Err(Error::Unsupported(format!(
                    "tile mode {mode} is not decoded"
                )));
            }
        };
        let block = format.block_dim();
        let blocks_w = reference.width.div_ceil(block);
        let blocks_h = reference.height.div_ceil(block);
        let mut layout = Layout::new(
            swizzle,
            blocks_w,
            blocks_h,
            reference.mip_levels,
            format.bytes_per_block(),
        )
        .ok_or_else(|| {
            Error::Unsupported(format!(
                "{}x{} DXGI {} has no layout",
                reference.width, reference.height, reference.dxgi_format
            ))
        })?;
        if reference.slices > 1 {
            layout = layout.with_slices(reference.slices);
        }
        let mut chosen = None;
        for mip in 0..reference.mip_levels as usize {
            let Some((relative_start, relative_end)) = layout.mip_span(mip) else {
                break;
            };
            let start = reference.virtual_start + relative_start;
            let len = relative_end - relative_start;
            if len == 0 || !store.range_supported(start, len) {
                continue;
            }
            chosen = Some((mip, start, len));
            break;
        }
        let (mip, start, len) = chosen.ok_or_else(|| {
            let codec = layout
                .mip_span(0)
                .map(|(start, end)| {
                    store
                        .first_unsupported(
                            reference.virtual_start + start,
                            end.saturating_sub(start),
                        )
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            Error::Unsupported(format!(
                "no mip of {} is stored in a decoded chunk (first codec {codec:#04x})",
                reference.describe()
            ))
        })?;
        let bytes = store.read_range(start, len)?;
        let linear = layout.untile(&bytes, mip).ok_or_else(|| {
            Error::Malformed(format!(
                "{} mip {mip} cannot be untiled",
                reference.describe()
            ))
        })?;
        let width = (reference.width >> mip).max(1);
        let height = (reference.height >> mip).max(1);
        let expected = format
            .surface_bytes(width, height)
            .ok_or_else(|| Error::Unsupported("texture surface size overflows".into()))?;
        if linear.len() != expected {
            return Err(Error::Malformed(format!(
                "{} mip {mip} untiled to {} bytes, expected {expected}",
                reference.describe(),
                linear.len()
            )));
        }
        Ok(Texture {
            name: reference.describe(),
            width,
            height,
            format,
            source_mip_levels: reference.mip_levels,
            data: linear,
            source: format!(
                "{}{}",
                reference.label,
                if mip == 0 {
                    String::new()
                } else {
                    format!(" (mip {mip} of {})", reference.mip_levels)
                }
            ),
        })
    }
}

fn collect_stores(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), Error> {
    if depth > MAX_DEPTH || out.len() >= MAX_STORES {
        return Ok(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if depth > 0 => {
            log::debug!("skipping texture store directory {}: {err}", dir.display());
            return Ok(());
        }
        Err(err) => return Err(Error::Io(err)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_stores(&path, depth + 1, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case(STORE_EXTENSION))
        {
            out.push(path);
            if out.len() >= MAX_STORES {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn format_for_dxgi(dxgi: u32) -> Result<TextureFormat, Error> {
    Ok(match dxgi {
        71 => TextureFormat::Bc1Unorm,
        72 => TextureFormat::Bc1UnormSrgb,
        77 => TextureFormat::Bc3Unorm,
        78 => TextureFormat::Bc3UnormSrgb,
        80 | 81 => TextureFormat::Bc4Unorm,
        83 | 84 => TextureFormat::Bc5Unorm,
        95 | 96 => TextureFormat::Bc6hUf16,
        98 => TextureFormat::Bc7Unorm,
        99 => TextureFormat::Bc7UnormSrgb,
        28 => TextureFormat::Rgba8Unorm,
        29 => TextureFormat::Rgba8UnormSrgb,
        87 => TextureFormat::Bgra8Unorm,
        91 => TextureFormat::Bgra8UnormSrgb,
        61 => TextureFormat::R8Unorm,
        49 => TextureFormat::Rg8Unorm,
        56 => TextureFormat::R16Unorm,
        11 => TextureFormat::Rgba16Unorm,
        54 => TextureFormat::R16Float,
        10 => TextureFormat::Rgba16Float,
        41 => TextureFormat::R32Float,
        24 => TextureFormat::Rgb10a2Unorm,
        other => {
            return Err(Error::Unsupported(format!(
                "DXGI format {other} is not decoded"
            )));
        }
    })
}

/// A texture stored inside a model resource rather than in a `.ttpf` store.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddedTexture {
    pub hash: u64,
    pub texture: Texture,
}

/// Finds and decodes the texture records embedded in a resource's system
/// segment. Only records whose shape is plausible are read; a record that
/// cannot be decoded is skipped rather than guessed.
pub fn embedded_textures(system: &[u8], graphics: &[u8]) -> Vec<EmbeddedTexture> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 0x48 <= system.len() {
        match embedded_texture_at(system, graphics, offset) {
            Some(texture) => {
                out.push(texture);
                offset += 0x70;
            }
            None => offset += 8,
        }
    }
    out
}

fn embedded_texture_at(system: &[u8], graphics: &[u8], offset: usize) -> Option<EmbeddedTexture> {
    let u16_at = |at: usize| {
        system
            .get(at..at + 2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().expect("two bytes")))
    };
    let u64_at = |at: usize| {
        system
            .get(at..at + 8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    };
    if u16_at(offset + 0x0E)? != 8 {
        return None;
    }
    let data = u64_at(offset + 0x18)?;
    if data >> 28 != 6 {
        return None;
    }
    let width = u32::from(u16_at(offset + 0x38)?);
    let height = u32::from(u16_at(offset + 0x3A)?);
    let depth = u32::from(u16_at(offset + 0x3C)?);
    let dxgi = u32::from(*system.get(offset + 0x3F)?);
    let mips = u32::from(*system.get(offset + 0x42)?);
    if width == 0
        || height == 0
        || width > MAX_TEXTURE_DIMENSION
        || height > MAX_TEXTURE_DIMENSION
        || depth == 0
        || depth > 256
        || mips == 0
        || mips > 15
        || dxgi == 0
        || dxgi > 132
    {
        return None;
    }
    let name_record = u64_at(offset + 0x30)?;
    if name_record >> 28 != 5 {
        return None;
    }
    let name_offset = (name_record & 0x0FFF_FFFF) as usize;
    let hash = u64_at(name_offset + 8)?;
    if hash == 0 {
        return None;
    }
    let format = format_for_dxgi(dxgi).ok()?;
    let data_offset = (data & 0x0FFF_FFFF) as usize;
    let block = format.block_dim();
    let texture = if height == 1 {
        let length = usize::try_from(width)
            .ok()?
            .checked_mul(format.bytes_per_block() as usize)?;
        let bytes = graphics.get(data_offset..data_offset + length)?.to_vec();
        Texture {
            name: format!("embedded {hash:016x}"),
            width,
            height,
            format,
            source_mip_levels: mips,
            data: bytes,
            source: "embedded in the model".into(),
        }
    } else {
        let mut layout = Layout::new(
            Swizzle::S4k,
            width.div_ceil(block),
            height.div_ceil(block),
            mips,
            format.bytes_per_block(),
        )?;
        if depth > 1 {
            layout = layout.with_slices(depth);
        }
        let (relative_start, end) = layout.mip_span(0)?;
        let length = usize::try_from(end - relative_start).ok()?;
        let start = data_offset.checked_add(relative_start as usize)?;
        let bytes = graphics.get(start..start + length)?;
        let linear = layout.untile(bytes, 0)?;
        Texture {
            name: format!("embedded {hash:016x}"),
            width,
            height,
            format,
            source_mip_levels: mips,
            data: linear,
            source: "embedded in the model".into(),
        }
    };
    texture.validate().ok()?;
    Some(EmbeddedTexture { hash, texture })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn dxgi_names_map_to_scene_formats() {
        assert_eq!(format_for_dxgi(71).unwrap(), TextureFormat::Bc1Unorm);
        assert_eq!(format_for_dxgi(99).unwrap(), TextureFormat::Bc7UnormSrgb);
        assert_eq!(format_for_dxgi(28).unwrap(), TextureFormat::Rgba8Unorm);
        assert!(format_for_dxgi(1234).is_err());
    }

    fn tile_rgba8(pixels: &[[u8; 4]]) -> Vec<u8> {
        let layout = Layout::new(Swizzle::S4k, 8, 8, 1, 4).unwrap();
        let mut tiled = vec![0u8; layout.total as usize];
        for y in 0..8 {
            for x in 0..8 {
                let at = layout.address(0, 0, x, y).unwrap() as usize;
                tiled[at..at + 4].copy_from_slice(&pixels[(y * 8 + x) as usize]);
            }
        }
        tiled
    }

    fn synthetic_store(pixels: &[[u8; 4]]) -> Vec<u8> {
        let tiled = tile_rgba8(pixels);
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tiled).unwrap();
        let compressed = encoder.finish().unwrap();
        let etpf = 0x100u64;
        let data = 0x200u64;
        let end = (data + compressed.len() as u64).div_ceil(0x100) * 0x100;
        let mut file = vec![0u8; end as usize];
        file[..4].copy_from_slice(b"RDS5");
        file[4..8].copy_from_slice(&4u32.to_le_bytes());
        let entries = [
            // ETPF block
            (1u32, 0u32),
            // data chunk, zlib codec 8, virtual start 0x2000
            (2u32 | (8 << 26) | (1 << 30), 0u32),
            // terminator, virtual end 0x3000
            ((end >> 8) as u32 | (2 << 30), 0u32),
        ];
        for (index, (a, b)) in entries.iter().enumerate() {
            let at = 0x18 + index * 8;
            file[at..at + 4].copy_from_slice(&a.to_le_bytes());
            file[at + 4..at + 8].copy_from_slice(&b.to_le_bytes());
        }
        file[etpf as usize..etpf as usize + 4].copy_from_slice(b"ETPF");
        file[etpf as usize + 4..etpf as usize + 8].copy_from_slice(&634u32.to_le_bytes());
        file[etpf as usize + 8..etpf as usize + 12].copy_from_slice(&1u32.to_le_bytes());
        let descriptor = etpf as usize + 16;
        let d0 = 7u32 | (7 << 14);
        // DXGI 28, 2D, one slice, tile mode 1.
        let d1: u32 = (28 << 3) | (2 << 20) | (1 << 24);
        file[descriptor..descriptor + 4].copy_from_slice(&d0.to_le_bytes());
        file[descriptor + 4..descriptor + 8].copy_from_slice(&d1.to_le_bytes());
        file[descriptor + 8..descriptor + 16].copy_from_slice(&1u64.to_le_bytes());
        let key_at = descriptor + 16;
        file[key_at..key_at + 8].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
        file[data as usize..data as usize + compressed.len()].copy_from_slice(&compressed);
        file
    }

    #[test]
    fn a_synthetic_store_decodes_a_tiled_rgba8_texture() {
        let mut pixels = [[0u8; 4]; 64];
        for (index, pixel) in pixels.iter_mut().enumerate() {
            *pixel = [index as u8, (index * 3) as u8, (255 - index) as u8, 255];
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("synthetic.ttpf");
        std::fs::write(&path, synthetic_store(&pixels)).unwrap();
        let index = TextureStoreIndex::scan(temp.path()).unwrap();
        assert_eq!(index.store_count(), 1);
        assert_eq!(index.texture_count(), 1);
        let reference = match index.resolve(0x0123_4567_89AB_CDEF) {
            Resolution::Unique(texture) => texture,
            other => panic!("expected one store match, got {other:?}"),
        };
        let texture = index.decode(&reference).unwrap();
        assert_eq!((texture.width, texture.height), (8, 8));
        assert_eq!(texture.format, TextureFormat::Rgba8Unorm);
        assert_eq!(texture.data.len(), 8 * 8 * 4);
        assert_eq!(&texture.data[(3 * 8 + 5) * 4..][..4], &pixels[29]);
    }

    #[test]
    fn a_missing_key_is_reported_as_missing() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("synthetic.ttpf");
        std::fs::write(&path, synthetic_store(&[[0u8; 4]; 64])).unwrap();
        let index = TextureStoreIndex::scan(temp.path()).unwrap();
        assert!(matches!(index.resolve(0xDEAD_BEEF), Resolution::Missing));
    }
}
