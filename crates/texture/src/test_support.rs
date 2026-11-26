//! Synthetic RDS5 containers for the texture tests. No game data is used.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::write::ZlibEncoder;

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn set_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn up(value: usize, to: usize) -> usize {
    value.next_multiple_of(to)
}

fn inflated_len(block: &[u8]) -> u64 {
    let mut decoded = Vec::new();
    flate2::read::ZlibDecoder::new(block)
        .read_to_end(&mut decoded)
        .unwrap();
    decoded.len() as u64
}

/// One descriptor's four words.
pub fn entry(width: u32, height: u32, format: u8, kind: u8, page: u32) -> [u32; 4] {
    let w0 = (width - 1) & 0x3FFF | ((height - 1) & 0x3FFF) << 14;
    let w1 = u32::from(format) << 3 | u32::from(kind) << 20;
    [w0, w1, page, 0]
}

/// The same descriptor with a non-zero tile mode. `1..=3` is a 4 KiB tile
/// grid; `0` is the non-tiled path in the current viewer.
pub fn entry_tiled(width: u32, height: u32, format: u8, kind: u8, page: u32, tile: u8) -> [u32; 4] {
    let mut words = entry(width, height, format, kind, page);
    words[1] |= u32::from(tile) << 24;
    words
}

/// Builds a store with one zlib block per descriptor. The entries must point
/// at the first page of their block.
pub fn build(blocks: &[Vec<u8>], entries: &[[u32; 4]]) -> Vec<u8> {
    assert_eq!(blocks.len(), entries.len());
    // A block shorter than one virtual page would not reach the next page,
    // so the descriptor's page range would be empty. Real small textures are
    // page-sized; these fixtures are too.
    let padded: Vec<Vec<u8>> = blocks
        .iter()
        .map(|block| {
            let mut bytes = block.clone();
            // A page shorter than one virtual page is right-aligned behind a
            // zero prelude, matching the sampled level model.
            if bytes.len() < 0x1000 {
                let mut page = vec![0u8; 0x1000];
                page[0x1000 - bytes.len()..].copy_from_slice(&bytes);
                bytes = page;
            }
            bytes
        })
        .collect();
    let compressed: Vec<Vec<u8>> = padded.iter().map(|block| zlib(block)).collect();
    let record_count = blocks.len() + 2;
    let entry_count = entries.len();
    let record_end = up(0x10 + 8 * record_count, 0x100);
    let table_len = 16 * entry_count;
    let chunk_len = 0x10 + table_len + table_len;
    let first_block = record_end + up(chunk_len, 0x1000);

    let mut offsets = vec![record_end, first_block];
    let mut pos = first_block;
    for block in &compressed {
        pos += up(block.len(), 0x100);
        offsets.push(pos);
    }
    let size = pos;

    let mut virtual_positions = vec![0u64; record_count];
    let mut acc = 0x1000u64;
    for (k, _block) in blocks.iter().enumerate() {
        virtual_positions[k + 1] = acc;
        acc += inflated_len(&compressed[k]);
    }
    virtual_positions[blocks.len() + 1] = acc;

    let mut bytes = vec![0u8; size];
    bytes[..4].copy_from_slice(b"RDS5");
    set_u32(&mut bytes, 4, record_count as u32);
    set_u32(&mut bytes, 8, (0x1000 + size - first_block) as u32);
    set_u32(&mut bytes, 0x0C, 0x1600_0000);
    for (index, offset) in offsets.iter().enumerate() {
        let at = 0x10 + 8 * index;
        let class = if index == 0 { 0 } else { 0x20 };
        let mut lo = ((*offset / 0x100) as u32 & 0x00FF_FFFF) | (class << 24);
        let virtual_at = virtual_positions[index];
        lo |= (((virtual_at % 0x4000) / 0x1000) as u32 & 3) << 30;
        set_u32(&mut bytes, at, lo);
        let padding = compressed
            .get(index.saturating_sub(1))
            .map_or(0, |block| up(block.len(), 0x100) - block.len());
        set_u32(
            &mut bytes,
            at + 4,
            (((padding as u32) & 0xFFF) << 20) | (virtual_at / 0x4000) as u32,
        );
    }
    bytes[record_end..record_end + 4].copy_from_slice(b"ETPF");
    set_u32(&mut bytes, record_end + 4, 0x27A);
    set_u32(&mut bytes, record_end + 8, entry_count as u32);
    set_u32(&mut bytes, record_end + 0x0C, 0);
    for (index, words) in entries.iter().enumerate() {
        let at = record_end + 0x10 + index * 16;
        for (word, value) in words.iter().enumerate() {
            set_u32(&mut bytes, at + 4 * word, *value);
        }
    }
    let mut pos = first_block;
    for block in &compressed {
        bytes[pos..pos + block.len()].copy_from_slice(block);
        pos += up(block.len(), 0x100);
    }
    bytes
}
