//! Decoding of entries behind the payload transform.
//!
//! The transform is a counter-mode keystream over the stored bytes. The
//! engine does not transform the whole stored range: the verified sample shows
//! the first 2048 bytes of an entry and the first 1024 bytes of each later
//! 9216-byte stream buffer transformed, while the rest is plaintext. The exact
//! segmentation for large and multi-chunk entries is not fully established, so
//! this module tries the verified models and accepts a result only when every
//! chunk inflates to its declared logical size.

use std::io::Read;

use flate2::read::ZlibDecoder;

use super::stream_block::EncodedStreamBlock;
use crate::rpf::metadata::ChunkTable;
use crate::rpf::metadata::transform::{BLOCK_LEN, BlockDecrypt, CipherDescriptor};

const ZLIB_METHOD: u8 = 3;
const ENCODING_2_PREFIX: usize = 16;
/// The first transformed span of every stream.
const LEADING: usize = 2048;
/// Later stream buffers are 9216 bytes and only their first 1024 are
/// transformed.
const BUFFER: usize = 9216;
const BUFFER_PREFIX: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// No verified transformation model produced the declared payload.
    Unsupported(&'static str),
    /// The chosen model produced a payload of the wrong size or a bad stream.
    Decode(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Unsupported(reason) => {
                write!(f, "unsupported payload transform: {reason}")
            }
            DecodeError::Decode(reason) => write!(f, "payload transform decode failed: {reason}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Applies the verified models with each candidate block set and returns the
/// first payload whose chunks match `logical_len`.
pub fn decode_transformed(
    stored: &[u8],
    table: &ChunkTable,
    logical_len: u64,
    descriptor: &CipherDescriptor,
    blocks: &[EncodedStreamBlock],
) -> Result<Vec<u8>, DecodeError> {
    if blocks.is_empty() {
        return Err(DecodeError::Unsupported(
            "no algorithm-0x11 key state and tables",
        ));
    }
    let mut last = None;
    for block in blocks {
        for model in Model::ALL {
            let mut plain = stored.to_vec();
            model.apply(&mut plain, descriptor.parameter, block);
            match decode_chunks(table, &plain, logical_len) {
                Ok(payload) => return Ok(payload),
                Err(err) => last = Some(err),
            }
        }
    }
    Err(DecodeError::Decode(
        last.unwrap_or_else(|| "no model matched".to_string()),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Model {
    Whole,
    Leading,
    Buffers,
}

impl Model {
    const ALL: [Model; 3] = [Model::Buffers, Model::Leading, Model::Whole];

    fn apply(self, plain: &mut [u8], parameter: [u8; BLOCK_LEN], block: &EncodedStreamBlock) {
        match self {
            Model::Whole => decrypt_span(plain, parameter, block, 0, plain.len()),
            Model::Leading => decrypt_span(plain, parameter, block, 0, LEADING.min(plain.len())),
            Model::Buffers => {
                let leading = LEADING.min(plain.len());
                decrypt_span(plain, parameter, block, 0, leading);
                let mut start = BUFFER;
                while start < plain.len() {
                    let end = (start + BUFFER_PREFIX).min(plain.len());
                    decrypt_span(plain, parameter, block, start, end);
                    start += BUFFER;
                }
            }
        }
    }
}

/// XORs the keystream for byte range `start..end` into `plain`. Both ends are
/// rounded to block boundaries; the stored sizes in the sample are aligned.
fn decrypt_span(
    plain: &mut [u8],
    parameter: [u8; BLOCK_LEN],
    block: &EncodedStreamBlock,
    start: usize,
    end: usize,
) {
    if start >= end {
        return;
    }
    let first = start / BLOCK_LEN;
    let last = end.div_ceil(BLOCK_LEN);
    for index in first..last {
        let mut counter = add_be(parameter, index as u64);
        block.decrypt_block(&mut counter);
        let offset = index * BLOCK_LEN;
        let limit = (offset + BLOCK_LEN).min(plain.len());
        if offset >= limit {
            break;
        }
        for (byte, key) in plain[offset..limit].iter_mut().zip(counter.iter()) {
            *byte ^= key;
        }
    }
}

fn add_be(counter: [u8; BLOCK_LEN], value: u64) -> [u8; BLOCK_LEN] {
    let mut out = counter;
    let mut carry = value;
    for byte in out.iter_mut().rev() {
        let total = u64::from(*byte) + (carry & 0xFF);
        *byte = total as u8;
        carry = (carry >> 8) + (total >> 8);
    }
    out
}

fn decode_chunks(table: &ChunkTable, stored: &[u8], logical_len: u64) -> Result<Vec<u8>, String> {
    let prefix = if table.encoding == 2 {
        ENCODING_2_PREFIX
    } else {
        0
    };
    if prefix > stored.len() {
        return Err("the stored prefix does not fit".to_string());
    }
    let mut out = Vec::with_capacity(
        usize::try_from(logical_len)
            .unwrap_or(0)
            .min(64 * 1024 * 1024),
    );
    let mut position = prefix;
    for (index, chunk) in table.chunks.iter().enumerate() {
        let compressed = chunk
            .stored_len
            .checked_sub(chunk.padding)
            .ok_or_else(|| format!("chunk {index} has more padding than stored bytes"))?;
        let end = position
            .checked_add(compressed as usize)
            .ok_or_else(|| format!("chunk {index} overflows"))?;
        if end > stored.len() {
            return Err(format!("chunk {index} lies outside the stored bytes"));
        }
        let data = &stored[position..end];
        if chunk.method == ZLIB_METHOD {
            let mut decoder = ZlibDecoder::new(data);
            let mut chunk_out = Vec::with_capacity(chunk.logical_len as usize);
            decoder
                .read_to_end(&mut chunk_out)
                .map_err(|err| format!("chunk {index} does not inflate: {err}"))?;
            if chunk_out.len() != chunk.logical_len as usize {
                return Err(format!(
                    "chunk {index} inflates to {} bytes, not {}",
                    chunk_out.len(),
                    chunk.logical_len
                ));
            }
            out.extend_from_slice(&chunk_out);
        } else {
            if compressed != chunk.logical_len {
                return Err(format!("chunk {index} is copied with a different length"));
            }
            out.extend_from_slice(data);
        }
        position += chunk.stored_len as usize;
    }
    if out.len() as u64 != logical_len {
        return Err(format!(
            "the payload is {} bytes, not the declared {logical_len}",
            out.len()
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpf::metadata::Chunk;

    #[test]
    fn adds_the_counter_in_big_endian_order() {
        let mut counter = [0u8; 16];
        counter[15] = 0xFF;
        let next = add_be(counter, 1);
        assert_eq!(next[14], 1);
        assert_eq!(next[15], 0);
    }

    #[test]
    fn decodes_a_zlib_chunk_and_a_copy_chunk() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let text = b"<Item>value</Item>";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(text).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut stored = compressed.clone();
        stored.extend_from_slice(b"copy");
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![
                Chunk {
                    logical_len: text.len() as u32,
                    stored_len: compressed.len() as u32,
                    padding: 0,
                    compressed_len: compressed.len() as u32,
                    method: 3,
                },
                Chunk {
                    logical_len: 4,
                    stored_len: 4,
                    padding: 0,
                    compressed_len: 4,
                    method: 0,
                },
            ],
        };
        let out = decode_chunks(&table, &stored, (text.len() + 4) as u64).unwrap();
        assert_eq!(out, b"<Item>value</Item>copy");
    }
}
