//! Selection and preparation of the payload-transform stream.
//!
//! The covered range depends on the descriptor's stream fields. For the common
//! shape it covers the first 2048 bytes, the first 1024 bytes at offset 9216
//! and the first 1024 bytes of every 8192 bytes after that. Another shape
//! covers the whole stored range. The transformed bytes are produced on read
//! by [`StreamTransform`]; this module selects the right key table and range
//! from the archive data without decoding a whole resource.
//!
//! The selection probe uses zlib chunks. It applies the partial range to each
//! candidate table and requires the chunk to inflate to its declared logical
//! size. Chunks are verified until one covers a byte that the partial and
//! whole-range rules treat differently, so the range rule is proven, not
//! guessed. The whole-range rule is tried only for a row with a single chunk,
//! where that chunk covers the entire stream and therefore verifies the rule on
//! its own; a multi-chunk row with the partial rule cannot verify a different
//! range from its later copied chunks. A resource whose stream cannot be
//! verified this way is refused rather than decoded speculatively.

use std::fmt;
use std::io::Read;
use std::sync::Arc;

use flate2::read::ZlibDecoder;
use lforge_binary::Source;

use super::stream_block::EncodedStreamBlock;
use crate::rpf::metadata::payload::{
    LEADING, StreamModel, StreamTransform, apply_transform, separates_models,
};
use crate::rpf::metadata::transform::{BlockDecrypt, CipherDescriptor};
use crate::rpf::metadata::{ChunkTable, Entry};

/// Stored bytes read to select and verify a transform key table.
pub const PROBE_LIMIT: u64 = 8 * 1024 * 1024;
const ZLIB_METHOD: u8 = 3;
const ENCODING_2_PREFIX: u64 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTransformError {
    /// The row does not carry the payload transform.
    NoTransform,
    /// The row has no cipher descriptor.
    NoDescriptor(String),
    /// The row has no chunk table.
    NoChunkTable(String),
    /// The executable has no algorithm-`0x11` state for the descriptor key.
    NoKeyState,
    /// The first zlib chunk cannot verify any candidate table.
    Unverifiable(&'static str),
    /// The stored range is malformed.
    StoredRange(String),
    /// The prefix cannot be read.
    Read(String),
}

impl fmt::Display for StreamTransformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamTransformError::NoTransform => f.write_str("the row has no payload transform"),
            StreamTransformError::NoDescriptor(reason) => {
                write!(f, "the row has no usable cipher descriptor: {reason}")
            }
            StreamTransformError::NoChunkTable(reason) => {
                write!(f, "the row has no usable chunk table: {reason}")
            }
            StreamTransformError::NoKeyState => {
                f.write_str("no algorithm-0x11 key state is available for the descriptor key")
            }
            StreamTransformError::Unverifiable(reason) => {
                write!(f, "the payload transform cannot be verified: {reason}")
            }
            StreamTransformError::StoredRange(reason) => {
                write!(f, "the stored range is invalid: {reason}")
            }
            StreamTransformError::Read(reason) => {
                write!(f, "the stored prefix cannot be read: {reason}")
            }
        }
    }
}

impl std::error::Error for StreamTransformError {}

/// Builds the transform for `entry` from a bounded stored prefix. The first
/// zlib chunk selects the candidate table and verifies it.
pub fn prepare_stream_transform(
    entry: &Entry,
    main: &Source,
    alternates: &[Option<Source>],
    blocks: Vec<EncodedStreamBlock>,
) -> Result<StreamTransform, StreamTransformError> {
    if !matches!(entry.payload_transform, Ok(true)) {
        return Err(StreamTransformError::NoTransform);
    }
    let cipher = match &entry.payload_cipher {
        Ok(Some(cipher)) => cipher,
        Ok(None) => {
            return Err(StreamTransformError::NoDescriptor(
                "the transform field is present but shorter than a descriptor".to_string(),
            ));
        }
        Err(reason) => return Err(StreamTransformError::NoDescriptor(reason.clone())),
    };
    let table = match &entry.chunks {
        Ok(Some(table)) => table,
        Ok(None) => {
            return Err(StreamTransformError::NoChunkTable(
                "the row has no chunk table".to_string(),
            ));
        }
        Err(reason) => return Err(StreamTransformError::NoChunkTable(reason.clone())),
    };
    if blocks.is_empty() {
        return Err(StreamTransformError::NoKeyState);
    }
    let location = match &entry.location {
        Ok(Some(location)) => *location,
        Ok(None) => {
            return Err(StreamTransformError::StoredRange(
                "the row has no location record".to_string(),
            ));
        }
        Err(reason) => return Err(StreamTransformError::StoredRange(reason.clone())),
    };
    let source = entry
        .source(main, alternates)
        .map_err(|err| StreamTransformError::StoredRange(err.to_string()))?;
    let end = location
        .payload_offset
        .checked_add(location.stored_len)
        .ok_or_else(|| {
            StreamTransformError::StoredRange("the stored range overflows".to_string())
        })?;
    if end > source.len() {
        return Err(StreamTransformError::StoredRange(format!(
            "the stored range ends at {end:#x}, after the source ({:#x})",
            source.len()
        )));
    }
    let prefix_len = location.stored_len.min(PROBE_LIMIT);
    let mut prefix = source
        .slice(location.payload_offset, prefix_len)
        .map_err(|err| StreamTransformError::Read(err.to_string()))?;
    let mut bytes = Vec::with_capacity(prefix_len as usize);
    prefix
        .read_to_end(&mut bytes)
        .map_err(|err| StreamTransformError::Read(err.to_string()))?;
    let views: Vec<&dyn BlockDecrypt> = blocks
        .iter()
        .map(|block| block as &dyn BlockDecrypt)
        .collect();
    let (index, model) = select_stream_block(&bytes, table, cipher, &views).ok_or(
        StreamTransformError::Unverifiable(
            "no zlib chunk verified a recognized table and range rule",
        ),
    )?;
    let mut blocks = blocks;
    let block = blocks.swap_remove(index);
    Ok(StreamTransform::with_model(
        cipher.parameter,
        Arc::new(block),
        model,
    ))
}

/// The range rules that a row's first zlib chunk can verify. A single chunk
/// covers the whole stream, so it verifies the whole-range rule on its own. On
/// a multi-chunk row the partial rule is the only rule the first chunk can
/// verify for the rest of the stream.
fn candidate_models(chunk_count: usize) -> &'static [StreamModel] {
    if chunk_count == 1 {
        &[StreamModel::Partial, StreamModel::Whole]
    } else {
        &[StreamModel::Partial]
    }
}

/// The index of the candidate table whose keystream verifies the stream, and
/// the range rule it verifies.
///
/// A zlib chunk is decoded and checksummed before it is accepted. Chunks are
/// verified in order until one covers a byte that the two range rules treat
/// differently, which proves the rule for the whole stream. A stream that
/// extends beyond the leading region without such a chunk is refused: a later
/// copied chunk carries no checksum, so a wrong rule would not be detected.
fn select_stream_block(
    stored: &[u8],
    table: &ChunkTable,
    cipher: &CipherDescriptor,
    blocks: &[&dyn BlockDecrypt],
) -> Option<(usize, StreamModel)> {
    for &model in candidate_models(table.chunks.len()) {
        for (index, block) in blocks.iter().enumerate() {
            if verifies_stream(stored, table, cipher, *block, model) {
                return Some((index, model));
            }
        }
    }
    None
}

/// Whether `block` proves `model` over the whole stream. Every zlib chunk up
/// to the first one that separates the rules must inflate to its declared
/// logical size.
fn verifies_stream(
    stored: &[u8],
    table: &ChunkTable,
    cipher: &CipherDescriptor,
    block: &dyn BlockDecrypt,
    model: StreamModel,
) -> bool {
    let mut start = if table.encoding == 2 {
        ENCODING_2_PREFIX
    } else {
        0
    };
    // Transformed on demand, so a short probe stays cheap for the common
    // first-chunk case.
    let mut plain: Vec<u8> = Vec::new();
    let mut content_end = 0;
    for chunk in &table.chunks {
        let Some(compressed) = chunk.stored_len.checked_sub(chunk.padding) else {
            return false;
        };
        let Some(end) = start.checked_add(u64::from(compressed)) else {
            return false;
        };
        if end > stored.len() as u64 {
            return false;
        }
        if plain.len() < end as usize {
            let from = plain.len();
            plain.extend_from_slice(&stored[from..end as usize]);
            apply_transform(
                &mut plain[from..],
                from as u64,
                cipher.parameter,
                block,
                model,
            );
        }
        if chunk.method == ZLIB_METHOD {
            let mut decoder = ZlibDecoder::new(&plain[start as usize..end as usize]);
            let mut output = Vec::new();
            if decoder.read_to_end(&mut output).is_err()
                || output.len() != chunk.logical_len as usize
            {
                return false;
            }
            if separates_models(start, end) {
                return true;
            }
        }
        content_end = end;
        let Some(next) = start.checked_add(u64::from(chunk.stored_len)) else {
            return false;
        };
        start = next;
    }
    // Both rules agree over the whole leading region, so a stream that ends
    // there needs no separating chunk.
    content_end <= LEADING
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpf::metadata::Chunk;
    use crate::rpf::metadata::payload::{StreamModel, apply_transform, separates_models};
    use crate::rpf::metadata::transform::{BLOCK_LEN, BlockDecrypt};
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    struct Toy;

    impl BlockDecrypt for Toy {
        fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
            for (index, byte) in block.iter_mut().enumerate() {
                *byte = byte.wrapping_mul(31).wrapping_add(index as u8);
            }
        }
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::none());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn cipher() -> CipherDescriptor {
        CipherDescriptor {
            key_id: 0x1000_0000,
            kind: 0x11,
            parameter: [0x42; BLOCK_LEN],
        }
    }

    fn chunk(logical: usize, stored: usize, method: u8) -> Chunk {
        Chunk {
            logical_len: logical as u32,
            stored_len: stored as u32,
            padding: 0,
            compressed_len: stored as u32,
            method,
        }
    }

    /// Two chunks whose first zlib chunk ends inside the leading region, so
    /// only the second chunk separates the two range rules.
    fn two_chunks(model: StreamModel, second_is_zlib: bool) -> (Vec<u8>, ChunkTable) {
        let a = vec![0x31u8; 512];
        let b = vec![0x47u8; 4096];
        let ca = zlib(&a);
        let cb = if second_is_zlib { zlib(&b) } else { b.clone() };
        let mut stored = [ca.clone(), cb.clone()].concat();
        apply_transform(&mut stored, 0, cipher().parameter, &Toy, model);
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![
                chunk(a.len(), ca.len(), 3),
                chunk(b.len(), cb.len(), if second_is_zlib { 3 } else { 0 }),
            ],
        };
        (stored, table)
    }

    #[test]
    fn selection_verifies_a_second_chunk_when_the_first_is_short() {
        let (stored, table) = two_chunks(StreamModel::Partial, true);
        assert_eq!(
            select_stream_block(&stored, &table, &cipher(), &[&Toy]),
            Some((0, StreamModel::Partial))
        );
    }

    #[test]
    fn selection_refuses_a_multi_chunk_whole_range_stream() {
        // The whole-range rule is only used for a stream whose single chunk
        // verifies it. A multi-chunk row cannot be verified past a short first
        // chunk, so it must be refused rather than decoded with the partial
        // rule.
        let (stored, table) = two_chunks(StreamModel::Whole, true);
        assert_eq!(
            select_stream_block(&stored, &table, &cipher(), &[&Toy]),
            None
        );
    }

    #[test]
    fn selection_refuses_copied_bytes_that_hide_the_rule() {
        // The first chunk is too short to separate the rules and the second
        // is copied, so no checksum can prove the range.
        let (stored, table) = two_chunks(StreamModel::Partial, false);
        assert_eq!(
            select_stream_block(&stored, &table, &cipher(), &[&Toy]),
            None
        );
    }

    #[test]
    fn selection_accepts_a_stream_inside_the_leading_region() {
        let plain = vec![0x5Eu8; 500];
        let compressed = zlib(&plain);
        let mut stored = compressed.clone();
        apply_transform(
            &mut stored,
            0,
            cipher().parameter,
            &Toy,
            StreamModel::Partial,
        );
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(plain.len(), compressed.len(), 3)],
        };
        assert_eq!(
            select_stream_block(&stored, &table, &cipher(), &[&Toy]),
            Some((0, StreamModel::Partial))
        );
    }

    #[test]
    fn selection_accepts_the_whole_range_for_a_single_long_chunk() {
        let plain = vec![0x6Au8; 4096];
        let compressed = zlib(&plain);
        let mut stored = compressed.clone();
        apply_transform(&mut stored, 0, cipher().parameter, &Toy, StreamModel::Whole);
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(plain.len(), compressed.len(), 3)],
        };
        assert_eq!(
            select_stream_block(&stored, &table, &cipher(), &[&Toy]),
            Some((0, StreamModel::Whole))
        );
    }

    #[test]
    fn separating_ranges_follow_the_verified_regions() {
        assert!(!separates_models(0, 2048));
        assert!(separates_models(0, 2049));
        assert!(!separates_models(9216, 10_240));
        assert!(separates_models(10_240, 10_241));
        assert!(!separates_models(17_408, 18_432));
        assert!(separates_models(17_408, 18_433));
    }

    #[test]
    fn no_transform_is_reported() {
        let entry = Entry {
            row: 0,
            location: Ok(None),
            name_hash: Ok(None),
            name_key: Ok(None),
            chunks: Ok(None),
            payload_transform: Ok(false),
            payload_cipher: Ok(None),
            read_source: Ok(None),
            payload_end: None,
        };
        let file = tempfile::NamedTempFile::new().unwrap();
        let source = Source::open(file.path()).unwrap();
        assert!(matches!(
            prepare_stream_transform(&entry, &source, &[], Vec::new()),
            Err(StreamTransformError::NoTransform)
        ));
    }

    #[test]
    fn empty_key_state_is_reported_without_a_probe() {
        // The transform and descriptor are enough to reach the key-state
        // check; no stored bytes are read when no candidate exists.
        let entry = Entry {
            row: 0,
            location: Ok(None),
            name_hash: Ok(None),
            name_key: Ok(None),
            chunks: Ok(Some(ChunkTable {
                encoding: 3,
                chunks: vec![Chunk {
                    logical_len: 1,
                    stored_len: 16,
                    padding: 0,
                    compressed_len: 16,
                    method: 3,
                }],
            })),
            payload_transform: Ok(true),
            payload_cipher: Ok(Some(CipherDescriptor {
                key_id: 1,
                kind: 0x11,
                parameter: [0u8; 16],
            })),
            read_source: Ok(None),
            payload_end: None,
        };
        let file = tempfile::NamedTempFile::new().unwrap();
        let source = Source::open(file.path()).unwrap();
        assert!(matches!(
            prepare_stream_transform(&entry, &source, &[], Vec::new()),
            Err(StreamTransformError::NoKeyState)
        ));
    }

    #[test]
    fn the_whole_range_rule_is_limited_to_single_chunk_rows() {
        assert_eq!(
            candidate_models(1),
            &[StreamModel::Partial, StreamModel::Whole]
        );
        assert_eq!(candidate_models(0), &[StreamModel::Partial]);
        assert_eq!(candidate_models(2), &[StreamModel::Partial]);
        assert_eq!(candidate_models(64), &[StreamModel::Partial]);
    }
}
