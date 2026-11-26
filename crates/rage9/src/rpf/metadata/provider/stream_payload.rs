//! Selection and preparation of the payload-transform stream.
//!
//! The covered range depends on the descriptor's stream fields. For the common
//! shape it covers the first 2048 bytes, the first 1024 bytes at offset 9216
//! and the first 1024 bytes of every 8192 bytes after that. Another shape
//! covers the whole stored range. The transformed bytes are produced on read
//! by [`StreamTransform`]; this module selects the right key table and range
//! from the archive data without decoding a whole resource.
//!
//! The selection probe uses the first zlib chunk. It applies the partial range
//! to each candidate table and requires the chunk to inflate to its declared
//! logical size. The whole-range rule is tried only for a row with a single
//! chunk, where that chunk covers the entire stream and therefore verifies the
//! rule on its own; a multi-chunk row with the partial rule cannot verify a
//! different range from its first chunk. A resource whose stream cannot be
//! verified this way is refused rather than decoded speculatively.

use std::fmt;
use std::io::Read;
use std::sync::Arc;

use flate2::read::ZlibDecoder;
use lforge_binary::Source;

use super::stream_block::EncodedStreamBlock;
use crate::rpf::metadata::payload::{StreamModel, StreamTransform, apply_transform};
use crate::rpf::metadata::transform::CipherDescriptor;
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
    let (index, model) = select_stream_block(&bytes, table, cipher, &blocks).ok_or(
        StreamTransformError::Unverifiable(
            "the first zlib chunk did not match any recognized table",
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

/// The index of the candidate table whose keystream makes the first zlib
/// chunk inflate to its declared logical size.
fn select_stream_block(
    stored: &[u8],
    table: &ChunkTable,
    cipher: &CipherDescriptor,
    blocks: &[EncodedStreamBlock],
) -> Option<(usize, StreamModel)> {
    let mut start = if table.encoding == 2 {
        ENCODING_2_PREFIX
    } else {
        0
    };
    for chunk in &table.chunks {
        if chunk.method == ZLIB_METHOD {
            let compressed = chunk.stored_len.checked_sub(chunk.padding)?;
            let end = start.checked_add(u64::from(compressed))?;
            if end > stored.len() as u64 {
                return None;
            }
            let (start, end) = (start as usize, end as usize);
            for &model in candidate_models(table.chunks.len()) {
                for (index, block) in blocks.iter().enumerate() {
                    let mut plain = stored[..end].to_vec();
                    apply_transform(&mut plain, 0, cipher.parameter, block, model);
                    let mut decoder = ZlibDecoder::new(&plain[start..end]);
                    let mut output = Vec::new();
                    if decoder.read_to_end(&mut output).is_ok()
                        && output.len() == chunk.logical_len as usize
                    {
                        return Some((index, model));
                    }
                }
            }
            return None;
        }
        start = start.checked_add(u64::from(chunk.stored_len))?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpf::metadata::Chunk;

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
