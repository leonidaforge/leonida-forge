//! Selection and preparation of the payload-transform stream.
//!
//! The covered range is read from the descriptor's stream fields, so the
//! selection no longer guesses a range. The transformed bytes are produced on
//! read by [`StreamTransform`]; this module selects the right key table from
//! the archive data without decoding a whole resource.
//!
//! The selection probe uses the stored stream. For a chunked entry every zlib
//! chunk that fits in the probe must inflate to its declared logical size
//! under the candidate key state, and its Adler-32 must match. For a raw
//! DEFLATE entry, which has no checksum, the whole stream is read through the
//! transform in bounded steps and must decode to the declared logical size and
//! end at the last stored byte. A stream that cannot be verified this way is
//! refused rather than decoded speculatively.

use std::fmt;
use std::io::{self, Read};
use std::sync::Arc;

use flate2::read::ZlibDecoder;
use flate2::{Decompress, FlushDecompress, Status};
use lforge_binary::Source;

use super::stream_block::EncodedStreamBlock;
use crate::rpf::metadata::payload::{StreamTransform, apply_transform};
use crate::rpf::metadata::transform::{BLOCK_LEN, BlockDecrypt, CipherDescriptor, StreamRange};
use crate::rpf::metadata::{Chunk, ChunkTable, Entry};

/// Stored bytes read to select a key state for a chunked stream. The probe
/// decides selection only: reading and extraction stream the rest of the
/// stored payload through [`StreamTransform`].
pub const PROBE_LIMIT: u64 = 8 * 1024 * 1024;
/// Stored bytes read per step while decoding a raw DEFLATE stream.
const STREAM_STEP: usize = 64 * 1024;
/// Bytes inflated per step while verifying a chunk or a stream.
const INFLATE_STEP: usize = 64 * 1024;
const ZLIB_METHOD: u8 = 3;

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
        Ok(table) => table.as_ref(),
        Err(reason) => return Err(StreamTransformError::NoChunkTable(reason.clone())),
    };
    let range = match &entry.payload_range {
        Ok(Some(range)) => *range,
        Ok(None) => {
            return Err(StreamTransformError::NoDescriptor(
                "the transform descriptor has no stream range".to_string(),
            ));
        }
        Err(reason) => return Err(StreamTransformError::NoDescriptor(reason.clone())),
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
    let views: Vec<&dyn BlockDecrypt> = blocks
        .iter()
        .map(|block| block as &dyn BlockDecrypt)
        .collect();
    let base = match table {
        Some(table) => table
            .stored_prefix(location.stored_len)
            .map_err(|err| StreamTransformError::StoredRange(err.to_string()))?,
        None => 0,
    };
    let index = match table {
        Some(table) => {
            // Only selection reads a prefix; the stream itself is transformed
            // on demand when the payload is read.
            let probe_len = location.stored_len.min(PROBE_LIMIT);
            let mut prefix = source
                .slice(location.payload_offset, probe_len)
                .map_err(|err| StreamTransformError::Read(err.to_string()))?;
            let mut bytes = Vec::with_capacity(probe_len as usize);
            prefix
                .read_to_end(&mut bytes)
                .map_err(|err| StreamTransformError::Read(err.to_string()))?;
            if !probe_holds_first_chunk(table, base, &bytes) {
                return Err(StreamTransformError::Unverifiable(
                    "the first chunk is larger than the probe limit",
                ));
            }
            select_chunk_block(
                &bytes,
                table,
                base,
                location.stored_len,
                cipher,
                range,
                &views,
            )
        }
        None if location.mode == 1 => {
            // A raw DEFLATE stream has no checksum, so it is decoded to its
            // end in bounded steps and must reach its declared size.
            select_deflate_block(
                source,
                location.payload_offset,
                location.stored_len,
                location.logical_len,
                cipher,
                range,
                &views,
            )
        }
        None => None,
    }
    .ok_or(StreamTransformError::Unverifiable(
        "no candidate key state verified the stored stream",
    ))?;
    let mut blocks = blocks;
    let block = blocks.swap_remove(index);
    Ok(StreamTransform::new(
        cipher.parameter,
        Arc::new(block),
        range,
        base,
        location.stored_len - base,
    ))
}

/// Whether the probe holds the whole first chunk, without which no candidate
/// can be tested. A table with no chunk has nothing to verify either.
fn probe_holds_first_chunk(table: &ChunkTable, prefix: u64, probe: &[u8]) -> bool {
    let Some(first) = table.chunks.first() else {
        return true;
    };
    let Some(compressed) = first.stored_len.checked_sub(first.padding) else {
        return false;
    };
    prefix
        .checked_add(u64::from(compressed))
        .is_some_and(|end| end <= probe.len() as u64)
}

/// The index of the candidate key state under which every zlib chunk the probe
/// holds inflates to its declared size.
fn select_chunk_block(
    stored: &[u8],
    table: &ChunkTable,
    prefix: u64,
    stored_len: u64,
    cipher: &CipherDescriptor,
    range: StreamRange,
    blocks: &[&dyn BlockDecrypt],
) -> Option<usize> {
    blocks
        .iter()
        .position(|block| verifies_chunks(stored, table, prefix, stored_len, cipher, *block, range))
}

/// Whether `block` decodes every zlib chunk the probe holds to its declared
/// logical size under `range`. Each zlib chunk carries an Adler-32, so a wrong
/// key state or range fails. A probe that ends inside a chunk verifies the
/// chunks before it; a stream with no zlib chunk in the probe cannot be
/// verified and is refused.
fn verifies_chunks(
    stored: &[u8],
    table: &ChunkTable,
    prefix: u64,
    stored_len: u64,
    cipher: &CipherDescriptor,
    block: &dyn BlockDecrypt,
    range: StreamRange,
) -> bool {
    let Some(stream_len) = stored_len.checked_sub(prefix) else {
        return false;
    };
    let mut start = prefix;
    // Transformed on demand, so a short probe stays cheap for the common
    // first-chunk case.
    let mut plain: Vec<u8> = Vec::new();
    let mut verified = false;
    for chunk in &table.chunks {
        let Some(compressed) = chunk.stored_len.checked_sub(chunk.padding) else {
            return false;
        };
        let Some(end) = start.checked_add(u64::from(compressed)) else {
            return false;
        };
        if end > stored.len() as u64 {
            // The probe ends here. Everything before it has been verified
            // against the real stream length, which is what the tail region
            // is measured from.
            break;
        }
        if plain.len() < end as usize {
            let from = plain.len();
            plain.extend_from_slice(&stored[from..end as usize]);
            // The stored prefix is not part of the transformed stream, and
            // the counter starts at the first chunk byte.
            let start_at = from.max(prefix as usize);
            if start_at < end as usize {
                apply_transform(
                    &mut plain[start_at..end as usize],
                    start_at as u64 - prefix,
                    stream_len,
                    cipher.parameter,
                    block,
                    range,
                );
            }
        }
        if !inflates_to(chunk, &plain[start as usize..end as usize]) {
            return false;
        }
        verified |= chunk.method == ZLIB_METHOD;
        let Some(next) = start.checked_add(u64::from(chunk.stored_len)) else {
            return false;
        };
        start = next;
    }
    verified
}

/// Whether a chunk's stored bytes inflate to exactly its declared logical
/// size. A zlib chunk also has to reach its Adler-32. Output is counted in a
/// fixed buffer, so a wrong size fails without allocating the decoded chunk.
fn inflates_to(chunk: &Chunk, stored: &[u8]) -> bool {
    if chunk.method != ZLIB_METHOD {
        return true;
    }
    let expected = u64::from(chunk.logical_len);
    let mut decoder = ZlibDecoder::new(stored);
    let mut buffer = [0u8; INFLATE_STEP];
    let mut total = 0u64;
    loop {
        match decoder.read(&mut buffer) {
            Ok(0) => return total == expected,
            Ok(n) => {
                total += n as u64;
                if total > expected {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
}

/// The index of the candidate key state under which the raw DEFLATE stream
/// decodes to `logical_len` bytes and ends at the last stored byte.
fn select_deflate_block(
    source: &Source,
    offset: u64,
    stored_len: u64,
    logical_len: u64,
    cipher: &CipherDescriptor,
    range: StreamRange,
    blocks: &[&dyn BlockDecrypt],
) -> Option<usize> {
    blocks.iter().position(|block| {
        verifies_deflate(
            source,
            offset,
            stored_len,
            logical_len,
            cipher,
            *block,
            range,
        )
    })
}

/// Whether `block` decodes the stored bytes under `range` to exactly
/// `logical_len` bytes, ending at the last stored byte.
///
/// The stream is read through the transform in bounded steps, so the stored
/// size never has to fit in memory. Raw DEFLATE has no checksum: the exact
/// size, the stream end and zero trailing bytes are structural checks, not
/// authentication.
fn verifies_deflate(
    source: &Source,
    offset: u64,
    stored_len: u64,
    logical_len: u64,
    cipher: &CipherDescriptor,
    block: &dyn BlockDecrypt,
    range: StreamRange,
) -> bool {
    let Ok(slice) = source.slice(offset, stored_len) else {
        return false;
    };
    let mut reader = Transformed {
        source: slice,
        stream_len: stored_len,
        parameter: cipher.parameter,
        block,
        range,
        pos: 0,
    };
    let mut decoder = Decompress::new(false);
    let mut input = [0u8; STREAM_STEP];
    let mut output = [0u8; INFLATE_STEP];
    let mut filled = 0usize;
    let mut consumed = 0usize;
    let mut produced = 0u64;
    loop {
        if consumed == filled {
            match reader.read(&mut input) {
                Ok(0) => return false,
                Ok(n) => {
                    filled = n;
                    consumed = 0;
                }
                Err(_) => return false,
            }
        }
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let Ok(status) =
            decoder.decompress(&input[consumed..filled], &mut output, FlushDecompress::None)
        else {
            return false;
        };
        let took = (decoder.total_in() - before_in) as usize;
        consumed += took;
        produced += decoder.total_out() - before_out;
        if produced > logical_len {
            return false;
        }
        if status == Status::StreamEnd {
            // Raw DEFLATE rows may store zero padding after the stream. Any
            // other trailing byte is unexplained and refuses the candidate.
            return produced == logical_len
                && trailing_is_zero(&mut reader, &input[consumed..filled]);
        }
        if took == 0 {
            return false;
        }
    }
}

/// Whether every stored byte after the DEFLATE stream is zero.
fn trailing_is_zero(reader: &mut Transformed<'_>, rest: &[u8]) -> bool {
    if !rest.iter().all(|byte| *byte == 0) {
        return false;
    }
    let mut buffer = [0u8; STREAM_STEP];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return true,
            Ok(n) if buffer[..n].iter().all(|byte| *byte == 0) => {}
            _ => return false,
        }
    }
}

/// Stored bytes with the payload transform applied on read.
struct Transformed<'a> {
    source: Source,
    stream_len: u64,
    parameter: [u8; BLOCK_LEN],
    block: &'a dyn BlockDecrypt,
    range: StreamRange,
    pos: u64,
}

impl Read for Transformed<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let n = self.source.read(buffer)?;
        apply_transform(
            &mut buffer[..n],
            self.pos,
            self.stream_len,
            self.parameter,
            self.block,
            self.range,
        );
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpf::metadata::Chunk;
    use crate::rpf::metadata::payload::apply_transform;
    use crate::rpf::metadata::transform::{BLOCK_LEN, BlockDecrypt, StreamRange};
    use crate::rpf::metadata::{Payload, PayloadSource};
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

    /// The shape `+0x18 = +0x20 = 0x400`, `+0x28 = 0x1C00`, `+0x30 = 0`.
    fn common() -> StreamRange {
        StreamRange::from_parts(0x800, 0x1C00, 0x400, 0x2000, 0).unwrap()
    }

    /// A range that covers every stored position.
    fn whole() -> StreamRange {
        StreamRange::from_parts(0, 0, 16, 16, 0).unwrap()
    }

    #[test]
    fn an_encoding_2_prefix_does_not_shift_the_counter() {
        let text = vec![0x4Du8; 6000];
        let compressed = zlib(&text);
        let body_len = compressed.len() as u64;
        let mut body = compressed.clone();
        apply_transform(&mut body, 0, body_len, cipher().parameter, &Toy, common());
        let mut stored = vec![0u8; 16];
        stored.extend_from_slice(&body);
        let table = ChunkTable {
            encoding: 2,
            chunks: vec![chunk(text.len(), body.len(), 3)],
        };
        // The prefix is 16 bytes; the counter still starts at the first chunk
        // byte, so the same transform decodes the body.
        assert!(verifies_chunks(
            &stored,
            &table,
            16,
            stored.len() as u64,
            &cipher(),
            &Toy,
            common()
        ));

        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut file = temp.as_file();
        file.write_all(&stored).unwrap();
        file.flush().unwrap();
        let source = Source::open(temp.path()).unwrap();
        let transform =
            StreamTransform::new(cipher().parameter, Arc::new(Toy), common(), 16, body_len);
        let mut payload = Payload::chunked(
            0,
            PayloadSource::transformed(source, transform),
            text.len() as u64,
            &table,
        )
        .unwrap();
        let mut out = Vec::new();
        payload.read_to_end(&mut out).unwrap();
        assert_eq!(out, text);
    }

    #[test]
    fn a_truncated_transformed_chunk_is_refused() {
        let text = vec![0x61u8; 4000];
        let compressed = zlib(&text);
        let mut stored = compressed.clone();
        let stored_len = stored.len() as u64;
        apply_transform(
            &mut stored,
            0,
            stored_len,
            cipher().parameter,
            &Toy,
            common(),
        );
        stored.truncate(stored.len() - 8);
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(text.len(), compressed.len(), 3)],
        };
        assert!(!verifies_chunks(
            &stored,
            &table,
            0,
            stored.len() as u64,
            &cipher(),
            &Toy,
            common()
        ));
    }

    fn deflate_verifies(stored: &[u8], logical: u64, range: StreamRange) -> bool {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut file = temp.as_file();
        file.write_all(stored).unwrap();
        file.flush().unwrap();
        let source = Source::open(temp.path()).unwrap();
        verifies_deflate(
            &source,
            0,
            stored.len() as u64,
            logical,
            &cipher(),
            &Toy,
            range,
        )
    }

    #[test]
    fn raw_deflate_verification_accepts_only_zero_trailing_bytes() {
        use flate2::Compression;
        use flate2::write::DeflateEncoder;

        let text: Vec<u8> = (0..40_000u32)
            .map(|value| (value.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&text).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut stored = compressed.clone();
        let stored_len = stored.len() as u64;
        let range = common();
        apply_transform(&mut stored, 0, stored_len, cipher().parameter, &Toy, range);
        assert!(deflate_verifies(&stored, text.len() as u64, range));

        stored.extend_from_slice(&[0u8; 5]);
        assert!(deflate_verifies(&stored, text.len() as u64, range));
        let last = stored.len() - 1;
        stored[last] = 1;
        assert!(!deflate_verifies(&stored, text.len() as u64, range));
    }

    #[test]
    fn a_zero_stream_range_is_not_usable() {
        assert!(StreamRange::parse(&[0u8; 64]).is_none());
        assert!(StreamRange::parse(&[0u8; 0x30]).is_none());
        let mut value = [0u8; 0x38];
        value[0x20] = 0x10;
        value[0x21] = 0x00;
        value[0x22] = 0x00;
        value[0x23] = 0x00;
        let range = StreamRange::parse(&value).expect("a 0x1000 step");
        assert!(range.is_whole());
    }

    #[test]
    fn a_descriptor_with_no_covered_bytes_is_rejected() {
        // `a = b = t = 0` with a non-zero gap covers nothing.
        let mut value = [0u8; 0x38];
        value[0x28] = 5;
        assert!(StreamRange::parse(&value).is_none());
        // A trailing region needs a periodic step to measure the stream
        // against, so `b = c = 0` is refused even with a tail.
        let mut tail = [0u8; 0x38];
        tail[0x30] = 1;
        assert!(StreamRange::parse(&tail).is_none());
    }

    #[test]
    fn a_descriptor_whose_field_sums_overflow_is_rejected() {
        let mut leading = [0u8; 0x38];
        leading[0x18..0x20].copy_from_slice(&u64::MAX.to_le_bytes());
        leading[0x20] = 1;
        assert!(StreamRange::parse(&leading).is_none());
        let mut step = [0u8; 0x38];
        step[0x20..0x28].copy_from_slice(&u64::MAX.to_le_bytes());
        step[0x28] = 1;
        assert!(StreamRange::parse(&step).is_none());
    }

    #[test]
    fn a_tail_longer_than_the_stream_covers_all_of_it() {
        let range = StreamRange::from_parts(0, 1, 1, 1, 4096).unwrap();
        assert!(range.covers(0, 100));
        assert!(range.covers(99, 100));
    }

    #[test]
    fn a_probe_selects_from_the_chunks_it_holds() {
        let (stored, table) = two_chunks(common(), true);
        let first_end = usize::try_from(table.chunks[0].stored_len).unwrap();
        assert_eq!(
            select_chunk_block(
                &stored[..first_end],
                &table,
                0,
                stored.len() as u64,
                &cipher(),
                common(),
                &[&Toy]
            ),
            Some(0)
        );
        // A probe that ends inside the first chunk verifies nothing.
        assert_eq!(
            select_chunk_block(
                &stored[..first_end - 1],
                &table,
                0,
                stored.len() as u64,
                &cipher(),
                common(),
                &[&Toy]
            ),
            None
        );
    }

    #[test]
    fn raw_deflate_verification_rejects_wrong_sizes_and_truncation() {
        use flate2::write::DeflateEncoder;

        let text: Vec<u8> = (0..40_000u32)
            .map(|value| (value.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&text).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut stored = compressed.clone();
        let range = common();
        let stored_len = stored.len() as u64;
        apply_transform(&mut stored, 0, stored_len, cipher().parameter, &Toy, range);
        let logical = text.len() as u64;
        assert!(deflate_verifies(&stored, logical, range));
        assert!(!deflate_verifies(&stored, logical + 1, range));
        assert!(!deflate_verifies(&stored, logical - 1, range));
        let mut truncated = stored.clone();
        truncated.truncate(stored.len() - 4);
        assert!(!deflate_verifies(&truncated, logical, range));
    }

    fn two_chunks(range: StreamRange, second_is_zlib: bool) -> (Vec<u8>, ChunkTable) {
        let a = vec![0x31u8; 512];
        let b = vec![0x47u8; 4096];
        let ca = zlib(&a);
        let cb = if second_is_zlib { zlib(&b) } else { b.clone() };
        let mut stored = [ca.clone(), cb.clone()].concat();
        let stored_len = stored.len() as u64;
        apply_transform(&mut stored, 0, stored_len, cipher().parameter, &Toy, range);
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![
                chunk(a.len(), ca.len(), 3),
                chunk(b.len(), cb.len(), if second_is_zlib { 3 } else { 0 }),
            ],
        };
        (stored, table)
    }

    // The common range covers the first 2048 bytes, then the first 1024 bytes
    // of every 8192-byte buffer from 9216, so the second chunk of
    // `two_chunks` crosses the first plaintext gap only under the common rule.
    #[test]
    fn selection_verifies_a_second_chunk_when_the_first_is_short() {
        let (stored, table) = two_chunks(common(), true);
        assert_eq!(
            select_chunk_block(
                &stored,
                &table,
                0,
                stored.len() as u64,
                &cipher(),
                common(),
                &[&Toy]
            ),
            Some(0)
        );
    }

    #[test]
    fn selection_refuses_a_range_the_chunk_does_not_verify() {
        let (stored, table) = two_chunks(whole(), true);
        assert_eq!(
            select_chunk_block(
                &stored,
                &table,
                0,
                stored.len() as u64,
                &cipher(),
                common(),
                &[&Toy]
            ),
            None
        );
    }

    #[test]
    fn selection_requires_a_verifiable_chunk() {
        // A stream of copied chunks carries no checksum, so no candidate can
        // be verified and the row is refused.
        let bytes = vec![0x22u8; 4096];
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(bytes.len(), bytes.len(), 0)],
        };
        assert_eq!(
            select_chunk_block(
                &bytes,
                &table,
                0,
                bytes.len() as u64,
                &cipher(),
                whole(),
                &[&Toy]
            ),
            None
        );
    }

    #[test]
    fn selection_accepts_a_stream_inside_the_leading_region() {
        let plain = vec![0x5Eu8; 500];
        let compressed = zlib(&plain);
        let mut stored = compressed.clone();
        let stored_len = stored.len() as u64;
        apply_transform(
            &mut stored,
            0,
            stored_len,
            cipher().parameter,
            &Toy,
            common(),
        );
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(plain.len(), compressed.len(), 3)],
        };
        assert_eq!(
            select_chunk_block(
                &stored,
                &table,
                0,
                stored.len() as u64,
                &cipher(),
                common(),
                &[&Toy]
            ),
            Some(0)
        );
    }

    #[test]
    fn selection_accepts_the_whole_range_for_a_single_long_chunk() {
        let plain = vec![0x6Au8; 4096];
        let compressed = zlib(&plain);
        let mut stored = compressed.clone();
        let stored_len = stored.len() as u64;
        apply_transform(
            &mut stored,
            0,
            stored_len,
            cipher().parameter,
            &Toy,
            whole(),
        );
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(plain.len(), compressed.len(), 3)],
        };
        assert_eq!(
            select_chunk_block(
                &stored,
                &table,
                0,
                stored.len() as u64,
                &cipher(),
                whole(),
                &[&Toy]
            ),
            Some(0)
        );
    }

    #[test]
    fn the_common_range_skips_the_plaintext_gaps() {
        let range = common();
        let len = 30_000;
        assert!(range.covers(0, len));
        assert!(range.covers(2047, len));
        assert!(!range.covers(2048, len));
        assert!(!range.covers(9215, len));
        assert!(range.covers(9216, len));
        assert!(range.covers(10_239, len));
        assert!(!range.covers(10_240, len));
        assert!(range.covers(17_408, len));
        assert!(range.covers(18_431, len));
        assert!(!range.covers(18_432, len));
        assert!(!range.is_whole());
        assert!(whole().is_whole());
    }

    #[test]
    fn a_contiguous_shape_with_no_gap_is_the_whole_range() {
        // `+0x18 = 0`, `+0x20 = 0x1000`, `+0x28 = 0` abuts its buffers.
        let range = StreamRange::from_parts(0x1000, 0, 0x1000, 0x1000, 0).unwrap();
        assert!(range.is_whole());
        let len = 0x2000_0000;
        assert!(range.covers(0, len));
        assert!(range.covers(0x1000, len));
        assert!(range.covers(0x1234_5678, len));
    }

    #[test]
    fn the_trailing_region_starts_at_the_end_of_the_stream() {
        let range = StreamRange::from_parts(0x2000, 0x31000, 0x1000, 0x32000, 0x1000).unwrap();
        assert!(range.covers(0x2000_0000 - 0x1000, 0x2000_0000));
        assert!(range.covers(0x2000_0000 - 1, 0x2000_0000));
        assert!(!range.covers(0x2000_0000 - 0x1001, 0x2000_0000));
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
            payload_range: Ok(None),
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
            payload_range: Ok(Some(whole())),
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
}
