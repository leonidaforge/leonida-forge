//! The contents of an entry: its stored bytes, a raw DEFLATE stream, or
//! chunks that are copied or hold one zlib stream each.
//!
//! Every size is checked against the table of contents, and every failure
//! is an error. The engine instead traps on decoder failures and does not
//! compare sizes.
//!
//! A zlib chunk is decoded and verified completely, up to its checksum,
//! before any of its bytes are returned, and the bytes returned are the ones
//! that were verified: they are kept in memory or, for large chunks, in an
//! anonymous temporary file, not decoded again. A raw DEFLATE entry has no
//! checksum, and its end is checked only when it is read to the end: a
//! partial read returns the bytes decoded so far without knowing whether the
//! rest of the stream is intact.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::{Decompress, FlushDecompress, Status};
use lforge_binary::Source;

use super::transform::{BLOCK_LEN, BlockDecrypt};
use super::{Chunk, ChunkTable, Error, invalid};

/// Stored bytes read per decoder step.
const INPUT_LEN: usize = 64 * 1024;
/// Bytes decoded per step when skipping to a position.
const SKIP_LEN: usize = 64 * 1024;
/// The chunk method that holds a zlib stream. The others are copied.
const ZLIB_METHOD: u8 = 3;
/// Encoding-2 entries store a 16-byte prefix before the first chunk. The
/// chunk table measures only the chunks: on real rows their stored sizes sum
/// to exactly 16 less than the entry's stored size, and the first zlib stream
/// starts at offset 16. The prefix's meaning is not established, but its
/// length is the same on every observed entry. It is skipped only for
/// encoding 2; encodings 3 and 4 start their chunks at offset 0.
const ENCODING_2_PREFIX: u64 = 16;
/// Zlib chunks up to this size are kept in memory while they are read.
/// Larger ones are kept in a temporary file.
const CHUNK_BUFFER_LEN: u64 = 1024 * 1024;
/// For reads that cannot be cancelled.
static NEVER: AtomicBool = AtomicBool::new(false);

/// The verified payload-transform regions, in stored bytes.
pub(crate) const LEADING: u64 = 2048;
const BUFFER: u64 = 9216;
const BUFFER_STEP: u64 = 8192;
const BUFFER_PREFIX: u64 = 1024;

/// The counter-mode keystream of an authenticated payload transform. The
/// covered range is the descriptor-dependent partial range or, where the first
/// zlib chunk verifies it, the whole stored range.
#[derive(Clone)]
pub struct StreamTransform {
    parameter: [u8; BLOCK_LEN],
    block: Arc<dyn BlockDecrypt + Send + Sync>,
    model: StreamModel,
}

impl StreamTransform {
    pub fn new(parameter: [u8; BLOCK_LEN], block: Arc<dyn BlockDecrypt + Send + Sync>) -> Self {
        Self {
            parameter,
            block,
            model: StreamModel::Partial,
        }
    }

    pub(crate) fn with_model(
        parameter: [u8; BLOCK_LEN],
        block: Arc<dyn BlockDecrypt + Send + Sync>,
        model: StreamModel,
    ) -> Self {
        Self {
            parameter,
            block,
            model,
        }
    }

    fn apply(&self, buf: &mut [u8], absolute: u64) {
        apply_transform(buf, absolute, self.parameter, &*self.block, self.model);
    }
}

/// Applies the verified payload-transform regions to `buf`, which starts at
/// `origin` within the entry's stored range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamModel {
    /// The verified first-2048 and later-buffer regions.
    Partial,
    /// The whole stored range, used only for a single-chunk stream where the
    /// verified regions do not verify it.
    Whole,
}

pub(crate) fn apply_transform(
    buf: &mut [u8],
    origin: u64,
    parameter: [u8; BLOCK_LEN],
    block: &dyn BlockDecrypt,
    model: StreamModel,
) {
    if model == StreamModel::Whole {
        if buf.is_empty() {
            return;
        }
        let end = origin + buf.len() as u64;
        let first = origin / BLOCK_LEN as u64;
        let last = (end - 1) / BLOCK_LEN as u64;
        for index in first..=last {
            let start = index * BLOCK_LEN as u64;
            let from = start.max(origin);
            let to = (start + BLOCK_LEN as u64).min(end);
            let mut counter = add_be(parameter, index);
            block.decrypt_block(&mut counter);
            for offset in from..to {
                buf[(offset - origin) as usize] ^= counter[(offset - start) as usize];
            }
        }
        return;
    }
    if buf.is_empty() {
        return;
    }
    let end = origin + buf.len() as u64;
    let first = origin / BLOCK_LEN as u64;
    let last = (end - 1) / BLOCK_LEN as u64;
    for index in first..=last {
        let start = index * BLOCK_LEN as u64;
        let from = start.max(origin);
        let to = (start + BLOCK_LEN as u64).min(end);
        if !is_transformed(from) {
            continue;
        }
        let mut counter = add_be(parameter, index);
        block.decrypt_block(&mut counter);
        for offset in from..to {
            buf[(offset - origin) as usize] ^= counter[(offset - start) as usize];
        }
    }
}

impl std::fmt::Debug for StreamTransform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamTransform")
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

pub(crate) fn is_transformed(offset: u64) -> bool {
    offset < LEADING || (offset >= BUFFER && (offset - BUFFER) % BUFFER_STEP < BUFFER_PREFIX)
}

/// Whether `[start, end)` holds a byte above the leading region that the
/// partial rule leaves in plaintext, which the whole-range rule transforms.
/// Such a verified chunk proves which rule applies.
pub(crate) fn separates_models(start: u64, end: u64) -> bool {
    let mut at = start.max(LEADING);
    while at < end {
        if !is_transformed(at) {
            return true;
        }
        at = if at < BUFFER {
            BUFFER
        } else {
            BUFFER + (at - BUFFER) / BUFFER_STEP * BUFFER_STEP + BUFFER_PREFIX
        };
    }
    false
}

/// Stored bytes, with the payload transform applied on read when present.
#[derive(Clone)]
pub(crate) struct PayloadSource {
    source: Source,
    origin: u64,
    transform: Option<StreamTransform>,
    pos: u64,
}

impl PayloadSource {
    pub(super) fn plain(source: Source) -> Self {
        Self {
            source,
            origin: 0,
            transform: None,
            pos: 0,
        }
    }

    pub(super) fn transformed(source: Source, transform: StreamTransform) -> Self {
        Self {
            source,
            origin: 0,
            transform: Some(transform),
            pos: 0,
        }
    }

    pub(super) fn len(&self) -> u64 {
        self.source.len()
    }

    pub(super) fn slice(&self, offset: u64, len: u64) -> io::Result<Self> {
        let origin = self
            .origin
            .checked_add(offset)
            .ok_or_else(|| bad("the stored slice overflows"))?;
        Ok(Self {
            source: self.source.slice(offset, len)?,
            origin,
            transform: self.transform.clone(),
            pos: 0,
        })
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut source = self.source.clone();
        source.seek(SeekFrom::Start(offset))?;
        let n = source.read(buf)?;
        if let Some(transform) = &self.transform {
            transform.apply(&mut buf[..n], self.origin + offset);
        }
        Ok(n)
    }
}

impl Read for PayloadSource {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len() {
            return Ok(0);
        }
        let room = usize::try_from(self.len() - self.pos).unwrap_or(usize::MAX);
        let take = buf.len().min(room);
        let n = self.read_at(self.pos, &mut buf[..take])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for PayloadSource {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.len().checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        self.pos = target.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek to an invalid position")
        })?;
        Ok(self.pos)
    }
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}

fn bad(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// One DEFLATE stream over stored bytes that must decode to exactly `len`
/// bytes.
struct Inflater {
    stored: PayloadSource,
    /// Whether the stream must use all stored bytes, as a chunk's does.
    exact_input: bool,
    decompress: Decompress,
    input: Vec<u8>,
    start: usize,
    end: usize,
    len: u64,
    out: u64,
    finished: bool,
}

impl Inflater {
    fn new(stored: PayloadSource, zlib: bool, exact_input: bool, len: u64) -> Self {
        Self {
            stored,
            exact_input,
            decompress: Decompress::new(zlib),
            input: vec![0; INPUT_LEN],
            start: 0,
            end: 0,
            len,
            out: 0,
            finished: false,
        }
    }

    /// Runs the decoder once into `out`. Returns the bytes produced and
    /// whether the stream ended.
    fn step(&mut self, out: &mut [u8], cancel: &AtomicBool) -> io::Result<(usize, bool)> {
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        if self.start == self.end {
            self.start = 0;
            self.end = self.stored.read(&mut self.input)?;
        }
        let has_input = self.start < self.end;
        let (in_before, out_before) = (self.decompress.total_in(), self.decompress.total_out());
        let status = self
            .decompress
            .decompress(
                &self.input[self.start..self.end],
                out,
                FlushDecompress::None,
            )
            .map_err(|err| bad(format!("the compressed data is invalid: {err}")))?;
        let consumed = (self.decompress.total_in() - in_before) as usize;
        let produced = (self.decompress.total_out() - out_before) as usize;
        self.start += consumed;
        let ended = status == Status::StreamEnd;
        if !ended && consumed == 0 && produced == 0 {
            return Err(bad(if has_input {
                "the decoder makes no progress"
            } else {
                "the compressed data ends before its stream does"
            }));
        }
        Ok((produced, ended))
    }

    /// Requires the end of the stream, with no further output.
    fn finish(&mut self, cancel: &AtomicBool) -> io::Result<()> {
        let mut scratch = [0; 1];
        loop {
            let (produced, ended) = self.step(&mut scratch, cancel)?;
            if produced > 0 {
                return Err(bad(format!(
                    "the stream holds more than the declared {} bytes",
                    self.len
                )));
            }
            if ended {
                break;
            }
        }
        if self.exact_input && self.decompress.total_in() != self.stored.len() {
            return Err(bad(format!(
                "the stream ends after {} of its {} compressed bytes",
                self.decompress.total_in(),
                self.stored.len()
            )));
        }
        self.finished = true;
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8], cancel: &AtomicBool) -> io::Result<usize> {
        let remaining = self.len - self.out;
        if self.finished || buf.is_empty() {
            return Ok(0);
        }
        if remaining == 0 {
            self.finish(cancel)?;
            return Ok(0);
        }
        let max = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        loop {
            let (produced, ended) = self.step(&mut buf[..max], cancel)?;
            self.out += produced as u64;
            if ended && self.out != self.len {
                return Err(bad(format!(
                    "the stream ends after {} of the declared {} bytes",
                    self.out, self.len
                )));
            }
            if self.out == self.len {
                self.finish(cancel)?;
            }
            if produced > 0 {
                return Ok(produced);
            }
        }
    }

    /// Decodes the whole stream into `out` and checks its end.
    fn decode_into(&mut self, out: &mut impl Write, cancel: &AtomicBool) -> io::Result<()> {
        let mut buf = vec![0; SKIP_LEN];
        while self.out < self.len {
            match self.read(&mut buf, cancel)? {
                0 => return Err(bad("the stream ends early")),
                n => out.write_all(&buf[..n])?,
            }
        }
        // Checks the end of the stream, also of an empty one.
        self.read(&mut [0; 1], cancel)?;
        Ok(())
    }

    /// Decodes and discards bytes up to `target`.
    fn skip_to(&mut self, target: u64, cancel: &AtomicBool) -> io::Result<()> {
        if self.out >= target {
            return Ok(());
        }
        let mut scratch = vec![0; SKIP_LEN];
        while self.out < target {
            let want = usize::try_from(target - self.out).map_or(SKIP_LEN, |n| n.min(SKIP_LEN));
            if self.read(&mut scratch[..want], cancel)? == 0 {
                return Err(bad("the stream ends before the position"));
            }
        }
        Ok(())
    }
}

/// A chunk and where it starts.
struct Span {
    logical: u64,
    stored: u64,
    chunk: Chunk,
}

impl Span {
    fn logical_end(&self) -> u64 {
        self.logical + u64::from(self.chunk.logical_len)
    }
}

enum Kind {
    /// The stored bytes are the contents.
    Stored(PayloadSource),
    /// One raw DEFLATE stream from the start of the stored bytes.
    Deflate {
        stored: PayloadSource,
        inflater: Option<Box<Inflater>>,
    },
    Chunked {
        stored: PayloadSource,
        spans: Vec<Span>,
        /// The zlib chunk read last, by chunk number.
        current: Option<(usize, Decoded)>,
    },
}

/// The contents of a zlib chunk whose stream was decoded and checked
/// completely.
enum Decoded {
    Buffered(Vec<u8>),
    /// A chunk larger than [`CHUNK_BUFFER_LEN`], in a temporary file.
    Spooled(Source),
}

/// The contents of an entry, readable and seekable. Each value keeps its
/// own position and decoder state.
pub struct Payload {
    len: u64,
    pos: u64,
    kind: Kind,
}

impl Payload {
    pub(super) fn stored(source: PayloadSource) -> Self {
        Self {
            len: source.len(),
            pos: 0,
            kind: Kind::Stored(source),
        }
    }

    pub(super) fn deflate(stored: PayloadSource, len: u64) -> Self {
        Self {
            len,
            pos: 0,
            kind: Kind::Deflate {
                stored,
                inflater: None,
            },
        }
    }

    /// Checks the chunk table against the entry's sizes and the stored
    /// bytes.
    pub(super) fn chunked(
        row: u32,
        stored: PayloadSource,
        len: u64,
        table: &ChunkTable,
    ) -> Result<Self, Error> {
        let malformed = |what: String| invalid(format!("entry {row}: {what}"));
        let prefix = if table.encoding == 2 {
            ENCODING_2_PREFIX
        } else {
            0
        };
        if prefix > stored.len() {
            return Err(malformed(format!(
                "its {prefix}-byte stored prefix does not fit in its {} stored bytes",
                stored.len()
            )));
        }
        let mut spans = Vec::with_capacity(table.chunks.len());
        let (mut logical, mut stored_at) = (0u64, prefix);
        for (n, chunk) in table.chunks.iter().enumerate() {
            let compressed = chunk.stored_len.checked_sub(chunk.padding).ok_or_else(|| {
                malformed(format!(
                    "chunk {n} has more padding ({}) than stored bytes ({})",
                    chunk.padding, chunk.stored_len
                ))
            })?;
            if chunk.method != ZLIB_METHOD && compressed != chunk.logical_len {
                return Err(malformed(format!(
                    "chunk {n} is copied, but its {compressed} stored bytes differ from its \
                     logical size {}",
                    chunk.logical_len
                )));
            }
            spans.push(Span {
                logical,
                stored: stored_at,
                chunk: Chunk {
                    compressed_len: compressed,
                    ..*chunk
                },
            });
            logical += u64::from(chunk.logical_len);
            stored_at += u64::from(chunk.stored_len);
        }
        if stored_at > stored.len() {
            return Err(malformed(format!(
                "its chunks take {stored_at} stored bytes, more than its {}",
                stored.len()
            )));
        }
        if logical != len {
            return Err(malformed(format!(
                "its chunks hold {logical} bytes, but its logical size is {len}"
            )));
        }
        Ok(Self {
            len,
            pos: 0,
            kind: Kind::Chunked {
                stored,
                spans,
                current: None,
            },
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// [`Read::read`] that stops with [`io::ErrorKind::Interrupted`] once
    /// `cancel` is set, also while it decodes a large chunk.
    pub fn read_cancellable(&mut self, buf: &mut [u8], cancel: &AtomicBool) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let room = usize::try_from(self.len - self.pos).unwrap_or(usize::MAX);
        let buf_len = buf.len().min(room);
        let buf = &mut buf[..buf_len];
        let pos = self.pos;
        let n = match &mut self.kind {
            Kind::Stored(source) => {
                let n = source.read_at(pos, buf)?;
                if n == 0 && !buf.is_empty() {
                    return Err(bad("the stored bytes end early"));
                }
                n
            }
            Kind::Deflate { stored, inflater } => {
                let reusable = inflater.as_ref().is_some_and(|i| i.out <= pos);
                if !reusable {
                    *inflater = Some(Box::new(Inflater::new(
                        stored.clone(),
                        false,
                        false,
                        self.len,
                    )));
                }
                let inflater = inflater.as_mut().expect("set above");
                inflater.skip_to(pos, cancel)?;
                inflater.read(buf, cancel)?
            }
            Kind::Chunked {
                stored,
                spans,
                current,
            } => {
                let index = spans.partition_point(|span| span.logical_end() <= pos);
                let span = &spans[index];
                let offset = pos - span.logical;
                let room = usize::try_from(span.logical_end() - pos).unwrap_or(usize::MAX);
                let buf_len = buf.len().min(room);
                let buf = &mut buf[..buf_len];
                if span.chunk.method != ZLIB_METHOD {
                    let n = stored.read_at(span.stored + offset, buf)?;
                    if n == 0 && !buf.is_empty() {
                        return Err(bad(format!("chunk {index} ends early")));
                    }
                    n
                } else {
                    if !matches!(current, Some((n, _)) if *n == index) {
                        // Drops the previous chunk first, so that at most
                        // one is kept.
                        *current = None;
                        *current = Some((index, decode_chunk(stored, span, cancel)?));
                    }
                    let n = match current.as_ref().map(|(_, decoded)| decoded) {
                        Some(Decoded::Buffered(bytes)) => {
                            let start = usize::try_from(offset).unwrap_or(usize::MAX);
                            let chunk = bytes.get(start..).unwrap_or_default();
                            let n = buf.len().min(chunk.len());
                            buf[..n].copy_from_slice(&chunk[..n]);
                            n
                        }
                        Some(Decoded::Spooled(file)) => source_read_at(file, offset, buf)?,
                        None => 0,
                    };
                    if n == 0 {
                        return Err(bad(format!("chunk {index} ends early")));
                    }
                    n
                }
            }
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.kind {
            Kind::Stored(_) => "stored",
            Kind::Deflate { .. } => "raw DEFLATE",
            Kind::Chunked { .. } => "chunked",
        };
        f.debug_struct("Payload")
            .field("kind", &kind)
            .field("len", &self.len)
            .field("pos", &self.pos)
            .finish()
    }
}

/// A zlib chunk, decoded and checked completely before any of it is used.
fn decode_chunk(stored: &PayloadSource, span: &Span, cancel: &AtomicBool) -> io::Result<Decoded> {
    let len = u64::from(span.chunk.logical_len);
    let compressed = stored
        .slice(span.stored, span.chunk.compressed_len.into())
        .map_err(|err| bad(err.to_string()))?;
    let mut inflater = Inflater::new(compressed, true, true, len);
    if len <= CHUNK_BUFFER_LEN {
        let mut bytes = Vec::with_capacity(len as usize);
        inflater.decode_into(&mut bytes, cancel)?;
        return Ok(Decoded::Buffered(bytes));
    }
    let mut file = io::BufWriter::new(tempfile::tempfile()?);
    inflater.decode_into(&mut file, cancel)?;
    let file = file.into_inner().map_err(|err| err.into_error())?;
    let spooled = Source::from_file(file)?;
    if spooled.len() != len {
        return Err(bad("the temporary copy of the chunk has the wrong size"));
    }
    Ok(Decoded::Spooled(spooled))
}

fn source_read_at(source: &Source, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut source = source.clone();
    source.seek(SeekFrom::Start(offset))?;
    let n = source.read(buf)?;
    if n == 0 && !buf.is_empty() {
        return Err(bad("the stored bytes end early"));
    }
    Ok(n)
}

impl Read for Payload {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_cancellable(buf, &NEVER)
    }
}

impl Seek for Payload {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        self.pos = target.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek to an invalid position")
        })?;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpf::metadata::transform::BlockDecrypt;

    struct Toy;

    impl BlockDecrypt for Toy {
        fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
            for (index, byte) in block.iter_mut().enumerate() {
                *byte = byte.wrapping_add(index as u8) ^ 0xA5;
            }
        }
    }

    fn transform(parameter: [u8; BLOCK_LEN]) -> StreamTransform {
        StreamTransform::new(parameter, Arc::new(Toy))
    }

    #[test]
    fn transform_covers_only_the_verified_regions() {
        let original = vec![0u8; 30_000];
        let mut data = original.clone();
        apply_transform(&mut data, 0, [0u8; BLOCK_LEN], &Toy, StreamModel::Partial);
        let ranges = [0..2048, 9216..10_240, 17_408..18_432, 25_600..26_624];
        for range in &ranges {
            assert!(
                data[range.clone()]
                    .iter()
                    .zip(&original[range.clone()])
                    .any(|(a, b)| a != b),
                "range {range:?} was not transformed"
            );
        }
        for (index, (a, b)) in data.iter().zip(&original).enumerate() {
            if !ranges.iter().any(|range| range.contains(&index)) {
                assert_eq!(a, b, "byte {index} outside the transform");
            }
        }
    }

    #[test]
    fn transform_origin_keeps_the_counter_relative_to_the_entry() {
        let parameter = [0x11; BLOCK_LEN];
        let mut full = vec![0u8; 20_000];
        apply_transform(&mut full, 0, parameter, &Toy, StreamModel::Partial);
        let mut tail = vec![0u8; 10_784];
        apply_transform(&mut tail, 9_216, parameter, &Toy, StreamModel::Partial);
        assert_eq!(&tail[..], &full[9_216..]);
    }

    #[test]
    fn streaming_payload_matches_the_decoded_chunk() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let text = b"<CVehicleDistantLightData>streaming transform test</CVehicleDistantLightData>";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(text).unwrap();
        let compressed = encoder.finish().unwrap();
        let parameter = [0x33; BLOCK_LEN];
        let mut stored = compressed.clone();
        apply_transform(&mut stored, 0, parameter, &Toy, StreamModel::Partial);

        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut file = temp.as_file();
        file.write_all(&stored).unwrap();
        file.flush().unwrap();
        let source = Source::open(temp.path()).unwrap();
        let table = ChunkTable {
            encoding: 4,
            chunks: vec![Chunk {
                logical_len: text.len() as u32,
                stored_len: compressed.len() as u32,
                padding: 0,
                compressed_len: compressed.len() as u32,
                method: 3,
            }],
        };
        let mut payload = Payload::chunked(
            0,
            PayloadSource::transformed(source, transform(parameter)),
            text.len() as u64,
            &table,
        )
        .unwrap();
        let mut out = Vec::new();
        payload.read_to_end(&mut out).unwrap();
        assert_eq!(out, text);
    }

    fn zlib(bytes: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::none());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn chunk_file(bytes: &[u8]) -> (tempfile::NamedTempFile, Source) {
        use std::io::Write;

        let temp = tempfile::NamedTempFile::new().unwrap();
        let mut file = temp.as_file();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
        let source = Source::open(temp.path()).unwrap();
        (temp, source)
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

    fn two_chunk_table(a: &[u8], ca: &[u8], b: &[u8], cb: &[u8]) -> ChunkTable {
        ChunkTable {
            encoding: 3,
            chunks: vec![chunk(a.len(), ca.len(), 3), chunk(b.len(), cb.len(), 3)],
        }
    }

    #[test]
    fn chunks_decode_in_order_to_their_declared_sizes() {
        let a = vec![0x11u8; 1000];
        let b = vec![0x22u8; 5000];
        let (ca, cb) = (zlib(&a), zlib(&b));
        let stored = [ca.clone(), cb.clone()].concat();
        let (_temp, source) = chunk_file(&stored);
        let table = two_chunk_table(&a, &ca, &b, &cb);
        let mut payload = Payload::chunked(
            0,
            PayloadSource::plain(source),
            (a.len() + b.len()) as u64,
            &table,
        )
        .unwrap();
        let mut out = Vec::new();
        payload.read_to_end(&mut out).unwrap();
        assert_eq!(out, [a, b].concat());
    }

    #[test]
    fn a_corrupt_later_chunk_fails_the_read() {
        let a = vec![0x11u8; 1000];
        let b = vec![0x22u8; 5000];
        let (ca, cb) = (zlib(&a), zlib(&b));
        let mut stored = [ca.clone(), cb.clone()].concat();
        let last = stored.len() - 1;
        stored[last] ^= 0xFF;
        let (_temp, source) = chunk_file(&stored);
        // The entry size matches the table, so only the checksum can catch it.
        let table = two_chunk_table(&a, &ca, &b, &cb);
        let mut payload = Payload::chunked(
            0,
            PayloadSource::plain(source),
            (a.len() + b.len()) as u64,
            &table,
        )
        .unwrap();
        let mut out = Vec::new();
        assert!(payload.read_to_end(&mut out).is_err());
    }

    #[test]
    fn a_chunk_must_not_produce_more_than_its_declared_size() {
        let plain = vec![0x33u8; 4000];
        let compressed = zlib(&plain);
        let (_temp, source) = chunk_file(&compressed);
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(plain.len() - 1, compressed.len(), 3)],
        };
        let mut payload = Payload::chunked(
            0,
            PayloadSource::plain(source),
            (plain.len() - 1) as u64,
            &table,
        )
        .unwrap();
        assert!(payload.read_to_end(&mut Vec::new()).is_err());
    }

    #[test]
    fn chunk_sizes_must_sum_to_the_entry_size() {
        let a = vec![0x44u8; 1000];
        let b = vec![0x55u8; 5000];
        let (ca, cb) = (zlib(&a), zlib(&b));
        let stored = [ca.clone(), cb.clone()].concat();
        let (_temp, source) = chunk_file(&stored);
        let table = two_chunk_table(&a, &ca, &b, &cb);
        let result = Payload::chunked(
            0,
            PayloadSource::plain(source),
            (a.len() + b.len() + 1) as u64,
            &table,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_copied_chunk_must_be_as_long_as_it_is_stored() {
        let (_temp, source) = chunk_file(&[0u8; 10]);
        let table = ChunkTable {
            encoding: 3,
            chunks: vec![chunk(9, 10, 0)],
        };
        assert!(Payload::chunked(0, PayloadSource::plain(source), 9, &table).is_err());
    }

    #[test]
    fn the_transform_uses_absolute_offsets_across_chunks() {
        let parameter = [0x77; BLOCK_LEN];
        let a = vec![0x5Au8; 12_000];
        let b = vec![0xA5u8; 8_000];
        let (ca, cb) = (zlib(&a), zlib(&b));
        let mut stored = [ca.clone(), cb.clone()].concat();
        apply_transform(&mut stored, 0, parameter, &Toy, StreamModel::Partial);
        let (_temp, source) = chunk_file(&stored);
        let table = two_chunk_table(&a, &ca, &b, &cb);
        let mut payload = Payload::chunked(
            0,
            PayloadSource::transformed(source, transform(parameter)),
            (a.len() + b.len()) as u64,
            &table,
        )
        .unwrap();
        let mut out = Vec::new();
        payload.read_to_end(&mut out).unwrap();
        assert_eq!(out, [a, b].concat());
    }
}
