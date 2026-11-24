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
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::{Decompress, FlushDecompress, Status};
use lforge_binary::Source;

use super::{Chunk, ChunkTable, Error, invalid};

/// Stored bytes read per decoder step.
const INPUT_LEN: usize = 64 * 1024;
/// Bytes decoded per step when skipping to a position.
const SKIP_LEN: usize = 64 * 1024;
/// The chunk method that holds a zlib stream. The others are copied.
const ZLIB_METHOD: u8 = 3;
/// Zlib chunks up to this size are kept in memory while they are read.
/// Larger ones are kept in a temporary file.
const CHUNK_BUFFER_LEN: u64 = 1024 * 1024;
/// For reads that cannot be cancelled.
static NEVER: AtomicBool = AtomicBool::new(false);

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}

fn bad(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// One DEFLATE stream over stored bytes that must decode to exactly `len`
/// bytes.
struct Inflater {
    stored: Source,
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
    fn new(stored: Source, zlib: bool, exact_input: bool, len: u64) -> Self {
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
    Stored(Source),
    /// One raw DEFLATE stream from the start of the stored bytes.
    Deflate {
        stored: Source,
        inflater: Option<Inflater>,
    },
    Chunked {
        stored: Source,
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
    pub(super) fn stored(source: Source) -> Self {
        Self {
            len: source.len(),
            pos: 0,
            kind: Kind::Stored(source),
        }
    }

    pub(super) fn deflate(stored: Source, len: u64) -> Self {
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
        stored: Source,
        len: u64,
        table: &ChunkTable,
    ) -> Result<Self, Error> {
        let malformed = |what: String| invalid(format!("entry {row}: {what}"));
        let mut spans = Vec::with_capacity(table.chunks.len());
        let (mut logical, mut stored_at) = (0u64, 0u64);
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
            Kind::Stored(source) => read_at(source, pos, buf)?,
            Kind::Deflate { stored, inflater } => {
                let reusable = inflater.as_ref().is_some_and(|i| i.out <= pos);
                if !reusable {
                    *inflater = Some(Inflater::new(stored.clone(), false, false, self.len));
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
                    read_at(stored, span.stored + offset, buf)?
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
                        Some(Decoded::Spooled(file)) => read_at(file, offset, buf)?,
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
fn decode_chunk(stored: &Source, span: &Span, cancel: &AtomicBool) -> io::Result<Decoded> {
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

fn read_at(source: &Source, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
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
