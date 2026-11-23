//! Carving zlib streams out of the data area.
//!
//! Every 16-byte aligned offset that starts with a valid zlib header is
//! inflated. A candidate only counts as a stream if it inflates to its end,
//! which includes the Adler-32 check. The archive is split into segments that
//! are scanned in parallel; a stream that crosses into the next segment is
//! kept from the segment it starts in.

use std::io::{self, Read, Seek, SeekFrom};
use std::num::NonZero;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use flate2::{Decompress, FlushDecompress, Status as ZlibStatus};

use super::{
    ALIGN, Error, Header, Index, Kind, Progress, Region, Stream, align_up, read_header, reconstruct,
};
use crate::resource;

const BLOCK_LEN: usize = 1024 * 1024;
pub(crate) const SCRATCH_LEN: usize = 64 * 1024;
/// A multiple of [`ALIGN`].
const SEGMENT_LEN: u64 = 64 * 1024 * 1024;
const MAX_THREADS: usize = 8;
/// Candidates that inflate to more than this are rejected. Observed streams
/// are at most a few hundred KiB.
pub(crate) const MAX_STREAM_LEN: u64 = 256 * 1024 * 1024;
/// Inflated bytes kept per stream for classification.
const HEAD_LEN: usize = 256;
const TEXT_PROBE_LEN: usize = 128;
/// Progress is published and cancellation checked after this many bytes.
const REPORT_STEP: u64 = 1024 * 1024;

/// A buffered view of the archive for reads at arbitrary offsets.
pub(crate) struct Window<S> {
    source: S,
    len: u64,
    start: u64,
    buf: Vec<u8>,
}

impl<S: Read + Seek> Window<S> {
    pub(crate) fn new(source: S, len: u64) -> Self {
        Self {
            source,
            len,
            start: 0,
            buf: Vec::new(),
        }
    }

    /// The bytes from `pos` to the end of the buffer, refilled so that at
    /// least `min` bytes are available unless the data ends first.
    pub(crate) fn at(&mut self, pos: u64, min: usize) -> io::Result<&[u8]> {
        let end = self.start + self.buf.len() as u64;
        let needed = pos.saturating_add(min as u64).min(self.len);
        if pos < self.start || needed > end {
            let count = self.len.saturating_sub(pos).min(BLOCK_LEN as u64) as usize;
            self.buf.resize(count, 0);
            self.source.seek(SeekFrom::Start(pos))?;
            self.source.read_exact(&mut self.buf)?;
            self.start = pos;
        }
        let from = usize::try_from(pos - self.start).unwrap_or(usize::MAX);
        Ok(&self.buf[from.min(self.buf.len())..])
    }
}

/// Inflates the zlib stream at `offset`, passing the output to `sink`.
/// Returns the compressed and inflated sizes, or `None` if there is no valid
/// stream of at most `max_len` inflated bytes.
pub(crate) fn inflate<S: Read + Seek>(
    window: &mut Window<S>,
    offset: u64,
    max_len: u64,
    scratch: &mut [u8],
    sink: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
) -> Result<Option<(u64, u64)>, Error> {
    let mut zlib = Decompress::new(true);
    let mut pos = offset;
    loop {
        let input = window.at(pos, 1)?;
        if input.is_empty() {
            return Ok(None);
        }
        let (in_before, out_before) = (zlib.total_in(), zlib.total_out());
        // One byte more than allowed, so an oversized stream is detected.
        let room = usize::try_from(max_len - out_before + 1)
            .unwrap_or(usize::MAX)
            .min(scratch.len());
        let Ok(status) = zlib.decompress(input, &mut scratch[..room], FlushDecompress::None) else {
            return Ok(None);
        };
        let consumed = zlib.total_in() - in_before;
        let produced = (zlib.total_out() - out_before) as usize;
        pos += consumed;
        if zlib.total_out() > max_len {
            return Ok(None);
        }
        sink(&scratch[..produced])?;
        if status == ZlibStatus::StreamEnd {
            return Ok(Some((zlib.total_in(), zlib.total_out())));
        }
        if consumed == 0 && produced == 0 {
            return Ok(None);
        }
    }
}

fn is_zlib_header(bytes: &[u8]) -> bool {
    let [cmf, flg, ..] = *bytes else {
        return false;
    };
    // Deflate with a window of at most 32 KiB, no preset dictionary.
    cmf & 0x0F == 8
        && cmf >> 4 <= 7
        && flg & 0x20 == 0
        && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
}

pub(crate) fn classify(head: &[u8]) -> Kind {
    let body = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    if body.starts_with(b"<?xml") {
        return Kind::Xml;
    }
    if head.starts_with(b"PSIN") {
        return Kind::Pso;
    }
    if head.starts_with(b"RBF0") {
        return Kind::Rbf;
    }
    if head.starts_with(b"\x89PNG\r\n\x1A\n") {
        return Kind::Png;
    }
    if head.starts_with(b"DDS ") {
        return Kind::Dds;
    }
    if resource::page_map_offset(head).is_some() {
        return Kind::Resource;
    }
    let probe = &head[..head.len().min(TEXT_PROBE_LEN)];
    let printable = probe
        .iter()
        .filter(|&&byte| matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7E))
        .count();
    if !probe.is_empty() && printable * 100 >= probe.len() * 95 {
        return Kind::Text;
    }
    Kind::Binary
}

/// What one segment found. `runs` are non-zero bytes outside the streams the
/// segment found; streams of other segments are subtracted later.
#[derive(Default)]
struct Segment {
    streams: Vec<Stream>,
    runs: Vec<(u64, u64)>,
}

/// Scans the data area of an archive. Only a completed scan yields an index.
pub fn scan<S: Read + Seek + Clone + Send>(
    mut source: S,
    progress: &Progress,
    cancel: &AtomicBool,
) -> Result<Index, Error> {
    let header = read_header(&mut source)?;
    let len = source.seek(SeekFrom::End(0))?;
    let start = header.data_start().min(len);
    scan_from(source, header, len, start, SEGMENT_LEN, progress, cancel)
}

pub(crate) fn scan_from<S: Read + Seek + Clone + Send>(
    source: S,
    header: Header,
    len: u64,
    start: u64,
    segment_len: u64,
    progress: &Progress,
    cancel: &AtomicBool,
) -> Result<Index, Error> {
    progress.total.store(len - start, Ordering::Relaxed);
    progress.done.store(0, Ordering::Relaxed);
    let count = usize::try_from((len - start).div_ceil(segment_len))
        .map_err(|_| Error::InvalidHeader("the archive is too large".into()))?;
    let threads = thread::available_parallelism()
        .map_or(1, NonZero::get)
        .clamp(1, MAX_THREADS)
        .min(count.max(1));
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let results: Mutex<Vec<Option<Result<Segment, Error>>>> =
        Mutex::new((0..count).map(|_| None).collect());

    thread::scope(|scope| {
        for _ in 0..threads {
            let source = source.clone();
            let (next, stop, results) = (&next, &stop, &results);
            scope.spawn(move || {
                loop {
                    let ix = next.fetch_add(1, Ordering::Relaxed);
                    if ix >= count || stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let seg_start = start + ix as u64 * segment_len;
                    let seg_end = seg_start.saturating_add(segment_len).min(len);
                    let result = scan_segment(
                        source.clone(),
                        seg_start,
                        seg_end,
                        len,
                        progress,
                        cancel,
                        stop,
                    );
                    if result.is_err() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    results.lock().unwrap_or_else(|err| err.into_inner())[ix] = Some(result);
                }
            });
        }
    });

    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let results = results.into_inner().unwrap_or_else(|err| err.into_inner());
    let mut segments = Vec::with_capacity(count);
    let mut cancelled = false;
    for result in results {
        match result {
            Some(Ok(segment)) => segments.push(segment),
            Some(Err(Error::Cancelled)) | None => cancelled = true,
            Some(Err(err)) => return Err(err),
        }
    }
    if cancelled {
        return Err(Error::Cancelled);
    }
    let (mut streams, regions) = merge(start, segments);
    let resources = reconstruct::resolve(source, len, &mut streams, cancel)?;
    Ok(Index::new(len, header, streams, resources, regions))
}

fn scan_segment<S: Read + Seek>(
    source: S,
    start: u64,
    end: u64,
    len: u64,
    progress: &Progress,
    cancel: &AtomicBool,
    stop: &AtomicBool,
) -> Result<Segment, Error> {
    let mut window = Window::new(source, len);
    let mut scratch = vec![0; SCRATCH_LEN];
    let mut head = Vec::with_capacity(HEAD_LEN);
    let mut segment = Segment::default();
    let mut run: Option<(u64, u64)> = None;
    let mut pos = start;
    let mut reported = start;
    while pos < end {
        if pos - reported >= REPORT_STEP {
            if cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                return Err(Error::Cancelled);
            }
            progress.done.fetch_add(pos - reported, Ordering::Relaxed);
            reported = pos;
        }
        let (candidate, block_end, nonzero) = {
            let bytes = window.at(pos, ALIGN as usize)?;
            let block = &bytes[..bytes.len().min(ALIGN as usize)];
            (
                is_zlib_header(block),
                pos + block.len() as u64,
                block.iter().any(|&byte| byte != 0),
            )
        };
        if candidate {
            head.clear();
            let found = inflate(&mut window, pos, MAX_STREAM_LEN, &mut scratch, &mut |out| {
                let take = (HEAD_LEN - head.len()).min(out.len());
                head.extend_from_slice(&out[..take]);
                Ok(())
            })?;
            if let Some((stored, inflated)) = found
                && inflated > 0
                && let (Ok(stored_len), Ok(stream_len)) =
                    (u32::try_from(stored), u32::try_from(inflated))
                && let Some(next) = pos.checked_add(stored).and_then(align_up)
            {
                segment.runs.extend(run.take());
                segment.streams.push(Stream {
                    offset: pos,
                    stored_len,
                    len: stream_len,
                    kind: classify(&head),
                });
                pos = next;
                continue;
            }
        }
        if nonzero {
            run = Some((run.map_or(pos, |(from, _)| from), block_end));
        }
        pos += ALIGN;
    }
    segment.runs.extend(run);
    progress
        .done
        .fetch_add(pos.saturating_sub(reported), Ordering::Relaxed);
    Ok(segment)
}

/// Keeps the first stream at each position, in archive order, and turns the
/// non-zero runs into one region per gap between streams.
fn merge(start: u64, segments: Vec<Segment>) -> (Vec<Stream>, Vec<Region>) {
    let mut streams: Vec<Stream> = Vec::new();
    let mut runs = Vec::new();
    let mut cut = start;
    for segment in segments {
        for stream in segment.streams {
            if stream.offset >= cut {
                cut = stream.aligned_end().unwrap_or(u64::MAX);
                streams.push(stream);
            }
        }
        runs.extend(segment.runs);
    }
    let regions = regions(&streams, runs);
    (streams, regions)
}

fn regions(streams: &[Stream], mut runs: Vec<(u64, u64)>) -> Vec<Region> {
    let end_of = |stream: &Stream| stream.aligned_end().unwrap_or(u64::MAX);
    runs.sort_unstable();
    // (index of the stream after the gap, start, end)
    let mut pieces: Vec<(usize, u64, u64)> = Vec::new();
    for (mut from, to) in runs {
        let mut ix = streams.partition_point(|stream| end_of(stream) <= from);
        while from < to {
            match streams.get(ix) {
                Some(stream) if stream.offset < to => {
                    if from < stream.offset {
                        pieces.push((ix, from, stream.offset));
                    }
                    from = from.max(end_of(stream));
                    ix += 1;
                }
                _ => {
                    pieces.push((ix, from, to));
                    break;
                }
            }
        }
    }
    pieces.sort_unstable();
    let mut regions: Vec<(usize, u64, u64)> = Vec::new();
    for (gap, from, to) in pieces {
        match regions.last_mut() {
            Some(last) if last.0 == gap => {
                last.1 = last.1.min(from);
                last.2 = last.2.max(to);
            }
            _ => regions.push((gap, from, to)),
        }
    }
    regions
        .into_iter()
        .map(|(_, from, to)| Region {
            offset: from,
            len: to - from,
        })
        .collect()
}
