//! Resources reconstructed from the streams a scan found.
//!
//! As observed, a resource is stored as 16 zero bytes followed by one zlib
//! stream per page, system pages first, at consecutive aligned offsets. The
//! pages of a resource are taken from the streams that directly follow its
//! first one; a gap, the start of a file or of another resource candidate
//! ends the run. Only system pages are inflated, to read the page map and to
//! check pointers.

use std::io::{Read, Seek};
use std::num::NonZero;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use super::scan::{SCRATCH_LEN, Window, inflate, is_zlib_header};
use super::{ALIGN, Error, Kind, Resource, Stream};
use crate::resource::{Builder, Issue, PAGE_UNIT, RawPage, group_pages};

/// The zeroed bytes in front of the first system stream.
const PREFIX_LEN: usize = 16;
/// Streams considered per resource: two segments of 255 pages, with room
/// for split pages.
const MAX_RUN: usize = 1024;
/// Pointer offsets have 28 bits, so system data cannot be longer.
const MAX_SYSTEM_LEN: u64 = 1 << 28;
/// Inflated bytes collected before the start of system data is checked.
const HEAD_LEN: usize = 64;
const MAX_THREADS: usize = 8;

/// Reconstructs a resource at every stream of kind [`Kind::Resource`].
/// Streams without the zeroed prefix are not resources and become
/// [`Kind::Binary`].
pub(crate) fn resolve<S: Read + Seek + Clone + Send>(
    source: S,
    len: u64,
    streams: &mut [Stream],
    cancel: &AtomicBool,
) -> Result<Vec<Resource>, Error> {
    // Rejected first, so that they do not end the page runs of others.
    let mut window = Window::new(source.clone(), len);
    for stream in streams.iter_mut() {
        if stream.kind == Kind::Resource && !has_zero_prefix(&mut window, stream.offset)? {
            stream.kind = Kind::Binary;
        }
    }
    let candidates: Vec<usize> = streams
        .iter()
        .enumerate()
        .filter(|(_, stream)| stream.kind == Kind::Resource)
        .map(|(ix, _)| ix)
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let threads = thread::available_parallelism()
        .map_or(1, NonZero::get)
        .clamp(1, MAX_THREADS)
        .min(candidates.len());
    let per_thread = candidates.len().div_ceil(threads);
    let stop = AtomicBool::new(false);
    let shared: &[Stream] = streams;
    let parts: Vec<Result<Vec<Option<Resource>>, Error>> = thread::scope(|scope| {
        let handles: Vec<_> = candidates
            .chunks(per_thread)
            .map(|part| {
                let source = source.clone();
                let stop = &stop;
                scope.spawn(move || {
                    let mut window = Window::new(source, len);
                    let mut scratch = vec![0; SCRATCH_LEN];
                    let result: Result<Vec<Option<Resource>>, Error> = part
                        .iter()
                        .map(|&ix| {
                            if cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                                return Err(Error::Cancelled);
                            }
                            resolve_one(&mut window, shared, ix, len, &mut scratch)
                        })
                        .collect();
                    if result.is_err() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    result
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    if cancel.load(Ordering::Relaxed) {
        return Err(Error::Cancelled);
    }
    let mut found = Vec::with_capacity(candidates.len());
    let mut cancelled = false;
    for part in parts {
        match part {
            Ok(part) => found.extend(part),
            Err(Error::Cancelled) => cancelled = true,
            Err(err) => return Err(err),
        }
    }
    if cancelled {
        return Err(Error::Cancelled);
    }
    let mut resources = Vec::new();
    for (ix, resource) in candidates.into_iter().zip(found) {
        match resource {
            Some(resource) => resources.push(resource),
            None => streams[ix].kind = Kind::Binary,
        }
    }
    Ok(resources)
}

/// Collects the start of the system data until it can be checked, then
/// passes everything to a [`Builder`].
#[derive(Default)]
struct Feed {
    head: Vec<u8>,
    builder: Option<Builder>,
    rejected: bool,
}

impl Feed {
    fn push(&mut self, bytes: &[u8]) {
        match &mut self.builder {
            Some(builder) => builder.feed(bytes),
            None if !self.rejected => {
                self.head.extend_from_slice(bytes);
                if self.head.len() >= HEAD_LEN {
                    self.start();
                }
            }
            None => {}
        }
    }

    fn start(&mut self) {
        if self.builder.is_some() || self.rejected {
            return;
        }
        let head = std::mem::take(&mut self.head);
        match Builder::new(&head) {
            Some(mut builder) => {
                builder.feed(&head);
                self.builder = Some(builder);
            }
            None => self.rejected = true,
        }
    }
}

fn has_zero_prefix<S: Read + Seek>(window: &mut Window<S>, offset: u64) -> Result<bool, Error> {
    let Some(at) = offset.checked_sub(PREFIX_LEN as u64) else {
        return Ok(false);
    };
    let prefix = window.at(at, PREFIX_LEN)?;
    Ok(prefix.len() >= PREFIX_LEN && prefix[..PREFIX_LEN].iter().all(|&byte| byte == 0))
}

fn resolve_one<S: Read + Seek>(
    window: &mut Window<S>,
    streams: &[Stream],
    first: usize,
    limit: u64,
    scratch: &mut [u8],
) -> Result<Option<Resource>, Error> {
    let head = &streams[first];
    let mut last = first;
    while last + 1 - first < MAX_RUN
        && let Some(next) = streams.get(last + 1)
        && streams[last].is_followed_by(next)
        && !next.kind.is_file_start()
    {
        last += 1;
    }
    let run = &streams[first..=last];
    let lens: Vec<u64> = run.iter().map(|stream| u64::from(stream.len)).collect();
    let pages = group_pages(&lens);

    let mut feed = Feed::default();
    let mut fed_len = 0u64;
    let mut next = 0;
    'pages: for (fed, &(count, _)) in pages.iter().enumerate() {
        if feed.rejected || feed.builder.as_ref().is_some_and(|b| b.has_system(fed)) {
            break;
        }
        for stream in &run[next..next + count as usize] {
            fed_len += u64::from(stream.len);
            if fed_len > MAX_SYSTEM_LEN {
                break 'pages;
            }
            let inflated = inflate(
                window,
                stream.offset,
                stream.len.into(),
                scratch,
                &mut |bytes| {
                    feed.push(bytes);
                    Ok(())
                },
            )?;
            if inflated != Some((stream.stored_len.into(), stream.len.into())) {
                return Err(Error::Changed(format!(
                    "the stream at {:#x} no longer inflates as scanned",
                    stream.offset
                )));
            }
            feed.start();
        }
        next += count as usize;
    }
    feed.start();
    let Some(builder) = feed.builder else {
        return Ok(None);
    };

    // A declared page that no zlib stream holds may be one raw stored range
    // after the streams. Only the last declared page is considered, and only
    // when exactly one page is missing.
    let attributed = builder
        .page_map()
        .and_then(Result::ok)
        .map(|map| usize::from(map.system_pages) + usize::from(map.graphics_pages));
    let mut raw = None;
    let mut tail = None;
    if attributed.is_some_and(|total| pages.len() + 1 == total) {
        match find_tail(window, run, last, limit)? {
            Tail::None => {}
            Tail::Page(page) => raw = Some(page),
            Tail::TooLong { offset, len } | Tail::AllZero { offset, len } => {
                tail = Some(Issue::UnclassifiableTail { offset, len });
            }
            Tail::LooksCompressed { offset } => {
                tail = Some(Issue::DamagedStream { offset });
            }
        }
    }
    let mut layout = builder.finish(&pages, raw);
    if layout.tail.is_none() {
        layout.tail = tail;
    }
    Ok(Some(Resource {
        offset: head.offset,
        first_stream: first as u32,
        layout,
    }))
}

/// What a range after the last stream of a resource run looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// Nothing after the streams, or nothing that could be a page.
    None,
    /// A stored range that fits one last page.
    Page(RawPage),
    /// Non-zero bytes longer than one page.
    TooLong { offset: u64, len: u64 },
    /// A range that is entirely zero, so its length cannot be established.
    AllZero { offset: u64, len: u64 },
    /// A range that starts with a zlib header but did not inflate.
    LooksCompressed { offset: u64 },
}

/// The range a raw page could occupy: from the aligned end of the last
/// stream to the next stream or the end of the payload area.
fn tail_bounds(streams: &[Stream], last: usize, limit: u64) -> Option<(u64, u64)> {
    let start = streams[last].aligned_end()?;
    if start > limit {
        return None;
    }
    let stop = streams
        .get(last + 1)
        .map_or(limit, |next| next.offset.min(limit));
    (stop > start).then_some((start, stop))
}

/// Classifies the range a raw page could occupy. A page of at most
/// [`PAGE_UNIT`] bytes is `Page`; the bytes after it to the next stream must
/// be zero fill.
fn find_tail<S: Read + Seek>(
    window: &mut Window<S>,
    streams: &[Stream],
    last: usize,
    limit: u64,
) -> Result<Tail, Error> {
    let Some((start, stop)) = tail_bounds(streams, last, limit) else {
        return Ok(Tail::None);
    };
    // A range that starts like a zlib stream is a stream that failed to
    // inflate, not a stored page: every observed raw page starts without a
    // zlib header. The chunk counts then stay short and the page is reported
    // missing instead of being invented from a damaged stream.
    let head = window.at(start, 2)?;
    if is_zlib_header(&head[..head.len().min(2)]) {
        return Ok(Tail::LooksCompressed { offset: start });
    }
    // One page plus one block of margin, so an oversized range is detected
    // without walking a whole gap.
    let scan_end = stop.min(start.saturating_add(2 * PAGE_UNIT));
    let mut end = start;
    let mut pos = start;
    while pos < scan_end {
        let bytes = window.at(pos, ALIGN as usize)?;
        let Some(block) = bytes
            .get(..bytes.len().min(ALIGN as usize))
            .filter(|b| !b.is_empty())
        else {
            break;
        };
        if block.iter().any(|&byte| byte != 0) {
            end = pos + block.len() as u64;
        }
        pos += block.len() as u64;
    }
    let len = end.saturating_sub(start);
    if len > PAGE_UNIT {
        return Ok(Tail::TooLong {
            offset: start,
            len: stop - start,
        });
    }
    if len == 0 {
        return Ok(Tail::AllZero {
            offset: start,
            len: stop - start,
        });
    }
    if len % ALIGN != 0 {
        return Ok(Tail::TooLong {
            offset: start,
            len: stop - start,
        });
    }
    Ok(Tail::Page(RawPage { offset: start, len }))
}
