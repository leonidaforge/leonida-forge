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

use super::scan::{SCRATCH_LEN, Window, inflate};
use super::{Error, Kind, Resource, Stream};
use crate::resource::{Builder, group_pages};

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
                            resolve_one(&mut window, shared, ix, &mut scratch)
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
    Ok(Some(Resource {
        offset: head.offset,
        first_stream: first as u32,
        layout: builder.finish(&pages),
    }))
}
