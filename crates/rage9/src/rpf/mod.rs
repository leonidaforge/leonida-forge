//! Read-only access to GTA VI RPF9 archives.
//!
//! The engine processes most of the table of contents in place before reading
//! it, with algorithms that are not known; [`metadata`] parses the table once
//! it is available in that processed form. What can be listed without it is
//! recovered from the data area instead: file data is stored
//! as zlib streams at 16-byte aligned offsets, and files larger than 64 KiB
//! are split into one stream per 64 KiB chunk. [`scan`] finds these streams,
//! checks each one by inflating it completely, reconstructs resources from
//! their page streams, and groups the remaining consecutive chunks into
//! [`Entry`] values.
//!
//! Recovered entries have no original names or paths. They are identified by
//! the archive offset of their first stream. Bytes outside all recovered
//! streams that are not zero padding are reported as [`Region`] values.

mod cache;
pub mod metadata;
pub mod names;
mod reconstruct;
mod scan;

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub use crate::Status;
use crate::resource::{Layout, Page, Segment, Storage};
pub use cache::{CacheKey, Origin, file_location, file_version, load, open, store};
pub use scan::scan;

pub const MAGIC: [u8; 4] = *b"9FPR";
pub const HEADER_LEN: usize = 0x40;
/// Data offsets are multiples of this.
pub const ALIGN: u64 = 16;
/// Inflated size of every stream of a chunked file except the last.
pub const CHUNK_LEN: u32 = 0x1_0000;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NotRpf9,
    InvalidHeader(String),
    Cancelled,
    TooLarge {
        len: u64,
        limit: u64,
    },
    /// The archive no longer matches its index.
    Changed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::NotRpf9 => f.write_str("not an RPF9 archive"),
            Error::InvalidHeader(reason) => write!(f, "invalid RPF9 header: {reason}"),
            Error::Cancelled => f.write_str("cancelled"),
            Error::TooLarge { len, limit } => {
                write!(
                    f,
                    "the entry is too large to read ({len} bytes, limit {limit})"
                )
            }
            Error::Changed(reason) => write!(f, "the archive has changed: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(err) => err,
            Error::Cancelled => io::Error::new(io::ErrorKind::Interrupted, "cancelled"),
            Error::NotRpf9 | Error::InvalidHeader(_) => {
                io::Error::new(io::ErrorKind::InvalidData, err.to_string())
            }
            other => io::Error::other(other.to_string()),
        }
    }
}

pub fn is_rpf9(signature: &[u8]) -> bool {
    signature.starts_with(&MAGIC)
}

/// The fixed 64-byte header. Only the magic and the end of the table of
/// contents are understood; the other fields are kept as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    bytes: [u8; HEADER_LEN],
}

impl Header {
    pub fn parse(bytes: &[u8], archive_len: u64) -> Result<Self, Error> {
        if !is_rpf9(bytes) {
            return Err(Error::NotRpf9);
        }
        let bytes: [u8; HEADER_LEN] = bytes
            .get(..HEADER_LEN)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::InvalidHeader("the file is shorter than the header".into()))?;
        let header = Self { bytes };
        let toc_end = header.toc_end();
        if toc_end < HEADER_LEN as u64 {
            return Err(Error::InvalidHeader(format!(
                "the table of contents ends at {toc_end:#x}, inside the header"
            )));
        }
        if toc_end > archive_len {
            return Err(Error::InvalidHeader(format!(
                "the table of contents ends at {toc_end:#x}, after the end of the file ({archive_len:#x})"
            )));
        }
        header.payload_end(archive_len)?;
        Ok(header)
    }

    pub fn bytes(&self) -> &[u8; HEADER_LEN] {
        &self.bytes
    }

    /// The little-endian `u32` at `offset`, which must be within the header.
    pub fn u32_at(&self, offset: usize) -> u32 {
        let bytes = self.bytes[offset..offset + 4].try_into().expect("4 bytes");
        u32::from_le_bytes(bytes)
    }

    /// The end of the encrypted table of contents, which starts after the header.
    pub fn toc_end(&self) -> u64 {
        self.u32_at(0x04).into()
    }

    /// The byte length of the trailing region, the `u32` at `0x0C`. Its
    /// contents are not interpreted.
    pub fn trailer_len(&self) -> u32 {
        self.u32_at(0x0C)
    }

    /// The end of the stored payload data: `archive_len - hdr[0x0C]`.
    ///
    /// A zero length declares no trailing region and leaves the whole file
    /// available; every archive of the measured population declares one. A
    /// declared boundary must be a multiple of [`ALIGN`], lie above the end
    /// of the table of contents and below the end of the file.
    pub fn payload_end(&self, archive_len: u64) -> Result<u64, Error> {
        let trailer = u64::from(self.trailer_len());
        if trailer == 0 {
            return Ok(archive_len);
        }
        let end = archive_len.checked_sub(trailer).ok_or_else(|| {
            Error::InvalidHeader(format!(
                "the {trailer}-byte trailing region is longer than the {archive_len}-byte file"
            ))
        })?;
        if end % ALIGN != 0 {
            return Err(Error::InvalidHeader(format!(
                "the trailing region starts at {end:#x}, not on a {ALIGN}-byte boundary"
            )));
        }
        if end <= self.toc_end() {
            return Err(Error::InvalidHeader(format!(
                "the trailing region starts at {end:#x}, at or before the end of the table of contents ({:#x})",
                self.toc_end()
            )));
        }
        Ok(end)
    }

    /// Where the scan for data streams starts.
    pub fn data_start(&self) -> u64 {
        // `toc_end` is a u32, so this cannot overflow.
        align_up(self.toc_end()).unwrap_or(u64::MAX)
    }
}

pub fn read_header(source: &mut (impl Read + Seek)) -> Result<Header, Error> {
    let len = source.seek(SeekFrom::End(0))?;
    source.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(HEADER_LEN);
    source.take(HEADER_LEN as u64).read_to_end(&mut bytes)?;
    Header::parse(&bytes, len)
}

pub(crate) fn align_up(offset: u64) -> Option<u64> {
    Some(offset.checked_add(ALIGN - 1)? & !(ALIGN - 1))
}

/// What the first bytes of an entry look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// An XML declaration, optionally after a UTF-8 byte order mark.
    Xml,
    /// Starts with `PSIN`. The payload encoding is unresolved; nothing
    /// relates it to a confirmed PSO format.
    Psin,
    /// Starts with `RBF0`.
    Rbf,
    /// Starts with `GFX` and the supported version byte.
    Gfx,
    Png,
    Dds,
    /// The start of RAGE resource system data, after 16 zero bytes; see
    /// [`crate::resource`].
    Resource,
    /// Printable text without a recognised file signature.
    Text,
    Binary,
}

impl Kind {
    pub const ALL: [Kind; 9] = [
        Kind::Xml,
        Kind::Psin,
        Kind::Rbf,
        Kind::Png,
        Kind::Dds,
        Kind::Resource,
        Kind::Text,
        Kind::Binary,
        Kind::Gfx,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Xml => "xml",
            Kind::Psin => "psin",
            Kind::Rbf => "rbf",
            Kind::Gfx => "gfx",
            Kind::Png => "png",
            Kind::Dds => "dds",
            Kind::Resource => "resource",
            Kind::Text => "text",
            Kind::Binary => "binary",
        }
    }

    /// The extension given to recovered entries of this kind. A PSIN payload
    /// has no established extension, so it gets the neutral one.
    pub fn extension(self) -> &'static str {
        match self {
            Kind::Xml => "xml",
            Kind::Psin => "bin",
            Kind::Rbf => "rbf",
            Kind::Gfx => "bin",
            Kind::Png => "png",
            Kind::Dds => "dds",
            Kind::Text => "txt",
            Kind::Resource | Kind::Binary => "bin",
        }
    }

    /// Whether [`Kind::extension`] is a neutral display fallback rather than
    /// an established extension for the format. A PSIN payload is named `.bin`
    /// because nothing establishes its real extension.
    pub fn extension_is_synthetic(self) -> bool {
        matches!(self, Kind::Psin | Kind::Resource | Kind::Binary | Kind::Gfx)
    }

    /// Whether data of this kind is only expected at the start of a file.
    pub fn is_file_start(self) -> bool {
        !matches!(self, Kind::Text | Kind::Binary)
    }

    fn to_u8(self) -> u8 {
        Kind::ALL.iter().position(|kind| *kind == self).unwrap_or(0) as u8
    }

    fn from_u8(value: u8) -> Option<Kind> {
        Kind::ALL.get(usize::from(value)).copied()
    }
}

/// One zlib stream that inflated completely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stream {
    pub offset: u64,
    pub stored_len: u32,
    pub len: u32,
    pub kind: Kind,
}

impl Stream {
    /// The end of the stream rounded up to the next aligned offset.
    pub fn aligned_end(&self) -> Option<u64> {
        align_up(self.offset.checked_add(self.stored_len.into())?)
    }

    /// Whether `next` starts at the first aligned offset after this stream.
    pub fn is_followed_by(&self, next: &Stream) -> bool {
        self.aligned_end() == Some(next.offset)
    }
}

/// A resource reconstructed from consecutive streams: its system pages, then
/// its graphics pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// The archive offset of the first system stream, which is also the
    /// offset of its entry.
    pub offset: u64,
    first_stream: u32,
    pub layout: Layout,
}

impl Resource {
    pub fn status(&self) -> Status {
        self.layout.status()
    }
}

/// Consecutive streams that hold one file or resource, or what was recovered
/// of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The archive offset of the first stream. Unique within an archive.
    pub offset: u64,
    first_stream: u32,
    stream_count: u32,
    pub kind: Kind,
    pub status: Status,
    /// Inflated size in bytes. For resources, system and graphics data.
    pub len: u64,
    /// Compressed size in bytes.
    pub stored_len: u64,
}

impl Entry {
    pub fn stream_count(&self) -> u32 {
        self.stream_count
    }
}

/// Bytes between recovered streams that are not zero padding: data that is
/// not stored as zlib streams, for example the encrypted table of contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub offset: u64,
    pub len: u64,
}

/// The result of a completed scan. A cancelled or failed scan yields no index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    pub archive_len: u64,
    pub header: Header,
    pub streams: Vec<Stream>,
    /// Sorted by offset. Their streams are not part of any other entry.
    pub resources: Vec<Resource>,
    pub entries: Vec<Entry>,
    pub regions: Vec<Region>,
}

impl Index {
    /// `streams` must be sorted by offset and must not overlap. `resources`
    /// must be sorted and claim disjoint runs of streams.
    pub(crate) fn new(
        archive_len: u64,
        header: Header,
        streams: Vec<Stream>,
        resources: Vec<Resource>,
        regions: Vec<Region>,
    ) -> Self {
        let entries = group(&streams, &resources);
        let regions = subtract_raw_pages(regions, &resources);
        Self {
            archive_len,
            header,
            streams,
            resources,
            entries,
            regions,
        }
    }

    pub fn entry_streams(&self, entry: &Entry) -> &[Stream] {
        let first = entry.first_stream as usize;
        &self.streams[first..first + entry.stream_count as usize]
    }

    pub fn entry_at(&self, offset: u64) -> Option<&Entry> {
        let ix = self
            .entries
            .binary_search_by_key(&offset, |entry| entry.offset)
            .ok()?;
        Some(&self.entries[ix])
    }

    pub fn region_at(&self, offset: u64) -> Option<&Region> {
        let ix = self
            .regions
            .binary_search_by_key(&offset, |region| region.offset)
            .ok()?;
        Some(&self.regions[ix])
    }

    pub fn resource_at(&self, offset: u64) -> Option<&Resource> {
        let ix = self
            .resources
            .binary_search_by_key(&offset, |resource| resource.offset)
            .ok()?;
        Some(&self.resources[ix])
    }

    /// The pages of `resource` with their streams, in storage order.
    pub fn resource_pages<'a>(
        &'a self,
        resource: &'a Resource,
    ) -> impl Iterator<Item = (&'a Page, &'a [Stream])> + 'a {
        let mut next = resource.first_stream as usize;
        resource.layout.pages.iter().map(move |page| {
            let streams = &self.streams[next..next + page.stream_count as usize];
            next += page.stream_count as usize;
            (page, streams)
        })
    }

    /// The resource page whose first stream is at `offset`, with the
    /// resource and the page's position among all pages of the resource.
    pub fn page_at(&self, offset: u64) -> Option<(&Resource, usize, &Page, &[Stream])> {
        let stream = self
            .streams
            .binary_search_by_key(&offset, |stream| stream.offset)
            .ok()?;
        let ix = self
            .resources
            .partition_point(|resource| resource.first_stream as usize <= stream)
            .checked_sub(1)?;
        let resource = &self.resources[ix];
        self.resource_pages(resource)
            .enumerate()
            .find(|(_, (_, streams))| streams[0].offset == offset)
            .map(|(position, (page, streams))| (resource, position, page, streams))
    }

    /// Bytes after the table of contents.
    pub fn data_len(&self) -> u64 {
        self.archive_len.saturating_sub(self.header.data_start())
    }

    /// Bytes inside recovered streams, including alignment padding.
    pub fn recovered_len(&self) -> u64 {
        self.streams
            .iter()
            .map(|stream| stream.aligned_end().unwrap_or(stream.offset) - stream.offset)
            .sum()
    }

    pub fn unrecovered_len(&self) -> u64 {
        self.regions.iter().map(|region| region.len).sum()
    }
}

/// Removes the raw resource pages from the unrecovered regions: they are
/// recovered data, even though no zlib stream holds them.
fn subtract_raw_pages(regions: Vec<Region>, resources: &[Resource]) -> Vec<Region> {
    let mut ranges: Vec<(u64, u64)> = resources
        .iter()
        .flat_map(|resource| resource.layout.pages.iter())
        .filter_map(|page| match page.storage {
            Storage::Raw { offset } => Some((offset, offset.checked_add(page.len)?)),
            Storage::Streams => None,
        })
        .collect();
    if ranges.is_empty() {
        return regions;
    }
    ranges.sort_unstable();
    let mut out = Vec::with_capacity(regions.len());
    for region in regions {
        let mut pieces = vec![(region.offset, region.offset + region.len)];
        for &(from, to) in &ranges {
            let mut kept = Vec::with_capacity(pieces.len());
            for (start, end) in pieces {
                if to <= start || from >= end {
                    kept.push((start, end));
                    continue;
                }
                if start < from {
                    kept.push((start, from));
                }
                if to < end {
                    kept.push((to, end));
                }
            }
            pieces = kept;
        }
        out.extend(
            pieces
                .into_iter()
                .filter(|(start, end)| end > start)
                .map(|(start, end)| Region {
                    offset: start,
                    len: end - start,
                }),
        );
    }
    out.sort_unstable_by_key(|region| region.offset);
    out
}

/// One entry per resource for the streams it claims. Other streams join the
/// previous entry when they directly follow a full 64 KiB chunk and do not
/// themselves look like the start of a file.
fn group(streams: &[Stream], resources: &[Resource]) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut resources = resources.iter().peekable();
    // Whether the last entry is a plain file that the next stream may continue.
    let mut open = false;
    let mut ix = 0;
    while ix < streams.len() {
        if let Some(resource) = resources.next_if(|r| r.first_stream as usize == ix) {
            let count = resource.layout.stream_count();
            let claimed = &streams[ix..ix + count as usize];
            entries.push(Entry {
                offset: resource.offset,
                first_stream: ix as u32,
                stream_count: count,
                kind: Kind::Resource,
                status: resource.status(),
                len: resource.layout.segment_len(Segment::System)
                    + resource.layout.segment_len(Segment::Graphics),
                stored_len: claimed.iter().map(|s| u64::from(s.stored_len)).sum(),
            });
            open = false;
            ix += count as usize;
            continue;
        }
        let stream = &streams[ix];
        let continues = open && {
            let previous = &streams[ix - 1];
            previous.len == CHUNK_LEN
                && previous.is_followed_by(stream)
                && !stream.kind.is_file_start()
        };
        match entries.last_mut() {
            Some(entry) if continues => {
                entry.stream_count += 1;
                entry.len += u64::from(stream.len);
                entry.stored_len += u64::from(stream.stored_len);
            }
            _ => entries.push(Entry {
                offset: stream.offset,
                first_stream: ix as u32,
                stream_count: 1,
                kind: stream.kind,
                status: Status::Unverified,
                len: stream.len.into(),
                stored_len: stream.stored_len.into(),
            }),
        }
        open = true;
        ix += 1;
    }
    for entry in &mut entries {
        if entry.kind == Kind::Resource {
            continue;
        }
        let last = &streams[(entry.first_stream + entry.stream_count - 1) as usize];
        entry.status = match entry.kind {
            Kind::Text | Kind::Binary => Status::Unverified,
            _ if last.len == CHUNK_LEN => Status::Partial,
            _ => Status::Complete,
        };
    }
    entries
}

/// Scan progress in bytes. `done` may briefly exceed `total` because
/// streams that cross a segment boundary are read twice.
#[derive(Debug, Default)]
pub struct Progress {
    done: AtomicU64,
    total: AtomicU64,
}

impl Progress {
    pub fn fraction(&self) -> Option<f32> {
        let total = self.total.load(Ordering::Relaxed);
        let done = self.done.load(Ordering::Relaxed);
        (total > 0).then(|| (done as f64 / total as f64).min(1.0) as f32)
    }

    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed).min(self.total())
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
}

/// Inflates `streams`, for example those of one resource page, into `out`,
/// checking each against the index. Returns [`Error::Cancelled`] if `cancel`
/// is set, checked between streams and as each produces output.
pub fn read_streams<S: Read + Seek>(
    mut source: S,
    index: &Index,
    streams: &[Stream],
    limit: u64,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> Result<u64, Error> {
    read_streams_mut(&mut source, index, streams, limit, out, cancel)
}

fn read_streams_mut<S: Read + Seek>(
    source: &mut S,
    index: &Index,
    streams: &[Stream],
    limit: u64,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> Result<u64, Error> {
    let len: u64 = streams.iter().map(|s| u64::from(s.len)).sum();
    if len > limit {
        return Err(Error::TooLarge { len, limit });
    }
    check_len(source, index)?;
    let mut window = scan::Window::new(source, index.archive_len);
    let mut scratch = vec![0; scan::SCRATCH_LEN];
    for stream in streams {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let inflated = scan::inflate(
            &mut window,
            stream.offset,
            stream.len.into(),
            &mut scratch,
            &mut |bytes| {
                if cancel.load(Ordering::Relaxed) {
                    return Err(Error::Cancelled);
                }
                out.write_all(bytes).map_err(Error::Io)
            },
        )?;
        if inflated != Some((stream.stored_len.into(), stream.len.into())) {
            return Err(Error::Changed(format!(
                "the stream at {:#x} does not match the index",
                stream.offset
            )));
        }
    }
    Ok(len)
}

/// Copies the stored bytes of one raw resource page into `out`.
fn read_raw_page<S: Read + Seek>(
    source: &mut S,
    index: &Index,
    offset: u64,
    len: u64,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> Result<u64, Error> {
    if offset
        .checked_add(len)
        .is_none_or(|end| end > index.archive_len)
    {
        return Err(Error::Changed(
            "the raw page lies outside the indexed archive".into(),
        ));
    }
    source.seek(SeekFrom::Start(offset))?;
    let mut reader = source.take(len);
    let mut buf = vec![0u8; scan::SCRATCH_LEN];
    let mut copied = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        out.write_all(&buf[..read])?;
        copied += read as u64;
    }
    if copied != len {
        return Err(Error::Changed(
            "the archive is shorter than its index".into(),
        ));
    }
    Ok(copied)
}

/// Writes one page of `resource`: the streams of a stream page are inflated,
/// a raw page is copied as stored. Returns the number of bytes written.
pub fn read_page<S: Read + Seek>(
    mut source: S,
    index: &Index,
    resource: &Resource,
    position: usize,
    limit: u64,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> Result<u64, Error> {
    let page = resource
        .layout
        .pages
        .get(position)
        .ok_or_else(|| Error::Changed(format!("the resource has no page {position}")))?;
    if page.len > limit {
        return Err(Error::TooLarge {
            len: page.len,
            limit,
        });
    }
    let skip: usize = resource
        .layout
        .pages
        .iter()
        .take(position)
        .map(|page| page.stream_count as usize)
        .sum();
    let next = resource.first_stream as usize + skip;
    match page.storage {
        Storage::Streams => {
            let count = page.stream_count as usize;
            let streams = index
                .streams
                .get(next..next + count)
                .ok_or_else(|| Error::Changed("a page has too few streams".into()))?;
            read_streams_mut(&mut source, index, streams, page.len, out, cancel)
        }
        Storage::Raw { offset } => read_raw_page(&mut source, index, offset, page.len, out, cancel),
    }
}

/// Inflates one entry into `out` and checks it against the index. Returns the
/// number of bytes written. A resource is written as its system pages
/// followed by its graphics pages, the layout its pointers refer to; a raw
/// page is copied as it is stored.
pub fn read_entry<S: Read + Seek>(
    mut source: S,
    index: &Index,
    entry: &Entry,
    limit: u64,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> Result<u64, Error> {
    if entry.kind == Kind::Resource
        && let Some(resource) = index.resource_at(entry.offset)
    {
        return read_resource(&mut source, index, resource, limit, out, cancel);
    }
    read_streams_mut(
        &mut source,
        index,
        index.entry_streams(entry),
        limit,
        out,
        cancel,
    )
}

/// Writes every page of `resource` in order: streams are inflated and a raw
/// page is copied.
fn read_resource<S: Read + Seek>(
    source: &mut S,
    index: &Index,
    resource: &Resource,
    limit: u64,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> Result<u64, Error> {
    let total = resource.layout.segment_len(Segment::System)
        + resource.layout.segment_len(Segment::Graphics);
    if total > limit {
        return Err(Error::TooLarge { len: total, limit });
    }
    let mut next = resource.first_stream as usize;
    let mut written = 0u64;
    for page in &resource.layout.pages {
        match page.storage {
            Storage::Streams => {
                let count = page.stream_count as usize;
                let streams = index
                    .streams
                    .get(next..next + count)
                    .ok_or_else(|| Error::Changed("a page has too few streams".into()))?;
                read_streams_mut(source, index, streams, limit, out, cancel)?;
                next += count;
            }
            Storage::Raw { offset } => {
                read_raw_page(source, index, offset, page.len, out, cancel)?;
            }
        }
        written += page.len;
    }
    Ok(written)
}

fn check_len(source: &mut impl Seek, index: &Index) -> Result<(), Error> {
    let len = source.seek(SeekFrom::End(0))?;
    if len != index.archive_len {
        return Err(Error::Changed(format!(
            "its size is {len} bytes, the index expects {}",
            index.archive_len
        )));
    }
    Ok(())
}

/// Copies the raw bytes of a region into `out`. Returns [`Error::Cancelled`]
/// if `cancel` is set, checked as the bytes are copied.
pub fn read_region<S: Read + Seek>(
    mut source: S,
    region: &Region,
    limit: u64,
    out: &mut dyn Write,
    cancel: &AtomicBool,
) -> Result<u64, Error> {
    if region.len > limit {
        return Err(Error::TooLarge {
            len: region.len,
            limit,
        });
    }
    let len = source.seek(SeekFrom::End(0))?;
    if region
        .offset
        .checked_add(region.len)
        .is_none_or(|end| end > len)
    {
        return Err(Error::Changed(
            "the archive is shorter than its index".into(),
        ));
    }
    source.seek(SeekFrom::Start(region.offset))?;
    let mut reader = source.take(region.len);
    let mut buf = vec![0u8; scan::SCRATCH_LEN];
    let mut copied = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        out.write_all(&buf[..read])?;
        copied += read as u64;
    }
    if copied != region.len {
        return Err(Error::Changed(
            "the archive is shorter than its index".into(),
        ));
    }
    Ok(copied)
}

/// The segment and 1-based position of `page` within its segment.
pub fn page_label(layout: &Layout, position: usize) -> (Segment, usize) {
    let page = &layout.pages[position];
    let before = layout.pages[..position]
        .iter()
        .filter(|other| other.segment == page.segment)
        .count();
    (page.segment, before + 1)
}

#[cfg(test)]
pub(crate) mod tests;
