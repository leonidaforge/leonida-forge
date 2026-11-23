//! Indexes persisted between runs, so an archive is scanned once per change.
//!
//! A cache file holds the stream, region and resource tables, not archive
//! data. It is used only if the archive still has the size and modification
//! time it had when the scan started.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use super::{Error, HEADER_LEN, Header, Index, Kind, Progress, Region, Resource, Stream, scan};
use crate::resource::{Layout, Page, PageMap, PageMapError, Pointers, Segment};

const MAGIC: &[u8; 8] = b"LFRPFIDX";
/// Version 1 indexes did not reconstruct resources.
const VERSION: u32 = 2;
const STREAM_LEN: usize = 8 + 4 + 4 + 1;
const REGION_LEN: usize = 8 + 8;
/// A resource record with no pages.
const MIN_RESOURCE_LEN: usize = 4 + 1 + 4 + 1 + 1 + 1 + 1 + 4 * 4 + 1 + 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    secs: u64,
    nanos: u32,
}

fn stamp(archive: &Path) -> io::Result<Stamp> {
    let metadata = fs::metadata(archive)?;
    let modified = metadata
        .modified()?
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    Ok(Stamp {
        len: metadata.len(),
        secs: modified.as_secs(),
        nanos: modified.subsec_nanos(),
    })
}

/// The cache file for `archive`, named after a hash of its absolute path.
fn cache_file(cache_dir: &Path, archive: &Path) -> PathBuf {
    let absolute = std::path::absolute(archive).unwrap_or_else(|_| archive.to_path_buf());
    // Windows paths are case-insensitive.
    let key = absolute.to_string_lossy().to_lowercase();
    let digest = Sha256::digest(key.as_bytes());
    let name: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    cache_dir.join(format!("{name}.lfidx"))
}

/// The persisted index of `archive`, if it is still valid.
pub fn load_cached(cache_dir: &Path, archive: &Path) -> Option<Index> {
    let stamp = stamp(archive).ok()?;
    let bytes = fs::read(cache_file(cache_dir, archive)).ok()?;
    decode(&bytes, stamp)
}

/// Persists `index`, which must have been built from `archive` as it is now.
/// The file is written next to its final name and renamed into place, so
/// readers never see a partial file.
pub fn store_cached(cache_dir: &Path, archive: &Path, index: &Index) -> io::Result<()> {
    let stamp = stamp(archive)?;
    if stamp.len != index.archive_len {
        return Err(io::Error::other("the archive changed during the scan"));
    }
    store(cache_dir, archive, index, stamp)
}

fn store(cache_dir: &Path, archive: &Path, index: &Index, stamp: Stamp) -> io::Result<()> {
    fs::create_dir_all(cache_dir)?;
    let path = cache_file(cache_dir, archive);
    let temp = path.with_extension("lfidx.tmp");
    fs::write(&temp, encode(index, stamp))?;
    fs::rename(&temp, &path)
}

/// How [`open`] obtained an index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Cache,
    Scan,
}

/// Loads the persisted index of `archive` or scans it. A fresh index is
/// persisted when `cache_dir` is given and the archive did not change while
/// it was scanned. Failing to persist is not an error.
pub fn open(
    archive: &Path,
    cache_dir: Option<&Path>,
    progress: &Progress,
    cancel: &AtomicBool,
) -> Result<(Index, Origin), Error> {
    let before = stamp(archive)?;
    if let Some(dir) = cache_dir
        && let Some(index) = load_cached(dir, archive)
    {
        return Ok((index, Origin::Cache));
    }
    let source = lforge_binary::Source::open(archive)?;
    let index = scan(source, progress, cancel)?;
    if let Some(dir) = cache_dir
        && stamp(archive).is_ok_and(|after| after == before)
    {
        let _ = store(dir, archive, &index, before);
    }
    Ok((index, Origin::Scan))
}

fn encode(index: &Index, stamp: Stamp) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        64 + HEADER_LEN + index.streams.len() * STREAM_LEN + index.regions.len() * REGION_LEN,
    );
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&stamp.len.to_le_bytes());
    out.extend_from_slice(&stamp.secs.to_le_bytes());
    out.extend_from_slice(&stamp.nanos.to_le_bytes());
    out.extend_from_slice(index.header.bytes());
    out.extend_from_slice(&(index.streams.len() as u64).to_le_bytes());
    for stream in &index.streams {
        out.extend_from_slice(&stream.offset.to_le_bytes());
        out.extend_from_slice(&stream.stored_len.to_le_bytes());
        out.extend_from_slice(&stream.len.to_le_bytes());
        out.push(stream.kind.to_u8());
    }
    out.extend_from_slice(&(index.regions.len() as u64).to_le_bytes());
    for region in &index.regions {
        out.extend_from_slice(&region.offset.to_le_bytes());
        out.extend_from_slice(&region.len.to_le_bytes());
    }
    out.extend_from_slice(&(index.resources.len() as u64).to_le_bytes());
    for resource in &index.resources {
        encode_resource(resource, &mut out);
    }
    out
}

fn encode_resource(resource: &Resource, out: &mut Vec<u8>) {
    let layout = &resource.layout;
    out.extend_from_slice(&resource.first_stream.to_le_bytes());
    let (code, map) = match layout.page_map {
        Ok(map) => (0, map),
        Err(err) => (
            match err {
                PageMapError::Outside => 1,
                PageMapError::NonZero => 2,
                PageMapError::NoSystemPage => 3,
            },
            PageMap {
                offset: 0,
                system_pages: 0,
                graphics_pages: 0,
            },
        ),
    };
    out.push(code);
    out.extend_from_slice(&map.offset.to_le_bytes());
    out.push(map.system_pages);
    out.push(map.graphics_pages);
    out.push(layout.tag.is_some().into());
    out.push(layout.tag.unwrap_or(0));
    let pointers = layout.pointers;
    for count in [
        pointers.system,
        pointers.graphics,
        pointers.system_outside,
        pointers.graphics_outside,
    ] {
        out.extend_from_slice(&count.to_le_bytes());
    }
    out.push(pointers.checked.into());
    out.extend_from_slice(&(layout.pages.len() as u16).to_le_bytes());
    for page in &layout.pages {
        out.push(match page.segment {
            Segment::System => 0,
            Segment::Graphics => 1,
        });
        out.extend_from_slice(&page.stream_count.to_le_bytes());
    }
}

/// Decodes one resource whose streams must follow `cut`, the first stream
/// not claimed by the previous resource.
fn decode_resource(reader: &mut Reader, streams: &[Stream], cut: usize) -> Option<Resource> {
    let first_stream = reader.u32()?;
    let first = usize::try_from(first_stream).ok()?;
    let code = reader.u8()?;
    let map = PageMap {
        offset: reader.u32()?,
        system_pages: reader.u8()?,
        graphics_pages: reader.u8()?,
    };
    let page_map = match code {
        0 => Ok(map),
        1 => Err(PageMapError::Outside),
        2 => Err(PageMapError::NonZero),
        3 => Err(PageMapError::NoSystemPage),
        _ => return None,
    };
    let tag = match (reader.u8()?, reader.u8()?) {
        (0, _) => None,
        (1, value) => Some(value),
        _ => return None,
    };
    let pointers = Pointers {
        system: reader.u32()?,
        graphics: reader.u32()?,
        system_outside: reader.u32()?,
        graphics_outside: reader.u32()?,
        checked: match reader.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        },
    };
    let page_count = u16::from_le_bytes(reader.take(2)?.try_into().ok()?);
    if first < cut || streams.get(first)?.kind != Kind::Resource || page_count == 0 {
        return None;
    }
    let mut pages = Vec::with_capacity(page_count.into());
    let mut next = first;
    for _ in 0..page_count {
        let segment = match reader.u8()? {
            0 => Segment::System,
            1 => Segment::Graphics,
            _ => return None,
        };
        let stream_count = reader.u32()?;
        let end = next.checked_add(usize::try_from(stream_count).ok()?)?;
        let claimed = streams.get(next..end).filter(|s| !s.is_empty())?;
        if next > first && !streams[next - 1].is_followed_by(&claimed[0]) {
            return None;
        }
        if claimed
            .windows(2)
            .any(|pair| !pair[0].is_followed_by(&pair[1]))
            || claimed[usize::from(next == first)..]
                .iter()
                .any(|stream| stream.kind.is_file_start())
        {
            return None;
        }
        pages.push(Page {
            segment,
            stream_count,
            len: claimed.iter().map(|s| u64::from(s.len)).sum(),
        });
        next = end;
    }
    let system = pages
        .iter()
        .take_while(|page| page.segment == Segment::System)
        .count();
    let graphics = pages.len() - system;
    let consistent = match page_map {
        Ok(map) => {
            map.system_pages > 0
                && system >= 1
                && system <= usize::from(map.system_pages)
                && graphics <= usize::from(map.graphics_pages)
                && (graphics == 0 || system == usize::from(map.system_pages))
        }
        Err(_) => pages.len() == 1 && system == 1,
    };
    consistent.then(|| Resource {
        offset: streams[first].offset,
        first_stream,
        layout: Layout {
            page_map,
            pages,
            pointers,
            tag,
        },
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.bytes.split_at_checked(n)?;
        self.bytes = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A count of records of `record_len` bytes that must fit in the rest.
    fn count(&mut self, record_len: usize) -> Option<usize> {
        let count = usize::try_from(self.u64()?).ok()?;
        (count.checked_mul(record_len)? <= self.bytes.len()).then_some(count)
    }
}

/// Decodes a cache file. Anything unexpected, including a stale stamp,
/// makes the cache unusable rather than an error.
fn decode(bytes: &[u8], expected: Stamp) -> Option<Index> {
    let mut reader = Reader { bytes };
    if reader.take(MAGIC.len())? != MAGIC || reader.u32()? != VERSION {
        return None;
    }
    let stamp = Stamp {
        len: reader.u64()?,
        secs: reader.u64()?,
        nanos: reader.u32()?,
    };
    if stamp != expected {
        return None;
    }
    let archive_len = stamp.len;
    let header = Header::parse(reader.take(HEADER_LEN)?, archive_len).ok()?;

    let count = reader.count(STREAM_LEN)?;
    let mut streams: Vec<Stream> = Vec::with_capacity(count);
    let mut cut = header.data_start();
    for _ in 0..count {
        let stream = Stream {
            offset: reader.u64()?,
            stored_len: reader.u32()?,
            len: reader.u32()?,
            kind: Kind::from_u8(reader.u8()?)?,
        };
        let end = stream.offset.checked_add(stream.stored_len.into())?;
        if stream.offset < cut || stream.len == 0 || end > archive_len {
            return None;
        }
        cut = stream.aligned_end()?;
        streams.push(stream);
    }

    let count = reader.count(REGION_LEN)?;
    let mut regions: Vec<Region> = Vec::with_capacity(count);
    let mut cut = 0;
    for _ in 0..count {
        let region = Region {
            offset: reader.u64()?,
            len: reader.u64()?,
        };
        let end = region.offset.checked_add(region.len)?;
        if region.offset < cut || end > archive_len {
            return None;
        }
        cut = end;
        regions.push(region);
    }

    let count = reader.count(MIN_RESOURCE_LEN)?;
    let mut resources: Vec<Resource> = Vec::with_capacity(count);
    let mut cut = 0;
    for _ in 0..count {
        let resource = decode_resource(&mut reader, &streams, cut)?;
        cut = resource.first_stream as usize + resource.layout.stream_count() as usize;
        resources.push(resource);
    }
    let heads = streams
        .iter()
        .filter(|stream| stream.kind == Kind::Resource)
        .count();
    if heads != resources.len() || !reader.bytes.is_empty() {
        return None;
    }
    Some(Index::new(archive_len, header, streams, resources, regions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpf::tests::{add_resource, archive, system_data, zlib};

    #[test]
    fn round_trips_and_rejects_stale_or_damaged_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.rpf");
        let mut chunks = vec![zlib(b"<?xml version=\"1.0\"?><a/>")];
        chunks.push(zlib(&[7u8; 300]));
        fs::write(&path, archive(&chunks)).unwrap();
        let cache = dir.path().join("cache");

        let progress = Progress::default();
        let cancel = AtomicBool::new(false);
        let (index, origin) = open(&path, Some(&cache), &progress, &cancel).unwrap();
        assert_eq!(origin, Origin::Scan);
        assert_eq!(index.entries.len(), 2);
        let (cached, origin) = open(&path, Some(&cache), &progress, &cancel).unwrap();
        assert_eq!(origin, Origin::Cache);
        assert_eq!(cached, index);

        let stamp = stamp(&path).unwrap();
        let bytes = encode(&index, stamp);
        assert_eq!(decode(&bytes, stamp), Some(index.clone()));
        let stale = Stamp {
            secs: stamp.secs + 1,
            ..stamp
        };
        assert_eq!(decode(&bytes, stale), None);
        assert_eq!(decode(&bytes[..bytes.len() - 1], stamp), None);
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(decode(&extra, stamp), None);
        let mut bad_kind = bytes.clone();
        let kind_at = 8 + 4 + 8 + 8 + 4 + HEADER_LEN + 8 + 16;
        bad_kind[kind_at] = 0xFF;
        assert_eq!(decode(&bad_kind, stamp), None);
        let mut huge_count = bytes;
        huge_count[8 + 4 + 8 + 8 + 4 + HEADER_LEN..][..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(decode(&huge_count, stamp), None);
    }

    #[test]
    fn resources_round_trip_and_inconsistent_records_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.rpf");
        let mut bytes = archive(&[]);
        let mut system = system_data(0x100, 0xC0, 1, 2);
        system[0x10..0x14].copy_from_slice(b"0DRP");
        add_resource(&mut bytes, &[system, vec![3; 0x2_0000], vec![4; 0x7000]]);
        bytes.resize(bytes.len().next_multiple_of(16), 0);
        fs::write(&path, &bytes).unwrap();
        let (index, _) = open(&path, None, &Progress::default(), &AtomicBool::new(false)).unwrap();
        assert_eq!(index.resources.len(), 1);
        assert_eq!(index.resources[0].layout.pages.len(), 3);

        let stamp = stamp(&path).unwrap();
        let encoded = encode(&index, stamp);
        assert_eq!(decode(&encoded, stamp), Some(index));

        // Indexes from the previous recovery are not current.
        let mut old = encoded.clone();
        old[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(decode(&old, stamp), None);

        // The last page record: a segment byte and a stream count.
        let last = encoded.len() - 5;
        let mut past_end = encoded.clone();
        past_end[last + 1..].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(decode(&past_end, stamp), None);
        let mut bad_segment = encoded.clone();
        bad_segment[last] = 2;
        assert_eq!(decode(&bad_segment, stamp), None);
        // A third system page, although the page map declares one.
        let mut too_many = encoded;
        too_many[last - 5] = 0;
        too_many[last] = 0;
        assert_eq!(decode(&too_many, stamp), None);
    }

    #[test]
    fn a_changed_archive_is_scanned_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.rpf");
        fs::write(&path, archive(&[zlib(b"one")])).unwrap();
        let cache = dir.path().join("cache");
        let progress = Progress::default();
        let cancel = AtomicBool::new(false);
        open(&path, Some(&cache), &progress, &cancel).unwrap();

        fs::write(&path, archive(&[zlib(b"one"), zlib(b"two")])).unwrap();
        let (index, origin) = open(&path, Some(&cache), &progress, &cancel).unwrap();
        assert_eq!(origin, Origin::Scan);
        assert_eq!(index.entries.len(), 2);
    }

    #[test]
    fn cache_keys_ignore_case() {
        let dir = Path::new(r"C:\cache");
        assert_eq!(
            cache_file(dir, Path::new(r"D:\Game\Data.RPF")),
            cache_file(dir, Path::new(r"d:\game\data.rpf"))
        );
        assert_ne!(
            cache_file(dir, Path::new(r"D:\Game\a.rpf")),
            cache_file(dir, Path::new(r"D:\Game\b.rpf"))
        );
    }
}
