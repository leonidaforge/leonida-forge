//! Indexes persisted between runs, so an archive is scanned once per change.
//!
//! A cache file holds the stream and region tables, not archive data. It is
//! used only if the archive still has the size and modification time it had
//! when the scan started.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use crate::{Error, HEADER_LEN, Header, Index, Kind, Progress, Region, Stream, scan};

const MAGIC: &[u8; 8] = b"LFRPFIDX";
const VERSION: u32 = 1;
const STREAM_LEN: usize = 8 + 4 + 4 + 1;
const REGION_LEN: usize = 8 + 8;

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
    out
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
    if !reader.bytes.is_empty() {
        return None;
    }
    Some(Index::new(archive_len, header, streams, regions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{archive, zlib};

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
