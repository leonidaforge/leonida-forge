//! Resource page splitting for a decoded native row.
//!
//! A native resource row is stored as one decoded chunk per page, except that
//! a page larger than 32 MiB is split into several chunks. The chunk table
//! carries each chunk's decoded length, so the page sizes can be recovered
//! before the page map is read. The page map then says how many of those pages
//! are system pages and how many are graphics pages.

use std::io::{Read, Seek, SeekFrom};

use super::Error;
use super::metadata::ChunkTable;
use crate::resource::{self, PageMap};

/// A split of a decoded resource into its system and graphics segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSplit {
    pub system_len: u64,
    pub graphics_len: u64,
    pub system_pages: u8,
    pub graphics_pages: u8,
}

const PAGE_MAP_HEADER: u64 = resource::PAGE_MAP_HEADER_LEN as u64;

/// Splits the decoded payload in `source` using `chunks` and the page map at
/// system `+0x08`. `len` is the payload length and `max_system` bounds how much
/// of the payload may be read to find the map.
pub fn page_split<R: Read + Seek>(
    source: &mut R,
    len: u64,
    chunks: &ChunkTable,
    max_system: u64,
) -> Result<PageSplit, Error> {
    if len < PAGE_MAP_HEADER {
        return Err(Error::Changed(
            "the resource is shorter than its header".into(),
        ));
    }
    if chunks.chunks.is_empty() {
        return Err(Error::Changed("the resource has no chunks".into()));
    }
    let header = read_at(source, 0, PAGE_MAP_HEADER as usize, len)?;
    let map_offset = u64::from(resource::page_map_offset(&header).ok_or_else(|| {
        Error::Changed("the resource header does not hold a system page-map pointer".into())
    })?);
    if map_offset > max_system || map_offset.saturating_add(PAGE_MAP_HEADER) > len {
        return Err(Error::Changed(format!(
            "the page map at {map_offset:#x} is outside the bounded system area"
        )));
    }
    let counts = read_at(source, map_offset, PAGE_MAP_HEADER as usize, len)?;
    let declared = u64::from(counts[8]) + u64::from(counts[9]);
    if declared > u64::from(u8::MAX) * 2 {
        return Err(Error::Changed(format!(
            "the page map declares {declared} pages"
        )));
    }
    let map_len = PAGE_MAP_HEADER + 8 * declared;
    if map_offset
        .checked_add(map_len)
        .is_none_or(|end| end > len || end > max_system)
    {
        return Err(Error::Changed(format!(
            "the {map_len}-byte page map at {map_offset:#x} is not inside the bounded system area"
        )));
    }
    let map_bytes = read_at(source, map_offset, map_len as usize, len)?;
    let map = PageMap::parse(map_offset as u32, &map_bytes).map_err(|err| {
        Error::Changed(format!(
            "the page map at {map_offset:#x}: {}",
            err.describe()
        ))
    })?;

    let mut lengths = Vec::with_capacity(chunks.chunks.len());
    for chunk in &chunks.chunks {
        if chunk.logical_len == 0 {
            return Err(Error::Changed(
                "a resource chunk has a zero decoded length".into(),
            ));
        }
        lengths.push(u64::from(chunk.logical_len));
    }
    let mut groups = resource::group_pages(&lengths);
    if groups.len() as u64 != declared {
        // A page of exactly 32 MiB is indistinguishable from the start of a
        // split page. When the declared count matches one chunk per page, use
        // that reading instead.
        if lengths.len() as u64 == declared {
            groups = lengths.iter().map(|&len| (1, len)).collect();
        } else {
            return Err(Error::Changed(format!(
                "the chunks describe {} pages but the page map declares {declared}",
                groups.len()
            )));
        }
    }
    let total = groups
        .iter()
        .try_fold(0u64, |total, &(_, len)| total.checked_add(len));
    let Some(total) = total else {
        return Err(Error::Changed(
            "the decoded chunk lengths overflow the payload size".into(),
        ));
    };
    if total != len {
        return Err(Error::Changed(format!(
            "the chunks describe {total} decoded bytes but the payload is {len}"
        )));
    }
    let system_len = groups
        .iter()
        .take(usize::from(map.system_pages))
        .try_fold(0u64, |total, &(_, len)| total.checked_add(len));
    let Some(system_len) = system_len else {
        return Err(Error::Changed(
            "the system page lengths overflow the payload size".into(),
        ));
    };
    let graphics_len = total - system_len;
    if map_offset
        .checked_add(map_len)
        .is_none_or(|end| end > system_len)
    {
        return Err(Error::Changed(format!(
            "the page map at {map_offset:#x} is outside the {system_len}-byte system segment"
        )));
    }
    Ok(PageSplit {
        system_len,
        graphics_len,
        system_pages: map.system_pages,
        graphics_pages: map.graphics_pages,
    })
}

fn read_at<R: Read + Seek>(
    source: &mut R,
    at: u64,
    len: usize,
    file_len: u64,
) -> Result<Vec<u8>, Error> {
    if at.checked_add(len as u64).is_none_or(|end| end > file_len) {
        return Err(Error::Changed(format!(
            "the {len}-byte read at {at:#x} is outside the {file_len}-byte payload"
        )));
    }
    let mut bytes = vec![0u8; len];
    source.seek(SeekFrom::Start(at)).map_err(Error::Io)?;
    source.read_exact(&mut bytes).map_err(Error::Io)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::SPLIT_LEN;
    use crate::rpf::metadata::Chunk;
    use std::io;

    const PAGE_MAP_BASE: u64 = 0x5000_0000;

    fn chunk(logical_len: u32) -> Chunk {
        Chunk {
            logical_len,
            stored_len: logical_len,
            padding: 0,
            compressed_len: logical_len,
            method: 0,
        }
    }

    fn payload(len: usize, map_offset: usize, system: u8, graphics: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        bytes[8..16].copy_from_slice(&(PAGE_MAP_BASE | map_offset as u64).to_le_bytes());
        bytes[map_offset + 8] = system;
        bytes[map_offset + 9] = graphics;
        bytes
    }

    fn table(lengths: &[u32]) -> ChunkTable {
        ChunkTable {
            encoding: 2,
            chunks: lengths.iter().copied().map(chunk).collect(),
        }
    }

    fn split(bytes: &[u8], lengths: &[u32]) -> Result<PageSplit, Error> {
        page_split(
            &mut io::Cursor::new(bytes),
            bytes.len() as u64,
            &table(lengths),
            crate::rpf::RESOURCE_SYSTEM_LIMIT,
        )
    }

    #[test]
    fn splits_one_system_and_one_graphics_page() {
        let bytes = payload(0x2000, 0x40, 1, 1);
        let split = split(&bytes, &[0x1000, 0x1000]).unwrap();
        assert_eq!((split.system_len, split.graphics_len), (0x1000, 0x1000));
        assert_eq!((split.system_pages, split.graphics_pages), (1, 1));
    }

    #[test]
    fn splits_a_map_in_the_second_system_page() {
        let bytes = payload(0x3000, 0x1800, 2, 1);
        let split = split(&bytes, &[0x1000, 0x1000, 0x1000]).unwrap();
        assert_eq!((split.system_len, split.graphics_len), (0x2000, 0x1000));
    }

    #[test]
    fn a_split_chunk_continues_its_page() {
        let len = SPLIT_LEN as usize + 0x2000;
        let bytes = payload(len, 0x40, 1, 1);
        let split = split(&bytes, &[SPLIT_LEN as u32, 0x1000, 0x1000]).unwrap();
        assert_eq!(
            (split.system_len, split.graphics_len),
            (SPLIT_LEN + 0x1000, 0x1000)
        );
    }

    #[test]
    fn an_exact_split_length_page_can_be_one_page_per_chunk() {
        let bytes = payload((SPLIT_LEN * 2) as usize, 0x40, 1, 1);
        let split = split(&bytes, &[SPLIT_LEN as u32, SPLIT_LEN as u32]).unwrap();
        assert_eq!(
            (split.system_len, split.graphics_len),
            (SPLIT_LEN, SPLIT_LEN)
        );
    }

    #[test]
    fn a_page_count_mismatch_is_rejected() {
        let bytes = payload(0x2000, 0x40, 1, 1);
        let err = split(&bytes, &[0x1000, 0x1000, 0x1000]).unwrap_err();
        assert!(err.to_string().contains("page map declares"), "{err}");
    }

    #[test]
    fn a_map_outside_the_system_pages_is_rejected() {
        let bytes = payload(0x2000, 0x1800, 1, 1);
        let err = split(&bytes, &[0x1000, 0x1000]).unwrap_err();
        assert!(err.to_string().contains("system segment"), "{err}");
    }

    #[test]
    fn a_non_system_map_pointer_is_rejected() {
        let mut bytes = payload(0x2000, 0x40, 1, 1);
        bytes[8..16].copy_from_slice(&(0x6000_0000u64 | 0x40).to_le_bytes());
        let err = split(&bytes, &[0x1000, 0x1000]).unwrap_err();
        assert!(err.to_string().contains("system page-map pointer"), "{err}");
    }

    #[test]
    fn a_non_zero_header_word_is_rejected() {
        let mut bytes = payload(0x2000, 0x40, 1, 1);
        bytes[0] = 1;
        let err = split(&bytes, &[0x1000, 0x1000]).unwrap_err();
        assert!(err.to_string().contains("system page-map pointer"), "{err}");
    }

    #[test]
    fn a_non_zero_page_map_slot_is_rejected() {
        let mut bytes = payload(0x2000, 0x40, 1, 1);
        bytes[0x50] = 1;
        let err = split(&bytes, &[0x1000, 0x1000]).unwrap_err();
        assert!(err.to_string().contains("non-zero"), "{err}");
    }

    #[test]
    fn a_zero_decoded_chunk_is_rejected() {
        let bytes = payload(0x2000, 0x40, 1, 1);
        let err = split(&bytes, &[0, 0x2000]).unwrap_err();
        assert!(err.to_string().contains("zero decoded length"), "{err}");
    }

    #[test]
    fn a_payload_that_does_not_match_the_chunks_is_rejected() {
        let bytes = payload(0x2000, 0x40, 1, 1);
        let err = split(&bytes, &[0x1000, 0xFFF]).unwrap_err();
        assert!(err.to_string().contains("decoded bytes"), "{err}");
    }
}
