//! Tests on synthetic archives built in memory.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use flate2::Compression;
use flate2::write::ZlibEncoder;

use super::scan::{Window, classify, inflate, scan_from};
use super::*;
use crate::resource::PageMapError;

/// The fake table of contents ends here; data starts at the next 16 bytes.
const TOC_END: u32 = 0x9C;

pub(crate) fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub(crate) fn header(toc_end: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; HEADER_LEN];
    bytes[..4].copy_from_slice(&MAGIC);
    bytes[4..8].copy_from_slice(&toc_end.to_le_bytes());
    bytes
}

/// A header, a non-zero table of contents and `chunks` at consecutive
/// aligned offsets.
pub(crate) fn archive(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = header(TOC_END);
    bytes.resize(TOC_END as usize, 0xA5);
    for chunk in chunks {
        pad(&mut bytes);
        bytes.extend_from_slice(chunk);
    }
    pad(&mut bytes);
    bytes
}

fn pad(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(ALIGN as usize), 0);
}

/// Deterministic data that compresses only a little.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).max(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state % 64) as u8 + b' '
        })
        .collect()
}

fn chunked(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(CHUNK_LEN as usize).map(zlib).collect()
}

fn scan_bytes(bytes: Vec<u8>) -> Index {
    scan(
        Cursor::new(bytes),
        &Progress::default(),
        &AtomicBool::new(false),
    )
    .unwrap()
}

fn read(bytes: &[u8], index: &Index, entry: &Entry) -> Vec<u8> {
    let mut out = Vec::new();
    read_entry(
        Cursor::new(bytes),
        index,
        entry,
        u64::MAX,
        &mut out,
        &AtomicBool::new(false),
    )
    .unwrap();
    out
}

fn xml(len: usize) -> Vec<u8> {
    let mut data = b"\xEF\xBB\xBF<?xml version=\"1.0\"?>\n".to_vec();
    data.extend(noise(len - data.len(), len as u32));
    data
}

#[test]
fn recognises_the_signature() {
    assert!(is_rpf9(b"9FPR\x00\x01"));
    assert!(!is_rpf9(b"RPF9"));
    assert!(!is_rpf9(b"9FP"));
    assert!(!is_rpf9(b""));
}

#[test]
fn parses_valid_headers_and_rejects_invalid_ones() {
    let header_bytes = header(0x360);
    let parsed = Header::parse(&header_bytes, 0x1000).unwrap();
    assert_eq!(parsed.toc_end(), 0x360);
    assert_eq!(parsed.data_start(), 0x360);
    assert_eq!(
        Header::parse(&header(0x361), 0x1000).unwrap().data_start(),
        0x370
    );

    assert!(matches!(
        Header::parse(b"PK\x03\x04", 100),
        Err(Error::NotRpf9)
    ));
    assert!(matches!(
        Header::parse(&header_bytes[..32], 100),
        Err(Error::InvalidHeader(_))
    ));
    assert!(matches!(
        Header::parse(&header(0x20), 0x1000),
        Err(Error::InvalidHeader(_))
    ));
    assert!(matches!(
        Header::parse(&header(0x2000), 0x1000),
        Err(Error::InvalidHeader(_))
    ));
    assert!(matches!(
        Header::parse(&header(u32::MAX), u64::MAX),
        Ok(header) if header.data_start() == 0x1_0000_0000
    ));
}

#[test]
fn reads_headers_from_truncated_files() {
    let mut short = Cursor::new(header(0x40)[..40].to_vec());
    assert!(matches!(
        read_header(&mut short),
        Err(Error::InvalidHeader(_))
    ));
    let mut empty = Cursor::new(Vec::new());
    assert!(matches!(read_header(&mut empty), Err(Error::NotRpf9)));
    let mut only_header = Cursor::new(header(0x40));
    assert_eq!(read_header(&mut only_header).unwrap().toc_end(), 0x40);
}

#[test]
fn an_archive_without_data_has_no_entries() {
    let index = scan_bytes(header(0x40));
    assert!(index.entries.is_empty());
    assert!(index.regions.is_empty());
    assert_eq!(index.data_len(), 0);
}

#[test]
fn joins_64_kib_chunks_into_one_file() {
    let data = xml(2 * CHUNK_LEN as usize + 1234);
    let mut chunks = chunked(&data);
    assert_eq!(chunks.len(), 3);
    chunks.push(zlib(b"\x89PNG\r\n\x1A\nrest"));
    let bytes = archive(&chunks);
    let index = scan_bytes(bytes.clone());

    assert_eq!(index.streams.len(), 4);
    assert_eq!(index.entries.len(), 2);
    let file = &index.entries[0];
    assert_eq!(file.offset, u64::from(TOC_END).next_multiple_of(ALIGN));
    assert_eq!((file.kind, file.status), (Kind::Xml, Status::Complete));
    assert_eq!(file.stream_count(), 3);
    assert_eq!(file.len, data.len() as u64);
    assert_eq!(
        file.stored_len,
        chunks[..3].iter().map(|c| c.len() as u64).sum::<u64>()
    );
    assert_eq!(read(&bytes, &index, file), data);

    let png = &index.entries[1];
    assert_eq!((png.kind, png.status), (Kind::Png, Status::Complete));
    assert_eq!(read(&bytes, &index, png), b"\x89PNG\r\n\x1A\nrest");
    assert_eq!(index.entry_at(png.offset), Some(png));
    assert_eq!(index.entry_at(png.offset + 16), None);
}

#[test]
fn a_file_start_after_a_full_chunk_begins_a_new_entry() {
    let first = xml(CHUNK_LEN as usize);
    let second = xml(100);
    let bytes = archive(&[zlib(&first), zlib(&second)]);
    let index = scan_bytes(bytes);
    assert_eq!(index.entries.len(), 2);
    // The first file ends with a full chunk, so its end is not known.
    assert_eq!(index.entries[0].status, Status::Partial);
    assert_eq!(index.entries[1].status, Status::Complete);
}

#[test]
fn a_gap_ends_a_chunked_file() {
    let data = noise(CHUNK_LEN as usize + 10, 3);
    let chunks = chunked(&data);
    let mut bytes = archive(&chunks[..1]);
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&chunks[1]);
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    assert_eq!(index.entries.len(), 2);
    assert!(index.entries.iter().all(|e| e.status == Status::Unverified));
    assert_eq!(index.entries[0].kind, Kind::Text);
}

#[test]
fn classifies_conservatively() {
    let mut system_page = vec![0u8; 64];
    system_page[8..12].copy_from_slice(&0x5000_0030u32.to_le_bytes());
    assert_eq!(classify(&system_page), Kind::Resource);
    system_page[12] = 1;
    assert_eq!(classify(&system_page), Kind::Binary);
    system_page[12] = 0;
    system_page[0] = 1;
    assert_eq!(classify(&system_page), Kind::Binary);

    assert_eq!(classify(b"<?xml version"), Kind::Xml);
    assert_eq!(classify(b"\xEF\xBB\xBF<?xml version"), Kind::Xml);
    // Markup without a declaration may be the middle of a file.
    assert_eq!(classify(b"<Item>value</Item>"), Kind::Text);
    assert_eq!(classify(b"PSIN\x00\x00"), Kind::Psin);
    // The magic is a signature, but PSIN has no established extension and is
    // not a confirmed PSO payload.
    assert_eq!(Kind::Psin.name(), "psin");
    assert_eq!(Kind::Psin.extension(), "bin");
    assert!(Kind::Psin.is_file_start());
    assert_eq!(classify(b"RBF0\x00"), Kind::Rbf);
    assert_eq!(classify(b"DDS \x7C"), Kind::Dds);
    assert_eq!(classify(&[0u8, 1, 2, 3]), Kind::Binary);
    assert_eq!(classify(b""), Kind::Binary);
}

fn put_u64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// System data of `len` bytes with a page map at `map_at` that declares
/// `system` and `graphics` pages.
pub(crate) fn system_data(len: usize, map_at: usize, system: u8, graphics: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    put_u64(&mut bytes, 8, 0x5000_0000 + map_at as u64);
    bytes[map_at + 8] = system;
    bytes[map_at + 9] = graphics;
    bytes
}

/// Appends 16 zero bytes at the next 4 KiB boundary and then `pages` as
/// consecutive streams. Returns the offsets of the streams.
pub(crate) fn add_resource(bytes: &mut Vec<u8>, pages: &[Vec<u8>]) -> Vec<u64> {
    let start = bytes.len().next_multiple_of(0x1000) + 16;
    bytes.resize(start, 0);
    add_streams(bytes, pages)
}

fn add_streams(bytes: &mut Vec<u8>, data: &[Vec<u8>]) -> Vec<u64> {
    data.iter()
        .map(|data| {
            pad(bytes);
            let offset = bytes.len() as u64;
            bytes.extend_from_slice(&zlib(data));
            offset
        })
        .collect()
}

fn empty_archive() -> Vec<u8> {
    let mut bytes = header(0x40);
    bytes.resize(0x800, 0);
    bytes
}

fn graphics(len: usize, seed: u32) -> Vec<u8> {
    noise(len, seed)
}

#[test]
fn reconstructs_system_and_graphics_pages() {
    let mut system = system_data(0x200, 0x1C0, 1, 2);
    put_u64(&mut system, 0x20, 0x6000_0000 + 0x2_0010);
    let pages = vec![system.clone(), graphics(0x2_0000, 1), graphics(0x7000, 2)];
    let mut bytes = empty_archive();
    let offsets = add_resource(&mut bytes, &pages);
    // A small file packed directly after the resource.
    let after = add_streams(&mut bytes, &[b"some text after it".to_vec()]);
    pad(&mut bytes);
    let index = scan_bytes(bytes.clone());

    assert_eq!(index.resources.len(), 1);
    let resource = &index.resources[0];
    assert_eq!(resource.offset, offsets[0]);
    assert_eq!(
        resource.status(),
        Status::Complete,
        "{:?}",
        resource.layout.issues()
    );
    assert_eq!(resource.layout.segment_len(Segment::System), 0x200);
    assert_eq!(resource.layout.segment_len(Segment::Graphics), 0x2_7000);

    assert_eq!(index.entries.len(), 2);
    let entry = index.entry_at(offsets[0]).unwrap();
    assert_eq!(
        (entry.kind, entry.status),
        (Kind::Resource, Status::Complete)
    );
    assert_eq!(entry.stream_count(), 3);
    assert_eq!(entry.len, 0x2_7200);
    assert_eq!(read(&bytes, &index, entry), pages.concat());
    let text = index.entry_at(after[0]).unwrap();
    assert_eq!(text.kind, Kind::Text);

    let (owner, position, page, streams) = index.page_at(offsets[2]).unwrap();
    assert_eq!(owner.offset, offsets[0]);
    assert_eq!(position, 2);
    assert_eq!((page.segment, page.len), (Segment::Graphics, 0x7000));
    assert_eq!(page_label(&owner.layout, position), (Segment::Graphics, 2));
    let mut out = Vec::new();
    read_streams(
        Cursor::new(&bytes),
        &index,
        streams,
        u64::MAX,
        &mut out,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(out, pages[2]);
    assert!(index.page_at(after[0]).is_none());
    assert!(index.page_at(offsets[0] + 16).is_none());
}

#[test]
fn system_only_resources_are_complete() {
    let mut bytes = empty_archive();
    let mut system = system_data(0x100, 0x80, 1, 0);
    system[0x10..0x14].copy_from_slice(b"0DRP");
    system[0x14] = 0x7A;
    let offsets = add_resource(&mut bytes, &[system]);
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    let resource = index.resource_at(offsets[0]).unwrap();
    assert_eq!(resource.status(), Status::Complete);
    assert_eq!(resource.layout.tag, Some(0x7A));
    assert_eq!(resource.layout.segment_len(Segment::Graphics), 0);
}

#[test]
fn missing_graphics_pages_leave_a_partial_resource() {
    let mut bytes = empty_archive();
    let system = system_data(0x100, 0xC0, 1, 2);
    let mut damaged = zlib(&graphics(0x7000, 3));
    let middle = damaged.len() / 2;
    damaged[middle] ^= 0xFF;
    let offsets = add_resource(&mut bytes, &[system, graphics(0x2_0000, 4)]);
    // The second page does not inflate; the next stream follows a gap.
    pad(&mut bytes);
    bytes.extend_from_slice(&damaged);
    bytes.extend_from_slice(&[0u8; 48]);
    let later = add_streams(&mut bytes, &[graphics(0x3000, 5)]);
    pad(&mut bytes);
    let index = scan_bytes(bytes);

    let resource = index.resource_at(offsets[0]).unwrap();
    assert_eq!(resource.status(), Status::Partial);
    assert_eq!(resource.layout.pages.len(), 2);
    assert!(
        resource
            .layout
            .issues()
            .contains(&crate::resource::Issue::MissingPages {
                segment: Segment::Graphics,
                declared: 2,
                found: 1
            })
    );
    // A stream that is merely nearby is not taken as the missing page.
    let next = index.entry_at(later[0]).unwrap();
    assert_eq!((next.kind, next.status), (Kind::Text, Status::Unverified));
    assert_eq!(index.entries.len(), 2);
}

#[test]
fn pages_of_64_kib_are_not_joined_like_file_chunks() {
    // Two system pages, the first exactly one 64 KiB chunk long, and a page
    // map in the second. Grouping as file chunks would hide the second page.
    let mut system = system_data(0x1_0000 + 0x300, 0x1_0200, 2, 1);
    put_u64(&mut system, 0x20, 0x5000_0000 + 0x1_0100);
    let (first, second) = system.split_at(0x1_0000);
    let mut bytes = empty_archive();
    let offsets = add_resource(
        &mut bytes,
        &[first.to_vec(), second.to_vec(), graphics(0x900, 6)],
    );
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    let resource = index.resource_at(offsets[0]).unwrap();
    assert_eq!(
        resource.status(),
        Status::Complete,
        "{:?}",
        resource.layout.issues()
    );
    let pages: Vec<_> = index
        .resource_pages(resource)
        .map(|(page, streams)| (page.segment, streams[0].offset))
        .collect();
    assert_eq!(
        pages,
        [
            (Segment::System, offsets[0]),
            (Segment::System, offsets[1]),
            (Segment::Graphics, offsets[2])
        ]
    );
}

#[test]
fn neighbouring_streams_with_the_wrong_sizes_are_not_pages() {
    let mut bytes = empty_archive();
    let system = system_data(0x100, 0xC0, 1, 2);
    // Neither stream fits the size pattern of two graphics pages.
    let offsets = add_resource(
        &mut bytes,
        &[system, graphics(0x1_8000, 7), graphics(0x2_0000, 8)],
    );
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    let resource = index.resource_at(offsets[0]).unwrap();
    assert_eq!(resource.status(), Status::Unverified);
}

#[test]
fn a_resource_shape_without_zero_bytes_before_it_is_not_a_resource() {
    let mut bytes = empty_archive();
    let offsets = add_streams(
        &mut bytes,
        &[b"text".to_vec(), system_data(0x100, 0xC0, 1, 0)],
    );
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    assert!(index.resources.is_empty());
    assert_eq!(index.entry_at(offsets[1]).unwrap().kind, Kind::Binary);
    assert!(index.streams.iter().all(|s| s.kind != Kind::Resource));
}

#[test]
fn an_invalid_page_map_leaves_an_unverified_candidate() {
    let mut bytes = empty_archive();
    let mut system = system_data(0x100, 0xC0, 1, 1);
    system[0xC0] = 0x33;
    let offsets = add_resource(&mut bytes, &[system, graphics(0x1000, 9)]);
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    let resource = index.resource_at(offsets[0]).unwrap();
    assert_eq!(resource.status(), Status::Unverified);
    assert_eq!(resource.layout.page_map, Err(PageMapError::NonZero));
    // Without a page map nothing after the first stream is attributed.
    assert_eq!(index.entry_at(offsets[0]).unwrap().stream_count(), 1);
    assert_eq!(index.entry_at(offsets[1]).unwrap().kind, Kind::Text);
}

#[test]
fn a_page_map_past_the_recovered_data_leaves_an_unverified_candidate() {
    let mut bytes = empty_archive();
    let mut system = vec![0u8; 0x100];
    put_u64(&mut system, 8, 0x5000_8000);
    let offsets = add_resource(&mut bytes, &[system]);
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    let resource = index.resource_at(offsets[0]).unwrap();
    assert_eq!(resource.layout.page_map, Err(PageMapError::Outside));
    assert_eq!(resource.status(), Status::Unverified);
}

#[test]
fn the_start_of_another_file_ends_a_resource() {
    let mut bytes = empty_archive();
    let system = system_data(0x100, 0xC0, 1, 1);
    let offsets = add_resource(
        &mut bytes,
        &[system, b"<?xml version=\"1.0\"?><a/>".to_vec()],
    );
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    assert_eq!(
        index.resource_at(offsets[0]).unwrap().status(),
        Status::Partial
    );
    assert_eq!(index.entry_at(offsets[1]).unwrap().kind, Kind::Xml);
}

#[test]
fn cancelled_reconstruction_yields_no_resources() {
    let mut bytes = empty_archive();
    add_resource(&mut bytes, &[system_data(0x100, 0xC0, 1, 0)]);
    pad(&mut bytes);
    let mut streams = scan_bytes(bytes.clone()).streams;
    streams[0].kind = Kind::Resource;
    let len = bytes.len() as u64;
    let result = reconstruct::resolve(
        Cursor::new(bytes),
        len,
        &mut streams,
        &AtomicBool::new(true),
    );
    assert!(matches!(result, Err(Error::Cancelled)));
}

#[test]
fn reports_unrecovered_bytes_but_not_padding() {
    let mut bytes = archive(&[zlib(b"first")]);
    let opaque_at = bytes.len() + 32;
    bytes.resize(opaque_at, 0);
    bytes.extend_from_slice(&[0x11; 40]);
    bytes.resize(bytes.len() + 64, 0);
    bytes.extend_from_slice(&[0x22; 8]);
    pad(&mut bytes);
    let after = bytes.len();
    bytes.extend_from_slice(&zlib(b"second"));
    pad(&mut bytes);

    let index = scan_bytes(bytes);
    assert_eq!(index.entries.len(), 2);
    assert_eq!(index.entries[1].offset, after as u64);
    // One region for the whole gap; the table of contents is not scanned.
    assert_eq!(index.regions.len(), 1);
    let gap = index.regions[0];
    assert_eq!(gap.offset, opaque_at as u64);
    // Regions end with the last aligned block that holds a non-zero byte.
    assert_eq!(gap.offset + gap.len, (opaque_at + 112) as u64);
    assert_eq!(index.region_at(gap.offset), Some(&gap));
}

#[test]
fn skips_corrupted_and_truncated_streams() {
    let good = zlib(b"intact");
    let mut corrupt = zlib(&noise(5000, 9));
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 0xFF;
    let mut bad_checksum = zlib(b"checksum");
    let last = bad_checksum.len() - 1;
    bad_checksum[last] ^= 0x01;
    let bytes = archive(&[good.clone(), corrupt, bad_checksum, good.clone()]);
    let index = scan_bytes(bytes.clone());
    assert_eq!(index.entries.len(), 2);
    assert!(index.unrecovered_len() > 0);
    for entry in &index.entries {
        assert_eq!(read(&bytes, &index, entry), b"intact");
    }

    let mut truncated = archive(std::slice::from_ref(&good));
    let long = zlib(&noise(4000, 1));
    truncated.extend_from_slice(&long[..long.len() - 10]);
    let index = scan_bytes(truncated);
    assert_eq!(index.entries.len(), 1);
    assert_eq!(index.regions.len(), 1);
}

#[test]
fn segment_boundaries_do_not_change_the_result() {
    let data = xml(3 * CHUNK_LEN as usize + 77);
    let mut chunks = chunked(&data);
    chunks.push(zlib(b"tail text that is printable"));
    let bytes = archive(&chunks);
    let header = Header::parse(&bytes, bytes.len() as u64).unwrap();
    let len = bytes.len() as u64;
    let run = |segment_len| {
        scan_from(
            Cursor::new(bytes.clone()),
            header.clone(),
            len,
            header.data_start(),
            segment_len,
            &Progress::default(),
            &AtomicBool::new(false),
        )
        .unwrap()
    };
    let whole = run(len.next_multiple_of(ALIGN));
    for segment_len in [16, 4096, 0x8000, 0x1_0010] {
        assert_eq!(run(segment_len), whole, "segment length {segment_len}");
    }
    assert_eq!(whole.entries.len(), 2);
    assert_eq!(whole.entries[0].len, data.len() as u64);
}

#[test]
fn identifiers_do_not_depend_on_other_entries() {
    let a = zlib(b"alpha");
    let b = zlib(&xml(500));
    let index = scan_bytes(archive(&[a.clone(), b.clone()]));
    let offsets: Vec<u64> = index.entries.iter().map(|e| e.offset).collect();
    // Damaging the first stream removes its entry but keeps the second id.
    let mut damaged = a.clone();
    damaged[2] ^= 0xFF;
    let index = scan_bytes(archive(&[damaged, b]));
    assert_eq!(index.entries.len(), 1);
    assert_eq!(index.entries[0].offset, offsets[1]);
}

#[test]
fn cancelled_scans_yield_no_index() {
    let bytes = archive(&chunked(&noise(4 * 1024 * 1024, 5)));
    let result = scan(
        Cursor::new(bytes),
        &Progress::default(),
        &AtomicBool::new(true),
    );
    assert!(matches!(result, Err(Error::Cancelled)));
}

#[test]
fn reports_progress() {
    let bytes = archive(&chunked(&noise(300_000, 2)));
    let progress = Progress::default();
    scan(
        Cursor::new(bytes.clone()),
        &progress,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(progress.total(), bytes.len() as u64 - 0xA0);
    assert_eq!(progress.done(), progress.total());
    assert_eq!(progress.fraction(), Some(1.0));
}

#[test]
fn rejects_streams_over_the_size_limit() {
    let bomb = zlib(&vec![0u8; 100_000]);
    let mut window = Window::new(Cursor::new(bomb.clone()), bomb.len() as u64);
    let mut scratch = vec![0; 4096];
    let mut seen = 0;
    let result = inflate(&mut window, 0, 99_999, &mut scratch, &mut |out| {
        seen += out.len();
        Ok(())
    })
    .unwrap();
    assert_eq!(result, None);
    assert!(seen < 100_000);
    let result = inflate(&mut window, 0, 100_000, &mut scratch, &mut |_| Ok(())).unwrap();
    assert_eq!(result, Some((bomb.len() as u64, 100_000)));
}

#[test]
fn reads_check_limits_and_changes() {
    let data = noise(70_000, 4);
    let mut bytes = archive(&chunked(&data));
    bytes.extend_from_slice(&[0x33; 48]);
    let index = scan_bytes(bytes.clone());
    let entry = &index.entries[0];
    let ok = AtomicBool::new(false);
    let mut out = Vec::new();
    let err = read_entry(Cursor::new(&bytes), &index, entry, 69_999, &mut out, &ok).unwrap_err();
    assert!(matches!(err, Error::TooLarge { len: 70_000, .. }));

    let mut changed = bytes.clone();
    let second = index.entry_streams(entry)[1].offset as usize;
    changed[second + 4] ^= 0xFF;
    let err = read_entry(
        Cursor::new(&changed),
        &index,
        entry,
        u64::MAX,
        &mut out,
        &ok,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Changed(_)));
    let err = read_entry(
        Cursor::new(&bytes[..second]),
        &index,
        entry,
        u64::MAX,
        &mut Vec::new(),
        &ok,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Changed(_)));

    // A set cancel flag stops a read before it writes a complete payload.
    let cancelled = AtomicBool::new(true);
    let mut out = Vec::new();
    let err = read_entry(
        Cursor::new(&bytes),
        &index,
        entry,
        u64::MAX,
        &mut out,
        &cancelled,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
    assert!(out.len() < 70_000);

    let region = index.regions[0];
    let mut raw = Vec::new();
    read_region(Cursor::new(&bytes), &region, u64::MAX, &mut raw, &ok).unwrap();
    assert_eq!(raw, &bytes[region.offset as usize..][..region.len as usize]);
    assert!(read_region(Cursor::new(&bytes), &region, 1, &mut raw, &ok).is_err());
    let mut raw = Vec::new();
    let err =
        read_region(Cursor::new(&bytes), &region, u64::MAX, &mut raw, &cancelled).unwrap_err();
    assert!(matches!(err, Error::Cancelled));
}

/// Zeros of any length with a few bytes set, for offsets past 4 GiB
/// without a file of that size.
#[derive(Clone)]
struct Sparse {
    len: u64,
    patches: Arc<Vec<(u64, Vec<u8>)>>,
    pos: u64,
}

impl Read for Sparse {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf
            .len()
            .min(usize::try_from(self.len.saturating_sub(self.pos)).unwrap_or(usize::MAX));
        buf[..n].fill(0);
        for (at, bytes) in self.patches.iter() {
            for (i, byte) in bytes.iter().enumerate() {
                let offset = at + i as u64;
                if offset >= self.pos && offset < self.pos + n as u64 {
                    buf[(offset - self.pos) as usize] = *byte;
                }
            }
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Sparse {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(delta) => self.len.checked_add_signed(delta).unwrap(),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta).unwrap(),
        };
        Ok(self.pos)
    }
}

#[test]
fn handles_offsets_past_4_gib() {
    let base: u64 = 5 * 1024 * 1024 * 1024 + 0x10;
    let first = zlib(&xml(CHUNK_LEN as usize));
    let second = zlib(b"end of the file");
    let second_at = (base + first.len() as u64).next_multiple_of(ALIGN);
    let len = second_at + 0x100;
    let source = Sparse {
        len,
        patches: Arc::new(vec![
            (0, header(0x40)),
            (base, first.clone()),
            (second_at, second),
        ]),
        pos: 0,
    };
    let header = read_header(&mut source.clone()).unwrap();
    let index = scan_from(
        source.clone(),
        header,
        len,
        base - 0x10,
        4096,
        &Progress::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(index.entries.len(), 1);
    let entry = &index.entries[0];
    assert_eq!(entry.offset, base);
    assert_eq!(entry.stream_count(), 2);
    assert_eq!(entry.status, Status::Complete);
    let mut out = Vec::new();
    read_entry(
        source,
        &index,
        entry,
        u64::MAX,
        &mut out,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(out.ends_with(b"end of the file"));
}

#[test]
fn reconstructs_resources_past_4_gib() {
    let base: u64 = 5 * 1024 * 1024 * 1024 + 0x10;
    let system = zlib(&system_data(0x100, 0xC0, 1, 1));
    let page = zlib(&graphics(0x3000, 11));
    let page_at = (base + system.len() as u64).next_multiple_of(ALIGN);
    let len = page_at + page.len() as u64 + 0x100;
    let source = Sparse {
        len,
        patches: Arc::new(vec![(0, header(0x40)), (base, system), (page_at, page)]),
        pos: 0,
    };
    let header = read_header(&mut source.clone()).unwrap();
    let index = scan_from(
        source.clone(),
        header,
        len,
        base - 0x10,
        4096,
        &Progress::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    let resource = index.resource_at(base).unwrap();
    assert_eq!(resource.status(), Status::Complete);
    let (owner, position, _, streams) = index.page_at(page_at).unwrap();
    assert_eq!((owner.offset, position), (base, 1));
    let mut out = Vec::new();
    read_streams(
        source,
        &index,
        streams,
        u64::MAX,
        &mut out,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(out, graphics(0x3000, 11));
}

#[test]
fn a_page_that_starts_like_a_resource_still_belongs_to_its_resource() {
    let mut system = system_data(0x1_0000 + 0x800, 0x1_0700, 2, 0);
    // The second page starts with a zero u64 and a system pointer, but has
    // no zeroed prefix.
    put_u64(&mut system, 0x1_0008, 0x5000_0100);
    let (first, second) = system.split_at(0x1_0000);
    let mut bytes = empty_archive();
    let offsets = add_resource(&mut bytes, &[first.to_vec(), second.to_vec()]);
    pad(&mut bytes);
    let index = scan_bytes(bytes);
    assert_eq!(index.resources.len(), 1);
    let resource = index.resource_at(offsets[0]).unwrap();
    assert_eq!(
        resource.status(),
        Status::Complete,
        "{:?}",
        resource.layout.issues()
    );
    assert_eq!(resource.layout.pages.len(), 2);
    assert_eq!(index.streams[1].kind, Kind::Binary);
}
