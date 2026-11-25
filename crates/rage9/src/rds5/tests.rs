//! Synthetic RDS5 containers. No game data is used.

use std::io::{Cursor, Write};
use std::sync::atomic::AtomicBool;

use flate2::Compression;
use flate2::write::ZlibEncoder;

use super::*;

/// Builds a container from `blocks`, one entry per block, and `field_m` bytes
/// of content after the entry table.
struct Build {
    version: u32,
    /// Selector written into each block record's high byte, shifted into bits
    /// 2..3.
    selectors: Vec<u8>,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            version: 0x1600_0000,
            selectors: Vec::new(),
        }
    }
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn set_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn up(value: usize, to: usize) -> usize {
    value.next_multiple_of(to)
}

impl Build {
    /// The blocks are stored back to back, each padded to a 0x100 boundary.
    fn build(&self, blocks: &[Vec<u8>], field_m: u32) -> Vec<u8> {
        let record_count = blocks.len() + 2;
        let entry_count = blocks.len();
        let record_end = up(
            HEADER_LEN as usize + RECORD_LEN as usize * record_count,
            0x100,
        );
        let table_len = ENTRY_LEN as usize * entry_count;
        let chunk_len = 0x10 + table_len + table_len + field_m as usize;
        let first_block = record_end + up(chunk_len, 0x1000);

        let mut offsets = vec![record_end, first_block];
        let mut pos = first_block;
        for block in blocks {
            pos += up(block.len(), 0x100);
            offsets.push(pos);
        }
        let size = pos;

        let mut bytes = vec![0u8; size];
        bytes[..4].copy_from_slice(&MAGIC);
        set_u32(&mut bytes, 4, record_count as u32);
        let total = blocks
            .iter()
            .map(|block| up(block.len(), 0x1000))
            .sum::<usize>();
        set_u32(&mut bytes, 8, (0x1000 + total) as u32);
        set_u32(&mut bytes, 0x0C, self.version);
        for (index, offset) in offsets.iter().enumerate() {
            let at = HEADER_LEN as usize + RECORD_LEN as usize * index;
            let high = if index == 0 {
                0
            } else {
                self.selectors.get(index - 1).copied().unwrap_or(0) << 2
            };
            let lo = ((*offset / 0x100) as u32 & OFFSET_MASK) | (u32::from(high) << 24);
            set_u32(&mut bytes, at, lo);
            set_u32(&mut bytes, at + 4, 0);
        }
        bytes[record_end..record_end + 4].copy_from_slice(&ETPF_MAGIC);
        set_u32(&mut bytes, record_end + 4, ETPF_TYPE);
        set_u32(&mut bytes, record_end + 8, entry_count as u32);
        set_u32(&mut bytes, record_end + 0x0C, field_m);
        for index in 0..entry_count {
            let at = record_end + 0x10 + index * ENTRY_LEN as usize;
            set_u32(&mut bytes, at, 0xC001);
            set_u32(&mut bytes, at + 4, 0x20);
            set_u32(&mut bytes, at + 8, index as u32 + 1);
            set_u32(&mut bytes, at + 12, 1);
        }
        let mut pos = first_block;
        for block in blocks {
            bytes[pos..pos + block.len()].copy_from_slice(block);
            pos += up(block.len(), 0x100);
        }
        bytes
    }
}

fn read(bytes: &[u8]) -> Result<Container, Error> {
    Container::read(
        &mut Cursor::new(bytes),
        bytes.len() as u64,
        &Limits::default(),
        &AtomicBool::new(false),
    )
}

fn zlib_block() -> Vec<u8> {
    zlib(&[0x11; 0x800])
}

/// Bytes that compress poorly, so blocks stay large.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn build_standard() -> Vec<u8> {
    Build::default().build(&[zlib_block(), zlib_block(), zlib_block()], 0x40)
}

#[test]
fn parses_header_records_and_blocks() {
    let bytes = build_standard();
    let container = read(&bytes).unwrap();
    assert!(is_rds5(&bytes[..8]));
    assert_eq!(container.version, 0x1600_0000);
    assert_eq!(container.record_count(), 5);
    assert_eq!(container.entry_count, 3);
    assert_eq!(container.field_m, 0x40);
    assert_eq!(container.blocks.len(), 3);
    assert_eq!(container.blocks[0].record, 1);
    assert_eq!(container.blocks[2].record, 3);
    // Blocks are contiguous: each ends where the next record starts.
    for pair in container.records[1..].windows(2) {
        assert!(pair[0].offset < pair[1].offset);
    }
    assert_eq!(container.records[4].offset, bytes.len() as u64);
    assert_eq!(container.entry_table_offset(), container.etpf_offset + 0x10);
    assert_eq!(
        container.region_len(),
        container.entry_table_len() + u64::from(container.field_m)
    );
    assert_eq!(
        container.content_end,
        container.etpf_offset + 0x10 + 2 * container.entry_table_len() + 0x40
    );
    assert!(container.first_block > container.content_end);
    // The builder follows the observed alignment, so nothing is reported.
    assert!(container.warnings.is_empty(), "{:?}", container.warnings);
    // Nothing is read until asked.
    assert!(
        container
            .blocks
            .iter()
            .all(|b| b.storage == Storage::Unread)
    );
}

#[test]
fn accepts_both_observed_versions_and_rejects_others() {
    for version in VERSIONS {
        let bytes = Build {
            version,
            ..Build::default()
        }
        .build(&[zlib_block()], 0);
        assert_eq!(read(&bytes).unwrap().version, version);
    }
    let bytes = Build {
        version: 0x1600_0002,
        ..Build::default()
    }
    .build(&[zlib_block()], 0);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("unsupported RDS5 version 0x16000002"), "{err}");
}

#[test]
fn rejects_short_and_foreign_input() {
    assert!(matches!(
        read(&[]),
        Err(Error::Invalid(reason)) if reason.contains("shorter than")
    ));
    let mut bytes = build_standard();
    bytes[0] = b'X';
    assert!(matches!(read(&bytes), Err(Error::NotRds5)));
}

#[test]
fn rejects_a_record_array_below_three_records() {
    let mut bytes = build_standard();
    set_u32(&mut bytes, 4, 2);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("at least 3"), "{err}");
}

#[test]
fn rejects_a_record_array_that_exceeds_the_file() {
    let mut bytes = build_standard();
    set_u32(&mut bytes, 4, 100_000);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("record array ends at"), "{err}");
}

#[test]
fn rejects_a_record_count_over_the_limit() {
    let bytes = build_standard();
    let limits = Limits {
        max_records: 4,
        ..Limits::default()
    };
    let err = Container::read(
        &mut Cursor::new(&bytes),
        bytes.len() as u64,
        &limits,
        &AtomicBool::new(false),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("more than the 4 limit"), "{err}");
}

#[test]
fn rejects_a_first_record_that_misses_the_etpf_chunk() {
    let mut bytes = build_standard();
    let at = HEADER_LEN as usize;
    let lo = u32_at(&bytes, at) + 2;
    set_u32(&mut bytes, at, lo);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("record 0 points at"), "{err}");
}

#[test]
fn rejects_a_wrong_chunk_magic_or_type() {
    let mut bytes = build_standard();
    let container = read(&bytes).unwrap();
    let at = container.etpf_offset as usize;
    bytes[at..at + 4].copy_from_slice(b"XTPF");
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("does not start with ETPF"), "{err}");

    let mut bytes = build_standard();
    set_u32(&mut bytes, at + 4, 0x27B);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("only 0x27A is known"), "{err}");
}

#[test]
fn rejects_a_content_length_that_is_not_a_multiple_of_16() {
    let mut bytes = build_standard();
    let at = read(&bytes).unwrap().etpf_offset as usize;
    set_u32(&mut bytes, at + 0x0C, 0x41);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("not a multiple of 16"), "{err}");
}

#[test]
fn rejects_content_or_a_table_past_the_file() {
    let mut bytes = build_standard();
    let at = read(&bytes).unwrap().etpf_offset as usize;
    set_u32(&mut bytes, at + 8, 2_000_001);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("more than the 2000000 limit"), "{err}");

    let mut bytes = build_standard();
    let at = read(&bytes).unwrap().etpf_offset as usize;
    set_u32(&mut bytes, at + 8, 100_000);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("entry table ends at"), "{err}");
}

#[test]
fn rejects_a_content_end_past_the_first_block() {
    // Blocks that barely compress leave room for a content length that still
    // fits the file but reaches past the first block.
    let blocks = vec![zlib(&noise(0x2000)), zlib(&noise(0x2000))];
    let mut bytes = Build::default().build(&blocks, 0);
    let at = read(&bytes).unwrap().etpf_offset as usize;
    set_u32(&mut bytes, at + 0x0C, 0x1500);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("after the first block"), "{err}");
}

#[test]
fn rejects_a_non_zero_byte_before_the_first_block() {
    let mut bytes = build_standard();
    let container = read(&bytes).unwrap();
    bytes[container.content_end as usize] = 1;
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("non-zero byte at"), "{err}");
}

#[test]
fn rejects_unordered_and_out_of_bounds_records() {
    let mut bytes = build_standard();
    let container = read(&bytes).unwrap();
    let third = container.blocks[2].record as usize;
    let at = HEADER_LEN as usize + RECORD_LEN as usize * third;
    let lo = u32_at(&bytes, at) - 4;
    set_u32(&mut bytes, at, lo);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("do not increase"), "{err}");

    let mut bytes = build_standard();
    let container = read(&bytes).unwrap();
    let at = HEADER_LEN as usize + RECORD_LEN as usize * (container.blocks[0].record as usize);
    set_u32(&mut bytes, at, OFFSET_MASK);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("outside the container"), "{err}");
}

#[test]
fn rejects_a_last_record_that_is_not_the_file_end() {
    let mut bytes = build_standard();
    let count = read(&bytes).unwrap().record_count() as usize;
    let at = HEADER_LEN as usize + RECORD_LEN as usize * (count - 1);
    let lo = u32_at(&bytes, at) + 1;
    set_u32(&mut bytes, at, lo);
    let err = read(&bytes).unwrap_err().to_string();
    assert!(err.contains("not at the end of the container"), "{err}");
}

#[test]
fn reports_a_first_block_off_the_observed_relation() {
    // Insert 0x100 zero bytes before the first block and move every block
    // record up by one 0x100 unit. The chunk and record 0 stay put, so the
    // container stays valid but the observed alignment no longer explains the
    // first block.
    let bytes = build_standard();
    let container = read(&bytes).unwrap();
    let gap = container.content_end as usize;
    let count = container.record_count() as usize;
    let mut moved = bytes[..gap].to_vec();
    moved.resize(gap + 0x100, 0);
    moved.extend_from_slice(&bytes[gap..]);
    for index in 1..count {
        let at = HEADER_LEN as usize + RECORD_LEN as usize * index;
        let lo = u32_at(&moved, at) + 1;
        set_u32(&mut moved, at, lo);
    }
    let container = read(&moved).unwrap();
    assert!(
        container
            .warnings
            .iter()
            .any(|warning| warning.contains("the first block is at")),
        "{:?}",
        container.warnings
    );
}

#[test]
fn classifies_blocks_by_selector_and_header() {
    let mut bytes = Build {
        selectors: vec![0, 0, 1],
        ..Build::default()
    }
    .build(&[zlib_block(), zlib_block(), zlib_block()], 0);
    // Make the second block carry the zlib selector without a zlib header.
    let container = read(&bytes).unwrap();
    let second = container.blocks[1].offset as usize;
    bytes[second] = 0x30;
    bytes[second + 1] = 0xDE;

    let mut container = read(&bytes).unwrap();
    let done = container
        .classify(
            &mut Cursor::new(&bytes),
            usize::MAX,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(done, 3);
    assert_eq!(container.blocks[0].storage, Storage::Zlib);
    assert_eq!(container.blocks[1].storage, Storage::NotZlib);
    assert_eq!(container.blocks[2].storage, Storage::Unidentified(1));
    assert_eq!(container.blocks_zlib(), 1);

    // Sampling stops early and leaves the rest unread.
    let mut container = read(&bytes).unwrap();
    assert_eq!(
        container
            .classify(&mut Cursor::new(&bytes), 1, &AtomicBool::new(false))
            .unwrap(),
        1
    );
    assert_eq!(container.blocks[1].storage, Storage::Unread);
}

#[test]
fn decodes_a_zlib_block_and_reports_padding() {
    let data: Vec<u8> = (0..0x1234u32).map(|value| value as u8).collect();
    let bytes = Build::default().build(&[zlib(&data)], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    let mut decoded = Vec::new();
    let report = decode_block(
        &mut source,
        &container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |chunk| {
            decoded.extend_from_slice(chunk);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(decoded, data);
    assert_eq!(report.len, data.len() as u64);
    assert_eq!(report.stored_len, container.blocks[0].stored_len);
    // The block range is rounded up to 0x100, so padding may trail.
    assert!(report.trailing < 0x100);
}

#[test]
fn refuses_blocks_it_cannot_decode() {
    let bytes = Build {
        selectors: vec![1],
        ..Build::default()
    }
    .build(&[zlib_block()], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    let err = decode_block(
        &mut source,
        &container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("was not classified"), "{err}");

    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    let err = decode_block(
        &mut source,
        &container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("compressor selector 1") || err.contains("has not been identified"),
        "{err}"
    );
    let err = decode_block(
        &mut source,
        &container,
        7,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("does not exist"), "{err}");
}

#[test]
fn rejects_a_truncated_zlib_stream() {
    let data = vec![0x5A; 0x800];
    let mut stream = zlib(&data);
    stream.truncate(stream.len() / 2);
    let bytes = Build::default().build(&[stream], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    let err = decode_block(
        &mut source,
        &container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("ends before") || err.contains("not a valid zlib stream"),
        "{err}"
    );
}

#[test]
fn caps_the_decoded_size() {
    let data = vec![0x77; 0x4000];
    let bytes = Build::default().build(&[zlib(&data)], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    let limits = Limits {
        max_block_len: 0x100,
        ..Limits::default()
    };
    let err = decode_block(
        &mut source,
        &container,
        0,
        &limits,
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("decodes to more than"), "{err}");
}

#[test]
fn samples_entries() {
    let blocks = vec![zlib_block(), zlib_block()];
    let bytes = Build::default().build(&blocks, 0);
    let container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    let entries = container.entries(&mut source, 0, 8).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].index, 0);
    assert_eq!(entries[1].index, 1);
    assert_eq!(entries[0].words[0], 0xC001);
    assert_eq!(entries[1].page(), 2);
    let tail = container.entries(&mut source, 1, 8).unwrap();
    assert_eq!(tail.len(), 1);
    assert!(container.entries(&mut source, 9, 1).is_err());
}

#[test]
fn reports_a_total_off_the_observed_multiple() {
    let mut bytes = build_standard();
    set_u32(&mut bytes, 8, 0x1234);
    let container = read(&bytes).unwrap();
    assert!(
        container
            .warnings
            .iter()
            .any(|warning| warning.contains("not a multiple of 0x1000")),
        "{:?}",
        container.warnings
    );
}

#[test]
fn treats_a_wrong_length_as_a_limit_not_a_read() {
    let bytes = build_standard();
    let err = Container::read(
        &mut Cursor::new(&bytes),
        bytes.len() as u64 + 0x1000,
        &Limits::default(),
        &AtomicBool::new(false),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("last record"), "{err}");
    let limits = Limits {
        max_len: 0x100,
        ..Limits::default()
    };
    let err = Container::read(
        &mut Cursor::new(&bytes),
        bytes.len() as u64,
        &limits,
        &AtomicBool::new(false),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("more than the 256 byte limit"), "{err}");
}

#[test]
fn decodes_blocks_that_fill_the_output_buffer_exactly() {
    for multiple in 1..=3usize {
        let len = DECODE_OUTPUT * multiple;
        let data = noise(len);
        let bytes = Build::default().build(&[zlib(&data)], 0);
        let mut container = read(&bytes).unwrap();
        let mut source = Cursor::new(&bytes);
        container
            .classify(&mut source, usize::MAX, &AtomicBool::new(false))
            .unwrap();
        let mut decoded = Vec::new();
        let report = decode_block(
            &mut source,
            &container,
            0,
            &Limits::default(),
            &AtomicBool::new(false),
            |chunk| {
                decoded.extend_from_slice(chunk);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(decoded, data, "{len} bytes");
        assert_eq!(report.len, len as u64);
    }
}

#[test]
fn stops_when_cancelled() {
    let bytes = build_standard();
    let err = Container::read(
        &mut Cursor::new(&bytes),
        bytes.len() as u64,
        &Limits::default(),
        &AtomicBool::new(true),
    )
    .unwrap_err();
    assert!(matches!(err, Error::Cancelled));
}
