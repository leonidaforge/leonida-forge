//! Synthetic RDS5 containers. No game data is used.

use std::io::{Cursor, Read, Write};
use std::sync::atomic::AtomicBool;

use flate2::Compression;
use flate2::write::ZlibEncoder;

use super::*;

/// Builds a container from `blocks`, one entry per block, and `field_m` bytes
/// of content after the entry table.
struct Build {
    version: u32,
    /// Six-bit storage class per block, written into bits 24..29. Defaults to
    /// `0x20`, zlib.
    classes: Vec<u8>,
    /// Set bit 24 of a block record, which makes the class reading ambiguous.
    ambiguous: Vec<bool>,
    /// Second word per block: counter, page term and padding.
    second_words: Vec<u32>,
    /// Descriptor words per entry. Defaults to a placeholder.
    entries: Vec<[u32; 4]>,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            version: 0x1600_0000,
            classes: Vec::new(),
            ambiguous: Vec::new(),
            second_words: Vec::new(),
            entries: Vec::new(),
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

/// The virtual length of a synthetic block: its inflated length for the zlib
/// class, its stored length otherwise.
fn inflated_len(block: &[u8], class: u8) -> u64 {
    if class & 0x3C != 0x20 {
        return block.len() as u64;
    }
    let mut decoded = Vec::new();
    match flate2::read::ZlibDecoder::new(block).read_to_end(&mut decoded) {
        Ok(_) => decoded.len() as u64,
        Err(_) => block.len() as u64,
    }
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

        // Virtual positions advance by each block's inflated length, in
        // units of 0x4000 (counter) and 0x1000 (page term). Record 0 is the
        // chunk record, so record `k + 1` starts block `k`. The first block
        // starts at page 1, as in every sampled store.
        let mut virtual_positions = vec![0u64; record_count];
        let mut acc = 0x1000u64;
        for (k, block) in blocks.iter().enumerate() {
            let class = self.classes.get(k).copied().unwrap_or(0x20);
            virtual_positions[k + 1] = acc;
            acc += inflated_len(block, class);
        }
        virtual_positions[blocks.len() + 1] = acc;

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
            let class = if index == 0 {
                0
            } else {
                self.classes.get(index - 1).copied().unwrap_or(0x20)
            };
            let ambiguous = index > 0 && self.ambiguous.get(index - 1).copied().unwrap_or(false);
            let mut lo = ((*offset / 0x100) as u32 & OFFSET_MASK) | (u32::from(class) << 24);
            if ambiguous {
                lo |= 1 << 24;
            }
            let virtual_at = virtual_positions[index];
            lo |= (((virtual_at % 0x4000) / 0x1000) as u32 & 3) << 30;
            set_u32(&mut bytes, at, lo);
            // Every block is padded to the next 0x100 boundary, and the
            // record declares that padding in bits 20..31 of its second word.
            let padding = blocks
                .get(index.saturating_sub(1))
                .map_or(0, |block| up(block.len(), 0x100) - block.len());
            let second = self.second_words.get(index.saturating_sub(1)).copied();
            set_u32(
                &mut bytes,
                at + 4,
                second.unwrap_or((((padding as u32) & 0xFFF) << 20) | (virtual_at / 0x4000) as u32),
            );
        }
        bytes[record_end..record_end + 4].copy_from_slice(&ETPF_MAGIC);
        set_u32(&mut bytes, record_end + 4, ETPF_TYPE);
        set_u32(&mut bytes, record_end + 8, entry_count as u32);
        set_u32(&mut bytes, record_end + 0x0C, field_m);
        for index in 0..entry_count {
            let at = record_end + 0x10 + index * ENTRY_LEN as usize;
            let words =
                self.entries
                    .get(index)
                    .copied()
                    .unwrap_or([0xC001, 0x20, index as u32 + 1, 1]);
            for (word, value) in words.iter().enumerate() {
                set_u32(&mut bytes, at + 4 * word, *value);
            }
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
fn classifies_blocks_by_class_id_and_header() {
    let mut bytes = Build {
        classes: vec![0x20, 0x20, 0x04],
        ..Build::default()
    }
    .build(&[zlib_block(), zlib_block(), zlib_block()], 0);
    // Make the second block carry the zlib class without a zlib header.
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
    assert_eq!(container.blocks[1].storage, Storage::ZlibHeaderMissing);
    assert_eq!(container.blocks[2].storage, Storage::Undecoded(0x04));
    assert_eq!(container.blocks[2].class_id, 0x04);
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
    // Inflated lengths are multiples of 0x1000, as every measured case.
    let data: Vec<u8> = (0..0x2000u32).map(|value| value as u8).collect();
    let bytes = Build::default().build(&[zlib(&data)], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    let mut decoded = Vec::new();
    let report = decode_block(
        &mut source,
        &mut container,
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
    // The declared padding trails the stream and is reported, not counted.
    assert_eq!(report.trailing, u64::from(container.blocks[0].padding));
}

#[test]
fn refuses_blocks_it_cannot_decode() {
    let bytes = Build {
        classes: vec![0x04],
        ..Build::default()
    }
    .build(&[zlib_block()], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    let err = decode_block(
        &mut source,
        &mut container,
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
        &mut container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("storage class 0x04") || err.contains("is not decoded"),
        "{err}"
    );
    let err = decode_block(
        &mut source,
        &mut container,
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
        &mut container,
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
        &mut container,
        0,
        &limits,
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("more than the 256 byte limit"), "{err}");
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
    assert_eq!(entries[1].locator_page(), 2);
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
            &mut container,
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

#[test]
fn classifies_every_observed_class() {
    let classes = [0x00u8, 0x04, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20];
    let blocks: Vec<Vec<u8>> = classes
        .iter()
        .map(|class| {
            if *class == 0x20 {
                zlib(&vec![0xAB; 0x1000])
            } else if *class == 0x00 {
                vec![0xCD; 0x1000]
            } else {
                vec![0xEF; 0x1000]
            }
        })
        .collect();
    let bytes = Build {
        classes: classes.to_vec(),
        ..Build::default()
    }
    .build(&blocks, 0);
    let mut container = read(&bytes).unwrap();
    container
        .classify(
            &mut Cursor::new(&bytes),
            usize::MAX,
            &AtomicBool::new(false),
        )
        .unwrap();
    let expected = [
        Storage::Stored,
        Storage::Undecoded(0x04),
        Storage::Undecoded(0x0C),
        Storage::Undecoded(0x10),
        Storage::Undecoded(0x14),
        Storage::Undecoded(0x18),
        Storage::Undecoded(0x1C),
        Storage::Zlib,
    ];
    let actual: Vec<Storage> = container.blocks.iter().map(|block| block.storage).collect();
    assert_eq!(actual, expected);
    assert_eq!(container.blocks_zlib(), 1);
}

#[test]
fn decodes_a_stored_block_verbatim() {
    let data: Vec<u8> = (0..0x1000u32).map(|value| value as u8).collect();
    let bytes = Build {
        classes: vec![0x00],
        ..Build::default()
    }
    .build(std::slice::from_ref(&data), 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(container.blocks[0].content_len, 0x1000);
    assert_eq!(container.blocks[0].virtual_len, 0x1000);
    let mut decoded = Vec::new();
    let report = decode_block(
        &mut source,
        &mut container,
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
    assert_eq!(report.len, 0x1000);
}

#[test]
fn reports_a_stored_block_whose_length_disagrees_with_the_virtual_length() {
    let bytes = Build {
        classes: vec![0x00],
        // Counter 10 puts the next record far ahead of the stored content.
        second_words: vec![10],
        ..Build::default()
    }
    .build(&[vec![0x11; 0x1000]], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    let err = decode_block(
        &mut source,
        &mut container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("virtual length"), "{err}");
}

#[test]
fn accepts_an_ambiguous_class_record_and_reports_both_offsets() {
    let bytes = Build {
        classes: vec![0x04],
        ambiguous: vec![true],
        ..Build::default()
    }
    .build(&[vec![0x22; 0x100]], 0);
    let container = read(&bytes).unwrap();
    let block = &container.blocks[0];
    assert!(block.ambiguous);
    assert_eq!(block.class_id, 0x05);
    assert_eq!(block.offset26, Some(block.offset + 0x1_0000_0000));
    let record = container.records[1];
    assert_eq!(record.dispatch_class(), 0x04);
    assert_eq!(record.offset26(), block.offset + 0x1_0000_0000);
}

#[test]
fn virtual_position_has_no_extra_constant() {
    let record = Record {
        index: 1,
        offset: 0,
        high_byte: 0x20 | (1 << 6),
        second_word: 3,
    };
    assert_eq!(record.counter(), 3);
    assert_eq!(record.page_term(), 1);
    assert_eq!(record.virtual_position(), 3 * 0x4000 + 0x1000);
    let sub_page = Record {
        index: 2,
        offset: 0,
        high_byte: 0x20 | (2 << 6),
        second_word: 0,
    };
    assert_eq!(sub_page.virtual_position(), 0x2000);
}

#[test]
fn reports_non_zero_padding_and_accepts_zero_padding() {
    // The builder declares the alignment padding, which is zero.
    let data = vec![0x33; 0x1000];
    let bytes = Build::default().build(&[zlib(&data)], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    assert!(container.blocks[0].padding > 0);
    decode_block(
        &mut source,
        &mut container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap();

    let mut damaged = bytes;
    let padding_at = container.blocks[0].offset as usize + container.blocks[0].content_len as usize;
    damaged[padding_at] = 0x7F;
    let mut container = read(&damaged).unwrap();
    container
        .classify(
            &mut Cursor::new(&damaged),
            usize::MAX,
            &AtomicBool::new(false),
        )
        .unwrap();
    let err = decode_block(
        &mut Cursor::new(&damaged),
        &mut container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("padding bytes that are not zero"), "{err}");
}

#[test]
fn reads_and_checks_the_key_table() {
    let bytes = Build::default().build(&[zlib_block(), zlib_block()], 0);
    let container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    let keys = container.keys(&mut source).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(!Container::keys_sorted(&keys));

    let mut sorted = bytes;
    let at = container.entry_table_offset() as usize + container.entry_table_len() as usize;
    set_u32(&mut sorted, at, 1);
    set_u32(&mut sorted, at + 8, 2);
    let container = read(&sorted).unwrap();
    let keys = container.keys(&mut Cursor::new(&sorted)).unwrap();
    assert_eq!(keys, vec![1, 2]);
    assert!(Container::keys_sorted(&keys));
}

#[test]
fn caps_the_cumulative_decoded_size() {
    let page = vec![0x11; 0x1000];
    let bytes = Build::default().build(&[zlib(&page), zlib(&page)], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    container
        .classify(&mut source, usize::MAX, &AtomicBool::new(false))
        .unwrap();
    let limits = Limits {
        max_total_len: 0x1000,
        ..Limits::default()
    };
    decode_block(
        &mut source,
        &mut container,
        0,
        &limits,
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap();
    let err = decode_block(
        &mut source,
        &mut container,
        1,
        &limits,
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("cumulative limit"), "{err}");
}

#[test]
fn rejects_an_index_that_cannot_exist() {
    let bytes = Build::default().build(&[zlib_block(), zlib_block()], 0);
    let mut container = read(&bytes).unwrap();
    container
        .classify(
            &mut Cursor::new(&bytes),
            usize::MAX,
            &AtomicBool::new(false),
        )
        .unwrap();
    for index in [7, u32::MAX] {
        let err = decode_block(
            &mut Cursor::new(&bytes),
            &mut container,
            index,
            &Limits::default(),
            &AtomicBool::new(false),
            |_| Ok(()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not exist"), "{err}");
    }
}

/// A descriptor with the fields the research defines.
#[derive(Clone, Copy)]
struct Descriptor {
    width: u32,
    height: u32,
    mip: u8,
    flags: u8,
    format: u8,
    array_minus_one: u16,
    kind: u8,
    tile: u8,
    page: u32,
}

impl Default for Descriptor {
    fn default() -> Self {
        Self {
            width: 64,
            height: 64,
            mip: 0,
            flags: 0,
            format: 98,
            array_minus_one: 0,
            kind: 2,
            tile: 0,
            page: 1,
        }
    }
}

impl Descriptor {
    fn bytes(self) -> [u32; 4] {
        let w0 = (self.width - 1) | ((self.height - 1) << 14) | (u32::from(self.mip) << 28);
        let w1 = u32::from(self.flags)
            | (u32::from(self.format) << 3)
            | (u32::from(self.array_minus_one) << 10)
            | (u32::from(self.kind) << 20)
            | (u32::from(self.tile) << 24);
        [w0, w1, self.page, 0]
    }
}

#[test]
fn reconstructs_a_single_block_texture() {
    let texels = 1024u32 * 512;
    let data = noise(texels as usize);
    let bytes = Build {
        entries: vec![
            Descriptor {
                width: 1024,
                height: 512,
                flags: 1,
                ..Descriptor::default()
            }
            .bytes(),
        ],
        ..Build::default()
    }
    .build(&[zlib(&data)], 0);
    let mut container = read(&bytes).unwrap();
    let mut source = Cursor::new(&bytes);
    let mut decoded = Vec::new();
    let report = reconstruct_texture(
        &mut source,
        &mut container,
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
    assert_eq!(report.width, 1024);
    assert_eq!(report.height, 512);
    assert_eq!(report.format_id, 98);
    assert_eq!(report.kind, 2);
    assert_eq!(report.mip, 0);
    assert_eq!(report.first_page, 1);
    assert_eq!(report.block_count, 1);
    assert_eq!(report.classes, vec![0x20]);
    assert_eq!(report.decoded_len, u64::from(texels));
    assert_eq!(report.virtual_start, 0x1000);
    assert_eq!(report.virtual_end, 0x1000 + u64::from(texels));
    assert_eq!(report.bytes_per_texel, Some(1));
    assert!(report.complete, "{report:?}");
}

#[test]
fn reconstructs_a_stored_class_texture_verbatim() {
    let data = noise(0x1000);
    let bytes = Build {
        classes: vec![0x00],
        entries: vec![
            Descriptor {
                format: 71,
                ..Descriptor::default()
            }
            .bytes(),
        ],
        ..Build::default()
    }
    .build(std::slice::from_ref(&data), 0);
    let mut container = read(&bytes).unwrap();
    let mut decoded = Vec::new();
    let report = reconstruct_texture(
        &mut Cursor::new(&bytes),
        &mut container,
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
    assert_eq!(report.classes, vec![0x00]);
    assert!(report.complete);
}

#[test]
fn refuses_a_texture_whose_block_class_is_undecoded() {
    let bytes = Build {
        classes: vec![0x04],
        entries: vec![Descriptor::default().bytes()],
        ..Build::default()
    }
    .build(&[vec![0x55; 0x1000]], 0);
    let mut container = read(&bytes).unwrap();
    let err = reconstruct_texture(
        &mut Cursor::new(&bytes),
        &mut container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("storage class 0x04"), "{err}");
}

#[test]
fn refuses_a_locator_page_that_is_not_a_block_start() {
    let bytes = Build {
        entries: vec![
            Descriptor {
                page: 7,
                ..Descriptor::default()
            }
            .bytes(),
        ],
        ..Build::default()
    }
    .build(&[zlib(&vec![0u8; 0x1000])], 0);
    let mut container = read(&bytes).unwrap();
    let err = reconstruct_texture(
        &mut Cursor::new(&bytes),
        &mut container,
        0,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("not a block start"), "{err}");
}

#[test]
fn reports_a_descriptor_that_does_not_exist() {
    let bytes = Build::default().build(&[zlib(&vec![0u8; 0x1000])], 0);
    let mut container = read(&bytes).unwrap();
    let err = reconstruct_texture(
        &mut Cursor::new(&bytes),
        &mut container,
        5,
        &Limits::default(),
        &AtomicBool::new(false),
        |_| Ok(()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("does not exist"), "{err}");
}
