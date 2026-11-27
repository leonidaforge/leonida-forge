//! Tests on synthetic metadata built in memory.

use std::io::Cursor;

use super::*;

const KEY_X: u64 = 0x1111_2222_3333_4444;
const KEY_Y: u64 = 0x5555_6666_7777_8888;

pub(crate) struct Column {
    key: u64,
    width: u16,
    pool: Vec<u8>,
    cells: Vec<Option<u32>>,
}

impl Column {
    pub(crate) fn new(key: u64, width: u16, elements: &[&[u8]], cells: &[Option<u32>]) -> Self {
        let mut pool = Vec::new();
        for element in elements {
            assert_eq!(element.len(), usize::from(width));
            pool.extend_from_slice(element);
        }
        Self {
            key,
            width,
            pool,
            cells: cells.to_vec(),
        }
    }
}

pub(crate) struct Build {
    pub(crate) a_ids: Vec<u16>,
    pub(crate) b_len: u32,
    pub(crate) flags: u8,
    pub(crate) selector: u8,
    pub(crate) cell_width: u8,
    pub(crate) secondary: u16,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            a_ids: vec![2, 3, 4, 6],
            b_len: 0x150,
            flags: 1,
            selector: 0,
            cell_width: 1,
            secondary: 0,
        }
    }
}

fn up(value: usize, to: usize) -> usize {
    value.next_multiple_of(to)
}

impl Build {
    fn build(&self, columns: &[Column]) -> Vec<u8> {
        let rows = columns.first().map_or(0, |c| c.cells.len());
        let count = columns.len();
        let secondary = usize::from(self.secondary);
        let primary = count - secondary;
        let f = usize::from(self.cell_width);
        let region = if self.flags & 1 != 0 { 16 } else { 8 };
        let a = up(0x40, if self.flags & 1 != 0 { 16 } else { 4 });
        let b = up(a + self.a_ids.len() * 8, region);
        let descriptors = up(b + self.b_len as usize, region);
        let primary_cells = up(descriptors + count * DESCRIPTOR_LEN, f);
        let primary_pool = up(primary_cells + primary * rows * f, 8);
        let mut pool_offsets = Vec::new();
        let mut primary_end = primary_pool;
        for column in &columns[..primary] {
            pool_offsets.push(primary_end - primary_pool);
            primary_end += column.pool.len();
        }
        let secondary_cells = up(primary_end, f);
        let secondary_pool = up(secondary_cells + secondary * rows * f, 8);
        let mut end = secondary_pool;
        for column in &columns[primary..] {
            pool_offsets.push(end - secondary_pool);
            end += column.pool.len();
        }

        let mut bytes = vec![0u8; end];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..8].copy_from_slice(&(end as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(primary_end as u32).to_le_bytes());
        bytes[0x1A..0x1C].copy_from_slice(&(self.a_ids.len() as u16).to_le_bytes());
        bytes[0x1C..0x20].copy_from_slice(&self.b_len.to_le_bytes());
        bytes[0x20..0x22].copy_from_slice(&(count as u16).to_le_bytes());
        bytes[0x22..0x24].copy_from_slice(&self.secondary.to_le_bytes());
        bytes[0x24..0x28].copy_from_slice(&(rows as u32).to_le_bytes());
        bytes[0x2C] = self.cell_width;
        bytes[0x2D] = self.flags;
        bytes[0x2E] = self.selector;
        bytes[0x30..0x34].copy_from_slice(&0x10u32.min(self.b_len).to_le_bytes());
        for (ix, id) in self.a_ids.iter().enumerate() {
            let record = a + ix * 8;
            bytes[record..record + 2].copy_from_slice(&id.to_le_bytes());
            bytes[record + 4..record + 8].copy_from_slice(&(ix as u32 * 0x20).to_le_bytes());
        }
        for (ix, column) in columns.iter().enumerate() {
            let at = descriptors + ix * DESCRIPTOR_LEN;
            bytes[at..at + 8].copy_from_slice(&column.key.to_le_bytes());
            bytes[at + 8..at + 12].fill(0xAA);
            bytes[at + 12..at + 16].copy_from_slice(&(pool_offsets[ix] as u32).to_le_bytes());
            bytes[at + 16..at + 18].copy_from_slice(&column.width.to_le_bytes());
            bytes[at + 18..at + 24].fill(0xBB);
            let (store, stride, local, pool) = if ix < primary {
                (primary_cells, primary, ix, primary_pool)
            } else {
                (secondary_cells, secondary, ix - primary, secondary_pool)
            };
            let pool_at = pool + pool_offsets[ix];
            bytes[pool_at..pool_at + column.pool.len()].copy_from_slice(&column.pool);
            for (row, cell) in column.cells.iter().enumerate() {
                let at = store + (row * stride + local) * f;
                let value = cell.unwrap_or(u32::MAX);
                bytes[at..at + f].copy_from_slice(&value.to_le_bytes()[..f]);
            }
        }
        bytes
    }

    pub(crate) fn metadata(&self, columns: &[Column]) -> Metadata {
        Metadata::from_decoded(self.build(columns)).unwrap()
    }
}

pub(crate) fn record_a(
    stored16: u32,
    offset16: u32,
    logical: u64,
    type_id: u8,
    mode: u8,
) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&stored16.to_le_bytes());
    value.extend_from_slice(&offset16.to_le_bytes());
    let packed = logical | (u64::from(type_id) << 48) | (u64::from(mode) << 56);
    value.extend_from_slice(&packed.to_le_bytes());
    value
}

fn record_r(words: [u32; 4], type_id: u8, mode: u8) -> Vec<u8> {
    let mut value: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    value.extend_from_slice(&[type_id, mode, 0, 0]);
    value
}

fn record_f(offset16: u64, stored16: u64, logical: u64, type_id: u8, mode: u8) -> Vec<u8> {
    let first = offset16 | (u64::from(type_id) << 40) | (u64::from(mode) << 48);
    [first, stored16, logical]
        .iter()
        .flat_map(|q| q.to_le_bytes())
        .collect()
}

fn invalid_reason<T: fmt::Debug>(result: Result<T, Error>) -> String {
    match result {
        Err(Error::Invalid(reason)) => reason,
        other => panic!("expected Error::Invalid, got {other:?}"),
    }
}

#[test]
fn layout_matches_documented_offsets() {
    let columns = [
        Column::new(KEY_X, 4, &[&[1, 0, 0, 0]], &[Some(0), Some(0)]),
        Column::new(KEY_Y, 4, &[&[2, 0, 0, 0]], &[Some(0), None]),
        Column::new(keys::NAME_HASH, 8, &[&[3; 8]], &[Some(0), Some(0)]),
    ];
    let metadata = Build {
        secondary: 1,
        ..Build::default()
    }
    .metadata(&columns);
    let layout = metadata.layout();
    assert_eq!(layout.a_table, 0x40..0x60);
    assert_eq!(layout.b_block, 0x60..0x1B0);
    assert_eq!(layout.descriptors, 0x1B0..0x1F8);
    assert_eq!(layout.primary_cells, 0x1F8..0x1FC);
    assert_eq!(layout.primary_pool.start, 0x200);
}

#[test]
fn layout_without_16_byte_alignment() {
    let columns = [Column::new(KEY_X, 1, &[&[7]], &[Some(0)])];
    let metadata = Build {
        a_ids: vec![2, 3, 6],
        b_len: 0x15,
        flags: 0,
        ..Build::default()
    }
    .metadata(&columns);
    let layout = metadata.layout();
    assert_eq!(layout.b_block, 0x58..0x6D);
    assert_eq!(layout.descriptors.start, 0x70);
    assert_eq!(metadata.value(0, 0).unwrap(), Some(&[7][..]));
}

#[test]
fn looks_up_primary_and_secondary_columns() {
    let columns = [
        Column::new(
            keys::NAME_HASH,
            8,
            &[&7u64.to_le_bytes(), &9u64.to_le_bytes()],
            &[Some(1), Some(0)],
        ),
        Column::new(KEY_X, 2, &[&[0xAB, 0xCD]], &[Some(0), None]),
    ];
    let metadata = Build {
        secondary: 1,
        cell_width: 2,
        ..Build::default()
    }
    .metadata(&columns);
    assert_eq!(metadata.column(KEY_X), Some(1));
    assert_eq!(metadata.column(KEY_Y), None);
    assert_eq!(metadata.name_hash(0).unwrap(), Some(9));
    assert_eq!(metadata.name_hash(1).unwrap(), Some(7));
    assert_eq!(metadata.field(0, KEY_X).unwrap(), Some(&[0xAB, 0xCD][..]));
    assert_eq!(metadata.field(1, KEY_X).unwrap(), None);
    assert_eq!(metadata.field(0, KEY_Y).unwrap(), None);
    let secondary = metadata.layout().secondary_pool.clone();
    assert!(secondary.start >= metadata.prefix().primary_len as usize);
}

#[test]
fn addresses_cells_row_major() {
    let element = |n: u8| [n];
    let pool: Vec<[u8; 1]> = (0..9).map(element).collect();
    let pool: Vec<&[u8]> = pool.iter().map(|e| &e[..]).collect();
    let columns: Vec<Column> = (0..3)
        .map(|c| {
            let cells: Vec<Option<u32>> = (0..3).map(|r| Some(r * 3 + c)).collect();
            Column::new(KEY_X + u64::from(c), 1, &pool, &cells)
        })
        .collect();
    let metadata = Build {
        cell_width: 2,
        ..Build::default()
    }
    .metadata(&columns);
    for row in 0..3 {
        for column in 0..3u16 {
            let expected = row * 3 + u32::from(column);
            assert_eq!(metadata.cell(row, column).unwrap(), Some(expected));
            assert_eq!(
                metadata.value(row, column).unwrap(),
                Some(&[expected as u8][..])
            );
        }
    }
    let raw = Build {
        cell_width: 2,
        ..Build::default()
    }
    .build(&columns);
    let store = metadata.layout().primary_cells.start;
    let cell = store + (2 * 3 + 1) * 2;
    assert_eq!(u16::from_le_bytes([raw[cell], raw[cell + 1]]), 7);
}

#[test]
fn rows_share_dictionary_values() {
    let columns = [Column::new(KEY_X, 4, &[&[1, 2, 3, 4]], &[Some(0), Some(0)])];
    let metadata = Build::default().metadata(&columns);
    let first = metadata.value(0, 0).unwrap().unwrap();
    let second = metadata.value(1, 0).unwrap().unwrap();
    assert_eq!(first.as_ptr(), second.as_ptr());
}

#[test]
fn null_sentinels() {
    for cell_width in [1, 2] {
        let columns = [Column::new(KEY_X, 1, &[&[5]], &[None, Some(0)])];
        let metadata = Build {
            cell_width,
            ..Build::default()
        }
        .metadata(&columns);
        assert_eq!(metadata.cell(0, 0).unwrap(), None);
        assert_eq!(metadata.value(0, 0).unwrap(), None);
        assert_eq!(metadata.value(1, 0).unwrap(), Some(&[5][..]));
    }
    // Width 4 has no sentinel: all ones is an index, here past the pool.
    let columns = [Column::new(KEY_X, 1, &[&[5]], &[Some(u32::MAX)])];
    let metadata = Build {
        cell_width: 4,
        ..Build::default()
    }
    .metadata(&columns);
    assert_eq!(metadata.cell(0, 0).unwrap(), Some(u32::MAX));
    invalid_reason(metadata.value(0, 0));
}

#[test]
fn keeps_unknown_descriptor_bytes() {
    let columns = [Column::new(KEY_X, 1, &[&[5]], &[Some(0)])];
    let descriptor = Build::default().metadata(&columns).descriptor(0).unwrap();
    assert_eq!(descriptor.key, KEY_X);
    assert_eq!(descriptor.unknown_08, [0xAA; 4]);
    assert_eq!(descriptor.unknown_12, [0xBB; 6]);
    assert_eq!(descriptor.width, 1);
}

#[test]
fn parses_location_layouts() {
    let r = Location::parse(RecordLayout::R, &record_r([0x30, 0x20, 0x10, 0x40], 7, 1)).unwrap();
    assert_eq!(r.payload_offset, 0x400);
    assert_eq!(r.stored_len, 0x100);
    assert_eq!(r.logical_len, 0x50);
    assert_eq!((r.type_id, r.mode), (7, 1));
    assert!(r.is_compressed());

    let f = Location::parse(
        RecordLayout::F,
        &record_f(0xAB_CDEF_0123, 0x12_3456, 0xFFF_FFFF_FFFF, 9, 0),
    )
    .unwrap();
    assert_eq!(f.payload_offset, 0x0ABC_DEF0_1230);
    assert_eq!(f.stored_len, 0x123_4560);
    assert_eq!(f.logical_len, 0xFFF_FFFF_FFFF);
    assert_eq!((f.type_id, f.mode), (9, 0));
    assert!(!f.is_compressed());

    let a = Location::parse(
        RecordLayout::A,
        &record_a(0x10, 0x20, 0x1234_5678_9ABC, 3, 2),
    )
    .unwrap();
    assert_eq!(a.payload_offset, 0x200);
    assert_eq!(a.stored_len, 0x100);
    assert_eq!(a.logical_len, 0x1234_5678_9ABC);
    assert_eq!((a.type_id, a.mode), (3, 2));
}

#[test]
fn masks_unused_location_bits() {
    // Bits above the 40-bit fields of F and above the 48-bit size of A.
    let mut f = record_f(1, 1, 0x10, 0, 0);
    f[0x0F] = 0xFF;
    f[0x17] = 0xFF;
    let f = Location::parse(RecordLayout::F, &f).unwrap();
    assert_eq!((f.stored_len, f.logical_len), (0x10, 0x10));
    let a = record_a(0, 0, 0x55, 0xEE, 0xDD);
    let a = Location::parse(RecordLayout::A, &a).unwrap();
    assert_eq!((a.logical_len, a.type_id, a.mode), (0x55, 0xEE, 0xDD));
}

#[test]
fn resource_logical_size() {
    // Bit 31 of word 0 and the low nibbles of both words are masked off.
    let record = record_r([0x8000_001F, 0x0000_100F, 0, 0], 0, 0);
    let location = Location::parse(RecordLayout::R, &record).unwrap();
    assert_eq!(location.logical_len, 0x1000 + 0x10);
    let record = record_r([0xFFFF_FFFF, 0xFFFF_FFFF, 0, 0], 0, 0);
    let location = Location::parse(RecordLayout::R, &record).unwrap();
    assert_eq!(location.logical_len, 0xFFFF_FFF0 + 0x7FFF_FFF0);
}

#[test]
fn stored_size_wraps_in_32_bits() {
    let r = Location::parse(
        RecordLayout::R,
        &record_r([0, 0, 0x1000_0001, 0x1000_0001], 0, 0),
    )
    .unwrap();
    assert_eq!(r.stored_len, 0x10);
    assert_eq!(r.payload_offset, 0x1_0000_0010);
    let a = Location::parse(RecordLayout::A, &record_a(0x1000_0001, 0, 0, 0, 0)).unwrap();
    assert_eq!(a.stored_len, 0x10);
    let f = Location::parse(RecordLayout::F, &record_f(0, 0xF0_0000_0001, 0, 0, 0)).unwrap();
    assert_eq!(f.stored_len, 0xF00_0000_0010);
}

#[test]
fn location_priority() {
    let a = record_a(1, 2, 3, 0, 0);
    let r = record_r([0, 0, 4, 5], 0, 0);
    let f = record_f(6, 7, 8, 0, 0);
    // Descriptor order A, F, R: the selection order must not follow it.
    let columns = [
        Column::new(
            keys::LOCATION_A,
            16,
            &[&a],
            &[Some(0), Some(0), Some(0), None],
        ),
        Column::new(keys::LOCATION_F, 24, &[&f], &[None, Some(0), Some(0), None]),
        Column::new(keys::LOCATION_R, 20, &[&r], &[None, None, Some(0), None]),
    ];
    let metadata = Build::default().metadata(&columns);
    assert_eq!(metadata.location(0).unwrap().layout, RecordLayout::A);
    assert_eq!(metadata.location(1).unwrap().layout, RecordLayout::F);
    assert_eq!(metadata.location(2).unwrap().layout, RecordLayout::R);
    invalid_reason(metadata.location(3));
}

#[test]
fn rejects_short_location_records() {
    let columns = [Column::new(
        keys::LOCATION_R,
        0x11,
        &[&[0; 0x11]],
        &[Some(0)],
    )];
    let metadata = Build::default().metadata(&columns);
    assert!(invalid_reason(metadata.location(0)).contains("shorter"));
}

#[test]
fn checks_payload_ranges() {
    let a = Location::parse(RecordLayout::A, &record_a(2, 3, 0, 0, 0)).unwrap();
    assert_eq!(a.stored_range(0x1000), Some(0x1030..0x1050));
    assert_eq!(a.stored_range(u64::MAX - 0x10), None);
}

fn chunk_entry_2(logical16: u64, stored16: u64, padding: u64, method: u64) -> u64 {
    logical16 | (stored16 << 32) | (padding << 58) | (method << 62)
}

#[test]
fn decodes_chunk_encodings() {
    let two = Chunk::decode(chunk_entry_2(0x1000, 0x123, 5, 3), 2).unwrap();
    assert_eq!(
        two,
        Chunk {
            logical_len: 0x1_0000,
            stored_len: 0x1230,
            padding: 5,
            compressed_len: 0x122B,
            method: 3,
        }
    );
    assert!(two.is_compressed());

    // The padding nibble is the low nibble of the compressed-size field.
    let three = Chunk::decode(0x0100 | (0x2345 << 16) | (2 << 60), 3).unwrap();
    assert_eq!(
        three,
        Chunk {
            logical_len: 0xFF00,
            stored_len: 0xDCBB + 5,
            padding: 5,
            compressed_len: 0x1_0000 - 0x2345,
            method: 2,
        }
    );
    let full = Chunk::decode(0, 3).unwrap();
    assert_eq!(
        (full.logical_len, full.compressed_len),
        (0x1_0000, 0x1_0000)
    );

    let four = Chunk::decode(0x00AB_CDEF | (0x42 << 28) | (7 << 52) | (2 << 56), 4).unwrap();
    assert_eq!(
        four,
        Chunk {
            logical_len: 0x00AB_CDEF,
            stored_len: 0x420,
            padding: 7,
            compressed_len: 0x419,
            method: 2,
        }
    );
    assert!(!four.is_compressed());

    for encoding in [0, 1, 5, 0xFF] {
        assert_eq!(Chunk::decode(u64::MAX, encoding), None);
    }
}

#[test]
fn chunk_compressed_size_wraps_like_the_engine() {
    let chunk = Chunk::decode(chunk_entry_2(0, 0, 5, 0), 2).unwrap();
    assert_eq!(chunk.compressed_len, 0u32.wrapping_sub(5));
}

fn chunk_value(relative: u32, count: u16, encoding: u8, entries: &[u64]) -> Vec<u8> {
    let mut value = relative.to_le_bytes().to_vec();
    value.extend_from_slice(&count.to_le_bytes());
    value.push(0);
    value.push(encoding);
    for entry in entries {
        value.extend_from_slice(&entry.to_le_bytes());
    }
    value
}

#[test]
fn reads_chunk_tables() {
    let entries = [0x0100 | (0x2345 << 16), 0x0200];
    let value = chunk_value(8, 2, 3, &entries);
    let width = value.len() as u16;
    let columns = [Column::new(
        keys::CHUNK_TABLE,
        width,
        &[&value],
        &[Some(0), None],
    )];
    let metadata = Build::default().metadata(&columns);
    let table = metadata.chunk_table(0).unwrap().unwrap();
    assert_eq!(table.encoding, 3);
    assert_eq!(table.chunks.len(), 2);
    assert_eq!(table.chunks[1].logical_len, 0xFE00);
    assert_eq!(metadata.chunk_table(1).unwrap(), None);
}

#[test]
fn rejects_bad_chunk_tables() {
    for (value, reason) in [
        (chunk_value(8, 100, 3, &[0]), "after their pool"),
        (chunk_value(u32::MAX, 1, 3, &[0]), ""),
        (chunk_value(8, 1, 9, &[0]), "unsupported chunk encoding"),
    ] {
        let width = value.len() as u16;
        let columns = [Column::new(keys::CHUNK_TABLE, width, &[&value], &[Some(0)])];
        let metadata = Build::default().metadata(&columns);
        assert!(invalid_reason(metadata.chunk_table(0)).contains(reason));
    }
    let columns = [Column::new(keys::CHUNK_TABLE, 4, &[&[0; 4]], &[Some(0)])];
    let metadata = Build::default().metadata(&columns);
    assert!(invalid_reason(metadata.chunk_table(0)).contains("shorter"));
}

#[test]
fn reports_the_payload_transform_flag() {
    let columns = [
        Column::new(keys::PAYLOAD_TRANSFORM, 1, &[&[0]], &[Some(0), None]),
        Column::new(KEY_X, 1, &[&[0]], &[Some(0), Some(0)]),
    ];
    let metadata = Build::default().metadata(&columns);
    assert!(metadata.payload_transform(0).unwrap());
    assert!(!metadata.payload_transform(1).unwrap());
}

/// A descriptor shaped like the engine's: key identifier, cipher type and
/// 16-byte parameter, followed by stream fields that the reader ignores.
fn transform_value(key_id: u32, kind: u16, parameter: [u8; 16]) -> Vec<u8> {
    let mut value = vec![0u8; 64];
    value[0..4].copy_from_slice(&key_id.to_le_bytes());
    value[4..6].copy_from_slice(&kind.to_le_bytes());
    value[6..22].copy_from_slice(&parameter);
    value[0x38..0x3c].copy_from_slice(&4u32.to_le_bytes());
    value
}

#[test]
fn reads_the_payload_transform_descriptor() {
    use crate::rpf::metadata::transform::{Algorithm, CipherDescriptor};

    let parameter = [
        0x75, 0x83, 0x2e, 0x88, 0xa4, 0x56, 0x13, 0x33, 0x67, 0xe5, 0x89, 0xc6, 0x0a, 0x10, 0x83,
        0xb8,
    ];
    let value = transform_value(0x1000_0029, 0x11, parameter);
    let columns = [
        Column::new(keys::PAYLOAD_TRANSFORM, 64, &[&value], &[Some(0), None]),
        Column::new(KEY_X, 1, &[&[0]], &[Some(0), Some(0)]),
    ];
    let metadata = Build::default().metadata(&columns);

    let cipher = metadata.payload_cipher(0).unwrap().unwrap();
    assert_eq!(
        cipher,
        CipherDescriptor {
            key_id: 0x1000_0029,
            kind: 0x11,
            parameter,
        }
    );
    // Type 0x11 selects algorithm 0x11, whose block operation is not
    // implemented, so readers must keep refusing transformed payloads.
    assert_eq!(Algorithm::of(cipher.kind).unwrap().id(), 0x11);
    assert!(metadata.payload_cipher(1).unwrap().is_none());
    // The flag accessor keeps reporting presence alone.
    assert!(metadata.payload_transform(0).unwrap());
    assert!(!metadata.payload_transform(1).unwrap());
}

#[test]
fn rejects_a_short_payload_transform_descriptor() {
    let columns = [Column::new(
        keys::PAYLOAD_TRANSFORM,
        8,
        &[&[0u8; 8]],
        &[Some(0)],
    )];
    let metadata = Build::default().metadata(&columns);
    let reason = invalid_reason(metadata.payload_cipher(0));
    assert!(reason.contains("shorter than 22"), "{reason}");
    // Presence alone still holds, so the transform flag is unaffected.
    assert!(metadata.payload_transform(0).unwrap());
}

fn header_with(edit: impl FnOnce(&mut Vec<u8>)) -> Result<Metadata, Error> {
    let columns = [Column::new(KEY_X, 4, &[&[1, 2, 3, 4]], &[Some(0)])];
    let mut bytes = Build::default().build(&columns);
    edit(&mut bytes);
    Metadata::from_decoded(bytes)
}

fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn rejects_malformed_prefixes() {
    type Edit = Box<dyn FnOnce(&mut Vec<u8>)>;
    let cases: [(&str, Edit); 7] = [
        ("secondary columns", Box::new(|b| set_u16(b, 0x22, 2))),
        ("index width", Box::new(|b| b[0x2C] = 3)),
        ("rows exceed", Box::new(|b| set_u32(b, 0x24, 0x1_0000))),
        ("inside the header", Box::new(|b| set_u32(b, 8, 0x20))),
        (
            "after the metadata area",
            Box::new(|b| set_u32(b, 8, u32::MAX)),
        ),
        ("trailer", Box::new(|b| set_u32(b, 0x30, 0x151))),
        ("not an RPF9", Box::new(|b| b[0] = 0)),
    ];
    for (reason, edit) in cases {
        let message = invalid_reason(header_with(edit));
        assert!(message.contains(reason), "{message}");
    }
}

#[test]
fn rejects_regions_outside_their_areas() {
    let message = invalid_reason(header_with(|b| set_u16(b, 0x20, 40)));
    assert!(message.contains("primary regions"), "{message}");
    let message = invalid_reason(header_with(|b| set_u32(b, 0x1C, 0x10_0000)));
    assert!(message.contains("primary regions"), "{message}");
    let message = invalid_reason(header_with(|b| {
        set_u16(b, 0x22, 1);
        set_u32(b, 0x24, 0xFFFF);
    }));
    assert!(message.contains("secondary regions"), "{message}");
    let message = invalid_reason(header_with(|b| b.push(0)));
    assert!(message.contains("bytes given"), "{message}");
}

#[test]
fn rejects_index_store_overflow() {
    let message = invalid_reason(header_with(|b| {
        set_u16(b, 0x20, 0xFFFF);
        set_u32(b, 0x24, 0xFFFF);
        b[0x2C] = 4;
    }));
    assert!(message.contains("32 bits"), "{message}");
}

#[test]
fn rejects_out_of_range_values() {
    let columns = [Column::new(KEY_X, 4, &[&[1, 2, 3, 4]], &[Some(1)])];
    let metadata = Build::default().metadata(&columns);
    assert!(invalid_reason(metadata.value(0, 0)).contains("after its pool"));
    invalid_reason(metadata.cell(1, 0));
    invalid_reason(metadata.cell(0, 1));

    let mut bytes = Build {
        cell_width: 4,
        ..Build::default()
    }
    .build(&[Column::new(KEY_X, 4, &[&[0; 4]], &[Some(u32::MAX)])]);
    let descriptor = 0x1B0;
    set_u32(&mut bytes, descriptor + 0x0C, u32::MAX);
    set_u16(&mut bytes, descriptor + 0x10, u16::MAX);
    let metadata = Metadata::from_decoded(bytes).unwrap();
    invalid_reason(metadata.value(0, 0));
}

fn stored(selector: u8, a_ids: Vec<u16>) -> Stored {
    let columns = [Column::new(KEY_X, 4, &[&[1, 2, 3, 4]], &[Some(0)])];
    let bytes = Build {
        selector,
        a_ids,
        ..Build::default()
    }
    .build(&columns);
    Stored::from_bytes(bytes).unwrap()
}

#[test]
fn does_not_parse_processed_metadata() {
    let static_pass = stored(9, vec![2, 3, 4, 6]);
    let expected = Processing {
        static_pass: true,
        archive_pass: None,
    };
    assert_eq!(static_pass.processing(), expected);
    assert!(matches!(static_pass.decode(), Err(Error::Transformed(p)) if p == expected));

    let archive_pass = stored(0, vec![1, 2, 6]);
    let expected = Processing {
        static_pass: false,
        archive_pass: Some(true),
    };
    assert!(matches!(archive_pass.decode(), Err(Error::Transformed(p)) if p == expected));

    let plain = stored(0, vec![2, 3, 4, 6]);
    assert!(plain.processing().is_none());
    let metadata = plain.decode().unwrap();
    assert_eq!(metadata.field(0, KEY_X).unwrap(), Some(&[1, 2, 3, 4][..]));
}

#[test]
fn reads_stored_metadata_from_an_archive() {
    let columns = [Column::new(KEY_X, 4, &[&[1, 2, 3, 4]], &[Some(0)])];
    let metadata = Build::default().build(&columns);
    let mut archive = metadata.clone();
    archive.extend_from_slice(&[0xCC; 64]);

    let stored = Stored::read(&mut Cursor::new(&archive), 1 << 20).unwrap();
    assert_eq!(stored.bytes(), &metadata[..]);
    assert_eq!(stored.prefix().rows, 1);

    let limit = metadata.len() as u64 - 1;
    assert!(matches!(
        Stored::read(&mut Cursor::new(&archive), limit),
        Err(Error::TooLarge { .. })
    ));
    let truncated = &archive[..metadata.len() - 1];
    invalid_reason(Stored::read(&mut Cursor::new(truncated), 1 << 20));
    assert!(matches!(
        Stored::read(&mut Cursor::new(&archive[..0x20]), 1 << 20),
        Err(Error::Io(_))
    ));
}

mod chain {
    //! The cipher passes with synthetic block operations and keys.

    use super::*;
    use crate::rpf::metadata::transform::tests::Toy;
    use crate::rpf::metadata::transform::{self, BLOCK_LEN, Block};

    const STATIC_ID: u32 = 0x51;
    const ARCHIVE_ID: u32 = 0xA7;
    const STATIC_KEY: Block = *b"static key 00004";
    const ARCHIVE_KEY: Block = *b"archive key 0001";
    const STATIC_IV: Block = [0x3C; BLOCK_LEN];
    const ARCHIVE_IV: Block = [0x96; BLOCK_LEN];

    // Spans of the synthetic layout below.
    const A_SPAN: Range<usize> = 0x40..0x60;
    const B_SPAN: Range<usize> = 0x60..0x1A0;
    const AB_SPAN: Range<usize> = 0x40..0x1B0;
    const PRIMARY_SPAN: Range<usize> = 0x1A0..0x1F0;
    const SECONDARY_SPAN: Range<usize> = 0x1F0..0x200;

    #[derive(Default)]
    struct Source {
        statics: Vec<(u8, Block)>,
        keys: Vec<(u32, Block)>,
    }

    impl Source {
        fn full() -> Self {
            Self {
                statics: (0..8).map(|index| (index, STATIC_IV)).collect(),
                keys: vec![(STATIC_ID, STATIC_KEY), (ARCHIVE_ID, ARCHIVE_KEY)],
            }
        }
    }

    impl transform::CipherSource for Source {
        type Block = Toy;

        fn static_descriptor(&self, index: u8) -> Option<(u32, Block)> {
            let (_, iv) = self.statics.iter().find(|(i, _)| *i == index)?;
            Some((STATIC_ID, *iv))
        }

        fn cbc_block(&self, key_id: u32) -> Option<Toy> {
            let (_, key) = self.keys.iter().find(|(id, _)| *id == key_id)?;
            Some(Toy { key: *key })
        }
    }

    fn archive(kind: u16) -> transform::CipherDescriptor {
        transform::CipherDescriptor {
            key_id: ARCHIVE_ID,
            kind,
            parameter: ARCHIVE_IV,
        }
    }

    /// Metadata with `B` sub-block 1 at the start of `B` when `a_ids` lists
    /// ID 1 first.
    fn plain(selector: u8, a_ids: Vec<u16>, descriptor: transform::CipherDescriptor) -> Vec<u8> {
        let columns = [
            Column::new(KEY_X, 8, &[&[0x5A; 8]], &[Some(0)]),
            Column::new(KEY_Y, 8, &[&[0xC3; 8]], &[Some(0)]),
        ];
        let mut bytes = Build {
            selector,
            a_ids,
            secondary: 1,
            ..Build::default()
        }
        .build(&columns);
        let b = B_SPAN.start;
        set_u32(&mut bytes, b, descriptor.key_id);
        set_u16(&mut bytes, b + 4, descriptor.kind);
        bytes[b + 6..b + 22].copy_from_slice(&descriptor.parameter);
        let layout = Stored::from_bytes(bytes.clone()).unwrap().layout().clone();
        assert_eq!(layout.b_block.start, B_SPAN.start);
        assert_eq!(layout.primary_pool.end, PRIMARY_SPAN.end);
        assert_eq!(layout.secondary_pool.end, SECONDARY_SPAN.end);
        bytes
    }

    /// The inverse of one span runner call.
    fn encrypt(bytes: &mut [u8], key: Block, iv: Block, spans: &[Range<usize>], per_span: bool) {
        let mut next = iv;
        for span in spans {
            Toy { key }.encrypt(next, &mut bytes[span.clone()]);
            next = if per_span {
                iv
            } else {
                bytes[span.end - BLOCK_LEN..span.end].try_into().unwrap()
            };
        }
    }

    fn encrypt_archive_passes(bytes: &mut [u8], per_span: bool) {
        encrypt(bytes, ARCHIVE_KEY, ARCHIVE_IV, &[SECONDARY_SPAN], per_span);
        encrypt(bytes, ARCHIVE_KEY, ARCHIVE_IV, &[PRIMARY_SPAN], per_span);
    }

    fn assert_fields(transformed: Transformed) {
        let metadata = transformed.decode();
        assert_eq!(metadata.field(0, KEY_X).unwrap(), Some(&[0x5A; 8][..]));
        assert_eq!(metadata.field(0, KEY_Y).unwrap(), Some(&[0xC3; 8][..]));
    }

    fn cipher_error(result: Result<Transformed, Error>) -> transform::Error {
        match result {
            Err(Error::Cipher(err)) => err,
            other => panic!("expected Error::Cipher, got {other:?}"),
        }
    }

    #[test]
    fn runs_static_and_archive_passes() {
        let plain = plain(9, vec![1, 2, 6], archive(16));
        let mut bytes = plain.clone();
        encrypt_archive_passes(&mut bytes, false);
        encrypt(&mut bytes, STATIC_KEY, STATIC_IV, &[A_SPAN, B_SPAN], false);
        for span in [A_SPAN, B_SPAN, PRIMARY_SPAN, SECONDARY_SPAN] {
            assert_ne!(bytes[span.clone()], plain[span]);
        }
        let stored = Stored::from_bytes(bytes.clone()).unwrap();

        let transformed = stored.transform(&Source::full()).unwrap();
        assert_eq!(transformed.bytes(), &plain[..]);
        assert!(!transformed.key_lookup_skipped());
        assert_eq!(stored.bytes(), &bytes[..]);
        assert_fields(transformed);
        // Decoding the stored bytes still refuses the processed metadata.
        assert!(matches!(stored.decode(), Err(Error::Transformed(_))));
    }

    #[test]
    fn per_span_types_restart_each_span() {
        // Static index 1 has cipher type 3.
        let plain = plain(3, vec![1, 2, 6], archive(4));
        let mut bytes = plain.clone();
        encrypt_archive_passes(&mut bytes, true);
        encrypt(&mut bytes, STATIC_KEY, STATIC_IV, &[A_SPAN, B_SPAN], true);
        let stored = Stored::from_bytes(bytes).unwrap();
        assert_eq!(
            stored.transform(&Source::full()).unwrap().bytes(),
            &plain[..]
        );
    }

    #[test]
    fn single_static_span_overlaps_the_primary_pass() {
        // Bit 0 clear: one span over A and all of B, including the trailer
        // that step 4 processes again.
        let plain = plain(8, vec![1, 2, 6], archive(16));
        let mut bytes = plain.clone();
        encrypt_archive_passes(&mut bytes, false);
        encrypt(&mut bytes, STATIC_KEY, STATIC_IV, &[AB_SPAN], false);
        let stored = Stored::from_bytes(bytes).unwrap();
        assert_eq!(
            stored.transform(&Source::full()).unwrap().bytes(),
            &plain[..]
        );
    }

    #[test]
    fn default_static_descriptor_is_a_no_op() {
        let plain = plain(1, vec![1, 2, 6], archive(16));
        let mut bytes = plain.clone();
        encrypt_archive_passes(&mut bytes, false);
        let stored = Stored::from_bytes(bytes).unwrap();
        let source = Source {
            keys: vec![(ARCHIVE_ID, ARCHIVE_KEY)],
            ..Source::full()
        };
        let transformed = stored.transform(&source).unwrap();
        assert!(transformed.key_lookup_skipped());
        assert_fields(transformed);
    }

    #[test]
    fn rejects_spans_that_disagree_with_the_layout() {
        let columns = [Column::new(KEY_X, 8, &[&[0x5A; 8]], &[Some(0)])];
        // G bit 0 clear with odd A: the layout puts B at 0x58, the engine at
        // 0x60. G bit 0 set with B not a multiple of 16: the descriptors start
        // at 0x1C0, the engine's B ends at 0x1B8.
        for (flags, selector, a_ids, b_len) in [
            (0, 9, vec![1, 2, 6], 0x150),
            (0, 0, vec![1, 2, 6], 0x150),
            (1, 9, vec![2, 3, 6, 4], 0x158),
        ] {
            let bytes = Build {
                flags,
                selector,
                a_ids,
                b_len,
                ..Build::default()
            }
            .build(&columns);
            let stored = Stored::from_bytes(bytes).unwrap();
            let reason = invalid_reason(stored.transform(&Source::full()));
            assert!(reason.contains("cipher spans"), "{reason}");
        }
        // G bit 0 clear, even A and B a multiple of 8 agree.
        let bytes = Build {
            flags: 0,
            a_ids: vec![1, 2, 6, 3],
            b_len: 0x148,
            ..Build::default()
        }
        .build(&columns);
        Stored::from_bytes(bytes)
            .unwrap()
            .check_span_formulas()
            .unwrap();
    }

    #[test]
    fn archive_pass_only() {
        let plain = plain(0, vec![1, 2, 6], archive(11));
        let mut bytes = plain.clone();
        encrypt_archive_passes(&mut bytes, false);
        let stored = Stored::from_bytes(bytes).unwrap();
        let source = Source {
            keys: vec![(ARCHIVE_ID, ARCHIVE_KEY)],
            ..Source::default()
        };
        assert_eq!(stored.transform(&source).unwrap().bytes(), &plain[..]);
    }

    #[test]
    fn no_passes_keep_the_bytes() {
        let plain = plain(0, vec![2, 3, 6], archive(16));
        let stored = Stored::from_bytes(plain.clone()).unwrap();
        let transformed = stored.transform(&Source::default()).unwrap();
        assert_eq!(transformed.bytes(), &plain[..]);
        assert_eq!(
            transformed.decode().field(0, KEY_X).unwrap(),
            stored.decode().unwrap().field(0, KEY_X).unwrap()
        );
    }

    #[test]
    fn reports_missing_ciphers() {
        let stored = Stored::from_bytes(plain(9, vec![1, 2, 6], archive(16))).unwrap();
        let error = cipher_error(stored.transform(&Source::default()));
        assert_eq!(error, transform::Error::NoStaticDescriptor(4));

        let stored = Stored::from_bytes(plain(0, vec![1, 2, 6], archive(16))).unwrap();
        let source = Source {
            keys: vec![(STATIC_ID, STATIC_KEY)],
            ..Source::full()
        };
        let error = cipher_error(stored.transform(&source));
        assert_eq!(error, transform::Error::NoKey(ARCHIVE_ID));
    }

    #[test]
    fn refuses_unsupported_archive_ciphers() {
        for (kind, expected) in [
            (13, transform::Error::InvalidType(13)),
            (
                2,
                transform::Error::Unsupported {
                    kind: 2,
                    algorithm: 2,
                },
            ),
            (
                7,
                transform::Error::Unsupported {
                    kind: 7,
                    algorithm: 0x12,
                },
            ),
        ] {
            let stored = Stored::from_bytes(plain(0, vec![1, 2, 6], archive(kind))).unwrap();
            assert_eq!(cipher_error(stored.transform(&Source::full())), expected);
            assert!(matches!(stored.decode(), Err(Error::Transformed(_))));
        }
    }

    #[test]
    fn rejects_a_descriptor_outside_the_metadata() {
        let mut bytes = plain(0, vec![1, 2, 6], archive(16));
        set_u32(&mut bytes, A_SPAN.start + 4, 0xFFFF_0000);
        let stored = Stored::from_bytes(bytes).unwrap();
        let reason = invalid_reason(stored.transform(&Source::full()));
        assert!(reason.contains("sub-block 1"), "{reason}");
    }

    #[test]
    fn rejects_unaligned_primary_span() {
        let columns = [Column::new(KEY_X, 4, &[&[1, 2, 3, 4]], &[Some(0)])];
        let mut bytes = Build {
            a_ids: vec![1, 2, 6],
            ..Build::default()
        }
        .build(&columns);
        set_u32(&mut bytes, B_SPAN.start, ARCHIVE_ID);
        set_u16(&mut bytes, B_SPAN.start + 4, 16);
        let stored = Stored::from_bytes(bytes).unwrap();
        let span = stored.primary_span().unwrap();
        assert!(!span.len().is_multiple_of(BLOCK_LEN));
        let error = cipher_error(stored.transform(&Source::full()));
        assert_eq!(error, transform::Error::Unaligned(span.len()));
    }

    #[test]
    fn uses_the_sources_kind_and_block_overrides() {
        // Selector 1 -> index 0, whose current-build static_kind is 0, a
        // no-op. A source that overrides static_kind(0) to 16 (CBC) must drive
        // a real decryption of the static spans, and every pass must resolve
        // its block through cbc_block_for, not the bare cbc_block.
        let plain = plain(1, vec![1, 2, 6], archive(16));
        let mut bytes = plain.clone();
        encrypt_archive_passes(&mut bytes, false);
        encrypt(&mut bytes, STATIC_KEY, STATIC_IV, &[A_SPAN, B_SPAN], false);
        let stored = Stored::from_bytes(bytes).unwrap();

        struct Recognized;
        impl transform::CipherSource for Recognized {
            type Block = Toy;

            fn static_descriptor(&self, index: u8) -> Option<(u32, Block)> {
                (index == 0).then_some((STATIC_ID, STATIC_IV))
            }

            fn static_kind(&self, index: u8) -> Option<u16> {
                (index == 0).then_some(16)
            }

            // Returning None proves the transform resolves blocks through
            // cbc_block_for below, never through the bare cbc_block.
            fn cbc_block(&self, _: u32) -> Option<Toy> {
                None
            }

            fn cbc_block_for(&self, kind: u16, key_id: u32) -> Option<Toy> {
                if !matches!(
                    transform::Algorithm::of(kind),
                    Ok(transform::Algorithm::Cbc)
                ) {
                    return None;
                }
                match key_id {
                    STATIC_ID => Some(Toy { key: STATIC_KEY }),
                    ARCHIVE_ID => Some(Toy { key: ARCHIVE_KEY }),
                    _ => None,
                }
            }
        }

        assert_eq!(stored.transform(&Recognized).unwrap().bytes(), &plain[..]);
    }
}

mod embedded {
    //! Archives inside files and inside other archives, read through views
    //! of a file-backed source.

    use std::io::Write;

    use lforge_binary::Source;

    use super::*;

    const PAYLOADS: usize = 0x1000;

    fn source(bytes: &[u8]) -> Source {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        Source::from_file(file).unwrap()
    }

    fn leaf(value: [u8; 4]) -> Vec<u8> {
        Build::default().build(&[Column::new(KEY_X, 4, &[&value], &[Some(0)])])
    }

    enum Storage {
        Raw,
        Compressed,
        Transformed,
        /// Raw, read through the given read source.
        Source(u32),
        /// Raw, with a logical size one byte above the stored size.
        Oversized,
    }

    /// An archive with one row per payload, stored from offset 0x1000 on.
    fn parent(payloads: &[(&[u8], Storage)]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut records = Vec::new();
        for (payload, stored) in payloads {
            let offset = PAYLOADS + data.len();
            let mode = u8::from(matches!(stored, Storage::Compressed));
            let units = payload.len().div_ceil(16) as u32;
            let logical = match stored {
                Storage::Oversized => u64::from(units) * 16 + 1,
                _ => payload.len() as u64,
            };
            records.push(record_a(units, (offset / 16) as u32, logical, 0, mode));
            data.extend_from_slice(payload);
            data.resize(data.len().next_multiple_of(16), 0);
        }
        let all: Vec<Option<u32>> = (0..payloads.len() as u32).map(Some).collect();
        let transformed: Vec<Option<u32>> = payloads
            .iter()
            .map(|(_, stored)| matches!(stored, Storage::Transformed).then_some(0))
            .collect();
        let sources: Vec<[u8; 4]> = payloads
            .iter()
            .map(|(_, stored)| match stored {
                Storage::Source(index) => index.to_le_bytes(),
                _ => [0; 4],
            })
            .collect();
        let with_source: Vec<Option<u32>> = payloads
            .iter()
            .enumerate()
            .map(|(n, (_, stored))| matches!(stored, Storage::Source(_)).then_some(n as u32))
            .collect();
        let records: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
        let sources: Vec<&[u8]> = sources.iter().map(|s| &s[..]).collect();
        let mut bytes = Build::default().build(&[
            Column::new(keys::LOCATION_A, 16, &records, &all),
            Column::new(keys::PAYLOAD_TRANSFORM, 1, &[&[0]], &transformed),
            Column::new(keys::READ_SOURCE, 4, &sources, &with_source),
        ]);
        assert!(bytes.len() <= PAYLOADS);
        bytes.resize(PAYLOADS, 0);
        bytes.extend_from_slice(&data);
        bytes
    }

    fn decode(source: &mut Source) -> Metadata {
        Stored::read(source, 1 << 20).unwrap().decode().unwrap()
    }

    fn view(parent: &Source, metadata: &Metadata, row: u32) -> Source {
        metadata.raw_source(row, parent, &[]).unwrap()
    }

    #[test]
    fn reads_an_archive_at_offset_zero() {
        let mut bytes = leaf([1, 2, 3, 4]);
        bytes.extend_from_slice(&[0xCC; 0x40]);
        let metadata = decode(&mut source(&bytes));
        assert_eq!(metadata.field(0, KEY_X).unwrap(), Some(&[1, 2, 3, 4][..]));
    }

    #[test]
    fn reads_an_archive_embedded_at_an_offset() {
        let archive = leaf([1, 2, 3, 4]);
        let mut bytes = vec![0xEE; 0x30];
        bytes.extend_from_slice(&archive);
        bytes.extend_from_slice(&[0xCC; 0x20]);
        let file = source(&bytes);

        let metadata = decode(&mut file.slice(0x30, archive.len() as u64).unwrap());
        assert_eq!(metadata.field(0, KEY_X).unwrap(), Some(&[1, 2, 3, 4][..]));
        // A view may extend past the metadata area.
        let rest = file.len() - 0x30;
        decode(&mut file.slice(0x30, rest).unwrap());
        // Without the view, the file does not start with an archive.
        invalid_reason(Stored::read(&mut file.clone(), 1 << 20));
    }

    #[test]
    fn rejects_truncated_embedded_metadata() {
        let archive = leaf([1, 2, 3, 4]);
        let mut bytes = vec![0xEE; 0x30];
        bytes.extend_from_slice(&archive);
        let file = source(&bytes);
        let short = archive.len() as u64 - 1;
        let reason = invalid_reason(Stored::read(&mut file.slice(0x30, short).unwrap(), 1 << 20));
        assert!(reason.contains("end of the file"), "{reason}");
        let header_only = file.slice(0x30, 0x20).unwrap();
        assert!(matches!(
            Stored::read(&mut header_only.clone(), 1 << 20),
            Err(Error::Io(_))
        ));
        assert!(file.slice(0x30, archive.len() as u64 + 1).is_err());
    }

    #[test]
    fn reads_archives_nested_in_an_embedded_archive() {
        let first = leaf([1, 2, 3, 4]);
        let second = leaf([5, 6, 7, 8]);
        let archive = parent(&[(&first, Storage::Raw), (&second, Storage::Raw)]);
        let mut bytes = vec![0xEE; 0x50];
        bytes.extend_from_slice(&archive);
        let file = source(&bytes);

        let outer = file.slice(0x50, archive.len() as u64).unwrap();
        let metadata = decode(&mut outer.clone());
        let mut a = view(&outer, &metadata, 0);
        let mut b = view(&outer, &metadata, 1);
        // The views are archive-relative, not file-relative.
        assert_eq!(metadata.raw_range(0).unwrap().start, PAYLOADS as u64);
        drop((file, outer));
        let a = decode(&mut a);
        let b = decode(&mut b);
        assert_eq!(a.field(0, KEY_X).unwrap(), Some(&[1, 2, 3, 4][..]));
        assert_eq!(b.field(0, KEY_X).unwrap(), Some(&[5, 6, 7, 8][..]));
    }

    #[test]
    fn refuses_encoded_entries_as_raw_bytes() {
        let child = leaf([1, 2, 3, 4]);
        let archive = parent(&[
            (&child, Storage::Raw),
            (&child, Storage::Compressed),
            (&child, Storage::Transformed),
        ]);
        let metadata = decode(&mut source(&archive));
        assert!(metadata.raw_range(0).is_ok());
        for (row, expected) in [(1, "compressed"), (2, "behind the payload transform")] {
            match metadata.raw_range(row) {
                Err(Error::Encoded { row: r, encoding }) => {
                    assert_eq!((r, encoding), (row, expected));
                }
                other => panic!("row {row}: {other:?}"),
            }
        }
    }

    #[test]
    fn refuses_entries_outside_the_archive() {
        let child = leaf([1, 2, 3, 4]);
        let mut archive = parent(&[(&child, Storage::Raw)]);
        archive.truncate(PAYLOADS + child.len() - 1);
        let outer = source(&archive);
        let metadata = decode(&mut outer.clone());
        let reason = invalid_reason(metadata.raw_source(0, &outer, &[]));
        assert!(reason.contains("after the end of the archive"), "{reason}");
    }

    #[test]
    fn rejects_raw_entries_larger_than_their_stored_bytes() {
        let child = leaf([1, 2, 3, 4]);
        let archive = parent(&[(&child, Storage::Oversized)]);
        let metadata = decode(&mut source(&archive));
        let reason = invalid_reason(metadata.raw_range(0));
        assert!(reason.contains("exceeds its stored size"), "{reason}");
    }

    #[test]
    fn reads_the_read_source_column() {
        let child = leaf([1, 2, 3, 4]);
        let archive = parent(&[
            (&child, Storage::Raw),
            (&child, Storage::Source(u32::MAX)),
            (&child, Storage::Source(0)),
            (&child, Storage::Source(3)),
        ]);
        let metadata = decode(&mut source(&archive));
        let sources: Vec<_> = (0..4)
            .map(|row| metadata.read_source(row).unwrap())
            .collect();
        assert_eq!(sources, [None, None, Some(0), Some(3)]);
        // Without the column every row uses the main source.
        let plain = decode(&mut source(&parent(&[(&child, Storage::Raw)])));
        assert_eq!(plain.read_source(0).unwrap(), None);
    }

    #[test]
    fn alternate_sources_must_be_supplied() {
        let first = leaf([1, 2, 3, 4]);
        let second = leaf([5, 6, 7, 8]);
        let archive = parent(&[(&first, Storage::Raw), (&second, Storage::Source(1))]);
        let main = source(&archive);
        let metadata = decode(&mut main.clone());
        for alternates in [&[][..], &[Some(main.clone())]] {
            match metadata.raw_source(1, &main, alternates) {
                Err(Error::ReadSource { row: 1, index: 1 }) => {}
                other => panic!("{other:?}"),
            }
        }
        // A supplied alternate is read at the same address as the main source.
        let mut altered = archive.clone();
        let range = metadata.raw_range(1).unwrap();
        altered[range.start as usize + 0x40..range.end as usize].fill(0);
        let alternates = [Some(source(&altered)), Some(source(&archive))];
        let mut from_alternate = metadata.raw_source(1, &main, &alternates).unwrap();
        assert_eq!(
            decode(&mut from_alternate).field(0, KEY_X).unwrap(),
            Some(&[5, 6, 7, 8][..])
        );
        assert!(matches!(
            metadata.raw_source(1, &main, &alternates[..1]),
            Err(Error::ReadSource { .. })
        ));
        // The bytes come from the alternate, not from the main source.
        let both_altered = [alternates[0].clone(), alternates[0].clone()];
        let mut altered_view = metadata.raw_source(1, &main, &both_altered).unwrap();
        assert_eq!(decode(&mut altered_view).field(0, KEY_X).unwrap(), None);
        // Main-source rows ignore the alternates.
        let mut first_view = metadata.raw_source(0, &main, &alternates).unwrap();
        assert_eq!(
            decode(&mut first_view).field(0, KEY_X).unwrap(),
            Some(&[1, 2, 3, 4][..])
        );
    }
}

mod pipeline {
    //! Source, header, decoded metadata, entries, names and raw payloads,
    //! on one synthetic archive.

    use std::io::Write;

    use lforge_binary::Source;

    use super::*;
    use crate::rpf::names::{
        self, Candidate, Class, MountPrefix, RPF_TYPE, Types, Unresolved, hash64, joaat,
    };

    pub(super) const PAYLOADS: usize = 0x1000;
    const TEXTURE: u8 = 7;

    pub(super) struct Spec {
        pub(super) layout: RecordLayout,
        pub(super) payload: Vec<u8>,
        pub(super) type_id: u8,
        pub(super) mode: u8,
        pub(super) hash: Option<u64>,
        pub(super) key: Option<u32>,
        pub(super) source: Option<u32>,
        /// The chunk table value.
        pub(super) chunks: Option<Vec<u8>>,
        pub(super) transform: bool,
        /// Overrides the logical size.
        pub(super) logical: Option<u64>,
        /// Moves the payload offset this many 16-byte units further.
        pub(super) shift: u32,
    }

    pub(super) fn spec(layout: RecordLayout, payload: Vec<u8>, type_id: u8) -> Spec {
        Spec {
            layout,
            payload,
            type_id,
            mode: 0,
            hash: None,
            key: None,
            source: None,
            chunks: None,
            transform: false,
            logical: None,
            shift: 0,
        }
    }

    /// One column with a value for each row where `value` gives one.
    fn column(key: u64, width: u16, values: Vec<Option<Vec<u8>>>) -> Column {
        let elements: Vec<Vec<u8>> = values
            .iter()
            .map(|v| v.clone().unwrap_or_else(|| vec![0; usize::from(width)]))
            .collect();
        let elements: Vec<&[u8]> = elements.iter().map(Vec::as_slice).collect();
        let cells: Vec<Option<u32>> = values
            .iter()
            .enumerate()
            .map(|(n, v)| v.as_ref().map(|_| n as u32))
            .collect();
        Column::new(key, width, &elements, &cells)
    }

    pub(super) fn archive(specs: &[Spec]) -> Vec<u8> {
        archive_with(specs, Build::default())
    }

    /// Like [`archive`], with the given `A` table and `B` block.
    pub(super) fn archive_with(specs: &[Spec], build: Build) -> Vec<u8> {
        let mut data = Vec::new();
        let mut records: Vec<(RecordLayout, Vec<u8>)> = Vec::new();
        for spec in specs {
            let offset16 = ((PAYLOADS + data.len()) / 16) as u32 + spec.shift;
            let stored16 = spec.payload.len().div_ceil(16) as u32;
            let logical = spec.logical.unwrap_or(spec.payload.len() as u64);
            let (t, m) = (spec.type_id, spec.mode);
            let record = match spec.layout {
                RecordLayout::A => record_a(stored16, offset16, logical, t, m),
                RecordLayout::F => record_f(offset16.into(), stored16.into(), logical, t, m),
                RecordLayout::R => {
                    assert_eq!(logical % 16, 0);
                    record_r([logical as u32, 0, stored16, offset16], t, m)
                }
            };
            records.push((spec.layout, record));
            data.extend_from_slice(&spec.payload);
            data.resize(data.len().next_multiple_of(16), 0);
        }
        let location = |layout: RecordLayout| {
            records
                .iter()
                .map(|(l, record)| (*l == layout).then(|| record.clone()))
                .collect::<Vec<_>>()
        };
        let each =
            |value: &dyn Fn(&Spec) -> Option<Vec<u8>>| specs.iter().map(value).collect::<Vec<_>>();
        let chunk_width = specs
            .iter()
            .filter_map(|s| s.chunks.as_ref().map(Vec::len))
            .max()
            .unwrap_or(8);
        let mut bytes = build.build(&[
            column(keys::LOCATION_R, 20, location(RecordLayout::R)),
            column(keys::LOCATION_F, 24, location(RecordLayout::F)),
            column(keys::LOCATION_A, 16, location(RecordLayout::A)),
            column(
                keys::NAME_HASH,
                8,
                each(&|s| s.hash.map(|h| h.to_le_bytes().to_vec())),
            ),
            column(
                keys::NAME_KEY,
                4,
                each(&|s| s.key.map(|k| k.to_le_bytes().to_vec())),
            ),
            column(
                keys::READ_SOURCE,
                4,
                each(&|s| s.source.map(|i| i.to_le_bytes().to_vec())),
            ),
            column(
                keys::PAYLOAD_TRANSFORM,
                1,
                each(&|s| s.transform.then(|| vec![1])),
            ),
            column(
                keys::CHUNK_TABLE,
                chunk_width as u16,
                each(&|s| {
                    s.chunks.clone().map(|mut value| {
                        value.resize(chunk_width, 0);
                        value
                    })
                }),
            ),
        ]);
        assert!(bytes.len() <= PAYLOADS);
        bytes.resize(PAYLOADS, 0);
        bytes.extend_from_slice(&data);
        bytes
    }

    pub(super) fn file(bytes: &[u8]) -> Source {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        Source::from_file(file).unwrap()
    }

    #[test]
    fn a_declared_trailer_bounds_payload_reads() {
        let mut bytes = archive(&[spec(RecordLayout::A, vec![7u8; 32], RPF_TYPE)]);
        // Declare the last 16 payload bytes as a trailing region.
        bytes[0x0C..0x10].copy_from_slice(&16u32.to_le_bytes());
        let source = file(&bytes);
        let stored = Stored::read(&mut source.clone(), 1 << 20).unwrap();
        assert_eq!(stored.payload_end(), Some(bytes.len() as u64 - 16));
        let metadata = stored.decode().unwrap();
        let entry = metadata.entry(0).unwrap();
        let reason = entry.raw_source(&source, &[]).unwrap_err().to_string();
        assert!(reason.contains("trailing region"), "{reason}");
    }

    #[test]
    fn an_unaligned_trailer_start_is_rejected() {
        let mut bytes = archive(&[spec(RecordLayout::A, vec![7u8; 32], RPF_TYPE)]);
        bytes[0x0C..0x10].copy_from_slice(&15u32.to_le_bytes());
        let mut source = file(&bytes);
        let reason = invalid_reason(Stored::read(&mut source, 1 << 20));
        assert!(reason.contains("16-byte boundary"), "{reason}");
    }

    #[test]
    fn a_trailer_that_starts_inside_the_metadata_is_rejected() {
        let mut bytes = archive(&[spec(RecordLayout::A, vec![7u8; 32], RPF_TYPE)]);
        let metadata_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let trailer = u32::try_from(bytes.len() as u64 - u64::from(metadata_len) + 0x20).unwrap();
        bytes[0x0C..0x10].copy_from_slice(&trailer.to_le_bytes());
        let mut source = file(&bytes);
        let reason = invalid_reason(Stored::read(&mut source, 1 << 20));
        assert!(reason.contains("metadata end"), "{reason}");
    }

    fn nested() -> Vec<u8> {
        Build::default().build(&[Column::new(KEY_X, 4, &[&[9, 8, 7, 6]], &[Some(0)])])
    }

    fn specs() -> Vec<Spec> {
        let raw = |layout, payload: &[u8], type_id| spec(layout, payload.to_vec(), type_id);
        let dup = hash64(b"dup");
        vec![
            // 0: a nested archive.
            Spec {
                hash: Some(hash64(b"Packs/Inner")),
                ..raw(RecordLayout::A, &nested(), RPF_TYPE)
            },
            // 1: a 32-bit-class entry in an R record.
            Spec {
                key: Some(joaat(b"textures/sky")),
                ..raw(RecordLayout::R, &[0x5A; 32], TEXTURE)
            },
            // 2: compressed, in an F record.
            Spec {
                mode: 1,
                hash: Some(hash64(b"packed")),
                ..raw(RecordLayout::F, b"not really zlib", RPF_TYPE)
            },
            // 3: chunked.
            Spec {
                chunks: Some(chunk_value(8, 1, 3, &[0x0100 | (0x2345 << 16)])),
                ..raw(RecordLayout::A, &[1; 16], RPF_TYPE)
            },
            // 4: behind the payload transform.
            Spec {
                transform: true,
                ..raw(RecordLayout::A, &[2; 16], RPF_TYPE)
            },
            // 5: read through alternate source 2.
            Spec {
                source: Some(2),
                ..raw(RecordLayout::A, &[3; 16], RPF_TYPE)
            },
            // 6 and 7: the same name hash and type.
            Spec {
                hash: Some(dup),
                ..raw(RecordLayout::A, &[4; 16], RPF_TYPE)
            },
            Spec {
                hash: Some(dup),
                ..raw(RecordLayout::F, &[5; 16], RPF_TYPE)
            },
            // 8: a logical size above the stored size.
            Spec {
                logical: Some(17),
                ..raw(RecordLayout::A, &[6; 16], RPF_TYPE)
            },
            // 9: a payload offset past the end of the archive.
            Spec {
                shift: 0x10_0000,
                ..raw(RecordLayout::A, &[7; 16], RPF_TYPE)
            },
        ]
    }

    const ARCHIVE_PATH: &[u8] = b"dev:/synthetic/Packs/sample.rpf";

    #[test]
    fn reads_entries_names_and_raw_payloads() {
        let archive = archive(&specs());
        let mut bytes = vec![0xEE; 0x70];
        bytes.extend_from_slice(&archive);
        let file = file(&bytes);
        let view = file.slice(0x70, archive.len() as u64).unwrap();
        drop(file);

        let header = crate::rpf::read_header(&mut view.clone()).unwrap();
        let stored = Stored::read(&mut view.clone(), 1 << 20).unwrap();
        assert_eq!(header.toc_end(), u64::from(stored.prefix().metadata_len));
        assert!(stored.processing().is_none());
        let metadata = stored.decode().unwrap();
        let entries: Vec<Entry> = metadata.entries().collect();
        assert_eq!(entries.len(), 10);
        assert_eq!(metadata.entry(3).unwrap(), entries[3]);
        invalid_reason(metadata.entry(10));

        // Fields, as stored.
        let location = |n: usize| entries[n].location.clone().unwrap().unwrap();
        assert_eq!(location(0).layout, RecordLayout::A);
        assert_eq!(location(1).layout, RecordLayout::R);
        assert_eq!(location(2).layout, RecordLayout::F);
        assert_eq!(location(0).payload_offset, PAYLOADS as u64);
        assert_eq!(location(0).logical_len, nested().len() as u64);
        assert_eq!(location(1).stored_len, 32);
        assert_eq!((location(2).mode, entries[2].type_id()), (1, Some(0)));
        assert_eq!(entries[1].type_id(), Some(TEXTURE));
        assert_eq!(entries[1].name_hash, Ok(None));
        assert_eq!(entries[1].name_key, Ok(Some(joaat(b"textures/sky"))));
        assert_eq!(entries[3].chunks.clone().unwrap().unwrap().encoding, 3);
        assert_eq!(entries[4].payload_transform, Ok(true));
        assert_eq!(entries[5].read_source, Ok(Some(2)));
        assert_eq!(entries[0].read_source, Ok(None));

        // Names.
        let mut types = Types::default();
        types.insert_extension(b"ytd", TEXTURE);
        types.insert_class(TEXTURE, Class::Key32);
        let candidates = [
            Candidate::Path(b"dev:/synthetic/Packs/packs/inner.rpf"),
            Candidate::Path(b"dev:/synthetic/Packs/textures/sky.ytd"),
            Candidate::Path(b"dev:/synthetic/Packs/missing.rpf"),
            Candidate::Path(b"dev:/synthetic/Packs/model.ydr"),
            Candidate::Path(b"dev:/synthetic/Packs/dup.rpf"),
            Candidate::Path(b"dev:/synthetic/Packs/PACKS\\INNER.rpf"),
        ];
        let prefix = MountPrefix::from_archive_path(ARCHIVE_PATH).unwrap();
        let matches = names::match_entries(&entries, &prefix, &types, &candidates).unwrap();
        assert_eq!(matches.row(0).unwrap().candidates, [0, 5]);
        assert!(!matches.row(0).unwrap().ambiguous);
        assert_eq!(matches.row(1).unwrap().candidates, [1]);
        assert!(matches.row(3).unwrap().candidates.is_empty());
        let rows = |n: usize| matches.candidates[n].as_ref().unwrap().rows.clone();
        assert!(rows(2).is_empty());
        assert_eq!(rows(4), [6, 7]);
        assert_eq!(
            matches.candidates[3],
            Err(Unresolved::UnknownExtension(b"ydr".to_vec()))
        );
        // The same result straight from the metadata.
        let direct = names::match_candidates(&metadata, &prefix, &types, &candidates).unwrap();
        assert_eq!(direct, matches);

        // Raw payloads.
        let mut inner = entries[0].raw_source(&view, &[]).unwrap();
        let inner = Stored::read(&mut inner, 1 << 20).unwrap().decode().unwrap();
        assert_eq!(inner.field(0, KEY_X).unwrap(), Some(&[9, 8, 7, 6][..]));
        let mut sky = entries[1].raw_source(&view, &[]).unwrap();
        assert_eq!(lforge_binary::read_at(&mut sky, 0, 64).unwrap(), [0x5A; 32]);
        for (row, expected) in [
            (2, "compressed"),
            (3, "in chunks"),
            (4, "behind the payload transform"),
        ] {
            match entries[row].raw_source(&view, &[]) {
                Err(Error::Encoded { encoding, .. }) => assert_eq!(encoding, expected),
                other => panic!("row {row}: {other:?}"),
            }
        }
        for alternates in [&[][..], &[Some(view.clone()), None, None]] {
            assert!(matches!(
                entries[5].raw_source(&view, alternates),
                Err(Error::ReadSource { row: 5, index: 2 })
            ));
        }
        let alternates = [None, None, Some(view.clone())];
        let mut third = entries[5].raw_source(&view, &alternates).unwrap();
        assert_eq!(lforge_binary::read_at(&mut third, 0, 64).unwrap(), [3; 16]);
        assert!(invalid_reason(entries[8].raw_range()).contains("exceeds its stored size"));
        assert!(entries[9].raw_range().is_ok());
        let reason = invalid_reason(entries[9].raw_source(&view, &[]));
        assert!(reason.contains("after the end of the archive"), "{reason}");
    }

    #[test]
    fn distinguishes_missing_and_malformed_fields() {
        // A name hash column too narrow for a u64, and a row without any
        // location record.
        let columns = [
            Column::new(keys::NAME_HASH, 4, &[&[1, 2, 3, 4]], &[Some(0), None]),
            Column::new(
                keys::LOCATION_A,
                16,
                &[&record_a(1, 0x100, 16, 0, 0)],
                &[Some(0), None],
            ),
        ];
        let metadata = Build::default().metadata(&columns);
        let entries: Vec<Entry> = metadata.entries().collect();
        assert!(entries[0].name_hash.is_err());
        assert!(entries[0].location.as_ref().unwrap().is_some());
        assert_eq!(entries[1].name_hash, Ok(None));
        assert_eq!(entries[1].location, Ok(None));
        assert_eq!(entries[1].type_id(), None);
        assert!(invalid_reason(entries[1].raw_range()).contains("no location record"));
        // Name matching needs every row to be well formed.
        invalid_reason(names::match_entries(
            &entries,
            &MountPrefix::EMPTY,
            &Types::default(),
            &[],
        ));
    }

    #[test]
    fn processed_metadata_yields_no_entries() {
        let mut bytes = archive(&specs());
        bytes[0x2E] = 9;
        let stored = Stored::read(&mut file(&bytes), 1 << 20).unwrap();
        assert!(!stored.processing().is_none());
        assert!(matches!(
            stored.clone().decode(),
            Err(Error::Transformed(_))
        ));
        // Without a cipher source there is nothing to run the passes with.
        struct NoCiphers;
        impl transform::CipherSource for NoCiphers {
            type Block = transform::tests::Toy;
            fn static_descriptor(&self, _: u8) -> Option<(u32, transform::Block)> {
                None
            }
            fn cbc_block(&self, _: u32) -> Option<Self::Block> {
                None
            }
        }
        assert!(matches!(
            stored.transform(&NoCiphers),
            Err(Error::Cipher(transform::Error::NoStaticDescriptor(4)))
        ));
    }
}

mod probing {
    //! How much of the metadata area deciding its processing reads.

    use std::io::{Read, Seek, SeekFrom};

    use super::*;

    /// Counts the bytes read through it.
    struct Counting<R> {
        inner: R,
        read: u64,
    }

    impl<R: Read> Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read += n as u64;
            Ok(n)
        }
    }

    impl<R: Seek> Seek for Counting<R> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    fn counting(bytes: Vec<u8>) -> Counting<Cursor<Vec<u8>>> {
        Counting {
            inner: Cursor::new(bytes),
            read: 0,
        }
    }

    fn metadata(selector: u8, a_ids: Vec<u16>) -> Vec<u8> {
        let columns = [Column::new(KEY_X, 4, &[&[1, 2, 3, 4]], &[Some(0)])];
        Build {
            selector,
            a_ids,
            ..Build::default()
        }
        .build(&columns)
    }

    /// The metadata followed by payload bytes.
    fn archive(metadata: &[u8]) -> Vec<u8> {
        let mut bytes = metadata.to_vec();
        bytes.resize(bytes.len() + 0x1000, 0xAB);
        bytes
    }

    #[test]
    fn the_static_pass_is_decided_from_the_header() {
        let metadata = metadata(9, vec![2, 3, 4, 6]);
        let mut source = counting(archive(&metadata));
        let probe = Stored::probe(&mut source).unwrap();
        assert_eq!(source.read, HEADER_LEN as u64);
        let stored = Stored::from_bytes(metadata).unwrap();
        assert_eq!(probe.processing, stored.processing());
        assert_eq!(probe.processing.archive_pass, None);
        assert_eq!(&probe.layout, stored.layout());
        assert_eq!(probe.archive_descriptor, None);
    }

    #[test]
    fn selector_zero_needs_the_a_table() {
        let metadata = metadata(0, vec![2, 3, 6]);
        let mut source = counting(archive(&metadata));
        let probe = Stored::probe(&mut source).unwrap();
        assert_eq!(source.read, (HEADER_LEN + 3 * 8) as u64);
        let stored = Stored::from_bytes(metadata).unwrap();
        assert_eq!(probe.processing, stored.processing());
        assert!(probe.processing.is_none());
        // The stored bytes may be usable, so they are read in full.
        assert!(stored.decode().is_ok());
    }

    #[test]
    fn selector_zero_with_an_archive_descriptor() {
        let mut metadata = metadata(0, vec![1, 2, 6]);
        let b = Stored::from_bytes(metadata.clone())
            .unwrap()
            .layout()
            .b_block
            .start;
        set_u32(&mut metadata, b, 0x77);
        set_u16(&mut metadata, b + 4, 16);
        metadata[b + 6..b + 22].fill(0x96);
        let mut source = counting(archive(&metadata));
        let probe = Stored::probe(&mut source).unwrap();
        assert_eq!(
            source.read,
            (HEADER_LEN + 3 * 8 + transform::CipherDescriptor::LEN) as u64
        );
        assert_eq!(
            probe.processing,
            Processing {
                static_pass: false,
                archive_pass: Some(true),
            }
        );
        let descriptor = probe.archive_descriptor.unwrap();
        assert_eq!((descriptor.key_id, descriptor.kind), (0x77, 16));

        // A sub-block 1 outside the metadata area is not read.
        set_u32(&mut metadata, 0x40 + 4, 0xFFFF_0000);
        let mut source = counting(archive(&metadata));
        let probe = Stored::probe(&mut source).unwrap();
        assert_eq!(probe.processing.archive_pass, Some(true));
        assert_eq!(probe.archive_descriptor, None);
        assert_eq!(source.read, (HEADER_LEN + 3 * 8) as u64);
    }

    /// Zeros of any length behind a header.
    struct Sparse {
        header: Vec<u8>,
        len: u64,
        pos: u64,
    }

    impl Read for Sparse {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf
                .len()
                .min(usize::try_from(self.len.saturating_sub(self.pos)).unwrap_or(usize::MAX));
            for (i, byte) in buf[..n].iter_mut().enumerate() {
                let at = self.pos as usize + i;
                *byte = self.header.get(at).copied().unwrap_or(0);
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
    fn a_large_declared_metadata_area_is_not_read() {
        let len = 0x7000_0000u32;
        let mut header = vec![0u8; HEADER_LEN];
        header[..4].copy_from_slice(&MAGIC);
        set_u32(&mut header, 4, len);
        set_u32(&mut header, 8, len);
        header[0x2C] = 1;
        header[0x2D] = 1;
        header[0x2E] = 9;
        let sparse = |header: &[u8]| Counting {
            inner: Sparse {
                header: header.to_vec(),
                len: u64::from(len) + 0x40,
                pos: 0,
            },
            read: 0,
        };
        let mut source = sparse(&header);
        let probe = Stored::probe(&mut source).unwrap();
        assert!(probe.processing.static_pass);
        assert_eq!(source.read, HEADER_LEN as u64);
        // Reading it in full stops at the limit, after the header.
        let mut source = sparse(&header);
        assert!(matches!(
            Stored::read(&mut source, 1 << 20),
            Err(Error::TooLarge { .. })
        ));
        assert_eq!(source.read, HEADER_LEN as u64);
        // With selector 0 only the A table is read in addition.
        header[0x2E] = 0;
        let mut source = sparse(&header);
        assert!(Stored::probe(&mut source).unwrap().processing.is_none());
        assert_eq!(source.read, HEADER_LEN as u64);
    }

    #[test]
    fn describes_the_passes_without_calling_all_of_them_encryption() {
        let probe = |metadata: Vec<u8>| Stored::probe(&mut counting(archive(&metadata))).unwrap();
        let reason = |metadata| probe(metadata).unsupported();
        // Static descriptor 4 has cipher type 16, 1 has type 3, others type 0.
        for (selector, expected) in [
            (
                9,
                "it is encrypted: the static pass decrypts it with cipher type 16",
            ),
            (
                3,
                "it is encrypted: the static pass decrypts it with cipher type 3",
            ),
            (1, "a no-op cipher"),
            (5, "a no-op cipher"),
        ] {
            let text = reason(metadata(selector, vec![2, 3, 4, 6])).unwrap();
            assert!(text.contains(expected), "{selector}: {text}");
        }
        assert!(!reason(metadata(1, vec![2])).unwrap().contains("encrypted"));
        assert_eq!(reason(metadata(0, vec![2, 3, 6])), None);

        let with_descriptor = |kind: u16| {
            let mut metadata = metadata(0, vec![1, 2, 6]);
            set_u16(&mut metadata, 0x60 + 4, kind);
            metadata
        };
        for (kind, expected) in [
            (
                16,
                "it is encrypted: the archive pass decrypts it with cipher type 16",
            ),
            (
                0,
                "the archive pass processes it with cipher type 0, a no-op cipher",
            ),
            (2, "algorithm 0x2, which is not supported"),
            (13, "invalid cipher type 13"),
        ] {
            let text = reason(with_descriptor(kind)).unwrap();
            assert!(text.contains(expected), "{kind}: {text}");
        }
    }

    #[test]
    fn malformed_and_truncated_headers_are_errors() {
        let metadata = metadata(9, vec![2, 3, 4, 6]);
        let mut truncated = counting(metadata[..0x20].to_vec());
        assert!(matches!(Stored::probe(&mut truncated), Err(Error::Io(_))));
        // The metadata area ends after the end of the data.
        let short = counting(metadata[..metadata.len() - 1].to_vec());
        let reason = invalid_reason(Stored::probe(&mut { short }));
        assert!(reason.contains("end of the file"), "{reason}");
        let mut bad = metadata.clone();
        bad[0x2C] = 3;
        assert!(invalid_reason(Stored::probe(&mut counting(bad))).contains("index width"));
        let mut not_rpf = metadata.clone();
        not_rpf[0] = 0;
        invalid_reason(Stored::probe(&mut counting(not_rpf)));
        // Regions outside their areas fail like a full read.
        let mut regions = metadata;
        set_u16(&mut regions, 0x20, 40);
        let reason = invalid_reason(Stored::probe(&mut counting(regions)));
        assert!(reason.contains("primary regions"), "{reason}");
    }
}

mod decoding {
    //! Entry contents: stored, raw DEFLATE and chunked.

    use std::io::{self, Read, Seek, SeekFrom, Write};

    use flate2::Compression;
    use flate2::write::{DeflateEncoder, ZlibEncoder};
    use lforge_binary::Source;

    use super::pipeline::{Spec, archive, file, spec};
    use super::*;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Compressible, but not trivially.
    fn data(len: usize, seed: u32) -> Vec<u8> {
        (0..len as u32)
            .map(|i| ((i / 7 + seed) % 251) as u8 ^ (i % 3) as u8)
            .collect()
    }

    /// One chunk table entry in `encoding`.
    fn chunk_entry(
        encoding: u8,
        logical: usize,
        compressed: usize,
        stored: usize,
        method: u8,
    ) -> u64 {
        let padding = (stored - compressed) as u64;
        let method = u64::from(method);
        match encoding {
            2 => {
                assert_eq!(logical % 16, 0);
                (logical / 16) as u64 | ((stored / 16) as u64) << 32 | padding << 58 | method << 62
            }
            3 => {
                let field = (0x10000 - compressed) as u64;
                assert_eq!(field & 0xF, padding);
                ((0x10000 - logical) as u64 & 0xFFFF) | (field & 0xFFFF) << 16 | method << 60
            }
            4 => logical as u64 | ((stored / 16) as u64) << 28 | padding << 52 | method << 56,
            _ => unreachable!(),
        }
    }

    /// Stored chunks, the chunk table value and the contents. Method 3
    /// chunks hold a zlib stream, the others a copy. Padding is nonzero.
    fn chunked(encoding: u8, chunks: &[(u8, Vec<u8>)]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut stored = Vec::new();
        if encoding == 2 {
            // Encoding 2 reserves 16 bytes before the first chunk.
            stored.resize(16, 0);
        }
        let mut entries = Vec::new();
        let mut contents = Vec::new();
        for (method, data) in chunks {
            let compressed = if *method == 3 {
                zlib(data)
            } else {
                data.clone()
            };
            let stored_len = compressed.len().next_multiple_of(16);
            stored.extend_from_slice(&compressed);
            stored.resize(stored.len() + stored_len - compressed.len(), 0xA5);
            entries.push(chunk_entry(
                encoding,
                data.len(),
                compressed.len(),
                stored_len,
                *method,
            ));
            contents.extend_from_slice(data);
        }
        let table = chunk_value(8, entries.len() as u16, encoding, &entries);
        (stored, table, contents)
    }

    fn chunked_spec(stored: Vec<u8>, table: Vec<u8>, logical: usize) -> Spec {
        Spec {
            chunks: Some(table),
            logical: Some(logical as u64),
            ..spec(RecordLayout::A, stored, 0)
        }
    }

    fn open(specs: &[Spec]) -> (Source, Vec<Entry>) {
        let source = file(&archive(specs));
        let metadata = Stored::read(&mut source.clone(), 1 << 20)
            .unwrap()
            .decode()
            .unwrap();
        (source, metadata.entries().collect())
    }

    fn contents(entry: &Entry, source: &Source) -> io::Result<Vec<u8>> {
        let mut payload = entry.payload(source, &[]).map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        payload.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn invalid_data(result: io::Result<Vec<u8>>) -> String {
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        err.to_string()
    }

    #[test]
    fn decodes_stored_and_raw_deflate_entries() {
        let plain = data(5000, 1);
        let big = data(200_000, 2);
        let (source, entries) = open(&[
            spec(RecordLayout::A, plain.clone(), 0),
            Spec {
                mode: 1,
                logical: Some(big.len() as u64),
                ..spec(RecordLayout::F, deflate(&big), 0)
            },
        ]);
        assert_eq!(contents(&entries[0], &source).unwrap(), plain);
        assert_eq!(contents(&entries[1], &source).unwrap(), big);
        let mut payload = entries[1].payload(&source, &[]).unwrap();
        assert_eq!(payload.len(), big.len() as u64);
        // Forward and backward seeks restart or continue the stream.
        for pos in [150_000u64, 10, 199_990, 0] {
            payload.seek(SeekFrom::Start(pos)).unwrap();
            let mut buf = [0; 10];
            payload.read_exact(&mut buf).unwrap();
            assert_eq!(buf, big[pos as usize..pos as usize + 10], "{pos}");
        }
    }

    #[test]
    fn rejects_bad_raw_deflate_entries() {
        let big = data(100_000, 3);
        let stream = deflate(&big);
        let with = |payload: Vec<u8>, logical: usize| Spec {
            mode: 1,
            logical: Some(logical as u64),
            ..spec(RecordLayout::A, payload, 0)
        };
        let (source, entries) = open(&[
            // A zlib header and trailer are not raw DEFLATE.
            with(zlib(&big), big.len()),
            with(stream.clone(), big.len() - 1),
            with(stream.clone(), big.len() + 1),
            with(stream[..stream.len() / 2].to_vec(), big.len()),
            // Ten megabytes of zeros declared as 1000 bytes.
            with(deflate(&vec![0; 10_000_000]), 1000),
        ]);
        invalid_data(contents(&entries[0], &source));
        assert!(invalid_data(contents(&entries[1], &source)).contains("more than the declared"));
        assert!(invalid_data(contents(&entries[2], &source)).contains("ends after"));
        assert!(invalid_data(contents(&entries[3], &source)).contains("ends before"));
        assert!(invalid_data(contents(&entries[4], &source)).contains("more than the declared"));
    }

    #[test]
    fn refuses_unsupported_modes() {
        let (source, entries) = open(&[
            Spec {
                mode: 2,
                ..spec(RecordLayout::A, vec![1; 16], 0)
            },
            Spec {
                mode: 5,
                ..spec(RecordLayout::A, vec![1; 16], 0)
            },
            Spec {
                mode: 1,
                transform: true,
                ..spec(RecordLayout::A, deflate(b"x"), 0)
            },
        ]);
        for (row, expected) in [(0, "mode 2 fails"), (1, "mode 5 has no known codec")] {
            match entries[row].payload(&source, &[]) {
                Err(Error::Undecodable { reason, .. }) => {
                    assert!(reason.contains(expected), "{reason}")
                }
                other => panic!("row {row}: {:?}", other.map(|p| p.len())),
            }
        }
        assert!(matches!(
            entries[2].payload(&source, &[]),
            Err(Error::Encoded {
                encoding: "behind the payload transform",
                ..
            })
        ));
    }

    #[test]
    fn decodes_chunk_encodings_and_methods() {
        let cases = [
            (
                2,
                vec![
                    (3, data(0x10000, 4)),
                    (0, data(32, 5)),
                    (1, data(48, 6)),
                    (2, data(16, 7)),
                    (3, data(0x2000, 8)),
                ],
            ),
            (
                3,
                vec![
                    (3, data(0x10000, 9)),
                    (3, data(0x8000, 10)),
                    (0, data(0x100, 11)),
                ],
            ),
            (
                4,
                vec![
                    (3, data(1000, 12)),
                    (0, data(100, 13)),
                    (3, data(70_000, 14)),
                ],
            ),
        ];
        for (encoding, chunks) in cases {
            let (stored, table, expected) = chunked(encoding, &chunks);
            // With a chunk table the entry's mode does not pick the decoder.
            let row = Spec {
                mode: 5,
                ..chunked_spec(stored, table, expected.len())
            };
            let (source, entries) = open(&[row]);
            assert_eq!(
                contents(&entries[0], &source).unwrap(),
                expected,
                "encoding {encoding}"
            );
        }
    }

    #[test]
    fn encoding_2_chunks_start_after_a_stored_prefix() {
        let first = data(0x100, 30);
        let second = data(0x80, 31);
        let (mut stored, table, expected) = chunked(2, &[(3, first), (3, second)]);
        // Only the prefix length is part of the container; its bytes are not
        // required to be zero.
        stored[..16].fill(0x5A);
        let (source, entries) = open(&[chunked_spec(stored, table, expected.len())]);
        assert_eq!(contents(&entries[0], &source).unwrap(), expected);
        // The second chunk starts one logical chunk later, not one stored
        // chunk later.
        let mut payload = entries[0].payload(&source, &[]).unwrap();
        payload.seek(SeekFrom::Start(0x100)).unwrap();
        let mut buf = [0; 8];
        payload.read_exact(&mut buf).unwrap();
        assert_eq!(buf, expected[0x100..0x108]);
    }

    #[test]
    fn rejects_encoding_2_rows_without_room_for_the_prefix() {
        let entry = chunk_entry(2, 16, 16, 16, 0);
        let table = ChunkTable {
            encoding: 2,
            chunks: vec![Chunk::decode(entry, 2).unwrap()],
        };
        for stored_len in [0, 8, 15] {
            let stored = file(&vec![0; stored_len]);
            let reason = invalid_reason(Payload::chunked(
                0,
                super::payload::PayloadSource::plain(stored),
                16,
                &table,
            ));
            assert!(reason.contains("stored prefix"), "{stored_len}: {reason}");
        }
    }

    #[test]
    fn encoding_4_chunks_start_after_a_stored_prefix_when_the_sizes_leave_one() {
        let first = data(0x120, 40);
        let second = data(0x80, 41);
        let (stored, table, expected) = chunked(4, &[(3, first), (3, second)]);
        // Without a stored prefix, the chunks start at the payload offset.
        let (source, entries) =
            open(&[chunked_spec(stored.clone(), table.clone(), expected.len())]);
        assert_eq!(contents(&entries[0], &source).unwrap(), expected);

        // A 16-byte stored prefix leaves the chunk sizes 16 bytes short of the
        // entry's stored size. Only the length is part of the container.
        let mut prefixed = vec![0u8; 16];
        prefixed.extend(stored);
        prefixed[..16].fill(0x5A);
        let (source, entries) = open(&[chunked_spec(prefixed, table, expected.len())]);
        assert_eq!(contents(&entries[0], &source).unwrap(), expected);
    }

    #[test]
    fn rejects_encoding_4_rows_with_an_unknown_stored_prefix() {
        let (stored, table, expected) = chunked(4, &[(3, data(0x80, 42))]);
        let mut prefixed = vec![0u8; 32];
        prefixed.extend(stored);
        let (source, entries) = open(&[chunked_spec(prefixed, table, expected.len())]);
        let reason = match entries[0].payload(&source, &[]) {
            Err(Error::Invalid(reason)) => reason,
            other => panic!("{:?}", other.map(|p| p.len())),
        };
        assert!(reason.contains("32-byte stored prefix"), "{reason}");
    }

    #[test]
    fn decodes_encoding_4_with_every_chunk_method_and_a_mid_stream_copy() {
        let chunks = [
            (3, data(0x1000, 50)),
            (0, data(0x30, 51)),
            (1, data(0x20, 52)),
            (2, data(0x40, 53)),
            (3, data(0x2000, 54)),
            (0, data(0x18, 55)),
            (3, data(0x400, 56)),
        ];
        let (mut stored, table, expected) = chunked(4, &chunks);
        let mut prefixed = vec![0u8; 16];
        prefixed.append(&mut stored);
        let (source, entries) = open(&[chunked_spec(prefixed, table, expected.len())]);
        assert_eq!(contents(&entries[0], &source).unwrap(), expected);
    }

    #[test]
    fn rejects_encoding_4_streams_with_a_bad_checksum() {
        let original = data(0x2000, 57);
        let mut stream = zlib(&original);
        *stream.last_mut().unwrap() ^= 1;
        let stored_len = stream.len().next_multiple_of(16);
        let mut stored = vec![0u8; 16];
        stored.extend_from_slice(&stream);
        stored.resize(16 + stored_len, 0xA5);
        let entry = chunk_entry(4, original.len(), stream.len(), stored_len, 3);
        let table = chunk_value(8, 1, 4, &[entry]);
        let (source, entries) = open(&[chunked_spec(stored, table, original.len())]);
        let message = invalid_data(contents(&entries[0], &source));
        assert!(message.contains("invalid"), "{message}");
    }

    #[test]
    fn rejects_truncated_encoding_4_stored_chunks() {
        let (stored, table, expected) = chunked(4, &[(3, data(0x100, 58)), (3, data(0x80, 59))]);
        let (source, entries) = open(&[chunked_spec(
            stored[..stored.len() - 16].to_vec(),
            table,
            expected.len(),
        )]);
        let reason = match entries[0].payload(&source, &[]) {
            Err(Error::Invalid(reason)) => reason,
            other => panic!("{:?}", other.map(|p| p.len())),
        };
        assert!(reason.contains("more than its"), "{reason}");
    }

    #[test]
    fn rejects_an_encoding_4_chunk_that_produces_excess_output() {
        let original = data(0x200, 60);
        let stream = zlib(&original);
        let stored_len = stream.len().next_multiple_of(16);
        let mut stored = vec![0u8; 16];
        stored.extend_from_slice(&stream);
        stored.resize(16 + stored_len, 0u8);
        // The chunk declares half the bytes the stream holds.
        let entry = chunk_entry(4, 0x100, stream.len(), stored_len, 3);
        let table = chunk_value(8, 1, 4, &[entry]);
        let (source, entries) = open(&[chunked_spec(stored, table, 0x100)]);
        let message = invalid_data(contents(&entries[0], &source));
        assert!(message.contains("more than the declared"), "{message}");
    }

    #[test]
    fn decodes_a_short_encoding_4_copy_chunk() {
        let payload = data(15, 61);
        let (stored, table, expected) = chunked(4, &[(0, payload)]);
        let (source, entries) = open(&[chunked_spec(stored, table, expected.len())]);
        assert_eq!(contents(&entries[0], &source).unwrap(), expected);
    }

    #[test]
    fn rejects_invalid_encoding_2_streams() {
        let original = data(0x2000, 32);
        let mut stream = zlib(&original);
        *stream.last_mut().unwrap() ^= 1;
        let stored_len = stream.len().next_multiple_of(16);
        let mut stored = vec![0; 16];
        stored.extend_from_slice(&stream);
        stored.resize(16 + stored_len, 0xA5);
        let entry = chunk_entry(2, original.len(), stream.len(), stored_len, 3);
        let table = chunk_value(8, 1, 2, &[entry]);
        let (source, entries) = open(&[chunked_spec(stored, table, original.len())]);
        let message = invalid_data(contents(&entries[0], &source));
        assert!(message.contains("invalid"), "{message}");
    }

    #[test]
    fn reads_chunked_entries_at_any_position() {
        let chunks = [
            (3, data(0x1000, 15)),
            (0, data(0x30, 16)),
            (3, data(0x3000, 17)),
            (2, data(0x20, 18)),
            (3, data(0x800, 19)),
        ];
        let (stored, table, expected) = chunked(2, &chunks);
        let (source, entries) = open(&[chunked_spec(stored, table, expected.len())]);
        let mut payload = entries[0].payload(&source, &[]).unwrap();
        // Forward and backward, across chunk boundaries.
        for (pos, len) in [
            (0x0FF0, 0x60),
            (0x4000, 0x80),
            (0x10, 0x20),
            (0x1028, 0x10),
            (0x4020, 0x830),
            (0x0, 0x1000),
            (expected.len() as u64 - 5, 5),
        ] {
            payload.seek(SeekFrom::Start(pos)).unwrap();
            let mut buf = vec![0; len];
            payload.read_exact(&mut buf).unwrap();
            assert_eq!(buf, expected[pos as usize..pos as usize + len], "{pos:#x}");
        }
        assert_eq!(
            payload.seek(SeekFrom::End(0)).unwrap(),
            expected.len() as u64
        );
        assert_eq!(payload.read(&mut [0; 4]).unwrap(), 0);
        assert!(
            payload
                .seek(SeekFrom::Current(-(expected.len() as i64) - 1))
                .is_err()
        );
        // Independent payloads keep their own positions.
        let mut other = entries[0].payload(&source, &[]).unwrap();
        let mut first = [0; 4];
        other.read_exact(&mut first).unwrap();
        assert_eq!(first, expected[..4]);
    }

    #[test]
    fn later_chunks_do_not_decode_earlier_ones() {
        let chunks = [(3, data(0x1000, 20)), (3, data(0x1000, 21))];
        let (mut stored, table, expected) = chunked(4, &chunks);
        // Damage the first zlib stream.
        stored[2..10].fill(0xFF);
        let (source, entries) = open(&[chunked_spec(stored, table, expected.len())]);
        let mut payload = entries[0].payload(&source, &[]).unwrap();
        payload.seek(SeekFrom::Start(0x1000)).unwrap();
        let mut second = vec![0; 0x1000];
        payload.read_exact(&mut second).unwrap();
        assert_eq!(second, expected[0x1000..]);
        payload.seek(SeekFrom::Start(0)).unwrap();
        assert!(payload.read_exact(&mut [0; 16]).is_err());
    }

    #[test]
    fn rejects_bad_zlib_chunks() {
        let original = data(0x2000, 22);
        let stream = zlib(&original);
        // The Adler-32 trailer.
        let mut checksum = stream.clone();
        *checksum.last_mut().unwrap() ^= 1;
        // A stream followed by bytes it does not use.
        let mut trailing = stream.clone();
        trailing.extend_from_slice(&[0; 7]);
        let cases: [(Vec<u8>, usize, &str); 4] = [
            (checksum, original.len(), "invalid"),
            (trailing, original.len(), "of its"),
            (stream.clone(), original.len() - 1, "more than the declared"),
            (stream, original.len() + 1, "ends after"),
        ];
        for (compressed, logical, expected) in cases {
            let stored_len = compressed.len().next_multiple_of(16);
            let mut stored = compressed.clone();
            stored.resize(stored_len, 0xA5);
            let entry = chunk_entry(4, logical, compressed.len(), stored_len, 3);
            let table = chunk_value(8, 1, 4, &[entry]);
            let (source, entries) = open(&[chunked_spec(stored, table, logical)]);
            let message = invalid_data(contents(&entries[0], &source));
            assert!(message.contains(expected), "{expected}: {message}");
        }
    }

    #[test]
    fn rejects_inconsistent_chunk_tables() {
        let copy = data(0x40, 23);
        let (stored, table, expected) = chunked(4, &[(0, copy)]);
        let reason = |spec: Spec| {
            let (source, entries) = open(&[spec]);
            match entries[0].payload(&source, &[]) {
                Err(Error::Invalid(reason)) => reason,
                other => panic!("{:?}", other.map(|p| p.len())),
            }
        };
        // A copy chunk whose stored bytes differ from its logical size.
        let wrong_copy = chunk_value(8, 1, 4, &[chunk_entry(4, 0x30, 0x40, 0x40, 1)]);
        let message = reason(chunked_spec(stored.clone(), wrong_copy, 0x30));
        assert!(message.contains("is copied"), "{message}");
        // More padding than stored bytes.
        let padded = chunk_value(8, 1, 2, &[0x4 | (0xFu64 << 58) | (3u64 << 62)]);
        let message = reason(chunked_spec(stored.clone(), padded, 0x40));
        assert!(message.contains("more padding"), "{message}");
        // Sums against the entry's sizes.
        let message = reason(chunked_spec(
            stored.clone(),
            table.clone(),
            expected.len() + 1,
        ));
        assert!(message.contains("logical size"), "{message}");
        let big = chunk_value(8, 1, 4, &[chunk_entry(4, 0x40, 0x40, 0x40, 0)]);
        let message = reason(chunked_spec(vec![0; 0x20], big, 0x40));
        assert!(message.contains("more than its"), "{message}");
        // An encoding-2 chunk table whose spans and prefix exceed the stored
        // range.
        let big = chunk_value(8, 1, 2, &[chunk_entry(2, 0x40, 0x40, 0x40, 0)]);
        let message = reason(chunked_spec(vec![0; 0x30], big, 0x40));
        assert!(message.contains("more than its"), "{message}");
        // A table whose entries lie outside the pool, or with an encoding
        // that is not 2, 3 or 4.
        for table in [
            chunk_value(8, 100, 4, &[0]),
            chunk_value(8, 100, 2, &[0]),
            chunk_value(8, 1, 9, &[0]),
        ] {
            let message = reason(chunked_spec(stored.clone(), table, 0x40));
            assert!(message.contains("malformed chunk table"), "{message}");
        }
    }

    #[test]
    fn uses_the_read_source_and_archive_bounds() {
        let big = data(50_000, 24);
        let (stored, table, expected) = chunked(4, &[(3, big.clone())]);
        let (source, entries) = open(&[
            Spec {
                source: Some(1),
                ..chunked_spec(stored.clone(), table.clone(), expected.len())
            },
            Spec {
                shift: 0x10_0000,
                ..chunked_spec(stored, table, expected.len())
            },
        ]);
        assert!(matches!(
            entries[0].payload(&source, &[]),
            Err(Error::ReadSource { row: 0, index: 1 })
        ));
        let alternates = [None, Some(source.clone())];
        let mut payload = entries[0].payload(&source, &alternates).unwrap();
        let mut bytes = Vec::new();
        payload.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, big);
        let reason = invalid_reason(entries[1].payload(&source, &[]));
        assert!(reason.contains("after the end"), "{reason}");
    }

    #[test]
    fn decoded_entries_hold_nested_archives() {
        // A 16-byte column keeps the nested archive a multiple of 16 bytes,
        // which encoding 2 requires.
        let value = [4u8, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let inner = Build::default().build(&[Column::new(KEY_X, 16, &[&value], &[Some(0)])]);
        let (stored, table, expected) = chunked(3, &[(3, inner.clone())]);
        let (stored_2, table_2, expected_2) = chunked(2, &[(3, inner.clone())]);
        let (source, entries) = open(&[
            Spec {
                mode: 1,
                logical: Some(inner.len() as u64),
                ..spec(RecordLayout::A, deflate(&inner), 0)
            },
            chunked_spec(stored, table, expected.len()),
            chunked_spec(stored_2, table_2, expected_2.len()),
        ]);
        for entry in &entries {
            let bytes = contents(entry, &source).unwrap();
            let nested = Stored::from_bytes(bytes).unwrap().decode().unwrap();
            assert_eq!(nested.field(0, KEY_X).unwrap(), Some(&value[..]));
        }
    }

    #[test]
    fn partial_reads_verify_the_whole_zlib_chunk() {
        // Buffered and streamed chunk sizes.
        for len in [0x3000, 0x20_0000] {
            let original = data(len, 25);
            let next = data(0x100, 26);
            let (mut stored, table, expected) = chunked(4, &[(3, original.clone()), (3, next)]);
            // The Adler-32 trailer of the first chunk.
            let trailer = zlib(&original).len() - 1;
            stored[trailer] ^= 1;
            let (source, entries) = open(&[chunked_spec(stored, table, expected.len())]);
            let mut payload = entries[0].payload(&source, &[]).unwrap();
            // The first bytes of the damaged chunk are not returned.
            let err = payload.read(&mut [0; 16]).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{len:#x}");
            payload.seek(SeekFrom::Start(len as u64 / 2)).unwrap();
            assert!(payload.read(&mut [0; 16]).is_err(), "{len:#x}");
            // The intact chunk after it still reads.
            payload.seek(SeekFrom::Start(len as u64)).unwrap();
            let mut tail = vec![0; 0x100];
            payload.read_exact(&mut tail).unwrap();
            assert_eq!(tail, expected[len..]);
        }
    }

    #[test]
    fn large_zlib_chunks_read_at_any_position() {
        let original = data(0x30_0000, 27);
        let (stored, table, expected) = chunked(4, &[(3, original)]);
        let (source, entries) = open(&[chunked_spec(stored, table, expected.len())]);
        let mut payload = entries[0].payload(&source, &[]).unwrap();
        for pos in [0x28_0000u64, 0x10, 0x2F_FFF0, 0x10_0000] {
            payload.seek(SeekFrom::Start(pos)).unwrap();
            let mut buf = [0; 16];
            payload.read_exact(&mut buf).unwrap();
            assert_eq!(buf, expected[pos as usize..pos as usize + 16], "{pos:#x}");
        }
    }

    #[test]
    fn returned_bytes_are_the_verified_bytes() {
        let temp = tempfile::tempdir().unwrap();
        for len in [0x8000, 0x18_0000] {
            let original = data(len, 28);
            let (stored, table, expected) = chunked(4, &[(3, original)]);
            let bytes = archive(&[chunked_spec(stored, table, expected.len())]);
            let path = temp.path().join(format!("{len}.rpf"));
            std::fs::write(&path, &bytes).unwrap();
            let source = Source::open(&path).unwrap();
            let metadata = Stored::read(&mut source.clone(), 1 << 20)
                .unwrap()
                .decode()
                .unwrap();
            let entry = metadata.entry(0).unwrap();
            let mut payload = entry.payload(&source, &[]).unwrap();
            let mut head = [0; 16];
            payload.read_exact(&mut head).unwrap();
            assert_eq!(head, expected[..16]);

            // The stored chunk changes on disk after it was verified.
            let range = entry.location.clone().unwrap().unwrap();
            let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.seek(SeekFrom::Start(range.payload_offset + 8))
                .unwrap();
            file.write_all(&[0xFF; 64]).unwrap();
            file.sync_all().unwrap();
            drop(file);

            // The rest of the chunk is what was verified, not re-decoded.
            let mut rest = Vec::new();
            payload.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, expected[16..], "{len:#x}");
            // A new reader sees the damage.
            let mut fresh = entry.payload(&source, &[]).unwrap();
            assert!(fresh.read(&mut [0; 16]).is_err(), "{len:#x}");
        }
    }

    #[test]
    fn decoding_a_chunk_can_be_cancelled() {
        let original = data(0x20_0000, 29);
        let (stored, table, expected) = chunked(4, &[(3, original)]);
        let (source, entries) = open(&[chunked_spec(stored, table, expected.len())]);
        let mut payload = entries[0].payload(&source, &[]).unwrap();
        let cancel = std::sync::atomic::AtomicBool::new(true);
        let err = payload.read_cancellable(&mut [0; 16], &cancel).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Interrupted);
        // Nothing half-decoded is kept.
        cancel.store(false, std::sync::atomic::Ordering::Relaxed);
        let mut head = [0; 16];
        assert_eq!(payload.read_cancellable(&mut head, &cancel).unwrap(), 16);
        assert_eq!(head, expected[..16]);
    }
}

mod companions {
    //! `B` sub-block 3 and companion files, on synthetic archives.

    use std::fs;
    use std::io::{Read, Write};
    use std::path::Path;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::pipeline::{Spec, archive_with, spec};
    use super::*;
    use crate::rpf::metadata::companion::MAGIC;

    const B_LEN: u32 = 0x600;

    /// The `B` block offset of sub-block 3 with the default `A` table,
    /// whose second record is ID 3.
    const SUB_BLOCK: usize = 0x20;

    fn record(name: &[u8], identifier: u64) -> Vec<u8> {
        let mut record = vec![0; 0x108];
        record[..name.len()].copy_from_slice(name);
        record[0x100..].copy_from_slice(&identifier.to_le_bytes());
        record
    }

    /// An archive with `records` in sub-block 3.
    fn archive(specs: &[Spec], records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = archive_with(
            specs,
            Build {
                b_len: B_LEN,
                ..Build::default()
            },
        );
        let b = Stored::read(&mut Cursor::new(&bytes), 1 << 20)
            .unwrap()
            .layout()
            .b_block
            .start;
        let at = b + SUB_BLOCK;
        set_u32(&mut bytes, at, records.len() as u32);
        bytes[at + 4..at + 8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        for (n, record) in records.iter().enumerate() {
            let start = at + 8 + n * 0x108;
            bytes[start..start + 0x108].copy_from_slice(record);
        }
        bytes
    }

    fn metadata(bytes: &[u8]) -> Metadata {
        Stored::read(&mut Cursor::new(bytes), 1 << 20)
            .unwrap()
            .decode()
            .unwrap()
    }

    fn companion(identifier: u64, rest: &[u8]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&identifier.to_le_bytes());
        bytes.extend_from_slice(rest);
        bytes
    }

    fn status(statuses: &[CompanionStatus]) -> Vec<&'static str> {
        statuses
            .iter()
            .map(|status| match status {
                CompanionStatus::Available(_) => "available",
                CompanionStatus::Missing(_) => "missing",
                CompanionStatus::Invalid(_) => "invalid",
                CompanionStatus::Unsupported(_) => "unsupported",
            })
            .collect()
    }

    fn reason(status: &CompanionStatus) -> &str {
        match status {
            CompanionStatus::Available(_) => "available",
            CompanionStatus::Missing(reason)
            | CompanionStatus::Invalid(reason)
            | CompanionStatus::Unsupported(reason) => reason,
        }
    }

    #[test]
    fn parses_sub_block_3() {
        let mut unterminated = record(&[b'x'; 0x100], 3);
        unterminated[0x100..].copy_from_slice(&3u64.to_le_bytes());
        let bytes = archive(
            &[spec(RecordLayout::A, vec![1; 16], 0)],
            &[
                record(b"first.dat", 0x1122_3344_5566_7788),
                record(b"sub/second.dat", 2),
                unterminated,
            ],
        );
        let companions = metadata(&bytes).companions().unwrap();
        assert_eq!(companions.unknown_04, [0xDE, 0xAD, 0xBE, 0xEF]);
        let records = &companions.records;
        assert_eq!(records.len(), 3);
        assert_eq!(
            (
                records[0].index,
                records[0].name.as_slice(),
                records[0].identifier
            ),
            (0, &b"first.dat"[..], 0x1122_3344_5566_7788)
        );
        assert_eq!((records[1].index, records[1].terminated), (1, true));
        assert_eq!(
            (records[2].name.len(), records[2].terminated),
            (0x100, false)
        );

        // Without sub-block 3 there are no companions.
        let without = archive_with(
            &[spec(RecordLayout::A, vec![1; 16], 0)],
            Build {
                a_ids: vec![2, 4, 6],
                ..Build::default()
            },
        );
        assert_eq!(
            metadata(&without).companions().unwrap(),
            Companions::default()
        );
    }

    #[test]
    fn rejects_malformed_sub_blocks() {
        let row = [spec(RecordLayout::A, vec![1; 16], 0)];
        let mut too_many = archive(&row, &[record(b"a.dat", 1)]);
        let b = metadata(&too_many).layout().b_block.clone();
        set_u32(&mut too_many, b.start + SUB_BLOCK, u32::MAX);
        let message = invalid_reason(metadata(&too_many).companions());
        assert!(message.contains("more than fit"), "{message}");
        // One record more than the B block holds.
        let fit = (B_LEN as usize - SUB_BLOCK - 8) / 0x108;
        let mut truncated = archive(&row, &[]);
        set_u32(&mut truncated, b.start + SUB_BLOCK, fit as u32 + 1);
        invalid_reason(metadata(&truncated).companions());
        set_u32(&mut truncated, b.start + SUB_BLOCK, fit as u32);
        assert_eq!(
            metadata(&truncated).companions().unwrap().records.len(),
            fit
        );
        // The sub-block's own offset outside the B block. The A record for
        // ID 3 is the second one.
        let mut outside = archive(&row, &[]);
        set_u32(&mut outside, 0x40 + 8 + 4, B_LEN - 4);
        invalid_reason(metadata(&outside).companions());
    }

    #[test]
    fn checks_names_and_headers() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("pack");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(temp.path().join("outside.dat"), companion(9, b"")).unwrap();
        fs::write(dir.join("good.dat"), companion(2, b"payload")).unwrap();
        fs::write(dir.join("wrong_id.dat"), companion(4, b"")).unwrap();
        let mut bad_magic = companion(5, b"");
        bad_magic[3] = 0x38;
        fs::write(dir.join("bad_magic.dat"), bad_magic).unwrap();
        fs::write(dir.join("short.dat"), &companion(6, b"")[..15]).unwrap();
        fs::write(dir.join("sub").join("nested.dat"), companion(7, b"")).unwrap();
        let names: [(&[u8], u64); 12] = [
            (b"missing.dat", 1),
            (b"good.dat", 2),
            (b"wrong_id.dat", 3),
            (b"bad_magic.dat", 5),
            (b"short.dat", 6),
            (b"sub\\nested.dat", 7),
            (b"sub/../good.dat", 2),
            (b"../outside.dat", 9),
            (b"/good.dat", 2),
            (b"c:good.dat", 2),
            (b"g\xFFod.dat", 2),
            (b"sub", 2),
        ];
        // The B block of these archives holds five records, so the names are
        // spread over several archives in the same directory.
        let mut statuses = Vec::new();
        for (n, group) in names.chunks(5).enumerate() {
            let records: Vec<Vec<u8>> = group.iter().map(|(n, id)| record(n, *id)).collect();
            let bytes = archive(&[spec(RecordLayout::A, vec![1; 16], 0)], &records);
            let archive_path = dir.join(format!("main{n}.rpf"));
            fs::write(&archive_path, &bytes).unwrap();
            statuses.extend(metadata(&bytes).companions().unwrap().open(&archive_path));
        }
        assert_eq!(
            status(&statuses),
            [
                "missing",
                "available",
                "invalid",
                "invalid",
                "invalid",
                "available",
                "available",
                "invalid",
                "invalid",
                "unsupported",
                "unsupported",
                "invalid",
            ]
        );
        assert!(
            reason(&statuses[2]).contains("identifier"),
            "{}",
            reason(&statuses[2])
        );
        assert!(reason(&statuses[3]).contains("signature"));
        assert!(reason(&statuses[4]).contains("shorter"));
        assert!(reason(&statuses[7]).contains("leaves"));
        assert!(reason(&statuses[8]).contains("absolute"));
        assert!(reason(&statuses[11]).contains("not a file"));
        // The companion is read from its start; the header is not skipped.
        let mut good = statuses[1].source().unwrap().clone();
        let mut bytes = Vec::new();
        good.read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes[16..], b"payload");
    }

    #[test]
    fn refuses_links_out_of_the_directory() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("pack");
        fs::create_dir(&dir).unwrap();
        let outside = temp.path().join("outside.dat");
        fs::write(&outside, companion(1, b"")).unwrap();
        let link = dir.join("link.dat");
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&outside, &link);
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&outside, &link);
        if linked.is_err() {
            // Creating links needs a privilege this environment may lack.
            return;
        }
        let bytes = archive(
            &[spec(RecordLayout::A, vec![1; 16], 0)],
            &[record(b"link.dat", 1)],
        );
        let statuses = metadata(&bytes)
            .companions()
            .unwrap()
            .open(&dir.join("main.rpf"));
        assert!(
            reason(&statuses[0]).contains("outside"),
            "{}",
            reason(&statuses[0])
        );
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Directory junctions need no privilege on Windows.
    #[cfg(windows)]
    #[test]
    fn refuses_junctions_out_of_the_directory() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("pack");
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir(&dir).unwrap();
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join("data.dat"), companion(1, b"")).unwrap();
        let junction = dir.join("redirect");
        let made = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&elsewhere)
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        assert!(junction.join("data.dat").exists());
        let bytes = archive(
            &[spec(RecordLayout::A, vec![1; 16], 0)],
            &[record(b"redirect/data.dat", 1)],
        );
        let statuses = metadata(&bytes)
            .companions()
            .unwrap()
            .open(&dir.join("main.rpf"));
        assert_eq!(status(&statuses), ["invalid"]);
        assert!(
            reason(&statuses[0]).contains("outside"),
            "{}",
            reason(&statuses[0])
        );
    }

    fn read_all(payload: &mut Payload) -> Vec<u8> {
        let mut bytes = Vec::new();
        payload.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn file(path: &Path) -> lforge_binary::Source {
        lforge_binary::Source::open(path).unwrap()
    }

    #[test]
    fn payloads_are_read_from_their_companion() {
        let temp = tempfile::tempdir().unwrap();
        let text: Vec<u8> = (0..20_000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let chunk_stream = {
            let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&text).unwrap();
            encoder.finish().unwrap()
        };
        let stored_len = chunk_stream.len().next_multiple_of(16);
        let padding = (stored_len - chunk_stream.len()) as u64;
        let entry = text.len() as u64 | ((stored_len / 16) as u64) << 28 | padding << 52 | 3 << 56;
        let mut chunked = chunk_stream.clone();
        chunked.resize(stored_len, 0xA5);
        let rows = [
            Spec {
                source: Some(1),
                ..spec(RecordLayout::A, text.clone(), 0)
            },
            Spec {
                source: Some(1),
                mode: 1,
                logical: Some(text.len() as u64),
                ..spec(RecordLayout::F, deflate(&text), 0)
            },
            Spec {
                source: Some(1),
                chunks: Some(chunk_value(8, 1, 4, &[entry])),
                logical: Some(text.len() as u64),
                ..spec(RecordLayout::A, chunked, 0)
            },
            Spec {
                source: Some(0),
                ..spec(RecordLayout::A, text.clone(), 0)
            },
            Spec {
                source: Some(7),
                ..spec(RecordLayout::A, text.clone(), 0)
            },
            spec(RecordLayout::A, text.clone(), 0),
        ];
        let full = archive(
            &rows,
            &[record(b"missing.dat", 10), record(b"data.dat", 11)],
        );
        // The companion holds the payloads at the same offsets; the main
        // file holds zeros there, apart from the main-source row.
        let metadata_len = metadata(&full).prefix().metadata_len as usize;
        let mut companion = full.clone();
        companion[..16].copy_from_slice(&[&MAGIC[..], &11u64.to_le_bytes()].concat());
        let mut main = full.clone();
        let last = metadata(&full).raw_range(5).unwrap();
        main[metadata_len..last.start as usize].fill(0);
        let dir = temp.path();
        let main_path = dir.join("main.rpf");
        fs::write(&main_path, &main).unwrap();
        fs::write(dir.join("data.dat"), &companion).unwrap();

        let metadata = metadata(&main);
        let statuses = metadata.companions().unwrap().open(&main_path);
        assert_eq!(status(&statuses), ["missing", "available"]);
        let alternates: Vec<_> = statuses.iter().map(|s| s.source().cloned()).collect();
        let source = file(&main_path);
        for row in 0..3 {
            let entry = metadata.entry(row).unwrap();
            let mut payload = entry.payload(&source, &alternates).unwrap();
            assert_eq!(read_all(&mut payload), text, "row {row}");
        }
        // Companion 0 is missing and there is no companion 7. Neither falls
        // back to the main file.
        for (row, index) in [(3, 0), (4, 7)] {
            let entry = metadata.entry(row).unwrap();
            match entry.payload(&source, &alternates) {
                Err(Error::ReadSource { index: i, .. }) => assert_eq!(i, index),
                other => panic!("row {row}: {other:?}"),
            }
        }
        // The main source still serves its own rows, unchanged by the
        // companions.
        let entry = metadata.entry(5).unwrap();
        assert_eq!(
            read_all(&mut entry.payload(&source, &alternates).unwrap()),
            text
        );
    }
}

#[cfg(test)]
mod real_payload_transform_probe {
    //! Local, opt-in diagnostics for the payload transform. They read one real
    //! archive and never write game data. Enable with
    //! `LEONIDA_FORGE_EXECUTABLE` and `LEONIDA_FORGE_ARCHIVE`.
    //!
    //! [`payload_transform_key_state_probe`] is the Phase 11 baseline: it feeds
    //! the archive and static descriptors to the algorithm-`0x10` block. Its
    //! failure is expected, because the transform descriptor is the value of
    //! the entry's transform field, not the archive descriptor.
    //!
    //! [`payload_transform_descriptor_probe`] reports the descriptor the engine
    //! actually uses and stops before any transformation.

    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::AtomicBool;

    use lforge_binary::pe::ExecutableView;

    use super::*;
    use crate::rpf::metadata::provider::select_source;
    use crate::rpf::metadata::transform::{BLOCK_LEN, Block, BlockDecrypt, CipherDescriptor};

    fn zlib_ok(bytes: &[u8]) -> Option<usize> {
        let mut d = flate2::Decompress::new(true);
        let mut out = vec![0u8; 1 << 20];
        match d.decompress(bytes, &mut out, flate2::FlushDecompress::Finish) {
            Ok(flate2::Status::StreamEnd) => Some(d.total_out() as usize),
            _ => None,
        }
    }

    fn add_be(iv: &Block, index: u64) -> Block {
        let mut out = *iv;
        let mut carry = index;
        for byte in out.iter_mut().rev() {
            let sum = u64::from(*byte) + (carry & 0xff);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        out
    }

    fn xor_into(block: &mut Block, iv: &Block) {
        for (b, i) in block.iter_mut().zip(iv) {
            *b ^= i;
        }
    }

    #[test]
    #[ignore = "needs LEONIDA_FORGE_EXECUTABLE and LEONIDA_FORGE_ARCHIVE"]
    fn payload_transform_descriptor_probe() {
        use crate::rpf::metadata::transform::Algorithm;

        let (Ok(exe), Ok(archive)) = (
            std::env::var("LEONIDA_FORGE_EXECUTABLE"),
            std::env::var("LEONIDA_FORGE_ARCHIVE"),
        ) else {
            return;
        };
        let limit = std::env::var("LEONIDA_FORGE_PROBE_ROWS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(15usize);
        let view = ExecutableView::open(std::path::Path::new(&exe)).unwrap();
        let cancel = AtomicBool::new(false);
        let mut file = File::open(&archive).unwrap();
        let report = verify::open_authenticated(&mut file, &view, &cancel).unwrap();
        let md = report.authenticated.unwrap();
        let meta = md.metadata();

        // Stage accounting for the engine's pipeline. No key state is read and
        // no byte is transformed here.
        let mut examined = 0usize;
        let mut descriptors = 0usize;
        let mut malformed = 0usize;
        let mut kinds = std::collections::BTreeMap::new();
        let mut key_ids = std::collections::BTreeSet::new();
        let mut algorithms = std::collections::BTreeMap::new();
        let mut chunked = 0usize;
        for entry in meta.entries() {
            if entry.payload_transform != Ok(true) {
                continue;
            }
            if examined == limit {
                break;
            }
            examined += 1;
            let cipher = match &entry.payload_cipher {
                Ok(Some(cipher)) => cipher,
                Ok(None) => continue,
                Err(_) => {
                    malformed += 1;
                    continue;
                }
            };
            descriptors += 1;
            *kinds.entry(cipher.kind).or_insert(0usize) += 1;
            key_ids.insert(cipher.key_id);
            let algorithm = Algorithm::of(cipher.kind)
                .map(|a| a.id())
                .unwrap_or(u8::MAX);
            *algorithms.entry(algorithm).or_insert(0usize) += 1;
            if matches!(&entry.chunks, Ok(Some(_))) {
                chunked += 1;
            }
        }
        println!(
            "transformed rows examined: {examined}, descriptors: {descriptors}, \
             malformed: {malformed}, chunked: {chunked}"
        );
        println!("cipher types: {kinds:?}");
        println!("algorithm identifiers: {algorithms:?}");
        println!("distinct key identifiers: {}", key_ids.len());
        println!(
            "earliest failure stage: cipher initialization not implemented \
             (the algorithm-0x11 keystream block is not reproduced); \
             no byte was transformed and no payload was decoded"
        );
    }

    #[test]
    #[ignore = "needs LEONIDA_FORGE_EXECUTABLE and LEONIDA_FORGE_ARCHIVE"]
    fn payload_transform_key_state_probe() {
        let (Ok(exe), Ok(archive)) = (
            std::env::var("LEONIDA_FORGE_EXECUTABLE"),
            std::env::var("LEONIDA_FORGE_ARCHIVE"),
        ) else {
            return;
        };
        let view = ExecutableView::open(std::path::Path::new(&exe)).unwrap();
        let cancel = AtomicBool::new(false);
        let mut file = File::open(&archive).unwrap();
        let stored = Stored::read(&mut file, verify::MAX_METADATA).unwrap();
        let a_span = step1_a_span(stored.prefix(), stored.layout()).unwrap();
        let selection = select_source(
            &stored.bytes()[a_span],
            stored.prefix().a_records,
            stored.prefix().b_len,
            &view,
            stored.prefix().selector,
            &cancel,
        )
        .unwrap();
        let source = &selection.source;
        let report = verify::open_authenticated(&mut file, &view, &cancel).unwrap();
        let md = report.authenticated.unwrap();
        let meta = md.metadata();
        let a_table = &meta.bytes[meta.layout.a_table.clone()];
        let offset = find_sub_block(a_table, 1).unwrap();
        let start = meta.layout.b_block.start + offset as usize;
        let descriptor = CipherDescriptor::parse(&meta.bytes[start..]).unwrap();
        println!(
            "archive descriptor: key_id={:#x} kind={:#x} iv={:02x?}",
            descriptor.key_id, descriptor.kind, descriptor.parameter
        );
        let kind = descriptor.kind;
        let key_id = descriptor.key_id;
        let mut checked = 0;
        for entry in md.metadata().entries() {
            if entry.payload_transform != Ok(true) {
                continue;
            }
            let Ok(Some(location)) = entry.location else {
                continue;
            };
            if location.stored_len == 0 || location.stored_len > 4 * 1024 * 1024 {
                continue;
            }
            let chunks = match &entry.chunks {
                Ok(c) => c.is_some(),
                Err(_) => continue,
            };
            let mut raw = vec![0u8; location.stored_len as usize];
            file.seek(SeekFrom::Start(location.payload_offset)).unwrap();
            file.read_exact(&mut raw).unwrap();
            println!(
                "row {} type {} mode {} chunks {} stored {} logical {}",
                entry.row,
                location.type_id,
                location.mode,
                chunks,
                location.stored_len,
                location.logical_len
            );
            // For chunked entries, brute-force key/IV/base over the first
            // method-3 chunk. A correct combination must inflate it.
            if let (Ok(Some(table)), true) = (&entry.chunks, chunks) {
                let mut start = 0usize;
                let mut first: Option<(usize, usize, usize)> = None;
                for chunk in &table.chunks {
                    if chunk.method == 3 {
                        first = Some((
                            start,
                            chunk.compressed_len as usize,
                            chunk.stored_len as usize,
                        ));
                        break;
                    }
                    start += chunk.stored_len as usize;
                }
                if let Some((off, compressed, stored)) = first
                    && start + stored <= raw.len()
                {
                    let entry_units = location.payload_offset / 16;
                    let chunk_units = (location.payload_offset + off as u64) / 16;
                    let keys = [
                        ("archive", key_id, kind, descriptor.parameter),
                        (
                            "static",
                            source.descriptor().key_id(),
                            source.descriptor().kind(),
                            *source.descriptor().parameter(),
                        ),
                    ];
                    let mut wins = Vec::new();
                    for (kname, kid, kk, param) in keys {
                        for mode in [0u8, 1] {
                            let Some(block) = source.block_for_mode(kk, kid, mode) else {
                                continue;
                            };
                            for (bname, base) in [
                                ("pos0", 0u64),
                                ("entry", entry_units),
                                ("chunk", chunk_units),
                            ] {
                                let iv0 = add_be(&param, base);
                                for (sname, perblock) in [("cbc", false), ("blk", true)] {
                                    let mut buf = raw[off..off + stored].to_vec();
                                    if perblock {
                                        for (i, c) in buf
                                            .as_chunks_mut::<BLOCK_LEN>()
                                            .0
                                            .iter_mut()
                                            .enumerate()
                                        {
                                            let mut b16: Block = *c;
                                            block.decrypt_block(&mut b16);
                                            let iv = add_be(&iv0, i as u64);
                                            xor_into(&mut b16, &iv);
                                            c.copy_from_slice(&b16);
                                        }
                                    } else {
                                        let mut iv = iv0;
                                        for c in buf.as_chunks_mut::<BLOCK_LEN>().0.iter_mut() {
                                            let stored_block: Block = *c;
                                            let mut b16 = stored_block;
                                            block.decrypt_block(&mut b16);
                                            xor_into(&mut b16, &iv);
                                            iv = stored_block;
                                            c.copy_from_slice(&b16);
                                        }
                                    }
                                    if zlib_ok(&buf[..compressed]).is_some() {
                                        wins.push(format!("{kname}/mode{mode}/{bname}/{sname}"));
                                    }
                                }
                            }
                        }
                    }
                    println!(
                        "  first method-3 chunk off {} compressed {} stored {} wins: {:?}",
                        off, compressed, stored, wins
                    );
                }
            }
            checked += 1;
            if checked >= 15 {
                break;
            }
        }
        println!("checked {checked} transformed stored rows");
    }
}
