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
}
