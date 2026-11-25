//! Synthetic RPF9 archives for the CLI tests, built in memory. No game files
//! or data extracted from them are used.
//!
//! A dictionary-encoded columnar table, as the RPF9 table of contents is, with
//! payloads appended after it. Ported in trimmed form from the rage9 metadata
//! test scaffolding; it drives the real decoder through the CLI.

#![allow(dead_code)]

use std::io::{Cursor, Write};
use std::path::Path;
use std::process::{Command, Output};

use flate2::Compression;
use flate2::write::{DeflateEncoder, ZlibEncoder};
use lforge_rage9::rpf::metadata::{Metadata, Stored, keys};

const DESCRIPTOR_LEN: usize = 24;
/// Payloads start here, past the metadata area.
const PAYLOADS: usize = 0x1000;
/// `B` block start with the default A table (4 records, 16-byte alignment).
const B_START: usize = 0x60;
/// The `B` offset of sub-block 3: the second A record (ID 3) points here.
const SUB_BLOCK_3: usize = 0x20;
/// The first eight bytes of a companion file.
pub const COMPANION_MAGIC: [u8; 8] = [0, 0, 0, 0x39, 0x56, 0x46, 0x50, 0x52];

fn up(value: usize, to: usize) -> usize {
    value.next_multiple_of(to)
}

fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

struct Column {
    key: u64,
    width: u16,
    pool: Vec<u8>,
    cells: Vec<Option<u32>>,
}

impl Column {
    fn new(key: u64, width: u16, elements: &[&[u8]], cells: &[Option<u32>]) -> Self {
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

/// One column with a value for each row where `values` gives one.
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

struct Build {
    a_ids: Vec<u16>,
    b_len: u32,
    selector: u8,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            a_ids: vec![2, 3, 4, 6],
            b_len: 0x150,
            selector: 0,
        }
    }
}

impl Build {
    /// Lays out header, A table, B block, descriptors, cells and pools with
    /// 16-byte alignment (flags bit 0) and one-byte compact indices.
    fn build(&self, columns: &[Column]) -> Vec<u8> {
        let rows = columns.first().map_or(0, |c| c.cells.len());
        let count = columns.len();
        let a = up(0x40, 16);
        let b = up(a + self.a_ids.len() * 8, 16);
        let descriptors = up(b + self.b_len as usize, 16);
        let primary_cells = descriptors + count * DESCRIPTOR_LEN;
        let primary_pool = up(primary_cells + count * rows, 8);
        let mut pool_offsets = Vec::new();
        let mut end = primary_pool;
        for column in columns {
            pool_offsets.push(end - primary_pool);
            end += column.pool.len();
        }
        let end = up(end, 8);

        let mut bytes = vec![0u8; end];
        bytes[..4].copy_from_slice(b"9FPR");
        bytes[4..8].copy_from_slice(&(end as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(end as u32).to_le_bytes());
        bytes[0x1A..0x1C].copy_from_slice(&(self.a_ids.len() as u16).to_le_bytes());
        bytes[0x1C..0x20].copy_from_slice(&self.b_len.to_le_bytes());
        bytes[0x20..0x22].copy_from_slice(&(count as u16).to_le_bytes());
        bytes[0x24..0x28].copy_from_slice(&(rows as u32).to_le_bytes());
        bytes[0x2C] = 1; // compact index width
        bytes[0x2D] = 1; // flags: 16-byte alignment
        bytes[0x2E] = self.selector;
        bytes[0x30..0x34].copy_from_slice(&0x10u32.min(self.b_len).to_le_bytes());
        for (ix, id) in self.a_ids.iter().enumerate() {
            let record = a + ix * 8;
            bytes[record..record + 2].copy_from_slice(&id.to_le_bytes());
            set_u32(&mut bytes, record + 4, ix as u32 * 0x20);
        }
        for (ix, c) in columns.iter().enumerate() {
            let at = descriptors + ix * DESCRIPTOR_LEN;
            bytes[at..at + 8].copy_from_slice(&c.key.to_le_bytes());
            set_u32(&mut bytes, at + 12, pool_offsets[ix] as u32);
            bytes[at + 16..at + 18].copy_from_slice(&c.width.to_le_bytes());
            let pool_at = primary_pool + pool_offsets[ix];
            bytes[pool_at..pool_at + c.pool.len()].copy_from_slice(&c.pool);
            for (row, cell) in c.cells.iter().enumerate() {
                let at = primary_cells + row * count + ix;
                bytes[at] = cell.map_or(0xFF, |index| index as u8);
            }
        }
        bytes
    }
}

#[derive(Clone)]
pub struct Spec {
    pub payload: Vec<u8>,
    pub mode: u8,
    pub logical: Option<u64>,
    pub chunks: Option<Vec<u8>>,
    pub transform: bool,
    pub source: Option<u32>,
    pub has_location: bool,
    pub shift: u32,
    pub type_id: u8,
    pub hash: Option<u64>,
    pub key: Option<u32>,
}

pub fn spec(payload: &[u8]) -> Spec {
    Spec {
        payload: payload.to_vec(),
        mode: 0,
        logical: None,
        chunks: None,
        transform: false,
        source: None,
        has_location: true,
        shift: 0,
        type_id: 0,
        hash: None,
        key: None,
    }
}

fn record_a(stored16: u32, offset16: u32, logical: u64, mode: u8, type_id: u8) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&stored16.to_le_bytes());
    value.extend_from_slice(&offset16.to_le_bytes());
    let packed = logical | (u64::from(type_id) << 48) | (u64::from(mode) << 56);
    value.extend_from_slice(&packed.to_le_bytes());
    value
}

pub fn chunk_value(count: u16, encoding: u8, entries: &[u64]) -> Vec<u8> {
    let mut value = 8u32.to_le_bytes().to_vec();
    value.extend_from_slice(&count.to_le_bytes());
    value.push(0);
    value.push(encoding);
    for entry in entries {
        value.extend_from_slice(&entry.to_le_bytes());
    }
    value
}

/// One encoding-4 chunk table entry. `stored_len` is a multiple of 16.
pub fn chunk4(logical: u32, stored_len: u32, padding: u32, method: u8) -> u64 {
    u64::from(logical)
        | (u64::from(stored_len / 16) << 28)
        | (u64::from(padding) << 52)
        | (u64::from(method) << 56)
}

/// One encoding-2 chunk table entry. `logical` and `stored_len` are
/// multiples of 16.
pub fn chunk2(logical: u32, stored_len: u32, padding: u32, method: u8) -> u64 {
    u64::from(logical / 16)
        | (u64::from(stored_len / 16) << 32)
        | (u64::from(padding) << 58)
        | (u64::from(method) << 62)
}

/// An archive for `specs`, with `companions` listed in `B` sub-block 3.
pub fn assemble(specs: &[Spec], companions: &[(Vec<u8>, u64)]) -> Vec<u8> {
    assemble_inner(specs, companions, 0)
}

/// An archive whose metadata declares a processing pass (`hdr[0x2E]`), so it
/// needs an executable to be read like a retail archive.
pub fn assemble_processed(specs: &[Spec], selector: u8) -> Vec<u8> {
    assemble_inner(specs, &[], selector)
}

fn assemble_inner(specs: &[Spec], companions: &[(Vec<u8>, u64)], selector: u8) -> Vec<u8> {
    let mut data = Vec::new();
    let mut locations: Vec<Option<Vec<u8>>> = Vec::new();
    for spec in specs {
        let offset16 = ((PAYLOADS + data.len()) / 16) as u32 + spec.shift;
        let stored16 = spec.payload.len().div_ceil(16) as u32;
        let logical = spec.logical.unwrap_or(spec.payload.len() as u64);
        locations.push(
            spec.has_location
                .then(|| record_a(stored16, offset16, logical, spec.mode, spec.type_id)),
        );
        data.extend_from_slice(&spec.payload);
        data.resize(data.len().next_multiple_of(16), 0);
    }
    let chunk_width = specs
        .iter()
        .filter_map(|s| s.chunks.as_ref().map(Vec::len))
        .max()
        .unwrap_or(8)
        .max(8);
    let mut columns = vec![
        column(keys::LOCATION_A, 16, locations),
        column(
            keys::CHUNK_TABLE,
            chunk_width as u16,
            specs
                .iter()
                .map(|s| {
                    s.chunks.clone().map(|mut value| {
                        value.resize(chunk_width, 0);
                        value
                    })
                })
                .collect(),
        ),
        column(
            keys::PAYLOAD_TRANSFORM,
            1,
            specs
                .iter()
                .map(|s| s.transform.then(|| vec![1u8]))
                .collect(),
        ),
        column(
            keys::READ_SOURCE,
            4,
            specs
                .iter()
                .map(|s| s.source.map(|i| i.to_le_bytes().to_vec()))
                .collect(),
        ),
    ];
    if specs.iter().any(|spec| spec.hash.is_some()) {
        columns.push(column(
            keys::NAME_HASH,
            8,
            specs
                .iter()
                .map(|spec| spec.hash.map(|hash| hash.to_le_bytes().to_vec()))
                .collect(),
        ));
    }
    if specs.iter().any(|spec| spec.key.is_some()) {
        columns.push(column(
            keys::NAME_KEY,
            4,
            specs
                .iter()
                .map(|spec| spec.key.map(|key| key.to_le_bytes().to_vec()))
                .collect(),
        ));
    }
    let b_len = if companions.is_empty() { 0x150 } else { 0x600 };
    let mut bytes = Build {
        b_len,
        selector,
        ..Build::default()
    }
    .build(&columns);
    if !companions.is_empty() {
        let at = B_START + SUB_BLOCK_3;
        set_u32(&mut bytes, at, companions.len() as u32);
        for (n, (name, id)) in companions.iter().enumerate() {
            let start = at + 8 + n * 0x108;
            bytes[start..start + name.len()].copy_from_slice(name);
            bytes[start + 0x100..start + 0x108].copy_from_slice(&id.to_le_bytes());
        }
    }
    assert!(
        bytes.len() <= PAYLOADS,
        "metadata {:#x} exceeds {:#x}",
        bytes.len(),
        PAYLOADS
    );
    bytes.resize(PAYLOADS, 0);
    bytes.extend_from_slice(&data);
    bytes
}

pub fn decode(bytes: &[u8]) -> Metadata {
    Stored::read(&mut Cursor::new(bytes), 1 << 20)
        .unwrap()
        .decode()
        .unwrap()
}

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// A region holding a zlib chunk: the stream, then padding to 16 bytes.
pub fn zlib_chunk(data: &[u8]) -> (Vec<u8>, u64) {
    let stream = zlib(data);
    let stored = stream.len().next_multiple_of(16);
    let padding = (stored - stream.len()) as u64;
    let mut region = stream;
    region.resize(stored, 0xA5);
    let entry = chunk4(data.len() as u32, stored as u32, padding as u32, 3);
    (region, entry)
}

/// A region holding a copied (uncompressed) chunk.
pub fn copy_chunk(data: &[u8]) -> (Vec<u8>, u64) {
    let stored = data.len().next_multiple_of(16);
    let padding = (stored - data.len()) as u64;
    let mut region = data.to_vec();
    region.resize(stored, 0);
    let entry = chunk4(data.len() as u32, stored as u32, padding as u32, 0);
    (region, entry)
}

/// A region holding an encoding-2 zlib chunk: the stream, then padding to
/// 16 bytes.
pub fn zlib_chunk2(data: &[u8]) -> (Vec<u8>, u64) {
    let stream = zlib(data);
    let stored = stream.len().next_multiple_of(16);
    let padding = (stored - stream.len()) as u64;
    let mut region = stream;
    region.resize(stored, 0xA5);
    let entry = chunk2(data.len() as u32, stored as u32, padding as u32, 3);
    (region, entry)
}

/// A region holding an encoding-2 copied (uncompressed) chunk.
pub fn copy_chunk2(data: &[u8]) -> (Vec<u8>, u64) {
    assert_eq!(data.len() % 16, 0);
    let entry = chunk2(data.len() as u32, data.len() as u32, 0, 0);
    (data.to_vec(), entry)
}

pub fn lforge(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lforge"))
        .args(args)
        .output()
        .expect("failed to run lforge")
}

pub fn extract(archive: &Path, row: u32, output: &Path, extra: &[&str]) -> Output {
    let row = row.to_string();
    let mut args = vec![
        "archive",
        "extract",
        archive.to_str().unwrap(),
        "--row",
        &row,
        "--output",
        output.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    lforge(&args)
}

pub fn write_archive(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// One entry of a hand-built ZIP archive.
///
/// The records are written directly so two entries can share a full name, as a
/// real central directory may. The writer crate refuses duplicate names.
pub struct ZipEntry<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
    pub method: u16,
}

impl<'a> ZipEntry<'a> {
    pub fn stored(name: &'a str, data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            method: 0,
        }
    }

    pub fn with_method(name: &'a str, data: &'a [u8], method: u16) -> Self {
        Self { name, data, method }
    }
}

const LOCAL_HEADER: [u8; 4] = *b"PK\x03\x04";
const CENTRAL_HEADER: [u8; 4] = *b"PK\x01\x02";
const END_RECORD: [u8; 4] = *b"PK\x05\x06";

/// A ZIP archive whose stored entries may repeat a full name.
pub fn zip_with_entries(files: &[ZipEntry<'_>]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.sum()
    }
    let mut out = Vec::new();
    let mut central = Vec::new();
    for file in files {
        let crc = crc32(file.data);
        let offset = out.len() as u32;
        out.extend_from_slice(&LOCAL_HEADER);
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&file.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(file.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(file.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(file.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(file.name.as_bytes());
        out.extend_from_slice(file.data);

        central.extend_from_slice(&CENTRAL_HEADER);
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&file.method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(file.data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(file.data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(file.name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(file.name.as_bytes());
    }
    let directory_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&END_RECORD);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// [`zip_with_entries`] for stored entries.
pub fn zip_entries(files: &[(&str, &[u8])]) -> Vec<u8> {
    let entries: Vec<ZipEntry<'_>> = files
        .iter()
        .map(|(name, data)| ZipEntry::stored(name, data))
        .collect();
    zip_with_entries(&entries)
}
