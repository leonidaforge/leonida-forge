//! Tests on synthetic ADAT payloads built in memory.

use super::*;

struct Build {
    variant: u16,
    streams: u32,
    table: Vec<u8>,
    records: Vec<(u8, Vec<u8>)>,
}

impl Build {
    fn new(variant: u16, streams: u32) -> Self {
        let table_len = match variant {
            0xFF02 => 4 * streams as usize,
            0xFF21 | 0xFF25 => 0x04 + 10 * streams as usize,
            0xFF61 => 0x08 + 10 * streams as usize,
            _ => 0,
        };
        Self {
            variant,
            streams,
            table: vec![0u8; table_len],
            records: Vec::new(),
        }
    }

    fn phrase(codec: u8, declared: u32, rate: u16) -> Vec<u8> {
        let mut record = vec![0u8; 32];
        record[0..4].copy_from_slice(&declared.to_le_bytes());
        record[8..10].copy_from_slice(&rate.to_le_bytes());
        record[10..12].copy_from_slice(&0x0000u16.to_le_bytes());
        record[0x1C] = codec;
        record
    }

    fn page(pages: u32, stride: u32, entries: &[(u32, u16, u8)]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&pages.to_le_bytes());
        record.extend_from_slice(&stride.to_le_bytes());
        record.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (decoded, rate, codec) in entries {
            record.extend_from_slice(&0u32.to_le_bytes());
            record.extend_from_slice(&decoded.to_le_bytes());
            record.extend_from_slice(&(u32::from(*rate) << 16).to_le_bytes());
            record.extend_from_slice(&u16::from(*codec).to_le_bytes());
            record.extend_from_slice(&0u16.to_le_bytes());
        }
        record
    }

    fn push(mut self, kind: u8, payload: Vec<u8>) -> Self {
        self.records.push((kind, payload));
        self
    }

    fn payload(&self) -> Vec<u8> {
        let start = match self.variant {
            0xFF02 => 0x10 + 4 * self.streams as usize,
            0xFF21 | 0xFF25 => 0x14 + 10 * self.streams as usize,
            0xFF61 => 0x18 + 10 * self.streams as usize,
            _ => 0x10,
        };
        let data_offset = start + 8 * self.records.len();
        let mut bytes = vec![0u8; data_offset];
        bytes[..4].copy_from_slice(&MAGIC);
        let flags = (u32::from(self.variant) << 16) | 1;
        bytes[4..8].copy_from_slice(&flags.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.streams.to_le_bytes());
        bytes[0x0C..0x10].copy_from_slice(&(data_offset as u32).to_le_bytes());
        bytes[0x10..0x10 + self.table.len()].copy_from_slice(&self.table);
        let mut data = Vec::new();
        for (ix, (kind, payload)) in self.records.iter().enumerate() {
            let offset = data_offset + data.len();
            let word = (u64::from(*kind) << 56) | ((payload.len() as u64) << 28) | offset as u64;
            bytes[start + 8 * ix..start + 8 * ix + 8].copy_from_slice(&word.to_le_bytes());
            data.extend_from_slice(payload);
        }
        bytes.extend_from_slice(&data);
        bytes
    }
}

fn block(packets: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for packet in packets {
        bytes.extend_from_slice(&(packet.len() as u16).to_le_bytes());
        bytes.extend_from_slice(packet);
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.resize(BLOCK_LEN, 0);
    bytes
}

fn blocks(data: &[Vec<u8>]) -> Vec<u8> {
    data.iter().flat_map(|block| block.clone()).collect()
}

fn parse(build: &Build) -> Result<Report, Error> {
    super::parse(&build.payload(), &Limits::default())
}

#[test]
fn a_framed_stream_spanning_two_blocks_is_counted() {
    let packet = vec![0xFCu8; 320];
    let stream = blocks(&[block(&[&packet]), block(&[&packet])]);
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 640, 48_000))
        .push(TYPE_STREAM, stream);
    let report = parse(&build).unwrap();
    assert_eq!(report.variant, 0xFF21);
    assert_eq!(report.streams, 1);
    assert_eq!(report.blocks.data, 2);
    assert_eq!(report.blocks.sentinel, 0);
    assert_eq!(report.packets, 2);
    assert_eq!(report.packet_bytes, 640);
    assert_eq!(report.padding, 2 * (BLOCK_LEN as u64 - 322 - 2));
    assert_eq!(report.framing_violations, 0);
    assert_eq!(report.rates, vec![(48_000, 1)]);
    assert!(report.framing_checked);
    assert_eq!(report.codecs[0].support, "framed");
}

#[test]
fn several_packets_and_zero_padding_in_one_block() {
    let packets = [vec![1u8; 3], vec![2u8; 80], vec![3u8; 50]];
    let refs: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 133, 48_000))
        .push(TYPE_STREAM, block(&refs));
    let report = parse(&build).unwrap();
    assert_eq!(report.packets, 3);
    assert_eq!(report.packet_bytes, 133);
    assert_eq!(report.framing_violations, 0);
    let used = 3 * 2 + 3 + 80 + 50 + 2;
    assert_eq!(report.padding, (BLOCK_LEN - used) as u64);
}

#[test]
fn a_packet_crossing_the_block_end_is_a_violation() {
    let mut stream = 4_000u16.to_le_bytes().to_vec();
    stream.resize(BLOCK_LEN, 0x22);
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 4_000, 48_000))
        .push(TYPE_STREAM, stream);
    let report = parse(&build).unwrap();
    assert_eq!(report.framing_violations, 1);
    assert!(report.failures[0].contains("crosses"));
}

#[test]
fn non_zero_padding_is_a_violation() {
    let packet = vec![7u8; 10];
    let mut stream = block(&[&packet]);
    stream[BLOCK_LEN - 1] = 0xAB;
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 10, 48_000))
        .push(TYPE_STREAM, stream);
    let report = parse(&build).unwrap();
    assert_eq!(report.framing_violations, 1);
    assert!(report.failures[0].contains("non-zero bytes follow"));
}

#[test]
fn a_truncated_packet_length_is_a_violation() {
    let mut stream = (BLOCK_LEN as u16 - 3).to_le_bytes().to_vec();
    stream.extend(std::iter::repeat_n(0x22u8, BLOCK_LEN - 3));
    stream.resize(BLOCK_LEN + 1, 0);
    stream.resize(2 * BLOCK_LEN, 0);
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 1, 48_000))
        .push(TYPE_STREAM, stream);
    let report = parse(&build).unwrap();
    assert!(report.framing_violations >= 1);
}

#[test]
fn an_invalid_framed_size_is_a_violation() {
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 1, 48_000))
        .push(TYPE_STREAM, vec![0u8; 3_000]);
    let report = parse(&build).unwrap();
    assert_eq!(report.framing_violations, 1);
    assert!(report.failures[0].contains("not a multiple"));
}

#[test]
fn a_size_only_stream_is_not_block_framed() {
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_SIZE_ONLY, 3, 48_000))
        .push(TYPE_STREAM, vec![0x11u8; 12]);
    let report = parse(&build).unwrap();
    assert_eq!(report.framing_violations, 0);
    assert_eq!(report.blocks.data, 0);
    assert_eq!(report.codecs[0].support, "size-only");
}

#[test]
fn an_invalid_size_only_relation_is_a_violation() {
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_SIZE_ONLY, 3, 48_000))
        .push(TYPE_STREAM, vec![0x11u8; 16]);
    let report = parse(&build).unwrap();
    assert_eq!(report.framing_violations, 1);
    assert!(report.failures[0].contains("4 × 3"));
}

#[test]
fn mixed_codec_classes_are_flagged() {
    let build = Build::new(0xFF21, 2)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 10, 48_000))
        .push(TYPE_STREAM, block(&[&[1u8; 10]]))
        .push(TYPE_PHRASE, Build::phrase(CODEC_SIZE_ONLY, 3, 48_000))
        .push(TYPE_STREAM, vec![0u8; 12]);
    let report = parse(&build).unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("more than one codec class"))
    );
}

#[test]
fn unclassified_codec_bytes_are_refused() {
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(0x05, 3, 48_000))
        .push(TYPE_STREAM, vec![0u8; 12]);
    let report = parse(&build).unwrap();
    assert!(!report.framing_checked);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("unclassified"))
    );
}

fn sentinel() -> Vec<u8> {
    let mut bytes = vec![0xFFu8; BLOCK_LEN];
    for byte in bytes.iter_mut().skip(4) {
        *byte = 0;
    }
    bytes
}

fn metadata() -> Vec<u8> {
    let mut bytes = vec![0u8; BLOCK_LEN];
    bytes[0..2].copy_from_slice(&0x0FFFu16.to_le_bytes());
    bytes[2] = 0x55;
    bytes
}

fn zero() -> Vec<u8> {
    vec![0u8; BLOCK_LEN]
}

#[test]
fn ff25_pages_carry_sentinels_and_optional_metadata() {
    let packet = vec![0x78u8; 20];
    let page0 = blocks(&[sentinel(), block(&[&packet]), zero(), zero()]);
    let page1 = blocks(&[sentinel(), metadata(), block(&[&packet]), zero()]);
    let mut stream = page0;
    stream.extend_from_slice(&page1);
    let mut build = Build::new(0xFF25, 1);
    build.table[0..2].copy_from_slice(&1u16.to_le_bytes());
    let build = build
        .push(
            TYPE_PAGE,
            Build::page(2, 4 * BLOCK_LEN as u32, &[(20, 48_000, CODEC_FRAMED)]),
        )
        .push(TYPE_STREAM, stream);
    let report = parse(&build).unwrap();
    assert_eq!(report.blocks.sentinel, 2);
    assert_eq!(report.blocks.metadata, 1);
    assert_eq!(report.blocks.data, 2);
    assert_eq!(report.blocks.zero, 3);
    assert_eq!(report.packets, 2);
    assert_eq!(report.framing_violations, 0);
    let summary = report.page_summary.expect("a page summary");
    assert_eq!(summary.declared_pages, 2);
    assert!(summary.page_count_matches);
    assert_eq!(summary.pages_with_metadata, 1);
    assert_eq!(report.rates, vec![(48_000, 1)]);
}

#[test]
fn a_trailing_page_shorter_than_the_stride_is_reported() {
    let packet = vec![0x78u8; 20];
    // One page of four blocks is declared, but the stream holds two.
    let stream = blocks(&[sentinel(), block(&[&packet])]);
    let build = Build::new(0xFF25, 1)
        .push(
            TYPE_PAGE,
            Build::page(1, 4 * BLOCK_LEN as u32, &[(20, 48_000, CODEC_FRAMED)]),
        )
        .push(TYPE_STREAM, stream);
    let report = parse(&build).unwrap();
    assert_eq!(report.blocks.sentinel, 1);
    assert_eq!(report.blocks.data, 1);
    assert_eq!(report.packets, 1);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("shorter than the")),
        "{:?}",
        report.issues
    );
}

#[test]
fn a_non_monotone_position_table_is_reported() {
    let mut positions = Vec::new();
    for value in [0u32, 5, 3] {
        positions.extend_from_slice(&value.to_le_bytes());
    }
    let build = Build::new(0xFF21, 1)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 10, 48_000))
        .push(TYPE_STREAM, block(&[&[1u8; 10]]))
        .push(TYPE_POSITION, positions);
    let report = parse(&build).unwrap();
    let table = report.positions.expect("a position table");
    assert_eq!(table.entries, 3);
    assert!(table.starts_at_zero);
    assert!(!table.non_decreasing);
}

#[test]
fn atypical_rates_are_preserved_as_values() {
    let build = Build::new(0xFF21, 2)
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 10, 12_000))
        .push(TYPE_STREAM, block(&[&[1u8; 10]]))
        .push(TYPE_PHRASE, Build::phrase(CODEC_FRAMED, 10, 48_000))
        .push(TYPE_STREAM, block(&[&[1u8; 10]]));
    let report = parse(&build).unwrap();
    assert_eq!(report.rates, vec![(12_000, 1), (48_000, 1)]);
}

#[test]
fn a_stream_without_a_descriptor_is_reported() {
    let build = Build::new(0xFF21, 1).push(TYPE_STREAM, block(&[&[1u8; 10]]));
    let report = parse(&build).unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("1 stream records and 0 descriptors")),
        "{:?}",
        report.issues
    );
}

#[test]
fn oversized_and_truncated_inputs_are_refused() {
    let build = Build::new(0xFF21, 1).push(TYPE_PHRASE, Build::phrase(0x0B, 1, 48_000));
    let limits = Limits {
        max_streams: 0,
        ..Limits::default()
    };
    assert!(super::parse(&build.payload(), &limits).is_err());
    let limits = Limits {
        max_len: 8,
        ..Limits::default()
    };
    assert!(super::parse(&build.payload(), &limits).is_err());

    let mut bytes = build.payload();
    bytes[0x0C..0x10].copy_from_slice(&0x11u32.to_le_bytes());
    assert!(super::parse(&bytes, &Limits::default()).is_err());

    assert!(matches!(
        super::parse(b"ADAX", &Limits::default()),
        Err(Error::NotAdat)
    ));
}

#[test]
fn an_unsupported_variant_is_refused() {
    let mut bytes = Build::new(0xFF21, 1).payload();
    bytes[4..8].copy_from_slice(&((0xFF99u32 << 16) | 1).to_le_bytes());
    assert!(super::parse(&bytes, &Limits::default()).is_err());
}
