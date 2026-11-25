//! Tests on synthetic PSIN payloads built in memory.

use super::*;

fn align(len: usize) -> usize {
    len.next_multiple_of(16)
}

fn section(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(&((body.len() + 8) as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// Appends a `CHKS` section whose checksum covers the finished payload.
fn add_chks(payload: &mut Vec<u8>) {
    let mut body = vec![0u8; 12];
    body[8..12].copy_from_slice(b"zppp");
    payload.extend_from_slice(b"CHKS");
    payload.extend_from_slice(&20u32.to_be_bytes());
    let body_at = payload.len();
    payload.extend_from_slice(&body);
    let total = payload.len() as u32;
    payload[body_at..body_at + 4].copy_from_slice(&total.to_be_bytes());
    let computed = checksum_with_zeroed(payload, body_at);
    payload[body_at + 4..body_at + 8].copy_from_slice(&computed.to_be_bytes());
}

/// An `LSCH` payload: descriptors at `+0x08`, eight bytes of padding, the
/// data blocks, then `LSCH` and `LENM` sections and a checksum.
fn lsch_payload(descriptors: &[(u32, u32)], lsch_body: &[u8], lenm_body: &[u8]) -> Vec<u8> {
    let sum: usize = descriptors
        .iter()
        .map(|(_, len)| align(*len as usize))
        .sum();
    let first = 0x10 + 16 * descriptors.len() + sum;
    let mut payload = b"PSIN".to_vec();
    payload.extend_from_slice(&(first as u32).to_be_bytes());
    for (word, len) in descriptors {
        payload.extend_from_slice(&word.to_le_bytes());
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(&[0xAA; 8]);
    }
    payload.extend_from_slice(&[0u8; 8]);
    for (_, len) in descriptors {
        payload.extend(std::iter::repeat_n(0x11u8, *len as usize));
        payload.resize(payload.len().next_multiple_of(16), 0);
    }
    assert_eq!(payload.len(), first);
    payload.extend_from_slice(&section(b"LSCH", lsch_body));
    payload.extend_from_slice(&section(b"LENM", lenm_body));
    payload.extend_from_slice(&section(b"LSNS", &[0u8; 16]));
    payload.extend_from_slice(&section(b"LGID", &[0u8; 16]));
    payload.extend_from_slice(&section(b"LRSC", &[0u8; 16]));
    add_chks(&mut payload);
    payload
}

fn lsch_body(header_word: u32, markers: usize, tail: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 0x10];
    body[8..12].copy_from_slice(&header_word.to_le_bytes());
    for _ in 0..markers {
        let mut record = vec![0u8; 32];
        record[..8].copy_from_slice(&[0xAA; 8]);
        body.extend_from_slice(&record);
    }
    body.extend_from_slice(tail);
    body
}

/// A `PMAP` payload. Blocks are placed from `+0x10` with `0x70` padding
/// between them and none after the last.
fn pmap_payload(blocks: &[(u32, Vec<u8>)], metadata: bool) -> Vec<u8> {
    let mut presection = vec![0x70u8; 8];
    let mut offsets = Vec::new();
    for (ix, (_, data)) in blocks.iter().enumerate() {
        offsets.push((8 + presection.len()) as u32);
        presection.extend_from_slice(data);
        if ix + 1 < blocks.len() {
            // Blocks start on absolute 16-byte boundaries.
            let absolute = 8 + presection.len();
            presection.resize(absolute.next_multiple_of(16) - 8, 0x70);
        }
    }
    let first = 8 + presection.len();
    let mut payload = b"PSIN".to_vec();
    payload.extend_from_slice(&(first as u32).to_be_bytes());
    payload.extend_from_slice(&presection);
    assert_eq!(payload.len(), first);

    // The PMAP section body: mode, second word, count, six 0x70 bytes, records.
    let mut directory = Vec::new();
    directory.extend_from_slice(&1u32.to_be_bytes());
    directory.extend_from_slice(&0u32.to_be_bytes());
    directory.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
    directory.extend_from_slice(&[0x70; 6]);
    for (ix, (id, data)) in blocks.iter().enumerate() {
        directory.extend_from_slice(&id.to_be_bytes());
        directory.extend_from_slice(&offsets[ix].to_be_bytes());
        directory.extend_from_slice(&0u32.to_be_bytes());
        directory.extend_from_slice(&(data.len() as u32).to_be_bytes());
    }
    payload.extend_from_slice(&section(b"PMAP", &directory));

    // The PSCH table: one value per block id.
    let count = blocks.len();
    let values_start = 4 + 8 * count + 8;
    let mut ps = Vec::new();
    ps.extend_from_slice(&(count as u32).to_be_bytes());
    for (ix, (id, _)) in blocks.iter().enumerate() {
        ps.extend_from_slice(&id.to_be_bytes());
        ps.extend_from_slice(&((values_start + 4 * ix) as u32).to_be_bytes());
    }
    ps.extend_from_slice(&[0u8; 8]);
    for _ in 0..count {
        ps.extend_from_slice(&[0x5Au8; 4]);
    }
    payload.extend_from_slice(&section(b"PSCH", &ps));
    payload.extend_from_slice(&section(b"PSIG", &[0u8; 8]));
    if metadata {
        payload.extend_from_slice(&section(b"STDN", &[0u8; 8]));
    }
    payload.extend_from_slice(&section(b"STNS", &[0u8; 8]));
    add_chks(&mut payload);
    payload
}

#[test]
fn parses_the_lsch_descriptor_relation_and_bodies() {
    let payload = lsch_payload(
        &[(0x0102_0304, 32), (0x0203_0405, 48)],
        &lsch_body(768, 2, &[0u8; 16]),
        &lenm_exact(3),
    );
    let report = parse(&payload).unwrap();
    assert_eq!(report.family, Family::Lsch);
    let table = report.descriptors.expect("a solved table");
    assert_eq!(table.count, 2);
    assert_eq!(table.candidates, vec![2]);
    assert_eq!(table.descriptors[0].len, 32);
    assert_eq!(table.descriptors[1].word, 0x0203_0405);
    let body = report.lsch.expect("an LSCH body");
    assert_eq!(body.marker_records, 2);
    assert_eq!(body.tail_len, 16);
    assert_eq!(body.header_word, 768);
    assert!(body.aligned);
    let lenm = report.lenm.expect("a LENM body");
    assert_eq!(lenm.count, Some(3));
    assert_eq!(lenm.extra, Some(0));
    assert!(lenm.count_delimits_body);
    assert_eq!(report.checksum, Checksum::Verified);
    assert_eq!(
        report
            .sections
            .iter()
            .map(|section| section.tag_text())
            .collect::<Vec<_>>(),
        ["LSCH", "LENM", "LSNS", "LGID", "LRSC", "CHKS"]
    );
}

/// A non-empty `LENM` body whose count accounts for the whole body.
fn lenm_exact(count: u32) -> Vec<u8> {
    let mut body = vec![0u8; 0x20];
    body[8..16].copy_from_slice(&[0xEE; 8]);
    body[0x10..0x14].copy_from_slice(&count.to_le_bytes());
    let chain = 16 * count as usize - 8;
    body.resize(0x18 + chain, 0);
    body
}

#[test]
fn a_lenm_body_with_an_extra_region_is_reported_not_truncated() {
    let mut body = lenm_exact(2);
    body.extend_from_slice(&[0u8; 24]);
    let payload = lsch_payload(&[(0, 16)], &lsch_body(512, 0, &[]), &body);
    let report = parse(&payload).unwrap();
    let lenm = report.lenm.expect("a LENM body");
    assert_eq!(lenm.count, Some(2));
    assert_eq!(lenm.extra, Some(24));
    assert!(!lenm.count_delimits_body);
}

#[test]
fn an_empty_lenm_body_is_valid() {
    let payload = lsch_payload(&[(0, 16)], &lsch_body(512, 0, &[]), &[]);
    let report = parse(&payload).unwrap();
    let lenm = report.lenm.expect("a LENM body");
    assert_eq!(lenm.len, None);
    assert_eq!(lenm.count, None);
}

#[test]
fn an_unsatisfiable_descriptor_relation_is_reported() {
    let mut payload = lsch_payload(&[(0, 32)], &lsch_body(512, 0, &[]), &[]);
    // Enlarge the descriptor length so no count reproduces the first offset.
    let len = u32::from_le_bytes(payload[0x0C..0x10].try_into().unwrap());
    payload[0x0C..0x10].copy_from_slice(&(len + 16).to_le_bytes());
    let report = parse(&payload).unwrap();
    assert!(report.descriptors.is_none());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("no descriptor count satisfies")),
        "{:?}",
        report.issues
    );
}

#[test]
fn a_descriptor_without_the_marker_is_not_a_table() {
    let mut payload = lsch_payload(&[(0, 32)], &lsch_body(512, 0, &[]), &[]);
    // The descriptor marker at +0x10.
    payload[0x10] = 0;
    let report = parse(&payload).unwrap();
    assert!(report.descriptors.is_none());
}

#[test]
fn a_pmap_payload_never_uses_the_lsch_count() {
    let payload = pmap_payload(&[(1, vec![0x41; 12]), (0x100, vec![0x42; 20])], false);
    let report = parse(&payload).unwrap();
    assert_eq!(report.family, Family::Pmap);
    assert!(report.descriptors.is_none());
    let table = report.blocks.expect("a block table");
    assert_eq!(table.blocks.len(), 2);
    assert_eq!(table.blocks[0].offset, 0x10);
    assert!(table.offset_matches);
    assert!(table.padding_ok);
    assert_eq!(table.predicted_first_offset, report.first_offset);
}

#[test]
fn an_unaligned_pmap_last_block_is_predicted_without_padding() {
    // 12 bytes is not a multiple of 16, so padding after the last block would
    // move the first section.
    let payload = pmap_payload(&[(1, vec![0x41; 12]), (0x100, vec![0x42; 20])], false);
    let report = parse(&payload).unwrap();
    let table = report.blocks.expect("a block table");
    assert_ne!(report.first_offset % 16, 0);
    assert_eq!(table.predicted_first_offset, report.first_offset);
    // The padded-after-last model would predict a larger offset.
    let last = table.blocks.last().unwrap();
    let padded = table.predicted_first_offset.next_multiple_of(16);
    assert_ne!(u64::from(padded), u64::from(report.first_offset));
    assert_eq!(last.len, 20);
}

#[test]
fn a_misaligned_block_start_is_reported() {
    let mut payload = pmap_payload(&[(1, vec![0x41; 12]), (0x100, vec![0x42; 20])], false);
    // Move the second block by one byte in the directory.
    let first = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as usize;
    let pmap_body = first + 8;
    let second_block = pmap_body + 0x10 + 16;
    let offset = u32::from_be_bytes(
        payload[second_block + 4..second_block + 8]
            .try_into()
            .unwrap(),
    );
    payload[second_block + 4..second_block + 8].copy_from_slice(&(offset + 1).to_be_bytes());
    let report = parse(&payload).unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("not 16-byte aligned")),
        "{:?}",
        report.issues
    );
}

#[test]
fn a_directory_past_the_body_is_an_error() {
    let mut payload = pmap_payload(&[(1, vec![0x41; 12])], false);
    let first = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as usize;
    // Count of 40 blocks with no room for them.
    payload[first + 8 + 8..first + 8 + 10].copy_from_slice(&40u16.to_be_bytes());
    assert!(parse(&payload).is_err());
}

#[test]
fn a_psch_table_that_tiles_is_reported() {
    let payload = pmap_payload(&[(1, vec![0x41; 12]), (0x100, vec![0x42; 20])], true);
    let report = parse(&payload).unwrap();
    let table = report.section_table.expect("a PSCH table");
    assert_eq!(table.count, 2);
    assert!(table.tiling_ok, "{:?}", table.tiling_error);
    assert!(report.sections.iter().any(|s| &s.tag == b"STDN"));
}

#[test]
fn a_psch_gap_is_reported() {
    let mut payload = pmap_payload(&[(1, vec![0x41; 12]), (0x100, vec![0x42; 20])], false);
    let first = u32::from_be_bytes(payload[4..8].try_into().unwrap()) as usize;
    // The PSCH body follows the PMAP section; its first value offset is at
    // body + 4 + 4.
    let pmap_body_len = (payload[first + 4..first + 8]
        .try_into()
        .map(u32::from_be_bytes)
        .unwrap()) as usize;
    let psch_at = first + pmap_body_len;
    let value_offset = psch_at + 8 + 4 + 4;
    let offset = u32::from_be_bytes(payload[value_offset..value_offset + 4].try_into().unwrap());
    payload[value_offset..value_offset + 4].copy_from_slice(&(offset + 8).to_be_bytes());
    let report = parse(&payload).unwrap();
    let table = report.section_table.expect("a PSCH table");
    assert!(!table.tiling_ok);
    assert!(table.tiling_error.is_some());
}

#[test]
fn an_unknown_first_tag_is_reported_as_other() {
    let mut payload = b"PSIN".to_vec();
    payload.extend_from_slice(&0x08u32.to_be_bytes());
    payload.extend_from_slice(&section(b"ZZZZ", &[0u8; 8]));
    add_chks(&mut payload);
    let report = parse(&payload).unwrap();
    assert_eq!(report.family, Family::Other);
    assert_eq!(report.first_tag, *b"ZZZZ");
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.contains("no supported grammar"))
    );
    assert_eq!(report.checksum, Checksum::Verified);
}

#[test]
fn a_corrupted_payload_fails_the_checksum() {
    let mut payload = pmap_payload(&[(1, vec![0x41; 12])], false);
    payload[0x10] ^= 0x01;
    let report = parse(&payload).unwrap();
    assert!(matches!(report.checksum, Checksum::Mismatch { .. }));
}

#[test]
fn a_truncated_section_is_an_error() {
    let mut payload = b"PSIN".to_vec();
    payload.extend_from_slice(&0x08u32.to_be_bytes());
    payload.extend_from_slice(b"LSCH");
    payload.extend_from_slice(&0x100u32.to_be_bytes());
    assert!(parse(&payload).is_err());
}

#[test]
fn a_section_walk_that_does_not_end_at_the_payload_is_an_error() {
    let mut payload = b"PSIN".to_vec();
    payload.extend_from_slice(&0x08u32.to_be_bytes());
    payload.extend_from_slice(&section(b"ZZZZ", &[0u8; 8]));
    payload.extend_from_slice(&[0x00; 4]);
    assert!(parse(&payload).is_err());
}

#[test]
fn an_excessive_descriptor_count_is_bounded() {
    let mut payload = b"PSIN".to_vec();
    payload.extend_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
    payload.resize(0x40, 0);
    // The walk fails before the descriptor search, which keeps it bounded.
    assert!(parse(&payload).is_err());
}

#[test]
fn the_id1_block_is_exposed_without_text() {
    let payload = pmap_payload(
        &[(1, b"alpha\0beta\0".to_vec()), (0x100, vec![0x42; 20])],
        false,
    );
    let report = parse(&payload).unwrap();
    let id1 = report.id1_block.expect("the id-1 block");
    assert_eq!(id1.len, 11);
    assert!(id1.nul_terminated);
}

#[test]
fn the_checksum_zeroes_only_the_two_header_words() {
    let mut payload = vec![0x11u8; 32];
    let zero_at = 8;
    let with_words = checksum_with_zeroed(&payload, zero_at);
    payload[zero_at..zero_at + 8].copy_from_slice(&[0u8; 8]);
    assert_eq!(with_words, checksum_with_zeroed(&payload, zero_at));
}
