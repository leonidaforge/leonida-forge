//! Tests build every byte they read. No game payload is used.

use super::*;

/// One structure record as the fixture declares it.
type StructureRecord = (u32, u32, u32, u32, Vec<Field>);
/// One enum record as the fixture declares it.
type EnumRecord = (u32, u32, Vec<(u64, u32)>);

/// Builds an `LSCH`-family container from a schema, a block table and a
/// resource header.
struct Builder {
    structures: Vec<StructureRecord>,
    enums: Vec<EnumRecord>,
    blocks: Vec<(u32, Vec<u8>)>,
    header: Option<(u32, u8)>,
}

impl Builder {
    fn new() -> Self {
        Self {
            structures: Vec::new(),
            enums: Vec::new(),
            blocks: Vec::new(),
            header: None,
        }
    }

    fn structure(mut self, name: u32, size: u32, fields: Vec<Field>) -> Self {
        self.structures
            .push((name, 0x5a5a_5a5a, 0x300, size, fields));
        self
    }

    fn enumeration(mut self, name: u32, values: Vec<(u64, u32)>) -> Self {
        self.enums.push((name, 0x1234, values));
        self
    }

    fn block(mut self, id: u32, bytes: Vec<u8>) -> Self {
        self.blocks.push((id, bytes));
        self
    }

    fn header(mut self, roots: u32, object_type: u8) -> Self {
        self.header = Some((roots, object_type));
        self
    }

    fn build(&self) -> Vec<u8> {
        // Block area: the table, its terminator, then the blocks.
        let mut body = vec![0u8; 8];
        for (id, bytes) in &self.blocks {
            body.extend_from_slice(&id.to_le_bytes());
            body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            body.extend_from_slice(&[0xAA; 8]);
        }
        body.extend_from_slice(&[0x70; 8]);
        assert_eq!(body.len(), 0x10 + 16 * self.blocks.len());
        for (_, bytes) in &self.blocks {
            body.extend_from_slice(bytes);
            while !body.len().is_multiple_of(16) {
                body.push(0);
            }
        }
        let body_len = body.len();
        body[0..4].copy_from_slice(b"PSIN");
        body[4..8].copy_from_slice(&(body_len as u32).to_be_bytes());
        let mut payload = body;

        // LSCH: every structure record, then every field record.
        let mut schema = Vec::new();
        for (name, signature, flags, size, fields) in &self.structures {
            schema.extend_from_slice(&name.to_le_bytes());
            schema.extend_from_slice(&signature.to_le_bytes());
            schema.extend_from_slice(&flags.to_le_bytes());
            schema.extend_from_slice(&0u32.to_le_bytes());
            schema.extend_from_slice(&[0xAA; 8]);
            schema.extend_from_slice(&size.to_le_bytes());
            schema.extend_from_slice(&0u16.to_le_bytes());
            schema.extend_from_slice(&(fields.len() as u16).to_le_bytes());
        }
        for (_, _, _, _, fields) in &self.structures {
            for field in fields {
                schema.extend_from_slice(&field.name.to_le_bytes());
                schema.extend_from_slice(&field.offset.to_le_bytes());
                schema.extend_from_slice(&field.type_word.to_le_bytes());
                schema.extend_from_slice(&field.auxiliary.to_le_bytes());
            }
        }
        payload.extend_from_slice(b"LSCH");
        payload.extend_from_slice(&((schema.len() + 8) as u32).to_be_bytes());
        payload.extend_from_slice(&schema);

        let mut enums = Vec::new();
        for (name, signature, values) in &self.enums {
            enums.extend_from_slice(&name.to_le_bytes());
            enums.extend_from_slice(&signature.to_le_bytes());
            enums.extend_from_slice(&[0xEE; 8]);
            enums.extend_from_slice(&(values.len() as u32).to_le_bytes());
            enums.extend_from_slice(&0u32.to_le_bytes());
        }
        for (_, _, values) in &self.enums {
            for (value, name) in values {
                enums.extend_from_slice(&value.to_le_bytes());
                enums.extend_from_slice(&name.to_le_bytes());
                enums.extend_from_slice(&0u32.to_le_bytes());
            }
        }
        payload.extend_from_slice(b"LENM");
        payload.extend_from_slice(&((enums.len() + 8) as u32).to_be_bytes());
        payload.extend_from_slice(&enums);

        // ANSI: empty sections keep the walk realistic.
        for tag in [b"LSNS", b"LGID"] {
            payload.extend_from_slice(tag);
            payload.extend_from_slice(&8u32.to_be_bytes());
        }

        let mut header = vec![0u8; 0x40];
        header[0..4].copy_from_slice(b"0DRP");
        if let Some((roots, object_type)) = self.header {
            header[4] = object_type;
            header[0x10..0x14].copy_from_slice(&roots.to_le_bytes());
            header[0x38..0x3a].copy_from_slice(&(self.structures.len() as u16).to_le_bytes());
            header[0x3a..0x3c].copy_from_slice(&(self.enums.len() as u16).to_le_bytes());
            header[0x3c..0x3e].copy_from_slice(&(self.blocks.len() as u16).to_le_bytes());
        }
        payload.extend_from_slice(b"LRSC");
        payload.extend_from_slice(&((header.len() + 8) as u32).to_be_bytes());
        payload.extend_from_slice(&header);

        // CHKS: the total length, the checksum, and the `zppp` tag.
        let chks = payload.len();
        payload.extend_from_slice(b"CHKS");
        payload.extend_from_slice(&20u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(b"zppp");
        let total = payload.len();
        payload[chks + 8..chks + 12].copy_from_slice(&(total as u32).to_be_bytes());
        let checksum = super::super::checksum_with_zeroed(&payload, chks + 8);
        payload[chks + 12..chks + 16].copy_from_slice(&checksum.to_be_bytes());
        payload
    }
}

fn field(name: u32, offset: u32, code: u16, auxiliary: u32) -> Field {
    Field {
        name,
        offset,
        type_word: u32::from(code),
        auxiliary,
    }
}

/// A field whose type word carries a qualifier, as an array's element index
/// does.
fn qualified(name: u32, offset: u32, code: u16, upper: u16, auxiliary: u32) -> Field {
    Field {
        name,
        offset,
        type_word: (u32::from(upper) << 16) | u32::from(code),
        auxiliary,
    }
}

/// A reference word for `block` (counted from one) at `offset`.
fn reference(block: u32, offset: u32) -> u64 {
    (u64::from(offset) << 20) | u64::from(block)
}

const VECTOR: u32 = 0x1111_1111;
const ROOT: u32 = 0x3333_3333;
const ENUMERATION: u32 = 0x7777_7777;

/// Two records of a two-field structure, a root record that embeds the first,
/// references it and arrays over a hash pool, and an enumeration.
fn sample() -> Vec<u8> {
    let mut first = Vec::new();
    for (value, hash) in [(1.5f32, 0xdead_beefu32), (2.5, 0xcafe_babe)] {
        first.extend_from_slice(&value.to_le_bytes());
        first.extend_from_slice(&hash.to_le_bytes());
    }
    let mut root = Vec::new();
    root.extend_from_slice(&3.5f32.to_le_bytes());
    root.extend_from_slice(&0x0bad_f00du32.to_le_bytes());
    root.extend_from_slice(&reference(1, 0).to_le_bytes());
    // Array: reference to block 3, two elements, capacity two.
    root.extend_from_slice(&reference(3, 0).to_le_bytes());
    root.extend_from_slice(&2u16.to_le_bytes());
    root.extend_from_slice(&2u16.to_le_bytes());
    root.extend_from_slice(&0u32.to_le_bytes());
    let hashes: Vec<u8> = [0xaaaa_aaaa_u32, 0xbbbb_bbbb]
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    Builder::new()
        .structure(
            VECTOR,
            8,
            vec![
                field(0xaaaa_0001, 0, TYPE_F32, 0),
                field(0xaaaa_0002, 4, TYPE_HASH32, 0),
            ],
        )
        .structure(
            ROOT,
            32,
            vec![
                field(0xbbbb_0001, 0, TYPE_STRUCTURE, VECTOR),
                field(0xbbbb_0002, 8, TYPE_REFERENCE, 0),
                qualified(0xbbbb_0003, 16, TYPE_ARRAY, 3, 0),
                field(DESCRIPTOR_NAME, 0, TYPE_HASH32, 0),
            ],
        )
        .enumeration(ENUMERATION, vec![(0, 0x0100), (7, 0x0200)])
        .block(VECTOR, first)
        .block(ROOT, root)
        .block(0x4a, hashes)
        .header(1, 0x7a)
        .build()
}

#[test]
fn decodes_the_schema() {
    let document = decode(&sample()).expect("decodes");
    assert_eq!(document.structures.len(), 2);
    assert_eq!(document.structures[0].name, VECTOR);
    assert_eq!(document.structures[0].size, 8);
    assert_eq!(document.structures[0].fields.len(), 2);
    assert_eq!(document.structures[1].fields[2].code(), TYPE_ARRAY);
    assert_eq!(document.structures[1].fields[2].upper(), 3);
    assert_eq!(document.enums.len(), 1);
    assert_eq!(document.enums[0].values.len(), 2);
    assert_eq!(document.blocks.len(), 3);
}

#[test]
fn decodes_records_and_values() {
    let document = decode(&sample()).expect("decodes");
    let Content::Records {
        structure,
        stride,
        total,
        records,
    } = &document.blocks[0].content
    else {
        panic!("block 1 is a structure block");
    };
    assert_eq!(*structure, VECTOR);
    assert_eq!(*stride, 8);
    assert_eq!(*total, 2);
    // Offsets are container-relative, so the second record follows the first
    // by the structure's size.
    assert_eq!(records[1].offset, records[0].offset + 8);
    assert_eq!(records[1].fields[0].value, Value::Scalar(Scalar::F32(2.5)));
    assert_eq!(
        records[1].fields[1].value,
        Value::Scalar(Scalar::Hash32(0xcafe_babe))
    );

    let Content::Records { records, .. } = &document.blocks[1].content else {
        panic!("block 2 is a structure block");
    };
    let record = &records[0];
    let Value::Structure(embedded) = &record.fields[0].value else {
        panic!("the first field embeds a structure");
    };
    assert_eq!(embedded.structure, VECTOR);
    assert_eq!(embedded.fields[0].value, Value::Scalar(Scalar::F32(3.5)));
    let Value::Reference(reference) = &record.fields[1].value else {
        panic!("the second field is a reference");
    };
    assert_eq!(reference.word, super::tests::reference(1, 0));
    assert_eq!(
        reference.target,
        Some(Target {
            block: 1,
            record: 0,
            offset: 0,
            structure: VECTOR,
        })
    );
    let Value::Array(array) = &record.fields[2].value else {
        panic!("the third field is an array");
    };
    assert_eq!(array.span.count, 2);
    assert_eq!(
        array.elements,
        Ok(ArrayElements::Hash32 {
            values: vec![0xaaaa_aaaa, 0xbbbb_bbbb]
        })
    );
}

#[test]
fn keeps_descriptor_fields_out_of_the_decoded_values() {
    let document = decode(&sample()).expect("decodes");
    let Content::Records { records, .. } = &document.blocks[1].content else {
        panic!("block 2 is a structure block");
    };
    // The descriptor is a field of the schema, but it names an element rather
    // than storage, so it reports its type and reads no bytes.
    let descriptor = records[0]
        .field(DESCRIPTOR_NAME)
        .expect("the descriptor is reported");
    assert!(descriptor.field.is_descriptor());
    assert_eq!(descriptor.extent, None);
    assert_eq!(
        descriptor.value,
        Value::Descriptor {
            code: TYPE_HASH32,
            upper: 0,
            auxiliary: 0,
        }
    );
}

#[test]
fn decodes_the_hash_pool() {
    let document = decode(&sample()).expect("decodes");
    assert_eq!(
        document.blocks[2].content,
        Content::Pool {
            kind: PoolKind::Hash32,
            total: 2,
            entries: vec![
                PoolEntry::Hash32(0xaaaa_aaaa),
                PoolEntry::Hash32(0xbbbb_bbbb),
            ],
        }
    );
}

#[test]
fn reports_the_copied_header() {
    let document = decode(&sample()).expect("decodes");
    assert_eq!(
        document.header,
        Some(Header {
            object_type: 0x7a,
            roots: 1,
            structures: 2,
            enums: 1,
            blocks: 3,
        })
    );
    assert_eq!(document.header_matches(), Some(true));
    assert!(document.issues.is_empty(), "{:?}", document.issues);
    assert_eq!(document.roots(), vec![ROOT]);
}

#[test]
fn resolves_enumeration_members() {
    let mut record = Vec::new();
    record.extend_from_slice(&7u32.to_le_bytes());
    let payload = Builder::new()
        .structure(
            ROOT,
            4,
            vec![field(0xcccc_0001, 0, TYPE_ENUM32, ENUMERATION)],
        )
        .enumeration(ENUMERATION, vec![(0, 0x0100), (7, 0x0200)])
        .block(ROOT, record)
        .build();
    let document = decode(&payload).expect("decodes");
    let Content::Records { records, .. } = &document.blocks[0].content else {
        panic!("a structure block");
    };
    let Value::Enum(value) = &records[0].fields[0].value else {
        panic!("an enum value");
    };
    assert!(value.defined);
    assert_eq!(value.value, 7);
    assert_eq!(
        value.matches,
        vec![EnumValue {
            value: 7,
            name: 0x0200
        }]
    );
}

#[test]
fn refuses_a_payload_that_is_not_psin() {
    assert_eq!(decode(b"RBF0\x00\x00\x00\x00"), Err(Error::NotPsin));
    assert_eq!(decode(b""), Err(Error::NotPsin));
}

#[test]
fn refuses_the_pmap_family_by_name() {
    let mut payload = sample();
    // Rename the first section so the family is `PMAP`.
    let first = u32::from_be_bytes(payload[4..8].try_into().expect("4 bytes")) as usize;
    payload[first..first + 4].copy_from_slice(b"PMAP");
    let error = decode(&payload).expect_err("the family is not decoded");
    match error {
        Error::Unsupported { family, first_tag } => {
            assert_eq!(family, "PMAP");
            assert_eq!(first_tag, "PMAP");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn refuses_a_structure_record_without_its_marker() {
    let mut payload = sample();
    let first = u32::from_be_bytes(payload[4..8].try_into().expect("4 bytes")) as usize;
    payload[first + 8 + 16] = 0;
    let error = decode(&payload).expect_err("the marker is part of the layout");
    assert!(matches!(error, Error::Malformed(_)), "{error}");
}

#[test]
fn refuses_a_truncated_payload() {
    let payload = sample();
    for cut in [4, 16, 24, 40, 64] {
        let error = decode(&payload[..cut.min(payload.len())])
            .expect_err("a truncated payload does not decode");
        assert!(
            matches!(
                error,
                Error::NotPsin | Error::Malformed(_) | Error::Framing(_) | Error::Limit(_)
            ),
            "{error}"
        );
    }
}

#[test]
fn refuses_a_block_past_the_section() {
    let mut payload = sample();
    // The first block entry's length word is at 12.
    payload[12..16].copy_from_slice(&0xffff_u32.to_le_bytes());
    let error = decode(&payload).expect_err("the block cannot fit");
    assert!(matches!(error, Error::Malformed(_)), "{error}");
}

#[test]
fn refuses_a_structure_that_embeds_itself() {
    let mut record = vec![0u8; 4];
    record.extend_from_slice(&0xaaaa_aaaa_u32.to_le_bytes());
    let payload = Builder::new()
        .structure(ROOT, 8, vec![field(0xdddd_0001, 0, TYPE_STRUCTURE, ROOT)])
        .block(ROOT, record)
        .build();
    let error = decode(&payload).expect_err("an embedding cycle is malformed");
    assert!(matches!(error, Error::Malformed(_)), "{error}");
}

#[test]
fn stops_at_the_node_limit() {
    let payload = sample();
    let limits = Limits {
        nodes: 1,
        ..Limits::default()
    };
    let error = decode_with(&payload, limits).expect_err("the limit stops the read");
    assert!(matches!(error, Error::Limit(_)), "{error}");
}

#[test]
fn stops_at_the_depth_limit() {
    let payload = sample();
    let limits = Limits {
        depth: 0,
        ..Limits::default()
    };
    let error = decode_with(&payload, limits).expect_err("the depth limit stops the read");
    assert!(matches!(error, Error::Limit(_)), "{error}");
}

#[test]
fn truncates_an_oversized_block_and_says_so() {
    let payload = sample();
    let limits = Limits {
        records: 1,
        ..Limits::default()
    };
    let document = decode_with(&payload, limits).expect("decodes the first record");
    let Content::Records { total, records, .. } = &document.blocks[0].content else {
        panic!("a structure block");
    };
    assert_eq!(*total, 2);
    assert_eq!(records.len(), 1);
    assert!(
        document
            .issues
            .iter()
            .any(|issue| issue.contains("records")),
        "{:?}",
        document.issues
    );
}

#[test]
fn an_array_that_names_more_elements_than_it_holds_is_reported() {
    let mut root = Vec::new();
    root.extend_from_slice(&reference(2, 0).to_le_bytes());
    root.extend_from_slice(&99u16.to_le_bytes());
    root.extend_from_slice(&99u16.to_le_bytes());
    root.extend_from_slice(&0u32.to_le_bytes());
    let payload = Builder::new()
        .structure(
            ROOT,
            16,
            vec![
                qualified(0xeeee_0001, 0, TYPE_ARRAY, 1, 0),
                field(DESCRIPTOR_NAME, 0, TYPE_HASH32, 0),
            ],
        )
        .block(ROOT, root)
        .block(0x4a, vec![0x11, 0x22, 0x33, 0x44])
        .build();
    let document = decode(&payload).expect("the array header is readable");
    let Content::Records { records, .. } = &document.blocks[0].content else {
        panic!("a structure block");
    };
    let Value::Array(array) = &records[0].fields[0].value else {
        panic!("an array");
    };
    // The span is bounded by the pool, so only its one element is decoded.
    assert_eq!(
        array.elements,
        Ok(ArrayElements::Hash32 {
            values: vec![0x4433_2211]
        })
    );
}

#[test]
fn an_array_with_unequal_lengths_is_refused() {
    let mut root = Vec::new();
    root.extend_from_slice(&reference(2, 0).to_le_bytes());
    root.extend_from_slice(&1u16.to_le_bytes());
    root.extend_from_slice(&4u16.to_le_bytes());
    root.extend_from_slice(&0u32.to_le_bytes());
    let payload = Builder::new()
        .structure(
            ROOT,
            16,
            vec![
                qualified(0xeeee_0001, 0, TYPE_ARRAY, 1, 0),
                field(DESCRIPTOR_NAME, 0, TYPE_HASH32, 0),
            ],
        )
        .block(ROOT, root)
        .block(0x4a, vec![0x11, 0x22, 0x33, 0x44])
        .build();
    let document = decode(&payload).expect("the header is readable");
    let Content::Records { records, .. } = &document.blocks[0].content else {
        panic!("a structure block");
    };
    let Value::Array(array) = &records[0].fields[0].value else {
        panic!("an array");
    };
    assert!(array.elements.is_err());
}

#[test]
fn a_reference_outside_the_table_is_reported_not_followed() {
    let mut root = Vec::new();
    root.extend_from_slice(&reference(9, 0).to_le_bytes());
    let payload = Builder::new()
        .structure(ROOT, 8, vec![field(0xffff_0001, 0, TYPE_REFERENCE, 0)])
        .block(ROOT, root)
        .build();
    let document = decode(&payload).expect("decodes");
    let Content::Records { records, .. } = &document.blocks[0].content else {
        panic!("a structure block");
    };
    let Value::Reference(reference) = &records[0].fields[0].value else {
        panic!("a reference");
    };
    assert_eq!(reference.target, None);
    assert_eq!(reference.fault, Some(ReferenceFault::BlockOutside));
}

#[test]
fn an_unknown_type_keeps_its_bytes() {
    let mut record = vec![0u8; 8];
    record[..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let payload = Builder::new()
        .structure(ROOT, 8, vec![field(0x1234_0001, 0, 0x9f, 0x0042)])
        .block(ROOT, record)
        .build();
    let document = decode(&payload).expect("decodes");
    let Content::Records { records, .. } = &document.blocks[0].content else {
        panic!("a structure block");
    };
    assert_eq!(
        records[0].fields[0].value,
        Value::Unresolved {
            code: 0x9f,
            upper: 0,
            auxiliary: 0x0042,
            raw: vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0],
        }
    );
    assert_eq!(records[0].fields[0].extent, Some(8));
}

#[test]
fn an_unknown_block_type_is_reported() {
    let payload = Builder::new()
        .structure(ROOT, 4, vec![field(0x1111_0001, 0, TYPE_U32, 0)])
        .block(0x9999_9999, vec![0u8; 16])
        .build();
    let document = decode(&payload).expect("the container decodes");
    let Content::Unsupported(reason) = &document.blocks[0].content else {
        panic!("the block is not decoded");
    };
    assert!(reason.contains("0x99999999"), "{reason}");
}

#[test]
fn a_record_count_that_does_not_fit_its_structure_is_reported() {
    let payload = Builder::new()
        .structure(ROOT, 8, vec![field(0x1111_0001, 0, TYPE_U32, 0)])
        .block(ROOT, vec![0u8; 12])
        .build();
    let document = decode(&payload).expect("the container decodes");
    assert!(matches!(
        document.blocks[0].content,
        Content::Unsupported(_)
    ));
}

#[test]
fn half_precision_conversion_matches_known_values() {
    assert_eq!(half_to_f32(0x0000), 0.0);
    assert_eq!(half_to_f32(0x3c00), 1.0);
    assert_eq!(half_to_f32(0xc000), -2.0);
    assert_eq!(half_to_f32(0x7c00), f32::INFINITY);
    assert_eq!(half_to_f32(0x0001), 5.960_464_5e-8);
    assert_eq!(half_to_f32(0x3555), 0.333_251_95);
}
