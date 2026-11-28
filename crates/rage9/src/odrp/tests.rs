//! Synthetic documents for the `0DRP` resource form.
//!
//! Every fixture is built here rather than taken from a game resource: the
//! layout the decoder reads is exercised by the builder, and a change to the
//! decoder that stops reading real resources shows up as a fixture that no
//! longer decodes.

use super::*;

const SYSTEM_BASE: u64 = 0x5000_0000;
const GRAPHICS_BASE: u64 = 0x6000_0000;

fn system_pointer(offset: u32) -> u64 {
    SYSTEM_BASE | u64::from(offset)
}

fn graphics_pointer(offset: u32) -> u64 {
    GRAPHICS_BASE | u64::from(offset)
}

struct FieldSpec {
    name: u32,
    offset: u32,
    type_word: u32,
    auxiliary: u32,
}

fn field(name: u32, offset: u32, type_word: u32, auxiliary: u32) -> FieldSpec {
    FieldSpec {
        name,
        offset,
        type_word,
        auxiliary,
    }
}

struct StructureSpec {
    name: u32,
    size: u32,
    flags: u32,
    fields: Vec<FieldSpec>,
}

struct EnumSpec {
    name: u32,
    values: Vec<(u64, u32)>,
}

enum Where {
    System,
    Graphics,
}

enum BlockSpec {
    Records {
        structure: u32,
        records: Vec<Vec<u8>>,
        place: Where,
    },
    Pool {
        type_word: u32,
        bytes: Vec<u8>,
        place: Where,
    },
}

fn records(structure: u32, records: Vec<Vec<u8>>) -> BlockSpec {
    BlockSpec::Records {
        structure,
        records,
        place: Where::System,
    }
}

fn pool(type_word: u32, bytes: Vec<u8>) -> BlockSpec {
    BlockSpec::Pool {
        type_word,
        bytes,
        place: Where::System,
    }
}

/// Builds a system segment around the given tables.
struct Builder {
    system: Vec<u8>,
    graphics: Vec<u8>,
    structures: Vec<StructureSpec>,
    enums: Vec<EnumSpec>,
    blocks: Vec<BlockSpec>,
    roots: u32,
    graphics_pages: u8,
}

impl Builder {
    fn new() -> Self {
        Self {
            system: vec![0; 0x60],
            graphics: Vec::new(),
            structures: Vec::new(),
            enums: Vec::new(),
            blocks: Vec::new(),
            roots: 1,
            graphics_pages: 0,
        }
    }

    fn structure(mut self, structure: StructureSpec) -> Self {
        self.structures.push(structure);
        self
    }

    fn enumeration(mut self, enumeration: EnumSpec) -> Self {
        self.enums.push(enumeration);
        self
    }

    fn block(mut self, block: BlockSpec) -> Self {
        self.blocks.push(block);
        self
    }

    fn graphics_pages(mut self, pages: u8) -> Self {
        self.graphics_pages = pages;
        self
    }

    fn append_system(&mut self, bytes: &[u8]) -> u32 {
        let at = align(self.system.len(), 8);
        self.system.resize(at, 0);
        self.system.extend_from_slice(bytes);
        at as u32
    }

    fn append_graphics(&mut self, bytes: &[u8]) -> u32 {
        let at = align(self.graphics.len(), 8);
        self.graphics.resize(at, 0);
        self.graphics.extend_from_slice(bytes);
        at as u32
    }

    fn build(mut self) -> (Vec<u8>, Vec<u8>) {
        let structures = std::mem::take(&mut self.structures);
        let enums = std::mem::take(&mut self.enums);
        let mut members = Vec::new();
        for structure in &structures {
            if structure.fields.is_empty() {
                members.push(None);
                continue;
            }
            let mut bytes = Vec::with_capacity(structure.fields.len() * 16);
            for field in &structure.fields {
                bytes.extend_from_slice(&field.name.to_le_bytes());
                bytes.extend_from_slice(&field.offset.to_le_bytes());
                bytes.extend_from_slice(&field.type_word.to_le_bytes());
                bytes.extend_from_slice(&field.auxiliary.to_le_bytes());
            }
            members.push(Some(self.append_system(&bytes)));
        }
        let mut structure_bytes = Vec::with_capacity(structures.len() * 32);
        for (structure, member) in structures.iter().zip(&members) {
            structure_bytes.extend_from_slice(&structure.name.to_le_bytes());
            structure_bytes.extend_from_slice(&0xAABB_CCDD_u32.to_le_bytes());
            structure_bytes.extend_from_slice(&structure.flags.to_le_bytes());
            structure_bytes.extend_from_slice(&0_u32.to_le_bytes());
            structure_bytes.extend_from_slice(&member.map_or(0, system_pointer).to_le_bytes());
            structure_bytes.extend_from_slice(&structure.size.to_le_bytes());
            structure_bytes.extend_from_slice(&0_u16.to_le_bytes());
            structure_bytes.extend_from_slice(&(structure.fields.len() as u16).to_le_bytes());
        }
        let structure_table = self.append_system(&structure_bytes);

        let mut enum_tables = Vec::new();
        for enumeration in &enums {
            let mut bytes = Vec::with_capacity(enumeration.values.len() * 16);
            for (value, name) in &enumeration.values {
                bytes.extend_from_slice(&value.to_le_bytes());
                bytes.extend_from_slice(&name.to_le_bytes());
                bytes.extend_from_slice(&0_u32.to_le_bytes());
            }
            enum_tables.push(self.append_system(&bytes));
        }
        let mut enum_bytes = Vec::with_capacity(enums.len() * 24);
        for (enumeration, values) in enums.iter().zip(&enum_tables) {
            enum_bytes.extend_from_slice(&enumeration.name.to_le_bytes());
            enum_bytes.extend_from_slice(&0x1122_3344_u32.to_le_bytes());
            enum_bytes.extend_from_slice(&system_pointer(*values).to_le_bytes());
            enum_bytes.extend_from_slice(&(enumeration.values.len() as u32).to_le_bytes());
            enum_bytes.extend_from_slice(&0_u32.to_le_bytes());
        }
        let enum_table = if enums.is_empty() {
            0
        } else {
            self.append_system(&enum_bytes)
        };

        let blocks = std::mem::take(&mut self.blocks);
        let mut layout = Vec::with_capacity(blocks.len());
        for block in &blocks {
            match block {
                BlockSpec::Records {
                    structure,
                    records,
                    place,
                } => {
                    let mut bytes = Vec::new();
                    for record in records {
                        bytes.extend_from_slice(record);
                    }
                    let offset = match place {
                        Where::System => self.append_system(&bytes),
                        Where::Graphics => self.append_graphics(&bytes),
                    };
                    layout.push((*structure, offset, bytes.len() as u32, place));
                }
                BlockSpec::Pool {
                    type_word,
                    bytes,
                    place,
                } => {
                    let offset = match place {
                        Where::System => self.append_system(bytes),
                        Where::Graphics => self.append_graphics(bytes),
                    };
                    layout.push((*type_word, offset, bytes.len() as u32, place));
                }
            }
        }
        let mut block_bytes = Vec::with_capacity(layout.len() * 16);
        for (type_word, offset, len, place) in &layout {
            block_bytes.extend_from_slice(&type_word.to_le_bytes());
            block_bytes.extend_from_slice(&len.to_le_bytes());
            let pointer = match place {
                Where::System => system_pointer(*offset),
                Where::Graphics => graphics_pointer(*offset),
            };
            block_bytes.extend_from_slice(&pointer.to_le_bytes());
        }
        let block_table = self.append_system(&block_bytes);

        let pages = 1 + usize::from(self.graphics_pages);
        let mut map = vec![0u8; 16 + 8 * pages];
        map[8] = 1;
        map[9] = self.graphics_pages;
        let page_map = self.append_system(&map);

        let system_pages = 1u8;
        let mut header = self.system;
        header[0x10..0x14].copy_from_slice(&TAG);
        header[0x14] = 0x7A;
        header[0x08..0x10].copy_from_slice(&system_pointer(page_map).to_le_bytes());
        header[0x20..0x24].copy_from_slice(&self.roots.to_le_bytes());
        header[0x28..0x30].copy_from_slice(&system_pointer(structure_table).to_le_bytes());
        header[0x30..0x38].copy_from_slice(
            &(if enum_table == 0 {
                0
            } else {
                system_pointer(enum_table)
            })
            .to_le_bytes(),
        );
        header[0x38..0x40].copy_from_slice(&system_pointer(block_table).to_le_bytes());
        header[0x40..0x48].copy_from_slice(&system_pointer(0x60).to_le_bytes());
        header[0x48..0x4A].copy_from_slice(&(structures.len() as u16).to_le_bytes());
        header[0x4A..0x4C].copy_from_slice(&(enums.len() as u16).to_le_bytes());
        header[0x4C..0x4E].copy_from_slice(&(layout.len() as u16).to_le_bytes());
        let _ = system_pages;
        (header, self.graphics)
    }
}

fn align(value: usize, unit: usize) -> usize {
    (value + unit - 1) & !(unit - 1)
}

fn decode(system: &[u8], graphics: &[u8]) -> Result<Document, Error> {
    super::decode(system, graphics, &Limits::default())
}

/// A structure of one `u32` field and one text reference, one record, and a
/// text block holding two strings.
fn text_document() -> (Vec<u8>, Vec<u8>) {
    let mut record = Vec::new();
    record.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
    record.extend_from_slice(&0_u32.to_le_bytes());
    record.extend_from_slice(&((6_u64 << 20) | 2).to_le_bytes());

    Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 16,
            flags: 0x300,
            fields: vec![
                field(0xBBBB_0001, 0, 0x15, 0),
                field(0xBBBB_0002, 8, 0x42, 0),
            ],
        })
        .block(records(0xAAAA_0001, vec![record]))
        .block(pool(0x10, b"first\0second\0".to_vec()))
        .build()
}

#[test]
fn decodes_a_record_and_its_text() {
    let (system, graphics) = text_document();
    assert!(is_odrp(&system));
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(document.status(), "decoded", "{:?}", document.issues);
    assert_eq!(document.header.object_type, 0x7A);
    assert_eq!(document.header.structures, 1);
    assert_eq!(document.header.blocks, 2);
    assert_eq!(document.record_count(), 1);
    assert_eq!(document.text_count(), 1);
    assert_eq!(document.roots, vec![1]);
    let Some(Content::Records { records, .. }) = document.blocks.first().map(|b| &b.content) else {
        panic!("the first block holds records");
    };
    let record = &records[0];
    assert_eq!(
        record.fields[0].value,
        Value::Scalar(Scalar::U32(0x1234_5678))
    );
    let Value::Text(text) = &record.fields[1].value else {
        panic!("the second field is a text reference");
    };
    assert_eq!(text.text.as_deref(), Ok("second"));
}

#[test]
fn a_record_without_the_text_block_keeps_the_reference_but_is_partial() {
    let mut record = Vec::new();
    record.extend_from_slice(&0_u64.to_le_bytes());
    record.extend_from_slice(&((5_u64 << 20) | 9).to_le_bytes());
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 16,
            flags: 0x300,
            fields: vec![field(0xBBBB_0002, 8, 0x42, 0)],
        })
        .block(records(0xAAAA_0001, vec![record]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(document.status(), "partial");
    assert_eq!(document.unresolved_references, 1);
}

#[test]
fn an_embedded_structure_and_an_inline_array_are_decoded() {
    // Outer: an embedded `inner` at offset 0 and an inline array of two `inner`
    // records at offset 8.
    let mut record = Vec::new();
    record.extend_from_slice(&1_u32.to_le_bytes());
    record.extend_from_slice(&2_u32.to_le_bytes());
    record.extend_from_slice(&3_u32.to_le_bytes());
    record.extend_from_slice(&4_u32.to_le_bytes());
    record.extend_from_slice(&5_u32.to_le_bytes());
    record.extend_from_slice(&6_u32.to_le_bytes());
    record.resize(32, 0);
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 32,
            flags: 0x300,
            fields: vec![
                field(0xBBBB_0005, 0, 0x05, 0xAAAA_0002),
                field(0xBBBB_0001, 0, 0x15, 0),
                field(0x100, 0, 0x05, 0xAAAA_0002),
                field(0xBBBB_0002, 8, 0x0002_0050, 2),
            ],
        })
        .structure(StructureSpec {
            name: 0xAAAA_0002,
            size: 8,
            flags: 0x200,
            fields: vec![
                field(0xBBBB_0003, 0, 0x15, 0),
                field(0xBBBB_0004, 4, 0x15, 0),
            ],
        })
        .block(records(0xAAAA_0001, vec![record]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(document.status(), "decoded", "{:?}", document.issues);
    let Some(Content::Records { records, .. }) = document.blocks.first().map(|b| &b.content) else {
        panic!("records");
    };
    let outer = &records[0];
    assert!(
        matches!(outer.fields[0].value, Value::Structure(_)),
        "{:?}",
        outer.fields[0].value
    );
    assert_eq!(outer.fields[1].extent, Some(8));
    let Value::Array(array) = &outer.fields[3].value else {
        panic!("an inline array: {:?}", outer.fields[3].value);
    };
    let Ok(ArrayElements::Records { records }) = &array.elements else {
        panic!("inline records: {:?}", array.elements);
    };
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].fields[0].value, Value::Scalar(Scalar::U32(5)));
    assert_eq!(document.depth(), 2);
}

#[test]
fn an_array_of_scalars_reads_its_elements() {
    let mut record = Vec::new();
    record.extend_from_slice(&3_u32.to_le_bytes());
    record.extend_from_slice(&3_u32.to_le_bytes());
    record.extend_from_slice(&2_u64.to_le_bytes());
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 16,
            flags: 0x300,
            fields: vec![
                field(0x100, 0, 0x11, 0),
                field(0xBBBB_0001, 0, 0x0000_005c, 0),
            ],
        })
        .block(records(0xAAAA_0001, vec![record]))
        .block(pool(0x11, vec![7, 8, 9]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(
        document.status(),
        "decoded",
        "{:?} unsupported={} unresolved={} truncated={} blocks={:?}",
        document.issues,
        document.unsupported_blocks,
        document.unresolved_references,
        document.truncated,
        document
            .blocks
            .iter()
            .map(|block| (&block.content, block.id))
            .collect::<Vec<_>>()
    );
    let Some(Content::Records { records, .. }) = document.blocks.first().map(|b| &b.content) else {
        panic!("records");
    };
    let Value::Array(array) = &records[0].fields[1].value else {
        panic!("an array");
    };
    let Ok(ArrayElements::Scalars { code, values }) = &array.elements else {
        panic!("scalars: {:?}", array.elements);
    };
    assert_eq!(*code, 0x11);
    assert_eq!(values, &vec![Scalar::U8(7), Scalar::U8(8), Scalar::U8(9)]);
}

#[test]
fn a_map_reports_its_buckets_and_the_entries_they_hold() {
    // A map field and a bucket structure of 16 bytes' prefix and two entries.
    let mut map = Vec::new();
    map.extend_from_slice(&1_u32.to_le_bytes()); // buckets
    map.extend_from_slice(&2_u32.to_le_bytes()); // entries
    map.extend_from_slice(&2_u64.to_le_bytes());
    let bucket = vec![0u8; 32];
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 16,
            flags: 0x300,
            fields: vec![
                field(0x100, 0, 0x4a, 0),
                field(0x100, 0, 0x07, 0),
                field(0xBBBB_0001, 0, 0x75, 0x0001_0000),
            ],
        })
        .structure(StructureSpec {
            name: 0x101,
            size: 32,
            flags: 0x424,
            fields: vec![field(0xBBBB_0002, 0, 0x11, 0)],
        })
        .block(records(0xAAAA_0001, vec![map]))
        .block(records(0x101, vec![bucket]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(document.status(), "decoded", "{:?}", document.issues);
    let Some(Content::Records { records, .. }) = document.blocks.first().map(|b| &b.content) else {
        panic!("records");
    };
    let Value::Map(map) = &records[0].fields[2].value else {
        panic!("a map");
    };
    assert_eq!(map.span.count, 1);
    assert_eq!(map.span.capacity, 2);
    let Ok((structure, records)) = &map.entries else {
        panic!("entries: {:?}", map.entries);
    };
    assert_eq!(*structure, 0x101);
    assert_eq!(records.len(), 1);
}

#[test]
fn a_graphics_block_resolves_through_its_pointer() {
    let (system, graphics) = Builder::new()
        .graphics_pages(1)
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 4,
            flags: 0x300,
            fields: vec![field(0xBBBB_0001, 0, 0x15, 0)],
        })
        .block(BlockSpec::Records {
            structure: 0xAAAA_0001,
            records: vec![9_u32.to_le_bytes().to_vec()],
            place: Where::Graphics,
        })
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(document.status(), "decoded", "{:?}", document.issues);
    let block = &document.blocks[0];
    assert_eq!(block.segment, Segment::Graphics);
    assert_eq!(document.header.graphics_pages, 1);
}

#[test]
fn a_short_segment_is_not_a_document() {
    assert_eq!(decode(&[0u8; 16], &[]).unwrap_err(), Error::NotOdrp);
    let (system, graphics) = text_document();
    assert!(!is_odrp(&system[..0x13]));
    assert!(matches!(
        decode(&system[..0x30], &graphics).unwrap_err(),
        Error::Malformed(_)
    ));
}

#[test]
fn a_segment_without_the_tag_is_not_a_document() {
    let (mut system, graphics) = text_document();
    system[0x10..0x14].copy_from_slice(b"PSIN");
    assert!(!is_odrp(&system));
    assert_eq!(decode(&system, &graphics).unwrap_err(), Error::NotOdrp);
    let _ = graphics;
}

#[test]
fn a_block_outside_its_segment_is_refused() {
    let (mut system, graphics) = text_document();
    let table = (u64_at(&system, 0x38).expect("a block table pointer") & 0x0FFF_FFFF) as usize;
    let len = u32_at(&system, table + 4).expect("a length");
    system[table + 4..table + 8].copy_from_slice(&(len + 0x1000).to_le_bytes());
    assert!(matches!(
        decode(&system, &graphics).unwrap_err(),
        Error::Malformed(_)
    ));
}

#[test]
fn an_unknown_block_type_is_partial() {
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 4,
            flags: 0x300,
            fields: vec![field(0xBBBB_0001, 0, 0x15, 0)],
        })
        .block(records(0xAAAA_0001, vec![1_u32.to_le_bytes().to_vec()]))
        .block(pool(0x9999, vec![0, 0, 0, 0]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(
        document.status(),
        "partial",
        "unsupported={} unresolved={} issues={:?}",
        document.unsupported_blocks,
        document.unresolved_references,
        document.issues
    );
    assert_eq!(document.unsupported_blocks, 1);
    assert!(
        document.blocks.iter().any(|block| match &block.content {
            Content::Unsupported(reason) => reason.contains("9999"),
            _ => false,
        }),
        "{:?}",
        document.blocks
    );
}

#[test]
fn an_unknown_field_type_keeps_its_bytes() {
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 8,
            flags: 0x300,
            fields: vec![field(0xBBBB_0001, 0, 0x0F4D, 0)],
        })
        .block(records(0xAAAA_0001, vec![vec![1, 2, 3, 4, 5, 6, 7, 8]]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(document.status(), "decoded", "{:?}", document.issues);
    let Some(Content::Records { records, .. }) = document.blocks.first().map(|b| &b.content) else {
        panic!("records");
    };
    let Value::Unresolved { code, raw, .. } = &records[0].fields[0].value else {
        panic!("an unresolved value: {:?}", records[0].fields[0].value);
    };
    assert_eq!(*code, 0x0F4D);
    assert_eq!(raw, &vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn a_structure_that_embeds_itself_is_refused() {
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 4,
            flags: 0x300,
            fields: vec![field(0xBBBB_0009, 0, 0x05, 0xAAAA_0001)],
        })
        .block(records(0xAAAA_0001, vec![vec![0, 0, 0, 0]]))
        .build();
    assert!(matches!(
        decode(&system, &graphics).unwrap_err(),
        Error::Malformed(_)
    ));
}

#[test]
fn a_count_past_the_limit_is_refused() {
    let mut system = Builder::new().build().0;
    system[0x48..0x4A].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(
        decode(&system, &[]).unwrap_err(),
        Error::Limit(_) | Error::Malformed(_)
    ));
}

#[test]
fn a_record_limit_stops_the_decode() {
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 4,
            flags: 0x300,
            fields: vec![field(0xBBBB_0001, 0, 0x15, 0)],
        })
        .block(records(
            0xAAAA_0001,
            (0..8)
                .map(|value| (value as u32).to_le_bytes().to_vec())
                .collect(),
        ))
        .build();
    let limits = Limits {
        records: 2,
        ..Limits::default()
    };
    let document = super::decode(&system, &graphics, &limits).expect("a document");
    assert_eq!(document.status(), "partial");
    assert!(document.truncated);
    assert_eq!(document.record_count(), 2);
    let Some(Content::Records { total, .. }) = document.blocks.first().map(|b| &b.content) else {
        panic!("records");
    };
    assert_eq!(*total, 8);
}

#[test]
fn an_enumeration_names_its_members() {
    let (system, graphics) = Builder::new()
        .enumeration(EnumSpec {
            name: 0xCCCC_0001,
            values: vec![(0, 0xDDDD_0001), (1, 0xDDDD_0002)],
        })
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 4,
            flags: 0x300,
            fields: vec![field(0xBBBB_0001, 0, 0x62, 0xCCCC_0001)],
        })
        .block(records(0xAAAA_0001, vec![1_u32.to_le_bytes().to_vec()]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(document.status(), "decoded", "{:?}", document.issues);
    assert_eq!(document.enums.len(), 1);
    let Some(Content::Records { records, .. }) = document.blocks.first().map(|b| &b.content) else {
        panic!("records");
    };
    let Value::Enum(value) = &records[0].fields[0].value else {
        panic!("an enum: {:?}", records[0].fields[0].value);
    };
    assert!(value.defined);
    assert_eq!(value.matches.len(), 1);
    assert_eq!(value.matches[0].name, 0xDDDD_0002);
}

#[test]
fn a_structure_block_that_is_not_whole_records_is_partial() {
    let (system, graphics) = Builder::new()
        .structure(StructureSpec {
            name: 0xAAAA_0001,
            size: 4,
            flags: 0x300,
            fields: vec![field(0xBBBB_0001, 0, 0x15, 0)],
        })
        .block(records(0xAAAA_0001, vec![vec![0, 0, 0]]))
        .build();
    let document = decode(&system, &graphics).expect("a document");
    assert_eq!(
        document.status(),
        "partial",
        "unsupported={} unresolved={} issues={:?}",
        document.unsupported_blocks,
        document.unresolved_references,
        document.issues
    );
    assert_eq!(document.unsupported_blocks, 1);
}
