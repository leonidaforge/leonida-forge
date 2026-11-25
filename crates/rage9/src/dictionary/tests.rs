//! Tests on synthetic dictionaries built in memory.

use super::*;

const PAGE_MAP: u32 = 0x60;

#[derive(Clone)]
struct RecordSpec {
    units: u32,
    start: u32,
    width: u16,
    height: u16,
    format: u8,
    mip_word: u16,
    name: Option<&'static [u8]>,
    /// The `u64` at the name record's `+0x10`.
    variant: u64,
    /// Overrides the stored hash; otherwise the folded hash of `name`.
    stored_hash: Option<u32>,
}

impl Default for RecordSpec {
    fn default() -> Self {
        Self {
            units: 1,
            start: 0,
            width: 64,
            height: 64,
            format: 98,
            mip_word: 1,
            name: None,
            variant: NAME_HASH_VARIANT,
            stored_hash: None,
        }
    }
}

struct Build {
    hashes: Vec<u32>,
    /// The record index each value entry points at.
    order: Vec<usize>,
    records: Vec<RecordSpec>,
    graphics_len: u64,
    hash_capacity: Option<u16>,
    value_capacity: Option<u16>,
    hash_count: Option<u16>,
    value_count: Option<u16>,
    /// Overrides a value pointer, as a raw qword.
    bad_value: Option<(usize, u64)>,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            hashes: vec![0x1111_1111, 0x2222_2222],
            order: vec![0, 1],
            records: vec![
                RecordSpec {
                    start: 0,
                    ..RecordSpec::default()
                },
                RecordSpec {
                    start: 0x400,
                    ..RecordSpec::default()
                },
            ],
            graphics_len: 0x800,
            hash_capacity: None,
            value_capacity: None,
            hash_count: None,
            value_count: None,
            bad_value: None,
        }
    }
}

fn up(value: usize, to: usize) -> usize {
    value.next_multiple_of(to)
}

impl Build {
    /// Offset of the name record of `index`, computed as [`Build::system`]
    /// lays it out.
    fn name_record_at(&self, index: usize) -> usize {
        let n = self.hashes.len();
        let value_at = up(0xA0 + 4 * n, 8);
        up(value_at + 8 * self.order.len(), 8) + 0x20 * index
    }

    fn system(&self) -> Vec<u8> {
        let n = self.hashes.len();
        let hash_at = 0xA0;
        let value_at = up(hash_at + 4 * n, 8);
        let names_at = up(value_at + 8 * self.order.len(), 8);
        let names_len = 0x20 * self.records.len();
        let mut texts_at = names_at + names_len;
        let mut text_offsets = Vec::new();
        for record in &self.records {
            text_offsets.push(texts_at);
            texts_at += record.name.map_or(0, |name| name.len() + 1);
        }
        let records_at = up(texts_at, 0x10);
        let mut bytes = vec![0u8; records_at + 0x70 * self.records.len()];

        bytes[8..16].copy_from_slice(&(0x5000_0000u64 | u64::from(PAGE_MAP)).to_le_bytes());
        bytes[0x20..0x28].copy_from_slice(&(0x5000_0000u64 | hash_at as u64).to_le_bytes());
        bytes[0x28..0x2A].copy_from_slice(&self.hash_count.unwrap_or(n as u16).to_le_bytes());
        bytes[0x2A..0x2C]
            .copy_from_slice(&self.hash_capacity.unwrap_or(n as u16 + 2).to_le_bytes());
        bytes[0x30..0x38].copy_from_slice(&(0x5000_0000u64 | value_at as u64).to_le_bytes());
        bytes[0x38..0x3A].copy_from_slice(&self.value_count.unwrap_or(n as u16).to_le_bytes());
        bytes[0x3A..0x3C]
            .copy_from_slice(&self.value_capacity.unwrap_or(n as u16 + 2).to_le_bytes());
        for (ix, hash) in self.hashes.iter().enumerate() {
            bytes[hash_at + 4 * ix..hash_at + 4 * ix + 4].copy_from_slice(&hash.to_le_bytes());
        }
        for (ix, &record) in self.order.iter().enumerate() {
            let at = records_at + 0x70 * record;
            let pointer = 0x5000_0000u64 | at as u64;
            let value = match self.bad_value {
                Some((index, raw)) if index == ix => raw,
                _ => pointer,
            };
            bytes[value_at + 8 * ix..value_at + 8 * ix + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (ix, record) in self.records.iter().enumerate() {
            let at = records_at + 0x70 * ix;
            let set = |bytes: &mut [u8], offset: usize, data: &[u8]| {
                bytes[at + offset..at + offset + data.len()].copy_from_slice(data);
            };
            set(&mut bytes, 0x08, &record.units.to_le_bytes());
            let graphics = 0x6000_0000u64 | u64::from(record.start);
            set(&mut bytes, 0x18, &graphics.to_le_bytes());
            set(&mut bytes, 0x38, &record.width.to_le_bytes());
            set(&mut bytes, 0x3A, &record.height.to_le_bytes());
            set(&mut bytes, 0x3F, &[record.format]);
            set(&mut bytes, 0x42, &record.mip_word.to_le_bytes());
            set(&mut bytes, 0x10, &2432u64.to_le_bytes());
            if let Some(name) = record.name {
                let name_at = names_at + 0x20 * ix;
                set(
                    &mut bytes,
                    0x30,
                    &(0x5000_0000u64 | name_at as u64).to_le_bytes(),
                );
                let text = text_offsets[ix];
                let text_pointer = 0x5000_0000u64 | (text as u64 - 8);
                bytes[name_at..name_at + 8].copy_from_slice(&text_pointer.to_le_bytes());
                bytes[name_at + 0x10..name_at + 0x18]
                    .copy_from_slice(&record.variant.to_le_bytes());
                let hash = record.stored_hash.unwrap_or_else(|| joaat(name));
                bytes[name_at + 0x18..name_at + 0x1C].copy_from_slice(&hash.to_le_bytes());
                bytes[text..text + name.len()].copy_from_slice(name);
            }
        }
        bytes
    }
}

fn parse(build: &Build) -> Result<Report, Error> {
    parse_segments(&build.system(), build.graphics_len)
}

fn parse_segments(system: &[u8], graphics_len: u64) -> Result<Report, Error> {
    super::parse(system, graphics_len, &Limits::default())
}

#[test]
fn parses_a_two_record_dictionary() {
    let report = parse(&Build {
        hashes: vec![0x1111_1111, 0x2222_2222],
        records: vec![
            RecordSpec {
                width: 256,
                height: 128,
                format: 98,
                start: 0,
                ..RecordSpec::default()
            },
            RecordSpec {
                width: 64,
                height: 64,
                format: 71,
                start: 0x400,
                ..RecordSpec::default()
            },
        ],
        ..Build::default()
    })
    .unwrap();

    assert_eq!(report.hash_count, 2);
    assert_eq!(report.value_count, 2);
    assert!(!report.empty);
    assert_eq!(report.records.len(), 2);
    assert_eq!(report.records[0].width, 256);
    assert_eq!(report.records[0].height, 128);
    assert_eq!(report.records[0].format_id, 98);
    assert_eq!(report.records[1].format_id, 71);
    assert_eq!(report.records[0].mip_levels, 1);
    assert_eq!(report.records[0].graphics_at, Some(0));
    assert_eq!(report.records[0].extent, Some(0x400));
    assert_eq!(report.records[1].extent, Some(0x400));
    assert!(report.checks.counts_equal);
    assert!(report.checks.capacities_ok);
    assert!(report.checks.hash_sorted_unique);
    assert!(report.checks.value_order_matches_index);
    assert!(report.checks.starts_at_zero);
    assert!(report.checks.allocations_in_bounds);
    assert!(report.checks.partition_ok);
    assert!(!report.checks.allocation_duplicate);
    assert!(!report.checks.allocation_front_gap);
}

#[test]
fn an_empty_dictionary_is_valid() {
    let mut system = vec![0u8; 0x60];
    system[8..16].copy_from_slice(&(0x5000_0000u64 | u64::from(PAGE_MAP)).to_le_bytes());
    let report = parse_segments(&system, 0).unwrap();
    assert!(report.empty);
    assert!(report.records.is_empty());
    assert!(report.hashes.is_empty());
    assert!(report.checks.partition_ok);
}

#[test]
fn unequal_counts_are_not_a_dictionary() {
    let build = Build {
        hash_count: Some(3),
        ..Build::default()
    };
    assert_eq!(
        parse(&build).unwrap_err(),
        Error::NotADictionary(Step::CountsDiffer)
    );
}

#[test]
fn a_capacity_below_its_count_is_not_a_dictionary() {
    let build = Build {
        hash_capacity: Some(1),
        ..Build::default()
    };
    assert_eq!(
        parse(&build).unwrap_err(),
        Error::NotADictionary(Step::Capacity)
    );
}

#[test]
fn an_unsorted_hash_array_is_not_a_dictionary() {
    let build = Build {
        hashes: vec![0x2222_2222, 0x1111_1111],
        ..Build::default()
    };
    assert_eq!(
        parse(&build).unwrap_err(),
        Error::NotADictionary(Step::HashOrder)
    );
}

#[test]
fn a_duplicate_hash_is_not_a_dictionary() {
    let build = Build {
        hashes: vec![0x1111_1111, 0x1111_1111],
        ..Build::default()
    };
    assert_eq!(
        parse(&build).unwrap_err(),
        Error::NotADictionary(Step::HashOrder)
    );
}

#[test]
fn a_value_that_is_not_a_pointer_is_reported() {
    let build = Build {
        bad_value: Some((0, 0x1234_5678_9ABC_DEF0)),
        ..Build::default()
    };
    match parse(&build).unwrap_err() {
        Error::Invalid(reason) => assert!(reason.contains("not a system pointer"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_record_past_the_system_segment_is_reported() {
    let build = Build::default();
    let mut system = build.system();
    let last = up(0xA0 + 4 * build.hashes.len(), 8) + 8;
    let bad = 0x5000_0000u64 | (system.len() as u64 - 0x10);
    system[last..last + 8].copy_from_slice(&bad.to_le_bytes());
    match parse_segments(&system, build.graphics_len).unwrap_err() {
        Error::Invalid(reason) => assert!(reason.contains("needs 112 bytes"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_allocation_past_the_graphics_segment_fails_the_bound_checks() {
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                start: 0,
                ..RecordSpec::default()
            },
            RecordSpec {
                start: 0x900,
                ..RecordSpec::default()
            },
        ],
        graphics_len: 0x800,
        ..Build::default()
    })
    .unwrap();
    assert!(!report.checks.allocations_in_bounds);
    assert!(!report.checks.partition_ok);
    assert_eq!(report.records[1].graphics_at, Some(0x900));
}

#[test]
fn a_shared_allocation_start_is_reported() {
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                start: 0,
                ..RecordSpec::default()
            },
            RecordSpec {
                start: 0,
                ..RecordSpec::default()
            },
        ],
        ..Build::default()
    })
    .unwrap();
    assert!(report.checks.allocation_duplicate);
    assert!(!report.checks.partition_ok);
}

#[test]
fn a_front_gap_is_reported() {
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                start: 0x100,
                ..RecordSpec::default()
            },
            RecordSpec {
                start: 0x500,
                ..RecordSpec::default()
            },
        ],
        ..Build::default()
    })
    .unwrap();
    assert!(report.checks.allocation_front_gap);
    assert!(!report.checks.starts_at_zero);
    assert!(!report.checks.partition_ok);
}

#[test]
fn an_unsorted_value_array_does_not_match_the_index_order() {
    let report = parse(&Build {
        order: vec![1, 0],
        ..Build::default()
    })
    .unwrap();
    assert!(!report.checks.value_order_matches_index);
    // The record pointers still resolve; only their order differs.
    assert_eq!(report.records.len(), 2);
}

#[test]
fn a_hash_variant_name_record_is_verified() {
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                name: Some(b"diffuse"),
                ..RecordSpec::default()
            },
            RecordSpec {
                name: Some(b"bump_map"),
                ..RecordSpec::default()
            },
        ],
        ..Build::default()
    })
    .unwrap();
    assert_eq!(report.records[0].name_variant, NameVariant::Hash);
    assert_eq!(report.records[0].name_hash, Some(joaat(b"diffuse")));
    assert_eq!(report.records[0].name_check, NameCheck::Matched);
    assert_eq!(report.records[1].name_check, NameCheck::Matched);
}

#[test]
fn a_name_hash_that_does_not_match_is_reported_with_both_values() {
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                name: Some(b"diffuse"),
                stored_hash: Some(0xDEAD_BEEF),
                ..RecordSpec::default()
            },
            RecordSpec::default(),
        ],
        ..Build::default()
    })
    .unwrap();
    assert_eq!(
        report.records[0].name_check,
        NameCheck::Mismatched {
            stored: 0xDEAD_BEEF,
            computed: joaat(b"diffuse")
        }
    );
}

#[test]
fn a_pointer_variant_name_record_carries_no_hash() {
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                name: Some(b"diffuse"),
                variant: 0,
                ..RecordSpec::default()
            },
            RecordSpec::default(),
        ],
        ..Build::default()
    })
    .unwrap();
    assert_eq!(report.records[0].name_variant, NameVariant::Pointer);
    assert_eq!(report.records[0].name_hash, None);
    assert_eq!(report.records[0].name_check.name(), "not checked");
}

#[test]
fn unterminated_name_text_is_not_hashed() {
    // 64 non-zero bytes and no terminator inside the window.
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                name: Some(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef!"),
                ..RecordSpec::default()
            },
            RecordSpec::default(),
        ],
        ..Build::default()
    })
    .unwrap();
    assert_eq!(
        report.records[0].name_check.reason(),
        Some("the text is not terminated inside the 64-byte window")
    );
}

#[test]
fn unreachable_name_text_is_not_hashed() {
    let build = Build {
        records: vec![
            RecordSpec {
                name: Some(b"diffuse"),
                ..RecordSpec::default()
            },
            RecordSpec::default(),
        ],
        ..Build::default()
    };
    let mut system = build.system();
    // Point the name record's text pointer past the end of the segment.
    let name_at = build.name_record_at(0);
    let bad = 0x5000_0000u64 | 0x00FF_0000;
    system[name_at..name_at + 8].copy_from_slice(&bad.to_le_bytes());
    let report = parse_segments(&system, build.graphics_len).unwrap();
    assert_eq!(
        report.records[0].name_check.reason(),
        Some("the text is unreachable")
    );
}

#[test]
fn shared_name_hashes_leave_every_record_a_candidate() {
    let shared = joaat(b"diffuse");
    let report = parse(&Build {
        records: vec![
            RecordSpec {
                name: Some(b"diffuse"),
                ..RecordSpec::default()
            },
            RecordSpec {
                name: Some(b"diffuse"),
                stored_hash: Some(shared),
                ..RecordSpec::default()
            },
        ],
        ..Build::default()
    })
    .unwrap();
    let candidates = report.hash_candidates(shared);
    assert_eq!(candidates.len(), 2);
    assert_ne!(candidates[0].0, candidates[1].0);
}

#[test]
fn the_parameter_class_and_slot_are_split() {
    let texture = TextureParameter::split(8);
    assert_eq!(texture.class, 0);
    assert_eq!(texture.slot, 2);
    assert!(texture.is_texture());
    assert_eq!(slot_state(texture, 3, true), Some(SlotState::Bound));
    assert_eq!(slot_state(texture, 3, false), Some(SlotState::Unbound));
    assert_eq!(slot_state(texture, 2, true), Some(SlotState::Invalid));

    for class in [1, 2, 3] {
        let other = TextureParameter::split(class);
        assert!(!other.is_texture());
        assert_eq!(slot_state(other, 8, true), None);
    }
}

#[test]
fn a_non_dictionary_is_rejected_with_its_step() {
    assert_eq!(
        parse_segments(&[0u8; 8], 0).unwrap_err(),
        Error::NotADictionary(Step::HeaderLen)
    );
    let mut system = vec![0u8; 0x60];
    system[0] = 1;
    assert_eq!(
        parse_segments(&system, 0).unwrap_err(),
        Error::NotADictionary(Step::ZeroQword)
    );
    let system = vec![0u8; 0x60];
    assert_eq!(
        parse_segments(&system, 0).unwrap_err(),
        Error::NotADictionary(Step::PageMapPointer)
    );
    assert!(!is_dictionary(&system));
}
