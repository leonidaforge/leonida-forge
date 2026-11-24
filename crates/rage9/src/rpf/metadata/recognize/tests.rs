//! Tests over synthetic PE32+ images. Every fixture is built here; no
//! executable-derived bytes, key material or local path appears in this file.

use std::io::{Cursor, Write};
use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_binary::pe::{Error as PeError, ExecutableView};

use super::descriptor::{WRITER_PATTERN, recognize_with as recognize_descriptor_with};
use super::registry::{recognize_with as recognize_registry_with, with_records};
use super::*;
use crate::rpf::metadata::probe::{
    AUTHENTICATION, ProbeError, ProbeOutcome, ProbeReport, probe, probe_with_limit,
};
use crate::rpf::metadata::provider::{
    EncodedAesBlock, FixedTablesError, RecognizedSource, SourceError, recognize_fixed_tables,
    recognize_fixed_tables_with, synthetic,
};
use crate::rpf::metadata::transform::{BlockDecrypt, CipherSource};

const IMAGE_BASE: u64 = 0x1_4000_0000;
const TEXT_VA: u32 = 0x1000;
const RDATA_VA: u32 = 0x2_0000;
const DATA_VA: u32 = 0x20_0000;
const PDATA_VA: u32 = 0x21_0000;
const RODATA_VA: u32 = 0x30_0000;
const SIZE_OF_IMAGE: u32 = 0x40_0000;

const TEXT_CHARACTERISTICS: u32 = 0x6000_0020;
const RDATA_CHARACTERISTICS: u32 = 0x4000_0040;
const DATA_CHARACTERISTICS: u32 = 0xC000_0040;

/// Index of the exception table in the PE data directories.
const EXCEPTION_DIRECTORY: usize = 3;

const RECORD_LEN: usize = 0x18;
const STATES_OFFSET: usize = 0x100;

const KEY_FOUR: u32 = 0x0041_0004;
const KEY_ONE: u32 = 0x0041_0001;
const KIND_FOUR: u16 = 0x0010;
const KIND_ONE: u16 = 0x0003;
const IV_FOUR_OFFSET: usize = 0x00;
const IV_ONE_OFFSET: usize = 0x10;
const OBJECT_FOUR_OFFSET: usize = 0x20;
const OBJECT_ONE_OFFSET: usize = 0x40;

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn align(value: usize, to: usize) -> usize {
    value.div_ceil(to) * to
}

struct Section {
    name: &'static str,
    va: u32,
    characteristics: u32,
    data: Vec<u8>,
}

fn build_bytes(sections: &[Section], directories: &[(usize, u32, u32)]) -> Vec<u8> {
    let optional_start = 0x58usize;
    let optional_size = 0xF0usize;
    let table_start = optional_start + optional_size;

    let mut raw = align(table_start + 40 * sections.len(), 0x200);
    let mut raw_pointers = Vec::with_capacity(sections.len());
    for section in sections {
        raw_pointers.push(raw);
        raw = align(raw + section.data.len(), 0x200);
    }

    let mut buf = vec![0u8; raw];
    buf[0..2].copy_from_slice(b"MZ");
    put_u32(&mut buf, 0x3C, 0x40);
    buf[0x40..0x44].copy_from_slice(b"PE\0\0");

    put_u16(&mut buf, 0x44, 0x8664);
    put_u16(&mut buf, 0x46, sections.len() as u16);
    put_u16(&mut buf, 0x54, optional_size as u16);
    put_u16(&mut buf, 0x56, 0x0022);
    put_u16(&mut buf, optional_start, 0x20B);
    put_u64(&mut buf, optional_start + 24, IMAGE_BASE);
    put_u32(&mut buf, optional_start + 32, 0x1000);
    put_u32(&mut buf, optional_start + 36, 0x200);
    put_u32(&mut buf, optional_start + 56, SIZE_OF_IMAGE);
    put_u16(&mut buf, optional_start + 68, 3);
    let directory_count = directories
        .iter()
        .map(|(index, _, _)| index + 1)
        .max()
        .unwrap_or(0);
    put_u32(&mut buf, optional_start + 108, directory_count as u32);
    for (index, rva, size) in directories {
        put_u32(&mut buf, optional_start + 112 + 8 * index, *rva);
        put_u32(&mut buf, optional_start + 116 + 8 * index, *size);
    }

    for (index, section) in sections.iter().enumerate() {
        let offset = table_start + 40 * index;
        let name = section.name.as_bytes();
        buf[offset..offset + name.len()].copy_from_slice(name);
        put_u32(&mut buf, offset + 8, section.data.len() as u32);
        put_u32(&mut buf, offset + 12, section.va);
        put_u32(&mut buf, offset + 16, section.data.len() as u32);
        put_u32(&mut buf, offset + 20, raw_pointers[index] as u32);
        put_u32(&mut buf, offset + 36, section.characteristics);
        let raw = raw_pointers[index];
        buf[raw..raw + section.data.len()].copy_from_slice(&section.data);
    }
    buf
}

fn view_from_bytes(bytes: &[u8]) -> Result<ExecutableView, PeError> {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    ExecutableView::from_source(Source::from_file(file).unwrap())
}

fn build_view(sections: &[Section], directories: &[(usize, u32, u32)]) -> ExecutableView {
    view_from_bytes(&build_bytes(sections, directories)).unwrap()
}

fn state(magic: bool, bad_table: bool) -> Vec<u8> {
    let mut data = vec![0u8; STATE_LEN];
    put_u32(&mut data, 0, if magic { STATE_MAGIC } else { 0x1234_5678 });
    for index in 0..60 {
        put_u32(&mut data, 4 + 4 * index, 0x1111_1111 + index as u32);
    }
    let table: Vec<u8> = (0..=255).collect();
    for index in 0..16 {
        let start = 0xF4 + 0x100 * index;
        data[start..start + 0x100].copy_from_slice(&table);
    }
    if bad_table {
        data[0xF4 + 7] ^= 0xFF;
    }
    data
}

fn registry_data(
    base_va: u32,
    selectors: &[u64],
    magic: &[bool],
    bad_table: Option<usize>,
    duplicate: bool,
    out_of_image: bool,
) -> Vec<u8> {
    let mut data = vec![0u8; STATES_OFFSET + selectors.len() * STATE_LEN];
    for (index, selector) in selectors.iter().enumerate() {
        let pointer = if out_of_image {
            u64::MAX
        } else {
            IMAGE_BASE + u64::from(base_va) + (STATES_OFFSET + index * STATE_LEN) as u64
        };
        let selector = if duplicate && index == 1 {
            selectors[0]
        } else {
            *selector
        };
        let record = index * RECORD_LEN;
        put_u64(&mut data, record, selector);
        put_u64(&mut data, record + 8, pointer);
        put_u64(&mut data, record + 16, STATE_LEN as u64);
        let bytes = state(magic[index], bad_table == Some(index));
        let start = STATES_OFFSET + index * STATE_LEN;
        data[start..start + STATE_LEN].copy_from_slice(&bytes);
    }
    data
}

fn default_selectors() -> Vec<u64> {
    (1..=6u64)
        .map(|index| (index << 32) | 0x0200_0000)
        .collect()
}

fn default_magic() -> Vec<bool> {
    vec![true, true, true, false, false, false]
}

fn registry_section(va: u32, data: Vec<u8>) -> Section {
    Section {
        name: ".rdata",
        va,
        characteristics: RDATA_CHARACTERISTICS,
        data,
    }
}

fn simple_view(data: Vec<u8>) -> ExecutableView {
    build_view(&[registry_section(RDATA_VA, data)], &[])
}

fn recognize(data: Vec<u8>) -> Result<Registry, RegistryError> {
    recognize_registry(&simple_view(data), &AtomicBool::new(false))
}

fn limits() -> Limits {
    Limits::default()
}

// --- registry recognition -------------------------------------------------

#[test]
fn recognizes_a_registry() {
    let image = simple_view(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    ));
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    assert_eq!(registry.record_count(), 6);
    assert_eq!(registry.algorithm_state_count(), 3);
    // No state bytes are retained by recognition.
    assert!(format!("{registry:?}").contains("records"));
}

#[test]
fn ignores_section_names() {
    let section = Section {
        name: "XDATA",
        va: RDATA_VA,
        characteristics: RDATA_CHARACTERISTICS,
        data: registry_data(
            RDATA_VA,
            &default_selectors(),
            &default_magic(),
            None,
            false,
            false,
        ),
    };
    let image = build_view(&[section], &[]);
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    assert_eq!(registry.record_count(), 6);
}

#[test]
fn ignores_writable_and_executable_sections() {
    let payload = registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    );
    let writable = Section {
        name: ".data",
        va: RDATA_VA,
        characteristics: DATA_CHARACTERISTICS,
        data: payload.clone(),
    };
    let writable = build_view(&[writable], &[]);
    let error = recognize_registry(&writable, &AtomicBool::new(false)).unwrap_err();
    assert_eq!(error, RegistryError::NotFound);

    let executable = Section {
        name: ".text",
        va: RDATA_VA,
        characteristics: TEXT_CHARACTERISTICS,
        data: payload,
    };
    let executable = build_view(&[executable], &[]);
    let error = recognize_registry(&executable, &AtomicBool::new(false)).unwrap_err();
    assert_eq!(error, RegistryError::NotFound);
}

#[test]
fn rejects_duplicate_selectors() {
    let error = recognize(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        true,
        false,
    ))
    .unwrap_err();
    assert_eq!(error, RegistryError::NotFound);
}

#[test]
fn rejects_out_of_image_states() {
    let error = recognize(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        true,
    ))
    .unwrap_err();
    assert_eq!(error, RegistryError::NotFound);
}

#[test]
fn rejects_states_without_the_algorithm_magic() {
    let error = recognize(registry_data(
        RDATA_VA,
        &default_selectors(),
        &[false; 6],
        None,
        false,
        false,
    ))
    .unwrap_err();
    assert_eq!(error, RegistryError::NotFound);
}

#[test]
fn rejects_a_malformed_final_table() {
    // The first record is inspected during the scan, the fourth only when the
    // whole candidate is validated.
    for index in [0, 3] {
        let error = recognize(registry_data(
            RDATA_VA,
            &default_selectors(),
            &default_magic(),
            Some(index),
            false,
            false,
        ))
        .unwrap_err();
        assert_eq!(error, RegistryError::NotFound, "record {index}");
    }
}

#[test]
fn rejects_two_strong_candidates() {
    let payload = registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    );
    let mut second = registry_data(
        RODATA_VA,
        &[
            (0x11u64 << 32) | 0x0200_0000,
            0x12u64 << 32,
            0x13u64 << 32,
            0x14u64 << 32,
            0x15u64 << 32,
            0x16u64 << 32,
        ],
        &default_magic(),
        None,
        false,
        false,
    );
    second.truncate(payload.len());
    let image = build_view(
        &[
            registry_section(RDATA_VA, payload),
            Section {
                name: ".rodata",
                va: RODATA_VA,
                characteristics: RDATA_CHARACTERISTICS,
                data: second,
            },
        ],
        &[],
    );
    let error = recognize_registry(&image, &AtomicBool::new(false)).unwrap_err();
    assert_eq!(error, RegistryError::Ambiguous);
}

#[test]
fn enforces_the_record_limit() {
    let data = || {
        registry_data(
            RDATA_VA,
            &default_selectors(),
            &default_magic(),
            None,
            false,
            false,
        )
    };
    let image = simple_view(data());
    let error = recognize_registry_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            records: 3,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RegistryError::ResourceLimit {
            what: "registry records in one run",
            ..
        }
    ));

    // Exactly as many records as the run has is not an overflow.
    let registry = recognize_registry_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            records: 6,
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(registry.record_count(), 6);
}

#[test]
fn enforces_the_scan_budget() {
    let image = simple_view(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    ));
    let error = recognize_registry_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            scan_bytes: 1024,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RegistryError::ResourceLimit {
            what: "read-only scan",
            ..
        }
    ));
}

#[test]
fn enforces_the_scan_step_limit() {
    let image = simple_view(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    ));
    let error = recognize_registry_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            scan_offsets: 10,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RegistryError::ResourceLimit {
            what: "registry scan steps",
            ..
        }
    ));
}

#[test]
fn enforces_the_algorithm_state_limit() {
    let image = simple_view(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    ));
    recognize_registry_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            algorithm_states: 3,
            ..limits()
        },
    )
    .unwrap();
    let error = recognize_registry_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            algorithm_states: 2,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RegistryError::ResourceLimit {
            what: "algorithm-0x10 states in one registry run",
            ..
        }
    ));
}

#[test]
fn enforces_the_candidate_limit() {
    let first = registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    );
    let second = registry_data(
        RODATA_VA,
        &[
            (0x21u64 << 32) | 0x0200_0000,
            0x22u64 << 32,
            0x23u64 << 32,
            0x24u64 << 32,
            0x25u64 << 32,
        ],
        &[true, true, true, false, false],
        None,
        false,
        false,
    );
    let image = build_view(
        &[
            registry_section(RDATA_VA, first),
            Section {
                name: ".rodata",
                va: RODATA_VA,
                characteristics: RDATA_CHARACTERISTICS,
                data: second,
            },
        ],
        &[],
    );
    let error = recognize_registry_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            candidates: 1,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RegistryError::ResourceLimit {
            what: "registry candidate runs",
            ..
        }
    ));
}

#[test]
fn registry_recognition_can_be_cancelled() {
    let image = simple_view(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    ));
    let cancel = AtomicBool::new(true);
    let error = recognize_registry(&image, &cancel).unwrap_err();
    assert_eq!(error, RegistryError::Cancelled);
}

#[test]
fn rejects_a_truncated_executable() {
    let bytes = build_bytes(
        &[registry_section(
            RDATA_VA,
            registry_data(
                RDATA_VA,
                &default_selectors(),
                &default_magic(),
                None,
                false,
                false,
            ),
        )],
        &[],
    );
    assert!(matches!(
        view_from_bytes(&bytes[..0x100]),
        Err(PeError::Malformed(_) | PeError::Unsupported(_))
    ));
}

#[test]
fn resolving_duplicate_records_is_ambiguous() {
    let image = simple_view(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    ));
    let state_va = IMAGE_BASE + u64::from(RDATA_VA) + STATES_OFFSET as u64;
    let selector = selector_for(KEY_FOUR, ALGORITHM_CBC, STATIC_STEP1_MODE);
    let registry = with_records(
        image.clone(),
        &[
            (selector, state_va, STATE_LEN as u64),
            (selector, state_va, STATE_LEN as u64),
        ],
    );
    let error = registry
        .state_for_key(KEY_FOUR, ALGORITHM_CBC, STATIC_STEP1_MODE)
        .unwrap_err();
    assert_eq!(error, RegistryError::Ambiguous);
}

#[test]
fn resolving_a_non_state_record_is_malformed() {
    let image = simple_view(registry_data(
        RDATA_VA,
        &default_selectors(),
        &default_magic(),
        None,
        false,
        false,
    ));
    let state_va = IMAGE_BASE + u64::from(RDATA_VA) + STATES_OFFSET as u64;
    let selector = selector_for(KEY_FOUR, ALGORITHM_CBC, STATIC_STEP1_MODE);
    let registry = with_records(image, &[(selector, state_va, DEFAULT_RECORD_LEN)]);
    let error = registry
        .state_for_key(KEY_FOUR, ALGORITHM_CBC, STATIC_STEP1_MODE)
        .unwrap_err();
    assert!(matches!(error, RegistryError::StateMalformed(_)));
}

// --- descriptor recognition ----------------------------------------------

fn data_va(offset: usize) -> u64 {
    IMAGE_BASE + u64::from(DATA_VA) + offset as u64
}

struct DescriptorSpec {
    key: u32,
    kind: u16,
    parameter_va: u64,
    object_va: u64,
}

fn lea_bytes(opcode: u8, at_va: u64, target_va: u64) -> [u8; 7] {
    let displacement = target_va as i64 - (at_va as i64 + 7);
    let mut out = [0u8; 7];
    out[0..3].copy_from_slice(&[opcode, 0x8D, 0x0D]);
    out[3..7].copy_from_slice(&(displacement as i32).to_le_bytes());
    out
}

fn descriptor_block(base: u64, call_va: u64, spec: &DescriptorSpec) -> Vec<u8> {
    descriptor_block_with_kind(base, call_va, spec, true)
}

fn descriptor_block_with_kind(
    base: u64,
    call_va: u64,
    spec: &DescriptorSpec,
    word_kind: bool,
) -> Vec<u8> {
    let mut block = vec![0xBA];
    block.extend(spec.key.to_le_bytes());
    if word_kind {
        block.extend([0x66, 0x41, 0xB8]);
        block.extend(spec.kind.to_le_bytes());
    } else {
        block.extend([0x41, 0xB8]);
        block.extend(u32::from(spec.kind).to_le_bytes());
    }
    let at = base + block.len() as u64;
    block.extend(lea_bytes(0x4C, at, spec.parameter_va));
    let at = base + block.len() as u64;
    block.extend(lea_bytes(0x48, at, spec.object_va));
    let at = base + block.len() as u64;
    let relative = call_va as i64 - (at as i64 + 5);
    block.push(0xE9);
    block.extend((relative as i32).to_le_bytes());
    block
}

fn append_call(block: &mut Vec<u8>, call_va: u64, writer_va: u64) {
    let relative = writer_va as i64 - (call_va as i64 + 5);
    block.push(0xE8);
    block.extend((relative as i32).to_le_bytes());
    block.push(0xC3);
}

fn builder_code(
    func_va: u64,
    writer_va: u64,
    four: &DescriptorSpec,
    one: &DescriptorSpec,
) -> Vec<u8> {
    let mut code = vec![
        0x80, 0xF9, 0x04, // cmp cl, 4
        0x74, 0x06, // je index 4
        0x80, 0xF9, 0x01, // cmp cl, 1
        0x74, 0x1E, // je index 1
        0xC3, // ret
    ];
    assert_eq!(code.len(), 0x0B);
    code.extend(descriptor_block(func_va + 0x0B, func_va + 0x45, four));
    assert_eq!(code.len(), 0x28);
    code.extend(descriptor_block(func_va + 0x28, func_va + 0x45, one));
    assert_eq!(code.len(), 0x45);
    append_call(&mut code, func_va + 0x45, writer_va);
    code
}

fn ambiguous_mapping_code(func_va: u64, writer_va: u64, spec: &DescriptorSpec) -> Vec<u8> {
    let mut code = vec![
        0x80, 0xF9, 0x02, // cmp cl, 2
        0x74, 0x06, // je shared
        0x80, 0xF9, 0x04, // cmp cl, 4
        0x74, 0x01, // je shared
        0xC3, // ret
    ];
    assert_eq!(code.len(), 0x0B);
    code.extend(descriptor_block(func_va + 0x0B, func_va + 0x28, spec));
    assert_eq!(code.len(), 0x28);
    append_call(&mut code, func_va + 0x28, writer_va);
    code
}

fn unsupported_builder_code(func_va: u64, writer_va: u64, spec: &DescriptorSpec) -> Vec<u8> {
    let mut code = vec![
        0x80, 0xF9, 0x04, // cmp cl, 4
        0x74, 0x01, // je builder
        0xC3, // ret
    ];
    assert_eq!(code.len(), 0x06);
    let mut block = descriptor_block_with_kind(func_va + 0x06, func_va + 0x24, spec, false);
    assert_eq!(block.len(), 0x1E);
    append_call(&mut block, func_va + 0x24, writer_va);
    code.extend(block);
    code
}

fn standard_descriptor_specs() -> (DescriptorSpec, DescriptorSpec) {
    (
        DescriptorSpec {
            key: KEY_FOUR,
            kind: KIND_FOUR,
            parameter_va: data_va(IV_FOUR_OFFSET),
            object_va: data_va(OBJECT_FOUR_OFFSET),
        },
        DescriptorSpec {
            key: KEY_ONE,
            kind: KIND_ONE,
            parameter_va: data_va(IV_ONE_OFFSET),
            object_va: data_va(OBJECT_ONE_OFFSET),
        },
    )
}

fn descriptor_registry(selectors: &[u64], magic: &[bool]) -> Vec<u8> {
    registry_data(RDATA_VA, selectors, magic, None, false, false)
}

fn standard_descriptor_registry() -> Vec<u8> {
    let selectors: Vec<u64> = [
        KEY_FOUR,
        KEY_ONE,
        0x0041_0003,
        0x0041_0005,
        0x0041_0006,
        0x0041_0007,
    ]
    .into_iter()
    .map(|key| selector_for(key, ALGORITHM_CBC, STATIC_STEP1_MODE))
    .collect();
    descriptor_registry(&selectors, &default_magic())
}

fn descriptor_data() -> Vec<u8> {
    let mut data = vec![0u8; 0x100];
    data[IV_FOUR_OFFSET..IV_FOUR_OFFSET + 16].copy_from_slice(&[0x11; 16]);
    data[IV_ONE_OFFSET..IV_ONE_OFFSET + 16].copy_from_slice(&[0x22; 16]);
    data
}

fn runtime_function(begin: u32, end: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend(begin.to_le_bytes());
    bytes.extend(end.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes
}

fn descriptor_image(code: Vec<u8>, registry: Vec<u8>, data: Vec<u8>) -> ExecutableView {
    let mut text = vec![0u8; 0x200];
    text[..WRITER_PATTERN.len()].copy_from_slice(&WRITER_PATTERN);
    text[0x100..0x100 + code.len()].copy_from_slice(&code);
    let pdata = runtime_function(TEXT_VA + 0x100, TEXT_VA + 0x100 + code.len() as u32);
    build_view(
        &[
            Section {
                name: ".text",
                va: TEXT_VA,
                characteristics: TEXT_CHARACTERISTICS,
                data: text,
            },
            registry_section(RDATA_VA, registry),
            Section {
                name: ".data",
                va: DATA_VA,
                characteristics: DATA_CHARACTERISTICS,
                data,
            },
            Section {
                name: ".pdata",
                va: PDATA_VA,
                characteristics: RDATA_CHARACTERISTICS,
                data: pdata,
            },
        ],
        &[(EXCEPTION_DIRECTORY, PDATA_VA, 12)],
    )
}

fn standard_descriptor_image() -> ExecutableView {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (four, one) = standard_descriptor_specs();
    let code = builder_code(func_va, writer_va, &four, &one);
    descriptor_image(code, standard_descriptor_registry(), descriptor_data())
}

fn recognize_descriptor(
    image: &ExecutableView,
    registry: &Registry,
    selector: u8,
) -> Result<StaticDescriptor, DescriptorError> {
    recognize_static_descriptor(image, registry, selector, &AtomicBool::new(false))
}

#[test]
fn recognizes_the_static_descriptor_for_odd_and_even_selectors() {
    let image = standard_descriptor_image();
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();

    for selector in [9, 8] {
        let descriptor = recognize_descriptor(&image, &registry, selector).unwrap();
        assert_eq!(descriptor.index(), 4);
        assert_eq!(descriptor.kind(), KIND_FOUR);
        assert_eq!(descriptor.key_id(), KEY_FOUR);
        assert_eq!(descriptor.parameter(), &[0x11; 16]);
    }
    for selector in [3, 2] {
        let descriptor = recognize_descriptor(&image, &registry, selector).unwrap();
        assert_eq!(descriptor.index(), 1);
        assert_eq!(descriptor.kind(), KIND_ONE);
        assert_eq!(descriptor.key_id(), KEY_ONE);
        assert_eq!(descriptor.parameter(), &[0x22; 16]);
    }
}

#[test]
fn recognizes_through_the_composed_entry_point() {
    let image = standard_descriptor_image();
    let recognized = Recognized::recognize(&image, 9, &AtomicBool::new(false)).unwrap();
    assert_eq!(recognized.mode(), STATIC_STEP1_MODE);
    assert_eq!(recognized.algorithm_id(), ALGORITHM_CBC);
    assert_eq!(recognized.provider(), 2);
    assert_eq!(recognized.descriptor().index(), 4);
    let state = recognized.state().unwrap();
    assert_eq!(state.len(), STATE_LEN);
    assert_eq!(&state.as_slice()[..4], &STATE_MAGIC.to_le_bytes());
    // The Debug output must not contain the key identifier or the parameter.
    let debug = format!("{recognized:?}");
    assert!(!debug.contains(&format!("{KEY_FOUR:08x}")));
    assert!(!debug.contains("17171717"));

    // Cipher type 3 is a different kind in the same algorithm family. The
    // provider must follow the family, not the raw kind.
    let recognized = Recognized::recognize(&image, 3, &AtomicBool::new(false)).unwrap();
    assert_eq!(recognized.descriptor().kind(), KIND_ONE);
    assert_eq!(recognized.algorithm_id(), ALGORITHM_CBC);
    assert_eq!(recognized.provider(), 2);
    assert_eq!(recognized.state().unwrap().len(), STATE_LEN);
}

#[test]
fn reports_a_missing_descriptor() {
    let image = standard_descriptor_image();
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    for selector in [7, 6] {
        let error = recognize_descriptor(&image, &registry, selector).unwrap_err();
        assert_eq!(error, DescriptorError::DescriptorNotFound);
    }
}

#[test]
fn reports_ambiguous_descriptor_writers() {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (four, one) = standard_descriptor_specs();
    let code = builder_code(func_va, writer_va, &four, &one);

    let mut text = vec![0u8; 0x200];
    text[..WRITER_PATTERN.len()].copy_from_slice(&WRITER_PATTERN);
    text[0x40..0x40 + WRITER_PATTERN.len()].copy_from_slice(&WRITER_PATTERN);
    text[0x100..0x100 + code.len()].copy_from_slice(&code);
    let pdata = runtime_function(TEXT_VA + 0x100, TEXT_VA + 0x100 + code.len() as u32);
    let image = build_view(
        &[
            Section {
                name: ".text",
                va: TEXT_VA,
                characteristics: TEXT_CHARACTERISTICS,
                data: text,
            },
            registry_section(RDATA_VA, standard_descriptor_registry()),
            Section {
                name: ".pdata",
                va: PDATA_VA,
                characteristics: RDATA_CHARACTERISTICS,
                data: pdata,
            },
        ],
        &[(EXCEPTION_DIRECTORY, PDATA_VA, 12)],
    );
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert_eq!(error, DescriptorError::WriterAmbiguous);
}

#[test]
fn reports_an_ambiguous_selector_mapping() {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (four, _) = standard_descriptor_specs();
    let code = ambiguous_mapping_code(func_va, writer_va, &four);
    let image = descriptor_image(code, standard_descriptor_registry(), descriptor_data());
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert_eq!(error, DescriptorError::AmbiguousMapping);
}

#[test]
fn reports_an_unsupported_descriptor_builder() {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (four, _) = standard_descriptor_specs();
    let code = unsupported_builder_code(func_va, writer_va, &four);
    let image = descriptor_image(code, standard_descriptor_registry(), descriptor_data());
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert!(matches!(error, DescriptorError::UnsupportedLayout(_)));
}

#[test]
fn reports_a_malformed_parameter() {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (mut four, one) = standard_descriptor_specs();
    four.parameter_va = IMAGE_BASE + 0x80_0000;
    let code = builder_code(func_va, writer_va, &four, &one);
    let image = descriptor_image(code, standard_descriptor_registry(), descriptor_data());
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert_eq!(error, DescriptorError::MalformedParameter);
}

#[test]
fn reports_a_malformed_object() {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (mut four, one) = standard_descriptor_specs();
    four.object_va = IMAGE_BASE + 0x80_0000;
    let code = builder_code(func_va, writer_va, &four, &one);
    let image = descriptor_image(code, standard_descriptor_registry(), descriptor_data());
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert_eq!(error, DescriptorError::MalformedObject);
}

#[test]
fn reports_a_missing_compatible_state() {
    let selectors: Vec<u64> = [KEY_ONE, 0x0041_0003, 0x0041_0005, 0x0041_0006, 0x0041_0007]
        .into_iter()
        .map(|key| selector_for(key, ALGORITHM_CBC, STATIC_STEP1_MODE))
        .collect();
    let registry = descriptor_registry(&selectors, &[true, true, true, false, false]);
    let image = descriptor_image(
        {
            let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
            let func_va = writer_va + 0x100;
            let (four, one) = standard_descriptor_specs();
            builder_code(func_va, writer_va, &four, &one)
        },
        registry,
        descriptor_data(),
    );
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert_eq!(error, DescriptorError::NoCompatibleState);
}

#[test]
fn reports_an_incompatible_state() {
    let selectors: Vec<u64> = [
        KEY_FOUR,
        KEY_ONE,
        0x0041_0003,
        0x0041_0005,
        0x0041_0006,
        0x0041_0007,
    ]
    .into_iter()
    .map(|key| selector_for(key, ALGORITHM_CBC, STATIC_STEP1_MODE))
    .collect();
    let registry = descriptor_registry(&selectors, &[false, true, true, false, false, false]);
    let image = descriptor_image(
        {
            let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
            let func_va = writer_va + 0x100;
            let (four, one) = standard_descriptor_specs();
            builder_code(func_va, writer_va, &four, &one)
        },
        registry,
        descriptor_data(),
    );
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert_eq!(error, DescriptorError::StateMalformed);
}

#[test]
fn descriptor_recognition_can_be_cancelled() {
    let image = standard_descriptor_image();
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error =
        recognize_static_descriptor(&image, &registry, 9, &AtomicBool::new(true)).unwrap_err();
    assert_eq!(error, DescriptorError::Cancelled);
}

#[test]
fn rejects_a_missing_exception_table() {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (four, one) = standard_descriptor_specs();
    let code = builder_code(func_va, writer_va, &four, &one);
    let image = descriptor_image(code, standard_descriptor_registry(), descriptor_data());
    // Drop the exception directory by rebuilding without it.
    let mut text = vec![0u8; 0x200];
    text[..WRITER_PATTERN.len()].copy_from_slice(&WRITER_PATTERN);
    text[0x100..0x100 + 0x4B].copy_from_slice(&builder_code(func_va, writer_va, &four, &one));
    let image_without_pdata = build_view(
        &[
            Section {
                name: ".text",
                va: TEXT_VA,
                characteristics: TEXT_CHARACTERISTICS,
                data: text,
            },
            registry_section(RDATA_VA, standard_descriptor_registry()),
        ],
        &[],
    );
    let registry = recognize_registry(&image_without_pdata, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image_without_pdata, &registry, 9).unwrap_err();
    assert!(matches!(error, DescriptorError::UnsupportedLayout(_)));
    // The complete image does have exception data.
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    recognize_descriptor(&image, &registry, 9).unwrap();
}

#[test]
fn reports_malformed_exception_data() {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let (four, one) = standard_descriptor_specs();
    let code = builder_code(func_va, writer_va, &four, &one);
    let mut text = vec![0u8; 0x200];
    text[..WRITER_PATTERN.len()].copy_from_slice(&WRITER_PATTERN);
    text[0x100..0x100 + code.len()].copy_from_slice(&code);

    // A reversed range must be rejected, not guessed.
    let mut pdata = runtime_function(TEXT_VA + 0x200, TEXT_VA + 0x100);
    pdata.truncate(12);
    let image = build_view(
        &[
            Section {
                name: ".text",
                va: TEXT_VA,
                characteristics: TEXT_CHARACTERISTICS,
                data: text,
            },
            registry_section(RDATA_VA, standard_descriptor_registry()),
            Section {
                name: ".pdata",
                va: PDATA_VA,
                characteristics: RDATA_CHARACTERISTICS,
                data: pdata,
            },
        ],
        &[(EXCEPTION_DIRECTORY, PDATA_VA, 12)],
    );
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor(&image, &registry, 9).unwrap_err();
    assert!(matches!(error, DescriptorError::UnsupportedLayout(_)));
}

#[test]
fn enforces_the_function_length_limit() {
    let image = standard_descriptor_image();
    let registry = recognize_registry(&image, &AtomicBool::new(false)).unwrap();
    let error = recognize_descriptor_with(
        &image,
        &registry,
        9,
        &AtomicBool::new(false),
        Limits {
            function_bytes: 8,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        DescriptorError::ResourceLimit {
            what: "function length",
            ..
        }
    ));
}

#[test]
fn provider_selection_follows_the_algorithm_family() {
    use crate::rpf::metadata::transform::Algorithm;

    // Static step 1 is fixed at mode 1; the selector does not supply it.
    assert_eq!(STATIC_STEP1_MODE, 1);
    // The provider is a function of the algorithm identifier and mode.
    assert_eq!(provider_for(0x10, 0), 3);
    assert_eq!(provider_for(0x10, 1), 2);
    assert_eq!(provider_for(0x11, 1), 2);
    assert_eq!(provider_for(0x15, 7), 2);
    assert_eq!(provider_for(0x0f, 1), 0);
    assert_eq!(provider_for(0x16, 1), 0);
    // Cipher types 3, 4, 5, 10, 11, 12 and 16 select algorithm 0x10. The
    // provider must use that algorithm, not the raw cipher type.
    for kind in [3u16, 4, 5, 10, 11, 12, 16] {
        let algorithm = Algorithm::of(kind).unwrap();
        assert_eq!(algorithm, Algorithm::Cbc, "type {kind}");
        assert_eq!(algorithm.id(), ALGORITHM_CBC, "type {kind}");
        assert_eq!(provider_for(algorithm.id(), STATIC_STEP1_MODE), 2);
    }
    // Passing the raw type would select no provider.
    assert_eq!(provider_for(3, STATIC_STEP1_MODE), 0);
    assert_eq!(
        selector_for(0x1234_5678, ALGORITHM_CBC, 1),
        0x1234_5678_0200_0000
    );
    // Other traced or untraced types do not select the encoded AES block.
    assert_eq!(Algorithm::of(1), Ok(Algorithm::Untraced(1)));
    assert_eq!(Algorithm::of(17), Ok(Algorithm::Untraced(0x11)));
    assert!(Algorithm::of(13).is_err());
}

/// Optional read-only check against a local executable. The caller supplies
/// its path through `LEONIDA_FORGE_EXECUTABLE`; nothing here knows a build, a
/// path or a selector. The observed selectors are those of the inspected
/// build, so a different build may fail closed.
#[test]
#[ignore = "set LEONIDA_FORGE_EXECUTABLE to a local executable to run"]
fn local_executable_smoke_test() {
    let Some(path) = std::env::var_os("LEONIDA_FORGE_EXECUTABLE") else {
        panic!("set LEONIDA_FORGE_EXECUTABLE to a local executable to run this test");
    };
    let image = ExecutableView::open(std::path::Path::new(&path)).unwrap();
    let cancel = AtomicBool::new(false);
    let registry = recognize_registry(&image, &cancel).unwrap();
    // The research for the inspected build expects 24 records and 10
    // algorithm-0x10 states. The counts are printed rather than pinned, so a
    // different build is not rejected for a structural count alone.
    eprintln!(
        "registry records: {}, algorithm states: {}",
        registry.record_count(),
        registry.algorithm_state_count()
    );
    assert!(registry.record_count() > 0, "the registry has no records");
    assert!(
        registry.algorithm_state_count() > 0,
        "the registry has no algorithm-0x10 states"
    );

    let four_odd = recognize_static_descriptor(&image, &registry, 9, &cancel).unwrap();
    let four_even = recognize_static_descriptor(&image, &registry, 8, &cancel).unwrap();
    assert_eq!(
        four_odd, four_even,
        "selectors 9 and 8 must select the same descriptor"
    );
    let one_odd = recognize_static_descriptor(&image, &registry, 3, &cancel).unwrap();
    let one_even = recognize_static_descriptor(&image, &registry, 2, &cancel).unwrap();
    assert_eq!(
        one_odd, one_even,
        "selectors 3 and 2 must select the same descriptor"
    );
    assert_ne!(four_odd, one_odd, "the two descriptors must differ");
    eprintln!(
        "selector 9/8: index {}, kind {:#x}",
        four_odd.index(),
        four_odd.kind()
    );
    eprintln!(
        "selector 3/2: index {}, kind {:#x}",
        one_odd.index(),
        one_odd.kind()
    );

    for selector in [0u8, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15] {
        assert!(
            recognize_static_descriptor(&image, &registry, selector, &cancel).is_err(),
            "selector {selector} unexpectedly resolved"
        );
    }
    eprintln!("unavailable selectors fail closed");

    let source = RecognizedSource::recognize(&image, 9, &cancel).unwrap();
    assert_eq!(source.algorithm_id(), ALGORITHM_CBC);
    assert_eq!(source.provider(), 2);
    assert_eq!(source.mode(), STATIC_STEP1_MODE);
    let index = source.descriptor().index();
    assert_eq!(source.static_kind(index), Some(source.descriptor().kind()));
    assert!(source.static_descriptor(index).is_some());
    assert!(source.cbc_block(source.descriptor().key_id()).is_some());
    eprintln!(
        "provider: algorithm {:#x}, provider {}, mode {}, block initialized",
        source.algorithm_id(),
        source.provider(),
        source.mode()
    );
}

/// Optional read-only A-table probe against local files. The caller supplies
/// the executable through `LEONIDA_FORGE_EXECUTABLE` and an archive through
/// `LEONIDA_FORGE_ARCHIVE`. The result is evidence for these files only; it
/// does not authenticate the archive.
#[test]
#[ignore = "set LEONIDA_FORGE_EXECUTABLE and LEONIDA_FORGE_ARCHIVE to local files to run"]
fn local_archive_probe_smoke_test() {
    let Some(executable) = std::env::var_os("LEONIDA_FORGE_EXECUTABLE") else {
        panic!("set LEONIDA_FORGE_EXECUTABLE to a local executable to run this test");
    };
    let Some(archive) = std::env::var_os("LEONIDA_FORGE_ARCHIVE") else {
        panic!("set LEONIDA_FORGE_ARCHIVE to a local archive to run this test");
    };
    let image = ExecutableView::open(std::path::Path::new(&executable)).unwrap();
    let mut source = Source::open(std::path::Path::new(&archive)).unwrap();
    let report = probe(&mut source, &image, &AtomicBool::new(false)).unwrap();
    eprintln!("probe outcome: {}", report.outcome);
    eprintln!(
        "registry records: {:?}, algorithm states: {:?}",
        report.registry_records, report.registry_algorithm_states
    );
    eprintln!("descriptor: {:?}", report.descriptor);
    eprintln!("state identified: {}", report.state_identified);
    eprintln!("fixed tables: {}", report.fixed_tables);
    eprintln!("block initialized: {}", report.block_initialized);
    eprintln!("A table: {:?}", report.a_table);
    eprintln!("authentication: {}", report.authentication);
    assert_eq!(report.authentication, AUTHENTICATION);
    assert_ne!(report.outcome, ProbeOutcome::Cancelled);
}

// --- fixed transformation tables -----------------------------------------

fn fixed_section(data: Vec<u8>) -> Section {
    Section {
        name: ".rdata",
        va: RDATA_VA,
        characteristics: RDATA_CHARACTERISTICS,
        data,
    }
}

#[test]
fn recognizes_synthetic_fixed_tables() {
    let synthetic = synthetic::instance(&synthetic::FIPS_KEY);
    let image = build_view(&[fixed_section(synthetic.fixed_bytes())], &[]);
    let tables = recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap();
    let block = EncodedAesBlock::new(synthetic.state_bytes(), tables).unwrap();
    let mut value = synthetic::FIPS_CIPHERTEXT;
    block.decrypt_block(&mut value);
    assert_eq!(value, synthetic::FIPS_PLAINTEXT);
}

#[test]
fn ignores_writable_and_executable_fixed_tables() {
    let bytes = synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes();
    let writable = build_view(
        &[Section {
            name: ".data",
            va: RDATA_VA,
            characteristics: DATA_CHARACTERISTICS,
            data: bytes.clone(),
        }],
        &[],
    );
    assert_eq!(
        recognize_fixed_tables(&writable, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::NotFound
    );

    let executable = build_view(
        &[Section {
            name: ".text",
            va: RDATA_VA,
            characteristics: TEXT_CHARACTERISTICS,
            data: bytes,
        }],
        &[],
    );
    assert_eq!(
        recognize_fixed_tables(&executable, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::NotFound
    );
}

#[test]
fn rejects_two_fixed_table_blocks() {
    let synthetic = synthetic::instance(&synthetic::FIPS_KEY);
    let mut data = synthetic.fixed_bytes();
    data.extend_from_slice(&synthetic.fixed_bytes());
    let image = build_view(&[fixed_section(data)], &[]);
    assert_eq!(
        recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::Ambiguous
    );
}

#[test]
fn reports_missing_fixed_tables() {
    let image = build_view(&[fixed_section(vec![0u8; 0x5000])], &[]);
    assert_eq!(
        recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::NotFound
    );
}

#[test]
fn rejects_a_non_affine_stage_table() {
    let mut bytes = synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes();
    // Byte 5 is not one of the affine prefilter probes, so the stage table is
    // found and then rejected by the full check.
    bytes[5] ^= 1;
    let image = build_view(&[fixed_section(bytes)], &[]);
    assert!(matches!(
        recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::Malformed(_)
    ));
}

#[test]
fn rejects_duplicate_stage_tables() {
    let mut bytes = synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes();
    let first: Vec<u8> = bytes[..256].to_vec();
    bytes[256..512].copy_from_slice(&first);
    let image = build_view(&[fixed_section(bytes)], &[]);
    assert!(matches!(
        recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::Malformed(_)
    ));
}

#[test]
fn rejects_a_malformed_round_table() {
    let mut bytes = synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes();
    let round_table = 16 * 256;
    bytes.copy_within(round_table..round_table + 4, round_table + 4);
    let image = build_view(&[fixed_section(bytes)], &[]);
    assert!(matches!(
        recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::Malformed(_)
    ));
}

#[test]
fn rejects_duplicate_round_tables() {
    let mut bytes = synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes();
    let first_round = 16 * 256;
    let second_round = first_round + 1024;
    let first: Vec<u8> = bytes[first_round..first_round + 1024].to_vec();
    bytes[second_round..second_round + 1024].copy_from_slice(&first);
    let image = build_view(&[fixed_section(bytes)], &[]);
    assert!(matches!(
        recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::Malformed(_)
    ));
}

#[test]
fn rejects_a_truncated_fixed_table_block() {
    let mut bytes = synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes();
    bytes.truncate(16 * 256);
    let image = build_view(&[fixed_section(bytes)], &[]);
    assert!(matches!(
        recognize_fixed_tables(&image, &AtomicBool::new(false)).unwrap_err(),
        FixedTablesError::Malformed(_)
    ));
}

#[test]
fn fixed_table_recognition_can_be_cancelled() {
    let image = build_view(
        &[fixed_section(
            synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes(),
        )],
        &[],
    );
    assert_eq!(
        recognize_fixed_tables(&image, &AtomicBool::new(true)).unwrap_err(),
        FixedTablesError::Cancelled
    );
}

#[test]
fn enforces_fixed_table_scan_limits() {
    let image = build_view(
        &[fixed_section(
            synthetic::instance(&synthetic::FIPS_KEY).fixed_bytes(),
        )],
        &[],
    );
    let budget = recognize_fixed_tables_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            scan_bytes: 1024,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        budget,
        FixedTablesError::ResourceLimit {
            what: "fixed-table scan",
            ..
        }
    ));

    let steps = recognize_fixed_tables_with(
        &image,
        &AtomicBool::new(false),
        Limits {
            scan_offsets: 10,
            ..limits()
        },
    )
    .unwrap_err();
    assert!(matches!(
        steps,
        FixedTablesError::ResourceLimit {
            what: "fixed-table scan steps",
            ..
        }
    ));
}

#[test]
fn recognizes_registry_fixed_tables_and_block_end_to_end() {
    let synthetic = synthetic::instance(&synthetic::FIPS_KEY);
    let key_id = 0x0041_0004u32;
    let selector = selector_for(key_id, ALGORITHM_CBC, STATIC_STEP1_MODE);

    let records_offset = 0x5000usize;
    let state_offset = records_offset + 5 * RECORD_LEN;
    let state_va = IMAGE_BASE + u64::from(RDATA_VA) + state_offset as u64;
    let mut data = synthetic.fixed_bytes();
    data.resize(state_offset, 0);
    for index in 0..5 {
        let selector = if index == 0 {
            selector
        } else {
            ((0x7000 + index as u64) << 32) | 0x0200_0000
        };
        let record = records_offset + index * RECORD_LEN;
        put_u64(&mut data, record, selector);
        put_u64(&mut data, record + 8, state_va);
        put_u64(&mut data, record + 16, STATE_LEN as u64);
    }
    data.extend_from_slice(synthetic.raw_state());

    let image = build_view(&[fixed_section(data)], &[]);
    let cancel = AtomicBool::new(false);
    let registry = recognize_registry(&image, &cancel).unwrap();
    assert_eq!(registry.record_count(), 5);
    let state = registry
        .state_for_key(key_id, ALGORITHM_CBC, STATIC_STEP1_MODE)
        .unwrap();
    let tables = recognize_fixed_tables(&image, &cancel).unwrap();
    let block = EncodedAesBlock::new(state, tables).unwrap();
    let mut value = synthetic::FIPS_CIPHERTEXT;
    block.decrypt_block(&mut value);
    assert_eq!(value, synthetic::FIPS_PLAINTEXT);
}

// --- key provider source and A-table probe -------------------------------

const PROBE_IV: [u8; 16] = [0x33; 16];
const PROBE_RECORDS_OFFSET: usize = 0x5000;
const PROBE_A_RECORD_LEN: usize = 8;

fn a_record(id: u16, offset: u32) -> [u8; PROBE_A_RECORD_LEN] {
    let mut record = [0u8; PROBE_A_RECORD_LEN];
    put_u16(&mut record, 0, id);
    put_u32(&mut record, 4, offset);
    record
}

fn probe_selectors() -> Vec<u64> {
    let mut selectors = vec![selector_for(KEY_FOUR, ALGORITHM_CBC, STATIC_STEP1_MODE)];
    selectors.extend((1..5u64).map(|index| ((0x7000 + index) << 32) | 0x0200_0000u64));
    selectors
}

fn probe_rdata(selectors: &[u64], corrupt_fixed: Option<usize>) -> Vec<u8> {
    let synthetic = synthetic::instance(&synthetic::FIPS_KEY);
    let state_offset = PROBE_RECORDS_OFFSET + selectors.len() * RECORD_LEN;
    let state_va = IMAGE_BASE + u64::from(RDATA_VA) + state_offset as u64;
    let mut data = synthetic.fixed_bytes();
    if let Some(offset) = corrupt_fixed {
        data[offset] ^= 1;
    }
    data.resize(state_offset, 0);
    for (index, selector) in selectors.iter().enumerate() {
        let record = PROBE_RECORDS_OFFSET + index * RECORD_LEN;
        put_u64(&mut data, record, *selector);
        put_u64(&mut data, record + 8, state_va);
        put_u64(&mut data, record + 16, STATE_LEN as u64);
    }
    data.extend_from_slice(synthetic.raw_state());
    data
}

fn probe_image(selectors: &[u64], kind: u16, corrupt_fixed: Option<usize>) -> ExecutableView {
    let writer_va = IMAGE_BASE + u64::from(TEXT_VA);
    let func_va = writer_va + 0x100;
    let four = DescriptorSpec {
        key: KEY_FOUR,
        kind,
        parameter_va: data_va(IV_FOUR_OFFSET),
        object_va: data_va(OBJECT_FOUR_OFFSET),
    };
    let one = DescriptorSpec {
        key: KEY_ONE,
        kind: KIND_ONE,
        parameter_va: data_va(IV_ONE_OFFSET),
        object_va: data_va(OBJECT_ONE_OFFSET),
    };
    let code = builder_code(func_va, writer_va, &four, &one);
    let mut data = descriptor_data();
    data[IV_FOUR_OFFSET..IV_FOUR_OFFSET + 16].copy_from_slice(&PROBE_IV);
    descriptor_image(code, probe_rdata(selectors, corrupt_fixed), data)
}

fn cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    let mut previous = *iv;
    for block in data.as_chunks_mut::<16>().0 {
        for (byte, chain) in block.iter_mut().zip(&previous) {
            *byte ^= chain;
        }
        synthetic::reference_encrypt(key, block);
        previous = *block;
    }
}

fn probe_archive(
    records: &[[u8; PROBE_A_RECORD_LEN]],
    b_len: u32,
    selector: u8,
    flags: u8,
    key: &[u8; 32],
) -> Vec<u8> {
    let a_span = align(records.len() * PROBE_A_RECORD_LEN, 16);
    let b_start = 0x40 + a_span;
    let metadata_len = b_start + b_len as usize;
    let mut bytes = vec![0u8; metadata_len];
    bytes[..4].copy_from_slice(&crate::rpf::MAGIC);
    put_u32(&mut bytes, 0x04, metadata_len as u32);
    put_u32(&mut bytes, 0x08, metadata_len as u32);
    put_u16(&mut bytes, 0x1A, records.len() as u16);
    put_u32(&mut bytes, 0x1C, b_len);
    bytes[0x2C] = 1;
    bytes[0x2D] = flags;
    bytes[0x2E] = selector;
    let mut plaintext = vec![0u8; a_span];
    for (index, record) in records.iter().enumerate() {
        let start = index * PROBE_A_RECORD_LEN;
        plaintext[start..start + PROBE_A_RECORD_LEN].copy_from_slice(record);
    }
    cbc_encrypt(key, &PROBE_IV, &mut plaintext);
    bytes[0x40..0x40 + a_span].copy_from_slice(&plaintext);
    bytes
}

fn run_probe(image: &ExecutableView, archive: &[u8]) -> ProbeReport {
    let mut cursor = Cursor::new(archive.to_vec());
    probe(&mut cursor, image, &AtomicBool::new(false)).unwrap()
}

fn plausible_records() -> Vec<[u8; PROBE_A_RECORD_LEN]> {
    vec![
        a_record(1, 0x00),
        a_record(2, 0x20),
        a_record(9, 0x40),
        a_record(4, 0x60),
        a_record(5, 0x80),
    ]
}

#[test]
fn the_recognized_source_resolves_the_step1_provider() {
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let source = RecognizedSource::recognize(&image, 9, &AtomicBool::new(false)).unwrap();
    assert_eq!(source.descriptor().index(), 4);
    assert_eq!(source.descriptor().key_id(), KEY_FOUR);
    assert_eq!(source.algorithm_id(), ALGORITHM_CBC);
    assert_eq!(source.provider(), 2);
    assert_eq!(source.mode(), STATIC_STEP1_MODE);
    assert_eq!(source.static_kind(4), Some(KIND_FOUR));
    assert_eq!(source.static_kind(1), None);
    assert_eq!(source.static_descriptor(4), Some((KEY_FOUR, PROBE_IV)));
    assert_eq!(source.static_descriptor(1), None);
    assert!(source.cbc_block(KEY_FOUR).is_some());
    // Cipher type 3 selects the same algorithm 0x10 block.
    assert!(source.cbc_block_for(KIND_ONE, KEY_FOUR).is_some());
    assert!(source.cbc_block_for(1, KEY_FOUR).is_none());
    assert!(source.cbc_block_for(KIND_FOUR, 0xDEAD_BEEF).is_none());
    assert!(!format!("{source:?}").contains(&format!("{KEY_FOUR:#x}")));
}

#[test]
fn the_recognized_source_reports_a_missing_state() {
    let selectors: Vec<u64> = (1..=5u64)
        .map(|index| ((0x7000 + index) << 32) | 0x0200_0000u64)
        .collect();
    let image = probe_image(&selectors, KIND_FOUR, None);
    let error = RecognizedSource::recognize(&image, 9, &AtomicBool::new(false)).unwrap_err();
    assert!(matches!(
        error,
        SourceError::Recognition(RecognitionError::Descriptor(
            DescriptorError::NoCompatibleState
        ))
    ));
}

#[test]
fn the_probe_accepts_a_plausible_a_table() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &synthetic::FIPS_KEY);
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let report = run_probe(&image, &archive);
    assert_eq!(report.outcome, ProbeOutcome::Plausible);
    let summary = report.a_table.unwrap();
    assert_eq!(summary.records, 5);
    assert_eq!(summary.known_ids, 3);
    assert_eq!(report.registry_records, Some(5));
    assert!(report.registry_algorithm_states.unwrap() >= 1);
    assert_eq!(report.descriptor.unwrap().index, 4);
    assert!(report.state_identified);
    assert!(report.fixed_tables);
    assert!(report.block_initialized);
    assert_eq!(report.authentication, AUTHENTICATION);
}

#[test]
fn the_probe_accepts_a_kind_3_descriptor() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &synthetic::FIPS_KEY);
    // Cipher type 3 selects algorithm 0x10 as well.
    let image = probe_image(&probe_selectors(), KIND_ONE, None);
    let report = run_probe(&image, &archive);
    assert_eq!(report.outcome, ProbeOutcome::Plausible);
    let descriptor = report.descriptor.unwrap();
    assert_eq!(descriptor.kind, KIND_ONE);
    assert_eq!(descriptor.algorithm_id, ALGORITHM_CBC);
    assert_eq!(descriptor.provider, 2);
}

#[test]
fn the_probe_rejects_malformed_a_tables() {
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let cases = vec![
        (vec![], "the A table has no records"),
        (
            vec![
                a_record(1, 0x00),
                a_record(1, 0x10),
                a_record(2, 0x20),
                a_record(6, 0x30),
                a_record(9, 0x40),
            ],
            "two A records share an identifier",
        ),
        (
            vec![
                a_record(0, 0x00),
                a_record(1, 0x10),
                a_record(2, 0x20),
                a_record(6, 0x30),
                a_record(9, 0x40),
            ],
            "an A record has a zero identifier",
        ),
        (
            vec![
                a_record(1, 0x00),
                a_record(2, 0x100),
                a_record(9, 0x20),
                a_record(6, 0x30),
                a_record(3, 0x40),
            ],
            "an A record points outside the B block",
        ),
        (
            vec![
                a_record(4, 0x00),
                a_record(5, 0x10),
                a_record(7, 0x20),
                a_record(8, 0x30),
                a_record(10, 0x40),
            ],
            "no A record references a known sub-block",
        ),
    ];
    for (records, reason) in cases {
        let archive = probe_archive(&records, 0x100, 9, 1, &synthetic::FIPS_KEY);
        let report = run_probe(&image, &archive);
        assert_eq!(report.outcome, ProbeOutcome::Implausible(reason));
    }
}

#[test]
fn the_probe_does_not_accept_a_wrong_state() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &[0x42; 32]);
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let report = run_probe(&image, &archive);
    assert!(matches!(report.outcome, ProbeOutcome::Implausible(_)));
}

#[test]
fn the_probe_reports_an_unsupported_descriptor() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &synthetic::FIPS_KEY);
    // Cipher type 1 selects an untraced algorithm.
    let image = probe_image(&probe_selectors(), 1, None);
    let report = run_probe(&image, &archive);
    assert_eq!(
        report.outcome,
        ProbeOutcome::DescriptorUnsupported("the cipher type is not supported")
    );
    assert!(report.registry_records.is_some());
    assert!(report.descriptor.is_none());
}

#[test]
fn the_probe_reports_a_missing_state() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &synthetic::FIPS_KEY);
    let selectors: Vec<u64> = (1..=5u64)
        .map(|index| ((0x7000 + index) << 32) | 0x0200_0000u64)
        .collect();
    let image = probe_image(&selectors, KIND_FOUR, None);
    let report = run_probe(&image, &archive);
    assert_eq!(
        report.outcome,
        ProbeOutcome::StateUnsupported("no compatible key state")
    );
    assert!(report.descriptor.is_some());
    assert!(!report.state_identified);
}

#[test]
fn the_probe_reports_malformed_fixed_tables() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &synthetic::FIPS_KEY);
    let image = probe_image(&probe_selectors(), KIND_FOUR, Some(5));
    let report = run_probe(&image, &archive);
    assert!(matches!(
        report.outcome,
        ProbeOutcome::FixedTablesUnsupported(_)
    ));
    assert!(report.state_identified);
    assert!(!report.fixed_tables);
}

#[test]
fn the_probe_is_not_applicable_without_a_static_pass() {
    let archive = probe_archive(&[], 0, 0, 1, &synthetic::FIPS_KEY);
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let report = run_probe(&image, &archive);
    assert_eq!(report.outcome, ProbeOutcome::NotApplicable);
    assert!(report.registry_records.is_none());
}

#[test]
fn the_probe_can_be_cancelled() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &synthetic::FIPS_KEY);
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let mut cursor = Cursor::new(archive);
    let report = probe(&mut cursor, &image, &AtomicBool::new(true)).unwrap();
    assert_eq!(report.outcome, ProbeOutcome::Cancelled);
    assert!(report.registry_records.is_none());
}

#[test]
fn the_probe_enforces_the_span_limit() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 1, &synthetic::FIPS_KEY);
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let mut cursor = Cursor::new(archive);
    let report = probe_with_limit(&mut cursor, &image, &AtomicBool::new(false), 16).unwrap();
    assert_eq!(
        report.outcome,
        ProbeOutcome::ResourceLimit {
            what: "step-1 A span bytes",
            limit: 16
        }
    );
}

#[test]
fn the_probe_rejects_an_inconsistent_layout() {
    let archive = probe_archive(&plausible_records(), 0x100, 9, 0, &synthetic::FIPS_KEY);
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let mut cursor = Cursor::new(archive);
    let error = probe(&mut cursor, &image, &AtomicBool::new(false)).unwrap_err();
    assert_eq!(
        error,
        ProbeError::Archive("the cipher spans disagree with the layout")
    );
}

#[test]
fn the_probe_rejects_an_unreadable_archive() {
    let image = probe_image(&probe_selectors(), KIND_FOUR, None);
    let mut cursor = Cursor::new(Vec::new());
    let error = probe(&mut cursor, &image, &AtomicBool::new(false)).unwrap_err();
    assert_eq!(
        error,
        ProbeError::Archive("the metadata area cannot be read")
    );
}
