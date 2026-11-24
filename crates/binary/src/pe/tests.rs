//! Tests over synthetic PE32+ images. No real executable bytes appear here;
//! every fixture is built by [`Builder`].

use std::io::Write;
use std::sync::atomic::AtomicBool;

use sha2::{Digest, Sha256};

use super::{
    Error, ExecutableView, MAX_SECTIONS, Mapped, SCN_CNT_INITIALIZED_DATA, SCN_MEM_EXECUTE,
    SCN_MEM_READ, SCN_MEM_WRITE,
};
use crate::Source;

const IMAGE_BASE: u64 = 0x1_4000_0000;
const OPTIONAL_START: usize = 0x58;
const OPTIONAL_SIZE: u16 = 0xF0;
const TABLE_START: usize = OPTIONAL_START + OPTIONAL_SIZE as usize;

fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn name(text: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    let bytes = text.as_bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

#[derive(Clone)]
struct Sec {
    name: [u8; 8],
    vsize: u32,
    va: u32,
    raw_size: u32,
    raw_ptr: u32,
    chars: u32,
    data: Vec<u8>,
}

struct Builder {
    machine: u16,
    optional_magic: u16,
    image_base: u64,
    size_of_image: u32,
    section_count: Option<u16>,
    sections: Vec<Sec>,
}

impl Default for Builder {
    fn default() -> Self {
        // One read-only, initialized `.rdata` section: 0x100 file-backed bytes
        // followed by 0x100 zero-filled bytes.
        let data: Vec<u8> = (0..0x100u32).map(|n| (n * 7 + 1) as u8).collect();
        Self {
            machine: super::MACHINE_AMD64,
            optional_magic: super::PE32PLUS_MAGIC,
            image_base: IMAGE_BASE,
            size_of_image: 0x3000,
            section_count: None,
            sections: vec![Sec {
                name: name(".rdata"),
                vsize: 0x200,
                va: 0x1000,
                raw_size: 0x100,
                raw_ptr: 0x400,
                chars: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
                data,
            }],
        }
    }
}

impl Builder {
    fn build(&self) -> Vec<u8> {
        let table_len = self.sections.len() * 40;
        let mut file_len = (TABLE_START + table_len) as u64;
        for section in &self.sections {
            file_len = file_len.max(u64::from(section.raw_ptr) + section.data.len() as u64);
        }
        let mut buf = vec![0u8; file_len as usize];

        buf[0..2].copy_from_slice(b"MZ");
        put_u32(&mut buf, super::E_LFANEW as usize, 0x40);
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");

        // COFF file header at 0x44.
        put_u16(&mut buf, 0x44, self.machine);
        put_u16(
            &mut buf,
            0x46,
            self.section_count.unwrap_or(self.sections.len() as u16),
        );
        put_u16(&mut buf, 0x54, OPTIONAL_SIZE);
        put_u16(&mut buf, 0x56, 0x0022);

        // Optional header at 0x58.
        put_u16(&mut buf, OPTIONAL_START, self.optional_magic);
        put_u64(&mut buf, OPTIONAL_START + 24, self.image_base);
        put_u32(&mut buf, OPTIONAL_START + 32, 0x1000);
        put_u32(&mut buf, OPTIONAL_START + 36, 0x200);
        put_u32(&mut buf, OPTIONAL_START + 56, self.size_of_image);
        put_u16(&mut buf, OPTIONAL_START + 68, 3);
        put_u32(&mut buf, OPTIONAL_START + 108, 0);

        for (index, section) in self.sections.iter().enumerate() {
            let off = TABLE_START + 40 * index;
            buf[off..off + 8].copy_from_slice(&section.name);
            put_u32(&mut buf, off + 8, section.vsize);
            put_u32(&mut buf, off + 12, section.va);
            put_u32(&mut buf, off + 16, section.raw_size);
            put_u32(&mut buf, off + 20, section.raw_ptr);
            put_u32(&mut buf, off + 36, section.chars);
        }
        for section in &self.sections {
            let start = section.raw_ptr as usize;
            buf[start..start + section.data.len()].copy_from_slice(&section.data);
        }
        buf
    }
}

fn source_of(bytes: &[u8]) -> Source {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    Source::from_file(file).unwrap()
}

fn view_of(bytes: &[u8]) -> Result<ExecutableView, Error> {
    ExecutableView::from_source(source_of(bytes))
}

fn view(builder: &Builder) -> Result<ExecutableView, Error> {
    view_of(&builder.build())
}

#[test]
fn parses_a_valid_pe32plus_image() {
    let image = view(&Builder::default()).unwrap();
    assert_eq!(image.machine(), 0x8664);
    assert_eq!(image.image_base(), IMAGE_BASE);
    assert_eq!(image.size_of_image(), 0x3000);
    assert_eq!(image.sections().len(), 1);
    let section = &image.sections()[0];
    assert_eq!(section.name(), ".rdata");
    assert_eq!(section.virtual_address, 0x1000);
    assert_eq!(section.raw_size, 0x100);
}

#[test]
fn rejects_a_non_mz_file() {
    let mut bytes = Builder::default().build();
    bytes[0] = b'X';
    assert!(matches!(view_of(&bytes), Err(Error::Unsupported(_))));
}

#[test]
fn rejects_a_non_amd64_machine() {
    let image = Builder {
        machine: 0x014C, // i386
        ..Builder::default()
    };
    assert!(matches!(view(&image), Err(Error::Unsupported(_))));
}

#[test]
fn rejects_a_non_pe32plus_optional_header() {
    let image = Builder {
        optional_magic: 0x10B, // PE32
        ..Builder::default()
    };
    assert!(matches!(view(&image), Err(Error::Unsupported(_))));
}

#[test]
fn rejects_a_missing_pe_signature() {
    let mut bytes = Builder::default().build();
    bytes[0x40..0x44].copy_from_slice(b"XX\0\0");
    assert!(matches!(view_of(&bytes), Err(Error::Unsupported(_))));
    // Truncated before the COFF header: also no PE signature.
    let short = &Builder::default().build()[..0x50];
    assert!(matches!(view_of(short), Err(Error::Unsupported(_))));
    // Below a DOS header entirely.
    assert!(matches!(view_of(&[0u8; 8]), Err(Error::Unsupported(_))));
}

#[test]
fn rejects_a_truncated_optional_header() {
    let bytes = Builder::default().build();
    let truncated = &bytes[..OPTIONAL_START + 0x20];
    assert!(matches!(view_of(truncated), Err(Error::Malformed(_))));
}

#[test]
fn rejects_a_truncated_section_table() {
    let bytes = Builder::default().build();
    let truncated = &bytes[..TABLE_START + 10];
    assert!(matches!(view_of(truncated), Err(Error::Malformed(_))));
}

#[test]
fn rejects_section_raw_data_past_the_end_of_the_file() {
    let image = Builder {
        sections: vec![Sec {
            raw_size: 0x10_0000, // far larger than the data actually written
            data: vec![0; 0x10],
            ..Builder::default().sections.remove(0)
        }],
        ..Builder::default()
    };
    assert!(matches!(view(&image), Err(Error::Malformed(_))));
}

#[test]
fn rejects_a_section_past_size_of_image() {
    let image = Builder {
        size_of_image: 0x1000, // the section ends at RVA 0x1200
        ..Builder::default()
    };
    assert!(matches!(view(&image), Err(Error::Malformed(_))));
}

#[test]
fn rejects_a_zero_size_of_image() {
    let image = Builder {
        size_of_image: 0,
        ..Builder::default()
    };
    assert!(matches!(view(&image), Err(Error::Malformed(_))));
}

#[test]
fn rejects_an_image_with_no_sections() {
    let image = Builder {
        section_count: Some(0),
        sections: vec![],
        ..Builder::default()
    };
    assert!(matches!(view(&image), Err(Error::Malformed(_))));
}

#[test]
fn rejects_overlapping_sections() {
    let base = Builder::default().sections.remove(0);
    let image = Builder {
        sections: vec![
            Sec {
                name: name(".rdata"),
                raw_ptr: 0x400,
                ..base.clone()
            },
            Sec {
                name: name(".data"),
                va: 0x1100, // overlaps [0x1100, 0x1200) in memory
                raw_ptr: 0x800,
                ..base
            },
        ],
        size_of_image: 0x3000,
        ..Builder::default()
    };
    assert!(matches!(view(&image), Err(Error::Malformed(_))));
}

#[test]
fn enforces_the_file_size_limit() {
    let source = source_of(&Builder::default().build());
    let result = ExecutableView::parse(source, 0x100, MAX_SECTIONS);
    assert!(matches!(
        result,
        Err(Error::ResourceLimit { what: "size", .. })
    ));
}

#[test]
fn enforces_the_section_count_limit() {
    let base = Builder::default().sections.remove(0);
    let image = Builder {
        sections: vec![
            Sec {
                raw_ptr: 0x400,
                ..base.clone()
            },
            Sec {
                name: name(".data"),
                va: 0x2000,
                raw_ptr: 0x800,
                ..base
            },
        ],
        ..Builder::default()
    };
    let source = source_of(&image.build());
    let result = ExecutableView::parse(source, super::MAX_FILE_SIZE, 1);
    assert!(matches!(
        result,
        Err(Error::ResourceLimit {
            what: "section count",
            value: 2,
            limit: 1,
        })
    ));
}

#[test]
fn maps_an_rva_into_a_raw_backed_section() {
    let image = view(&Builder::default()).unwrap();
    // The data starts at RVA 0x1000, file offset 0x400.
    assert_eq!(image.classify_rva(0x1000), Mapped::File(0x400));
    assert_eq!(image.rva_to_file_offset(0x10FF), Some(0x4FF));
    let bytes = image.read_rva(0x1000, 0x100).unwrap();
    let expected: Vec<u8> = (0..0x100u32).map(|n| (n * 7 + 1) as u8).collect();
    assert_eq!(bytes, expected);
    // The same bytes through the virtual address.
    assert_eq!(
        image.read_va(IMAGE_BASE + 0x1000, 4).unwrap(),
        expected[..4].to_vec()
    );
}

#[test]
fn maps_an_rva_into_a_zero_filled_region() {
    let image = view(&Builder::default()).unwrap();
    // [0x1100, 0x1200) is virtual size beyond raw size.
    assert_eq!(image.classify_rva(0x1100), Mapped::ZeroFill);
    assert_eq!(image.rva_to_file_offset(0x1100), None);
    assert!(matches!(
        image.read_rva(0x1100, 1),
        Err(Error::Malformed(_))
    ));
    // A read that starts file-backed but crosses into the zero fill fails.
    assert!(matches!(
        image.read_rva(0x10F0, 0x20),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn reports_unmapped_addresses() {
    let image = view(&Builder::default()).unwrap();
    assert_eq!(image.classify_rva(0x2500), Mapped::Unmapped);
    assert_eq!(image.rva_to_file_offset(0x2500), None);
    assert_eq!(image.va_to_rva(IMAGE_BASE - 1), None);
    assert!(image.read_va(IMAGE_BASE - 1, 1).is_err());
    assert!(image.read_rva(0x2500, 1).is_err());
}

#[test]
fn checked_reads_reject_overflow() {
    let image = view(&Builder::default()).unwrap();
    assert!(matches!(
        image.read_rva(0x1000, usize::MAX),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn exposes_section_protection_flags() {
    let base = Builder::default().sections.remove(0);
    let image = Builder {
        sections: vec![
            Sec {
                name: name(".text"),
                va: 0x1000,
                raw_ptr: 0x400,
                chars: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_EXECUTE,
                ..base.clone()
            },
            Sec {
                name: name(".rdata"),
                va: 0x2000,
                raw_ptr: 0x800,
                chars: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ,
                ..base.clone()
            },
            Sec {
                name: name(".data"),
                va: 0x3000,
                raw_ptr: 0xC00,
                chars: SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE,
                ..base
            },
        ],
        size_of_image: 0x5000,
        ..Builder::default()
    };
    let image = view(&image).unwrap();
    let [text, rdata, data] = image.sections() else {
        panic!("expected three sections");
    };
    // A code section is readable and not writable, so `is_read_only` holds;
    // a registry scan narrows further with `!is_executable`.
    assert!(text.is_executable() && text.is_read_only() && !text.is_writable());
    assert!(rdata.is_read_only() && rdata.is_initialized() && !rdata.is_executable());
    assert!(data.is_writable() && !data.is_read_only());
}

#[test]
fn reading_leaves_the_file_unchanged() {
    let bytes = Builder::default().build();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &bytes).unwrap();
    let before = std::fs::read(file.path()).unwrap();

    let image = ExecutableView::open(file.path()).unwrap();
    let _ = image.read_rva(0x1000, 0x100).unwrap();
    let _ = image.identity(&AtomicBool::new(false)).unwrap();

    let after = std::fs::read(file.path()).unwrap();
    assert_eq!(before, after);
}

#[test]
fn reports_a_snapshot_identity() {
    let bytes = Builder::default().build();
    let image = view_of(&bytes).unwrap();
    let identity = image.identity(&AtomicBool::new(false)).unwrap();
    assert_eq!(identity.len, bytes.len() as u64);
    assert_eq!(identity.sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
}
