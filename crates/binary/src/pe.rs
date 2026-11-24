//! Read-only access to a locally supplied PE32+ x86-64 executable.
//!
//! The executable path is always a caller argument; nothing here depends on a
//! fixed location or a known build. The parser validates the DOS and NT
//! headers, the section table and every address conversion, and exposes
//! section protection flags so later recognition does not rely on section
//! names. It never executes or modifies the executable: reads go through a
//! read-only [`Source`].
//!
//! This is a bounded PE reader for one purpose, not a general PE analysis
//! framework. It reads headers eagerly and section bytes on demand, so it
//! never allocates the whole image.

use std::fmt;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use crate::{Error as BinaryError, Source, read_at, sha256};

/// Largest executable the reader accepts, checked before any read.
pub const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Largest section count the reader accepts.
pub const MAX_SECTIONS: usize = 96;

const DOS_HEADER_LEN: u64 = 0x40;
const E_LFANEW: u64 = 0x3C;
/// PE signature, COFF file header and the optional-header magic.
const PE_SIGNATURE: [u8; 4] = *b"PE\0\0";
const COFF_HEADER_LEN: u64 = 20;
const SECTION_HEADER_LEN: u64 = 40;
const MACHINE_AMD64: u16 = 0x8664;
const PE32PLUS_MAGIC: u16 = 0x20B;

const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// A limit from [`MAX_FILE_SIZE`] or [`MAX_SECTIONS`] was exceeded.
    ResourceLimit {
        what: &'static str,
        value: u64,
        limit: u64,
    },
    /// A valid image in a form this reader does not support: not a PE, a
    /// machine other than x86-64, or an optional header that is not PE32+.
    Unsupported(String),
    /// A PE32+ x86-64 image whose structure is inconsistent or out of bounds.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::ResourceLimit { what, value, limit } => {
                write!(
                    f,
                    "the executable's {what} ({value}) exceeds the limit ({limit})"
                )
            }
            Error::Unsupported(reason) => write!(f, "unsupported executable: {reason}"),
            Error::Malformed(reason) => write!(f, "malformed executable: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

fn malformed(reason: impl Into<String>) -> Error {
    Error::Malformed(reason.into())
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// Where an address lands in the mapped image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapped {
    /// Backed by file bytes at this file offset.
    File(u64),
    /// Inside a section but past its raw data: zero-filled when loaded, not
    /// backed by the file.
    ZeroFill,
    /// Not inside any section.
    Unmapped,
}

/// One entry of the section table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    raw_name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

impl Section {
    /// The section name with its trailing NUL padding removed. Non-UTF-8
    /// bytes are replaced; the name is diagnostic only.
    pub fn name(&self) -> std::borrow::Cow<'_, str> {
        let end = self
            .raw_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.raw_name.len());
        String::from_utf8_lossy(&self.raw_name[..end])
    }

    pub fn is_initialized(&self) -> bool {
        self.characteristics & SCN_CNT_INITIALIZED_DATA != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & SCN_MEM_READ != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    /// Readable and not writable, the property a key registry sits in.
    pub fn is_read_only(&self) -> bool {
        self.is_readable() && !self.is_writable()
    }

    /// The span the section occupies when mapped, the larger of its virtual
    /// and raw sizes. The sum cannot overflow: both are `u32`.
    pub fn mapped_span(&self) -> u64 {
        u64::from(self.virtual_size.max(self.raw_size))
    }

    /// The RVA range the section occupies when mapped.
    pub fn virtual_range(&self) -> Range<u64> {
        let start = u64::from(self.virtual_address);
        start..start + self.mapped_span()
    }

    /// The file range the section's raw data occupies, or `None` if it has
    /// none.
    pub fn raw_range(&self) -> Option<Range<u64>> {
        (self.raw_size != 0).then(|| {
            let start = u64::from(self.raw_pointer);
            start..start + u64::from(self.raw_size)
        })
    }

    pub fn contains_rva(&self, rva: u64) -> bool {
        self.virtual_range().contains(&rva)
    }
}

fn ranges_overlap(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

/// A snapshot identity of the inspected executable: its length and a SHA-256
/// digest of its bytes. A later recognizer can store this and recompute it to
/// detect that the executable changed. It is not a build allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub len: u64,
    pub sha256: [u8; 32],
}

/// A validated, read-only view of a PE32+ x86-64 executable.
#[derive(Debug, Clone)]
pub struct ExecutableView {
    source: Source,
    machine: u16,
    image_base: u64,
    size_of_image: u32,
    sections: Vec<Section>,
}

impl ExecutableView {
    /// Opens `path` read-only and parses it. The path is a caller argument and
    /// is not retained or logged.
    pub fn open(path: &Path) -> Result<Self, Error> {
        Self::from_source(Source::open(path)?)
    }

    /// Parses an already-open read-only source. For a PE embedded in a larger
    /// file, pass a [`Source::slice`] of it.
    pub fn from_source(source: Source) -> Result<Self, Error> {
        Self::parse(source, MAX_FILE_SIZE, MAX_SECTIONS)
    }

    fn parse(source: Source, max_file_size: u64, max_sections: usize) -> Result<Self, Error> {
        let file_len = source.len();
        if file_len > max_file_size {
            return Err(Error::ResourceLimit {
                what: "size",
                value: file_len,
                limit: max_file_size,
            });
        }
        if file_len < DOS_HEADER_LEN {
            return Err(Error::Unsupported("shorter than a DOS header".into()));
        }
        let dos = read_exact(&source, 0, DOS_HEADER_LEN as usize)?;
        if dos.get(..2) != Some(b"MZ") {
            return Err(Error::Unsupported("no MZ signature".into()));
        }
        let e_lfanew = u64::from(u32_at(&dos, E_LFANEW as usize).expect("DOS header read"));

        // PE signature and COFF file header.
        let coff_end = e_lfanew
            .checked_add(PE_SIGNATURE.len() as u64 + COFF_HEADER_LEN)
            .filter(|&end| end <= file_len)
            .ok_or_else(|| Error::Unsupported("no PE signature".into()))?;
        let coff = read_exact(&source, e_lfanew, (coff_end - e_lfanew) as usize)?;
        if coff.get(..4) != Some(&PE_SIGNATURE) {
            return Err(Error::Unsupported("no PE signature".into()));
        }
        let machine = u16_at(&coff, 4).expect("COFF header read");
        if machine != MACHINE_AMD64 {
            return Err(Error::Unsupported(format!(
                "machine {machine:#06x} is not x86-64"
            )));
        }
        let section_count = u16_at(&coff, 6).expect("COFF header read");
        let optional_header_size = u64::from(u16_at(&coff, 20).expect("COFF header read"));

        // Optional header. Only PE32+ fields the reader needs are read.
        let optional_start = coff_end;
        let optional_end = optional_start
            .checked_add(optional_header_size)
            .filter(|&end| end <= file_len)
            .ok_or_else(|| malformed("the optional header runs past the end of the file"))?;
        if optional_header_size < 0x70 {
            return Err(malformed("the optional header is too short for PE32+"));
        }
        let optional = read_exact(
            &source,
            optional_start,
            (optional_end - optional_start) as usize,
        )?;
        if u16_at(&optional, 0) != Some(PE32PLUS_MAGIC) {
            return Err(Error::Unsupported(
                "the optional header is not PE32+".into(),
            ));
        }
        let image_base = u64_at(&optional, 24).expect("optional header read");
        let size_of_image = u32_at(&optional, 56).expect("optional header read");
        if size_of_image == 0 {
            return Err(malformed("SizeOfImage is zero"));
        }

        // Section table.
        if section_count == 0 {
            return Err(malformed("the image has no sections"));
        }
        if usize::from(section_count) > max_sections {
            return Err(Error::ResourceLimit {
                what: "section count",
                value: u64::from(section_count),
                limit: max_sections as u64,
            });
        }
        let table_len = u64::from(section_count) * SECTION_HEADER_LEN;
        let table_end = optional_end
            .checked_add(table_len)
            .filter(|&end| end <= file_len)
            .ok_or_else(|| malformed("the section table runs past the end of the file"))?;
        let table = read_exact(&source, optional_end, (table_end - optional_end) as usize)?;

        let mut sections = Vec::with_capacity(usize::from(section_count));
        for entry in table.as_chunks::<{ SECTION_HEADER_LEN as usize }>().0 {
            let section = Section {
                raw_name: entry[..8].try_into().expect("8 bytes"),
                virtual_size: u32_at(entry, 8).expect("section header"),
                virtual_address: u32_at(entry, 12).expect("section header"),
                raw_size: u32_at(entry, 16).expect("section header"),
                raw_pointer: u32_at(entry, 20).expect("section header"),
                characteristics: u32_at(entry, 36).expect("section header"),
            };
            if let Some(raw) = section.raw_range()
                && raw.end > file_len
            {
                return Err(malformed(format!(
                    "section {:?} raw data ends at {:#x}, past the end of the file",
                    section.name(),
                    raw.end
                )));
            }
            if section.virtual_range().end > u64::from(size_of_image) {
                return Err(malformed(format!(
                    "section {:?} ends at RVA {:#x}, past SizeOfImage ({size_of_image:#x})",
                    section.name(),
                    section.virtual_range().end
                )));
            }
            sections.push(section);
        }

        for (i, a) in sections.iter().enumerate() {
            for b in &sections[i + 1..] {
                if ranges_overlap(&a.virtual_range(), &b.virtual_range()) {
                    return Err(malformed(format!(
                        "sections {:?} and {:?} overlap in memory",
                        a.name(),
                        b.name()
                    )));
                }
                if let (Some(ra), Some(rb)) = (a.raw_range(), b.raw_range())
                    && ranges_overlap(&ra, &rb)
                {
                    return Err(malformed(format!(
                        "sections {:?} and {:?} overlap in the file",
                        a.name(),
                        b.name()
                    )));
                }
            }
        }

        Ok(Self {
            source,
            machine,
            image_base,
            size_of_image,
            sections,
        })
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// The length of the executable, fixed when it was opened.
    pub fn file_len(&self) -> u64 {
        self.source.len()
    }

    /// The section whose mapped range contains `rva`. At most one does: the
    /// parser rejects overlapping sections.
    pub fn section_at_rva(&self, rva: u64) -> Option<&Section> {
        self.sections
            .iter()
            .find(|section| section.contains_rva(rva))
    }

    /// Where `rva` lands: a file offset, a zero-filled region, or unmapped.
    pub fn classify_rva(&self, rva: u64) -> Mapped {
        let Some(section) = self.section_at_rva(rva) else {
            return Mapped::Unmapped;
        };
        let delta = rva - u64::from(section.virtual_address);
        if delta < u64::from(section.raw_size) {
            Mapped::File(u64::from(section.raw_pointer) + delta)
        } else {
            Mapped::ZeroFill
        }
    }

    /// The file offset `rva` reads from, or `None` if it is zero-filled or
    /// unmapped.
    pub fn rva_to_file_offset(&self, rva: u64) -> Option<u64> {
        match self.classify_rva(rva) {
            Mapped::File(offset) => Some(offset),
            Mapped::ZeroFill | Mapped::Unmapped => None,
        }
    }

    /// The RVA of a virtual address, or `None` if it is below the image base.
    pub fn va_to_rva(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.image_base)
    }

    /// `len` bytes at `rva`, which must be entirely backed by one section's
    /// raw data. Reading into a zero-filled region or across a section end is
    /// an error.
    pub fn read_rva(&self, rva: u64, len: usize) -> Result<Vec<u8>, Error> {
        let section = self
            .section_at_rva(rva)
            .ok_or_else(|| malformed(format!("RVA {rva:#x} is not mapped")))?;
        let delta = rva - u64::from(section.virtual_address);
        let end = delta
            .checked_add(len as u64)
            .ok_or_else(|| malformed("the read length overflows"))?;
        if end > u64::from(section.raw_size) {
            return Err(malformed(format!(
                "a read of {len} bytes at RVA {rva:#x} leaves the raw data of section {:?}",
                section.name()
            )));
        }
        let offset = u64::from(section.raw_pointer) + delta;
        read_exact(&self.source, offset, len)
    }

    /// `len` bytes at virtual address `va`, with the same bounds as
    /// [`ExecutableView::read_rva`].
    pub fn read_va(&self, va: u64, len: usize) -> Result<Vec<u8>, Error> {
        let rva = self
            .va_to_rva(va)
            .ok_or_else(|| malformed(format!("VA {va:#x} is below the image base")))?;
        self.read_rva(rva, len)
    }

    /// A SHA-256 digest of the whole executable. Streams the file; `cancel`
    /// stops it between chunks.
    pub fn sha256(&self, cancel: &AtomicBool) -> Result<[u8; 32], BinaryError> {
        sha256(&mut self.source.clone(), cancel)
    }

    /// A snapshot [`Identity`]: the length and SHA-256 of the executable.
    pub fn identity(&self, cancel: &AtomicBool) -> Result<Identity, BinaryError> {
        Ok(Identity {
            len: self.source.len(),
            sha256: self.sha256(cancel)?,
        })
    }
}

/// Reads exactly `len` bytes at `offset`, cloning the shared handle so the
/// read is positional and does not disturb other readers.
fn read_exact(source: &Source, offset: u64, len: usize) -> Result<Vec<u8>, Error> {
    let bytes = read_at(&mut source.clone(), offset, len)?;
    if bytes.len() != len {
        return Err(malformed(format!(
            "expected {len} bytes at {offset:#x}, found {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
