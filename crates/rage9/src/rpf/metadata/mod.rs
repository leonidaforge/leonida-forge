//! The RPF9 table of contents: a dictionary-encoded columnar table in the
//! metadata area `[0, hdr[0x04])`.
//!
//! The engine processes parts of the stored metadata in place before it reads
//! the table. [`Stored`] holds the bytes as they are in the archive and reports
//! which of those passes apply. Only metadata that no pass touches, or that was
//! decoded elsewhere, becomes [`Metadata`], the parsed table.
//!
//! [`Stored::transform`] runs the cipher passes with ciphers that the caller
//! supplies (see [`transform`]). The block operation and keys for real archives
//! are not available, so this does not decrypt them.
//!
//! Layouts follow the research documentation for executable build e95020b2.
//! Unlike the engine, every count, offset and index is checked.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;

use super::{HEADER_LEN, MAGIC};
pub use companion::{Companion, Companions, Status as CompanionStatus};
pub use entry::{Entry, Field};
pub(crate) use payload::PayloadSource;
pub use payload::{Payload, StreamTransform};
use transform::{Algorithm, Cipher, CipherDescriptor, CipherSource, StreamRange};

mod companion;
mod entry;
mod payload;
pub mod probe;
pub mod provider;
pub mod recognize;
pub mod signature;
pub mod transform;
pub mod verify;

/// Field keys whose meaning is established.
pub mod keys {
    pub const NAME_HASH: u64 = 0x73BC_B72D_CE74_F11F;
    pub const LOCATION_R: u64 = 0xBA18_0AFB_232D_1B4B;
    pub const LOCATION_F: u64 = 0x33F7_0DFA_F2C5_0989;
    pub const LOCATION_A: u64 = 0x4EAA_16DD_8299_95BC;
    pub const CHUNK_TABLE: u64 = 0xE0C1_2D7A_5D48_84C5;
    pub const PAYLOAD_TRANSFORM: u64 = 0x2860_30A3_58A7_89FB;
    /// The 32-bit key of rows whose type uses the 32-bit class.
    pub const NAME_KEY: u64 = 0xB707_6B62_45D3_5FB5;
    pub const READ_SOURCE: u64 = 0xCBB6_8FF7_B707_8DB7;
}

pub const DESCRIPTOR_LEN: usize = 24;
/// The row count limit. Row index `0xFFFF` is the engine's invalid index.
pub const MAX_ROWS: u32 = 0xFFFF;
const A_RECORD_LEN: usize = 8;
/// The `B` sub-block holding the per-archive cipher descriptor.
const DESCRIPTOR_SUB_BLOCK: u16 = 1;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    TooLarge {
        len: u64,
        limit: u64,
    },
    Invalid(String),
    /// The engine processes the stored metadata before use, and that
    /// processing is not implemented.
    Transformed(Processing),
    Cipher(transform::Error),
    /// The entry's stored bytes are not its contents.
    Encoded {
        row: u32,
        encoding: &'static str,
    },
    /// The entry is read through an alternate source that was not supplied.
    ReadSource {
        row: u32,
        index: u32,
    },
    /// The entry's contents are stored in a way that is not supported.
    Undecodable {
        row: u32,
        reason: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::TooLarge { len, limit } => {
                write!(f, "the metadata is too large ({len} bytes, limit {limit})")
            }
            Error::Invalid(reason) => write!(f, "invalid RPF9 metadata: {reason}"),
            Error::Transformed(processing) => write!(
                f,
                "the stored metadata is processed before use ({processing}), which is not supported"
            ),
            Error::Cipher(err) => write!(f, "metadata cipher pass failed: {err}"),
            Error::Encoded { row, encoding } => write!(
                f,
                "entry {row} is stored {encoding}, so its stored bytes are not its contents"
            ),
            Error::ReadSource { row, index } => write!(
                f,
                "entry {row} is read through alternate source {index}, which is not available"
            ),
            Error::Undecodable { row, reason } => {
                write!(f, "entry {row} cannot be decoded: {reason}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<transform::Error> for Error {
    fn from(err: transform::Error) -> Self {
        Error::Cipher(err)
    }
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::Invalid(reason.into())
}

fn array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    data.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    array(data, offset).map(u16::from_le_bytes)
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    array(data, offset).map(u32::from_le_bytes)
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    array(data, offset).map(u64::from_le_bytes)
}

fn align(offset: u64, to: u64) -> Option<u64> {
    Some(offset.checked_add(to - 1)? & !(to - 1))
}

fn to_usize(value: u64) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| invalid("offset exceeds the address space"))
}

/// The counts and flags in the 0x40-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// `hdr[0x04]`, the end of the metadata area.
    pub metadata_len: u32,
    /// `hdr[0x08]`, the end of the primary area.
    pub primary_len: u32,
    /// `A`, the number of 8-byte records in the `A` table.
    pub a_records: u16,
    /// `B`, the size of the `B` block.
    pub b_len: u32,
    /// `C`.
    pub columns: u16,
    /// `D`, the columns stored in the secondary area.
    pub secondary_columns: u16,
    /// `E`.
    pub rows: u32,
    /// `F`, the width of a compact index: 1, 2 or 4.
    pub cell_width: u8,
    /// `G`. Bit 0 selects 16-byte region alignment.
    pub flags: u8,
    /// `hdr[0x2E]`, the cipher selector of the static pass.
    pub selector: u8,
    /// `u32@0x30`, the length of the `B` trailer.
    pub b_trailer_len: u32,
    /// `u32@0x0C`, the byte length of the trailing region after the stored
    /// payload data. Zero when the archive declares none.
    pub trailer_len: u32,
}

impl Prefix {
    pub fn parse(header: &[u8]) -> Result<Self, Error> {
        let header = header
            .get(..HEADER_LEN)
            .ok_or_else(|| invalid("shorter than the header"))?;
        if !header.starts_with(&MAGIC) {
            return Err(invalid("not an RPF9 header"));
        }
        let field = |offset| u32_at(header, offset).unwrap_or(0);
        let short = |offset| u16_at(header, offset).unwrap_or(0);
        let byte = |offset: usize| header.get(offset).copied().unwrap_or(0);
        let prefix = Prefix {
            metadata_len: field(0x04),
            primary_len: field(0x08),
            a_records: short(0x1A),
            b_len: field(0x1C),
            columns: short(0x20),
            secondary_columns: short(0x22),
            rows: field(0x24),
            cell_width: byte(0x2C),
            flags: byte(0x2D),
            selector: byte(0x2E),
            b_trailer_len: field(0x30),
            trailer_len: field(0x0C),
        };
        if (prefix.primary_len as usize) < HEADER_LEN {
            return Err(invalid("the primary area ends inside the header"));
        }
        if prefix.primary_len > prefix.metadata_len {
            return Err(invalid("the primary area ends after the metadata area"));
        }
        if prefix.secondary_columns > prefix.columns {
            return Err(invalid("more secondary columns than columns"));
        }
        if !matches!(prefix.cell_width, 1 | 2 | 4) {
            return Err(invalid(format!(
                "unsupported compact index width {}",
                prefix.cell_width
            )));
        }
        if prefix.rows > MAX_ROWS {
            return Err(invalid(format!("{} rows exceed the limit", prefix.rows)));
        }
        if prefix.b_trailer_len > prefix.b_len {
            return Err(invalid("the B trailer is longer than the B block"));
        }
        Ok(prefix)
    }

    pub fn primary_columns(&self) -> u16 {
        self.columns - self.secondary_columns
    }

    fn aligned16(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// Region offsets within the metadata area, as the engine's layout builder
/// computes them. The engine rounds addresses; these offsets match as long as
/// its buffer starts on a 16-byte boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub a_table: Range<usize>,
    pub b_block: Range<usize>,
    pub descriptors: Range<usize>,
    pub primary_cells: Range<usize>,
    pub primary_pool: Range<usize>,
    pub secondary_cells: Range<usize>,
    pub secondary_pool: Range<usize>,
}

impl Layout {
    pub fn new(prefix: &Prefix) -> Result<Self, Error> {
        let overflow = || invalid("region offsets overflow");
        let (a_align, region_align) = if prefix.aligned16() { (16, 16) } else { (4, 8) };
        let cell_width = u64::from(prefix.cell_width);
        let a = align(HEADER_LEN as u64, a_align).ok_or_else(overflow)?;
        let a_end = a + u64::from(prefix.a_records) * A_RECORD_LEN as u64;
        let b = align(a_end, region_align).ok_or_else(overflow)?;
        let b_end = b + u64::from(prefix.b_len);
        let descriptors = align(b_end, region_align).ok_or_else(overflow)?;
        let descriptors_end = descriptors + u64::from(prefix.columns) * DESCRIPTOR_LEN as u64;
        let primary_cells = align(descriptors_end, cell_width).ok_or_else(overflow)?;
        let primary_cells_end =
            primary_cells + store_len(prefix.primary_columns(), prefix.rows, prefix.cell_width)?;
        let primary_pool = align(primary_cells_end, 8).ok_or_else(overflow)?;
        let primary_len = u64::from(prefix.primary_len);
        if primary_pool > primary_len {
            return Err(invalid(format!(
                "the primary regions end at {primary_pool:#x}, after the primary area ({primary_len:#x})"
            )));
        }
        let secondary_cells = align(primary_len, cell_width).ok_or_else(overflow)?;
        let secondary_cells_end =
            secondary_cells + store_len(prefix.secondary_columns, prefix.rows, prefix.cell_width)?;
        let secondary_pool = align(secondary_cells_end, 8).ok_or_else(overflow)?;
        let metadata_len = u64::from(prefix.metadata_len);
        if secondary_pool > metadata_len {
            return Err(invalid(format!(
                "the secondary regions end at {secondary_pool:#x}, after the metadata area ({metadata_len:#x})"
            )));
        }
        let range = |start: u64, end: u64| Ok::<_, Error>(to_usize(start)?..to_usize(end)?);
        Ok(Self {
            a_table: range(a, a_end)?,
            b_block: range(b, b_end)?,
            descriptors: range(descriptors, descriptors_end)?,
            primary_cells: range(primary_cells, primary_cells_end)?,
            primary_pool: range(primary_pool, primary_len)?,
            secondary_cells: range(secondary_cells, secondary_cells_end)?,
            secondary_pool: range(secondary_pool, metadata_len)?,
        })
    }
}

/// The engine computes index store sizes as 32-bit products. A product that
/// would wrap is rejected.
fn store_len(columns: u16, rows: u32, cell_width: u8) -> Result<u64, Error> {
    u32::from(columns)
        .checked_mul(rows)
        .and_then(|cells| cells.checked_mul(u32::from(cell_width)))
        .map(u64::from)
        .ok_or_else(|| invalid("the index store size overflows 32 bits"))
}

/// The end of the stored payload data, `archive_len - hdr[0x0C]`.
///
/// A zero length declares no trailing region and leaves the whole file
/// available. A declared boundary must be a multiple of 16, lie above the
/// metadata end and below the end of the file: the bounds the measured
/// archive population holds. The trailing bytes themselves are not read.
fn payload_end(prefix: &Prefix, archive_len: u64) -> Result<u64, Error> {
    let trailer = u64::from(prefix.trailer_len);
    if trailer == 0 {
        return Ok(archive_len);
    }
    let end = archive_len.checked_sub(trailer).ok_or_else(|| {
        invalid(format!(
            "the {trailer}-byte trailing region is longer than the {archive_len}-byte archive"
        ))
    })?;
    if end % 16 != 0 {
        return Err(invalid(format!(
            "the trailing region starts at {end:#x}, not on a 16-byte boundary"
        )));
    }
    if end <= u64::from(prefix.metadata_len) {
        return Err(invalid(format!(
            "the trailing region starts at {end:#x}, at or before the metadata end ({:#x})",
            prefix.metadata_len
        )));
    }
    Ok(end)
}

/// The in-place passes the engine's validation chain runs over stored
/// metadata. A pass that runs may still leave the bytes unchanged, for
/// example with a no-op cipher type; that depends on descriptor contents and
/// is not modelled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Processing {
    /// Step 1 processes the `A` table and `B` block. Runs when `hdr[0x2E]` is
    /// nonzero.
    pub static_pass: bool,
    /// Steps 4 and 5 process the primary area from the `B` trailer and the
    /// secondary area. They run when `B` sub-block 1 exists. `None` when that
    /// can only be seen after the static pass.
    pub archive_pass: Option<bool>,
}

impl Processing {
    pub fn is_none(&self) -> bool {
        !self.static_pass && self.archive_pass == Some(false)
    }
}

impl fmt::Display for Processing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let archive = match self.archive_pass {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        };
        let static_pass = if self.static_pass { "yes" } else { "no" };
        write!(f, "static pass: {static_pass}, archive pass: {archive}")
    }
}

/// What the header and, where it is needed, the `A` table tell about the
/// stored metadata, read without the rest of the metadata area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub prefix: Prefix,
    pub layout: Layout,
    pub processing: Processing,
    /// `B` sub-block 1 as stored, the cipher descriptor of the archive pass.
    /// `None` if it is absent, lies inside the static pass or is not inside
    /// the metadata area.
    pub archive_descriptor: Option<CipherDescriptor>,
    /// The end of the stored payload data, from the declared trailing region.
    pub payload_end: u64,
}

impl Probe {
    /// Why the stored bytes are not what the engine reads, or `None` if no
    /// pass applies. Only the CBC algorithm is described as encryption.
    pub fn unsupported(&self) -> Option<String> {
        let describe = |pass: &str, kind: u16| match Algorithm::of(kind) {
            Ok(Algorithm::Cbc) => format!(
                "it is encrypted: the {pass} decrypts it with cipher type {kind}, whose key is not available"
            ),
            Ok(Algorithm::Identity) => format!(
                "the {pass} processes it with cipher type {kind}, a no-op cipher, but the engine's key lookup for it is not reproduced"
            ),
            Ok(Algorithm::Untraced(id)) => format!(
                "the {pass} processes it with cipher type {kind}, algorithm {id:#x}, which is not supported"
            ),
            Err(err) => format!("the {pass} uses an {err}"),
        };
        if self.processing.static_pass {
            let index = self.prefix.selector >> 1;
            return Some(describe("static pass", transform::static_kind(index)));
        }
        if self.processing.archive_pass != Some(true) {
            return None;
        }
        Some(match &self.archive_descriptor {
            Some(descriptor) => describe("archive pass", descriptor.kind),
            None => "the archive pass processes it with a cipher descriptor that lies outside the metadata area".to_string(),
        })
    }
}

/// The `B` offset of the first `A` record for sub-block `id`. Like the
/// engine, this does not require the offset to lie in the `B` block.
fn find_sub_block(a_table: &[u8], id: u16) -> Option<u32> {
    a_table
        .as_chunks::<A_RECORD_LEN>()
        .0
        .iter()
        .find(|record| u16_at(*record, 0) == Some(id))
        .and_then(|record| u32_at(record, 4))
}

fn read_range(source: &mut (impl Read + Seek), range: Range<usize>) -> Result<Vec<u8>, Error> {
    source.seek(SeekFrom::Start(range.start as u64))?;
    let mut bytes = vec![0; range.len()];
    source.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The step-1 `A` span: `A` starts at `0x40` and covers `align16(count * 8)`
/// bytes.
pub(crate) fn step1_a_span(prefix: &Prefix, layout: &Layout) -> Result<Range<usize>, Error> {
    let overflow = || invalid("static pass spans overflow");
    let a = layout.a_table.start;
    let a_len = to_usize(align(u64::from(prefix.a_records) * 8, 16).ok_or_else(overflow)?)?;
    let a_end = a.checked_add(a_len).ok_or_else(overflow)?;
    Ok(a..a_end)
}

/// The engine computes the start of `B` as `0x40 + align16(A * 8)` and the
/// end of `B` as the start of the descriptors when it places cipher spans,
/// while the layout aligns by `G`. Where the two disagree, the engine's spans
/// would cover other bytes than the layout's regions, so such metadata is
/// rejected.
pub(crate) fn check_span_formulas(prefix: &Prefix, layout: &Layout) -> Result<(), Error> {
    let overflow = || invalid("cipher span offsets overflow");
    let b = align(u64::from(prefix.a_records) * 8, 16)
        .map(|a| HEADER_LEN as u64 + a)
        .ok_or_else(overflow)?;
    let b_end = b + u64::from(prefix.b_len);
    if layout.b_block.start as u64 != b || layout.descriptors.start as u64 != b_end {
        return Err(invalid(format!(
            "the cipher spans place B at {b:#x}..{b_end:#x}, the layout at {:#x}..{:#x} \
             with descriptors at {:#x}",
            layout.b_block.start, layout.b_block.end, layout.descriptors.start
        )));
    }
    Ok(())
}

/// The metadata area as stored in the archive.
#[derive(Debug, Clone)]
pub struct Stored {
    bytes: Vec<u8>,
    prefix: Prefix,
    layout: Layout,
    /// Where the stored payload data ends, from the declared trailing region.
    /// `None` when the metadata was built from decoded bytes.
    payload_end: Option<u64>,
}

impl Stored {
    /// Reads `[0, hdr[0x04])` from the start of `source`. For an archive
    /// inside a larger file or another archive, `source` is a
    /// [`lforge_binary::Source::slice`] of it, which keeps all offsets
    /// archive-relative.
    pub fn read(source: &mut (impl Read + Seek), limit: u64) -> Result<Self, Error> {
        let (prefix, _, payload_end) = Self::read_prefix(source)?;
        let len = u64::from(prefix.metadata_len);
        if len > limit {
            return Err(Error::TooLarge { len, limit });
        }
        source.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(to_usize(len)?);
        source.take(len).read_to_end(&mut bytes)?;
        Self::finish(bytes, payload_end)
    }

    /// The prefix of a metadata area that lies inside `source`, the archive
    /// length, and the end of the stored payload data when the header
    /// declares a trailing region.
    fn read_prefix(source: &mut (impl Read + Seek)) -> Result<(Prefix, u64, Option<u64>), Error> {
        let archive_len = source.seek(SeekFrom::End(0))?;
        source.seek(SeekFrom::Start(0))?;
        let mut header = [0; HEADER_LEN];
        source.read_exact(&mut header)?;
        let prefix = Prefix::parse(&header)?;
        if u64::from(prefix.metadata_len) > archive_len {
            return Err(invalid("the metadata area ends after the end of the file"));
        }
        let end = payload_end(&prefix, archive_len)?;
        let declared = (prefix.trailer_len != 0).then_some(end);
        Ok((prefix, archive_len, declared))
    }

    /// Which processing passes apply, without reading the whole metadata
    /// area: the header, and only if `hdr[0x2E]` is zero, the `A` table and
    /// `B` sub-block 1, which the static pass would otherwise process. The
    /// checks are those of [`Stored::read`], except for its size limit, as
    /// nothing else is read.
    pub fn probe(source: &mut (impl Read + Seek)) -> Result<Probe, Error> {
        let (prefix, archive_len, payload_end) = Self::read_prefix(source)?;
        let layout = Layout::new(&prefix)?;
        let mut probe = Probe {
            prefix,
            processing: Processing {
                static_pass: prefix.selector != 0,
                archive_pass: None,
            },
            layout,
            archive_descriptor: None,
            payload_end: payload_end.unwrap_or(archive_len),
        };
        if probe.processing.static_pass {
            return Ok(probe);
        }
        let a_table = read_range(source, probe.layout.a_table.clone())?;
        let offset = find_sub_block(&a_table, DESCRIPTOR_SUB_BLOCK);
        probe.processing.archive_pass = Some(offset.is_some());
        let descriptor = offset.and_then(|offset| {
            let start = probe.layout.b_block.start.checked_add(offset as usize)?;
            let end = start.checked_add(CipherDescriptor::LEN)?;
            (end as u64 <= u64::from(prefix.metadata_len)).then_some(start..end)
        });
        if let Some(range) = descriptor {
            probe.archive_descriptor = CipherDescriptor::parse(&read_range(source, range)?);
        }
        Ok(probe)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::finish(bytes, None)
    }

    fn finish(bytes: Vec<u8>, payload_end: Option<u64>) -> Result<Self, Error> {
        let prefix = Prefix::parse(&bytes)?;
        if bytes.len() as u64 != u64::from(prefix.metadata_len) {
            return Err(invalid(format!(
                "{} bytes given for a metadata area of {}",
                bytes.len(),
                prefix.metadata_len
            )));
        }
        let layout = Layout::new(&prefix)?;
        Ok(Self {
            bytes,
            prefix,
            layout,
            payload_end,
        })
    }

    /// Where the stored payload data ends, when the archive declared it.
    pub fn payload_end(&self) -> Option<u64> {
        self.payload_end
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn processing(&self) -> Processing {
        let static_pass = self.prefix.selector != 0;
        Processing {
            static_pass,
            archive_pass: (!static_pass).then(|| self.has_sub_block(DESCRIPTOR_SUB_BLOCK)),
        }
    }

    fn has_sub_block(&self, id: u16) -> bool {
        self.sub_block(&self.bytes, id).is_some()
    }

    /// The `B` offset of sub-block `id`, from the `A` table in `bytes`.
    fn sub_block(&self, bytes: &[u8], id: u16) -> Option<u32> {
        find_sub_block(
            bytes.get(self.layout.a_table.clone()).unwrap_or_default(),
            id,
        )
    }

    /// Step 1 spans. They start at the `A` table and `B` block of the layout.
    fn static_spans(&self) -> Result<Vec<Range<usize>>, Error> {
        let overflow = || invalid("static pass spans overflow");
        let a = step1_a_span(&self.prefix, &self.layout)?;
        let b_len = to_usize(u64::from(self.prefix.b_len))?;
        Ok(if self.prefix.selector & 1 != 0 {
            let b = self.layout.b_block.start;
            let b_trailer = to_usize(u64::from(self.prefix.b_trailer_len))?;
            let b_end = b.checked_add(b_len - b_trailer).ok_or_else(overflow)?;
            vec![a, b..b_end]
        } else {
            let ab = a.start..a.end.checked_add(b_len).ok_or_else(overflow)?;
            vec![ab]
        })
    }

    /// See [`check_span_formulas`].
    fn check_span_formulas(&self) -> Result<(), Error> {
        check_span_formulas(&self.prefix, &self.layout)
    }

    /// The step 4 span, computed as the engine computes it.
    fn primary_span(&self) -> Result<Range<usize>, Error> {
        let start = align(u64::from(self.prefix.a_records) * 8, 16)
            .map(|a| HEADER_LEN as u64 + a + u64::from(self.prefix.b_len))
            .ok_or_else(|| invalid("primary pass span overflows"))?
            - u64::from(self.prefix.b_trailer_len);
        Ok(to_usize(start)?..to_usize(u64::from(self.prefix.primary_len))?)
    }

    /// `B` sub-block 1, read from `bytes` after step 1.
    fn archive_descriptor(&self, bytes: &[u8]) -> Result<Option<CipherDescriptor>, Error> {
        let Some(offset) = self.sub_block(bytes, DESCRIPTOR_SUB_BLOCK) else {
            return Ok(None);
        };
        self.layout
            .b_block
            .start
            .checked_add(offset as usize)
            .and_then(|start| CipherDescriptor::parse(bytes.get(start..)?))
            .map(Some)
            .ok_or_else(|| invalid("B sub-block 1 ends after the metadata area"))
    }

    /// Runs the cipher passes of the validation chain, steps 1, 4 and 5, on a
    /// copy of the stored bytes. Each step initializes its own cipher. The
    /// signature check of step 2 is not performed. On failure nothing of the
    /// partly processed copy is returned.
    ///
    /// The engine runs step 5 in read modes 0 and 1 (view state below 2) when
    /// the secondary area is non-empty. Both modes hold the same secondary
    /// bytes, in one buffer or two; `Stored` holds them in one. Other states
    /// are not modelled.
    pub fn transform(&self, source: &impl CipherSource) -> Result<Transformed, Error> {
        let (mut bytes, mut key_lookup_skipped) = self.decrypt_step1(source)?;
        key_lookup_skipped |= self.decrypt_archive(&mut bytes, source)?.unwrap_or(false);
        Ok(Transformed {
            bytes,
            prefix: self.prefix,
            layout: self.layout.clone(),
            payload_end: self.payload_end,
            key_lookup_skipped,
        })
    }

    /// Runs step 1 on a copy of the stored bytes. The signature and steps 4
    /// and 5 are not processed.
    pub(crate) fn decrypt_step1(
        &self,
        source: &impl CipherSource,
    ) -> Result<(Vec<u8>, bool), Error> {
        if !self.processing().is_none() {
            self.check_span_formulas()?;
        }
        let mut bytes = self.bytes.clone();
        if self.prefix.selector == 0 {
            return Ok((bytes, false));
        }
        let index = self.prefix.selector >> 1;
        let kind = source
            .static_kind(index)
            .ok_or(transform::Error::NoStaticDescriptor(index))?;
        let (key_id, parameter) = source
            .static_descriptor(index)
            .ok_or(transform::Error::NoStaticDescriptor(index))?;
        let descriptor = CipherDescriptor {
            key_id,
            kind,
            parameter,
        };
        let skipped = Algorithm::of(kind)? == Algorithm::Identity;
        Cipher::new(&descriptor, |key_id| {
            source.cbc_block_for(descriptor.kind, key_id)
        })?
        .run(&mut bytes, &self.static_spans()?)?;
        Ok((bytes, skipped))
    }

    /// Runs steps 4 and 5 over post-step-1 bytes with the `B` sub-block 1
    /// descriptor. Returns whether algorithm 0 was used.
    pub(crate) fn decrypt_archive(
        &self,
        bytes: &mut [u8],
        source: &impl CipherSource,
    ) -> Result<Option<bool>, Error> {
        let Some(descriptor) = self.archive_descriptor(bytes)? else {
            return Ok(None);
        };
        let skipped = Algorithm::of(descriptor.kind)? == Algorithm::Identity;
        Cipher::new(&descriptor, |key_id| {
            source.cbc_block_for(descriptor.kind, key_id)
        })?
        .run(bytes, &[self.primary_span()?])?;
        let secondary = to_usize(u64::from(self.prefix.primary_len))?
            ..to_usize(u64::from(self.prefix.metadata_len))?;
        if !secondary.is_empty() {
            Cipher::new(&descriptor, |key_id| {
                source.cbc_block_for(descriptor.kind, key_id)
            })?
            .run(bytes, &[secondary])?;
        }
        Ok(Some(skipped))
    }

    /// The parsed table, if the engine runs no processing pass over these
    /// bytes. The engine's signature check is not performed, so the result
    /// is unverified.
    pub fn decode(self) -> Result<Metadata, Error> {
        let processing = self.processing();
        if !processing.is_none() {
            return Err(Error::Transformed(processing));
        }
        Ok(Metadata {
            bytes: self.bytes,
            prefix: self.prefix,
            layout: self.layout,
            payload_end: self.payload_end,
        })
    }
}

/// The metadata area after the cipher passes of the validation chain, with
/// ciphers from a [`CipherSource`]. The signature is not checked, so the bytes
/// are unauthenticated, and success does not mean the engine accepts the
/// archive.
#[derive(Debug, Clone)]
pub struct Transformed {
    bytes: Vec<u8>,
    prefix: Prefix,
    layout: Layout,
    payload_end: Option<u64>,
    key_lookup_skipped: bool,
}

impl Transformed {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether a pass used algorithm 0. The engine looks up a key for it
    /// and rejects the archive if that fails; this implementation does not,
    /// so such a pass may succeed here and fail in the engine.
    pub fn key_lookup_skipped(&self) -> bool {
        self.key_lookup_skipped
    }

    /// The parsed table. No signature is checked: the result is
    /// unauthenticated, like that of [`Stored::decode`].
    pub fn decode(self) -> Metadata {
        Metadata {
            bytes: self.bytes,
            prefix: self.prefix,
            layout: self.layout,
            payload_end: self.payload_end,
        }
    }
}

/// One 24-byte column descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    pub key: u64,
    /// No traced engine code reads these bytes.
    pub unknown_08: [u8; 4],
    pub pool_offset: u32,
    pub width: u16,
    /// No traced engine code reads these bytes.
    pub unknown_12: [u8; 6],
}

impl Descriptor {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            key: u64_at(bytes, 0x00)?,
            unknown_08: array(bytes, 0x08)?,
            pool_offset: u32_at(bytes, 0x0C)?,
            width: u16_at(bytes, 0x10)?,
            unknown_12: array(bytes, 0x12)?,
        })
    }
}

/// The three alternative entry location layouts, in the order the engine
/// tries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordLayout {
    R,
    F,
    A,
}

impl RecordLayout {
    pub const PRIORITY: [RecordLayout; 3] = [RecordLayout::R, RecordLayout::F, RecordLayout::A];

    pub fn key(self) -> u64 {
        match self {
            RecordLayout::R => keys::LOCATION_R,
            RecordLayout::F => keys::LOCATION_F,
            RecordLayout::A => keys::LOCATION_A,
        }
    }

    fn min_len(self) -> usize {
        match self {
            RecordLayout::R => 0x12,
            RecordLayout::F => 0x18,
            RecordLayout::A => 0x10,
        }
    }
}

const MASK_40: u64 = 0xFF_FFFF_FFFF;
const MASK_44: u64 = 0xFFF_FFFF_FFFF;
const MASK_48: u64 = 0xFFFF_FFFF_FFFF;

/// Where an entry's payload is and how it is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub layout: RecordLayout,
    /// Relative to the archive base.
    pub payload_offset: u64,
    pub stored_len: u64,
    pub logical_len: u64,
    pub type_id: u8,
    pub mode: u8,
}

impl Location {
    pub fn parse(layout: RecordLayout, value: &[u8]) -> Result<Self, Error> {
        let short = || {
            invalid(format!(
                "a {layout:?} location record of {} bytes is shorter than {:#x}",
                value.len(),
                layout.min_len()
            ))
        };
        if value.len() < layout.min_len() {
            return Err(short());
        }
        let u32_field = |offset| u32_at(value, offset).ok_or_else(short);
        let u64_field = |offset| u64_at(value, offset).ok_or_else(short);
        let byte = |offset: usize| value.get(offset).copied().ok_or_else(short);
        // The engine shifts the 32-bit stored-size fields of R and A in 32-bit
        // arithmetic, so their result wraps above 4 GiB.
        Ok(match layout {
            RecordLayout::R => Self {
                layout,
                payload_offset: u64::from(u32_field(0x0C)?) << 4,
                stored_len: u64::from(u32_field(0x08)?.wrapping_shl(4)),
                logical_len: u64::from(u32_field(0x04)? & 0xFFFF_FFF0)
                    + u64::from(u32_field(0x00)? & 0x7FFF_FFF0),
                type_id: byte(0x10)?,
                mode: byte(0x11)?,
            },
            RecordLayout::F => Self {
                layout,
                payload_offset: (u64_field(0x00)? & MASK_40) << 4,
                stored_len: (u64_field(0x08)? & MASK_40) << 4,
                logical_len: u64_field(0x10)? & MASK_44,
                type_id: byte(0x05)?,
                mode: byte(0x06)?,
            },
            RecordLayout::A => Self {
                layout,
                payload_offset: u64::from(u32_field(0x04)?) << 4,
                stored_len: u64::from(u32_field(0x00)?.wrapping_shl(4)),
                logical_len: u64_field(0x08)? & MASK_48,
                type_id: byte(0x0E)?,
                mode: byte(0x0F)?,
            },
        })
    }

    pub fn is_compressed(&self) -> bool {
        self.mode != 0
    }

    /// Archive offsets of the stored bytes. `archive_base` is where the
    /// archive starts in its file.
    pub fn stored_range(&self, archive_base: u64) -> Option<Range<u64>> {
        let start = archive_base.checked_add(self.payload_offset)?;
        Some(start..start.checked_add(self.stored_len)?)
    }
}

/// One decoded chunk table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub logical_len: u32,
    pub stored_len: u32,
    pub padding: u32,
    pub compressed_len: u32,
    pub method: u8,
}

impl Chunk {
    /// Decodes one entry. `None` for an encoding other than 2, 3 or 4.
    pub fn decode(entry: u64, encoding: u8) -> Option<Self> {
        let low = entry as u32;
        let high = (entry >> 32) as u32;
        let top = (entry >> 56) as u8;
        match encoding {
            2 => {
                let padding = (high >> 26) & 0xF;
                let stored_len = ((entry >> 28) as u32) & 0x0FFF_FFF0;
                Some(Self {
                    logical_len: (low & 0xFF_FFFF) << 4,
                    stored_len,
                    padding,
                    compressed_len: stored_len.wrapping_sub(padding),
                    method: top >> 6,
                })
            }
            3 => {
                // The padding nibble lies inside the field the compressed size
                // comes from. The engine reads both from the same bits.
                let field = (entry >> 16) as u32;
                let compressed_len = 0x1_0000 - (field & 0xFFFF);
                let padding = field & 0xF;
                Some(Self {
                    logical_len: 0x1_0000 - (low & 0xFFFF),
                    stored_len: padding + compressed_len,
                    padding,
                    compressed_len,
                    method: (top >> 4) & 3,
                })
            }
            4 => {
                let padding = (high >> 20) & 0xF;
                let stored_len = ((entry >> 24) as u32) & 0x0FFF_FFF0;
                Some(Self {
                    logical_len: low & 0x0FFF_FFFF,
                    stored_len,
                    padding,
                    compressed_len: stored_len.wrapping_sub(padding),
                    method: top & 3,
                })
            }
            _ => None,
        }
    }

    /// Chunk method 3 selects the codec. Other methods store the chunk as is.
    pub fn is_compressed(&self) -> bool {
        self.method == 3
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkTable {
    pub encoding: u8,
    pub chunks: Vec<Chunk>,
}

/// The stored prefix before the first chunk of encodings 2 and 4.
pub const STORED_PREFIX_LEN: u64 = 16;

/// Why a chunk table and a location record do not describe one stored range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredPrefixError {
    /// The chunk stored sizes do not fit in 64 bits.
    Overflow,
    /// The chunks, or the prefix and chunks, take more bytes than the entry
    /// declares.
    ChunksOverrun { stored_end: u64, stored_len: u64 },
    /// The prefix and the chunks take more bytes than the entry declares.
    PrefixOverrun { prefix: u64, stored_len: u64 },
    /// The gap between the entry's stored size and the chunks is not a
    /// length this format was observed to use.
    Unsupported { prefix: u64 },
}

impl std::fmt::Display for StoredPrefixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoredPrefixError::Overflow => f.write_str("its chunk sizes overflow"),
            StoredPrefixError::ChunksOverrun {
                stored_end,
                stored_len,
            } => write!(
                f,
                "its chunks take {stored_end} stored bytes, more than its {stored_len}"
            ),
            StoredPrefixError::PrefixOverrun { prefix, stored_len } => write!(
                f,
                "its {prefix}-byte stored prefix does not fit in its {stored_len} stored bytes"
            ),
            StoredPrefixError::Unsupported { prefix } => {
                write!(f, "its chunks leave a {prefix}-byte stored prefix")
            }
        }
    }
}

impl std::error::Error for StoredPrefixError {}

impl ChunkTable {
    /// The bytes stored before chunk 0, from the entry's stored size and the
    /// sum of the chunk stored sizes.
    ///
    /// Encoding 2 always stores 16 bytes there. Encoding 4 stores the same
    /// prefix on resource-page payloads and none otherwise, so the prefix is
    /// what the stored size leaves after the chunks. Encoding 3 starts at the
    /// payload offset. Only the observed lengths 0 and 16 are accepted.
    pub fn stored_prefix(&self, stored_len: u64) -> Result<u64, StoredPrefixError> {
        let stored_sum = self
            .chunks
            .iter()
            .try_fold(0u64, |sum, chunk| {
                sum.checked_add(u64::from(chunk.stored_len))
            })
            .ok_or(StoredPrefixError::Overflow)?;
        let prefix = match self.encoding {
            2 => STORED_PREFIX_LEN,
            4 => stored_len
                .checked_sub(stored_sum)
                .ok_or(StoredPrefixError::ChunksOverrun {
                    stored_end: stored_sum,
                    stored_len,
                })?,
            _ => 0,
        };
        if !matches!(prefix, 0 | STORED_PREFIX_LEN) {
            return Err(StoredPrefixError::Unsupported { prefix });
        }
        if prefix > stored_len {
            return Err(StoredPrefixError::PrefixOverrun { prefix, stored_len });
        }
        let Some(end) = prefix.checked_add(stored_sum) else {
            return Err(StoredPrefixError::Overflow);
        };
        if end > stored_len {
            return Err(StoredPrefixError::ChunksOverrun {
                stored_end: end,
                stored_len,
            });
        }
        Ok(prefix)
    }
}

/// A pool and the range of one value inside it.
type ValueRange = (Range<usize>, Range<usize>);

/// The parsed table of contents, from metadata in the state the engine reads.
#[derive(Debug, Clone)]
pub struct Metadata {
    bytes: Vec<u8>,
    prefix: Prefix,
    layout: Layout,
    /// Where the stored payload data ends, when the archive declared it.
    payload_end: Option<u64>,
}

impl Metadata {
    /// `bytes` is the whole metadata area after the engine's processing, for
    /// example decoded elsewhere or built for a test. The caller vouches for
    /// that state: the header's processing fields are not consulted, and no
    /// signature is checked.
    pub fn from_decoded(bytes: Vec<u8>) -> Result<Self, Error> {
        let stored = Stored::from_bytes(bytes)?;
        Ok(Self {
            bytes: stored.bytes,
            prefix: stored.prefix,
            layout: stored.layout,
            payload_end: None,
        })
    }

    /// Where the stored payload data ends, when the archive declared it.
    pub fn payload_end(&self) -> Option<u64> {
        self.payload_end
    }

    pub fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn rows(&self) -> u32 {
        self.prefix.rows
    }

    pub fn descriptor(&self, column: u16) -> Option<Descriptor> {
        let start = self
            .layout
            .descriptors
            .start
            .checked_add(usize::from(column).checked_mul(DESCRIPTOR_LEN)?)?;
        if column >= self.prefix.columns {
            return None;
        }
        Descriptor::parse(self.bytes.get(start..start.checked_add(DESCRIPTOR_LEN)?)?)
    }

    pub fn descriptors(&self) -> impl Iterator<Item = Descriptor> + '_ {
        (0..self.prefix.columns).filter_map(|column| self.descriptor(column))
    }

    /// The first column with `key`, as the engine's key search returns it.
    pub fn column(&self, key: u64) -> Option<u16> {
        (0..self.prefix.columns).find(|&column| self.descriptor(column).map(|d| d.key) == Some(key))
    }

    /// The compact index of a cell. `None` for the null sentinel.
    pub fn cell(&self, row: u32, column: u16) -> Result<Option<u32>, Error> {
        if row >= self.prefix.rows {
            return Err(invalid(format!("row {row} of {}", self.prefix.rows)));
        }
        if column >= self.prefix.columns {
            return Err(invalid(format!(
                "column {column} of {}",
                self.prefix.columns
            )));
        }
        let primary = self.prefix.primary_columns();
        let (store, stride, local) = if column < primary {
            (&self.layout.primary_cells, primary, column)
        } else {
            (
                &self.layout.secondary_cells,
                self.prefix.secondary_columns,
                column - primary,
            )
        };
        let width = usize::from(self.prefix.cell_width);
        let offset = (row as usize)
            .checked_mul(usize::from(stride))
            .and_then(|cells| cells.checked_add(usize::from(local)))
            .and_then(|cell| cell.checked_mul(width))
            .ok_or_else(|| invalid("cell offset overflows"))?;
        let store = self
            .bytes
            .get(store.clone())
            .ok_or_else(|| invalid("index store outside the metadata"))?;
        let outside = || invalid("cell outside its index store");
        Ok(match self.prefix.cell_width {
            1 => {
                let index = *store.get(offset).ok_or_else(outside)?;
                (index != 0xFF).then_some(u32::from(index))
            }
            2 => {
                let index = u16_at(store, offset).ok_or_else(outside)?;
                (index != 0xFFFF).then_some(u32::from(index))
            }
            _ => Some(u32_at(store, offset).ok_or_else(outside)?),
        })
    }

    /// The pool and the element range of a cell's value.
    fn value_range(&self, row: u32, column: u16) -> Result<Option<ValueRange>, Error> {
        let Some(index) = self.cell(row, column)? else {
            return Ok(None);
        };
        let descriptor = self
            .descriptor(column)
            .ok_or_else(|| invalid("descriptor outside the metadata"))?;
        let pool = if column < self.prefix.primary_columns() {
            self.layout.primary_pool.clone()
        } else {
            self.layout.secondary_pool.clone()
        };
        let width = u64::from(descriptor.width);
        let start = (pool.start as u64)
            .checked_add(u64::from(descriptor.pool_offset))
            .and_then(|base| base.checked_add(width.checked_mul(u64::from(index))?))
            .ok_or_else(|| invalid("value offset overflows"))?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| invalid("value offset overflows"))?;
        if end > pool.end as u64 {
            return Err(invalid(format!(
                "the value of row {row}, column {column} ends at {end:#x}, after its pool ({:#x})",
                pool.end
            )));
        }
        Ok(Some((pool, to_usize(start)?..to_usize(end)?)))
    }

    pub fn value(&self, row: u32, column: u16) -> Result<Option<&[u8]>, Error> {
        Ok(self
            .value_range(row, column)?
            .and_then(|(_, range)| self.bytes.get(range)))
    }

    /// The value of the first column with `key`. `None` if no column has the
    /// key or the cell is null.
    pub fn field(&self, row: u32, key: u64) -> Result<Option<&[u8]>, Error> {
        match self.column(key) {
            Some(column) => self.value(row, column),
            None => Ok(None),
        }
    }

    pub fn name_hash(&self, row: u32) -> Result<Option<u64>, Error> {
        self.field(row, keys::NAME_HASH)?
            .map(|value| u64_at(value, 0).ok_or_else(|| invalid("name hash shorter than 8 bytes")))
            .transpose()
    }

    pub fn name_key(&self, row: u32) -> Result<Option<u32>, Error> {
        self.field(row, keys::NAME_KEY)?
            .map(|value| u32_at(value, 0).ok_or_else(|| invalid("name key shorter than 4 bytes")))
            .transpose()
    }

    /// The location record of the first layout present, in the order R, F, A.
    /// `None` if the row has none.
    pub fn location_record(&self, row: u32) -> Result<Option<Location>, Error> {
        for layout in RecordLayout::PRIORITY {
            if let Some(value) = self.field(row, layout.key())? {
                return Location::parse(layout, value).map(Some);
            }
        }
        Ok(None)
    }

    /// Like [`Metadata::location_record`], but a row without one is an error.
    pub fn location(&self, row: u32) -> Result<Location, Error> {
        self.location_record(row)?
            .ok_or_else(|| invalid(format!("row {row} has no location record")))
    }

    pub fn payload_transform(&self, row: u32) -> Result<bool, Error> {
        Ok(self.field(row, keys::PAYLOAD_TRANSFORM)?.is_some())
    }

    /// The payload-transform descriptor of `row`: the value of the
    /// [`keys::PAYLOAD_TRANSFORM`] field, which the engine hands to its cipher
    /// initializer as `u32` key identifier, `u16` cipher type and 16-byte
    /// parameter. `None` if the row has no such field.
    ///
    /// The descriptor's key identifier and type select a key state and an
    /// algorithm through the engine's registry. The block operation of that
    /// algorithm is not implemented here, so a caller MUST NOT use this to
    /// decode a payload.
    pub fn payload_cipher(&self, row: u32) -> Result<Option<CipherDescriptor>, Error> {
        let Some(value) = self.field(row, keys::PAYLOAD_TRANSFORM)? else {
            return Ok(None);
        };
        CipherDescriptor::parse(value).map(Some).ok_or_else(|| {
            invalid(format!(
                "the payload transform descriptor of row {row} is {} bytes, shorter than {}",
                value.len(),
                CipherDescriptor::LEN
            ))
        })
    }

    /// The stored range the payload transform of `row` covers, from the
    /// stream fields of the same descriptor. `None` if the row has no
    /// transform field.
    pub fn payload_transform_range(&self, row: u32) -> Result<Option<StreamRange>, Error> {
        let Some(value) = self.field(row, keys::PAYLOAD_TRANSFORM)? else {
            return Ok(None);
        };
        StreamRange::parse(value).map(Some).ok_or_else(|| {
            invalid(format!(
                "the payload transform descriptor of row {row} does not describe a usable stream range"
            ))
        })
    }

    /// The alternate source the entry's stored bytes are read through. `None`
    /// for the main source: the column is absent, the cell is null or the
    /// value is `0xFFFFFFFF`.
    pub fn read_source(&self, row: u32) -> Result<Option<u32>, Error> {
        let index = self
            .field(row, keys::READ_SOURCE)?
            .map(|value| {
                u32_at(value, 0).ok_or_else(|| invalid("read source shorter than 4 bytes"))
            })
            .transpose()?;
        Ok(index.filter(|&index| index != u32::MAX))
    }

    /// The fields of one row. Fails only for a row past the end.
    pub fn entry(&self, row: u32) -> Result<Entry, Error> {
        if row >= self.prefix.rows {
            return Err(invalid(format!("row {row} of {}", self.prefix.rows)));
        }
        Ok(Entry::read(self, row))
    }

    /// Every row, in row order.
    pub fn entries(&self) -> impl Iterator<Item = Entry> + '_ {
        (0..self.prefix.rows).map(|row| Entry::read(self, row))
    }

    /// See [`Entry::raw_range`].
    pub fn raw_range(&self, row: u32) -> Result<Range<u64>, Error> {
        self.entry(row)?.raw_range()
    }

    /// See [`Entry::raw_source`].
    pub fn raw_source(
        &self,
        row: u32,
        main: &lforge_binary::Source,
        alternates: &[Option<lforge_binary::Source>],
    ) -> Result<lforge_binary::Source, Error> {
        self.entry(row)?.raw_source(main, alternates)
    }

    /// The chunk table. Its entries are addressed relative to the value and
    /// must lie in the same pool.
    pub fn chunk_table(&self, row: u32) -> Result<Option<ChunkTable>, Error> {
        let Some((encoding, entries)) = self.chunk_entries(row)? else {
            return Ok(None);
        };
        let chunks = entries
            .into_iter()
            .filter_map(|entry| Chunk::decode(entry, encoding))
            .collect();
        Ok(Some(ChunkTable { encoding, chunks }))
    }

    /// The raw `u64` entries of the chunk table, and its encoding. The bit
    /// fields are decoded by [`Chunk::decode`].
    pub fn chunk_entries(&self, row: u32) -> Result<Option<(u8, Vec<u64>)>, Error> {
        let Some(column) = self.column(keys::CHUNK_TABLE) else {
            return Ok(None);
        };
        let Some((pool, value)) = self.value_range(row, column)? else {
            return Ok(None);
        };
        let header = self
            .bytes
            .get(value.clone())
            .filter(|header| header.len() >= 8)
            .ok_or_else(|| invalid("chunk table header shorter than 8 bytes"))?;
        let (Some(relative), Some(count), Some(&encoding)) =
            (u32_at(header, 0), u16_at(header, 4), header.get(7))
        else {
            return Err(invalid("chunk table header shorter than 8 bytes"));
        };
        if !matches!(encoding, 2..=4) {
            return Err(invalid(format!("unsupported chunk encoding {encoding}")));
        }
        let start = value
            .start
            .checked_add(relative as usize)
            .ok_or_else(|| invalid("chunk entries overflow"))?;
        let end = start
            .checked_add(usize::from(count) * 8)
            .ok_or_else(|| invalid("chunk entries overflow"))?;
        if end > pool.end {
            return Err(invalid(format!(
                "chunk entries end at {end:#x}, after their pool ({:#x})",
                pool.end
            )));
        }
        let entries = self
            .bytes
            .get(start..end)
            .ok_or_else(|| invalid("chunk entries outside the metadata"))?;
        Ok(Some((
            encoding,
            entries
                .as_chunks::<8>()
                .0
                .iter()
                .map(|entry| u64::from_le_bytes(*entry))
                .collect(),
        )))
    }
}

#[cfg(test)]
pub(crate) mod tests;
