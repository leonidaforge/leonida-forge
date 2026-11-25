//! A lossless, bounded reader for the ZIP central directory.
//!
//! The ZIP reader this build used before indexed entries by their name, so two
//! central-directory records with the same full name collapsed into one and
//! every index after the duplicate shifted. This module keeps one [`Entry`] per
//! central-directory record, in the order the directory lists them, and gives
//! each one its original index. Names are display data only; nothing here
//! resolves an entry by name.
//!
//! Only single-file archives are supported. Entry payloads decode with the
//! stored and DEFLATE methods; any other method, or an encrypted entry, is
//! reported as unsupported rather than guessed at. Decoding is bounded by a
//! caller limit, checks the declared size and the CRC-32, and never writes to
//! the archive.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

const END_RECORD: [u8; 4] = *b"PK\x05\x06";
const CENTRAL_HEADER: [u8; 4] = *b"PK\x01\x02";
const LOCAL_HEADER: [u8; 4] = *b"PK\x03\x04";
const ZIP64_LOCATOR: [u8; 4] = *b"PK\x06\x07";
const ZIP64_END_RECORD: [u8; 4] = *b"PK\x06\x06";

const END_RECORD_LEN: u64 = 22;
const CENTRAL_HEADER_LEN: usize = 46;
const LOCAL_HEADER_LEN: u64 = 30;
const ZIP64_LOCATOR_LEN: u64 = 20;
const ZIP64_END_RECORD_LEN: u64 = 56;
const MAX_COMMENT_LEN: u64 = 0xFFFF;
const ZIP64_EXTRA_ID: u16 = 0x0001;
/// Bytes copied per step while decoding.
const COPY_LEN: usize = 64 * 1024;

/// The ZIP compression methods this build decodes.
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// The flag that marks an encrypted entry.
const FLAG_ENCRYPTED: u16 = 0x0001;
/// The flag that marks an entry whose local header leaves the CRC and sizes
/// zero for a data descriptor to follow the payload.
const DATA_DESCRIPTOR_FLAG: u16 = 0x0008;
/// The flag that marks a UTF-8 name.
const FLAG_UTF8: u16 = 0x0800;

/// The category a failure belongs to. It keeps an undecodable payload apart
/// from a malformed one, so a caller can report the earliest real failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Io,
    /// The bytes are not a ZIP archive, or their structure is inconsistent.
    Malformed,
    /// A caller-supplied limit, including the entry count and metadata size.
    Limit,
    /// The compression method is not one this build decodes.
    UnsupportedCompression,
    /// The entry is encrypted.
    Encrypted,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn malformed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Malformed, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::new(ErrorKind::Io, err.to_string())
    }
}

fn check(cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::new(ErrorKind::Cancelled, "cancelled"))
    } else {
        Ok(())
    }
}

/// Caps one central-directory read.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Central-directory records kept.
    pub max_entries: u64,
    /// Bytes of central directory read.
    pub max_metadata: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 1 << 20,
            max_metadata: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Stored,
    Deflate,
    /// A method this build does not decode, with its central-directory value.
    Other(u16),
}

impl Compression {
    pub fn name(self) -> &'static str {
        match self {
            Compression::Stored => "stored",
            Compression::Deflate => "deflate",
            Compression::Other(_) => "unsupported",
        }
    }

    pub fn method(self) -> u16 {
        match self {
            Compression::Stored => METHOD_STORED,
            Compression::Deflate => METHOD_DEFLATE,
            Compression::Other(method) => method,
        }
    }

    pub fn is_supported(self) -> bool {
        matches!(self, Compression::Stored | Compression::Deflate)
    }
}

/// One central-directory record. `index` is its position in the directory and
/// identifies the entry; duplicate names keep distinct indices.
#[derive(Debug, Clone)]
pub struct Entry {
    pub index: usize,
    /// The name bytes exactly as the central directory stores them.
    pub raw_name: Vec<u8>,
    /// A display rendering of `raw_name`. Never used to identify the entry.
    pub name: String,
    pub flags: u16,
    pub compression: Compression,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_header_offset: u64,
}

impl Entry {
    /// Whether the name ends in `/`, as a directory entry does.
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }

    pub fn is_encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    /// Whether the local header leaves the CRC and sizes zero for a data
    /// descriptor to follow the payload. The central directory still carries
    /// the values this reader uses.
    pub fn has_data_descriptor(&self) -> bool {
        self.flags & DATA_DESCRIPTOR_FLAG != 0
    }

    /// Whether the name is declared UTF-8.
    pub fn is_utf8_name(&self) -> bool {
        self.flags & FLAG_UTF8 != 0
    }
}

#[derive(Debug, Clone)]
pub struct Archive {
    pub entries: Vec<Entry>,
    pub directory_start: u64,
    pub directory_len: u64,
    /// How many names occur more than once. They stay separate entries.
    pub duplicate_names: usize,
    pub zip64: bool,
}

impl Archive {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry(&self, index: usize) -> Result<&Entry, Error> {
        self.entries.get(index).ok_or_else(|| {
            Error::malformed(match self.entries.len() {
                0 => format!("ZIP entry {index}: the archive has no entries"),
                1 => format!("ZIP entry {index} is out of range: the only entry is 0"),
                count => format!(
                    "ZIP entry {index} is out of range: the entries are 0 to {}",
                    count - 1
                ),
            })
        })
    }

    /// Reads the central directory of `reader`.
    pub fn read(
        reader: &mut (impl Read + Seek),
        limits: &Limits,
        cancel: &AtomicBool,
    ) -> Result<Self, Error> {
        let len = reader.seek(SeekFrom::End(0))?;
        check(cancel)?;
        let directory = find_directory(reader, len)?;
        if directory.entries > limits.max_entries {
            return Err(Error::new(
                ErrorKind::Limit,
                format!(
                    "the ZIP central directory has {} entries, more than the {} entry limit",
                    directory.entries, limits.max_entries
                ),
            ));
        }
        if directory.size > limits.max_metadata {
            return Err(Error::new(
                ErrorKind::Limit,
                format!(
                    "the ZIP central directory is {} bytes, more than the {} byte limit",
                    directory.size, limits.max_metadata
                ),
            ));
        }
        if directory.entries == 0 {
            return Ok(Self {
                entries: Vec::new(),
                directory_start: directory.offset,
                directory_len: directory.size,
                duplicate_names: 0,
                zip64: directory.zip64,
            });
        }
        let entries = read_entries(reader, len, &directory, cancel)?;
        let duplicate_names = count_duplicates(&entries);
        Ok(Self {
            entries,
            directory_start: directory.offset,
            directory_len: directory.size,
            duplicate_names,
            zip64: directory.zip64,
        })
    }

    /// The offset of `entry`'s payload in the file. It reads the local header,
    /// because only that record gives the lengths of the local name and extra
    /// fields. `len` is the length of the file `reader` reads.
    pub fn data_start(
        &self,
        reader: &mut (impl Read + Seek),
        len: u64,
        entry: &Entry,
    ) -> Result<u64, Error> {
        let offset = entry.local_header_offset;
        if offset
            .checked_add(LOCAL_HEADER_LEN)
            .is_none_or(|end| end > len)
        {
            return Err(Error::malformed(format!(
                "ZIP entry {} starts at {offset:#x}, past the end of the file ({len:#x} bytes)",
                entry.index
            )));
        }
        let header = read_exact_at(reader, offset, LOCAL_HEADER_LEN as usize)?;
        if !header.starts_with(&LOCAL_HEADER) {
            return Err(Error::malformed(format!(
                "ZIP entry {} has no local file header at {offset:#x}",
                entry.index
            )));
        }
        let method = u16::from_le_bytes([header[8], header[9]]);
        if method != entry.compression.method() {
            return Err(Error::malformed(format!(
                "ZIP entry {} declares method {method} in its local header and {} in the directory",
                entry.index,
                entry.compression.method()
            )));
        }
        let name_len = u64::from(u16::from_le_bytes([header[26], header[27]]));
        let extra_len = u64::from(u16::from_le_bytes([header[28], header[29]]));
        let start = offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|at| at.checked_add(name_len))
            .and_then(|at| at.checked_add(extra_len))
            .ok_or_else(|| {
                Error::malformed(format!(
                    "the local header of ZIP entry {} overflows",
                    entry.index
                ))
            })?;
        if start
            .checked_add(entry.compressed_size)
            .is_none_or(|end| end > len)
        {
            return Err(Error::malformed(format!(
                "ZIP entry {} holds {} stored bytes at {start:#x}, past the end of the file ({len:#x} bytes)",
                entry.index, entry.compressed_size
            )));
        }
        Ok(start)
    }

    /// Decodes `entry` into `out`, checking the declared size and the CRC-32.
    /// `max_bytes` caps the decoded size; an entry above it fails with
    /// [`ErrorKind::Limit`] before any byte is read.
    pub fn decode_entry(
        &self,
        reader: &mut (impl Read + Seek),
        len: u64,
        entry: &Entry,
        cancel: &AtomicBool,
        max_bytes: u64,
        out: &mut dyn Write,
    ) -> Result<u64, Error> {
        if entry.is_encrypted() {
            return Err(Error::new(
                ErrorKind::Encrypted,
                format!("ZIP entry {} is encrypted", entry.index),
            ));
        }
        if !entry.compression.is_supported() {
            return Err(Error::new(
                ErrorKind::UnsupportedCompression,
                format!(
                    "ZIP entry {} uses compression method {}, which this build does not decode",
                    entry.index,
                    entry.compression.method()
                ),
            ));
        }
        if entry.uncompressed_size > max_bytes {
            return Err(Error::new(
                ErrorKind::Limit,
                format!(
                    "ZIP entry {} decodes to {} bytes, more than the {max_bytes} byte limit",
                    entry.index, entry.uncompressed_size
                ),
            ));
        }
        let start = self.data_start(reader, len, entry)?;
        reader.seek(SeekFrom::Start(start))?;
        let stored = (&mut *reader).take(entry.compressed_size);
        let mut crc = flate2::Crc::new();
        let written = match entry.compression {
            Compression::Stored => {
                let mut stored = stored;
                copy_checked(&mut stored, cancel, max_bytes, &mut crc, out)?
            }
            Compression::Deflate => {
                let mut decoder = flate2::read::DeflateDecoder::new(stored);
                copy_checked(&mut decoder, cancel, max_bytes, &mut crc, out)?
            }
            Compression::Other(_) => unreachable!("rejected above"),
        };
        if written != entry.uncompressed_size {
            return Err(Error::malformed(format!(
                "ZIP entry {} decoded to {written} bytes, not its declared {}",
                entry.index, entry.uncompressed_size
            )));
        }
        if crc.sum() != entry.crc32 {
            return Err(Error::malformed(format!(
                "ZIP entry {} has CRC-32 0x{:08X}, not the declared 0x{:08X}",
                entry.index,
                crc.sum(),
                entry.crc32
            )));
        }
        Ok(written)
    }

    /// Reads at most `max` decoded bytes of `entry` for recognition. No CRC is
    /// checked, and `complete` says whether the whole payload was read. An
    /// entry whose method is unsupported fails without decoding anything.
    pub fn read_prefix(
        &self,
        reader: &mut (impl Read + Seek),
        len: u64,
        entry: &Entry,
        cancel: &AtomicBool,
        max: usize,
    ) -> Result<Prefix, Error> {
        if entry.is_encrypted() {
            return Err(Error::new(
                ErrorKind::Encrypted,
                format!("ZIP entry {} is encrypted", entry.index),
            ));
        }
        if !entry.compression.is_supported() {
            return Err(Error::new(
                ErrorKind::UnsupportedCompression,
                format!(
                    "ZIP entry {} uses compression method {}, which this build does not decode",
                    entry.index,
                    entry.compression.method()
                ),
            ));
        }
        let start = self.data_start(reader, len, entry)?;
        reader.seek(SeekFrom::Start(start))?;
        let stored = (&mut *reader).take(entry.compressed_size);
        let mut buf = vec![0u8; max.clamp(1, COPY_LEN)];
        let mut bytes = Vec::new();
        let mut complete;
        match entry.compression {
            Compression::Stored => {
                let mut stored = stored;
                complete = read_into(&mut stored, cancel, max, &mut bytes, &mut buf)?;
            }
            Compression::Deflate => {
                let mut decoder = flate2::read::DeflateDecoder::new(stored);
                complete = read_into(&mut decoder, cancel, max, &mut bytes, &mut buf)?;
            }
            Compression::Other(_) => unreachable!("rejected above"),
        }
        // A stored entry can be read completely and still have bytes past
        // `max`; `read_into` reports whether it stopped early.
        if complete && bytes.len() as u64 > entry.uncompressed_size {
            complete = false;
        }
        Ok(Prefix { bytes, complete })
    }
}

/// The bounded result of [`Archive::read_prefix`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub bytes: Vec<u8>,
    /// Whether the whole payload was read, so the bytes are its complete
    /// contents.
    pub complete: bool,
}

fn copy_checked(
    reader: &mut dyn Read,
    cancel: &AtomicBool,
    max_bytes: u64,
    crc: &mut flate2::Crc,
    out: &mut dyn Write,
) -> Result<u64, Error> {
    let mut buf = vec![0u8; COPY_LEN];
    let mut written = 0u64;
    loop {
        check(cancel)?;
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        };
        written = written
            .checked_add(n as u64)
            .ok_or_else(|| Error::malformed("the decoded size overflowed"))?;
        if written > max_bytes {
            return Err(Error::new(
                ErrorKind::Limit,
                format!("the entry decodes to more than the {max_bytes} byte limit"),
            ));
        }
        crc.update(&buf[..n]);
        out.write_all(&buf[..n])?;
    }
    Ok(written)
}

/// Reads into `bytes` until `max` bytes are held or the stream ends. Returns
/// whether the stream ended before `max`.
fn read_into(
    reader: &mut dyn Read,
    cancel: &AtomicBool,
    max: usize,
    bytes: &mut Vec<u8>,
    buf: &mut [u8],
) -> Result<bool, Error> {
    while bytes.len() < max {
        check(cancel)?;
        let room = max - bytes.len();
        let want = room.min(buf.len());
        let n = match reader.read(&mut buf[..want]) {
            Ok(0) => return Ok(true),
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        };
        bytes.extend_from_slice(&buf[..n]);
    }
    Ok(false)
}

fn count_duplicates(entries: &[Entry]) -> usize {
    let mut names: Vec<&[u8]> = entries
        .iter()
        .map(|entry| entry.raw_name.as_slice())
        .collect();
    names.sort_unstable();
    let mut duplicates = 0;
    for pair in names.windows(2) {
        if pair[0] == pair[1] {
            duplicates += 1;
        }
    }
    duplicates
}

struct Directory {
    entries: u64,
    size: u64,
    offset: u64,
    zip64: bool,
}

fn read_exact_at(reader: &mut (impl Read + Seek), offset: u64, len: usize) -> io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Reads exactly `len` bytes, reporting a short read as a malformed record
/// rather than indexing past the bytes that were read.
fn read_full_at(
    reader: &mut (impl Read + Seek),
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, Error> {
    read_exact_at(reader, offset, len).map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            Error::malformed(format!(
                "the file ends before the {len} bytes at {offset:#x} that its records declare"
            ))
        } else {
            Error::from(err)
        }
    })
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4 bytes"))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("8 bytes"))
}

/// Finds the end of central directory record, reading the ZIP64 record when
/// the 32-bit fields overflow.
fn find_directory(reader: &mut (impl Read + Seek), len: u64) -> Result<Directory, Error> {
    if len < END_RECORD_LEN {
        return Err(Error::malformed("the file is too short for a ZIP archive"));
    }
    let tail_len = len.min(END_RECORD_LEN + MAX_COMMENT_LEN);
    let tail_start = len - tail_len;
    let tail = read_full_at(reader, tail_start, tail_len as usize)?;
    let last = tail.len() - END_RECORD_LEN as usize;
    let at = (0..=last).rev().find(|&at| {
        tail[at..].starts_with(&END_RECORD)
            && at as u64 + END_RECORD_LEN + u64::from(u16_at(&tail, at + 20)) <= tail_len
    });
    let Some(at) = at else {
        return Err(Error::malformed(
            "no end of central directory record was found; the archive may be truncated",
        ));
    };
    let record = &tail[at..at + END_RECORD_LEN as usize];
    let end_offset = tail_start + at as u64;
    let mut disk = u32::from(u16_at(record, 4));
    let mut directory_disk = u32::from(u16_at(record, 6));
    let mut entries_here = u64::from(u16_at(record, 8));
    let mut entries = u64::from(u16_at(record, 10));
    let mut size = u64::from(u32_at(record, 12));
    let mut offset = u64::from(u32_at(record, 16));
    let mut directory_end_limit = end_offset;
    let zip64 = entries == 0xFFFF || size == 0xFFFF_FFFF || offset == 0xFFFF_FFFF;
    if zip64 {
        let Some(locator_offset) = end_offset.checked_sub(ZIP64_LOCATOR_LEN) else {
            return Err(Error::malformed(
                "the ZIP64 end of central directory locator is missing",
            ));
        };
        let locator = read_full_at(reader, locator_offset, ZIP64_LOCATOR_LEN as usize)?;
        if !locator.starts_with(&ZIP64_LOCATOR) {
            return Err(Error::malformed(
                "the ZIP64 end of central directory locator is missing",
            ));
        }
        let record_offset = u64_at(&locator, 8);
        if record_offset
            .checked_add(ZIP64_END_RECORD_LEN)
            .is_none_or(|end| end > locator_offset)
        {
            return Err(Error::malformed(
                "the ZIP64 end of central directory record lies outside the file",
            ));
        }
        let record = read_full_at(reader, record_offset, ZIP64_END_RECORD_LEN as usize)?;
        if !record.starts_with(&ZIP64_END_RECORD) {
            return Err(Error::malformed(
                "the ZIP64 end of central directory record is invalid",
            ));
        }
        disk = u32_at(&record, 16);
        directory_disk = u32_at(&record, 20);
        entries_here = u64_at(&record, 24);
        entries = u64_at(&record, 32);
        size = u64_at(&record, 40);
        offset = u64_at(&record, 48);
        directory_end_limit = record_offset;
    }
    if disk != 0 || directory_disk != 0 || entries_here != entries {
        return Err(Error::malformed(
            "archives that span several files are not supported",
        ));
    }
    if offset
        .checked_add(size)
        .is_none_or(|end| end > directory_end_limit)
    {
        return Err(Error::malformed(
            "the central directory lies outside the file",
        ));
    }
    if entries
        .checked_mul(CENTRAL_HEADER_LEN as u64)
        .is_none_or(|min| min > size)
    {
        return Err(Error::malformed(format!(
            "the central directory is too small for {entries} entries"
        )));
    }
    Ok(Directory {
        entries,
        size,
        offset,
        zip64,
    })
}

fn read_entries(
    reader: &mut (impl Read + Seek),
    len: u64,
    directory: &Directory,
    cancel: &AtomicBool,
) -> Result<Vec<Entry>, Error> {
    let end = directory
        .offset
        .checked_add(directory.size)
        .ok_or_else(|| Error::malformed("the central directory range overflows"))?;
    let mut entries =
        Vec::with_capacity(usize::try_from(directory.entries.min(1 << 16)).unwrap_or(0));
    let mut at = directory.offset;
    for index in 0..directory.entries {
        check(cancel)?;
        if at
            .checked_add(CENTRAL_HEADER_LEN as u64)
            .is_none_or(|next| next > end)
        {
            return Err(Error::malformed(format!(
                "the central directory ends after {} of its {} entries",
                index, directory.entries
            )));
        }
        let header = read_exact_at(reader, at, CENTRAL_HEADER_LEN)?;
        if !header.starts_with(&CENTRAL_HEADER) {
            return Err(Error::malformed(format!(
                "central directory entry {index} at {at:#x} has no file header"
            )));
        }
        let flags = u16_at(&header, 8);
        let method = u16_at(&header, 10);
        let crc32 = u32_at(&header, 16);
        let mut compressed_size = u64::from(u32_at(&header, 20));
        let mut uncompressed_size = u64::from(u32_at(&header, 24));
        let name_len = usize::from(u16_at(&header, 28));
        let extra_len = usize::from(u16_at(&header, 30));
        let comment_len = usize::from(u16_at(&header, 32));
        let mut local_header_offset = u64::from(u32_at(&header, 42));
        let variable_end = at
            .checked_add(CENTRAL_HEADER_LEN as u64)
            .and_then(|at| at.checked_add(name_len as u64))
            .and_then(|at| at.checked_add(extra_len as u64))
            .and_then(|at| at.checked_add(comment_len as u64))
            .ok_or_else(|| {
                Error::malformed(format!("central directory entry {index} overflows"))
            })?;
        if variable_end > end {
            return Err(Error::malformed(format!(
                "central directory entry {index} extends past the directory"
            )));
        }
        let raw_name = read_exact_at(reader, at + CENTRAL_HEADER_LEN as u64, name_len)?;
        let extra = read_exact_at(
            reader,
            at + CENTRAL_HEADER_LEN as u64 + name_len as u64,
            extra_len,
        )?;
        if uncompressed_size == 0xFFFF_FFFF
            || compressed_size == 0xFFFF_FFFF
            || local_header_offset == 0xFFFF_FFFF
        {
            let (uncompressed, compressed, offset) = zip64_values(
                &extra,
                uncompressed_size == 0xFFFF_FFFF,
                compressed_size == 0xFFFF_FFFF,
                local_header_offset == 0xFFFF_FFFF,
            )
            .ok_or_else(|| {
                Error::malformed(format!(
                    "central directory entry {index} overflows a 32-bit field without a ZIP64 extra field"
                ))
            })?;
            if let Some(value) = uncompressed {
                uncompressed_size = value;
            }
            if let Some(value) = compressed {
                compressed_size = value;
            }
            if let Some(value) = offset {
                local_header_offset = value;
            }
        }
        if local_header_offset >= len {
            return Err(Error::malformed(format!(
                "central directory entry {index} starts at {local_header_offset:#x}, past the end of the file ({len:#x} bytes)"
            )));
        }
        let name = String::from_utf8_lossy(&raw_name).into_owned();
        entries.push(Entry {
            index: usize::try_from(index).map_err(|_| {
                Error::malformed(format!(
                    "central directory entry {index} does not fit in memory"
                ))
            })?,
            raw_name,
            name,
            flags,
            compression: match method {
                METHOD_STORED => Compression::Stored,
                METHOD_DEFLATE => Compression::Deflate,
                other => Compression::Other(other),
            },
            crc32,
            compressed_size,
            uncompressed_size,
            local_header_offset,
        });
        at = variable_end;
    }
    Ok(entries)
}

/// Reads the ZIP64 extended information extra field. Only the values whose
/// 32-bit field overflowed are stored, in this order: uncompressed size,
/// compressed size, local header offset, disk number.
fn zip64_values(
    extra: &[u8],
    want_uncompressed: bool,
    want_compressed: bool,
    want_offset: bool,
) -> Option<(Option<u64>, Option<u64>, Option<u64>)> {
    let mut at = 0usize;
    while at + 4 <= extra.len() {
        let id = u16_at(extra, at);
        let size = usize::from(u16_at(extra, at + 2));
        let body_start = at + 4;
        let body_end = body_start.checked_add(size)?;
        if body_end > extra.len() {
            return None;
        }
        if id == ZIP64_EXTRA_ID {
            let body = &extra[body_start..body_end];
            let mut cursor = 0usize;
            let mut read = |needed: bool| -> Option<Option<u64>> {
                if !needed {
                    return Some(None);
                }
                let value = body.get(cursor..cursor + 8)?;
                cursor += 8;
                Some(Some(u64::from_le_bytes(value.try_into().ok()?)))
            };
            let uncompressed = read(want_uncompressed)?;
            let compressed = read(want_compressed)?;
            let offset = read(want_offset)?;
            return Some((uncompressed, compressed, offset));
        }
        at = body_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Clone)]
    struct File {
        name: &'static str,
        data: Vec<u8>,
        method: u16,
        flags: u16,
        crc: Option<u32>,
        /// Whether the local header defers the sizes and CRC to a data
        /// descriptor, leaving zeros in their place.
        descriptor: bool,
    }

    impl File {
        fn stored(name: &'static str, data: &[u8]) -> Self {
            Self {
                name,
                data: data.to_vec(),
                method: METHOD_STORED,
                flags: 0,
                crc: None,
                descriptor: false,
            }
        }

        fn deflated(name: &'static str, data: &[u8]) -> Self {
            Self {
                name,
                data: data.to_vec(),
                method: METHOD_DEFLATE,
                flags: 0,
                crc: None,
                descriptor: false,
            }
        }
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        crc.sum()
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Builds a single-disk ZIP archive in memory, including duplicate names.
    fn build(files: &[File]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for file in files {
            let stored = if file.method == METHOD_DEFLATE {
                deflate(&file.data)
            } else {
                file.data.clone()
            };
            let crc = file.crc.unwrap_or_else(|| crc32(&file.data));
            let offset = out.len() as u32;
            let (local_crc, local_compressed, local_uncompressed) = if file.descriptor {
                (0u32, 0u32, 0u32)
            } else {
                (crc, stored.len() as u32, file.data.len() as u32)
            };
            out.extend_from_slice(&LOCAL_HEADER);
            out.extend_from_slice(&20u16.to_le_bytes());
            out.extend_from_slice(&file.flags.to_le_bytes());
            out.extend_from_slice(&file.method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&local_crc.to_le_bytes());
            out.extend_from_slice(&local_compressed.to_le_bytes());
            out.extend_from_slice(&local_uncompressed.to_le_bytes());
            out.extend_from_slice(&(file.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(file.name.as_bytes());
            out.extend_from_slice(&stored);

            central.extend_from_slice(&CENTRAL_HEADER);
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&file.flags.to_le_bytes());
            central.extend_from_slice(&file.method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
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

    fn read(bytes: &[u8]) -> Archive {
        Archive::read(
            &mut Cursor::new(bytes),
            &Limits::default(),
            &AtomicBool::new(false),
        )
        .unwrap()
    }

    /// Claims a larger file than it can read, as a file truncated between the
    /// length check and the read behaves.
    struct BeyondEnd {
        cursor: Cursor<Vec<u8>>,
        claimed: u64,
    }

    impl Read for BeyondEnd {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.cursor.read(buf)
        }
    }

    impl Seek for BeyondEnd {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            match pos {
                SeekFrom::End(0) => Ok(self.claimed),
                other => self.cursor.seek(other),
            }
        }
    }

    fn decode(archive: &Archive, bytes: &[u8], index: usize) -> Result<Vec<u8>, Error> {
        let mut reader = Cursor::new(bytes.to_vec());
        let mut out = Vec::new();
        let len = reader.seek(SeekFrom::End(0)).unwrap();
        let entry = archive.entry(index)?;
        archive.decode_entry(
            &mut reader,
            len,
            entry,
            &AtomicBool::new(false),
            u64::MAX,
            &mut out,
        )?;
        Ok(out)
    }

    #[test]
    fn duplicate_full_names_stay_separate_entries() {
        let bytes = build(&[
            File::stored("same.bin", b"first"),
            File::stored("other.bin", b"middle"),
            File::stored("same.bin", b"second"),
        ]);
        let archive = read(&bytes);
        assert_eq!(archive.len(), 3);
        assert_eq!(archive.duplicate_names, 1);
        assert_eq!(archive.entry(0).unwrap().name, "same.bin");
        assert_eq!(archive.entry(2).unwrap().name, "same.bin");
        assert_eq!(decode(&archive, &bytes, 0).unwrap(), b"first".to_vec());
        assert_eq!(decode(&archive, &bytes, 1).unwrap(), b"middle".to_vec());
        assert_eq!(decode(&archive, &bytes, 2).unwrap(), b"second".to_vec());
    }

    #[test]
    fn the_same_basename_in_different_folders_is_kept_apart() {
        let bytes = build(&[
            File::stored("a/same.bin", b"a"),
            File::stored("b/same.bin", b"b"),
        ]);
        let archive = read(&bytes);
        assert_eq!(archive.len(), 2);
        assert_eq!(archive.duplicate_names, 0);
        assert_eq!(decode(&archive, &bytes, 0).unwrap(), b"a".to_vec());
        assert_eq!(decode(&archive, &bytes, 1).unwrap(), b"b".to_vec());
    }

    #[test]
    fn a_file_and_a_directory_with_the_same_name_are_both_kept() {
        let bytes = build(&[File::stored("thing", b"file"), File::stored("thing/", b"")]);
        let archive = read(&bytes);
        assert_eq!(archive.len(), 2);
        assert!(!archive.entry(0).unwrap().is_dir());
        assert!(archive.entry(1).unwrap().is_dir());
    }

    #[test]
    fn stored_and_deflated_entries_decode() {
        let bytes = build(&[
            File::stored("stored.bin", b"stored payload"),
            File::deflated(
                "deflated.bin",
                b"deflated payload, repeated repeated repeated",
            ),
        ]);
        let archive = read(&bytes);
        assert_eq!(archive.entry(0).unwrap().compression, Compression::Stored);
        assert_eq!(archive.entry(1).unwrap().compression, Compression::Deflate);
        assert_eq!(
            decode(&archive, &bytes, 0).unwrap(),
            b"stored payload".to_vec()
        );
        assert_eq!(
            decode(&archive, &bytes, 1).unwrap(),
            b"deflated payload, repeated repeated repeated".to_vec()
        );
    }

    #[test]
    fn a_crc_mismatch_is_a_malformed_entry() {
        let mut file = File::stored("bad.bin", b"payload");
        file.crc = Some(0);
        let bytes = build(&[file]);
        let archive = read(&bytes);
        let err = decode(&archive, &bytes, 0).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Malformed);
        assert!(err.message.contains("CRC-32"), "{}", err.message);
    }

    #[test]
    fn an_entry_with_a_data_descriptor_decodes_from_the_central_sizes() {
        let mut file = File::stored("descriptor.bin", b"payload");
        file.flags = DATA_DESCRIPTOR_FLAG;
        file.descriptor = true;
        let bytes = build(&[file]);
        let archive = read(&bytes);
        let entry = archive.entry(0).unwrap();
        assert!(entry.has_data_descriptor());
        assert_eq!(entry.compressed_size, 7);
        assert_eq!(entry.uncompressed_size, 7);
        assert_eq!(decode(&archive, &bytes, 0).unwrap(), b"payload".to_vec());
    }

    #[test]
    fn a_short_read_of_the_tail_is_malformed() {
        let bytes = build(&[File::stored("a.bin", b"a")]);
        let mut reader = BeyondEnd {
            cursor: Cursor::new(bytes.clone()),
            claimed: bytes.len() as u64 + 10,
        };
        let err =
            Archive::read(&mut reader, &Limits::default(), &AtomicBool::new(false)).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Malformed);
        assert!(err.message.contains("ends before"), "{}", err.message);
    }

    #[test]
    fn an_unsupported_method_is_reported_as_compression() {
        let mut file = File::stored("bzip.bin", b"payload");
        file.method = 12;
        let bytes = build(&[file]);
        let archive = read(&bytes);
        assert_eq!(
            archive.entry(0).unwrap().compression,
            Compression::Other(12)
        );
        let err = decode(&archive, &bytes, 0).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedCompression);
    }

    #[test]
    fn an_encrypted_entry_is_reported_as_encrypted() {
        let mut file = File::stored("secret.bin", b"payload");
        file.flags = FLAG_ENCRYPTED;
        let bytes = build(&[file]);
        let archive = read(&bytes);
        assert!(archive.entry(0).unwrap().is_encrypted());
        let err = decode(&archive, &bytes, 0).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Encrypted);
        assert_eq!(
            archive
                .read_prefix(
                    &mut Cursor::new(bytes),
                    u64::MAX,
                    archive.entry(0).unwrap(),
                    &AtomicBool::new(false),
                    16,
                )
                .unwrap_err()
                .kind,
            ErrorKind::Encrypted
        );
    }

    #[test]
    fn a_prefix_read_stops_at_the_limit() {
        let payload: Vec<u8> = (0..200u16).map(|value| value as u8).collect();
        let bytes = build(&[File::deflated("long.bin", &payload)]);
        let archive = read(&bytes);
        let mut reader = Cursor::new(bytes.clone());
        let len = reader.seek(SeekFrom::End(0)).unwrap();
        let prefix = archive
            .read_prefix(
                &mut reader,
                len,
                archive.entry(0).unwrap(),
                &AtomicBool::new(false),
                64,
            )
            .unwrap();
        assert_eq!(prefix.bytes, payload[..64].to_vec());
        assert!(!prefix.complete);
    }

    #[test]
    fn a_truncated_central_directory_is_malformed() {
        let bytes = build(&[File::stored("a.bin", b"a")]);
        let archive = read(&bytes);
        let cut = bytes[..archive.directory_start as usize + 20].to_vec();
        let err = Archive::read(
            &mut Cursor::new(cut),
            &Limits::default(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Malformed);
    }

    #[test]
    fn an_entry_count_above_the_limit_is_reported() {
        let bytes = build(&[File::stored("a.bin", b"a"), File::stored("b.bin", b"b")]);
        let limits = Limits {
            max_entries: 1,
            ..Limits::default()
        };
        let err =
            Archive::read(&mut Cursor::new(bytes), &limits, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Limit);
    }

    #[test]
    fn an_entry_past_the_end_of_the_file_is_malformed() {
        let mut bytes = build(&[File::stored("a.bin", b"a")]);
        let archive = read(&bytes);
        // Point the single central record's local header offset past the file.
        let offset_at = archive.directory_start as usize + 42;
        bytes[offset_at..offset_at + 4].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        let err = Archive::read(
            &mut Cursor::new(bytes),
            &Limits::default(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Malformed);
    }

    #[test]
    fn a_missing_central_header_signature_is_malformed() {
        let mut bytes = build(&[File::stored("a.bin", b"a")]);
        let archive = read(&bytes);
        bytes[archive.directory_start as usize] = 0;
        let err = Archive::read(
            &mut Cursor::new(bytes),
            &Limits::default(),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Malformed);
    }

    #[test]
    fn an_index_past_the_last_entry_is_rejected() {
        let bytes = build(&[File::stored("a.bin", b"a")]);
        let archive = read(&bytes);
        let err = archive.entry(1).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Malformed);
        assert!(err.message.contains("only entry is 0"), "{}", err.message);
    }

    #[test]
    fn cancellation_stops_the_read() {
        let bytes = build(&[File::stored("a.bin", b"a")]);
        let err = Archive::read(
            &mut Cursor::new(bytes),
            &Limits::default(),
            &AtomicBool::new(true),
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Cancelled);
    }
}
