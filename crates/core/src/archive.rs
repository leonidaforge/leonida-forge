//! Recognises the supported archive formats from their contents.
//!
//! A signature at the start of the data makes a file a candidate. It is an
//! archive only if its structure checks out as well. A candidate that fails
//! the check is [`Identified::Invalid`], so it can be reported instead of
//! being shown as an empty folder. File names and extensions are not used.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use lforge_rage9::rpf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    Zip,
    Rpf9,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Zip => "ZIP",
            Format::Rpf9 => "RPF9",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identified {
    Archive(Format),
    /// Starts with the signature of `format`, but is not a valid archive of it.
    Invalid {
        format: Format,
        reason: String,
    },
    Unknown,
}

/// How many leading bytes [`sniff`] needs.
pub const HEAD_LEN: usize = rpf::HEADER_LEN;

const LOCAL_HEADER: &[u8; 4] = b"PK\x03\x04";
const END_RECORD: &[u8; 4] = b"PK\x05\x06";
const CENTRAL_HEADER: &[u8; 4] = b"PK\x01\x02";
const ZIP64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
const ZIP64_END_RECORD: &[u8; 4] = b"PK\x06\x06";
const LOCAL_HEADER_LEN: u64 = 30;
const END_RECORD_LEN: u64 = 22;
const CENTRAL_HEADER_LEN: u64 = 46;
const ZIP64_LOCATOR_LEN: u64 = 20;
const ZIP64_END_RECORD_LEN: u64 = 56;
const MAX_COMMENT_LEN: u64 = 0xFFFF;

/// The format whose signature the data starts with.
pub fn signature(head: &[u8]) -> Option<Format> {
    if rpf::is_rpf9(head) {
        Some(Format::Rpf9)
    } else if head.starts_with(LOCAL_HEADER) || head.starts_with(END_RECORD) {
        Some(Format::Zip)
    } else {
        None
    }
}

/// What the first [`HEAD_LEN`] bytes and the length of the data tell. This
/// validates RPF9 archives completely. For ZIP archives it only checks the
/// first record, as the central directory is at the end; [`identify`]
/// checks that as well.
pub fn sniff(head: &[u8], len: u64) -> Identified {
    let Some(format) = signature(head) else {
        return Identified::Unknown;
    };
    let checked = match format {
        Format::Rpf9 => rpf::Header::parse(head, len)
            .map(drop)
            .map_err(|err| match err {
                rpf::Error::InvalidHeader(reason) => reason,
                other => other.to_string(),
            }),
        Format::Zip => check_zip_start(head, len),
    };
    match checked {
        Ok(()) => Identified::Archive(format),
        Err(reason) => Identified::Invalid { format, reason },
    }
}

/// Identifies the data by its signature and validates its structure.
/// Reads the first bytes and, for ZIP candidates, the end of the data.
pub fn identify(reader: &mut (impl Read + Seek)) -> io::Result<Identified> {
    let len = reader.seek(SeekFrom::End(0))?;
    let head = read_at(
        reader,
        0,
        HEAD_LEN.min(usize::try_from(len).unwrap_or(HEAD_LEN)),
    )?;
    let sniffed = sniff(&head, len);
    if sniffed != Identified::Archive(Format::Zip) {
        return Ok(sniffed);
    }
    Ok(match check_zip_end(reader, len)? {
        Ok(()) => sniffed,
        Err(reason) => Identified::Invalid {
            format: Format::Zip,
            reason,
        },
    })
}

fn read_at(reader: &mut (impl Read + Seek), offset: u64, len: usize) -> io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::with_capacity(len);
    reader.take(len as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
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

/// Checks the local header of the first entry, or the end record of an
/// empty archive.
fn check_zip_start(head: &[u8], len: u64) -> Result<(), String> {
    if head.starts_with(END_RECORD) {
        return if len < END_RECORD_LEN {
            Err("the end of central directory record is truncated".into())
        } else {
            Ok(())
        };
    }
    if (head.len() as u64) < LOCAL_HEADER_LEN || len < LOCAL_HEADER_LEN {
        return Err("the first local file header is truncated".into());
    }
    let name_len = u64::from(u16_at(head, 26));
    let extra_len = u64::from(u16_at(head, 28));
    if name_len == 0 {
        return Err("the first entry has no name".into());
    }
    if LOCAL_HEADER_LEN + name_len + extra_len > len {
        return Err("the first local file header extends past the end of the file".into());
    }
    Ok(())
}

/// Finds the end of central directory record and checks that the central
/// directory it describes is inside the file. Archives that span several
/// files are not supported.
fn check_zip_end(reader: &mut (impl Read + Seek), len: u64) -> io::Result<Result<(), String>> {
    if len < END_RECORD_LEN {
        return Ok(Err("the file is too short for a ZIP archive".into()));
    }
    let tail_len = len.min(END_RECORD_LEN + MAX_COMMENT_LEN);
    let tail_start = len - tail_len;
    let tail = read_at(reader, tail_start, tail_len as usize)?;
    // The last record whose comment fits in the file, as readers do.
    let Some(at) = (0..=tail.len() - END_RECORD_LEN as usize)
        .rev()
        .find(|&at| {
            tail[at..].starts_with(END_RECORD)
                && at as u64 + END_RECORD_LEN + u64::from(u16_at(&tail, at + 20)) <= tail_len
        })
    else {
        return Ok(Err(
            "no end of central directory record was found; the archive may be truncated".into(),
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
            return Ok(Err(
                "the ZIP64 end of central directory locator is missing".into()
            ));
        };
        let locator = read_at(reader, locator_offset, ZIP64_LOCATOR_LEN as usize)?;
        if !locator.starts_with(ZIP64_LOCATOR) {
            return Ok(Err(
                "the ZIP64 end of central directory locator is missing".into()
            ));
        }
        let record_offset = u64_at(&locator, 8);
        if record_offset
            .checked_add(ZIP64_END_RECORD_LEN)
            .is_none_or(|end| end > locator_offset)
        {
            return Ok(Err(
                "the ZIP64 end of central directory record lies outside the file".into(),
            ));
        }
        let record = read_at(reader, record_offset, ZIP64_END_RECORD_LEN as usize)?;
        if !record.starts_with(ZIP64_END_RECORD) {
            return Ok(Err(
                "the ZIP64 end of central directory record is invalid".into()
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
        return Ok(Err(
            "archives that span several files are not supported".into()
        ));
    }
    if offset
        .checked_add(size)
        .is_none_or(|end| end > directory_end_limit)
    {
        return Ok(Err("the central directory lies outside the file".into()));
    }
    if entries
        .checked_mul(CENTRAL_HEADER_LEN)
        .is_none_or(|min| min > size)
    {
        return Ok(Err(format!(
            "the central directory is too small for {entries} entries"
        )));
    }
    if entries > 0 && !read_at(reader, offset, 4)?.starts_with(CENTRAL_HEADER) {
        return Ok(Err(
            "the central directory does not start with a file header".into(),
        ));
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(&mut out);
        for (name, data) in files {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
        out.into_inner()
    }

    fn rpf9() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x100];
        bytes[..4].copy_from_slice(b"9FPR");
        bytes[4..8].copy_from_slice(&0xA0u32.to_le_bytes());
        bytes
    }

    fn identified(bytes: &[u8]) -> Identified {
        identify(&mut Cursor::new(bytes)).unwrap()
    }

    fn is_invalid(result: Identified, expected: Format) -> bool {
        matches!(result, Identified::Invalid { format, .. } if format == expected)
    }

    #[test]
    fn recognises_valid_archives() {
        assert_eq!(identified(&rpf9()), Identified::Archive(Format::Rpf9));
        assert_eq!(
            identified(&zip(&[("a.txt", b"hello"), ("b/c.bin", &[0; 100])])),
            Identified::Archive(Format::Zip)
        );
        assert_eq!(identified(&zip(&[])), Identified::Archive(Format::Zip));
    }

    #[test]
    fn leaves_other_data_unknown() {
        for bytes in [
            &b""[..],
            b"P",
            b"RPF7\0\0\0\0",
            b"\x89PNG\r\n\x1a\n",
            b"PK\x07\x08spanned",
            &[0u8; 300],
        ] {
            assert_eq!(identified(bytes), Identified::Unknown, "{bytes:?}");
        }
    }

    #[test]
    fn a_signature_alone_is_not_an_archive() {
        assert!(is_invalid(identified(b"9FPR"), Format::Rpf9));
        let mut toc_past_end = rpf9();
        toc_past_end[4..8].copy_from_slice(&0x1000u32.to_le_bytes());
        assert!(is_invalid(identified(&toc_past_end), Format::Rpf9));
        let mut toc_in_header = rpf9();
        toc_in_header[4..8].copy_from_slice(&0x10u32.to_le_bytes());
        assert!(is_invalid(identified(&toc_in_header), Format::Rpf9));

        assert!(is_invalid(identified(b"PK\x03\x04"), Format::Zip));
        let mut no_directory = b"PK\x03\x04".to_vec();
        no_directory.resize(200, 0x11);
        assert!(is_invalid(identified(&no_directory), Format::Zip));
        assert!(is_invalid(identified(b"PK\x05\x06"), Format::Zip));
    }

    #[test]
    fn truncated_and_damaged_zip_archives_are_invalid() {
        let bytes = zip(&[("data.bin", &[7; 5000]), ("more.bin", &[8; 5000])]);
        assert!(is_invalid(
            identified(&bytes[..bytes.len() / 2]),
            Format::Zip
        ));
        assert!(is_invalid(
            identified(&bytes[..bytes.len() - 1]),
            Format::Zip
        ));

        // The central directory offset points past the record.
        let mut moved = bytes.clone();
        let end = moved.len() - END_RECORD_LEN as usize;
        moved[end + 16..end + 20].copy_from_slice(&u32::MAX.wrapping_sub(1).to_le_bytes());
        assert!(is_invalid(identified(&moved), Format::Zip));

        let mut wrong_entry = bytes.clone();
        let offset = u32_at(&bytes, end + 16) as usize;
        wrong_entry[offset + 2] = b'X';
        assert!(is_invalid(identified(&wrong_entry), Format::Zip));

        let mut spanned = bytes;
        spanned[end + 4] = 1;
        assert!(is_invalid(identified(&spanned), Format::Zip));
    }

    #[test]
    fn sniffing_checks_what_the_start_can_tell() {
        let rpf = rpf9();
        assert_eq!(
            sniff(&rpf[..HEAD_LEN], rpf.len() as u64),
            Identified::Archive(Format::Rpf9)
        );
        assert!(is_invalid(sniff(&rpf[..HEAD_LEN], 0x80), Format::Rpf9));
        let zip = zip(&[("a.txt", b"hi")]);
        assert_eq!(
            sniff(&zip[..HEAD_LEN], zip.len() as u64),
            Identified::Archive(Format::Zip)
        );
        assert!(is_invalid(sniff(&zip[..HEAD_LEN], 31), Format::Zip));
    }
}
