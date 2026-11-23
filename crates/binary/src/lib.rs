//! Read-only binary inspection: bounded reads, value interpretation, pattern
//! search and hashing. Nothing here holds a whole file in memory.

mod interpret;
mod search;

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

pub use interpret::{Endian, Utf8Preview, Values, format_f32, format_f64, interpret, utf8_preview};
pub use search::{find_next, find_previous, parse_hex_pattern};

/// Bytes read per step by search and hashing.
const CHUNK: usize = 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Cancelled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

fn check(cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// A file opened for positional reads.
///
/// Each clone keeps its own position but shares the handle, so clones can
/// read from different threads at the same time. The length is fixed when
/// the file is opened.
#[derive(Debug, Clone)]
pub struct Source {
    file: Arc<File>,
    len: u64,
    pos: u64,
}

impl Source {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::from_file(File::open(path)?)
    }

    pub fn from_file(file: File) -> io::Result<Self> {
        let len = file.metadata()?.len();
        Ok(Self {
            file: Arc::new(file),
            len,
            pos: 0,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Read for Source {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let max = usize::try_from(self.len - self.pos).unwrap_or(usize::MAX);
        let buf_len = buf.len().min(max);
        #[cfg(windows)]
        let n =
            std::os::windows::fs::FileExt::seek_read(&*self.file, &mut buf[..buf_len], self.pos)?;
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(&*self.file, &mut buf[..buf_len], self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Source {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        let target = target.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek to an invalid position")
        })?;
        self.pos = target;
        Ok(target)
    }
}

pub fn stream_len(reader: &mut impl Seek) -> io::Result<u64> {
    reader.seek(SeekFrom::End(0))
}

/// Reads up to `max` bytes at `offset`, stopping at the end of the data.
/// An offset past the end is an error; an offset at the end yields nothing.
pub fn read_at(reader: &mut (impl Read + Seek), offset: u64, max: usize) -> io::Result<Vec<u8>> {
    let len = stream_len(reader)?;
    if offset > len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("offset {offset:#x} is beyond the end of the data ({len:#x} bytes)"),
        ));
    }
    let count = usize::try_from(len - offset).map_or(max, |remaining| remaining.min(max));
    let mut bytes = vec![0; count];
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Streams all data through SHA-256.
pub fn sha256(reader: &mut (impl Read + Seek), cancel: &AtomicBool) -> Result<[u8; 32], Error> {
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0; CHUNK];
    loop {
        check(cancel)?;
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        };
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Parses a decimal offset or a hexadecimal one with a `0x` prefix.
pub fn parse_offset(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|err| match err.kind() {
        std::num::IntErrorKind::PosOverflow => format!("'{text}' is too large for an offset"),
        _ => format!("'{text}' is not a decimal or 0x-prefixed hexadecimal offset"),
    })
}

/// The character shown for a byte in ASCII columns: printable ASCII as is,
/// everything else as `.`.
pub fn ascii_char(byte: u8) -> char {
    if byte.is_ascii_graphic() || byte == b' ' {
        byte as char
    } else {
        '.'
    }
}

/// Space-separated uppercase hex, e.g. `4C 46 47`.
pub fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

/// Contiguous lowercase hex, as checksums are usually written.
pub fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    /// Zeros of any length with a few bytes set, for offsets past 4 GiB
    /// without a file of that size.
    pub(crate) struct Sparse {
        pub len: u64,
        pub patches: Vec<(u64, Vec<u8>)>,
        pub pos: u64,
    }

    impl Read for Sparse {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf
                .len()
                .min(usize::try_from(self.len.saturating_sub(self.pos)).unwrap_or(usize::MAX));
            buf[..n].fill(0);
            for (at, bytes) in &self.patches {
                for (i, byte) in bytes.iter().enumerate() {
                    let offset = at + i as u64;
                    if offset >= self.pos && offset < self.pos + n as u64 {
                        buf[(offset - self.pos) as usize] = *byte;
                    }
                }
            }
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl Seek for Sparse {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.pos = match pos {
                SeekFrom::Start(offset) => offset,
                SeekFrom::End(delta) => self.len.checked_add_signed(delta).unwrap(),
                SeekFrom::Current(delta) => self.pos.checked_add_signed(delta).unwrap(),
            };
            Ok(self.pos)
        }
    }

    #[test]
    fn reads_are_clamped_to_the_end() {
        let mut data = Cursor::new(vec![1u8, 2, 3, 4]);
        assert_eq!(read_at(&mut data, 1, 2).unwrap(), [2, 3]);
        assert_eq!(read_at(&mut data, 2, 100).unwrap(), [3, 4]);
        assert!(read_at(&mut data, 4, 100).unwrap().is_empty());
        assert!(read_at(&mut data, 5, 1).is_err());
        assert!(read_at(&mut data, u64::MAX, usize::MAX).is_err());
    }

    #[test]
    fn empty_data_reads_nothing() {
        let mut data = Cursor::new(Vec::new());
        assert!(read_at(&mut data, 0, 16).unwrap().is_empty());
        assert!(read_at(&mut data, 1, 16).is_err());
    }

    #[test]
    fn reads_beyond_four_gib() {
        let at = 5 * 1024 * 1024 * 1024 + 3;
        let mut data = Sparse {
            len: at + 4,
            patches: vec![(at, vec![0xDE, 0xAD, 0xBE, 0xEF])],
            pos: 0,
        };
        assert_eq!(
            read_at(&mut data, at - 1, 16).unwrap(),
            [0, 0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(read_at(&mut data, at + 4, 1).unwrap().is_empty());
    }

    #[test]
    fn source_reads_files_independently_per_clone() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"0123456789").unwrap();
        let mut a = Source::from_file(file).unwrap();
        let mut b = a.clone();
        assert_eq!(a.len(), 10);
        assert_eq!(read_at(&mut a, 2, 3).unwrap(), b"234");
        assert_eq!(read_at(&mut b, 7, 10).unwrap(), b"789");
        let mut rest = Vec::new();
        a.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"56789");
        assert!(a.seek(SeekFrom::Current(-100)).is_err());
    }

    #[test]
    fn source_of_empty_file() {
        let mut source = Source::from_file(tempfile::tempfile().unwrap()).unwrap();
        assert!(source.is_empty());
        assert!(read_at(&mut source, 0, 8).unwrap().is_empty());
    }

    #[test]
    fn sha256_streams_across_chunks() {
        let cancel = AtomicBool::new(false);
        let empty = sha256(&mut Cursor::new(Vec::new()), &cancel).unwrap();
        assert_eq!(
            hex_digest(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = sha256(&mut Cursor::new(b"abc".to_vec()), &cancel).unwrap();
        assert_eq!(
            hex_digest(&abc),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Larger than one chunk, compared against a one-shot digest.
        let data: Vec<u8> = (0..CHUNK * 2 + 17).map(|i| (i % 251) as u8).collect();
        let streamed = sha256(&mut Cursor::new(data.clone()), &cancel).unwrap();
        assert_eq!(streamed, <[u8; 32]>::from(Sha256::digest(&data)));
    }

    #[test]
    fn sha256_can_be_cancelled() {
        let cancel = AtomicBool::new(true);
        let result = sha256(&mut Cursor::new(vec![0u8; 10]), &cancel);
        assert!(matches!(result, Err(Error::Cancelled)));
    }

    #[test]
    fn parses_decimal_and_hex_offsets() {
        assert_eq!(parse_offset("16"), Ok(16));
        assert_eq!(parse_offset(" 0x10 "), Ok(16));
        assert_eq!(parse_offset("0XfF"), Ok(255));
        assert_eq!(parse_offset("0xFFFFFFFFFFFFFFFF"), Ok(u64::MAX));
        assert!(parse_offset("0x1_0000_0000_0000_0000").is_err());
        assert!(
            parse_offset("0x10000000000000000")
                .unwrap_err()
                .contains("too large")
        );
        assert!(parse_offset("18446744073709551616").is_err());
        assert!(parse_offset("-1").is_err());
        assert!(parse_offset("0x").is_err());
        assert!(parse_offset("ten").is_err());
        assert!(parse_offset("").is_err());
    }

    #[test]
    fn formats_bytes() {
        assert_eq!(hex_bytes(&[0x4C, 0x0, 0xFF]), "4C 00 FF");
        assert_eq!(hex_bytes(&[]), "");
        assert_eq!(hex_digest(&[0xAB, 0x01]), "ab01");
        let ascii: String = b"Te\x00\x7Fst ~".iter().map(|b| ascii_char(*b)).collect();
        assert_eq!(ascii, "Te..st ~");
    }
}
