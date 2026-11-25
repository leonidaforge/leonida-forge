//! RBF0: a payload with a fixed 12-byte prefix, a root name and inline field
//! names.
//!
//! Only the prefix is established: it is identical in all eight decoded
//! samples, and the `u16` at +0x0A is the length of the root name that
//! follows. The body interleaves length-prefixed names with values, but the
//! tag grammar was not decoded, so nothing here parses the body and nothing
//! interprets a field.
//!
//! The root name and the field names are payload text. They are not part of a
//! report; only their lengths are.

/// The four bytes the payload starts with.
pub const MAGIC: [u8; 4] = *b"RBF0";
/// Bytes before the root name.
pub const PREFIX_LEN: usize = 0x0C;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotRbf0,
    /// Fewer bytes than the prefix.
    TooShort,
}

impl Error {
    pub fn describe(self) -> &'static str {
        match self {
            Error::NotRbf0 => "not an RBF0 payload",
            Error::TooShort => "the payload is shorter than the 12-byte prefix",
        }
    }
}

/// Whether `head` starts an RBF0 payload.
pub fn is_rbf0(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

/// The prefix of an RBF0 payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The `u16` at +0x04: `0xFFFB` in all eight samples. Meaning unknown.
    pub word: u16,
    /// The `u32` at +0x06: `1` in all eight samples. Meaning unknown.
    pub flags: u32,
    /// The `u16` at +0x0A: the length of the root name that follows.
    pub root_name_len: u16,
}

impl Header {
    /// Parses the prefix from `head`, the start of the payload. No name byte
    /// is read or checked.
    pub fn parse(head: &[u8]) -> Result<Self, Error> {
        if !is_rbf0(head) {
            return Err(Error::NotRbf0);
        }
        let prefix = head.get(..PREFIX_LEN).ok_or(Error::TooShort)?;
        Ok(Self {
            word: u16::from_le_bytes([prefix[4], prefix[5]]),
            flags: u32::from_le_bytes([prefix[6], prefix[7], prefix[8], prefix[9]]),
            root_name_len: u16::from_le_bytes([prefix[0x0A], prefix[0x0B]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&0xFFFBu16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&17u16.to_le_bytes());
        bytes.extend_from_slice(&[b'A'; 17]);
        bytes.push(0xFF);
        bytes
    }

    #[test]
    fn parses_the_prefix_and_the_root_name_length() {
        let header = Header::parse(&payload()).unwrap();
        assert_eq!(header.word, 0xFFFB);
        assert_eq!(header.flags, 1);
        assert_eq!(header.root_name_len, 17);
    }

    #[test]
    fn rejects_other_magics_and_short_prefixes() {
        assert_eq!(Header::parse(b"RBFX\0\0\0\0\0\0\0\0"), Err(Error::NotRbf0));
        assert_eq!(Header::parse(b"RBF0\0\0"), Err(Error::TooShort));
        assert_eq!(Header::parse(&[]), Err(Error::NotRbf0));
        assert!(!is_rbf0(b"RB"));
    }
}
