//! Byte-level text encodings, and lossy decoding that never fails.
//!
//! An encoding says how the bytes of a payload become characters. A byte-order
//! mark is not an encoding of its own: it selects one of these and is skipped.

/// How the bytes of a payload map to characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Encoding {
    #[default]
    Utf8,
    Utf16Le,
    Utf16Be,
    /// One character per byte, as Windows-1252 writes its first 256 code points.
    Latin1,
}

impl Encoding {
    /// The encodings offered for a manual choice, in the order a menu shows
    /// them.
    pub const ALL: [Encoding; 4] = [
        Encoding::Utf8,
        Encoding::Utf16Le,
        Encoding::Utf16Be,
        Encoding::Latin1,
    ];

    /// The name shown for the encoding, including whether a byte-order mark was
    /// found.
    pub fn label(self, bom: bool) -> &'static str {
        match (self, bom) {
            (Encoding::Utf8, true) => "UTF-8 with BOM",
            (Encoding::Utf8, false) => "UTF-8",
            (Encoding::Utf16Le, true) => "UTF-16 LE with BOM",
            (Encoding::Utf16Le, false) => "UTF-16 LE",
            (Encoding::Utf16Be, true) => "UTF-16 BE with BOM",
            (Encoding::Utf16Be, false) => "UTF-16 BE",
            (Encoding::Latin1, _) => "Windows-1252 / Latin-1",
        }
    }

    /// The smallest number of bytes one character can occupy. A payload's
    /// length must be a multiple of it for the whole payload to decode.
    pub fn unit(self) -> usize {
        match self {
            Encoding::Utf8 | Encoding::Latin1 => 1,
            Encoding::Utf16Le | Encoding::Utf16Be => 2,
        }
    }
}

/// The byte-order mark at the start of a payload, and the encoding it selects.
///
/// UTF-16 marks are checked before UTF-8: `FF FE` and `FE FF` are not valid
/// UTF-8, so the order only matters for clarity.
pub fn bom(bytes: &[u8]) -> Option<(Encoding, usize)> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Some((Encoding::Utf8, 3));
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return Some((Encoding::Utf16Le, 2));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return Some((Encoding::Utf16Be, 2));
    }
    None
}

/// Decodes `bytes` as `encoding`, replacing malformed sequences with U+FFFD.
///
/// The returned count is the number of malformed sequences, so a caller can
/// tell a clean decode from a guessed one.
pub fn decode(bytes: &[u8], encoding: Encoding) -> (String, usize) {
    match encoding {
        Encoding::Utf8 => match std::str::from_utf8(bytes) {
            Ok(text) => (text.to_string(), 0),
            Err(_) => {
                let text = String::from_utf8_lossy(bytes).into_owned();
                (text, 1)
            }
        },
        Encoding::Latin1 => (bytes.iter().map(|&byte| byte as char).collect(), 0),
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let big_endian = encoding == Encoding::Utf16Be;
            let mut units = Vec::with_capacity(bytes.len() / 2);
            for pair in bytes.as_chunks::<2>().0 {
                units.push(if big_endian {
                    u16::from_be_bytes(*pair)
                } else {
                    u16::from_le_bytes(*pair)
                });
            }
            let malformed = bytes.len() % 2 + usize::from(String::from_utf16(&units).is_err());
            (String::from_utf16_lossy(&units), malformed)
        }
    }
}

/// The number of characters in `bytes` without allocating the decoded text.
///
/// Malformed sequences count as one character each, matching [`decode`].
pub fn char_count(bytes: &[u8], encoding: Encoding) -> u64 {
    match encoding {
        Encoding::Utf8 => bytes.iter().filter(|byte| (**byte & 0xC0) != 0x80).count() as u64,
        Encoding::Latin1 => bytes.len() as u64,
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let big_endian = encoding == Encoding::Utf16Be;
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .filter(|pair| {
                    let unit = if big_endian {
                        u16::from_be_bytes(**pair)
                    } else {
                        u16::from_le_bytes(**pair)
                    };
                    // A trailing surrogate is the second half of one character.
                    !(0xDC00..0xE000).contains(&unit)
                })
                .count() as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_select_their_encoding() {
        assert_eq!(bom(b"\xEF\xBB\xBFhello"), Some((Encoding::Utf8, 3)));
        assert_eq!(bom(b"\xFF\xFEh\0"), Some((Encoding::Utf16Le, 2)));
        assert_eq!(bom(b"\xFE\xFF\0h"), Some((Encoding::Utf16Be, 2)));
        assert_eq!(bom(b"hello"), None);
        assert_eq!(bom(b""), None);
    }

    #[test]
    fn every_encoding_round_trips_its_own_bytes() {
        for (encoding, bytes, expected) in [
            (Encoding::Utf8, "héllo".as_bytes().to_vec(), "héllo"),
            (Encoding::Latin1, vec![0x68, 0xE9], "hé"),
            (
                Encoding::Utf16Le,
                "hé".encode_utf16().flat_map(u16::to_le_bytes).collect(),
                "hé",
            ),
            (
                Encoding::Utf16Be,
                "hé".encode_utf16().flat_map(u16::to_be_bytes).collect(),
                "hé",
            ),
        ] {
            let (text, malformed) = decode(&bytes, encoding);
            assert_eq!(text, expected, "{encoding:?}");
            assert_eq!(malformed, 0, "{encoding:?}");
            assert_eq!(
                char_count(&bytes, encoding),
                expected.chars().count() as u64
            );
        }
    }

    #[test]
    fn malformed_utf8_is_replaced_not_refused() {
        let (text, malformed) = decode(b"a\xFFb", Encoding::Utf8);
        assert_eq!(text, "a\u{FFFD}b");
        assert_eq!(malformed, 1);
        assert_eq!(char_count(b"a\xFFb", Encoding::Utf8), 3);
    }

    #[test]
    fn odd_utf16_length_is_malformed() {
        let (text, malformed) = decode(&[0x68, 0x00, 0x69], Encoding::Utf16Le);
        assert_eq!(text, "h");
        assert_eq!(malformed, 1);
    }

    #[test]
    fn labels_name_the_mark_and_the_encoding() {
        assert_eq!(Encoding::Utf8.label(true), "UTF-8 with BOM");
        assert_eq!(Encoding::Utf16Le.label(false), "UTF-16 LE");
        assert_eq!(Encoding::Latin1.label(false), "Windows-1252 / Latin-1");
    }
}
