//! Byte-level text encodings, and lossy decoding that never fails.
//!
//! An encoding says how the bytes of a payload become characters. A byte-order
//! mark is not an encoding of its own: it selects one of these and is skipped.
//!
//! UTF-8 and UTF-16 are decided from the bytes. Legacy code pages are never
//! guessed: a byte-oriented encoding maps almost any bytes to characters, so a
//! guess would turn binary data into text. They are offered as an explicit
//! choice instead, and only the code pages listed in [`Encoding::ALL`] are.
//!
//! Every legacy encoding offered here is byte-oriented with no `0x0A` or `0x0D`
//! inside a multi-byte sequence, which is what lets the line index scan raw
//! bytes instead of decoded text.

/// How the bytes of a payload map to characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum Encoding {
    #[default]
    Utf8,
    Utf16Le,
    Utf16Be,
    /// A legacy code page, decoded by `encoding_rs` from an explicit choice.
    Legacy(&'static encoding_rs::Encoding),
}

impl Encoding {
    /// Windows-1252, the code page Latin-1 text is usually written in.
    pub const WINDOWS_1252: Encoding = Encoding::Legacy(encoding_rs::WINDOWS_1252);
    /// Windows-1251, Cyrillic.
    pub const WINDOWS_1251: Encoding = Encoding::Legacy(encoding_rs::WINDOWS_1251);
    /// ISO-8859-15, Latin-9.
    pub const ISO_8859_15: Encoding = Encoding::Legacy(encoding_rs::ISO_8859_15);
    /// Shift_JIS, Japanese.
    pub const SHIFT_JIS: Encoding = Encoding::Legacy(encoding_rs::SHIFT_JIS);
    /// GBK, Simplified Chinese.
    pub const GBK: Encoding = Encoding::Legacy(encoding_rs::GBK);
    /// Big5, Traditional Chinese.
    pub const BIG5: Encoding = Encoding::Legacy(encoding_rs::BIG5);
    /// EUC-KR, Korean.
    pub const EUC_KR: Encoding = Encoding::Legacy(encoding_rs::EUC_KR);

    /// The encodings offered for a manual choice, in the order a menu shows
    /// them. The two UTF-16 variants are decoded from the bytes alone, so they
    /// are also used when a payload is not text and the user asks anyway.
    pub const ALL: [Encoding; 10] = [
        Encoding::Utf8,
        Encoding::Utf16Le,
        Encoding::Utf16Be,
        Encoding::WINDOWS_1252,
        Encoding::WINDOWS_1251,
        Encoding::ISO_8859_15,
        Encoding::SHIFT_JIS,
        Encoding::GBK,
        Encoding::BIG5,
        Encoding::EUC_KR,
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
            (Encoding::Legacy(encoding), _) => encoding.name(),
        }
    }

    /// The smallest number of bytes one character can occupy. A payload's
    /// length must be a multiple of it for the whole payload to decode.
    pub fn unit(self) -> usize {
        match self {
            Encoding::Utf8 | Encoding::Legacy(_) => 1,
            Encoding::Utf16Le | Encoding::Utf16Be => 2,
        }
    }

    /// Whether the encoding is a legacy code page chosen by hand.
    pub fn is_legacy(self) -> bool {
        matches!(self, Encoding::Legacy(_))
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
/// The returned count is 1 when the decode found malformed input, so a caller
/// can tell a clean decode from a damaged one. For legacy code pages it counts
/// the decode as malformed when the code page leaves bytes unmapped.
pub fn decode(bytes: &[u8], encoding: Encoding) -> (String, usize) {
    match encoding {
        Encoding::Utf8 => match std::str::from_utf8(bytes) {
            Ok(text) => (text.to_string(), 0),
            Err(_) => {
                let text = String::from_utf8_lossy(bytes).into_owned();
                (text, 1)
            }
        },
        Encoding::Legacy(encoding) => {
            let (text, _, errors) = encoding.decode(bytes);
            (text.into_owned(), usize::from(errors))
        }
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
            let malformed = usize::from(bytes.len() % 2 == 1)
                + usize::from(String::from_utf16(&units).is_err());
            (String::from_utf16_lossy(&units), malformed)
        }
    }
}

/// The number of characters in `bytes` without allocating the decoded text.
///
/// Malformed sequences count as one character each, matching [`decode`]. A
/// legacy code page has to be decoded to be counted.
pub fn char_count(bytes: &[u8], encoding: Encoding) -> u64 {
    match encoding {
        Encoding::Utf8 => bytes.iter().filter(|byte| (**byte & 0xC0) != 0x80).count() as u64,
        Encoding::Legacy(_) => decode(bytes, encoding).0.chars().count() as u64,
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
            (Encoding::WINDOWS_1252, vec![0x68, 0xE9], "hé"),
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
    fn legacy_code_pages_decode_their_own_characters() {
        // Windows-1251 "Привет".
        let cyrillic = vec![0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2];
        assert_eq!(decode(&cyrillic, Encoding::WINDOWS_1251).0, "Привет");
        // Shift_JIS "あ" is two bytes, counted as one character.
        let japanese = [0x82, 0xA0];
        assert_eq!(decode(&japanese, Encoding::SHIFT_JIS).0, "あ");
        assert_eq!(char_count(&japanese, Encoding::SHIFT_JIS), 1);
        // ISO-8859-15 puts the euro sign at A4, unlike Windows-1252.
        assert_eq!(decode(&[0xA4], Encoding::ISO_8859_15).0, "€");
        assert_eq!(decode(&[0xA4], Encoding::WINDOWS_1252).0, "¤");
        // GBK and Big5 both write "中".
        assert_eq!(decode(&[0xD6, 0xD0], Encoding::GBK).0, "中");
        assert_eq!(decode(&[0xA4, 0xA4], Encoding::BIG5).0, "中");
    }

    #[test]
    fn unmapped_legacy_bytes_are_reported() {
        // Shift_JIS 0x82 starts a two-byte sequence, so it is truncated here.
        let (_, malformed) = decode(&[0x61, 0x82], Encoding::SHIFT_JIS);
        assert_eq!(malformed, 1);
        // Windows-1252 maps every byte, so nothing is damaged.
        let (_, malformed) = decode(&[0x61, 0x81, 0x62], Encoding::WINDOWS_1252);
        assert_eq!(malformed, 0);
    }

    #[test]
    fn multi_byte_legacy_text_round_trips_without_line_breaks() {
        // The line index scans raw bytes, so no sequence of an offered code page
        // may contain 0x0A or 0x0D.
        for (encoding, text) in [
            (Encoding::SHIFT_JIS, "日本語のテキスト"),
            (Encoding::GBK, "中文字符"),
            (Encoding::BIG5, "中文字元"),
            (Encoding::EUC_KR, "한국어"),
            (Encoding::WINDOWS_1251, "Привет"),
            (Encoding::ISO_8859_15, "café €"),
        ] {
            let Encoding::Legacy(named) = encoding else {
                panic!("{encoding:?} is not legacy");
            };
            let (bytes, _, errors) = named.encode(text);
            assert!(!errors, "{encoding:?} encodes its own text");
            assert!(!bytes.contains(&b'\n') && !bytes.contains(&b'\r'));
            assert_eq!(decode(&bytes, encoding).0, text);
            assert_eq!(char_count(&bytes, encoding), text.chars().count() as u64);
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
        assert_eq!(Encoding::WINDOWS_1252.label(false), "windows-1252");
        assert_eq!(Encoding::SHIFT_JIS.label(false), "Shift_JIS");
        assert!(Encoding::WINDOWS_1251.is_legacy());
        assert!(!Encoding::Utf8.is_legacy());
    }
}
