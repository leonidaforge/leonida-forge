//! Whether a payload is text, and in which encoding and language.
//!
//! The bytes decide. An extension may name the language of a payload that is
//! already text, and never turns binary data into text.

use crate::encoding::{self, Encoding};
use crate::language::Language;

/// A payload that is text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextInfo {
    pub encoding: Encoding,
    /// Whether the payload starts with a byte-order mark for `encoding`.
    pub bom: bool,
    pub language: Language,
    /// Whether the language was established from the bytes or a name, rather
    /// than defaulting to plain text.
    pub language_known: bool,
}

/// Why a payload is not text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryReason {
    /// A zero byte, which a text file never contains.
    NulBytes,
    /// Bytes that are not valid UTF-8 in any supported single- or multi-byte
    /// encoding.
    InvalidUtf8,
    /// Control characters at a density a text file does not have.
    ControlCharacters,
}

impl BinaryReason {
    pub fn text(self) -> &'static str {
        match self {
            BinaryReason::NulBytes => "the payload contains zero bytes",
            BinaryReason::InvalidUtf8 => "the payload is not valid UTF-8 text",
            BinaryReason::ControlCharacters => {
                "the payload contains control characters at a density text does not have"
            }
        }
    }
}

/// The outcome of inspecting a payload for text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detection {
    Text(TextInfo),
    Binary(BinaryReason),
}

impl Detection {
    pub fn text_info(self) -> Option<TextInfo> {
        match self {
            Detection::Text(info) => Some(info),
            Detection::Binary(_) => None,
        }
    }
}

/// The share of control characters a text payload may contain. Source files
/// occasionally embed one; a binary payload carries many.
const MAX_CONTROL_SHARE: usize = 100;
/// Bytes inspected when deciding whether a UTF-16 payload is little- or
/// big-endian.
const UTF16_SNIFF_LEN: usize = 512;

/// Decides whether the bytes at the start of a payload are text, and which
/// encoding and language they carry. `bytes` is the start of the payload;
/// [`SAMPLE_LEN`] is the length a caller reads.
pub fn detect(bytes: &[u8], extension: Option<&str>) -> Detection {
    let info = |encoding, bom, text: &str| TextInfo {
        encoding,
        bom,
        language: language_of(text, extension),
        language_known: language_known(text, extension),
    };
    if bytes.is_empty() {
        return Detection::Text(TextInfo {
            encoding: Encoding::Utf8,
            bom: false,
            language: extension
                .and_then(Language::from_extension)
                .unwrap_or(Language::Plain),
            language_known: extension.and_then(Language::from_extension).is_some(),
        });
    }
    if let Some((encoding, len)) = encoding::bom(bytes) {
        let body = &bytes[len..];
        return match check(body, encoding) {
            Ok(text) => Detection::Text(info(encoding, true, &text)),
            Err(reason) => Detection::Binary(reason),
        };
    }
    if let Some(encoding) = guess_utf16(bytes) {
        return match check(bytes, encoding) {
            Ok(text) => Detection::Text(info(encoding, false, &text)),
            // A guessed encoding that does not decode falls through to the
            // single-byte checks below.
            Err(_) => match guess_single_byte(bytes) {
                Ok((encoding, text)) => Detection::Text(info(encoding, false, &text)),
                Err(reason) => Detection::Binary(reason),
            },
        };
    }
    match guess_single_byte(bytes) {
        Ok((encoding, text)) => Detection::Text(info(encoding, false, &text)),
        Err(reason) => Detection::Binary(reason),
    }
}

/// UTF-8, or a refusal. Latin-1 is only used when the user chooses it: every
/// byte maps to a character, so its bytes alone are not evidence of text.
fn guess_single_byte(bytes: &[u8]) -> Result<(Encoding, String), BinaryReason> {
    if bytes.contains(&0) {
        return Err(BinaryReason::NulBytes);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            check_controls(text)?;
            Ok((Encoding::Utf8, text.to_string()))
        }
        Err(err) => {
            // A sample cut in the middle of a character is still valid text.
            let valid = &bytes[..err.valid_up_to()];
            if err.error_len().is_none() && !valid.is_empty() {
                let text = std::str::from_utf8(valid).unwrap_or_default();
                check_controls(text)?;
                return Ok((Encoding::Utf8, text.to_string()));
            }
            Err(BinaryReason::InvalidUtf8)
        }
    }
}

/// The encoding of a payload whose encoding is not declared and has no mark,
/// when its bytes alternate with zeros the way UTF-16 does.
fn guess_utf16(bytes: &[u8]) -> Option<Encoding> {
    let sample = &bytes[..bytes.len().min(UTF16_SNIFF_LEN * 2)];
    if sample.len() < 4 {
        return None;
    }
    let pairs = sample.as_chunks::<2>().0;
    let even_zeros = pairs.iter().filter(|pair| pair[0] == 0).count();
    let odd_zeros = pairs.iter().filter(|pair| pair[1] == 0).count();
    let total = pairs.len();
    // ASCII text in UTF-16 has a zero in the same byte of nearly every pair.
    let threshold = total * 8 / 10;
    let few = total / 10;
    match (odd_zeros >= threshold && even_zeros <= few, {
        even_zeros >= threshold && odd_zeros <= few
    }) {
        (true, false) => Some(Encoding::Utf16Le),
        (false, true) => Some(Encoding::Utf16Be),
        _ => None,
    }
}

/// Decodes `bytes` and rejects a decode that is binary in disguise.
fn check(bytes: &[u8], encoding: Encoding) -> Result<String, BinaryReason> {
    if bytes.contains(&0) && encoding != Encoding::Utf16Le && encoding != Encoding::Utf16Be {
        return Err(BinaryReason::NulBytes);
    }
    let (text, _) = encoding::decode(bytes, encoding);
    if text.contains('\0') {
        return Err(BinaryReason::NulBytes);
    }
    check_controls(&text)?;
    Ok(text)
}

fn check_controls(text: &str) -> Result<(), BinaryReason> {
    let chars = text.chars().count();
    if chars == 0 {
        return Ok(());
    }
    let controls = text
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\u{0B}' | '\u{0C}'))
        .count();
    if controls * MAX_CONTROL_SHARE > chars {
        return Err(BinaryReason::ControlCharacters);
    }
    Ok(())
}

fn language_of(text: &str, extension: Option<&str>) -> Language {
    extension
        .and_then(Language::from_extension)
        .or_else(|| Language::sniff(text))
        .unwrap_or(Language::Plain)
}

fn language_known(text: &str, extension: Option<&str>) -> bool {
    extension.and_then(Language::from_extension).is_some() || Language::sniff(text).is_some()
}

/// The encoding a payload is most likely written in, without judging whether
/// it is text. Used when the user asks for a specific alternative.
pub fn guess_encoding(bytes: &[u8]) -> (Encoding, bool) {
    if let Some((encoding, _)) = encoding::bom(bytes) {
        return (encoding, true);
    }
    match guess_utf16(bytes) {
        Some(encoding) => (encoding, false),
        None => (Encoding::Utf8, false),
    }
}

/// The number of bytes a text check reads.
pub const SAMPLE_LEN: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_bytes(bytes: &[u8], extension: Option<&str>) -> Detection {
        detect(bytes, extension)
    }

    #[test]
    fn plain_ascii_and_utf8_are_text() {
        assert!(matches!(
            detect_bytes(b"hello\nworld\n", Some("txt")),
            Detection::Text(TextInfo {
                encoding: Encoding::Utf8,
                bom: false,
                language: Language::Plain,
                ..
            })
        ));
        let info = detect_bytes("héllo".as_bytes(), None).text_info().unwrap();
        assert_eq!(info.encoding, Encoding::Utf8);
    }

    #[test]
    fn marks_decide_the_encoding() {
        let mut bytes = b"\xEF\xBB\xBF<a>".to_vec();
        bytes.extend_from_slice(b"</a>");
        let info = detect_bytes(&bytes, Some("xml")).text_info().unwrap();
        assert!(info.bom);
        assert_eq!(info.encoding, Encoding::Utf8);
        assert_eq!(info.language, Language::Xml);

        let le = "hello"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let be = "hello"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        for (bom, encoding, body) in [
            (b"\xFF\xFE".as_slice(), Encoding::Utf16Le, le),
            (b"\xFE\xFF".as_slice(), Encoding::Utf16Be, be),
        ] {
            let mut bytes = bom.to_vec();
            bytes.extend_from_slice(&body);
            let info = detect_bytes(&bytes, None).text_info().unwrap();
            assert_eq!(info.encoding, encoding);
            assert!(info.bom);
        }
    }

    #[test]
    fn unmarked_utf16_is_recognised_by_its_zero_pattern() {
        let le = "hello world"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let be = "hello world"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            detect_bytes(&le, None).text_info().unwrap().encoding,
            Encoding::Utf16Le
        );
        assert_eq!(
            detect_bytes(&be, None).text_info().unwrap().encoding,
            Encoding::Utf16Be
        );
    }

    #[test]
    fn binary_is_not_text() {
        assert_eq!(
            detect_bytes(b"name\0value", None),
            Detection::Binary(BinaryReason::NulBytes)
        );
        assert_eq!(
            detect_bytes(&[0xFF; 64], None),
            Detection::Binary(BinaryReason::InvalidUtf8)
        );
        let controls: Vec<u8> = (1..40).collect();
        assert!(matches!(
            detect_bytes(&controls, None),
            Detection::Binary(BinaryReason::ControlCharacters | BinaryReason::InvalidUtf8)
        ));
        // A signature alone never makes bytes text.
        assert!(matches!(
            detect_bytes(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR", Some("png")),
            Detection::Binary(_)
        ));
    }

    #[test]
    fn a_cut_character_at_the_end_of_a_sample_is_still_text() {
        let mut bytes = b"hello ".to_vec();
        bytes.extend_from_slice(&"é".as_bytes()[..1]);
        assert!(matches!(detect_bytes(&bytes, None), Detection::Text(_)));
    }

    #[test]
    fn bytes_that_are_not_utf8_need_an_explicit_encoding() {
        assert_eq!(
            detect_bytes(b"caf\xE9\n", None),
            Detection::Binary(BinaryReason::InvalidUtf8)
        );
        // The user can still open it as Windows-1252, which maps every byte.
        let (text, malformed) = encoding::decode(b"caf\xE9\n", Encoding::WINDOWS_1252);
        assert_eq!(text, "café\n");
        assert_eq!(malformed, 0);
    }

    #[test]
    fn the_extension_names_the_language_of_text() {
        let info = detect_bytes(b"{\"a\": 1}", Some("json"))
            .text_info()
            .unwrap();
        assert_eq!(info.language, Language::Json);
        assert!(info.language_known);
        let info = detect_bytes(b"a,b\n1,2\n", None).text_info().unwrap();
        assert_eq!(info.language, Language::Csv);
        assert!(info.language_known);
        let info = detect_bytes(b"just words\n", None).text_info().unwrap();
        assert_eq!(info.language, Language::Plain);
        assert!(!info.language_known);
    }

    #[test]
    fn an_empty_payload_is_empty_text() {
        assert!(matches!(detect_bytes(b"", Some("txt")), Detection::Text(_)));
    }

    #[test]
    fn encoding_guesses_prefer_marks_and_zero_patterns() {
        let mut bytes = b"\xFF\xFE".to_vec();
        bytes.extend_from_slice(&[b'a', 0]);
        assert_eq!(guess_encoding(&bytes), (Encoding::Utf16Le, true));
        assert_eq!(guess_encoding(b"plain"), (Encoding::Utf8, false));
    }
}
