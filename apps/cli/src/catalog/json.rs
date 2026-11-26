//! Small shared helpers for the catalog commands: archive path safety, a
//! duplicate-key scan for JSON text, and SHA-256 formatting.

use sha2::{Digest, Sha256};

pub const MAX_PATH_BYTES: usize = 512;
pub const MAX_PACKAGE_ID: usize = 128;
pub const MAX_RECORD_ID: usize = 128;

/// A relative POSIX archive path that cannot escape a destination and cannot
/// be a Windows device name. The importer never extracts entries, but a path
/// that is unsafe on either platform is refused instead of carried forward.
pub fn safe_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return false;
    }
    if path.contains('\\') || path.starts_with('/') || path.starts_with("//") {
        return false;
    }
    if path.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return false;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return false;
    }
    if path.ends_with('/') {
        return false;
    }
    path.split('/').all(|segment| {
        !segment.is_empty() && segment != "." && segment != ".." && !reserved_name(segment)
    })
}

fn reserved_name(segment: &str) -> bool {
    let base = segment.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(
        base.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

pub fn package_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=MAX_PACKAGE_ID).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn record_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=MAX_RECORD_ID).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub fn sha256_is_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn iso_timestamp(value: &str) -> bool {
    // The same shape the website accepts: an explicit zone is required.
    let bytes = value.as_bytes();
    if !(20..=40).contains(&bytes.len()) || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
        return false;
    }
    if !(bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let tail = &value[19..];
    tail == "Z"
        || (tail.len() >= 6
            && (tail.as_bytes()[0] == b'.'
                || tail.as_bytes()[0] == b'+'
                || tail.as_bytes()[0] == b'-'))
}

/// Finds a duplicate object key in valid JSON text. The JSON parser keeps the
/// last value silently, so the source text is scanned before it is trusted.
/// Keys are compared after unescaping: `"a"` and `"\u0061"` are one key.
pub fn duplicate_key(text: &str) -> Result<Option<String>, String> {
    let mut scanner = Scanner {
        bytes: text.as_bytes(),
        at: 0,
    };
    let duplicate = scanner.value()?;
    scanner.ws();
    if scanner.at != scanner.bytes.len() {
        return Err("trailing bytes".to_string());
    }
    Ok(duplicate)
}

struct Scanner<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Scanner<'_> {
    fn ws(&mut self) {
        while self.at < self.bytes.len() && self.bytes[self.at].is_ascii_whitespace() {
            self.at += 1;
        }
    }

    fn value(&mut self) -> Result<Option<String>, String> {
        self.ws();
        match self.bytes.get(self.at).copied() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => {
                self.string()?;
                Ok(None)
            }
            Some(_) => self.scalar(),
            None => Err("unexpected end of JSON".to_string()),
        }
    }

    fn scalar(&mut self) -> Result<Option<String>, String> {
        let start = self.at;
        while self.at < self.bytes.len()
            && !matches!(
                self.bytes[self.at],
                b',' | b']' | b'}' | b' ' | b'\n' | b'\r' | b'\t'
            )
        {
            self.at += 1;
        }
        if self.at == start {
            return Err("expected a JSON value".to_string());
        }
        Ok(None)
    }

    fn object(&mut self) -> Result<Option<String>, String> {
        self.at += 1;
        let mut keys: Vec<String> = Vec::new();
        loop {
            self.ws();
            match self.bytes.get(self.at).copied() {
                Some(b'}') => {
                    self.at += 1;
                    return Ok(None);
                }
                Some(b'"') => {
                    let key = self.string()?;
                    if keys.iter().any(|seen| seen == &key) {
                        return Ok(Some(key));
                    }
                    keys.push(key);
                    self.ws();
                    if self.bytes.get(self.at) != Some(&b':') {
                        return Err("expected ':'".to_string());
                    }
                    self.at += 1;
                    if let Some(duplicate) = self.value()? {
                        return Ok(Some(duplicate));
                    }
                    self.ws();
                    match self.bytes.get(self.at).copied() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(None);
                        }
                        _ => return Err("expected ',' or '}'".to_string()),
                    }
                }
                _ => return Err("expected an object key".to_string()),
            }
        }
    }

    fn array(&mut self) -> Result<Option<String>, String> {
        self.at += 1;
        loop {
            self.ws();
            if self.bytes.get(self.at) == Some(&b']') {
                self.at += 1;
                return Ok(None);
            }
            if let Some(duplicate) = self.value()? {
                return Ok(Some(duplicate));
            }
            self.ws();
            match self.bytes.get(self.at).copied() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(None);
                }
                _ => return Err("expected ',' or ']'".to_string()),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.at) != Some(&b'"') {
            return Err("expected a string".to_string());
        }
        self.at += 1;
        let mut out = String::new();
        loop {
            let byte = *self.bytes.get(self.at).ok_or("unterminated string")?;
            self.at += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = *self.bytes.get(self.at).ok_or("unterminated escape")?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.at..self.at + 4)
                                .ok_or("short unicode escape")?;
                            let hex = std::str::from_utf8(hex).map_err(|_| "bad unicode escape")?;
                            let code =
                                u16::from_str_radix(hex, 16).map_err(|_| "bad unicode escape")?;
                            self.at += 4;
                            if let Some(character) = char::from_u32(u32::from(code)) {
                                out.push(character);
                            }
                        }
                        _ => return Err("bad escape".to_string()),
                    }
                }
                byte if byte < 0x20 => return Err("control character in string".to_string()),
                byte => out.push(byte as char),
            }
        }
    }
}
