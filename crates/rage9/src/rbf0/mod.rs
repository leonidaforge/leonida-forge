//! RBF0: a binary token stream with a per-document name table.
//!
//! The grammar is the one the research validated on 238 unique payloads
//! (RBF0-F15 to RBF0-F17):
//!
//! ```text
//! Document      := "RBF0" VersionHeader? Element
//! VersionHeader := u16(0xFFFB) u16(version)
//! Element       := Token(type=0) Name? u32(reserved) u16(attribute_count)
//!                  Attribute* BodyToken* u16(0xFFFF)
//! Attribute     := Token(type=1..6) Name? Value
//! BodyToken     := Element | Value | Text | u16(0xFFFF)
//! Value         := Token(type=1..6) Name? bytes
//! Text          := u16(0xFFFD) u32(byte_length) bytes
//! Token         := u16(name_index | (type_code << 12))
//! ```
//!
//! The versioned header makes numbers 8 bytes wide; the versionless one
//! starts the token stream at `+0x04` and numbers are 4 bytes wide. `Name?`
//! is present only when the token's 12-bit name index equals the current name
//! table length; a lower index reuses an earlier name, a higher one is an
//! error.
//!
//! Type codes 7 to 14 were not observed. A token with one of them stops the
//! parse with its offset and class instead of being skipped.
//!
//! Names and text values are payload text. They stay in memory so a caller
//! can hash them and are never part of a report.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

/// The four bytes the payload starts with.
pub const MAGIC: [u8; 4] = *b"RBF0";
/// The `u16` that marks the versioned header, at `+0x04`.
pub const HEADER_MARKER: u16 = 0xFFFB;
/// The only version observed with the versioned header.
pub const VERSION: u16 = 1;
/// Number width of a versioned document.
pub const VERSIONED_NUMBER_LEN: usize = 8;
/// Number width of a versionless document.
pub const VERSIONLESS_NUMBER_LEN: usize = 4;
/// Closes the innermost open element.
pub const TERMINATOR: u16 = 0xFFFF;
/// A text node: `u32` byte length, then bytes.
pub const TEXT_TOKEN: u16 = 0xFFFD;
/// The low 12 bits of a token: the name index.
pub const NAME_INDEX_MASK: u16 = 0x0FFF;
/// The high 4 bits of a token: the type code.
pub const TYPE_SHIFT: u32 = 12;

/// Whether `head` starts an RBF0 payload.
pub fn is_rbf0(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

/// The type code of a token word.
pub fn type_code(token: u16) -> u8 {
    (token >> TYPE_SHIFT) as u8
}

/// The name index of a token word.
pub fn name_index(token: u16) -> u16 {
    token & NAME_INDEX_MASK
}

/// Bytes a value of type code `code` occupies, when it is fixed. `None` for
/// the length-prefixed and zero-byte forms, which the parser handles.
pub fn fixed_value_len(code: u8) -> Option<usize> {
    match code {
        2 | 3 => Some(0),
        5 => Some(12),
        _ => None,
    }
}

/// Why a payload could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The bytes do not start with the magic.
    NotRbf0,
    /// The payload ends before a record does.
    TooShort,
    /// The header marker is not the verified value.
    UnsupportedVersion,
    /// The bytes contradict the established grammar.
    Structure,
    /// A token class the grammar does not define.
    UnsupportedToken,
    /// A name index beyond the current name table.
    NameIndex,
    /// An element without its `0xFFFF` terminator.
    Unterminated,
    /// Bytes after the root element.
    Trailing,
    /// A caller limit was reached.
    Limit,
    Cancelled,
}

/// A parse failure and the offset it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
    pub message: String,
}

impl Error {
    fn new(kind: ErrorKind, offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}: {}", self.offset, self.message)
    }
}

impl std::error::Error for Error {}

/// The document header: the versioned form or the versionless one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Whether the `0xFFFB` marker and a version word are present.
    pub versioned: bool,
    /// The `u16` after the marker. `None` for the versionless form.
    pub version: Option<u16>,
}

impl Header {
    /// Parses the header from `head`, the start of the payload. No token is
    /// read.
    pub fn parse(head: &[u8]) -> Result<Self, Error> {
        if !is_rbf0(head) {
            return Err(Error::new(ErrorKind::NotRbf0, 0, "not an RBF0 payload"));
        }
        if head.len() < MAGIC.len() + 2 {
            return Err(Error::new(
                ErrorKind::TooShort,
                head.len(),
                "the payload ends before the first token",
            ));
        }
        let word = u16::from_le_bytes([head[4], head[5]]);
        if word == HEADER_MARKER {
            let version = head
                .get(6..8)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
            let Some(version) = version else {
                return Err(Error::new(
                    ErrorKind::TooShort,
                    6,
                    "the versioned header ends before its version word",
                ));
            };
            return Ok(Self {
                versioned: true,
                version: Some(version),
            });
        }
        Ok(Self {
            versioned: false,
            version: None,
        })
    }

    /// The offset of the first token.
    pub fn body_offset(&self) -> usize {
        if self.versioned {
            MAGIC.len() + 4
        } else {
            MAGIC.len()
        }
    }

    /// The width of a number value, which the header variant decides.
    pub fn number_len(&self) -> usize {
        if self.versioned {
            VERSIONED_NUMBER_LEN
        } else {
            VERSIONLESS_NUMBER_LEN
        }
    }
}

/// Caps one parse.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Nested elements allowed below the root element. The root is depth 0.
    pub max_depth: usize,
    /// Names the document may define.
    pub max_names: usize,
    /// Elements the document may hold.
    pub max_elements: usize,
    /// Bytes a single name, text node or value may declare.
    pub max_value_len: u32,
    /// Text bytes copied out of one payload.
    pub max_text: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_names: 4096,
            max_elements: 1 << 20,
            max_value_len: 1 << 20,
            max_text: 8 << 20,
        }
    }
}

/// An observed oddity that did not stop the parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostic {
    pub offset: usize,
    pub message: &'static str,
}

/// One name the document defines, by its name index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The 12-bit name index.
    pub index: u16,
    /// Offset of the name length that starts the definition.
    pub offset: usize,
    pub name_len: usize,
    /// SHA-256 of the name bytes, so a name can be identified without being
    /// shown.
    pub name_digest: [u8; 32],
}

/// Counts and lengths of one kind of text value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TextStats {
    pub count: usize,
    pub bytes: u64,
    pub min_len: usize,
    pub max_len: usize,
}

impl TextStats {
    fn add(&mut self, len: usize) {
        if self.count == 0 || len < self.min_len {
            self.min_len = len;
        }
        if len > self.max_len {
            self.max_len = len;
        }
        self.count += 1;
        self.bytes += len as u64;
    }
}

/// A parsed RBF0 document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub header: Header,
    /// SHA-256 of the root element's name bytes.
    pub root_name_digest: [u8; 32],
    /// Offset of the first token.
    pub body_offset: usize,
    /// Names the document defined.
    pub names: usize,
    /// Elements, including the root element.
    pub objects: usize,
    /// Deepest element depth, the root element being 0.
    pub depth: usize,
    /// Value tokens in body positions.
    pub fields: usize,
    /// Attribute tokens.
    pub attributes: usize,
    /// Text nodes.
    pub text_nodes: usize,
    /// Value tokens per type code, indices 1 to 6.
    pub types: [usize; 7],
    pub definitions: Vec<Definition>,
    /// Counts and lengths of the text nodes.
    pub strings: TextStats,
    /// Counts and lengths of the length-prefixed (type 6) values.
    pub attribute_values: TextStats,
    /// Defined names, in definition order. Payload text: a caller may hash
    /// it, and it is never reported.
    pub field_names: Vec<String>,
    /// Text-node content, in document order. Payload text, as above.
    pub string_texts: Vec<String>,
    /// Type 6 values, in document order. Payload text, as above.
    pub attribute_texts: Vec<String>,
    /// End of the root element.
    pub end: usize,
    pub diagnostics: Vec<Diagnostic>,
}

/// Which verified text field a string came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    FieldName,
    StringValue,
    AttributeValue,
}

impl TextKind {
    pub fn name(self) -> &'static str {
        match self {
            TextKind::FieldName => "field_name",
            TextKind::StringValue => "string_value",
            TextKind::AttributeValue => "attribute_value",
        }
    }
}

/// Parses a whole RBF0 payload. The root element must consume the payload
/// exactly.
pub fn parse(bytes: &[u8], limits: &Limits, cancel: &AtomicBool) -> Result<Document, Error> {
    let header = Header::parse(bytes)?;
    if let Some(version) = header.version
        && version != VERSION
    {
        return Err(Error::new(
            ErrorKind::UnsupportedVersion,
            6,
            format!("version {version} was not observed; only {VERSION} is supported"),
        ));
    }
    let mut parser = Parser {
        bytes,
        at: header.body_offset(),
        limits: *limits,
        cancel,
        names: Vec::new(),
        text: 0,
        diagnostics: Vec::new(),
        document: Document {
            header,
            root_name_digest: [0; 32],
            body_offset: header.body_offset(),
            names: 0,
            objects: 0,
            depth: 0,
            fields: 0,
            attributes: 0,
            text_nodes: 0,
            types: [0; 7],
            definitions: Vec::new(),
            strings: TextStats::default(),
            attribute_values: TextStats::default(),
            field_names: Vec::new(),
            string_texts: Vec::new(),
            attribute_texts: Vec::new(),
            end: 0,
            diagnostics: Vec::new(),
        },
    };
    let root_offset = parser.at;
    let token = parser.u16("root token")?;
    if type_code(token) != 0 {
        return Err(Error::new(
            ErrorKind::Structure,
            root_offset,
            format!(
                "the first token has type code {}, but the root must be an element (0)",
                type_code(token)
            ),
        ));
    }
    parser.element_at(token, root_offset, 0)?;
    if parser.at != bytes.len() {
        return Err(Error::new(
            ErrorKind::Trailing,
            parser.at,
            format!(
                "{} bytes follow the root element, which must end the payload",
                bytes.len() - parser.at
            ),
        ));
    }
    let mut document = parser.document;
    document.end = parser.at;
    document.diagnostics = parser.diagnostics;
    Ok(document)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    limits: Limits,
    cancel: &'a AtomicBool,
    /// Defined names, by name index.
    names: Vec<String>,
    /// Text bytes copied so far.
    text: usize,
    diagnostics: Vec<Diagnostic>,
    document: Document,
}

impl<'a> Parser<'a> {
    fn check_cancel(&self) -> Result<(), Error> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::Cancelled, self.at, "cancelled"));
        }
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(len).ok_or_else(|| {
            Error::new(
                ErrorKind::Structure,
                self.at,
                format!("the {what} length overflows"),
            )
        })?;
        if end > self.bytes.len() {
            return Err(Error::new(
                ErrorKind::TooShort,
                self.at,
                format!(
                    "truncated {what}: {len} bytes needed, {} available",
                    self.remaining()
                ),
            ));
        }
        let bytes: &'a [u8] = self.bytes;
        let slice = &bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u16(&mut self, what: &str) -> Result<u16, Error> {
        let bytes = self.take(2, what)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, what: &str) -> Result<u32, Error> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("four bytes were taken"),
        ))
    }

    /// Parses one element whose type-0 token has already been read.
    fn element_at(&mut self, token: u16, token_offset: usize, depth: usize) -> Result<(), Error> {
        self.check_cancel()?;
        if depth > self.limits.max_depth {
            return Err(Error::new(
                ErrorKind::Limit,
                token_offset,
                format!(
                    "elements nest deeper than the {} level limit",
                    self.limits.max_depth
                ),
            ));
        }
        if self.document.objects >= self.limits.max_elements {
            return Err(Error::new(
                ErrorKind::Limit,
                token_offset,
                format!(
                    "the payload holds more than {} elements",
                    self.limits.max_elements
                ),
            ));
        }
        self.document.objects += 1;
        self.document.depth = self.document.depth.max(depth);
        self.name_of(token, token_offset)?;
        if depth == 0
            && let Some(name) = self.names.first()
        {
            self.document.root_name_digest = Sha256::digest(name.as_bytes()).into();
        }

        let reserved = self.at;
        if self.u32("element reserved word")? != 0 {
            self.diagnostics.push(Diagnostic {
                offset: reserved,
                message: "the element reserved word is not zero",
            });
        }
        let declared = usize::from(self.u16("element attribute count")?);
        // An attribute token is at least two bytes, so a larger count cannot
        // fit in what is left.
        if declared > self.remaining() / 2 {
            return Err(Error::new(
                ErrorKind::Structure,
                self.at,
                format!(
                    "the element declares {declared} attributes, more than the remaining {} bytes hold",
                    self.remaining()
                ),
            ));
        }
        for _ in 0..declared {
            self.check_cancel()?;
            self.attribute()?;
        }
        loop {
            self.check_cancel()?;
            if self.remaining() < 2 {
                return Err(Error::new(
                    ErrorKind::Unterminated,
                    self.at,
                    "the element has no terminator",
                ));
            }
            let offset = self.at;
            let token = self.u16("body token")?;
            if token == TERMINATOR {
                return Ok(());
            }
            if token == TEXT_TOKEN {
                self.text_node()?;
                continue;
            }
            match type_code(token) {
                0 => self.element_at(token, offset, depth + 1)?,
                1..=6 => {
                    self.value(token, offset)?;
                    self.document.fields += 1;
                }
                code => {
                    return Err(Error::new(
                        ErrorKind::UnsupportedToken,
                        offset,
                        format!("token class {code} is not part of the grammar"),
                    ));
                }
            }
        }
    }

    fn attribute(&mut self) -> Result<(), Error> {
        let offset = self.at;
        let token = self.u16("attribute token")?;
        let code = type_code(token);
        if code == 0 {
            return Err(Error::new(
                ErrorKind::Structure,
                offset,
                "an element token appears in an attribute position",
            ));
        }
        if !(1..=6).contains(&code) {
            return Err(Error::new(
                ErrorKind::UnsupportedToken,
                offset,
                format!("attribute token class {code} is not part of the grammar"),
            ));
        }
        self.value(token, offset)?;
        self.document.attributes += 1;
        Ok(())
    }

    /// A text node: `u16 0xFFFD`, `u32` length, then bytes.
    fn text_node(&mut self) -> Result<(), Error> {
        let len_at = self.at;
        let len = self.u32("text length")?;
        let len = usize::try_from(len).map_err(|_| {
            Error::new(
                ErrorKind::Limit,
                len_at,
                "the text length does not fit in memory",
            )
        })?;
        self.check_len(len, "text node")?;
        let bytes = self.take(len, "text node")?;
        self.document.text_nodes += 1;
        self.document.strings.add(len);
        self.note_text(bytes, TextKind::StringValue, false);
        Ok(())
    }

    /// Reads a value token's optional name and then its value bytes.
    fn value(&mut self, token: u16, offset: usize) -> Result<(), Error> {
        let code = type_code(token);
        self.name_of(token, offset)?;
        self.document.types[usize::from(code.min(6))] += 1;
        match code {
            1 | 4 => {
                let width = self.document.header.number_len();
                self.take(width, "number value")?;
            }
            2 | 3 => {}
            5 => {
                self.take(12, "twelve-byte value")?;
            }
            6 => {
                let len_at = self.at;
                let len = usize::from(self.u16("value length")?);
                self.check_len(len, "length-prefixed value")?;
                let bytes = self.take(len, "length-prefixed value")?;
                let _ = len_at;
                self.document.attribute_values.add(len);
                self.note_text(bytes, TextKind::AttributeValue, false);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::UnsupportedToken,
                    offset,
                    format!("token class {code} is not part of the grammar"),
                ));
            }
        }
        Ok(())
    }

    /// Reads the name of a token: its `u16` length and bytes when the index
    /// equals the current table length, or nothing when it reuses a name.
    fn name_of(&mut self, token: u16, token_offset: usize) -> Result<(), Error> {
        let index = name_index(token);
        let defined = self.names.len();
        if usize::from(index) < defined {
            return Ok(());
        }
        if usize::from(index) > defined {
            return Err(Error::new(
                ErrorKind::NameIndex,
                token_offset,
                format!("name index {index} is beyond the {defined} names defined so far"),
            ));
        }
        if defined >= self.limits.max_names {
            return Err(Error::new(
                ErrorKind::Limit,
                token_offset,
                format!(
                    "the payload defines more than {} names",
                    self.limits.max_names
                ),
            ));
        }
        let name_offset = self.at;
        let name_len = usize::from(self.u16("name length")?);
        self.check_len(name_len, "name")?;
        let name = self.take(name_len, "name")?;
        let digest = Sha256::digest(name).into();
        self.note_text(name, TextKind::FieldName, false);
        let text = std::str::from_utf8(name)
            .map(str::to_string)
            .unwrap_or_default();
        self.names.push(text);
        self.document.names = self.names.len();
        self.document.definitions.push(Definition {
            index,
            offset: name_offset,
            name_len,
            name_digest: digest,
        });
        Ok(())
    }

    fn check_len(&self, len: usize, what: &str) -> Result<(), Error> {
        if len as u64 > u64::from(self.limits.max_value_len) {
            return Err(Error::new(
                ErrorKind::Limit,
                self.at,
                format!(
                    "a {what} declares {len} bytes, more than the {} byte limit",
                    self.limits.max_value_len
                ),
            ));
        }
        Ok(())
    }

    /// Keeps payload text for a caller that hashes it. `terminated` values end
    /// with one NUL that is not part of the value.
    fn note_text(&mut self, bytes: &[u8], kind: TextKind, terminated: bool) {
        let start = self.at.saturating_sub(bytes.len());
        let body = match (terminated, bytes.strip_suffix(&[0])) {
            (true, Some(without)) => without,
            (true, None) => {
                self.diagnostics.push(Diagnostic {
                    offset: start,
                    message: "the string value does not end with a NUL",
                });
                bytes
            }
            (false, _) => bytes,
        };
        if body.contains(&0) {
            self.diagnostics.push(Diagnostic {
                offset: start,
                message: match kind {
                    TextKind::FieldName => "the field name contains a NUL",
                    _ => "the value contains a NUL before its end",
                },
            });
        }
        if self.text >= self.limits.max_text {
            return;
        }
        let Ok(value) = std::str::from_utf8(body) else {
            self.diagnostics.push(Diagnostic {
                offset: start,
                message: "the text value is not valid UTF-8",
            });
            return;
        };
        if self.text + value.len() > self.limits.max_text {
            return;
        }
        self.text += value.len();
        let target = match kind {
            TextKind::FieldName => &mut self.document.field_names,
            TextKind::StringValue => &mut self.document.string_texts,
            TextKind::AttributeValue => &mut self.document.attribute_texts,
        };
        target.push(value.to_string());
    }
}

#[cfg(test)]
mod tests;
