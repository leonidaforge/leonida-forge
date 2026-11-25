//! RBF0: a recursive object stream with inline field names.
//!
//! Established on 18 payloads of one nested archive (research findings RBF0-F01
//! to RBF0-F14):
//!
//! ```text
//! Document  := Header Object
//! Header    := "RBF0" u16(0xFFFB) u32(1) u16(root_name_len) root_name
//! Object    := u32(0) u16(attribute_count) Attribute* Field* u16(0xFFFF)
//! Attribute := FieldId [u16(name_len) name] u16(value_len) value
//! Field     := FieldId [u16(name_len) name] FieldValue
//! FieldId   := u16
//! ```
//!
//! A field name is present only on the first use of its identifier within one
//! payload. A string value is `u32(0) u16(0) u16(0xFFFD) u32(len) bytes
//! u16(0xFFFF)`, an object value is another object, and `0x1006` carries eight
//! bytes with no length prefix and no terminator.
//!
//! Only the identifiers the research observed are accepted: `0x0001` and
//! `0x0002` for objects, `0x0004` to `0x000A` for strings, `0x1006` for the
//! eight-byte value and `0x6003`/`0x6004` for attributes. Any other identifier
//! stops the parse instead of being guessed at.
//!
//! The root name, the field names and every text value are payload text. They
//! stay in memory so a caller can hash them and are never part of a report.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

/// The four bytes the payload starts with.
pub const MAGIC: [u8; 4] = *b"RBF0";
/// Bytes before the root name: magic, header marker, header value and root
/// name length.
pub const PREFIX_LEN: usize = 0x0C;
/// The `u16` at +0x04 in every verified payload. Meaning unknown.
pub const HEADER_MARKER: u16 = 0xFFFB;
/// The `u32` at +0x06 in every verified payload. Meaning unknown.
pub const HEADER_VALUE: u32 = 1;
/// Closes an object and follows every string value.
pub const TERMINATOR: u16 = 0xFFFF;
/// Tags a string value after its two zero words.
pub const STRING_VALUE_TAG: u16 = 0xFFFD;
/// The one observed field identifier with a fixed eight-byte value.
pub const FIXED8_FIELD: u16 = 0x1006;
/// Length of that value.
pub const FIXED8_LEN: usize = 8;
/// Field identifiers whose value is another object.
pub const OBJECT_FIELDS: [u16; 2] = [0x0001, 0x0002];
/// The field identifiers whose value is a string.
pub const STRING_FIELDS: std::ops::RangeInclusive<u16> = 0x0004..=0x000A;
/// The field identifiers used for attributes.
pub const ATTRIBUTE_FIELDS: [u16; 2] = [0x6003, 0x6004];

/// Whether `head` starts an RBF0 payload.
pub fn is_rbf0(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

/// How the verified identifier sets classify a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    Object,
    String,
    Fixed8,
    Attribute,
}

impl FieldClass {
    /// The class of `field_id`, or `None` when the identifier is outside the
    /// observed sets.
    pub fn of(field_id: u16) -> Option<Self> {
        match field_id {
            id if OBJECT_FIELDS.contains(&id) => Some(FieldClass::Object),
            id if STRING_FIELDS.contains(&id) => Some(FieldClass::String),
            FIXED8_FIELD => Some(FieldClass::Fixed8),
            id if ATTRIBUTE_FIELDS.contains(&id) => Some(FieldClass::Attribute),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            FieldClass::Object => "object",
            FieldClass::String => "string",
            FieldClass::Fixed8 => "fixed8",
            FieldClass::Attribute => "attribute",
        }
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

/// The header in front of the root name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The `u16` at +0x04. Meaning unknown; [`HEADER_MARKER`] in every sample.
    pub word: u16,
    /// The `u32` at +0x06. Meaning unknown; [`HEADER_VALUE`] in every sample.
    pub flags: u32,
    /// The `u16` at +0x0A: the length of the root name that follows.
    pub root_name_len: u16,
}

impl Header {
    /// Parses the header from `head`, the start of the payload. No root name
    /// byte is read or checked.
    pub fn parse(head: &[u8]) -> Result<Self, Error> {
        if !is_rbf0(head) {
            return Err(Error::new(ErrorKind::NotRbf0, 0, "not an RBF0 payload"));
        }
        let prefix = head.get(..PREFIX_LEN).ok_or_else(|| {
            Error::new(
                ErrorKind::TooShort,
                head.len(),
                "the payload is shorter than the 12-byte header",
            )
        })?;
        Ok(Self {
            word: u16::from_le_bytes([prefix[4], prefix[5]]),
            flags: u32::from_le_bytes([prefix[6], prefix[7], prefix[8], prefix[9]]),
            root_name_len: u16::from_le_bytes([prefix[0x0A], prefix[0x0B]]),
        })
    }
}

/// Caps one parse.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Nested objects allowed below the root object. The root is depth 0.
    pub max_depth: usize,
    /// Field identifiers stored as a definition.
    pub max_definitions: usize,
    /// Bytes a single name or value may declare.
    pub max_value_len: u32,
    /// Text bytes copied out of one payload.
    pub max_text: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_definitions: 4096,
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

/// One field identifier and the name defined for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    pub field_id: u16,
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
    /// SHA-256 of the root name bytes.
    pub root_name_digest: [u8; 32],
    /// Offset of the root object.
    pub body_offset: usize,
    /// Objects, including the root object.
    pub objects: usize,
    /// Deepest object depth, the root object being 0.
    pub depth: usize,
    pub fields: usize,
    pub object_fields: usize,
    pub string_fields: usize,
    pub fixed8_fields: usize,
    pub attributes: usize,
    pub definitions: Vec<Definition>,
    pub strings: TextStats,
    pub attribute_values: TextStats,
    /// Verified field names, in definition order. Payload text: a caller may
    /// hash it, and it is never reported.
    pub field_names: Vec<String>,
    /// Verified string values, in document order. Payload text, as above.
    pub string_texts: Vec<String>,
    /// Verified attribute values, in document order. Payload text, as above.
    pub attribute_texts: Vec<String>,
    /// End of the root object.
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

/// Parses a whole RBF0 payload.
pub fn parse(bytes: &[u8], limits: &Limits, cancel: &AtomicBool) -> Result<Document, Error> {
    let header = Header::parse(bytes)?;
    if header.word != HEADER_MARKER {
        return Err(Error::new(
            ErrorKind::UnsupportedVersion,
            4,
            format!(
                "header marker 0x{:04X} is not the verified 0x{HEADER_MARKER:04X}",
                header.word
            ),
        ));
    }
    let mut parser = Parser {
        bytes,
        at: PREFIX_LEN,
        limits: *limits,
        cancel,
        defined: HashSet::new(),
        text: 0,
        diagnostics: Vec::new(),
        document: Document {
            header,
            root_name_digest: [0; 32],
            body_offset: PREFIX_LEN,
            objects: 0,
            depth: 0,
            fields: 0,
            object_fields: 0,
            string_fields: 0,
            fixed8_fields: 0,
            attributes: 0,
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
    if header.flags != HEADER_VALUE {
        parser.diagnostics.push(Diagnostic {
            offset: 6,
            message: "the header value is not the observed 1",
        });
    }
    let root_name_len = usize::from(header.root_name_len);
    let root_name = parser.take(root_name_len, "root name")?;
    parser.document.root_name_digest = Sha256::digest(root_name).into();
    parser.document.body_offset = parser.at;
    parser.object(0)?;
    if parser.at != bytes.len() {
        return Err(Error::new(
            ErrorKind::Structure,
            parser.at,
            format!(
                "{} bytes follow the root object, which must end the payload",
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
    /// Field identifiers whose name has been defined in this payload.
    defined: HashSet<u16>,
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

    fn object(&mut self, depth: usize) -> Result<(), Error> {
        self.check_cancel()?;
        if depth > self.limits.max_depth {
            return Err(Error::new(
                ErrorKind::Limit,
                self.at,
                format!(
                    "objects nest deeper than the {} level limit",
                    self.limits.max_depth
                ),
            ));
        }
        self.document.objects += 1;
        self.document.depth = self.document.depth.max(depth);

        let reserved = self.at;
        if self.u32("object reserved word")? != 0 {
            self.diagnostics.push(Diagnostic {
                offset: reserved,
                message: "the object reserved word is not zero",
            });
        }
        let declared = usize::from(self.u16("object attribute count")?);
        // An attribute is at least three bytes, so a larger count cannot fit.
        if declared > self.remaining() / 3 {
            return Err(Error::new(
                ErrorKind::Structure,
                self.at,
                format!(
                    "the object declares {declared} attributes, more than the remaining {} bytes hold",
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
            let field_offset = self.at;
            if self.remaining() < 2 {
                return Err(Error::new(
                    ErrorKind::Structure,
                    self.at,
                    "the object has no terminator",
                ));
            }
            let field_id = self.u16("field identifier")?;
            if field_id == TERMINATOR {
                return Ok(());
            }
            let Some(class) = FieldClass::of(field_id) else {
                return Err(Error::new(
                    ErrorKind::Structure,
                    field_offset,
                    format!(
                        "field identifier 0x{field_id:04X} is outside the observed identifier sets"
                    ),
                ));
            };
            match class {
                FieldClass::Object => {
                    self.definition(field_id)?;
                    self.document.fields += 1;
                    self.document.object_fields += 1;
                    self.object(depth + 1)?;
                }
                FieldClass::String => {
                    self.definition(field_id)?;
                    self.document.fields += 1;
                    self.document.string_fields += 1;
                    self.string_value()?;
                }
                FieldClass::Fixed8 => {
                    self.definition(field_id)?;
                    self.document.fields += 1;
                    self.document.fixed8_fields += 1;
                    self.take(FIXED8_LEN, "fixed eight-byte value")?;
                }
                FieldClass::Attribute => {
                    return Err(Error::new(
                        ErrorKind::Structure,
                        field_offset,
                        format!(
                            "attribute identifier 0x{field_id:04X} occurs in the field stream; attribute position is unresolved"
                        ),
                    ));
                }
            }
        }
    }

    fn attribute(&mut self) -> Result<(), Error> {
        let offset = self.at;
        let field_id = self.u16("attribute identifier")?;
        match FieldClass::of(field_id) {
            Some(FieldClass::Attribute) => {}
            Some(class) => {
                return Err(Error::new(
                    ErrorKind::Structure,
                    offset,
                    format!(
                        "identifier 0x{field_id:04X} is used as an attribute but carries {} values",
                        class.name()
                    ),
                ));
            }
            None => {
                return Err(Error::new(
                    ErrorKind::Structure,
                    offset,
                    format!(
                        "attribute identifier 0x{field_id:04X} is outside the observed identifier sets"
                    ),
                ));
            }
        }
        self.definition(field_id)?;
        self.document.attributes += 1;
        let len = usize::from(self.u16("attribute value length")?);
        self.check_len(len, "attribute value")?;
        let bytes = self.take(len, "attribute value")?;
        self.document.attribute_values.add(len);
        self.note_text(bytes, TextKind::AttributeValue, false);
        Ok(())
    }

    fn string_value(&mut self) -> Result<(), Error> {
        let header = self.at;
        let reserved = self.u32("string value reserved word")?;
        let zero = self.u16("string value zero word")?;
        if reserved != 0 || zero != 0 {
            self.diagnostics.push(Diagnostic {
                offset: header,
                message: "the string value starts with two words that are not zero",
            });
        }
        let tag_offset = self.at;
        let tag = self.u16("string value tag")?;
        if tag != STRING_VALUE_TAG {
            return Err(Error::new(
                ErrorKind::Structure,
                tag_offset,
                format!(
                    "string value tag 0x{tag:04X} is not the observed 0x{STRING_VALUE_TAG:04X}"
                ),
            ));
        }
        let len = self.u32("string value length")?;
        let len = usize::try_from(len).map_err(|_| {
            Error::new(
                ErrorKind::Limit,
                tag_offset,
                "the string value length does not fit in memory",
            )
        })?;
        self.check_len(len, "string value")?;
        let bytes = self.take(len, "string value")?;
        self.document.strings.add(len);
        self.note_text(bytes, TextKind::StringValue, true);
        let terminator_offset = self.at;
        if self.u16("string value terminator")? != TERMINATOR {
            return Err(Error::new(
                ErrorKind::Structure,
                terminator_offset,
                format!("the string value is not closed by 0x{TERMINATOR:04X}"),
            ));
        }
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

    fn definition(&mut self, field_id: u16) -> Result<(), Error> {
        if self.defined.contains(&field_id) {
            return Ok(());
        }
        if self.document.definitions.len() >= self.limits.max_definitions {
            return Err(Error::new(
                ErrorKind::Limit,
                self.at,
                format!(
                    "the payload defines more than {} field identifiers",
                    self.limits.max_definitions
                ),
            ));
        }
        let name_offset = self.at;
        let name_len = usize::from(self.u16("field name length")?);
        self.check_len(name_len, "field name")?;
        let name = self.take(name_len, "field name")?;
        let digest = Sha256::digest(name).into();
        self.note_text(name, TextKind::FieldName, false);
        self.defined.insert(field_id);
        self.document.definitions.push(Definition {
            field_id,
            offset: name_offset,
            name_len,
            name_digest: digest,
        });
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
