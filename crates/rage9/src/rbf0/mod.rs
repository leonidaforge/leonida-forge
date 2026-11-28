//! RBF0: a binary token stream with a per-document name table.
//!
//! The grammar is the one the research validated on 238 unique payloads
//! (RBF0-F15 to RBF0-F17), revalidated on the whole population this decoder
//! was built against:
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
//! [`decode`] returns the document as the tree [`Document`] describes: nested
//! elements in document order, each with its counted attributes and its body.
//! [`parse`] keeps the summary view the inspection report and the name harvest
//! have always used, computed from the same walk.
//!
//! Type codes 7 to 14 were not observed. A token with one of them stops the
//! parse with its offset and class instead of being skipped, because the
//! grammar gives no width to skip.
//!
//! Names and text values are payload text. The tree keeps them so a caller can
//! hash them or show them; it never invents a name or a meaning.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

mod tree;

pub use tree::{Attribute, Document, Element, Field, Node, Text, Value};

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

impl ErrorKind {
    /// Where the failure sits: `header` or `structure`.
    pub fn stage(self) -> &'static str {
        match self {
            ErrorKind::NotRbf0 | ErrorKind::TooShort | ErrorKind::UnsupportedVersion => "header",
            _ => "structure",
        }
    }
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
    /// Name, text and value bytes one document may keep.
    pub max_text: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // The deepest document in the validated population nests 35
            // levels, so the cap leaves room rather than refusing real
            // payloads.
            max_depth: 256,
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

/// The counts of one document, without its tree.
///
/// The inspection report and the name harvest read this view; the document
/// itself is [`Document`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statistics {
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
    /// Counts and lengths of the length-prefixed (type 6) values, in attribute
    /// positions and in body positions.
    pub attribute_values: TextStats,
    /// Defined names, in definition order. A name whose bytes are not UTF-8 is
    /// `None` rather than an empty string, so a reader can tell an unreadable
    /// name from an empty one. Payload text: a caller may hash it, and it is
    /// never reported.
    pub field_names: Vec<String>,
    /// Text-node content, in document order. Payload text, as above.
    pub string_texts: Vec<String>,
    /// Length-prefixed (type 6) values that are UTF-8, in document order and
    /// from both attribute and body positions. Payload text, as above.
    pub attribute_texts: Vec<String>,
    /// End of the root element.
    pub end: usize,
    pub diagnostics: Vec<Diagnostic>,
}

/// Parses a whole RBF0 payload into its tree.
///
/// `Err` is returned only when nothing can be read at all: the magic, the
/// header or the version is wrong. A body the grammar cannot follow comes back
/// as a [`Document`] whose `failure` says where the parse stopped, so what was
/// decoded before that point stays available.
pub fn decode(bytes: &[u8], limits: &Limits, cancel: &AtomicBool) -> Result<Document, Error> {
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
        number_len: header.number_len(),
        limits: *limits,
        cancel,
        names: Vec::new(),
        definitions: Vec::new(),
        diagnostics: Vec::new(),
        kept: 0,
        elements: 0,
    };
    let body_offset = parser.at;
    let (root, failure) = parser.document();
    let end = parser.at;
    let trailing = if failure.is_none() {
        bytes.len().saturating_sub(end)
    } else {
        0
    };
    Ok(Document {
        header,
        names: parser.names,
        definitions: parser.definitions,
        root,
        failure,
        trailing,
        diagnostics: parser.diagnostics,
        body_offset,
        end,
    })
}

/// Parses a whole RBF0 payload into its tree, which must be complete: the root
/// element ends the payload.
pub fn decode_complete(
    bytes: &[u8],
    limits: &Limits,
    cancel: &AtomicBool,
) -> Result<Document, Error> {
    let document = decode(bytes, limits, cancel)?;
    match document.failure {
        Some(err) => Err(err),
        None if document.trailing != 0 => Err(Error::new(
            ErrorKind::Trailing,
            document.end,
            format!(
                "{} bytes follow the root element, which must end the payload",
                document.trailing
            ),
        )),
        None => Ok(document),
    }
}

/// Parses a whole RBF0 payload and summarises it.
///
/// The statistics are the ones the inspection report has always used: counts,
/// lengths and name digests, with the names and text kept for a caller that
/// hashes them. [`decode`] keeps the document itself.
pub fn parse(bytes: &[u8], limits: &Limits, cancel: &AtomicBool) -> Result<Statistics, Error> {
    let document = decode_complete(bytes, limits, cancel)?;
    let mut statistics = statistics(&document);
    statistics.diagnostics = document.diagnostics.clone();
    Ok(statistics)
}

/// Summarises a decoded document.
pub fn statistics(document: &Document) -> Statistics {
    let mut statistics = Statistics {
        header: document.header,
        root_name_digest: document
            .root_name()
            .map(|name| <[u8; 32]>::from(Sha256::digest(name.as_bytes())))
            .unwrap_or([0; 32]),
        body_offset: document.body_offset,
        names: document.names.len(),
        objects: 0,
        depth: 0,
        fields: 0,
        attributes: 0,
        text_nodes: 0,
        types: [0; 7],
        definitions: document.definitions.clone(),
        strings: TextStats::default(),
        attribute_values: TextStats::default(),
        // A name whose bytes are not UTF-8 is not "" and must not be hashed as
        // though the document stored an empty name.
        field_names: document.names.iter().flatten().cloned().collect(),
        string_texts: Vec::new(),
        attribute_texts: Vec::new(),
        end: document.end,
        diagnostics: Vec::new(),
    };
    walk(&document.root, 0, &mut statistics);
    statistics
}

fn walk(element: &Element, depth: usize, statistics: &mut Statistics) {
    statistics.objects += 1;
    statistics.depth = statistics.depth.max(depth);
    for attribute in &element.attributes {
        statistics.attributes += 1;
        count_value(&attribute.value, statistics);
    }
    for node in &element.children {
        match node {
            Node::Element(child) => walk(child, depth + 1, statistics),
            Node::Field(field) => {
                statistics.fields += 1;
                count_value(&field.value, statistics);
            }
            Node::Text(text) => {
                statistics.text_nodes += 1;
                statistics.strings.add(text.declared);
                if let Some((value, _)) = text.text() {
                    statistics.string_texts.push(value.to_string());
                }
            }
        }
    }
}

fn count_value(value: &Value, statistics: &mut Statistics) {
    statistics.types[usize::from(value.code().min(6))] += 1;
    if let Value::Bytes { declared, .. } = value {
        statistics.attribute_values.add(*declared);
        if let Some((text, _)) = value.text() {
            statistics.attribute_texts.push(text.to_string());
        }
    }
}

/// Reads one payload. Elements are kept on an explicit stack rather than the
/// call stack, so a document that stops early can be closed where it stopped.
struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
    /// Number width the header form fixes.
    number_len: usize,
    limits: Limits,
    cancel: &'a AtomicBool,
    /// Defined names, by name index.
    names: Vec<Option<String>>,
    definitions: Vec<Definition>,
    diagnostics: Vec<Diagnostic>,
    /// Name, text and value bytes kept so far.
    kept: usize,
    /// Elements opened so far.
    elements: usize,
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
            // The payload ran out, not the record: report where it ends, so the
            // offset can be read the same way as an unterminated element.
            return Err(Error::new(
                ErrorKind::TooShort,
                self.bytes.len(),
                format!(
                    "truncated {what}: {len} bytes needed at 0x{:08X}, {} available",
                    self.at,
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

    /// Whether `len` more bytes fit in the document's text budget, consuming
    /// it when they do.
    fn keep(&mut self, len: usize) -> bool {
        if self.kept.saturating_add(len) > self.limits.max_text {
            return false;
        }
        self.kept += len;
        true
    }

    fn check_len(&self, len: usize, what: &str, at: usize) -> Result<(), Error> {
        if len as u64 > u64::from(self.limits.max_value_len) {
            return Err(Error::new(
                ErrorKind::Limit,
                at,
                format!(
                    "a {what} declares {len} bytes, more than the {} byte limit",
                    self.limits.max_value_len
                ),
            ));
        }
        Ok(())
    }

    /// Reads the whole document. A body the grammar cannot follow closes every
    /// open element where it stopped and is returned beside the tree.
    fn document(&mut self) -> (Element, Option<Error>) {
        let root_offset = self.at;
        let root_token = match self.check_cancel().and_then(|()| self.u16("root token")) {
            Ok(token) => token,
            Err(err) => return (Element::default(), Some(err)),
        };
        if type_code(root_token) != 0 {
            return (
                Element::default(),
                Some(Error::new(
                    ErrorKind::Structure,
                    root_offset,
                    format!(
                        "the first token has type code {}, but the root must be an element (0)",
                        type_code(root_token)
                    ),
                )),
            );
        }
        let root = {
            let mut root = Element {
                offset: root_offset,
                ..Element::default()
            };
            match self.element_head(root_token, root_offset, 0, &mut root) {
                Ok(()) => root,
                Err(err) => {
                    // The head that was read is the document's own root, so it
                    // stays even when the rest of it could not be read.
                    root.end = err.offset;
                    return (root, Some(err));
                }
            }
        };
        // The depth of an open element is its position in the stack.
        let mut stack: Vec<Element> = vec![root];
        loop {
            if let Err(err) = self.check_cancel() {
                return (self.close_all(stack, err.offset), Some(err));
            }
            if self.remaining() < 2 {
                let err = Error::new(
                    ErrorKind::Unterminated,
                    self.at,
                    format!(
                        "the element opened at 0x{:08X} has no terminator",
                        stack.last().map_or(self.at, |element| element.offset)
                    ),
                );
                return (self.close_all(stack, self.at), Some(err));
            }
            let offset = self.at;
            let token = match self.u16("body token") {
                Ok(token) => token,
                Err(err) => return (self.close_all(stack, self.at), Some(err)),
            };
            if token == TERMINATOR {
                let mut finished = stack.pop().expect("the body loop holds an element");
                finished.end = self.at;
                finished.terminated = true;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(finished)),
                    None => return (finished, None),
                }
                continue;
            }
            let node = if token == TEXT_TOKEN {
                self.text_node().map(Node::Text)
            } else {
                match type_code(token) {
                    0 => {
                        let mut element = Element {
                            offset,
                            ..Element::default()
                        };
                        match self.element_head(token, offset, stack.len(), &mut element) {
                            Ok(()) => {
                                stack.push(element);
                                continue;
                            }
                            Err(err) => {
                                // Keep the head that was read, when there was
                                // one, as the child it was going to be.
                                if self.at > offset + 2 {
                                    element.end = err.offset;
                                    stack
                                        .last_mut()
                                        .expect("the body loop holds an element")
                                        .children
                                        .push(Node::Element(element));
                                }
                                return (self.close_all(stack, err.offset), Some(err));
                            }
                        }
                    }
                    1..=6 => self.value(token, offset).map(|value| {
                        Node::Field(Field {
                            offset,
                            index: name_index(token),
                            value,
                        })
                    }),
                    code => Err(Error::new(
                        ErrorKind::UnsupportedToken,
                        offset,
                        format!("token class {code} is not part of the grammar"),
                    )),
                }
            };
            match node {
                Ok(node) => stack
                    .last_mut()
                    .expect("the body loop holds an element")
                    .children
                    .push(node),
                Err(err) => return (self.close_all(stack, err.offset), Some(err)),
            }
        }
    }

    /// Closes every open element at `end`, innermost first, so the tree keeps
    /// what the parse reached. The parse position is left at `end`.
    fn close_all(&mut self, mut stack: Vec<Element>, end: usize) -> Element {
        let mut current: Option<Element> = None;
        while let Some(mut element) = stack.pop() {
            element.end = end;
            if let Some(child) = current.take() {
                element.children.push(Node::Element(child));
            }
            current = Some(element);
        }
        let mut root = current.unwrap_or_default();
        root.end = end;
        self.at = end;
        root
    }

    /// Reads an element's token payload, up to and including its attributes,
    /// into `element` and leaves it open. Whatever was read stays in `element`
    /// when this fails, so a caller can keep a partially read element.
    fn element_head(
        &mut self,
        token: u16,
        token_offset: usize,
        depth: usize,
        element: &mut Element,
    ) -> Result<(), Error> {
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
        if self.elements >= self.limits.max_elements {
            return Err(Error::new(
                ErrorKind::Limit,
                token_offset,
                format!(
                    "the payload holds more than {} elements",
                    self.limits.max_elements
                ),
            ));
        }
        self.elements += 1;
        element.offset = token_offset;
        element.index = self.name_of(token, token_offset)?;
        let reserved_offset = self.at;
        element.reserved = self.u32("element reserved word")?;
        if element.reserved != 0 {
            self.diagnostics.push(Diagnostic {
                offset: reserved_offset,
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
            let value = self.value(token, offset)?;
            element.attributes.push(Attribute {
                offset,
                index: name_index(token),
                value,
            });
        }
        Ok(())
    }

    /// A text node: `u16 0xFFFD`, `u32` length, then bytes.
    fn text_node(&mut self) -> Result<Text, Error> {
        let offset = self.at - 2;
        let len_at = self.at;
        let len = self.u32("text length")?;
        let declared = usize::try_from(len).map_err(|_| {
            Error::new(
                ErrorKind::Limit,
                len_at,
                "the text length does not fit in memory",
            )
        })?;
        self.check_len(declared, "text node", len_at)?;
        let keep = self.keep(declared);
        let bytes = self.take(declared, "text node")?;
        self.diagnose_text(bytes, offset, TextKind::StringValue);
        Ok(Text {
            offset,
            declared,
            bytes: if keep { bytes.to_vec() } else { Vec::new() },
        })
    }

    /// Reads a value token's optional name and then its value bytes.
    fn value(&mut self, token: u16, offset: usize) -> Result<Value, Error> {
        let code = type_code(token);
        self.name_of(token, offset)?;
        match code {
            1 | 4 => {
                let bytes = self.take(self.number_len, "number value")?.to_vec();
                Ok(Value::Number { code, bytes })
            }
            2 | 3 => Ok(Value::Zero { code }),
            5 => {
                let bytes = self.take(12, "twelve-byte value")?;
                let mut fixed = [0u8; 12];
                fixed.copy_from_slice(bytes);
                Ok(Value::Fixed { code, bytes: fixed })
            }
            6 => {
                let len_at = self.at;
                let declared = usize::from(self.u16("value length")?);
                self.check_len(declared, "length-prefixed value", len_at)?;
                let keep = self.keep(declared);
                let bytes = self.take(declared, "length-prefixed value")?;
                self.diagnose_text(bytes, offset, TextKind::AttributeValue);
                Ok(Value::Bytes {
                    code,
                    bytes: if keep { bytes.to_vec() } else { Vec::new() },
                    declared,
                })
            }
            _ => Err(Error::new(
                ErrorKind::UnsupportedToken,
                offset,
                format!("token class {code} is not part of the grammar"),
            )),
        }
    }

    /// Records what is anomalous about a text value without stopping the
    /// parse.
    ///
    /// A name is length-prefixed and a type-6 value is length-prefixed, so
    /// neither carries a terminator. A text node ends with one NUL that is not
    /// part of the value. A NUL anywhere else, or bytes that are not UTF-8, is
    /// noted and kept as it is.
    fn diagnose_text(&mut self, bytes: &[u8], offset: usize, kind: TextKind) {
        let problem = |message: &'static str| Diagnostic { offset, message };
        let (body, terminated) = match bytes.strip_suffix(&[0]) {
            Some(body) => (body, true),
            None => (bytes, false),
        };
        if !terminated && kind == TextKind::StringValue {
            self.diagnostics
                .push(problem("the text value does not end with a NUL"));
        }
        // The terminator a text node carries is the only NUL a value may end
        // with, so it is removed before the body is checked.
        let body = if kind == TextKind::StringValue {
            body
        } else {
            bytes
        };
        if body.contains(&0) {
            self.diagnostics.push(problem(match kind {
                TextKind::FieldName => "the field name contains a NUL",
                _ => "the value contains a NUL",
            }));
        }
        if std::str::from_utf8(body).is_err() {
            self.diagnostics.push(problem(match kind {
                TextKind::FieldName => "the field name is not valid UTF-8",
                _ => "the text value is not valid UTF-8",
            }));
        }
    }

    /// Reads the name of a token: its `u16` length and bytes when the index
    /// equals the current table length, or nothing when it reuses a name.
    fn name_of(&mut self, token: u16, token_offset: usize) -> Result<u16, Error> {
        let index = name_index(token);
        let defined = self.names.len();
        if usize::from(index) < defined {
            return Ok(index);
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
        self.check_len(name_len, "name", name_offset)?;
        // A name is kept whichever way, so its index stays addressable; the
        // budget refuses the document rather than the name.
        if !self.keep(name_len) {
            return Err(Error::new(
                ErrorKind::Limit,
                name_offset,
                format!(
                    "the payload keeps more than {} name, text and value bytes",
                    self.limits.max_text
                ),
            ));
        }
        let name = self.take(name_len, "name")?;
        let digest: [u8; 32] = Sha256::digest(name).into();
        self.diagnose_text(name, name_offset, TextKind::FieldName);
        let text = std::str::from_utf8(name).map(str::to_string).ok();
        self.names.push(text);
        self.definitions.push(Definition {
            index,
            offset: name_offset,
            name_len,
            name_digest: digest,
        });
        Ok(index)
    }
}

#[cfg(test)]
mod tests;
