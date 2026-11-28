//! The document an RBF0 payload holds, as a tree.
//!
//! The grammar is in [`super`]; this module is the shape the parser fills. It
//! keeps the document as the bytes describe it: nested elements in document
//! order, each with its own name index, its counted attributes and its body.
//! Nothing here interprets a value. A number keeps the bytes it stored, a
//! zero-byte value keeps its token class, and a length-prefixed value keeps
//! its bytes, so a reader can tell two documents apart without the decoder
//! guessing what either means.
//!
//! Names and text are payload text. The tree keeps the bytes so a caller can
//! hash them or show them; it never invents a name for a value.

/// One element of the document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Element {
    /// The 12-bit name index of the element's token.
    pub index: u16,
    /// Offset of the element's token.
    pub offset: usize,
    /// The `u32` after the name. Zero in every observed element.
    pub reserved: u32,
    /// The attributes the element's own count declares, in order.
    pub attributes: Vec<Attribute>,
    /// The body, in document order.
    pub children: Vec<Node>,
    /// Offset just past the element's `0xFFFF` terminator, or where the parse
    /// stopped when the element has none.
    pub end: usize,
    /// Whether the element's terminator was read.
    pub terminated: bool,
}

impl Element {
    /// The body children that are elements.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            _ => None,
        })
    }

    /// The body children that are values.
    pub fn fields(&self) -> impl Iterator<Item = &Field> {
        self.children.iter().filter_map(|node| match node {
            Node::Field(field) => Some(field),
            _ => None,
        })
    }

    /// The body children that are text nodes.
    pub fn texts(&self) -> impl Iterator<Item = &Text> {
        self.children.iter().filter_map(|node| match node {
            Node::Text(text) => Some(text),
            _ => None,
        })
    }

    /// The first attribute whose name index is `index`, when the element has
    /// one.
    pub fn attribute(&self, index: u16) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|attribute| attribute.index == index)
    }

    /// The body elements whose name index is `index`.
    pub fn elements_named(&self, index: u16) -> impl Iterator<Item = &Element> {
        self.elements()
            .filter(move |element| element.index == index)
    }
}

/// One node of a body, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A nested element.
    Element(Element),
    /// A value token in a body position.
    Field(Field),
    /// A text node.
    Text(Text),
}

impl Node {
    /// `element`, `field` or `text`.
    pub fn kind(&self) -> &'static str {
        match self {
            Node::Element(_) => "element",
            Node::Field(_) => "field",
            Node::Text(_) => "text",
        }
    }
}

/// A value token in a body position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Offset of the value's token.
    pub offset: usize,
    /// The 12-bit name index of the token.
    pub index: u16,
    pub value: Value,
}

/// An attribute: a value token in the element's counted prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Offset of the attribute's token.
    pub offset: usize,
    /// The 12-bit name index of the token.
    pub index: u16,
    pub value: Value,
}

/// A value, with the bytes it stored and no interpretation of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Type codes 1 and 4: a number whose width the header variant decides.
    Number {
        code: u8,
        /// Four bytes in a versionless document, eight in a versioned one.
        bytes: Vec<u8>,
    },
    /// Type codes 2 and 3: a token that stores no bytes at all.
    Zero { code: u8 },
    /// Type code 5: twelve bytes, meaning unestablished.
    Fixed { code: u8, bytes: [u8; 12] },
    /// Type code 6: a `u16` byte length and then those bytes.
    Bytes {
        code: u8,
        bytes: Vec<u8>,
        /// The declared length, which exceeds `bytes.len()` only when a read
        /// limit stopped the bytes being kept.
        declared: usize,
    },
}

impl Value {
    /// The token's type code.
    pub fn code(&self) -> u8 {
        match self {
            Value::Number { code, .. }
            | Value::Zero { code }
            | Value::Fixed { code, .. }
            | Value::Bytes { code, .. } => *code,
        }
    }

    /// `number`, `zero`, `fixed` or `bytes`.
    pub fn kind(&self) -> &'static str {
        match self {
            Value::Number { .. } => "number",
            Value::Zero { .. } => "zero",
            Value::Fixed { .. } => "fixed",
            Value::Bytes { .. } => "bytes",
        }
    }

    /// The bytes the value stored, when it stored any.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Value::Number { bytes, .. } | Value::Bytes { bytes, .. } => bytes,
            Value::Fixed { bytes, .. } => bytes,
            Value::Zero { .. } => &[],
        }
    }

    /// The length-prefixed bytes as text and whether a trailing NUL was found.
    ///
    /// A length-prefixed value carries no terminator — none of the 110,051
    /// observed values ends with one — so a NUL it ends with is part of the
    /// value and the second field is always `false`. `None` for every other
    /// value form, for bytes that are not UTF-8, and for bytes a read limit
    /// stopped keeping.
    pub fn text(&self) -> Option<(&str, bool)> {
        let Value::Bytes {
            bytes, declared, ..
        } = self
        else {
            return None;
        };
        if bytes.len() < *declared {
            return None;
        }
        std::str::from_utf8(bytes).ok().map(|text| (text, false))
    }

    /// The integer a type-1 token stores, read as signed, little-endian.
    ///
    /// The class is established by the population: of 30,663 class-1 values,
    /// 30,655 read as an `i32`-ranged integer, while the same bytes as a double
    /// are denormal noise. **Signedness is not established**: the bits are the
    /// fact, and [`Value::unsigned`] gives the other reading. `None` for any
    /// other class, and for a width that is neither four nor eight bytes.
    pub fn integer(&self) -> Option<i64> {
        match self {
            Value::Number { code: 1, bytes } => match bytes.len() {
                4 => Some(i64::from(i32::from_le_bytes(
                    bytes.as_slice().try_into().ok()?,
                ))),
                8 => Some(i64::from_le_bytes(bytes.as_slice().try_into().ok()?)),
                _ => None,
            },
            _ => None,
        }
    }

    /// The unsigned reading of a type-1 token, little-endian. Signedness is not
    /// established, so both readings are offered and neither is the truth.
    pub fn unsigned(&self) -> Option<u64> {
        match self {
            Value::Number { code: 1, bytes } => match bytes.len() {
                4 => Some(u64::from(u32::from_le_bytes(
                    bytes.as_slice().try_into().ok()?,
                ))),
                8 => Some(u64::from_le_bytes(bytes.as_slice().try_into().ok()?)),
                _ => None,
            },
            _ => None,
        }
    }

    /// The double a type-4 token stores, IEEE-754, little-endian.
    ///
    /// The class is established by the population: all 39,291 class-4 values
    /// are finite doubles in the range -431,602,080 to 65,536, and the same
    /// bytes as an integer are nonsense. The same value appears both ways: `1`
    /// is `01 00 00 00 00 00 00 00` as class 1 and `00 00 00 00 00 00 F0 3F` as
    /// class 4. The reading is returned as it is, so a malformed or synthetic
    /// document can yield a non-finite one. `None` for any other class, and
    /// for a width that is neither four nor eight bytes.
    pub fn float(&self) -> Option<f64> {
        match self {
            Value::Number { code: 4, bytes } => match bytes.len() {
                4 => Some(f64::from(f32::from_bits(u32::from_le_bytes(
                    bytes.as_slice().try_into().ok()?,
                )))),
                8 => Some(f64::from_bits(u64::from_le_bytes(
                    bytes.as_slice().try_into().ok()?,
                ))),
                _ => None,
            },
            _ => None,
        }
    }
}

/// A text node: `u16 0xFFFD`, a `u32` byte length, then those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    /// Offset of the node's token.
    pub offset: usize,
    /// The declared byte length.
    pub declared: usize,
    /// The bytes, empty when a read limit stopped them being kept.
    pub bytes: Vec<u8>,
}

impl Text {
    /// The text without one trailing NUL, and whether that NUL was there.
    /// `None` when the bytes are not UTF-8, and when a read limit stopped
    /// them being kept.
    pub fn text(&self) -> Option<(&str, bool)> {
        terminated_text(&self.bytes, self.declared)
    }
}

/// Splits one trailing NUL from `bytes` and decodes the rest as UTF-8.
fn terminated_text(bytes: &[u8], declared: usize) -> Option<(&str, bool)> {
    if bytes.len() < declared {
        return None;
    }
    let (body, terminated) = match bytes.strip_suffix(&[0]) {
        Some(body) => (body, true),
        None => (bytes, false),
    };
    std::str::from_utf8(body)
        .ok()
        .map(|text| (text, terminated))
}

/// The document a payload holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub header: super::Header,
    /// The name table, in the order the document defined the names. `None` is
    /// a name whose bytes are not UTF-8: the definition keeps its length and
    /// digest, and nothing is invented in its place.
    pub names: Vec<Option<String>>,
    /// Where each name was defined.
    pub definitions: Vec<super::Definition>,
    /// The root element.
    pub root: Element,
    /// Why the parse stopped, when it did not reach the end of the root.
    pub failure: Option<super::Error>,
    /// Bytes after the root element, when the payload carries any.
    pub trailing: usize,
    /// What did not add up and did not stop the parse.
    pub diagnostics: Vec<super::Diagnostic>,
    /// Offset of the root element's token.
    pub body_offset: usize,
    /// End of the root element, or where the parse stopped.
    pub end: usize,
}

impl Document {
    /// Whether the root element ended the payload.
    pub fn complete(&self) -> bool {
        self.failure.is_none() && self.trailing == 0
    }

    /// `decoded`, `partial` or `failed`.
    ///
    /// A decoded document ended with its root element. A partial one is whole
    /// but the payload carries bytes after it. A failed one stopped early, and
    /// `failure` says where.
    pub fn status(&self) -> &'static str {
        match (self.failure.is_some(), self.trailing) {
            (false, 0) => "decoded",
            (false, _) => "partial",
            (true, _) => "failed",
        }
    }

    /// The name a token's index refers to, when the document defines it and
    /// its bytes are UTF-8.
    pub fn name(&self, index: u16) -> Option<&str> {
        self.names
            .get(usize::from(index))
            .and_then(Option::as_deref)
    }

    /// The root element's name, when it defines one.
    pub fn root_name(&self) -> Option<&str> {
        self.name(self.root.index)
    }

    /// Whether the payload held a root element at all.
    ///
    /// A payload that stops before its first element token produced no tree,
    /// and a count of zero is the honest answer. An element that was started
    /// always carries an offset it ended at.
    pub fn root_started(&self) -> bool {
        self.root.end != 0 || self.root.terminated
    }

    /// Elements in the document, the root included.
    pub fn elements(&self) -> usize {
        fn count(element: &Element) -> usize {
            1 + element.elements().map(count).sum::<usize>()
        }
        if !self.root_started() {
            return 0;
        }
        count(&self.root)
    }

    /// Element nesting, the root being depth 0.
    pub fn depth(&self) -> usize {
        fn depth(element: &Element) -> usize {
            element
                .elements()
                .map(depth)
                .max()
                .map_or(0, |inner| inner + 1)
        }
        depth(&self.root)
    }

    /// Every element in document order, the root first.
    pub fn walk(&self) -> Vec<&Element> {
        fn push<'a>(element: &'a Element, out: &mut Vec<&'a Element>) {
            out.push(element);
            for child in element.elements() {
                push(child, out);
            }
        }
        let mut out = Vec::new();
        if self.root_started() {
            push(&self.root, &mut out);
        }
        out
    }
}
