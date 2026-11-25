//! Synthetic RBF0 payloads. None of these bytes come from the game.

use super::*;
use std::sync::atomic::AtomicBool;

fn u16v(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn u32v(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// One token word: `name_index | type_code << 12`.
fn token(code: u8, index: u16) -> Vec<u8> {
    u16v(u16::from(code) << TYPE_SHIFT | index)
}

/// A name definition: `u16` length and bytes.
fn named(name: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(name.len() as u16);
    bytes.extend_from_slice(name);
    bytes
}

fn versioned(body: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&u16v(HEADER_MARKER));
    bytes.extend_from_slice(&u16v(VERSION));
    bytes.extend_from_slice(body);
    bytes
}

fn versionless(body: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(body);
    bytes
}

/// An element: its type-0 token, optional name, reserved word, attribute
/// count, attributes, body and terminator.
fn element(index: u16, name: Option<&[u8]>, attributes: &[Vec<u8>], body: &[u8]) -> Vec<u8> {
    let mut bytes = token(0, index);
    if let Some(name) = name {
        bytes.extend_from_slice(&named(name));
    }
    bytes.extend_from_slice(&u32v(0));
    bytes.extend_from_slice(&u16v(attributes.len() as u16));
    for attribute in attributes {
        bytes.extend_from_slice(attribute);
    }
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(&u16v(TERMINATOR));
    bytes
}

/// A value token, its optional name and its value bytes.
fn value(code: u8, index: u16, name: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
    let mut bytes = token(code, index);
    if let Some(name) = name {
        bytes.extend_from_slice(&named(name));
    }
    bytes.extend_from_slice(payload);
    bytes
}

/// A text node.
fn text(value: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(TEXT_TOKEN);
    bytes.extend_from_slice(&u32v(value.len() as u32));
    bytes.extend_from_slice(value);
    bytes
}

/// A type-6 value payload: `u16` length and bytes.
fn prefixed(value: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(value.len() as u16);
    bytes.extend_from_slice(value);
    bytes
}

/// A document that uses every supported form: a root element with one
/// attribute, a text node, both number widths, both zero-byte values, the
/// twelve-byte value, a nested element, a reused name and a type-6 value.
fn sample() -> Vec<u8> {
    let mut child_body = value(4, 2, None, &[1; VERSIONED_NUMBER_LEN]);
    child_body.extend_from_slice(&text(b"y"));
    let child = element(5, Some(b"child"), &[], &child_body);

    let mut root_body = text(b"x");
    root_body.extend_from_slice(&value(1, 2, Some(b"num"), &[2; VERSIONED_NUMBER_LEN]));
    root_body.extend_from_slice(&value(2, 3, Some(b"flag"), &[]));
    root_body.extend_from_slice(&value(5, 4, Some(b"vec"), &[3; 12]));
    root_body.extend_from_slice(&child);
    root_body.extend_from_slice(&value(6, 6, Some(b"data"), &prefixed(b"hi")));

    let attribute = value(6, 1, Some(b"kind"), &prefixed(b"item"));
    let root = element(0, Some(b"doc"), &[attribute], &root_body);
    versioned(&root)
}

fn parse(bytes: &[u8]) -> Result<Document, Error> {
    parse_with(bytes, &Limits::default())
}

fn parse_with(bytes: &[u8], limits: &Limits) -> Result<Document, Error> {
    super::parse(bytes, limits, &AtomicBool::new(false))
}

#[test]
fn parses_every_token_form() {
    let bytes = sample();
    let document = parse(&bytes).expect("a valid document");
    assert!(document.header.versioned);
    assert_eq!(document.header.version, Some(VERSION));
    assert_eq!(document.header.number_len(), VERSIONED_NUMBER_LEN);
    assert_eq!(document.header.body_offset(), 8);
    assert_eq!(document.body_offset, 8);
    assert_eq!(document.end, bytes.len());
    assert_eq!(document.names, 7);
    assert_eq!(document.objects, 2);
    assert_eq!(document.depth, 1);
    // Four body values in the root plus the reused value in the child.
    assert_eq!(document.fields, 5);
    assert_eq!(document.attributes, 1);
    assert_eq!(document.text_nodes, 2);
    assert_eq!(document.types[1], 1);
    assert_eq!(document.types[2], 1);
    assert_eq!(document.types[4], 1);
    assert_eq!(document.types[5], 1);
    assert_eq!(document.types[6], 2);
    assert!(
        document.diagnostics.is_empty(),
        "{:?}",
        document.diagnostics
    );
    assert_eq!(
        document.root_name_digest,
        <[u8; 32]>::from(Sha256::digest(b"doc"))
    );
}

#[test]
fn keeps_the_name_table_in_first_definition_order() {
    let document = parse(&sample()).unwrap();
    let indices: Vec<u16> = document
        .definitions
        .iter()
        .map(|definition| definition.index)
        .collect();
    assert_eq!(indices, [0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        document.field_names,
        ["doc", "kind", "num", "flag", "vec", "child", "data"]
    );
    assert_eq!(document.names, document.definitions.len());
    assert_eq!(document.attribute_texts, ["item", "hi"]);
    assert_eq!(document.string_texts, ["x", "y"]);
    assert_eq!(document.strings.count, 2);
    assert_eq!(document.strings.bytes, 2);
}

#[test]
fn parses_the_versionless_header_with_four_byte_numbers() {
    let mut body = element(
        0,
        Some(b"r"),
        &[],
        &value(1, 1, Some(b"n"), &[0xAA; VERSIONLESS_NUMBER_LEN]),
    );
    body.extend_from_slice(&[]);
    let bytes = versionless(&body);
    let document = parse(&bytes).unwrap();
    assert!(!document.header.versioned);
    assert_eq!(document.header.version, None);
    assert_eq!(document.header.number_len(), VERSIONLESS_NUMBER_LEN);
    assert_eq!(document.body_offset, 4);
    assert_eq!(document.objects, 1);
    assert_eq!(document.fields, 1);
    assert_eq!(document.end, bytes.len());
}

#[test]
fn requires_the_payload_to_end_with_the_root_element() {
    let mut bytes = sample();
    bytes.push(0);
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Trailing);
    assert_eq!(err.offset, bytes.len() - 1);
}

#[test]
fn rejects_an_unknown_token_class() {
    let mut body = element(0, Some(b"r"), &[], &[]);
    // Drop the root terminator and insert an unsupported type-7 token.
    body.truncate(body.len() - 2);
    body.extend_from_slice(&token(7, 0));
    body.extend_from_slice(&u16v(TERMINATOR));
    let err = parse(&versioned(&body)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedToken);
    assert!(err.message.contains('7'), "{}", err.message);
}

#[test]
fn rejects_a_name_index_beyond_the_table() {
    let body = element(
        0,
        Some(b"r"),
        &[],
        &value(1, 4, None, &[0; VERSIONED_NUMBER_LEN]),
    );
    let err = parse(&versioned(&body)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::NameIndex);
}

#[test]
fn rejects_a_truncated_name_or_value() {
    let mut body = element(0, Some(b"r"), &[], &[]);
    let len = body.len();
    body.truncate(len - 2);
    let err = parse(&versioned(&body)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unterminated);
    assert_eq!(err.offset, 8 + len - 2);

    // A name that declares more bytes than remain.
    let mut body = token(0, 0);
    body.extend_from_slice(&u16v(0x20));
    let err = parse(&versioned(&body)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::TooShort);

    // A text node whose length overruns the payload.
    let mut body = element(0, Some(b"r"), &[], &[]);
    body.truncate(body.len() - 2);
    body.extend_from_slice(&u16v(TEXT_TOKEN));
    body.extend_from_slice(&u32v(0x100));
    let err = parse(&versioned(&body)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::TooShort);
}

#[test]
fn rejects_an_element_token_in_an_attribute_position() {
    let attribute = element(1, Some(b"bad"), &[], &[]);
    let body = element(0, Some(b"r"), &[attribute], &[]);
    let err = parse(&versioned(&body)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Structure);
    assert!(err.message.contains("attribute position"));
}

#[test]
fn enforces_depth_element_name_and_length_limits() {
    let nested = element(
        1,
        Some(b"inner"),
        &[],
        &value(1, 2, Some(b"n"), &[0; VERSIONED_NUMBER_LEN]),
    );
    let body = element(0, Some(b"r"), &[], &nested);
    let bytes = versioned(&body);

    let limits = Limits {
        max_depth: 0,
        ..Limits::default()
    };
    assert_eq!(
        parse_with(&bytes, &limits).unwrap_err().kind,
        ErrorKind::Limit
    );

    let limits = Limits {
        max_elements: 1,
        ..Limits::default()
    };
    assert_eq!(
        parse_with(&bytes, &limits).unwrap_err().kind,
        ErrorKind::Limit
    );

    let limits = Limits {
        max_names: 2,
        ..Limits::default()
    };
    assert_eq!(
        parse_with(&bytes, &limits).unwrap_err().kind,
        ErrorKind::Limit
    );

    let mut body = element(
        0,
        Some(b"r"),
        &[],
        &value(6, 1, Some(b"d"), &prefixed(b"long")),
    );
    body.truncate(body.len());
    let limits = Limits {
        max_value_len: 2,
        ..Limits::default()
    };
    let err = parse_with(&versioned(&body), &limits).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Limit);
}

#[test]
fn caps_copied_text_without_failing_the_parse() {
    let body = element(0, Some(b"r"), &[], &text(b"0123456789"));
    let limits = Limits {
        max_text: 4,
        ..Limits::default()
    };
    let document = parse_with(&versioned(&body), &limits).unwrap();
    assert_eq!(document.text_nodes, 1);
    assert_eq!(document.strings.bytes, 10);
    assert!(document.string_texts.is_empty());
}

#[test]
fn reports_non_zero_reserved_words_and_invalid_utf8_without_failing() {
    let mut body = token(0, 0);
    body.extend_from_slice(&named(b"r"));
    body.extend_from_slice(&u32v(1));
    body.extend_from_slice(&u16v(0));
    body.extend_from_slice(&text(&[0xFF, 0xFE]));
    body.extend_from_slice(&u16v(TERMINATOR));
    let document = parse(&versioned(&body)).unwrap();
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("reserved word"))
    );
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("UTF-8"))
    );
    assert!(document.string_texts.is_empty());
}

#[test]
fn rejects_an_unobserved_version() {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&u16v(HEADER_MARKER));
    bytes.extend_from_slice(&u16v(2));
    bytes.extend_from_slice(&element(0, Some(b"r"), &[], &[]));
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::UnsupportedVersion);
}

#[test]
fn rejects_a_short_or_foreign_payload() {
    assert_eq!(parse(b"RBF").unwrap_err().kind, ErrorKind::NotRbf0);
    assert_eq!(parse(b"RBF0").unwrap_err().kind, ErrorKind::TooShort);
    assert_eq!(parse(&MAGIC).unwrap_err().kind, ErrorKind::TooShort);
    // The versioned marker without its version word.
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&u16v(HEADER_MARKER));
    assert_eq!(parse(&bytes).unwrap_err().kind, ErrorKind::TooShort);
}

#[test]
fn stops_when_cancelled() {
    let engine = AtomicBool::new(true);
    let err = super::parse(&sample(), &Limits::default(), &engine).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
}
