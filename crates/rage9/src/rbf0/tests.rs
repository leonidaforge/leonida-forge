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

/// A text node. Its bytes end with the NUL the verified format carries, which
/// is not part of the value.
fn text(value: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(TEXT_TOKEN);
    bytes.extend_from_slice(&u32v(value.len() as u32 + 1));
    bytes.extend_from_slice(value);
    bytes.push(0);
    bytes
}

/// A type-6 value payload: `u16` length and bytes. Its bytes are the value;
/// unlike a text node it carries no terminator.
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

fn parse(bytes: &[u8]) -> Result<Statistics, Error> {
    parse_with(bytes, &Limits::default())
}

fn parse_with(bytes: &[u8], limits: &Limits) -> Result<Statistics, Error> {
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
    // Each text node stores its value and the NUL that ends it.
    assert_eq!(document.strings.bytes, 4);
}

#[test]
fn parses_the_versionless_header_with_four_byte_numbers() {
    let body = element(
        0,
        Some(b"r"),
        &[],
        &value(1, 1, Some(b"n"), &[0xAA; VERSIONLESS_NUMBER_LEN]),
    );
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

    let body = element(
        0,
        Some(b"r"),
        &[],
        &value(6, 1, Some(b"d"), &prefixed(b"long")),
    );
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
    // Ten characters and the NUL that ends them.
    assert_eq!(document.strings.bytes, 11);
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

fn decode(bytes: &[u8]) -> Document {
    super::decode(bytes, &Limits::default(), &AtomicBool::new(false)).expect("a readable payload")
}

#[test]
fn decodes_the_document_tree() {
    let bytes = sample();
    let document = decode(&bytes);
    assert!(document.complete());
    assert_eq!(document.status(), "decoded");
    assert_eq!(document.body_offset, 8);
    assert_eq!(document.end, bytes.len());
    assert_eq!(document.root_name(), Some("doc"));
    assert_eq!(document.elements(), 2);
    assert_eq!(document.depth(), 1);
    assert_eq!(document.names.len(), document.definitions.len());

    let root = &document.root;
    assert!(root.terminated);
    assert_eq!(root.attributes.len(), 1);
    assert_eq!(
        document.name(root.attributes[0].index),
        Some("kind"),
        "the attribute keeps the name it was defined with"
    );
    // A length-prefixed value keeps exactly the bytes its length declares and
    // carries no terminator.
    assert_eq!(root.attributes[0].value.text(), Some(("item", false)));

    let kinds: Vec<&str> = root.children.iter().map(Node::kind).collect();
    assert_eq!(
        kinds,
        ["text", "field", "field", "field", "element", "field"]
    );

    // Text first, then the four value forms in document order.
    assert_eq!(root.texts().next().unwrap().text(), Some(("x", true)));
    let fields: Vec<&Field> = root.fields().collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(document.name(fields[0].index), Some("num"));
    assert_eq!(
        fields[0].value,
        Value::Number {
            code: 1,
            bytes: vec![2; VERSIONED_NUMBER_LEN],
        }
    );
    assert_eq!(fields[1].value, Value::Zero { code: 2 });
    assert_eq!(document.name(fields[2].index), Some("vec"));
    assert_eq!(
        fields[2].value,
        Value::Fixed {
            code: 5,
            bytes: [3; 12],
        }
    );
    assert_eq!(fields[3].value.text(), Some(("hi", false)));

    // The nested element reuses the name its value defined, and keeps its own
    // child in document order.
    let child = root.elements().next().unwrap();
    assert_eq!(document.name(child.index), Some("child"));
    assert_eq!(child.children.len(), 2);
    assert_eq!(child.fields().next().unwrap().value.code(), 4);
}

#[test]
fn decodes_a_versionless_document() {
    let body = element(
        0,
        Some(b"r"),
        &[],
        &value(1, 1, Some(b"n"), &[0xAA; VERSIONLESS_NUMBER_LEN]),
    );
    let document = decode(&versionless(&body));
    assert!(document.complete());
    assert!(!document.header.versioned);
    let number = document.root.fields().next().unwrap();
    assert_eq!(number.value.bytes().len(), VERSIONLESS_NUMBER_LEN);
}

#[test]
fn reports_a_text_value_without_its_nul() {
    let mut unterminated = u16v(TEXT_TOKEN);
    unterminated.extend_from_slice(&u32v(1));
    unterminated.push(b'x');
    let body = element(0, Some(b"r"), &[], &unterminated);
    let document = decode(&versioned(&body));
    assert!(document.complete());
    assert_eq!(
        document.root.texts().next().unwrap().text(),
        Some(("x", false))
    );
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("NUL"))
    );
}

#[test]
fn keeps_what_parsed_when_the_body_stops() {
    let mut body = element(0, Some(b"r"), &[], &text(b"kept"));
    // Drop the root terminator, then put an undefined token class in the body.
    body.truncate(body.len() - 2);
    body.extend_from_slice(&token(9, 0));
    body.extend_from_slice(&u16v(TERMINATOR));
    let document = decode(&versioned(&body));
    assert!(!document.complete());
    assert_eq!(document.status(), "failed");
    let failure = document.failure.expect("the parse stopped");
    assert_eq!(failure.kind, ErrorKind::UnsupportedToken);
    // The text node parsed before the failure is still there, and the element
    // it sits in says it has no terminator.
    assert_eq!(
        document.root.texts().next().unwrap().text(),
        Some(("kept", true))
    );
    assert!(!document.root.terminated);
}

#[test]
fn reports_bytes_after_the_root_as_a_partial_document() {
    let mut bytes = sample();
    bytes.push(0);
    let document = decode(&bytes);
    assert_eq!(document.trailing, 1);
    assert_eq!(document.status(), "partial");
    assert!(!document.complete());
    assert!(document.failure.is_none());
    assert_eq!(
        super::decode_complete(&bytes, &Limits::default(), &AtomicBool::new(false))
            .unwrap_err()
            .kind,
        ErrorKind::Trailing
    );
}

#[test]
fn reports_a_truncated_record_as_a_failure_at_its_offset() {
    // Cut into the last value: its declared length runs past the payload.
    let mut bytes = sample();
    bytes.truncate(bytes.len() - 6);
    let document = decode(&bytes);
    assert_eq!(document.status(), "failed");
    let failure = document.failure.expect("the payload is short");
    assert_eq!(failure.kind, ErrorKind::TooShort);
    assert!(failure.offset <= bytes.len());

    // Cut half of the last terminator: the element never closes.
    let mut bytes = sample();
    bytes.truncate(bytes.len() - 1);
    let document = decode(&bytes);
    let failure = document.failure.expect("the element has no terminator");
    assert_eq!(failure.kind, ErrorKind::Unterminated);
    // The parse stops where the half terminator starts.
    assert_eq!(failure.offset, bytes.len() - 1);
    assert!(
        failure.message.contains("no terminator"),
        "{}",
        failure.message
    );
}

#[test]
fn enforces_nesting_and_name_budgets_on_the_tree() {
    let nested = element(1, Some(b"inner"), &[], &text(b"deep"));
    let body = element(0, Some(b"r"), &[], &nested);
    let bytes = versioned(&body);
    let engine = AtomicBool::new(false);

    let limits = Limits {
        max_depth: 0,
        ..Limits::default()
    };
    let document = super::decode(&bytes, &limits, &engine).unwrap();
    assert!(!document.complete());
    assert_eq!(
        document.failure.expect("depth refused").kind,
        ErrorKind::Limit
    );

    let limits = Limits {
        max_text: 2,
        ..Limits::default()
    };
    let document = super::decode(&bytes, &limits, &engine).unwrap();
    assert_eq!(
        document.failure.expect("name budget refused").kind,
        ErrorKind::Limit
    );
}

#[test]
fn walks_every_element_in_document_order() {
    let document = decode(&sample());
    let names: Vec<Option<&str>> = document
        .walk()
        .iter()
        .map(|element| document.name(element.index))
        .collect();
    assert_eq!(names, [Some("doc"), Some("child")]);
}

#[test]
fn reads_the_two_number_classes_as_an_integer_and_a_double() {
    let mut body = value(1, 1, Some(b"count"), &1_i64.to_le_bytes());
    body.extend_from_slice(&value(4, 2, Some(b"size"), &64.5_f64.to_le_bytes()));
    body.extend_from_slice(&value(4, 3, Some(b"flag"), &1.0_f64.to_le_bytes()));
    let bytes = versioned(&element(0, Some(b"r"), &[], &body));
    let document = decode(&bytes);
    let fields: Vec<&Field> = document.root.fields().collect();
    assert_eq!(fields[0].value.integer(), Some(1));
    assert_eq!(fields[0].value.float(), None);
    assert_eq!(fields[1].value.float(), Some(64.5));
    assert_eq!(fields[1].value.integer(), None);
    // The same eight bytes read as class 4 are a double, not the integer 1.
    assert_eq!(fields[2].value.float(), Some(1.0));
    assert_eq!(
        fields[1].value.bytes(),
        &64.5_f64.to_le_bytes(),
        "the stored bytes stay available"
    );
}

#[test]
fn a_name_that_is_not_utf8_is_absent_rather_than_empty() {
    let mut body = token(0, 0);
    body.extend_from_slice(&u16v(2));
    body.extend_from_slice(&[0xFF, 0xFE]);
    body.extend_from_slice(&u32v(0));
    body.extend_from_slice(&u16v(0));
    body.extend_from_slice(&u16v(TERMINATOR));
    let document = decode(&versioned(&body));
    assert!(document.complete());
    assert_eq!(document.names, vec![None]);
    assert_eq!(document.name(0), None, "an unreadable name is not \"\"");
    // The definition still identifies it.
    assert_eq!(document.definitions.len(), 1);
    assert_eq!(document.definitions[0].name_len, 2);
    assert_eq!(
        document.definitions[0].name_digest,
        <[u8; 32]>::from(Sha256::digest([0xFF, 0xFE]))
    );
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("not valid UTF-8"))
    );
    // The statistics view must not offer "" as a name to hash.
    assert!(statistics(&document).field_names.is_empty());
}

#[test]
fn classes_two_and_three_keep_their_own_code() {
    let mut body = value(2, 1, Some(b"a"), &[]);
    body.extend_from_slice(&value(3, 2, Some(b"b"), &[]));
    let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
    let fields: Vec<&Field> = document.root.fields().collect();
    assert_eq!(fields[0].value, Value::Zero { code: 2 });
    assert_eq!(fields[1].value, Value::Zero { code: 3 });
    assert_eq!(fields[0].value.code(), 2);
    assert_eq!(fields[1].value.code(), 3);
}

#[test]
fn an_element_whose_head_fails_keeps_what_was_read() {
    // A nested element whose attribute position holds an element token: the
    // head (its name) was read, so it stays in the tree.
    let mut inner = token(0, 1);
    inner.extend_from_slice(&named(b"child"));
    inner.extend_from_slice(&u32v(0));
    inner.extend_from_slice(&u16v(1));
    inner.extend_from_slice(&token(0, 0)); // element token in an attribute
    let mut body = element(0, Some(b"root"), &[], &[]);
    body.truncate(body.len() - 2);
    body.extend_from_slice(&inner);
    let document = decode(&versioned(&body));
    let failure = document.failure.clone().expect("the parse stopped");
    assert_eq!(failure.kind, ErrorKind::Structure);
    assert_eq!(document.root.children.len(), 1);
    let child = document.root.elements().next().expect("the partial child");
    assert_eq!(document.name(child.index), Some("child"));
    assert!(!child.terminated);
    assert!(child.attributes.is_empty());
}

#[test]
fn a_truncated_read_reports_where_the_payload_ends() {
    let mut body = element(0, Some(b"r"), &[], &[]);
    body.truncate(body.len() - 2);
    // A value whose declared length runs past the end.
    body.extend_from_slice(&token(6, 1));
    body.extend_from_slice(&named(b"d"));
    body.extend_from_slice(&u16v(16));
    body.extend_from_slice(b"abc");
    let bytes = versioned(&body);
    let document = decode(&bytes);
    let failure = document.failure.expect("the payload is short");
    assert_eq!(failure.kind, ErrorKind::TooShort);
    assert_eq!(failure.offset, bytes.len(), "the offset is where it ended");
    assert!(
        failure.message.contains("16 bytes needed"),
        "{}",
        failure.message
    );
}

#[test]
fn a_payload_that_stops_before_its_root_holds_no_element() {
    // Only the header: the root token was never read, so there is no element
    // to count and no tree to walk.
    let document = decode(&versioned(&[]));
    assert_eq!(document.status(), "failed");
    assert_eq!(
        document.failure.as_ref().expect("the parse stopped").kind,
        ErrorKind::TooShort
    );
    assert!(!document.root_started());
    assert_eq!(document.elements(), 0);
    assert!(document.walk().is_empty());
    assert_eq!(document.depth(), 0);
}

#[test]
fn a_length_prefixed_value_keeps_a_trailing_nul_as_its_own_byte() {
    // A type-6 value carries no terminator, so a NUL it ends with is part of
    // the value and not something to strip.
    let body = value(6, 1, Some(b"d"), &prefixed(b"a\0"));
    let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
    assert!(document.complete());
    let field = document.root.fields().next().expect("one value");
    assert_eq!(field.value.text(), Some(("a\u{0}", false)));
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("NUL"))
    );
}
