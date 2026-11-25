//! Synthetic RBF0 payloads. None of these bytes come from the game.

use super::*;
use std::sync::atomic::AtomicBool;

fn u16v(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn u32v(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn named(name: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(name.len() as u16);
    bytes.extend_from_slice(name);
    bytes
}

fn string_value(value: &[u8]) -> Vec<u8> {
    let mut bytes = u32v(0);
    bytes.extend_from_slice(&u16v(0));
    bytes.extend_from_slice(&u16v(STRING_VALUE_TAG));
    bytes.extend_from_slice(&u32v(value.len() as u32));
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(&u16v(TERMINATOR));
    bytes
}

fn attribute(field_id: u16, name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(field_id);
    bytes.extend_from_slice(&named(name));
    bytes.extend_from_slice(&u16v(value.len() as u16));
    bytes.extend_from_slice(value);
    bytes
}

fn object(attribute_count: u16, attributes: &[u8], fields: &[u8]) -> Vec<u8> {
    let mut bytes = u32v(0);
    bytes.extend_from_slice(&u16v(attribute_count));
    bytes.extend_from_slice(attributes);
    bytes.extend_from_slice(fields);
    bytes.extend_from_slice(&u16v(TERMINATOR));
    bytes
}

fn header(root_name: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(&u16v(HEADER_MARKER));
    bytes.extend_from_slice(&u32v(HEADER_VALUE));
    bytes.extend_from_slice(&named(root_name));
    bytes
}

/// A document with five objects, one attribute, one string and one fixed
/// eight-byte value.
fn sample() -> Vec<u8> {
    let mut inner_fields = u16v(0x0004);
    inner_fields.extend_from_slice(&named(b"text"));
    inner_fields.extend_from_slice(&string_value(b"x\0"));
    inner_fields.extend_from_slice(&u16v(FIXED8_FIELD));
    inner_fields.extend_from_slice(&named(b"number"));
    inner_fields.extend_from_slice(&[0xFF; FIXED8_LEN]);
    let inner = object(0, &[], &inner_fields);
    let empty = object(0, &[], &[]);

    let mut first_fields = u16v(0x0002);
    first_fields.extend_from_slice(&inner);
    first_fields.extend_from_slice(&u16v(0x0002));
    first_fields.extend_from_slice(&empty);
    let first = object(1, &attribute(0x6003, b"kind", b"item"), &first_fields);

    let mut container_fields = u16v(0x0002);
    container_fields.extend_from_slice(&named(b"item"));
    container_fields.extend_from_slice(&first);
    let container = object(0, &[], &container_fields);

    let mut root_fields = u16v(0x0001);
    root_fields.extend_from_slice(&named(b"list"));
    root_fields.extend_from_slice(&container);
    let root = object(0, &[], &root_fields);

    let mut bytes = header(b"doc");
    bytes.extend_from_slice(&root);
    bytes
}

fn parse(bytes: &[u8]) -> Result<Document, Error> {
    parse_with(bytes, &Limits::default())
}

fn parse_with(bytes: &[u8], limits: &Limits) -> Result<Document, Error> {
    super::parse(bytes, limits, &AtomicBool::new(false))
}

#[test]
fn parses_the_verified_grammar() {
    let bytes = sample();
    let document = parse(&bytes).expect("a valid document");
    assert_eq!(document.header.word, HEADER_MARKER);
    assert_eq!(document.header.flags, HEADER_VALUE);
    assert_eq!(document.header.root_name_len, 3);
    assert_eq!(document.body_offset, PREFIX_LEN + 3);
    assert_eq!(document.end, bytes.len());
    assert_eq!(document.objects, 5);
    assert_eq!(document.depth, 3);
    assert_eq!(document.fields, 6);
    assert_eq!(document.object_fields, 4);
    assert_eq!(document.string_fields, 1);
    assert_eq!(document.fixed8_fields, 1);
    assert_eq!(document.attributes, 1);
    assert!(
        document.diagnostics.is_empty(),
        "{:?}",
        document.diagnostics
    );
}

#[test]
fn keeps_the_field_dictionary_in_first_definition_order() {
    let document = parse(&sample()).unwrap();
    let ids: Vec<u16> = document
        .definitions
        .iter()
        .map(|definition| definition.field_id)
        .collect();
    assert_eq!(ids, [0x0001, 0x0002, 0x6003, 0x0004, FIXED8_FIELD]);
    let classes: Vec<&str> = ids
        .iter()
        .map(|id| FieldClass::of(*id).unwrap().name())
        .collect();
    assert_eq!(
        classes,
        ["object", "object", "attribute", "string", "fixed8"]
    );
    assert_eq!(
        document.field_names,
        ["list", "item", "kind", "text", "number"]
    );
    assert_eq!(document.attribute_texts, ["item"]);
    assert_eq!(document.string_texts, ["x"]);
}

#[test]
fn reports_text_lengths_without_the_terminator() {
    let document = parse(&sample()).unwrap();
    assert_eq!(document.strings.count, 1);
    // The declared length includes the NUL.
    assert_eq!(document.strings.bytes, 2);
    assert_eq!(document.strings.min_len, 2);
    assert_eq!(document.strings.max_len, 2);
    assert_eq!(document.attribute_values.count, 1);
    assert_eq!(document.attribute_values.bytes, 4);
}

#[test]
fn the_root_name_is_digested_not_kept() {
    let document = parse(&sample()).unwrap();
    let expected: [u8; 32] = Sha256::digest(b"doc").into();
    assert_eq!(document.root_name_digest, expected);
}

#[test]
fn rejects_other_magics_and_short_prefixes() {
    assert_eq!(
        Header::parse(b"RBFX\0\0\0\0\0\0\0\0").unwrap_err().kind,
        ErrorKind::NotRbf0
    );
    assert_eq!(
        Header::parse(b"RBF0\0\0").unwrap_err().kind,
        ErrorKind::TooShort
    );
    assert_eq!(Header::parse(&[]).unwrap_err().kind, ErrorKind::NotRbf0);
    assert!(!is_rbf0(b"RB"));
    assert_eq!(parse(b"RBF0").unwrap_err().kind, ErrorKind::TooShort);
}

#[test]
fn rejects_an_unknown_header_marker() {
    let mut bytes = sample();
    bytes[4..6].copy_from_slice(&0xFFF0u16.to_le_bytes());
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsupportedVersion);
    assert_eq!(error.offset, 4);
    assert!(error.message.contains("0xFFF0"), "{}", error.message);
}

#[test]
fn reports_a_different_header_value_without_rejecting_it() {
    let mut bytes = sample();
    bytes[6..10].copy_from_slice(&2u32.to_le_bytes());
    let document = parse(&bytes).expect("the header value is not a version gate");
    assert_eq!(document.header.flags, 2);
    assert_eq!(document.diagnostics.len(), 1);
    assert_eq!(document.diagnostics[0].offset, 6);
}

#[test]
fn reports_a_non_zero_object_reserved_word_without_rejecting_it() {
    let mut bytes = header(b"doc");
    let mut fields = u16v(0x0001);
    fields.extend_from_slice(&named(b"child"));
    fields.extend_from_slice(&object(0, &[], &[]));
    let mut root = u32v(1);
    root.extend_from_slice(&u16v(0));
    root.extend_from_slice(&fields);
    root.extend_from_slice(&u16v(TERMINATOR));
    bytes.extend_from_slice(&root);

    let document = parse(&bytes).expect("a reserved word does not change the grammar");
    assert_eq!(document.objects, 2);
    assert_eq!(document.diagnostics.len(), 1);
    assert_eq!(document.diagnostics[0].offset, PREFIX_LEN + 3);
}

#[test]
fn rejects_an_identifier_outside_the_observed_sets() {
    for field_id in [0x0003u16, 0x000B, 0x1007, 0x5FFF, 0x6005] {
        let mut bytes = header(b"doc");
        let mut fields = u16v(field_id);
        fields.extend_from_slice(&named(b"text"));
        fields.extend_from_slice(&string_value(b"x\0"));
        bytes.extend_from_slice(&object(0, &[], &fields));
        let error = parse(&bytes).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Structure, "{field_id:#06X}");
        assert!(
            error
                .message
                .contains("outside the observed identifier sets"),
            "{}",
            error.message
        );
    }
}

#[test]
fn rejects_an_unsupported_value_tag() {
    let mut bytes = sample();
    let at = bytes
        .windows(2)
        .position(|pair| pair == u16v(STRING_VALUE_TAG))
        .expect("the string value tag");
    bytes[at..at + 2].copy_from_slice(&0xFFFEu16.to_le_bytes());
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Structure);
    assert_eq!(error.offset, at);
    assert!(error.message.contains("0xFFFE"), "{}", error.message);
}

#[test]
fn rejects_an_attribute_identifier_in_the_field_stream() {
    let mut bytes = header(b"doc");
    let mut fields = u16v(0x6003);
    fields.extend_from_slice(&named(b"kind"));
    fields.extend_from_slice(&u16v(3));
    fields.extend_from_slice(b"abc");
    bytes.extend_from_slice(&object(0, &[], &fields));
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Structure);
    assert!(
        error.message.contains("attribute position is unresolved"),
        "{}",
        error.message
    );
}

#[test]
fn rejects_a_non_attribute_identifier_in_the_attribute_stream() {
    let mut bytes = header(b"doc");
    let mut attributes = u16v(0x0004);
    attributes.extend_from_slice(&named(b"kind"));
    attributes.extend_from_slice(&u16v(3));
    attributes.extend_from_slice(b"abc");
    bytes.extend_from_slice(&object(1, &attributes, &[]));
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Structure);
    assert!(
        error.message.contains("carries string values"),
        "{}",
        error.message
    );
}

#[test]
fn rejects_a_truncated_payload() {
    let bytes = sample();
    for cut in 1..=4 {
        let error = parse(&bytes[..bytes.len() - cut]).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::TooShort | ErrorKind::Structure),
            "{cut}: {error}"
        );
    }
}

#[test]
fn rejects_bytes_after_the_root_object() {
    let mut bytes = sample();
    bytes.push(0);
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Structure);
    assert!(
        error.message.contains("follow the root object"),
        "{}",
        error.message
    );
}

#[test]
fn rejects_an_object_without_a_terminator() {
    let mut bytes = header(b"doc");
    bytes.extend_from_slice(&u32v(0));
    bytes.extend_from_slice(&u16v(0));
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Structure);
    assert!(error.message.contains("no terminator"), "{}", error.message);
}

#[test]
fn rejects_an_attribute_count_larger_than_the_payload() {
    let mut bytes = header(b"doc");
    bytes.extend_from_slice(&u32v(0));
    bytes.extend_from_slice(&u16v(1000));
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Structure);
    assert!(
        error.message.contains("1000 attributes"),
        "{}",
        error.message
    );
}

#[test]
fn rejects_a_string_value_not_closed_by_the_terminator() {
    let mut bytes = header(b"doc");
    let mut fields = u16v(0x0004);
    fields.extend_from_slice(&named(b"text"));
    fields.extend_from_slice(&string_value(b"x\0"));
    bytes.extend_from_slice(&object(0, &[], &fields));
    // The payload ends with the value terminator, then the object terminator.
    let value_terminator = bytes.len() - 4;
    bytes[value_terminator..value_terminator + 2].copy_from_slice(&u16v(0));
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Structure);
    assert!(error.message.contains("not closed"), "{}", error.message);
}

#[test]
fn reports_a_string_value_without_a_nul_without_rejecting_it() {
    let mut bytes = header(b"doc");
    let mut fields = u16v(0x0004);
    fields.extend_from_slice(&named(b"text"));
    fields.extend_from_slice(&string_value(b"plain"));
    bytes.extend_from_slice(&object(0, &[], &fields));
    let document = parse(&bytes).expect("the value is still a string");
    assert_eq!(document.string_texts, ["plain"]);
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("NUL"))
    );
}

#[test]
fn reports_text_that_is_not_utf8() {
    let mut bytes = header(b"doc");
    let mut fields = u16v(0x0004);
    fields.extend_from_slice(&named(b"text"));
    fields.extend_from_slice(&string_value(&[0xFF, 0xFE, 0x00]));
    bytes.extend_from_slice(&object(0, &[], &fields));
    let document = parse(&bytes).expect("the value fits the grammar");
    assert!(document.string_texts.is_empty());
    assert!(
        document
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("UTF-8"))
    );
}

#[test]
fn rejects_a_declared_value_above_the_limit() {
    let mut bytes = header(b"doc");
    let mut fields = u16v(0x0004);
    fields.extend_from_slice(&named(b"text"));
    fields.extend_from_slice(&u32v(0));
    fields.extend_from_slice(&u16v(0));
    fields.extend_from_slice(&u16v(STRING_VALUE_TAG));
    fields.extend_from_slice(&u32v(u32::MAX));
    bytes.extend_from_slice(&object(0, &[], &fields));
    let limits = Limits {
        max_value_len: 1024,
        ..Limits::default()
    };
    let error = parse_with(&bytes, &limits).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Limit);
}

#[test]
fn rejects_object_nesting_above_the_limit() {
    // The outermost field defines the identifier; every nested object reuses
    // it without a name, one object value per level.
    let mut nested = object(0, &[], &[]);
    for _ in 1..8 {
        let mut inner = u16v(0x0001);
        inner.extend_from_slice(&nested);
        nested = object(0, &[], &inner);
    }
    let mut fields = u16v(0x0001);
    fields.extend_from_slice(&named(b"child"));
    fields.extend_from_slice(&nested);
    let mut bytes = header(b"doc");
    bytes.extend_from_slice(&object(0, &[], &fields));
    let limits = Limits {
        max_depth: 3,
        ..Limits::default()
    };
    let error = parse_with(&bytes, &limits).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Limit);
    assert!(error.message.contains("nest deeper"), "{}", error.message);
}

#[test]
fn rejects_more_definitions_than_the_limit() {
    let mut fields = u16v(0x0004);
    fields.extend_from_slice(&named(b"text"));
    fields.extend_from_slice(&string_value(b"v\0"));
    let mut bytes = header(b"doc");
    bytes.extend_from_slice(&object(0, &[], &fields));
    let limits = Limits {
        max_definitions: 0,
        ..Limits::default()
    };
    let error = parse_with(&bytes, &limits).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Limit);
    assert!(
        error.message.contains("defines more than"),
        "{}",
        error.message
    );
}

#[test]
fn a_cancelled_parse_stops_at_the_next_step() {
    let bytes = sample();
    let cancel = AtomicBool::new(true);
    let error = super::parse(&bytes, &Limits::default(), &cancel).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Cancelled);
}

#[test]
fn text_above_the_limit_is_not_kept() {
    let mut bytes = header(b"doc");
    let mut fields = u16v(0x0004);
    fields.extend_from_slice(&named(b"text"));
    fields.extend_from_slice(&string_value(b"abcdef\0"));
    bytes.extend_from_slice(&object(0, &[], &fields));
    let limits = Limits {
        max_text: 2,
        ..Limits::default()
    };
    let document = parse_with(&bytes, &limits).expect("the grammar still holds");
    assert!(document.string_texts.is_empty());
    assert_eq!(document.strings.count, 1);
}

#[test]
fn field_class_maps_only_observed_identifiers() {
    assert_eq!(FieldClass::of(0x0001), Some(FieldClass::Object));
    assert_eq!(FieldClass::of(0x0002), Some(FieldClass::Object));
    assert_eq!(FieldClass::of(0x0004), Some(FieldClass::String));
    assert_eq!(FieldClass::of(0x000A), Some(FieldClass::String));
    assert_eq!(FieldClass::of(0x000B), None);
    assert_eq!(FieldClass::of(FIXED8_FIELD), Some(FieldClass::Fixed8));
    assert_eq!(FieldClass::of(0x6003), Some(FieldClass::Attribute));
    assert_eq!(FieldClass::of(0x6004), Some(FieldClass::Attribute));
    assert_eq!(FieldClass::of(0x6005), None);
}
