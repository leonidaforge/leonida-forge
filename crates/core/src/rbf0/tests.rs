//! Synthetic RBF0 payloads and the two views of one of them. None of these
//! bytes come from the game.

use lforge_rage9::rbf0;

use super::{counts, document_json, document_xml};

fn u16v(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn u32v(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn token(code: u8, index: u16) -> Vec<u8> {
    u16v(u16::from(code) << 12 | index)
}

fn named(name: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(name.len() as u16);
    bytes.extend_from_slice(name);
    bytes
}

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
    bytes.extend_from_slice(&u16v(0xFFFF));
    bytes
}

fn value(code: u8, index: u16, name: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
    let mut bytes = token(code, index);
    if let Some(name) = name {
        bytes.extend_from_slice(&named(name));
    }
    bytes.extend_from_slice(payload);
    bytes
}

fn text(value: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(0xFFFD);
    bytes.extend_from_slice(&u32v(value.len() as u32 + 1));
    bytes.extend_from_slice(value);
    bytes.push(0);
    bytes
}

fn prefixed(value: &[u8]) -> Vec<u8> {
    let mut bytes = u16v(value.len() as u16);
    bytes.extend_from_slice(value);
    bytes
}

/// A versioned document: `screen` with a `kind` attribute, a text node, an
/// integer, a double, a nested `row` element and a non-UTF-8 value.
fn sample() -> Vec<u8> {
    let mut body = text(b"a <tag> & more");
    body.extend_from_slice(&value(1, 2, Some(b"count"), &7_i64.to_le_bytes()));
    body.extend_from_slice(&value(4, 3, Some(b"size"), &12.5_f64.to_le_bytes()));
    body.extend_from_slice(&element(
        4,
        Some(b"row"),
        &[],
        &value(4, 5, Some(b"width"), &64.0_f64.to_le_bytes()),
    ));
    body.extend_from_slice(&value(6, 6, Some(b"raw"), &prefixed(&[0xFF, 0xFE])));
    let attribute = value(6, 1, Some(b"kind"), &prefixed(b"uiScreen"));
    let root = element(0, Some(b"screen"), &[attribute], &body);
    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&u16v(0xFFFB));
    bytes.extend_from_slice(&u16v(1));
    bytes.extend_from_slice(&root);
    bytes
}

fn decode(bytes: &[u8]) -> rbf0::Document {
    rbf0::decode(
        bytes,
        &rbf0::Limits::default(),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .expect("a readable payload")
}

#[test]
fn counts_the_document_shape() {
    let document = decode(&sample());
    let counts = counts(&document);
    assert_eq!(counts.names, 7);
    assert_eq!(counts.elements, 2);
    assert_eq!(counts.depth, 1);
    assert_eq!(counts.fields, 4);
    assert_eq!(counts.attributes, 1);
    assert_eq!(counts.text_nodes, 1);
    assert_eq!(counts.values_by_type[1], 1);
    assert_eq!(counts.values_by_type[4], 2);
    assert_eq!(counts.values_by_type[6], 2);
    assert_eq!(counts.trailing, 0);
}

#[test]
fn json_keeps_names_values_and_order() {
    let document = decode(&sample());
    let json = document_json(&document);
    assert_eq!(json["format"], "rbf0");
    assert_eq!(json["status"], "decoded");
    assert_eq!(json["header"]["versioned"], true);
    assert_eq!(json["header"]["numberLen"], 8);
    assert_eq!(json["root"]["name"], "screen");
    assert_eq!(json["root"]["attributes"][0]["name"], "kind");
    assert_eq!(json["root"]["attributes"][0]["value"]["text"], "uiScreen");

    let children = json["root"]["children"].as_array().expect("a body");
    let kinds: Vec<&str> = children
        .iter()
        .map(|child| child["kind"].as_str().expect("a kind"))
        .collect();
    assert_eq!(kinds, ["text", "field", "field", "element", "field"]);

    // A text node loses the NUL it ends with and says it was there.
    assert_eq!(children[0]["text"], "a <tag> & more");
    assert_eq!(children[0]["terminated"], true);
    // The two number classes keep their bytes and their own reading.
    assert_eq!(children[1]["value"]["integer"], 7);
    assert!(children[1]["value"].get("float").is_none());
    assert_eq!(children[2]["value"]["float"], 12.5);
    assert!(children[2]["value"].get("integer").is_none());
    // A nested element keeps its own name and body.
    assert_eq!(children[3]["name"], "row");
    assert_eq!(children[3]["children"][0]["name"], "width");
    // Bytes that are not UTF-8 are reported as hex, not as lossy text.
    assert_eq!(children[4]["value"]["bytes"], "FFFE");
    assert!(children[4]["value"].get("text").is_none());
}

#[test]
fn json_reports_every_name_it_defined() {
    let document = decode(&sample());
    let json = document_json(&document);
    let names: Vec<&str> = json["names"]
        .as_array()
        .expect("a name table")
        .iter()
        .map(|entry| entry["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        ["screen", "kind", "count", "size", "row", "width", "raw"]
    );
}

#[test]
fn xml_is_generated_and_keeps_the_names_as_attributes() {
    let document = decode(&sample());
    let source = [
        ("archive", "data.rpf".to_string()),
        ("row", "41".to_string()),
    ];
    let xml = document_xml(&document, &source);
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
    assert!(xml.contains(r#"<rbf0 generator="leonida-forge" format="rbf0" status="decoded""#));
    assert!(xml.contains(r#"<source archive="data.rpf" row="41"/>"#));
    assert!(xml.contains(r#"<element index="0" name="screen""#));
    assert!(xml.contains(r#"<attribute index="1" name="kind""#));
    assert!(xml.contains(r#"<value kind="bytes" class="6" declared="8">uiScreen</value>"#));
    // Text is escaped rather than written raw.
    assert!(xml.contains("a &lt;tag&gt; &amp; more"));
    // The integer and the double each carry their own reading.
    assert!(xml.contains(r#"kind="number" class="1""#));
    assert!(xml.contains(r#"integer="7""#));
    assert!(xml.contains(r#"float="12.5""#));
    assert!(xml.trim_end().ends_with("</rbf0>"));
}

#[test]
fn xml_marks_a_document_that_did_not_reach_its_end() {
    let mut bytes = sample();
    // Cut the root terminator: the parse keeps the tree and says where it
    // stopped.
    bytes.truncate(bytes.len() - 1);
    let document = decode(&bytes);
    assert_eq!(document.status(), "failed");
    let xml = document_xml(&document, &[]);
    assert!(xml.contains(r#"status="failed""#));
    assert!(xml.contains("<failure kind="));
    let json = document_json(&document);
    assert_eq!(json["status"], "failed");
    assert_eq!(json["failure"]["kind"], "Unterminated");
    assert_eq!(json["failure"]["stage"], "structure");
    assert!(xml.contains(r#"stage="structure""#));
}

fn decode_with(bytes: &[u8], limits: &rbf0::Limits) -> rbf0::Document {
    rbf0::decode(bytes, limits, &std::sync::atomic::AtomicBool::new(false))
        .expect("a readable payload")
}

/// A versioned header around one root element.
fn versioned(root: &[u8]) -> Vec<u8> {
    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&u16v(0xFFFB));
    bytes.extend_from_slice(&u16v(1));
    bytes.extend_from_slice(root);
    bytes
}

#[test]
fn an_integer_past_two_to_the_53_keeps_its_exact_digits() {
    // Beyond 2^53 - 1 a JSON number no longer survives a reader that holds
    // numbers as doubles, so the digits are carried beside it as text.
    let large = i64::MAX;
    let mut body = value(1, 1, Some(b"count"), &large.to_le_bytes());
    body.extend_from_slice(&value(1, 2, Some(b"small"), &7_i64.to_le_bytes()));
    let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
    let json = document_json(&document);
    let children = json["root"]["children"].as_array().expect("a body");
    assert_eq!(children[0]["value"]["integerText"], "9223372036854775807");
    assert_eq!(children[0]["value"]["integer"], large);
    assert!(
        children[1]["value"].get("integerText").is_none(),
        "a readable number needs no second spelling"
    );
    let xml = document_xml(&document, &[]);
    assert!(xml.contains(r#"integerText="9223372036854775807""#));
}

#[test]
fn a_negative_integer_keeps_both_readings() {
    // The class establishes 64 bits; it does not establish signedness, so the
    // two's-complement reading is given too.
    let body = value(1, 1, Some(b"count"), &(-1_i64).to_le_bytes());
    let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
    let json = document_json(&document);
    let value = &json["root"]["children"][0]["value"];
    assert_eq!(value["integer"], -1);
    assert_eq!(value["unsigned"], u64::MAX);
    assert!(
        value.get("integerText").is_none(),
        "a readable number needs no second spelling"
    );
    assert!(xml_attr(&document, "unsigned"), "the XML carries it too");
}

fn xml_attr(document: &rbf0::Document, attribute: &str) -> bool {
    document_xml(document, &[]).contains(&format!("{attribute}=\"{}\"", u64::MAX))
}

#[test]
fn a_double_json_cannot_hold_is_named_rather_than_silently_null() {
    for (bits, spelling) in [
        (f64::NAN, "NaN"),
        (f64::INFINITY, "Infinity"),
        (f64::NEG_INFINITY, "-Infinity"),
    ] {
        let mut body = value(4, 1, Some(b"size"), &bits.to_le_bytes());
        body.extend_from_slice(&value(4, 2, Some(b"ok"), &12.5_f64.to_le_bytes()));
        let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
        let json = document_json(&document);
        let children = json["root"]["children"].as_array().expect("a body");
        assert_eq!(children[0]["value"]["float"], serde_json::Value::Null);
        assert_eq!(children[0]["value"]["floatText"], spelling);
        // The bit pattern stays the fact.
        assert_eq!(
            children[0]["value"]["bytes"].as_str().map(str::len),
            Some(16)
        );
        // A finite double is unaffected.
        assert_eq!(children[1]["value"]["float"], 12.5);
        assert!(children[1]["value"].get("floatText").is_none());

        let xml = document_xml(&document, &[]);
        assert!(xml.contains(&format!("floatText=\"{spelling}\"")));
        assert!(xml.contains(r#"float="12.5""#));
    }
}

#[test]
fn bytes_a_read_limit_dropped_do_not_look_empty() {
    // The names fit in the budget, the value does not, so the value keeps its
    // declared length and no bytes. That must be visible.
    let mut body = value(6, 1, Some(b"d"), &prefixed(b"0123456789abcdef"));
    body.extend_from_slice(&text(b"0123456789abcdef"));
    let bytes = versioned(&element(0, Some(b"r"), &[], &body));
    let limits = rbf0::Limits {
        max_text: 4,
        ..rbf0::Limits::default()
    };
    let document = decode_with(&bytes, &limits);
    assert!(document.complete(), "a budget is not a parse failure");
    let json = document_json(&document);
    let children = json["root"]["children"].as_array().expect("a body");
    assert_eq!(children[0]["value"]["omitted"], true);
    assert_eq!(children[0]["value"]["declared"], 16);
    assert!(
        children[0]["value"].get("bytes").is_none(),
        "a dropped value is not a value of no bytes"
    );
    assert_eq!(children[1]["kind"], "text");
    assert_eq!(children[1]["omitted"], true);
    assert_eq!(children[1]["declared"], 17);
    let xml = document_xml(&document, &[]);
    assert_eq!(xml.matches(r#"omitted="true""#).count(), 2);
}

#[test]
fn xml_writes_a_control_character_as_a_visible_escape() {
    // A C0 control other than tab, line feed and carriage return cannot appear
    // in XML 1.0 at all, so it must not be written raw.
    let body = text(b"a\x01b");
    let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
    let xml = document_xml(&document, &[]);
    assert!(xml.contains("a\\x01b"), "{xml}");
    assert!(!xml.contains('\u{1}'), "the raw control must not be there");
}

#[test]
fn xml_says_when_a_document_left_bytes_unread() {
    let mut bytes = sample();
    bytes.extend_from_slice(&[0; 3]);
    let document = decode(&bytes);
    assert_eq!(document.status(), "partial");
    let xml = document_xml(&document, &[]);
    assert!(xml.contains(r#"status="partial""#));
    assert!(xml.contains(r#"trailing="3""#));
    let json = document_json(&document);
    assert_eq!(json["status"], "partial");
    assert_eq!(json["counts"]["trailing"], 3);
}

#[test]
fn a_name_that_is_not_utf8_is_null_not_empty() {
    // 0xFF 0xFE is not UTF-8. An empty string would claim a name of no
    // characters.
    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&u16v(0xFFFB));
    bytes.extend_from_slice(&u16v(1));
    let root = element(0, Some(&[0xFF, 0xFE]), &[], &[]);
    bytes.extend_from_slice(&root);
    let document = decode(&bytes);
    let json = document_json(&document);
    assert_eq!(json["names"][0]["name"], serde_json::Value::Null);
    assert_eq!(json["names"][0]["length"], 2);
    assert_eq!(json["root"]["name"], serde_json::Value::Null);
}

#[test]
fn a_document_with_no_root_is_written_as_null() {
    // The header parsed and nothing else did, so there is no root to describe.
    let document = decode(&versioned(&[]));
    assert_eq!(document.status(), "failed");
    let json = document_json(&document);
    assert_eq!(json["root"], serde_json::Value::Null);
    assert_eq!(json["counts"]["elements"], 0);
    let xml = document_xml(&document, &[]);
    assert!(!xml.contains("<element"), "no element was read");
    assert!(xml.contains(r#"elements="0""#));
}

#[test]
fn xml_writes_a_code_point_xml_forbids_as_an_escape() {
    // U+FFFF is well-formed UTF-8 and outside the XML Char production.
    let body = text("a\u{FFFF}b".as_bytes());
    let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
    let xml = document_xml(&document, &[]);
    assert!(xml.contains("a\\uFFFFb"), "{xml}");
    assert!(
        !xml.contains('\u{FFFF}'),
        "the raw code point must not be there"
    );
}

#[test]
fn text_keeps_a_nul_a_length_prefixed_value_ends_with() {
    let body = value(6, 1, Some(b"d"), &prefixed(b"a\0"));
    let document = decode(&versioned(&element(0, Some(b"r"), &[], &body)));
    let json = document_json(&document);
    let value = &json["root"]["children"][0]["value"];
    assert_eq!(value["text"], "a\u{0}");
    assert!(
        value.get("terminated").is_none(),
        "a length-prefixed value has no terminator to report"
    );
}
