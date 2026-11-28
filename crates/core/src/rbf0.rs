//! JSON and XML views of a decoded `RBF0` metadata document.
//!
//! Both views carry the same facts as the decoded document: every element in
//! document order, its name, its counted attributes and its body, with the
//! bytes each value stored. Nothing is interpreted beyond the two readings the
//! population establishes: a type-1 number is a 64-bit integer and a type-4
//! number is an IEEE-754 double. A length-prefixed value and a text node keep
//! their bytes, and report the text only when they are UTF-8.
//!
//! The XML view is generated, and says so: its root element is `rbf0` with a
//! `generator` attribute, so a generated document is never mistaken for a
//! textual resource the game ships. Element names are attributes rather than
//! tag names, because a name is payload text and need not be a valid XML name.

use lforge_rage9::rbf0::{Document, Element, Node, Value};
use serde_json::{Value as Json, json};

/// What the document holds, for a summary line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub names: usize,
    pub elements: usize,
    pub depth: usize,
    pub fields: usize,
    pub attributes: usize,
    pub text_nodes: usize,
    pub values_by_type: [usize; 7],
    pub trailing: usize,
    pub diagnostics: usize,
}

/// Counts the facts a summary can state.
pub fn counts(document: &Document) -> Counts {
    let mut counts = Counts {
        names: document.names.len(),
        elements: document.elements(),
        depth: document.depth(),
        trailing: document.trailing,
        diagnostics: document.diagnostics.len(),
        ..Counts::default()
    };
    for element in document.walk() {
        counts.attributes += element.attributes.len();
        for attribute in &element.attributes {
            counts.values_by_type[usize::from(attribute.value.code().min(6))] += 1;
        }
        for node in &element.children {
            match node {
                Node::Element(_) => {}
                Node::Field(field) => {
                    counts.fields += 1;
                    counts.values_by_type[usize::from(field.value.code().min(6))] += 1;
                }
                Node::Text(_) => counts.text_nodes += 1,
            }
        }
    }
    counts
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// The largest integer a consumer that holds JSON numbers as doubles can read
/// exactly (2^53 - 1). Past it, the digits of a JSON number do not survive the
/// round trip, so the exact decimal is carried beside it.
const SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The spelling of a double JSON cannot hold.
fn non_finite(value: f64) -> &'static str {
    if value.is_nan() {
        "NaN"
    } else if value.is_sign_negative() {
        "-Infinity"
    } else {
        "Infinity"
    }
}

/// The note a value carries when its bytes were not kept.
const OMITTED: &str = "the bytes were not kept: the document's kept-bytes budget ran out";

fn header_json(document: &Document) -> Json {
    json!({
        "versioned": document.header.versioned,
        "version": document.header.version,
        "numberLen": document.header.number_len(),
        "bodyOffset": document.body_offset,
    })
}

/// A value, as the bytes it stored and the readings its class establishes.
fn value_json(value: &Value) -> Json {
    let code = value.code();
    match value {
        Value::Number { .. } => {
            let mut document = json!({
                "kind": "number",
                "class": code,
                "bytes": bytes_hex(value.bytes()),
            });
            // Class 1 is an integer; its signedness is not established, so both
            // readings are given and the bytes stay the fact.
            if let Some(integer) = value.integer() {
                document["integer"] = json!(integer);
                if let Some(unsigned) = value.unsigned() {
                    document["unsigned"] = json!(unsigned);
                }
                if integer.unsigned_abs() > SAFE_INTEGER {
                    document["integerText"] = json!(integer.to_string());
                }
            }
            if let Some(float) = value.float() {
                if float.is_finite() {
                    document["float"] = json!(float);
                } else {
                    // JSON has no NaN and no infinities. The bytes keep the
                    // exact bit pattern; the spelling says what it is.
                    document["float"] = Json::Null;
                    document["floatText"] = json!(non_finite(float));
                }
            }
            document
        }
        Value::Zero { .. } => json!({ "kind": "zero", "class": code }),
        Value::Fixed { .. } => json!({
            "kind": "fixed",
            "class": code,
            "bytes": bytes_hex(value.bytes()),
        }),
        Value::Bytes { declared, .. } => {
            let mut document = json!({
                "kind": "bytes",
                "class": code,
                "declared": declared,
            });
            // An empty value and a value whose bytes were dropped by a read
            // limit must not look the same.
            if value.bytes().len() < *declared {
                document["omitted"] = json!(true);
                document["note"] = json!(OMITTED);
                return document;
            }
            match value.text() {
                Some((text, terminated)) => {
                    document["text"] = json!(text);
                    if terminated {
                        document["terminated"] = json!(true);
                    }
                }
                None => document["bytes"] = json!(bytes_hex(value.bytes())),
            }
            document
        }
    }
}

fn text_json(node: &lforge_rage9::rbf0::Text) -> Json {
    let mut document = json!({
        "kind": "text",
        "declared": node.declared,
    });
    if node.bytes.len() < node.declared {
        document["omitted"] = json!(true);
        document["note"] = json!(OMITTED);
        return document;
    }
    match node.text() {
        Some((text, terminated)) => {
            document["text"] = json!(text);
            document["terminated"] = json!(terminated);
        }
        None => document["bytes"] = json!(bytes_hex(&node.bytes)),
    }
    document
}

fn element_json(document: &Document, element: &Element) -> Json {
    let children: Vec<Json> = element
        .children
        .iter()
        .map(|node| match node {
            Node::Element(child) => {
                let mut value = element_json(document, child);
                value["kind"] = json!("element");
                value
            }
            Node::Field(field) => json!({
                "kind": "field",
                "name": document.name(field.index),
                "index": field.index,
                "offset": field.offset,
                "value": value_json(&field.value),
            }),
            Node::Text(text) => {
                let mut value = text_json(text);
                value["offset"] = json!(text.offset);
                value
            }
        })
        .collect();
    json!({
        "name": document.name(element.index),
        "index": element.index,
        "offset": element.offset,
        "end": element.end,
        "reserved": element.reserved,
        "terminated": element.terminated,
        "attributes": element.attributes.iter().map(|attribute| json!({
            "name": document.name(attribute.index),
            "index": attribute.index,
            "offset": attribute.offset,
            "value": value_json(&attribute.value),
        })).collect::<Vec<Json>>(),
        "children": children,
    })
}

/// The decoded document as a JSON document.
pub fn document_json(document: &Document) -> Json {
    let counts = counts(document);
    let names: Vec<Json> = document
        .names
        .iter()
        .zip(&document.definitions)
        .map(|(name, definition)| {
            json!({
                "index": definition.index,
                "name": name,
                "offset": definition.offset,
                "length": definition.name_len,
                "sha256": bytes_hex(&definition.name_digest),
            })
        })
        .collect();
    let notes: Vec<Json> = document
        .diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "severity": "note",
                "offset": diagnostic.offset,
                "message": diagnostic.message,
            })
        })
        .collect();
    // A payload that stopped before its first element token has no root, and
    // an object with offset 0 would claim one.
    let root = if document.root_started() {
        let mut root = element_json(document, &document.root);
        root["kind"] = json!("element");
        root
    } else {
        Json::Null
    };
    let mut value = json!({
        "format": "rbf0",
        "status": document.status(),
        "header": header_json(document),
        "counts": {
            "names": counts.names,
            "elements": counts.elements,
            "depth": counts.depth,
            "fields": counts.fields,
            "attributes": counts.attributes,
            "textNodes": counts.text_nodes,
            "valuesByType": counts.values_by_type.iter().enumerate().map(|(code, count)| {
                json!({ "class": code, "count": count })
            }).collect::<Vec<Json>>(),
            "trailing": counts.trailing,
        },
        "names": names,
        "root": root,
        "notes": notes,
        "limitations": [
            "a name is payload text, kept as the document stores it",
            "a type-1 number reads as a 64-bit integer and a type-4 number as an IEEE-754 double; no field meaning is claimed",
            "a type-2 and type-3 value store no bytes, so their meaning is unknown",
            "a type-5 value stores twelve bytes whose meaning is not established",
            "token classes 7 to 14 were not observed and stop the parse with their offset",
        ],
    });
    if let Some(failure) = &document.failure {
        value["failure"] = json!({
            "kind": format!("{:?}", failure.kind),
            "stage": failure.kind.stage(),
            "offset": failure.offset,
            "message": failure.message,
        });
    }
    value
}

/// Escapes text for XML.
///
/// The five markup characters become entities. A C0 control other than tab,
/// line feed and carriage return cannot appear in XML 1.0 at all, so it is
/// written as a visible `\xNN` rather than left to make the document
/// ill-formed.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(character),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\x{:02X}", control as u32));
            }
            // U+FFFE and U+FFFF are well-formed UTF-8 and are not XML `Char`
            // productions, so they are written as an escape too.
            noncharacter if matches!(noncharacter as u32, 0xFFFE | 0xFFFF) => {
                out.push_str(&format!("\\u{:04X}", noncharacter as u32));
            }
            other => out.push(other),
        }
    }
    out
}

fn attribute(out: &mut String, name: &str, value: impl std::fmt::Display) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    out.push_str(&escape(&value.to_string()));
    out.push('"');
}

fn open(out: &mut String, tag: &str, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
    out.push('<');
    out.push_str(tag);
}

fn close(out: &mut String, tag: &str, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
    out.push_str("</");
    out.push_str(tag);
    out.push_str(">\n");
}

fn value_xml(out: &mut String, tag: &str, value: &Value, depth: usize) {
    open(out, tag, depth);
    attribute(out, "kind", value.kind());
    attribute(out, "class", value.code());
    match value {
        Value::Number { .. } => {
            attribute(out, "bytes", bytes_hex(value.bytes()));
            if let Some(integer) = value.integer() {
                attribute(out, "integer", integer);
                if let Some(unsigned) = value.unsigned() {
                    attribute(out, "unsigned", unsigned);
                }
                if integer.unsigned_abs() > SAFE_INTEGER {
                    attribute(out, "integerText", integer);
                }
            }
            if let Some(float) = value.float() {
                if float.is_finite() {
                    attribute(out, "float", float);
                } else {
                    attribute(out, "floatText", non_finite(float));
                }
            }
            out.push_str("/>\n");
        }
        Value::Zero { .. } => out.push_str("/>\n"),
        Value::Fixed { .. } => {
            attribute(out, "bytes", bytes_hex(value.bytes()));
            out.push_str("/>\n");
        }
        Value::Bytes { declared, .. } => {
            attribute(out, "declared", declared);
            if value.bytes().len() < *declared {
                attribute(out, "omitted", true);
                out.push_str("/>\n");
                return;
            }
            match value.text() {
                Some((text, terminated)) => {
                    if terminated {
                        attribute(out, "terminated", true);
                    }
                    out.push('>');
                    out.push_str(&escape(text));
                    out.push_str("</");
                    out.push_str(tag);
                    out.push_str(">\n");
                }
                None => {
                    attribute(out, "bytes", bytes_hex(value.bytes()));
                    out.push_str("/>\n");
                }
            }
        }
    }
}

fn text_xml(out: &mut String, node: &lforge_rage9::rbf0::Text, depth: usize) {
    open(out, "text", depth);
    attribute(out, "offset", node.offset);
    attribute(out, "declared", node.declared);
    if node.bytes.len() < node.declared {
        attribute(out, "omitted", true);
        out.push_str("/>\n");
        return;
    }
    match node.text() {
        Some((text, terminated)) => {
            attribute(out, "terminated", terminated);
            out.push('>');
            out.push_str(&escape(text));
            out.push_str("</text>\n");
        }
        None => {
            attribute(out, "bytes", bytes_hex(&node.bytes));
            out.push_str("/>\n");
        }
    }
}

fn element_xml(out: &mut String, document: &Document, element: &Element, depth: usize) {
    open(out, "element", depth);
    // The index is the fact; a name resolves it and is written beside it, so
    // two definitions with the same text stay distinguishable.
    attribute(out, "index", element.index);
    if let Some(name) = document.name(element.index) {
        attribute(out, "name", name);
    }
    attribute(out, "offset", element.offset);
    attribute(out, "end", element.end);
    if !element.terminated {
        attribute(out, "terminated", false);
    }
    if element.reserved != 0 {
        attribute(out, "reserved", element.reserved);
    }
    if element.attributes.is_empty() && element.children.is_empty() {
        out.push_str("/>\n");
        return;
    }
    out.push_str(">\n");
    for item in &element.attributes {
        open(out, "attribute", depth + 1);
        attribute(out, "index", item.index);
        if let Some(name) = document.name(item.index) {
            attribute(out, "name", name);
        }
        attribute(out, "offset", item.offset);
        out.push_str(">\n");
        value_xml(out, "value", &item.value, depth + 2);
        close(out, "attribute", depth + 1);
    }
    for node in &element.children {
        match node {
            Node::Element(child) => element_xml(out, document, child, depth + 1),
            Node::Field(field) => {
                open(out, "field", depth + 1);
                attribute(out, "index", field.index);
                if let Some(name) = document.name(field.index) {
                    attribute(out, "name", name);
                }
                attribute(out, "offset", field.offset);
                out.push_str(">\n");
                value_xml(out, "value", &field.value, depth + 2);
                close(out, "field", depth + 1);
            }
            Node::Text(text) => text_xml(out, text, depth + 1),
        }
    }
    close(out, "element", depth);
}

/// The decoded document as an XML document.
///
/// The root element is `rbf0` and carries a `generator` attribute, so a
/// generated document is distinguishable from a textual resource the game
/// ships. `source` becomes a `source` element holding where the bytes came
/// from.
pub fn document_xml(document: &Document, source: &[(&str, String)]) -> String {
    let counts = counts(document);
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    open(&mut out, "rbf0", 0);
    attribute(&mut out, "generator", "leonida-forge");
    attribute(&mut out, "format", "rbf0");
    attribute(&mut out, "status", document.status());
    attribute(&mut out, "versioned", document.header.versioned);
    attribute(&mut out, "names", counts.names);
    attribute(&mut out, "elements", counts.elements);
    attribute(&mut out, "depth", counts.depth);
    attribute(&mut out, "fields", counts.fields);
    attribute(&mut out, "attributes", counts.attributes);
    attribute(&mut out, "textNodes", counts.text_nodes);
    // A payload whose root element is followed by bytes is not fully decoded,
    // and the count says how much was left.
    if counts.trailing != 0 {
        attribute(&mut out, "trailing", counts.trailing);
    }
    out.push_str(">\n");
    if !source.is_empty() {
        open(&mut out, "source", 1);
        for (name, value) in source {
            attribute(&mut out, name, value.clone());
        }
        out.push_str("/>\n");
    }
    // A payload that stopped before its first element token has no root.
    if document.root_started() {
        element_xml(&mut out, document, &document.root, 1);
    }
    for diagnostic in &document.diagnostics {
        open(&mut out, "note", 1);
        attribute(&mut out, "offset", diagnostic.offset);
        attribute(&mut out, "message", diagnostic.message);
        out.push_str("/>\n");
    }
    if let Some(failure) = &document.failure {
        open(&mut out, "failure", 1);
        attribute(&mut out, "kind", format!("{:?}", failure.kind));
        attribute(&mut out, "stage", failure.kind.stage());
        attribute(&mut out, "offset", failure.offset);
        attribute(&mut out, "message", failure.message.clone());
        out.push_str("/>\n");
    }
    close(&mut out, "rbf0", 0);
    out
}

#[cfg(test)]
mod tests;
