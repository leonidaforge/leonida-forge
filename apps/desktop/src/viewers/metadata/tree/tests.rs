//! Row building from a decoded container. No window is needed.

use super::*;

fn names(lines: &str) -> Names {
    Names::from_table(&lforge_rage9::rpf::names::StringTable::parse(
        lines.as_bytes(),
        false,
    ))
}

fn document() -> Document {
    Document {
        structures: vec![lforge_rage9::psin::pso::Structure {
            name: 0x1111_1111,
            signature: 0x2222_2222,
            flags: 0x300,
            size: 8,
            fields: vec![
                Field {
                    name: 0xaaaa_0001,
                    offset: 0,
                    type_word: 0x21u32,
                    auxiliary: 0,
                },
                Field {
                    name: 0xaaaa_0002,
                    offset: 4,
                    type_word: 0x4au32,
                    auxiliary: 0,
                },
            ],
        }],
        enums: Vec::new(),
        blocks: vec![Block {
            index: 1,
            id: 0x1111_1111,
            offset: 64,
            len: 8,
            content: Content::Records {
                structure: 0x1111_1111,
                stride: 8,
                total: 1,
                records: vec![Record {
                    offset: 64,
                    structure: 0x1111_1111,
                    fields: vec![
                        FieldValue {
                            field: Field {
                                name: 0xaaaa_0001,
                                offset: 0,
                                type_word: 0x21u32,
                                auxiliary: 0,
                            },
                            extent: Some(4),
                            value: Value::Scalar(Scalar::F32(1.5)),
                        },
                        FieldValue {
                            field: Field {
                                name: 0xaaaa_0002,
                                offset: 4,
                                type_word: 0x4au32,
                                auxiliary: 0,
                            },
                            extent: Some(4),
                            value: Value::Scalar(Scalar::Hash32(0xdead_beef)),
                        },
                    ],
                }],
            },
        }],
        header: Some(lforge_rage9::psin::pso::Header {
            object_type: 0x7a,
            roots: 1,
            structures: 1,
            enums: 0,
            blocks: 1,
        }),
        issues: Vec::new(),
    }
}

#[test]
fn the_rows_are_a_pre_order_walk() {
    let tree = build(&document(), &Names::empty());
    let labels: Vec<&str> = tree.rows.iter().map(|row| row.label.as_str()).collect();
    assert_eq!(labels[0], "schema");
    assert!(labels[1].starts_with("structure 0x11111111"));
    assert!(labels[2].starts_with("0xAAAA0001"));
    assert!(labels[3].starts_with("0xAAAA0002"));
    assert_eq!(labels[4], "instances");
    assert!(labels[5].starts_with("block 1"));
    assert!(labels[6].starts_with("record 64"));
    assert_eq!(tree.status, "decoded");
    assert!(!tree.truncated);
    let depths: Vec<usize> = tree.rows.iter().map(|row| row.depth).collect();
    assert_eq!(depths, [0, 1, 2, 2, 0, 1, 2, 3, 3]);
}

#[test]
fn collapsing_a_group_hides_the_rows_under_it() {
    let tree = build(&document(), &Names::empty());
    let mut collapsed = HashSet::new();
    let all = tree.visible(&collapsed, "");
    assert_eq!(all.len(), tree.rows.len());
    collapsed.insert(0);
    let shown = tree.visible(&collapsed, "");
    assert_eq!(shown, vec![0, 4, 5, 6, 7, 8]);
    assert_eq!(tree.descendants(0), 3);
}

#[test]
fn a_collapsed_record_hides_its_fields() {
    let tree = build(&document(), &Names::empty());
    let mut collapsed = HashSet::new();
    collapsed.insert(6);
    let shown = tree.visible(&collapsed, "");
    assert_eq!(shown, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(tree.descendants(6), 2);
}

#[test]
fn a_filter_keeps_the_matching_rows_and_their_ancestors() {
    let tree = build(&document(), &Names::empty());
    let shown = tree.visible(&HashSet::new(), "1.5");
    // The record's value row, and the groups, block and record that hold it.
    assert_eq!(shown, vec![4, 5, 6, 7]);
}

#[test]
fn a_filter_reaches_into_a_collapsed_group() {
    let tree = build(&document(), &Names::empty());
    let mut collapsed = HashSet::new();
    collapsed.insert(0);
    assert_eq!(tree.visible(&collapsed, "1.5"), vec![4, 5, 6, 7]);
}

#[test]
fn a_filter_matches_case_insensitively() {
    let tree = build(&document(), &Names::empty());
    assert_eq!(
        tree.visible(&HashSet::new(), "0xdeadbeef").len(),
        tree.visible(&HashSet::new(), "0xDEADBEEF").len()
    );
}

#[test]
fn a_resolved_name_is_shown_beside_the_hash() {
    let hash = lforge_rage9::psin::pso::names::metadata_hash(b"fRainbow");
    let mut document = document();
    // Name the collection's second field with a hash the table reproduces.
    document.structures[0].fields[1].name = hash;
    let Content::Records { records, .. } = &mut document.blocks[0].content else {
        panic!("a structure block");
    };
    records[0].fields[1].field.name = hash;
    records[0].fields[1].value = Value::Scalar(Scalar::Hash32(hash));
    let tree = build(&document, &names("fRainbow\n"));
    let row = tree
        .rows
        .iter()
        .find(|row| row.label.contains(&format!("0x{hash:08X}")) && row.detail.contains("hash32"))
        .expect("the value row");
    assert!(row.label.contains("fRainbow"), "{}", row.label);
    assert_eq!(row.tone, Tone::Accent);
}

#[test]
fn the_parent_of_a_row_is_the_nearest_shallower_one() {
    let tree = build(&document(), &Names::empty());
    assert_eq!(tree.parent(2), Some(1));
    assert_eq!(tree.parent(1), Some(0));
    assert_eq!(tree.parent(0), None);
    assert_eq!(tree.parent(7), Some(6));
}

#[test]
fn an_unsupported_block_is_a_warning() {
    let mut document = document();
    document.blocks[0].content = Content::Unsupported("no structure".into());
    let tree = build(&document, &Names::empty());
    let row = tree
        .rows
        .iter()
        .find(|row| row.label.contains("unsupported"))
        .expect("the block row");
    assert_eq!(row.tone, Tone::Warning);
    assert!(!row.expandable);
}

#[test]
fn an_unresolved_field_keeps_its_bytes_in_the_detail() {
    let mut document = document();
    let Content::Records { records, .. } = &mut document.blocks[0].content else {
        panic!("a structure block");
    };
    records[0].fields[0].value = Value::Unresolved {
        code: 0x9f,
        upper: 0,
        auxiliary: 0,
        raw: vec![0x78, 0x56, 0x34, 0x12],
    };
    let tree = build(&document, &Names::empty());
    let row = tree
        .rows
        .iter()
        .find(|row| row.detail.contains("no established width"))
        .expect("the field row");
    assert!(row.label.starts_with("0xAAAA0001"), "{}", row.label);
    assert!(row.detail.contains("0x009F"), "{}", row.detail);
    assert!(row.detail.contains("78 56 34 12"), "{}", row.detail);
    assert_eq!(row.tone, Tone::Warning);
}

#[test]
fn issues_are_reported_as_rows() {
    let mut document = document();
    document
        .issues
        .push("the alignment padding after block 1 is not zero".to_string());
    let tree = build(&document, &Names::empty());
    assert_eq!(tree.status, "partial");
    assert_eq!(tree.issues.len(), 1);
    assert!(
        tree.rows
            .iter()
            .any(|row| row.label.contains("alignment padding"))
    );
}

/// A synthetic RBF0 payload: `screen` with a `kind` attribute, a text node,
/// an integer field and a nested `row`.
fn rbf0_bytes() -> Vec<u8> {
    fn u16v(value: u16) -> Vec<u8> {
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
    let mut count = token(1, 3);
    count.extend_from_slice(&named(b"count"));
    count.extend_from_slice(&3_i64.to_le_bytes());
    let mut row = token(0, 2);
    row.extend_from_slice(&named(b"row"));
    row.extend_from_slice(&[0; 4]);
    row.extend_from_slice(&u16v(0));
    row.extend_from_slice(&count);
    row.extend_from_slice(&u16v(0xFFFF));
    let mut body = u16v(0xFFFD);
    body.extend_from_slice(&5u32.to_le_bytes());
    body.extend_from_slice(b"note\0");
    body.extend_from_slice(&row);
    let mut attribute = token(6, 1);
    attribute.extend_from_slice(&named(b"kind"));
    attribute.extend_from_slice(&u16v(8));
    attribute.extend_from_slice(b"uiScreen");
    let mut root = token(0, 0);
    root.extend_from_slice(&named(b"screen"));
    root.extend_from_slice(&[0; 4]);
    root.extend_from_slice(&u16v(1));
    root.extend_from_slice(&attribute);
    root.extend_from_slice(&body);
    root.extend_from_slice(&u16v(0xFFFF));
    let mut bytes = b"RBF0".to_vec();
    bytes.extend_from_slice(&u16v(0xFFFB));
    bytes.extend_from_slice(&u16v(1));
    bytes.extend_from_slice(&root);
    bytes
}

fn rbf0_document() -> rbf::Document {
    rbf::decode(
        &rbf0_bytes(),
        &rbf::Limits::default(),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .expect("a readable payload")
}

#[test]
fn an_rbf0_document_shows_elements_attributes_and_values() {
    let tree = build_rbf0(&rbf0_document());
    let labels: Vec<&str> = tree.rows.iter().map(|row| row.label.as_str()).collect();
    assert_eq!(labels[0], "document");
    assert_eq!(labels[1], "screen");
    assert_eq!(labels[2], "@kind");
    assert_eq!(labels[3], "text");
    assert_eq!(labels[4], "row");
    assert_eq!(labels[5], "count");
    assert_eq!(labels[6], "name table");
    assert!(labels[7].starts_with("[0] "));
    assert_eq!(tree.status, "decoded");
    assert!(!tree.truncated);

    let depths: Vec<usize> = tree.rows.iter().map(|row| row.depth).collect();
    assert_eq!(depths, [0, 1, 2, 2, 2, 3, 1, 2, 2, 2, 2]);

    let attribute = tree
        .rows
        .iter()
        .find(|row| row.label == "@kind")
        .expect("the attribute row");
    assert_eq!(attribute.detail, "uiScreen");
    assert_eq!(attribute.tone, Tone::Accent);

    let count = tree
        .rows
        .iter()
        .find(|row| row.label == "count")
        .expect("the field row");
    assert!(count.detail.starts_with('3'), "{}", count.detail);
    assert!(count.detail.contains("integer"), "{}", count.detail);
}

#[test]
fn an_rbf0_row_copies_a_value_and_finds_it_by_filter() {
    let tree = build_rbf0(&rbf0_document());
    let attribute = tree
        .rows
        .iter()
        .find(|row| row.label == "@kind")
        .expect("the attribute row");
    assert_eq!(attribute.copy, "@kind = uiScreen");
    // A filter keeps the matching row and the elements that hold it.
    let shown = tree.visible(&HashSet::new(), "note");
    let labels: Vec<&str> = shown
        .iter()
        .map(|index| tree.rows[*index].label.as_str())
        .collect();
    assert_eq!(labels, ["document", "screen", "text"]);
}

#[test]
fn an_rbf0_document_that_stopped_reports_it_as_a_warning_row() {
    let mut bytes = rbf0_bytes();
    bytes.truncate(bytes.len() - 1);
    let document = rbf::decode(
        &bytes,
        &rbf::Limits::default(),
        &std::sync::atomic::AtomicBool::new(false),
    )
    .expect("a readable header");
    let tree = build_rbf0(&document);
    assert_eq!(tree.status, "failed");
    assert!(!tree.issues.is_empty());
    let warning = tree
        .rows
        .iter()
        .find(|row| row.label.starts_with("the parse stopped"))
        .expect("the failure row");
    assert_eq!(warning.tone, Tone::Warning);
}
