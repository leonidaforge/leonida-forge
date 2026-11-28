//! What can be checked about the viewer without a window: line preparation,
//! span conversion, row styling, and a manual pass over real text rows.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use lforge_text::{Document, Language};

use super::render::styled_line;
use super::{ColoredSpan, PageLine, display_name, page_line, spans_to_columns};
use crate::files::{self, Access, Entry, EntryKind};

#[test]
fn a_page_line_expands_tabs_and_keeps_its_columns() {
    let line = page_line("a\tb", Language::Plain);
    assert_eq!(line.text.as_ref(), "a   b");
    assert_eq!(line.columns, 5);
}

#[test]
fn a_page_line_carries_syntax_spans_in_columns() {
    let line = page_line("<Root name=\"v\">x</Root>", Language::Xml);
    assert!(!line.spans.is_empty());
    for span in &line.spans {
        assert!(span.start < span.end);
        assert!(span.end <= line.columns);
    }
}

#[test]
fn a_very_wide_line_is_shown_without_highlighting() {
    let text = format!("<{}>", "a".repeat(30_000));
    let line = page_line(&text, Language::Xml);
    assert_eq!(line.columns as usize, text.chars().count());
    assert!(line.spans.is_empty());
}

#[test]
fn spans_are_converted_to_columns_around_multibyte_text() {
    // Two bytes of `é` must count as one column before the tag name.
    let text = "é<a>";
    let spans = lforge_text::syntax::highlight(Language::Xml, text);
    let converted = spans_to_columns(text, spans);
    assert_eq!(converted[0].start, 2);
    assert_eq!(converted[0].end, 3);
}

#[test]
fn a_row_is_drawn_from_the_visible_columns_only() {
    let line = PageLine {
        text: "abcdef".into(),
        columns: 6,
        spans: vec![ColoredSpan {
            start: 0,
            end: 3,
            token: lforge_text::syntax::Token::Tag,
        }],
    };
    let (text, runs) = styled_line(&line, 2, 3, Some((3, 6)), &[], None, Some(4));
    assert_eq!(text.as_ref(), "cde");
    let bytes: usize = runs.iter().map(|run| run.len).sum();
    assert_eq!(bytes, text.len());
    assert!(runs.iter().all(|run| run.len > 0));
}

#[test]
fn a_row_that_starts_past_the_line_end_draws_nothing() {
    let line = PageLine {
        text: "abc".into(),
        columns: 3,
        spans: Vec::new(),
    };
    let (text, runs) = styled_line(&line, 5, 10, None, &[], None, None);
    assert!(text.is_empty());
    assert!(runs.is_empty());
}

#[test]
fn matches_are_clipped_to_the_row() {
    let line = PageLine {
        text: "abcdefgh".into(),
        columns: 8,
        spans: Vec::new(),
    };
    let found = lforge_text::Match {
        line: 0,
        start: 2,
        len: 3,
    };
    let (text, runs) = styled_line(&line, 0, 4, None, &[found], Some(found), None);
    assert_eq!(text.as_ref(), "abcd");
    let bytes: usize = runs.iter().map(|run| run.len).sum();
    assert_eq!(bytes, 4);
}

#[test]
fn the_payload_is_identified_by_its_name_not_its_row() {
    let path = Path::new(r"D:\GTA VI\common.rpf\Unnamed Entries\Row 00382");
    assert_eq!(
        display_name(path, Some("CCombatInfoMgr.xml")),
        "CCombatInfoMgr.xml"
    );
    assert_eq!(
        display_name(path, Some("0x1F2E3D4C.zxml")),
        "0x1F2E3D4C.zxml"
    );
    // Without a name the archive identifies the row, never the row label.
    assert_eq!(display_name(path, None), "common.rpf");
    assert!(!super::location(path).unwrap().contains("Row"));
    assert_eq!(
        super::location(path).unwrap(),
        "common.rpf / Unnamed Entries"
    );
}

/// Opens real text rows of GTA VI through the archive path, read only.
///
/// Ignored by default: it needs the local game installation. Set
/// `LF_TEST_TEXT_ARCHIVE` (an archive file or a directory), optionally
/// `LF_TEST_TEXT_ROWS` (comma-separated row numbers, default `382,45,117`) and
/// `LF_TEST_EXECUTABLE` (the game executable, when the archive metadata needs
/// it). Run with `--ignored --nocapture` to read the summary.
#[test]
#[ignore = "reads the local GTA VI installation"]
fn opens_real_text_rows() {
    let Ok(archive) = std::env::var("LF_TEST_TEXT_ARCHIVE") else {
        eprintln!("skipped: LF_TEST_TEXT_ARCHIVE is not set");
        return;
    };
    let rows: Vec<u32> = std::env::var("LF_TEST_TEXT_ROWS")
        .map(|value| {
            value
                .split(',')
                .filter_map(|row| row.trim().parse().ok())
                .collect()
        })
        .unwrap_or_else(|_| vec![382, 45, 117]);
    let access = match std::env::var("LF_TEST_EXECUTABLE") {
        Ok(path) => Access::with(Arc::new(
            files::Executable::open(Path::new(&path)).expect("the executable opens"),
        )),
        Err(_) => Access::none(),
    };
    let root = Path::new(&archive);
    // The explorer prepares an archive before listing it; the test does the
    // same, without recovery scanning.
    files::archive::prepare_with(
        root,
        &access,
        false,
        &files::archive::Stage::default(),
        &lforge_rage9::rpf::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("the archive is prepared");
    let found = find_rows(root, &access, &rows);
    assert!(
        !found.is_empty(),
        "no rows of {rows:?} were found under {archive}"
    );
    for (row, entry) in found {
        let head =
            files::read_head_with(&entry.path, &access, 64 * 1024).expect("the head is read");
        let detection = lforge_text::detect(&head, entry.extension().as_deref());
        let info = detection
            .text_info()
            .unwrap_or_else(|| panic!("row {row} is not text: {detection:?}"));
        let file = files::open_binary_with(&entry.path, &access).expect("the payload opens");
        let cancel = AtomicBool::new(false);
        let document =
            Document::load(file.source, info.encoding, &cancel, |_, _| {}).expect("indexed");
        assert!(document.line_count() > 0, "row {row} has no lines");
        let first = document.read_line(0).expect("the first line reads");
        assert!(!first.trim().is_empty(), "row {row} starts empty");
        let last = document
            .read_line(document.line_count() - 1)
            .expect("the last line reads");
        let sample = first.split_whitespace().next().unwrap_or("").to_string();
        let results = lforge_text::find(&document, &sample, true, &AtomicBool::new(false))
            .expect("searching reads the payload");
        assert!(
            !results.is_empty(),
            "the first token of row {row} is not found in it"
        );
        for line in document.read_lines(0, 40).expect("the head lines read") {
            assert!(!line.contains('\0'), "row {row} decodes a zero");
        }
        eprintln!(
            "row {row:>3}  {:>12} bytes  {:>6} lines  {:6}  {:?}  first={:?}  last={:?}  matches={}",
            document.len(),
            document.line_count(),
            info.encoding.label(info.bom),
            info.language,
            first.chars().take(48).collect::<String>(),
            last.chars().take(24).collect::<String>(),
            results.total,
        );
    }
}

/// The listings of `dir`, and of its folders, that carry one of `rows`.
fn find_rows(dir: &Path, access: &Access, rows: &[u32]) -> Vec<(u32, Entry)> {
    let mut found = Vec::new();
    walk(dir, access, rows, &mut found, 0);
    found
}

fn walk(dir: &Path, access: &Access, rows: &[u32], found: &mut Vec<(u32, Entry)>, depth: usize) {
    if depth > 4 {
        return;
    }
    let entries = match files::list_with(dir, access) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("skipped {}: {err}", dir.display());
            return;
        }
    };
    for entry in entries {
        if entry.kind == EntryKind::Directory {
            walk(&entry.path, access, rows, found, depth + 1);
            continue;
        }
        let Some(row) = entry
            .details
            .iter()
            .find(|(label, _)| *label == "Row")
            .and_then(|(_, value)| value.split_whitespace().next())
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if rows.contains(&row) {
            found.push((row, entry));
        }
    }
}
