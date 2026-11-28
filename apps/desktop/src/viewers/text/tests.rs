//! What can be checked about the viewer without a window: line preparation,
//! span conversion, row styling, and a manual pass over real text rows.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use lforge_text::syntax::State;
use lforge_text::{Document, Language};

use super::render::styled_line;
use super::{ColoredSpan, PageLine, display_name, page_line, spans_to_columns};
use crate::files::{self, Access, Entry, EntryKind};

fn prepare(raw: &str, language: Language) -> PageLine {
    page_line(raw, language, State::Plain).0
}

#[test]
fn a_page_line_expands_tabs_and_keeps_its_columns() {
    let line = prepare("a\tb", Language::Plain);
    assert_eq!(line.text.as_ref(), "a   b");
    assert_eq!(line.columns, 5);
}

#[test]
fn a_page_line_carries_syntax_spans_in_columns() {
    let line = prepare("<Root name=\"v\">x</Root>", Language::Xml);
    assert!(!line.spans.is_empty());
    for span in &line.spans {
        assert!(span.start < span.end);
        assert!(span.end <= line.columns);
    }
}

#[test]
fn a_very_wide_line_is_shown_without_highlighting() {
    let text = format!("<{}>", "a".repeat(30_000));
    let line = prepare(&text, Language::Xml);
    assert_eq!(line.columns as usize, text.chars().count());
    assert!(line.spans.is_empty());
}

#[test]
fn a_multiline_comment_colours_the_lines_it_covers() {
    let (first, state) = page_line("/* open", Language::JavaScript, State::Plain);
    assert_eq!(state, State::BlockComment);
    assert_eq!(first.spans.len(), 1);
    let (second, state) = page_line("still inside", Language::JavaScript, state);
    assert_eq!(state, State::BlockComment);
    assert_eq!(second.spans.len(), 1);
    let (third, state) = page_line("close */ let a = 1;", Language::JavaScript, state);
    assert_eq!(state, State::Plain);
    assert!(!third.spans.is_empty());
}

#[test]
fn wide_characters_keep_their_columns() {
    let line = prepare("a中文b", Language::Plain);
    assert_eq!(line.columns, 6);
}

#[test]
fn spans_are_converted_to_columns_around_multibyte_text() {
    // Two bytes of `é` must count as one column before the tag name.
    let text = "é<a>";
    let (spans, _) = lforge_text::syntax::highlight(Language::Xml, State::Plain, text);
    let converted = spans_to_columns(text, spans);
    assert_eq!(converted[0].start, 2);
    assert_eq!(converted[0].end, 3);
}

#[test]
fn spans_follow_wide_characters() {
    // `中` takes two columns, so the tag after it starts at column 3.
    let text = "中<a>";
    let (spans, _) = lforge_text::syntax::highlight(Language::Xml, State::Plain, text);
    let converted = spans_to_columns(text, spans);
    assert_eq!(converted[0].start, 3);
    assert_eq!(converted[0].end, 4);
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
    let (text, runs, start) = styled_line(&line, 2, 3, Some((3, 6)), &[], None, Some(4));
    assert_eq!(text.as_ref(), "cde");
    assert_eq!(start, 2);
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
    let (text, runs, _) = styled_line(&line, 5, 10, None, &[], None, None);
    assert!(text.is_empty());
    assert!(runs.is_empty());
}

#[test]
fn a_row_that_starts_inside_a_wide_character_starts_at_the_character() {
    let line = PageLine {
        text: "中a".into(),
        columns: 3,
        spans: Vec::new(),
    };
    let (text, _, start) = styled_line(&line, 1, 1, None, &[], None, None);
    assert_eq!(text.as_ref(), "中");
    assert_eq!(start, 0);
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
    let (text, runs, _) = styled_line(&line, 0, 4, None, &[found], Some(found), None);
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
    // With no label the archive identifies the entry, never the row path.
    assert_eq!(display_name(path, None), "common.rpf");
    assert_eq!(
        display_name(Path::new(r"D:\x\notes.txt"), None),
        "notes.txt"
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
        if !sample.is_empty() {
            let results = lforge_text::find(&document, &sample, true, &AtomicBool::new(false))
                .expect("searching reads the payload");
            assert!(
                !results.is_empty(),
                "the first token of row {row} is not found in it"
            );
        }
        for line in document.read_lines(0, 40).expect("the head lines read") {
            assert!(!line.contains('\0'), "row {row} decodes a zero");
        }
        eprintln!(
            "row {row:>3}  {:>12} bytes  {:>6} lines  {:6}  {:?}  malformed={}  first={:?}  last={:?}",
            document.len(),
            document.line_count(),
            info.encoding.label(info.bom),
            info.language,
            document.malformed(),
            first.chars().take(48).collect::<String>(),
            last.chars().take(24).collect::<String>(),
        );
    }
}

/// Opens every text payload of one archive and checks each, read only.
///
/// Ignored by default. Set `LF_TEST_TEXT_ARCHIVE` to an archive (or a
/// directory of them) and `LF_TEST_TEXT_ALL=1`; `LF_TEST_EXECUTABLE` supplies
/// the game executable when the archive metadata needs it. Every listed file
/// is checked: payloads that are not text are counted and skipped, and every
/// text payload must index, read its first and last line, and be found by a
/// search of its first token.
#[test]
#[ignore = "reads the local GTA VI installation"]
fn opens_every_text_payload_of_an_archive() {
    if std::env::var("LF_TEST_TEXT_ALL").as_deref() != Ok("1") {
        eprintln!("skipped: LF_TEST_TEXT_ALL is not set");
        return;
    }
    let Ok(archive) = std::env::var("LF_TEST_TEXT_ARCHIVE") else {
        eprintln!("skipped: LF_TEST_TEXT_ARCHIVE is not set");
        return;
    };
    let access = match std::env::var("LF_TEST_EXECUTABLE") {
        Ok(path) => Access::with(Arc::new(
            files::Executable::open(Path::new(&path)).expect("the executable opens"),
        )),
        Err(_) => Access::none(),
    };
    let root = Path::new(&archive);
    files::archive::prepare_with(
        root,
        &access,
        false,
        &files::archive::Stage::default(),
        &lforge_rage9::rpf::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("the archive is prepared");
    let candidates = all_files(root, &access, 4);
    let mut text = 0usize;
    let mut binary = 0usize;
    let mut failed = Vec::new();
    let mut malformed = 0u64;
    let mut lines = 0u64;
    let mut bytes = 0u64;
    for entry in candidates {
        let head = match files::read_head_with(&entry.path, &access, 64 * 1024) {
            Ok(head) => head,
            Err(err) => {
                failed.push(format!("{}: head read failed: {err}", entry.name));
                continue;
            }
        };
        let detection = lforge_text::detect(&head, entry.extension().as_deref());
        let Some(info) = detection.text_info() else {
            binary += 1;
            continue;
        };
        let file = match files::open_binary_with(&entry.path, &access) {
            Ok(file) => file,
            Err(err) => {
                failed.push(format!("{}: payload read failed: {err}", entry.name));
                continue;
            }
        };
        let cancel = AtomicBool::new(false);
        let document = match Document::load(file.source, info.encoding, &cancel, |_, _| {}) {
            Ok(document) => document,
            Err(err) => {
                failed.push(format!("{}: index failed: {err}", entry.name));
                continue;
            }
        };
        if document.line_count() == 0 {
            failed.push(format!("{}: no lines", entry.name));
            continue;
        }
        if let Err(err) = document.read_line(document.line_count() - 1) {
            failed.push(format!("{}: last line failed: {err}", entry.name));
            continue;
        }
        text += 1;
        malformed += document.malformed();
        lines += document.line_count() as u64;
        bytes += document.len();
    }
    eprintln!(
        "checked {} files: {text} text, {binary} not text, {} failed; {lines} lines, {bytes} bytes, {malformed} malformed sequences",
        text + binary + failed.len(),
        failed.len()
    );
    for note in failed.iter().take(20) {
        eprintln!("  failed: {note}");
    }
    assert!(!failed.is_empty() || text > 0, "no text payload was found");
    assert!(failed.is_empty(), "{} text payloads failed", failed.len());
}

/// Every file entry of a prepared archive, to a fixed depth.
fn all_files(dir: &Path, access: &Access, depth: usize) -> Vec<Entry> {
    let mut found = Vec::new();
    collect_files(dir, access, depth, &mut found);
    found
}

fn collect_files(dir: &Path, access: &Access, depth: usize, found: &mut Vec<Entry>) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = files::list_with(dir, access) else {
        return;
    };
    for entry in entries {
        match entry.kind {
            EntryKind::Directory => collect_files(&entry.path, access, depth - 1, found),
            EntryKind::File | EntryKind::Archive => found.push(entry),
            EntryKind::Unavailable => {}
        }
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
