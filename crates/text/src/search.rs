//! Searching a document for a literal string, and navigating the matches.
//!
//! A search reads the document line by line, so a match carries its line and
//! its display columns even when the payload is never decoded as a whole.
//!
//! Matching is case-insensitive through Unicode lower-casing rather than ASCII
//! folding, and a lower-case mapping that changes length still maps back to the
//! source characters it came from. `İ` lowercases to `i` plus a combining dot;
//! a match on that fold is reported on the `İ` itself, and a combining mark
//! adds no display column.
//!
//! A document can hold more matches than are worth keeping. [`Results`] keeps
//! the first [`STORE_LIMIT`] of them and the exact total; [`Cursor`] navigates
//! every one of them by loading the chunk it needs, so the limit never hides a
//! match from Find Next or Find Previous.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::document::{self, Document, TAB_WIDTH};

/// Matches one pass keeps. [`Cursor`] loads further chunks on demand.
pub const STORE_LIMIT: usize = 50_000;
/// Lines decoded per step of the search.
const BLOCK_LINES: usize = 512;

/// One match, in display columns of its line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub line: u32,
    /// The first display column of the match.
    pub start: u32,
    /// The width of the match in display columns.
    pub len: u32,
}

impl Match {
    pub fn end(&self) -> u32 {
        self.start + self.len
    }

    /// Reading order.
    pub fn key(&self) -> (u32, u32) {
        (self.line, self.start)
    }

    pub fn precedes(&self, other: &Match) -> bool {
        self.key() < other.key()
    }
}

/// The matches a first pass found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Results {
    /// The first matches, in reading order.
    pub matches: Vec<Match>,
    /// Every match counted.
    pub total: u64,
    /// The last match in the document, which the stored matches may not reach.
    pub last: Option<Match>,
    /// Whether more matches exist than are stored.
    pub capped: bool,
}

impl Results {
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

/// Finds every occurrence of `needle`, storing the first [`STORE_LIMIT`].
pub fn find(
    document: &Document,
    needle: &str,
    match_case: bool,
    cancel: &AtomicBool,
) -> Result<Results, document::Error> {
    let mut results = Results::default();
    if needle.is_empty() || document.line_count() == 0 {
        return Ok(results);
    }
    scan(document, needle, match_case, cancel, |found| {
        results.total += 1;
        results.last = Some(found);
        if results.matches.len() < STORE_LIMIT {
            results.matches.push(found);
        } else {
            results.capped = true;
        }
        Flow::Continue
    })?;
    Ok(results)
}

/// The next matches after `after`, in reading order.
pub fn find_after(
    document: &Document,
    needle: &str,
    match_case: bool,
    after: Match,
    limit: usize,
    cancel: &AtomicBool,
) -> Result<Vec<Match>, document::Error> {
    let mut found = Vec::new();
    if limit == 0 {
        return Ok(found);
    }
    scan(document, needle, match_case, cancel, |found_match| {
        if found_match.key() <= after.key() {
            return Flow::Continue;
        }
        found.push(found_match);
        if found.len() >= limit {
            Flow::Stop
        } else {
            Flow::Continue
        }
    })?;
    Ok(found)
}

/// The last `limit` matches before `before`, or the last `limit` of the
/// document when `before` is `None`, in reading order.
pub fn find_before(
    document: &Document,
    needle: &str,
    match_case: bool,
    before: Option<Match>,
    limit: usize,
    cancel: &AtomicBool,
) -> Result<Vec<Match>, document::Error> {
    let mut ring: std::collections::VecDeque<Match> = std::collections::VecDeque::new();
    if limit == 0 {
        return Ok(Vec::new());
    }
    scan(document, needle, match_case, cancel, |found| {
        if before.is_some_and(|before| found.key() >= before.key()) {
            return Flow::Stop;
        }
        if ring.len() == limit {
            ring.pop_front();
        }
        ring.push_back(found);
        Flow::Continue
    })?;
    Ok(ring.into_iter().collect())
}

enum Flow {
    Continue,
    Stop,
}

/// Walks the document and reports each match to `on_match`.
fn scan(
    document: &Document,
    needle: &str,
    match_case: bool,
    cancel: &AtomicBool,
    mut on_match: impl FnMut(Match) -> Flow,
) -> Result<(), document::Error> {
    let folded_needle = if match_case {
        String::new()
    } else {
        fold(needle)
    };
    let mut line = 0;
    while line < document.line_count() {
        if cancel.load(Ordering::Relaxed) {
            return Err(document::Error::Cancelled);
        }
        let count = BLOCK_LINES.min(document.line_count() - line);
        let lines = document.read_lines_cancellable(line, count, cancel)?;
        for (offset, text) in lines.iter().enumerate() {
            let index = line + offset;
            let mut from = 0;
            while let Some(found) = find_in_line(text, needle, &folded_needle, from, match_case) {
                let next = found.0;
                let note = Match {
                    line: u32::try_from(index).unwrap_or(u32::MAX),
                    start: found.1,
                    len: found.2,
                };
                if let Flow::Stop = on_match(note) {
                    return Ok(());
                }
                // Non-overlapping: continue after the matched source bytes.
                from = next;
            }
        }
        line += count;
    }
    Ok(())
}

/// Finds the next match at or after byte `from` on one line, and returns the
/// byte offset to continue from with its display columns.
fn find_in_line(
    text: &str,
    needle: &str,
    folded_needle: &str,
    from: usize,
    match_case: bool,
) -> Option<(usize, u32, u32)> {
    if match_case {
        let found = next_exact(text, needle, from)?;
        let end = found + needle.len();
        let start = document::column_at_byte(text, found, TAB_WIDTH);
        let stop = document::column_at_byte(text, end, TAB_WIDTH);
        return Some((end, start, stop.saturating_sub(start)));
    }
    if text.is_ascii() && folded_needle.is_ascii() {
        // The common case: no allocation, and a byte is a column.
        let found = next_ascii_insensitive(text, folded_needle, from)?;
        let end = found + folded_needle.len();
        return Some((end, found as u32, (end - found) as u32));
    }
    let (folded, source_chars, source_bytes) = fold_with_map(text);
    let mut at = 0usize;
    let mut char_index = 0usize;
    let needle_chars = folded_needle.chars().count();
    loop {
        let relative = folded.get(at..)?.find(folded_needle)?;
        let byte = at + relative;
        char_index += folded[at..byte].chars().count();
        let first = *source_chars.get(char_index)? as usize;
        let last = *source_chars.get(char_index + needle_chars - 1)? as usize;
        let source_start = *source_bytes.get(first)?;
        let source_end = source_bytes.get(last + 1).copied().unwrap_or(text.len());
        // The caller asked for matches at or after a byte offset in the
        // source text.
        if source_start >= from {
            let start = document::column_at_byte(text, source_start, TAB_WIDTH);
            let stop = document::column_at_byte(text, source_end, TAB_WIDTH);
            return Some((source_end, start, stop.saturating_sub(start)));
        }
        at = byte + folded_needle.len();
        char_index += needle_chars;
    }
}

/// The next exact occurrence at or after `from`.
fn next_exact(text: &str, needle: &str, from: usize) -> Option<usize> {
    if needle.is_empty() || from > text.len() {
        return None;
    }
    text.get(from..)?.find(needle).map(|at| from + at)
}

/// The next ASCII case-insensitive occurrence at or after `from`.
fn next_ascii_insensitive(text: &str, folded_needle: &str, from: usize) -> Option<usize> {
    let haystack = text.as_bytes();
    let needle = folded_needle.as_bytes();
    if needle.is_empty() || from + needle.len() > haystack.len() {
        return None;
    }
    let last = haystack.len() - needle.len();
    (from..=last).find(|&at| {
        haystack[at..at + needle.len()]
            .iter()
            .zip(needle)
            .all(|(found, wanted)| found.to_ascii_lowercase() == *wanted)
    })
}

/// Lower-cases `text` for matching.
fn fold(text: &str) -> String {
    text.chars().flat_map(char::to_lowercase).collect()
}

/// Lower-cases `text` and records, for every folded character, the source
/// character it came from, and where each source character starts.
fn fold_with_map(text: &str) -> (String, Vec<u32>, Vec<usize>) {
    let mut folded = String::with_capacity(text.len());
    let mut source_chars = Vec::with_capacity(text.len());
    for (index, c) in text.chars().enumerate() {
        for lower in c.to_lowercase() {
            folded.push(lower);
            source_chars.push(u32::try_from(index).unwrap_or(u32::MAX));
        }
    }
    let mut starts = Vec::with_capacity(text.chars().count() + 1);
    starts.extend(text.char_indices().map(|(at, _)| at));
    starts.push(text.len());
    (folded, source_chars, starts)
}

/// What a step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The cursor moved to another match.
    Moved,
    /// The target match is not loaded; [`Cursor::load`] says what to read.
    NeedLoad,
    /// There is no match to move to.
    Empty,
}

/// What a cursor needs read to continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Load {
    /// The first matches of the document.
    Head,
    /// The matches after the last loaded one.
    After(Match),
    /// The last matches of the document.
    Tail,
    /// The matches before the first loaded one.
    Before(Match),
}

/// A position in the document's matches, over a window of them.
///
/// Indices are absolute, so a window that has been trimmed keeps the cursor
/// where it was. The window never holds more than two store limits.
#[derive(Debug, Clone)]
pub struct Cursor {
    total: u64,
    /// The absolute index of `window[0]`.
    first: u64,
    window: Vec<Match>,
    current: Option<u64>,
}

impl Cursor {
    /// A cursor over `results`, placed at the first match at or after
    /// `position` when one is stored.
    pub fn new(results: &Results, position: (usize, u32)) -> Self {
        let current = results
            .matches
            .iter()
            .position(|found| (found.line as usize, found.start) >= position)
            .map(|index| index as u64);
        Self {
            total: results.total,
            first: 0,
            window: results.matches.clone(),
            current,
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn position(&self) -> Option<u64> {
        self.current
    }

    pub fn current(&self) -> Option<Match> {
        self.current.and_then(|index| self.at(index))
    }

    pub fn window(&self) -> &[Match] {
        &self.window
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// The match at an absolute index, when it is loaded.
    pub fn at(&self, index: u64) -> Option<Match> {
        let offset = index.checked_sub(self.first)?;
        self.window.get(usize::try_from(offset).ok()?).copied()
    }

    /// The index of the first loaded match at or after a line and column.
    pub fn index_at_or_after(&self, line: usize, column: u32) -> Option<u64> {
        self.window
            .iter()
            .position(|found| (found.line as usize, found.start) >= (line, column))
            .map(|offset| self.first + offset as u64)
    }

    /// Moves one match forward or backward, wrapping at the ends.
    pub fn step(&mut self, forward: bool) -> Step {
        if self.total == 0 {
            return Step::Empty;
        }
        let Some(current) = self.current else {
            let index = if forward { 0 } else { self.total - 1 };
            return if self.at(index).is_some() {
                self.current = Some(index);
                Step::Moved
            } else {
                Step::NeedLoad
            };
        };
        let (target, _) = if forward {
            if current + 1 < self.total {
                (current + 1, false)
            } else {
                (0, true)
            }
        } else if current > 0 {
            (current - 1, false)
        } else {
            (self.total - 1, true)
        };
        if self.at(target).is_some() {
            self.current = Some(target);
            return Step::Moved;
        }
        Step::NeedLoad
    }

    /// What to read so the step that just returned [`Step::NeedLoad`] can
    /// succeed.
    pub fn load(&self, forward: bool) -> Load {
        match (self.current, forward) {
            (Some(current), true) if current + 1 < self.total => Load::After(
                *self
                    .window
                    .last()
                    .expect("a cursor with a loaded match has a window"),
            ),
            (Some(current), false) if current > 0 => Load::Before(
                *self
                    .window
                    .first()
                    .expect("a cursor with a loaded match has a window"),
            ),
            (Some(_), true) => Load::Head,
            (Some(_), false) => Load::Tail,
            (None, true) => Load::Head,
            (None, false) => Load::Tail,
        }
    }

    /// Appends a chunk that starts right after the loaded window.
    pub fn push_after(&mut self, chunk: Vec<Match>) {
        self.window.extend(chunk);
        self.trim_front();
    }

    /// Prepends a chunk that ends right before the loaded window.
    pub fn push_before(&mut self, chunk: Vec<Match>) {
        self.first = self.first.saturating_sub(chunk.len() as u64);
        let mut combined = chunk;
        combined.append(&mut self.window);
        self.window = combined;
        self.trim_back();
    }

    /// Replaces the window with the first chunk of the document.
    pub fn replace_with_head(&mut self, chunk: Vec<Match>) {
        self.first = 0;
        self.window = chunk;
        self.trim_back();
    }

    /// Replaces the window with the last chunk of the document.
    pub fn replace_with_tail(&mut self, chunk: Vec<Match>) {
        self.first = self.total.saturating_sub(chunk.len() as u64);
        self.window = chunk;
        self.trim_front();
    }

    /// Moves the cursor to an absolute index that is loaded.
    pub fn set_position(&mut self, index: u64) {
        if self.at(index).is_some() {
            self.current = Some(index);
        }
    }

    fn trim_front(&mut self) {
        let excess = self.window.len().saturating_sub(2 * STORE_LIMIT);
        if excess > 0 {
            self.window.drain(..excess);
            self.first += excess as u64;
        }
    }

    fn trim_back(&mut self) {
        let excess = self.window.len().saturating_sub(2 * STORE_LIMIT);
        if excess > 0 {
            self.window.truncate(self.window.len() - excess);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::AtomicBool;

    use lforge_binary::Source;

    use super::*;
    use crate::document::Document;
    use crate::encoding::Encoding;

    fn open(bytes: &[u8]) -> Document {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        let source = Source::open(file.path()).unwrap();
        Document::load(source, Encoding::Utf8, &AtomicBool::new(false), |_, _| {}).unwrap()
    }

    fn search(bytes: &[u8], needle: &str, match_case: bool) -> Results {
        find(&open(bytes), needle, match_case, &AtomicBool::new(false)).unwrap()
    }

    fn matches(bytes: &[u8], needle: &str, match_case: bool) -> Vec<(u32, u32, u32)> {
        search(bytes, needle, match_case)
            .matches
            .iter()
            .map(|found| (found.line, found.start, found.len))
            .collect()
    }

    #[test]
    fn matches_carry_their_line_and_column() {
        let results = search(b"alpha beta\ngamma beta beta\n", "beta", false);
        assert_eq!(results.total, 3);
        assert_eq!(
            results.matches,
            vec![
                Match {
                    line: 0,
                    start: 6,
                    len: 4
                },
                Match {
                    line: 1,
                    start: 6,
                    len: 4
                },
                Match {
                    line: 1,
                    start: 11,
                    len: 4
                },
            ]
        );
        assert_eq!(
            results.last,
            Some(Match {
                line: 1,
                start: 11,
                len: 4
            })
        );
        assert!(!results.capped);
    }

    #[test]
    fn case_is_folded_only_when_asked() {
        let text = b"Name\nname\nNAME\n";
        assert_eq!(search(text, "name", true).total, 1);
        assert_eq!(search(text, "name", false).total, 3);
    }

    #[test]
    fn case_folding_is_unicode_aware() {
        // Greek capital sigma lower-cases to a small sigma, and the final form
        // of a word is still one character.
        assert_eq!(search("ΣΙΓΜΑ\n".as_bytes(), "σιγμα", false).total, 1);
        assert_eq!(search("ΣΙΓΜΑ\n".as_bytes(), "σιγμα", true).total, 0);
        // Cyrillic.
        assert_eq!(search("Привет мир\n".as_bytes(), "ПРИВЕТ", false).total, 1);
        // A mapping that changes length: İ lower-cases to i plus U+0307.
        let results = search("İstanbul\n".as_bytes(), "i̇stanbul", false);
        assert_eq!(results.total, 1);
        assert_eq!(results.matches[0].start, 0);
        assert_eq!(results.matches[0].len, 8);
    }

    #[test]
    fn combining_marks_take_no_display_column() {
        // "e" + U+0301 is one cell, so the match after it starts at column 2.
        let text = "he\u{301}llo wörld\r\n".as_bytes();
        let found = matches(text, "wörld", false);
        assert_eq!(found, vec![(0, 6, 5)]);
        // Searching for the base letter alone still finds it inside the pair.
        let found = matches("he\u{301}llo\n".as_bytes(), "h", false);
        assert_eq!(found, vec![(0, 0, 1)]);
    }

    #[test]
    fn wide_characters_count_two_columns() {
        let text = "中文 test\n".as_bytes();
        let found = matches(text, "test", false);
        assert_eq!(found, vec![(0, 5, 4)]);
        // A match on a wide character spans its two columns.
        let found = matches("a中文\n".as_bytes(), "中", false);
        assert_eq!(found, vec![(0, 1, 2)]);
    }

    #[test]
    fn tabs_advance_the_reported_column() {
        let results = search(b"\t\tvalue\n", "value", true);
        assert_eq!(results.matches[0].start, 8);
        // A match that contains a tab spans the columns the tab advances.
        let results = search(b"a\tb\n", "a\tb", true);
        assert_eq!(results.matches[0].start, 0);
        assert_eq!(results.matches[0].len, 5);
    }

    #[test]
    fn matches_do_not_overlap() {
        let results = search(b"aaaa\n", "aa", true);
        assert_eq!(results.total, 2);
        let results = search(b"aaaa\n", "aa", false);
        assert_eq!(results.total, 2);
    }

    #[test]
    fn an_empty_needle_finds_nothing() {
        assert!(search(b"abc\n", "", false).is_empty());
    }

    #[test]
    fn a_match_at_the_end_of_a_line_is_found() {
        let results = search(b"abc\ndef abc", "abc", true);
        assert_eq!(results.total, 2);
        assert_eq!(results.matches[1].line, 1);
    }

    #[test]
    fn matches_are_found_across_search_blocks() {
        let mut text = String::new();
        for index in 0..1500 {
            if index == 1400 {
                text.push_str("here is the needle\n");
            } else {
                text.push_str(&format!("line {index}\n"));
            }
        }
        let results = search(text.as_bytes(), "needle", true);
        assert_eq!(results.total, 1);
        assert_eq!(results.matches[0].line, 1400);
        assert_eq!(results.matches[0].start, 12);
    }

    #[test]
    fn many_matches_keep_the_first_and_the_last() {
        // One match per line, more than the store limit.
        let mut text = String::with_capacity(STORE_LIMIT * 8);
        for index in 0..STORE_LIMIT + 25 {
            text.push_str(&format!("match {index}\n"));
        }
        let document = open(text.as_bytes());
        let results = find(&document, "match", true, &AtomicBool::new(false)).unwrap();
        assert_eq!(results.total, (STORE_LIMIT + 25) as u64);
        assert_eq!(results.matches.len(), STORE_LIMIT);
        assert!(results.capped);
        assert_eq!(
            results.last,
            Some(Match {
                line: (STORE_LIMIT + 24) as u32,
                start: 0,
                len: 5
            })
        );
    }

    #[test]
    fn the_cursor_reaches_every_match_beyond_the_store_limit() {
        let mut text = String::new();
        for index in 0..STORE_LIMIT + 25 {
            text.push_str(&format!("match {index}\n"));
        }
        let document = open(text.as_bytes());
        let cancel = AtomicBool::new(false);
        let results = find(&document, "match", true, &cancel).unwrap();
        let mut cursor = Cursor::new(&results, (0, 0));
        assert_eq!(cursor.step(true), Step::Moved);
        let mut visited = 1u64;
        loop {
            match cursor.step(true) {
                Step::Moved => visited += 1,
                Step::NeedLoad => {
                    let load = cursor.load(true);
                    match load {
                        Load::After(after) => {
                            let chunk =
                                find_after(&document, "match", true, after, STORE_LIMIT, &cancel)
                                    .unwrap();
                            assert!(!chunk.is_empty());
                            cursor.push_after(chunk);
                        }
                        Load::Head => {
                            let head = find(&document, "match", true, &cancel).unwrap().matches;
                            cursor.replace_with_head(head);
                        }
                        Load::Tail => {
                            let tail =
                                find_before(&document, "match", true, None, STORE_LIMIT, &cancel)
                                    .unwrap();
                            cursor.replace_with_tail(tail);
                        }
                        Load::Before(before) => {
                            let chunk = find_before(
                                &document,
                                "match",
                                true,
                                Some(before),
                                STORE_LIMIT,
                                &cancel,
                            )
                            .unwrap();
                            cursor.push_before(chunk);
                        }
                    }
                    assert_eq!(cursor.step(true), Step::Moved, "after loading {load:?}");
                    visited += 1;
                }
                Step::Empty => panic!("the cursor ran out of matches"),
            }
            if cursor.position() == Some(0) && visited > 1 {
                break;
            }
        }
        assert_eq!(visited, STORE_LIMIT as u64 + 25);
    }

    #[test]
    fn the_cursor_walks_back_over_every_match() {
        let mut text = String::new();
        for index in 0..STORE_LIMIT + 10 {
            text.push_str(&format!("match {index}\n"));
        }
        let document = open(text.as_bytes());
        let cancel = AtomicBool::new(false);
        let results = find(&document, "match", true, &cancel).unwrap();
        let mut cursor = Cursor::new(&results, (0, 0));
        // Walking back from the first match wraps to the last, which is not
        // loaded.
        assert_eq!(cursor.step(false), Step::NeedLoad);
        let tail = find_before(&document, "match", true, None, STORE_LIMIT, &cancel).unwrap();
        cursor.replace_with_tail(tail);
        assert_eq!(cursor.step(false), Step::Moved);
        assert_eq!(cursor.position(), Some(results.total - 1));
        let mut visited = 1u64;
        loop {
            match cursor.step(false) {
                Step::Moved => visited += 1,
                Step::NeedLoad => {
                    let chunk = find_before(
                        &document,
                        "match",
                        true,
                        cursor.window().first().copied(),
                        STORE_LIMIT,
                        &cancel,
                    )
                    .unwrap();
                    assert!(!chunk.is_empty(), "a chunk before the window exists");
                    cursor.push_before(chunk);
                    assert_eq!(cursor.step(false), Step::Moved);
                    visited += 1;
                }
                Step::Empty => panic!("the cursor ran out of matches"),
            }
            if cursor.position() == Some(0) {
                break;
            }
        }
        assert_eq!(visited, STORE_LIMIT as u64 + 10);
    }

    #[test]
    fn find_after_and_before_are_ordered() {
        let document = open(b"a a a a\n");
        let cancel = AtomicBool::new(false);
        let all = find(&document, "a", true, &cancel).unwrap();
        assert_eq!(all.total, 4);
        let after = find_after(&document, "a", true, all.matches[1], 2, &cancel).unwrap();
        assert_eq!(
            after,
            vec![
                Match {
                    line: 0,
                    start: 4,
                    len: 1
                },
                Match {
                    line: 0,
                    start: 6,
                    len: 1
                },
            ]
        );
        let before = find_before(&document, "a", true, Some(all.matches[2]), 2, &cancel).unwrap();
        assert_eq!(
            before,
            vec![
                Match {
                    line: 0,
                    start: 0,
                    len: 1
                },
                Match {
                    line: 0,
                    start: 2,
                    len: 1
                },
            ]
        );
        let tail = find_before(&document, "a", true, None, 2, &cancel).unwrap();
        assert_eq!(tail.last().unwrap().start, 6);
    }

    #[test]
    fn a_utf16_document_matches_with_columns() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend("first\nsecond\n".encode_utf16().flat_map(u16::to_le_bytes));
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes).unwrap();
        let source = Source::open(file.path()).unwrap();
        let document = Document::load(
            source,
            Encoding::Utf16Le,
            &AtomicBool::new(false),
            |_, _| {},
        )
        .unwrap();
        let results = find(&document, "SECOND", false, &AtomicBool::new(false)).unwrap();
        assert_eq!(results.total, 1);
        assert_eq!(results.matches[0].line, 1);
        assert_eq!(results.matches[0].start, 0);
        assert_eq!(results.matches[0].len, 6);
    }
}
