//! Searching a document for a literal string.
//!
//! The search runs line by line, so a match has a line and a column even when
//! the payload is never decoded as a whole. Case-insensitivity folds ASCII
//! letters only: that is what code and markup use for names, and it keeps the
//! column arithmetic per byte exact.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::document::{self, Document};

/// Matches remembered for navigation. A larger count is still reported, but
/// only this many can be stepped through.
pub const MAX_MATCHES: usize = 100_000;
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

    /// Whether this match comes before `other` in reading order.
    pub fn precedes(&self, other: &Match) -> bool {
        (self.line, self.start) < (other.line, other.start)
    }
}

/// What a search found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Results {
    /// The matches kept for navigation, in reading order.
    pub matches: Vec<Match>,
    /// Every match counted, including those beyond [`MAX_MATCHES`].
    pub total: u64,
    /// Whether more matches were found than were kept.
    pub capped: bool,
}

impl Results {
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

/// Finds every non-overlapping occurrence of `needle`.
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
    let mut line = 0;
    while line < document.line_count() {
        if cancel.load(Ordering::Relaxed) {
            return Err(document::Error::Cancelled);
        }
        let count = BLOCK_LINES.min(document.line_count() - line);
        let lines = document.read_lines(line, count)?;
        for (offset, text) in lines.iter().enumerate() {
            let index = line + offset;
            let mut from = 0;
            while let Some(byte) = next_match(text, needle, from, match_case) {
                let start = document::column_at_byte(text, byte, document::TAB_WIDTH);
                let end = document::column_at_byte(text, byte + needle.len(), document::TAB_WIDTH);
                results.total += 1;
                if results.matches.len() < MAX_MATCHES {
                    results.matches.push(Match {
                        line: u32::try_from(index).unwrap_or(u32::MAX),
                        start,
                        len: end.saturating_sub(start),
                    });
                } else {
                    results.capped = true;
                }
                from = byte + needle.len();
            }
        }
        line += count;
    }
    Ok(results)
}

/// The byte offset of the next match at or after `from`.
fn next_match(haystack: &str, needle: &str, from: usize, match_case: bool) -> Option<usize> {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || from >= haystack.len() || haystack.len() - from < needle.len() {
        return None;
    }
    let last = haystack.len() - needle.len();
    (from..=last).find(|&at| {
        haystack[at..at + needle.len()]
            .iter()
            .zip(needle)
            .all(|(found, wanted)| {
                if match_case {
                    found == wanted
                } else {
                    found.eq_ignore_ascii_case(wanted)
                }
            })
    })
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
    }

    #[test]
    fn case_is_folded_only_when_asked() {
        let text = b"Name\nname\nNAME\n";
        assert_eq!(search(text, "name", true).total, 1);
        assert_eq!(search(text, "name", false).total, 3);
    }

    #[test]
    fn tabs_advance_the_reported_column() {
        let results = search(b"\t\tvalue\n", "value", true);
        assert_eq!(results.matches[0].start, 8);
    }

    #[test]
    fn matches_do_not_overlap() {
        let results = search(b"aaaa\n", "aa", true);
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
}
