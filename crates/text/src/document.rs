//! Line-addressed, read-only access to a text payload of any size.
//!
//! A document is built by one sequential pass over the payload that records
//! where each line starts, how many display columns it occupies and how many
//! sequences could not be decoded. The payload itself is never held in memory:
//! lines are decoded on demand from bounded byte ranges, so a document of any
//! size opens, and only the lines a caller asks for are decoded.
//!
//! Lines end at LF, CR or CRLF, in every supported encoding, and the two forms
//! may be mixed in one payload. A terminator is not part of the line. A final
//! terminator does not create an empty last line.
//!
//! Display columns are terminal cells, not characters: a combining mark takes
//! no cell, and a wide character takes two. That is what keeps match positions,
//! the caret and selection aligned on text that is not ASCII.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::Source;
use unicode_width::UnicodeWidthChar;

use crate::encoding::{self, Encoding};

/// Bytes read per step while indexing and while decoding a block of lines.
pub const CHUNK: usize = 1024 * 1024;
/// Columns a tab advances to the next multiple of.
pub const TAB_WIDTH: u32 = 4;
/// Lines a document may have. Beyond this the line index would hold more
/// memory than the payload justifies, so the document is refused rather than
/// truncated.
pub const MAX_LINES: usize = 10_000_000;
/// Bytes one block request may span; a request is split instead of refused.
pub const MAX_BLOCK_BYTES: u64 = 8 * 1024 * 1024;
/// Bytes one line may occupy. A longer line is refused rather than loaded
/// whole, because rendering it would hold that many bytes for one row.
pub const MAX_LINE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Cancelled,
    /// The payload has more lines than [`MAX_LINES`].
    TooManyLines {
        found: usize,
    },
    /// One line is longer than [`MAX_LINE_BYTES`].
    LineTooLong {
        line: usize,
        len: u64,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::Cancelled => f.write_str("cancelled"),
            Error::TooManyLines { found } => write!(
                f,
                "the payload has more than {MAX_LINES} lines (stopped after {found})"
            ),
            Error::LineTooLong { line, len } => write!(
                f,
                "line {} is {len} bytes, longer than the {MAX_LINE_BYTES}-byte limit",
                line + 1
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

fn cancelled(cancel: &AtomicBool) -> Result<(), Error> {
    if cancel.load(Ordering::Relaxed) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

/// One text payload, indexed by line.
#[derive(Debug, Clone)]
pub struct Document {
    source: Source,
    encoding: Encoding,
    /// Bytes of the byte-order mark, skipped by every line.
    bom_len: u64,
    len: u64,
    /// Absolute byte offset of the first byte of each line, from the payload
    /// start, including any terminator of the previous line.
    starts: Vec<u64>,
    /// Display columns of each line, with tabs expanded to [`TAB_WIDTH`].
    columns: Vec<u32>,
    max_columns: u32,
    /// Sequences the index pass could not decode: replacement characters a
    /// decode produces, and a line of a legacy code page with unmapped bytes
    /// counts as one.
    malformed: u64,
}

impl Document {
    /// Indexes `source` as `encoding`.
    ///
    /// `progress` is called after every chunk with the bytes read and the
    /// total length, so a caller can show the pass without polling.
    pub fn load(
        source: Source,
        encoding: Encoding,
        cancel: &AtomicBool,
        mut progress: impl FnMut(u64, u64),
    ) -> Result<Self, Error> {
        let len = source.len();
        let mut head = [0u8; 3];
        let head_len = read_at(&source, 0, &mut head[..len.min(3) as usize])?;
        let bom_len = match encoding::bom(&head[..head_len]) {
            // Only a mark for the encoding the caller chose is skipped: a mark
            // read as another encoding is data, not a mark.
            Some((marked, consumed)) if marked == encoding => consumed as u64,
            _ => 0,
        };
        let mut indexer = Indexer {
            encoding,
            starts: Vec::new(),
            columns: Vec::new(),
            max_columns: 0,
            malformed: 0,
            next_start: bom_len,
            columns_so_far: 0,
            line_bytes: Vec::new(),
            cancel,
        };
        let mut reader = source.clone();
        reader.seek(SeekFrom::Start(bom_len))?;
        let mut buffer = vec![0u8; CHUNK];
        let mut carrier: Vec<u8> = Vec::with_capacity(8);
        let mut offset = bom_len;
        let mut read = 0u64;
        loop {
            cancelled(cancel)?;
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            read += count as u64;
            progress(bom_len + read, len);
            let mut window: Vec<u8> = Vec::with_capacity(carrier.len() + count);
            window.extend_from_slice(&carrier);
            window.extend_from_slice(&buffer[..count]);
            let consumed = indexer.feed(&window, offset - carrier.len() as u64)?;
            carrier = window[consumed..].to_vec();
            offset += count as u64;
        }
        indexer.finish(&carrier, offset - carrier.len() as u64, len)?;
        Ok(Self {
            source,
            encoding,
            bom_len,
            len,
            starts: indexer.starts,
            columns: indexer.columns,
            max_columns: indexer.max_columns,
            malformed: indexer.malformed,
        })
    }

    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    pub fn bom_len(&self) -> u64 {
        self.bom_len
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sequences the index pass could not decode. A non-zero count means the
    /// text shown contains replacement characters that the payload does not.
    pub fn malformed(&self) -> u64 {
        self.malformed
    }

    pub fn line_count(&self) -> usize {
        self.starts.len()
    }

    /// Display columns of a line, with tabs expanded.
    pub fn line_columns(&self, line: usize) -> u32 {
        self.columns.get(line).copied().unwrap_or(0)
    }

    /// Display columns of the widest line.
    pub fn max_columns(&self) -> u32 {
        self.max_columns
    }

    /// The byte range the given lines are stored in, terminators included.
    pub fn byte_range(&self, lines: std::ops::Range<usize>) -> std::ops::Range<u64> {
        let first = lines.start.min(self.line_count());
        let end = lines.end.min(self.line_count());
        let start = self.starts.get(first).copied().unwrap_or(self.len);
        let end = self.starts.get(end).copied().unwrap_or(self.len);
        start..end
    }

    /// The lines `first..first + count`, decoded without their terminators.
    ///
    /// The whole range is read at once, in pieces of at most
    /// [`MAX_BLOCK_BYTES`], so a block of short lines does not cause one read
    /// per line.
    pub fn read_lines(&self, first: usize, count: usize) -> Result<Vec<String>, Error> {
        self.read_lines_cancellable(first, count, &AtomicBool::new(false))
    }

    /// [`read_lines`] that stops between reads once `cancel` is set, so a
    /// superseded block does not keep decoding.
    pub fn read_lines_cancellable(
        &self,
        first: usize,
        count: usize,
        cancel: &AtomicBool,
    ) -> Result<Vec<String>, Error> {
        let count = count.min(self.line_count().saturating_sub(first));
        let mut lines = Vec::with_capacity(count);
        let mut line = first;
        while line < first + count {
            cancelled(cancel)?;
            // Pick the largest run of lines whose bytes fit in one read.
            let mut end = line + 1;
            while end < first + count && self.starts[end] - self.starts[line] <= MAX_BLOCK_BYTES {
                end += 1;
            }
            let range = self.starts[line]..self.starts.get(end).copied().unwrap_or(self.len);
            if range.end - range.start > MAX_LINE_BYTES && end == line + 1 {
                return Err(Error::LineTooLong {
                    line,
                    len: range.end - range.start,
                });
            }
            let mut bytes = vec![0u8; usize::try_from(range.end - range.start).unwrap_or(0)];
            let read = read_at(&self.source, range.start, &mut bytes)?;
            bytes.truncate(read);
            for index in line..end {
                let start = usize::try_from(self.starts[index] - range.start).unwrap_or(0);
                let end = self.starts.get(index + 1).map_or(bytes.len(), |next| {
                    usize::try_from(next - range.start).unwrap_or(bytes.len())
                });
                let content = strip_terminator(&bytes[start..end], self.encoding);
                lines.push(encoding::decode(content, self.encoding).0);
            }
            line = end;
        }
        Ok(lines)
    }

    /// One line, decoded without its terminator.
    pub fn read_line(&self, line: usize) -> Result<String, Error> {
        Ok(self.read_lines(line, 1)?.pop().unwrap_or_default())
    }

    /// The text of the lines `first..first + count` with their terminators
    /// normalised to `\n`, for copying.
    pub fn read_text(&self, first: usize, count: usize) -> Result<String, Error> {
        let lines = self.read_lines(first, count)?;
        let mut text = String::new();
        for (offset, line) in lines.iter().enumerate() {
            if offset > 0 {
                text.push('\n');
            }
            text.push_str(line);
        }
        Ok(text)
    }
}

fn read_at(source: &Source, offset: u64, bytes: &mut [u8]) -> io::Result<usize> {
    let mut source = source.clone();
    source.seek(SeekFrom::Start(offset))?;
    let mut filled = 0;
    while filled < bytes.len() {
        let count = source.read(&mut bytes[filled..])?;
        if count == 0 {
            break;
        }
        filled += count;
    }
    Ok(filled)
}

/// The line without its terminator.
fn strip_terminator(bytes: &[u8], encoding: Encoding) -> &[u8] {
    let unit = encoding.unit();
    if bytes.len() < unit {
        return bytes;
    }
    let is = |at: usize, expected: u16| -> bool {
        match encoding {
            Encoding::Utf8 | Encoding::Legacy(_) => bytes[at] as u16 == expected,
            Encoding::Utf16Le => {
                bytes.len() >= at + 2 && u16::from_le_bytes([bytes[at], bytes[at + 1]]) == expected
            }
            Encoding::Utf16Be => {
                bytes.len() >= at + 2 && u16::from_be_bytes([bytes[at], bytes[at + 1]]) == expected
            }
        }
    };
    if is(bytes.len() - unit, u16::from(b'\n')) {
        let before = bytes.len() - 2 * unit;
        return if bytes.len() >= 2 * unit && is(before, u16::from(b'\r')) {
            &bytes[..before]
        } else {
            &bytes[..bytes.len() - unit]
        };
    }
    if is(bytes.len() - unit, u16::from(b'\r')) {
        return &bytes[..bytes.len() - unit];
    }
    bytes
}

/// What one encoded unit is, and how many bytes it occupies.
#[derive(Clone, Copy)]
struct Unit {
    len: usize,
    line_feed: bool,
    carriage_return: bool,
    tab: bool,
    width: u32,
    malformed: bool,
}

impl Unit {
    fn new(len: usize, width: u32, malformed: bool) -> Self {
        Self {
            len,
            line_feed: false,
            carriage_return: false,
            tab: false,
            width,
            malformed,
        }
    }
}

/// Walks a payload's units and records line starts and widths.
struct Indexer<'a> {
    encoding: Encoding,
    starts: Vec<u64>,
    columns: Vec<u32>,
    max_columns: u32,
    malformed: u64,
    /// Absolute offset of the line being measured.
    next_start: u64,
    columns_so_far: u32,
    /// The current line's bytes, for a legacy code page, whose widths are only
    /// known once the line is decoded.
    line_bytes: Vec<u8>,
    cancel: &'a AtomicBool,
}

impl Indexer<'_> {
    fn unit(&self, bytes: &[u8], at: usize) -> Option<Unit> {
        let rest = bytes.get(at..)?;
        match self.encoding {
            Encoding::Utf8 => {
                let lead = *rest.first()?;
                if lead == b'\n' || lead == b'\r' || lead == b'\t' {
                    let mut unit = Unit::new(1, 1, false);
                    unit.line_feed = lead == b'\n';
                    unit.carriage_return = lead == b'\r';
                    unit.tab = lead == b'\t';
                    return Some(unit);
                }
                // The length a well-formed sequence needs, from its lead byte.
                let len = match lead {
                    0x00..=0x7F => 1,
                    0xC2..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    0xF0..=0xF4 => 4,
                    _ => {
                        // A continuation byte or a byte no sequence starts
                        // with.
                        return Some(Unit::new(1, 1, true));
                    }
                };
                if len == 1 {
                    return Some(Unit::new(1, 1, false));
                }
                if rest.len() < len {
                    return None;
                }
                match std::str::from_utf8(&rest[..len]) {
                    Ok(text) => {
                        let c = text.chars().next().unwrap_or('\u{FFFD}');
                        Some(Unit::new(len, column_width(c, 0), false))
                    }
                    Err(_) => Some(Unit::new(1, 1, true)),
                }
            }
            Encoding::Legacy(_) => {
                let byte = *rest.first()?;
                if byte == b'\n' || byte == b'\r' || byte == b'\t' {
                    let mut unit = Unit::new(1, 0, false);
                    unit.line_feed = byte == b'\n';
                    unit.carriage_return = byte == b'\r';
                    unit.tab = byte == b'\t';
                    return Some(unit);
                }
                // One byte, of unknown width until the line is decoded.
                Some(Unit::new(1, 0, false))
            }
            Encoding::Utf16Le | Encoding::Utf16Be => {
                let big_endian = self.encoding == Encoding::Utf16Be;
                let read = |pair: &[u8]| {
                    if big_endian {
                        u16::from_be_bytes([pair[0], pair[1]])
                    } else {
                        u16::from_le_bytes([pair[0], pair[1]])
                    }
                };
                let first = read(rest.get(..2)?);
                if first == 0x0A || first == 0x0D || first == 0x09 {
                    let mut unit = Unit::new(2, 1, false);
                    unit.line_feed = first == 0x0A;
                    unit.carriage_return = first == 0x0D;
                    unit.tab = first == 0x09;
                    return Some(unit);
                }
                if (0xD800..0xDC00).contains(&first) {
                    // A pair is one character; a high surrogate alone is not.
                    let pair = rest.get(2..4);
                    let low = pair.map(read);
                    match low {
                        Some(low) if (0xDC00..0xE000).contains(&low) => {
                            Some(Unit::new(4, 1, false))
                        }
                        Some(_) => Some(Unit::new(2, 1, true)),
                        // The second unit has not been read yet.
                        None => None,
                    }
                } else if (0xDC00..0xE000).contains(&first) {
                    Some(Unit::new(2, 1, true))
                } else {
                    let c = char::from_u32(u32::from(first)).unwrap_or('\u{FFFD}');
                    Some(Unit::new(2, column_width(c, 0), false))
                }
            }
        }
    }

    /// Measures the units in `bytes`, whose first byte is at `offset`.
    /// Returns how many bytes were consumed; the rest needs a later chunk.
    fn feed(&mut self, bytes: &[u8], offset: u64) -> Result<usize, Error> {
        let mut at = 0;
        while at < bytes.len() {
            let Some(unit) = self.unit(bytes, at) else {
                break;
            };
            if unit.carriage_return {
                // CRLF is one terminator, so a CR at the very end needs the
                // next unit before the line can be ended.
                if at + unit.len == bytes.len() {
                    break;
                }
                let next = self.unit(bytes, at + unit.len);
                let mut width = unit.len;
                if next.is_some_and(|next| next.line_feed) {
                    width += next.map_or(0, |next| next.len);
                }
                self.end_line(offset + (at + width) as u64)?;
                at += width;
                continue;
            }
            if unit.line_feed {
                self.end_line(offset + (at + unit.len) as u64)?;
                at += unit.len;
                continue;
            }
            if self.encoding.is_legacy() {
                self.line_bytes.extend_from_slice(&bytes[at..at + unit.len]);
            }
            self.measure(unit);
            at += unit.len;
        }
        Ok(at)
    }

    /// Measures what is left at the end of the payload, where a CR has no unit
    /// after it.
    fn finish(&mut self, bytes: &[u8], offset: u64, len: u64) -> Result<(), Error> {
        let mut at = 0;
        while at < bytes.len() {
            let Some(unit) = self.unit(bytes, at) else {
                break;
            };
            let next = self.unit(bytes, at + unit.len);
            if unit.carriage_return || unit.line_feed {
                let mut width = unit.len;
                if unit.carriage_return && next.is_some_and(|next| next.line_feed) {
                    width += next.map_or(0, |next| next.len);
                }
                self.end_line(offset + (at + width) as u64)?;
                at += width;
                continue;
            }
            if self.encoding.is_legacy() {
                self.line_bytes.extend_from_slice(&bytes[at..at + unit.len]);
            }
            self.measure(unit);
            at += unit.len;
        }
        if at < bytes.len() {
            // A truncated sequence at the very end.
            self.malformed += 1;
        }
        if self.next_start < len {
            self.push_line()?;
        }
        Ok(())
    }

    fn measure(&mut self, unit: Unit) {
        if unit.malformed {
            self.malformed += 1;
        }
        if self.encoding.is_legacy() {
            return;
        }
        if unit.tab {
            self.columns_so_far += TAB_WIDTH - self.columns_so_far % TAB_WIDTH;
        } else {
            self.columns_so_far += unit.width;
        }
    }

    /// Ends the current line, whose content stops before `next_start`, and
    /// starts the next line there.
    fn end_line(&mut self, next_start: u64) -> Result<(), Error> {
        self.push_line()?;
        self.next_start = next_start;
        Ok(())
    }

    fn push_line(&mut self) -> Result<(), Error> {
        if self.starts.len() >= MAX_LINES {
            return Err(Error::TooManyLines {
                found: self.starts.len(),
            });
        }
        if self.starts.len().is_multiple_of(4096) {
            cancelled(self.cancel)?;
        }
        if self.encoding.is_legacy() {
            let (text, errors) = encoding::decode(&self.line_bytes, self.encoding);
            self.malformed += errors as u64;
            self.columns_so_far = display_columns(&text);
            self.line_bytes.clear();
        }
        self.starts.push(self.next_start);
        self.columns.push(self.columns_so_far);
        self.max_columns = self.max_columns.max(self.columns_so_far);
        self.columns_so_far = 0;
        Ok(())
    }
}

/// The columns one character occupies, with tabs advancing to the next stop.
pub fn column_width(c: char, column: u32) -> u32 {
    if c == '\t' {
        TAB_WIDTH - column % TAB_WIDTH
    } else {
        c.width().unwrap_or(0) as u32
    }
}

/// The display columns of `text`, with tabs expanded.
pub fn display_columns(text: &str) -> u32 {
    let mut column = 0;
    for c in text.chars() {
        column += column_width(c, column);
    }
    column
}

/// The display column a byte offset falls on, with tabs expanded.
pub fn column_at_byte(text: &str, byte: usize, tab_width: u32) -> u32 {
    let mut column = 0;
    for (at, c) in text.char_indices() {
        if at >= byte {
            return column;
        }
        column += width_at(c, column, tab_width);
    }
    column
}

/// The byte offset of the character at a display column, or the end of the
/// line when the column is beyond it. A column inside a wide character maps to
/// that character's first byte, and a zero-width character maps to the one it
/// is drawn over.
pub fn byte_index_at_column(text: &str, column: u32, tab_width: u32) -> usize {
    let mut at_column = 0;
    for (at, c) in text.char_indices() {
        let width = width_at(c, at_column, tab_width);
        if width == 0 {
            continue;
        }
        if at_column + width > column {
            return at;
        }
        at_column += width;
    }
    text.len()
}

/// The text shown from `start` columns, taking at most `width` columns.
///
/// The returned string may start before `start` when `start` falls inside a
/// wide character, and the second value is the column it really starts on. A
/// zero-width character at the start of the slice stays with the character it
/// belongs to, which is on the previous row when a line wraps.
pub fn slice_columns(text: &str, start: u32, width: u32) -> (String, u32) {
    let mut from = byte_index_at_column(text, start, TAB_WIDTH);
    if start > 0 {
        while let Some(c) = text[from..].chars().next() {
            if c.width().is_some_and(|width| width == 0) {
                from += c.len_utf8();
            } else {
                break;
            }
        }
    }
    let actual = column_at_byte(text, from, TAB_WIDTH);
    let limit = actual + width;
    let mut slice = String::new();
    let mut column = actual;
    for c in text[from..].chars() {
        if column >= limit {
            break;
        }
        let advance = column_width(c, column);
        slice.push(c);
        column += advance;
    }
    (slice, actual)
}

/// The text as it is shown: tabs replaced by the spaces they advance over.
pub fn expand_tabs(text: &str, tab_width: u32) -> String {
    if !text.contains('\t') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 8);
    let mut column = 0;
    for c in text.chars() {
        if c == '\t' {
            let spaces = tab_width - column % tab_width;
            out.extend(std::iter::repeat_n(' ', spaces as usize));
            column += spaces;
        } else {
            out.push(c);
            column += width_at(c, column, tab_width);
        }
    }
    out
}

fn width_at(c: char, column: u32, tab_width: u32) -> u32 {
    if c == '\t' {
        tab_width - column % tab_width
    } else {
        c.width().unwrap_or(0) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn open(bytes: &[u8], encoding: Encoding) -> Document {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
        let source = Source::open(file.path()).unwrap();
        Document::load(source, encoding, &AtomicBool::new(false), |_, _| {}).unwrap()
    }

    fn lines(document: &Document) -> Vec<String> {
        document.read_lines(0, document.line_count()).unwrap()
    }

    #[test]
    fn lf_crlf_and_cr_end_lines_the_same_way() {
        for bytes in [
            b"a\nb\nc".as_slice(),
            b"a\r\nb\r\nc".as_slice(),
            b"a\rb\rc".as_slice(),
            b"a\r\nb\nc\rd".as_slice(),
        ] {
            let document = open(bytes, Encoding::Utf8);
            let expected: &[&str] = match bytes {
                b"a\r\nb\nc\rd" => &["a", "b", "c", "d"],
                _ => &["a", "b", "c"],
            };
            assert_eq!(lines(&document), expected, "{bytes:?}");
        }
    }

    #[test]
    fn a_final_terminator_does_not_add_an_empty_line() {
        assert_eq!(open(b"a\n", Encoding::Utf8).line_count(), 1);
        assert_eq!(open(b"a", Encoding::Utf8).line_count(), 1);
        assert_eq!(open(b"a\n\n", Encoding::Utf8).line_count(), 2);
        assert_eq!(open(b"", Encoding::Utf8).line_count(), 0);
        assert_eq!(open(b"\n", Encoding::Utf8).line_count(), 1);
    }

    #[test]
    fn byte_order_marks_are_skipped_and_counted() {
        let bytes = b"\xEF\xBB\xBFone\r\ntwo".to_vec();
        let document = open(&bytes, Encoding::Utf8);
        assert_eq!(document.bom_len(), 3);
        assert_eq!(lines(&document), vec!["one", "two"]);

        let mut le = b"\xFF\xFE".to_vec();
        le.extend("one\r\ntwo".encode_utf16().flat_map(u16::to_le_bytes));
        let document = open(&le, Encoding::Utf16Le);
        assert_eq!(lines(&document), vec!["one", "two"]);

        let mut be = b"\xFE\xFF".to_vec();
        be.extend("one\ntwo".encode_utf16().flat_map(u16::to_be_bytes));
        let document = open(&be, Encoding::Utf16Be);
        assert_eq!(lines(&document), vec!["one", "two"]);
    }

    #[test]
    fn a_payload_of_only_a_mark_has_no_lines() {
        let document = open(b"\xEF\xBB\xBF", Encoding::Utf8);
        assert_eq!(document.line_count(), 0);
        assert_eq!(document.bom_len(), 3);
        assert_eq!(document.len(), 3);
        assert_eq!(document.malformed(), 0);
    }

    #[test]
    fn a_short_file_is_one_line() {
        let document = open(b"x", Encoding::Utf8);
        assert_eq!(document.line_count(), 1);
        assert_eq!(document.line_columns(0), 1);
        assert_eq!(document.read_line(0).unwrap(), "x");
    }

    #[test]
    fn utf16_without_a_mark_splits_on_its_own_terminators() {
        let bytes: Vec<u8> = "alpha\r\nbeta"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let document = open(&bytes, Encoding::Utf16Le);
        assert_eq!(lines(&document), vec!["alpha", "beta"]);
    }

    #[test]
    fn columns_expand_tabs() {
        let document = open(b"a\tb\t\tc", Encoding::Utf8);
        // a=1, tab to 4, b=5, tab to 8, tab to 12, c=13.
        assert_eq!(document.line_columns(0), 13);
        assert_eq!(expand_tabs("a\tb\t\tc", TAB_WIDTH), "a   b       c");
    }

    #[test]
    fn columns_map_to_bytes_and_back() {
        assert_eq!(column_at_byte("a\tb", 0, 4), 0);
        assert_eq!(column_at_byte("a\tb", 2, 4), 4);
        assert_eq!(byte_index_at_column("a\tb", 4, 4), 2);
        assert_eq!(byte_index_at_column("a\tb", 9, 4), 3);
        assert_eq!(column_at_byte("héllo", 3, 4), 2);
    }

    #[test]
    fn combining_marks_take_no_column() {
        // "e" followed by U+0301 is one cell.
        let text = "e\u{301}x";
        assert_eq!(display_columns(text), 2);
        assert_eq!(column_at_byte(text, 3, TAB_WIDTH), 1);
        assert_eq!(byte_index_at_column(text, 1, TAB_WIDTH), 3);
        let (slice, start) = slice_columns(text, 1, 1);
        assert_eq!(slice, "x");
        assert_eq!(start, 1);
    }

    #[test]
    fn wide_characters_take_two_columns() {
        let text = "中a";
        assert_eq!(display_columns(text), 3);
        assert_eq!(column_at_byte(text, 3, TAB_WIDTH), 2);
        assert_eq!(byte_index_at_column(text, 1, TAB_WIDTH), 0);
        let (slice, start) = slice_columns(text, 1, 2);
        assert_eq!(slice, "中");
        assert_eq!(start, 0);
    }

    #[test]
    fn slice_columns_reads_only_the_window() {
        let text = "abcdef";
        let (slice, start) = slice_columns(text, 2, 3);
        assert_eq!(slice, "cde");
        assert_eq!(start, 2);
        let (slice, start) = slice_columns(text, 4, 10);
        assert_eq!(slice, "ef");
        assert_eq!(start, 4);
        let (slice, _) = slice_columns(text, 9, 4);
        assert!(slice.is_empty());
    }

    #[test]
    fn a_block_crossing_chunk_boundaries_is_identical() {
        let mut text = String::new();
        for index in 0..20_000 {
            text.push_str(&format!("line {index}\r\n"));
        }
        let document = open(text.as_bytes(), Encoding::Utf8);
        assert_eq!(document.line_count(), 20_000);
        assert_eq!(document.read_line(0).unwrap(), "line 0");
        assert_eq!(document.read_line(19_999).unwrap(), "line 19999");
        let block = document.read_lines(19_990, 5).unwrap();
        assert_eq!(block[0], "line 19990");
        assert_eq!(document.byte_range(0..1).start, 0);
    }

    #[test]
    fn an_odd_utf16_tail_still_counts_its_line() {
        let mut bytes: Vec<u8> = "ab".encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes.push(b'c');
        let document = open(&bytes, Encoding::Utf16Le);
        assert_eq!(document.line_count(), 1);
        let text = document.read_line(0).unwrap();
        assert!(text.starts_with("ab"));
        assert_eq!(document.malformed(), 1);
    }

    #[test]
    fn malformed_sequences_are_counted_wherever_they_are() {
        // A valid prefix followed by an invalid byte far into the payload.
        let mut bytes = vec![b'a'; 100_000];
        bytes.extend_from_slice(b"\nvalid\n");
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        bytes.extend_from_slice(b"\nend\n");
        let document = open(&bytes, Encoding::Utf8);
        assert_eq!(document.line_count(), 4);
        assert!(
            document.malformed() >= 3,
            "three invalid bytes were counted as {}",
            document.malformed()
        );
    }

    #[test]
    fn an_unpaired_utf16_surrogate_is_malformed() {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&[0x00, 0xD8]); // high surrogate alone
        bytes.extend_from_slice(&[0x0A, 0x00]);
        bytes.extend_from_slice(&[0x41, 0x00]);
        let document = open(&bytes, Encoding::Utf16Le);
        assert_eq!(document.malformed(), 1);
        assert_eq!(document.line_count(), 2);
    }

    #[test]
    fn a_legacy_code_page_is_decoded_per_line() {
        // Shift_JIS "\u{3042}" (two bytes, two columns), a tab to column 4, then "x".
        let document = open(
            &[0x82, 0xA0, b'\t', b'x', b'\r', b'\n'],
            Encoding::SHIFT_JIS,
        );
        assert_eq!(document.line_count(), 1);
        assert_eq!(document.line_columns(0), 5);
        assert_eq!(document.read_line(0).unwrap(), "あ\tx");
        assert_eq!(document.malformed(), 0);
    }

    #[test]
    fn the_same_bytes_index_differently_in_two_encodings() {
        let mut bytes = Vec::new();
        bytes.extend("ab\r\ncd".encode_utf16().flat_map(u16::to_le_bytes));
        let utf16 = open(&bytes, Encoding::Utf16Le);
        assert_eq!(utf16.line_count(), 2);
        assert_eq!(utf16.line_columns(0), 2);
        // Read as UTF-8 the same bytes hold NULs and split on the same bytes.
        let utf8 = open(&bytes, Encoding::Utf8);
        assert_ne!(utf8.line_count(), utf16.line_count());
        assert_ne!(utf8.line_columns(0), utf16.line_columns(0));
    }

    #[test]
    fn cancellation_stops_the_pass() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"one\ntwo\n").unwrap();
        let source = Source::open(file.path()).unwrap();
        let cancel = AtomicBool::new(true);
        assert!(matches!(
            Document::load(source, Encoding::Utf8, &cancel, |_, _| {}),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn a_cancelled_block_read_stops() {
        let document = open(b"one\ntwo\n", Encoding::Utf8);
        let cancel = AtomicBool::new(true);
        assert!(matches!(
            document.read_lines_cancellable(0, 2, &cancel),
            Err(Error::Cancelled)
        ));
    }

    #[test]
    fn a_large_payload_is_indexed_and_read_at_its_end() {
        let mut text = String::with_capacity(12 << 20);
        for index in 0..250_000 {
            text.push_str(&format!("line {index} of the payload\n"));
        }
        let document = open(text.as_bytes(), Encoding::Utf8);
        assert_eq!(document.line_count(), 250_000);
        assert_eq!(document.read_line(0).unwrap(), "line 0 of the payload");
        assert_eq!(
            document.read_line(249_999).unwrap(),
            "line 249999 of the payload"
        );
        let block = document.read_lines(123_000, 3).unwrap();
        assert_eq!(block[0], "line 123000 of the payload");
    }

    #[test]
    fn one_long_line_is_one_row_and_reads_whole() {
        let text = "x".repeat(2 << 20);
        let document = open(text.as_bytes(), Encoding::Utf8);
        assert_eq!(document.line_count(), 1);
        assert_eq!(document.line_columns(0), 2 << 20);
        let line = document.read_line(0).unwrap();
        assert_eq!(line.len(), 2 << 20);
    }

    #[test]
    fn a_line_beyond_the_limit_is_refused_not_truncated() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        // One line of MAX_LINE_BYTES + 1 bytes, written without allocating it.
        let chunk = vec![b'x'; 1024 * 1024];
        let mut written = 0u64;
        while written < MAX_LINE_BYTES + 1 {
            std::io::Write::write_all(&mut file, &chunk).unwrap();
            written += chunk.len() as u64;
        }
        let source = Source::open(file.path()).unwrap();
        let document =
            Document::load(source, Encoding::Utf8, &AtomicBool::new(false), |_, _| {}).unwrap();
        assert_eq!(document.line_count(), 1);
        assert!(matches!(
            document.read_line(0),
            Err(Error::LineTooLong { line: 0, .. })
        ));
    }
}
