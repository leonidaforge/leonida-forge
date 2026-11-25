//! The GFx container: `GFX`, a version byte, a length, an SWF header and a
//! stream of tags.
//!
//! The grammar is the one the research validated on the 49-payload sample
//! (GFX-F01 to GFX-F12): version 42, a little-endian `u32` that equals the
//! payload length, a bit-packed RECT whose size follows its first byte, an
//! 8.8 fixed-point frame rate, a frame count and then tag records. Code 1 is
//! ShowFrame and code 0 is End; both are zero-length in the sample.
//!
//! Only tag 39 has a body this module walks: two `u16` values and a nested
//! record stream. Every other body is kept as a bounded opaque range. Nothing
//! here interprets tag contents, frame playback or ActionScript.

#[cfg(test)]
mod tests;

use std::fmt;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

/// The three bytes the payload starts with.
pub const MAGIC: [u8; 3] = *b"GFX";
/// The only version whose grammar is established.
pub const VERSION: u8 = 42;
/// ShowFrame.
pub const SHOW_FRAME: u16 = 1;
/// End.
pub const END: u16 = 0;
/// The tag whose body holds another record stream.
pub const NESTED_TAG: u16 = 39;
/// Bytes before a nested record stream inside tag 39.
const NESTED_PREFIX_LEN: usize = 4;

/// Whether `head` starts with the GFx identifier. The version byte is
/// separate: `GFX*` is not a four-byte signature.
pub fn is_gfx(head: &[u8]) -> bool {
    head.starts_with(&MAGIC)
}

/// Whether `head` is the version-42 form this module parses.
pub fn is_version_42(head: &[u8]) -> bool {
    head.get(..4)
        .is_some_and(|head| head[..3] == MAGIC && head[3] == VERSION)
}

/// Why a payload could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The bytes do not start with `GFX`.
    NotGfx,
    /// The payload ends before a header field does.
    TooShort,
    /// The version byte is not 42.
    UnsupportedVersion,
    /// The declared length differs from the payload length.
    Length,
    /// A RECT or tag overruns the payload.
    Truncated,
    /// The tag walk ends before an End tag, or End is not the last record.
    Unterminated,
    /// The nesting depth or tag count limit was reached.
    Limit,
    Cancelled,
}

/// A parse failure and the offset it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
    pub message: String,
}

impl Error {
    fn new(kind: ErrorKind, offset: usize, message: impl Into<String>) -> Self {
        Self {
            kind,
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}: {}", self.offset, self.message)
    }
}

impl std::error::Error for Error {}

/// Caps one parse.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Nesting depth of tag-39 record streams. The top-level stream is 0.
    pub max_depth: usize,
    /// Every record, nested ones included.
    pub max_tags: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_tags: 1 << 20,
        }
    }
}

/// The container header and the SWF frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    /// The `u32` at `+0x04`, which must equal the payload length.
    pub declared_len: u32,
    /// Bytes of the RECT, from its first byte.
    pub rect_len: usize,
    /// `RECT byte 0 >> 3`.
    pub nbits: u8,
    /// Little-endian `u16` in 8.8 fixed point.
    pub frame_rate: u16,
    pub frame_count: u16,
    /// Offset of the first tag.
    pub tag_start: usize,
}

/// One tag record. Bodies of tags other than [`NESTED_TAG`] are opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub code: u16,
    pub length: u32,
    /// Offset of the record's header.
    pub offset: usize,
    /// The body range.
    pub body: Range<usize>,
    /// How deep the record sits: 0 for the top-level stream.
    pub depth: usize,
}

/// A parsed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub header: Header,
    /// Every record, top-level first, then nested records in walk order.
    pub tags: Vec<Tag>,
    /// Records in the top-level stream.
    pub top_level: usize,
    pub max_depth: usize,
    /// Offset the walk reached, which must equal the payload length.
    pub end: usize,
}

/// Parses a version-42 payload. The walk must end exactly at the payload end,
/// after a zero-length End tag.
pub fn parse(bytes: &[u8], limits: &Limits, cancel: &AtomicBool) -> Result<Document, Error> {
    if !is_gfx(bytes) {
        return Err(Error::new(ErrorKind::NotGfx, 0, "not a GFx payload"));
    }
    if bytes.len() < 4 {
        return Err(Error::new(
            ErrorKind::TooShort,
            bytes.len(),
            "the payload ends before its version byte",
        ));
    }
    let version = bytes[3];
    if version != VERSION {
        return Err(Error::new(
            ErrorKind::UnsupportedVersion,
            3,
            format!("version {version} is not the supported {VERSION}"),
        ));
    }
    if bytes.len() < 8 {
        return Err(Error::new(
            ErrorKind::TooShort,
            bytes.len(),
            "the payload ends before its declared length",
        ));
    }
    let declared_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if u64::from(declared_len) != bytes.len() as u64 {
        return Err(Error::new(
            ErrorKind::Length,
            4,
            format!(
                "the declared length {declared_len} differs from the payload length {}",
                bytes.len()
            ),
        ));
    }
    let rect_at = 8;
    let first = bytes[rect_at];
    let nbits = first >> 3;
    let rect_len = (5 + 4 * usize::from(nbits)).div_ceil(8);
    let frame_at = rect_at + rect_len;
    if frame_at + 4 > bytes.len() {
        return Err(Error::new(
            ErrorKind::Truncated,
            rect_at,
            format!(
                "the {rect_len}-byte RECT and the frame header overrun the {} byte payload",
                bytes.len()
            ),
        ));
    }
    let header = Header {
        version,
        declared_len,
        rect_len,
        nbits,
        frame_rate: u16::from_le_bytes([bytes[frame_at], bytes[frame_at + 1]]),
        frame_count: u16::from_le_bytes([bytes[frame_at + 2], bytes[frame_at + 3]]),
        tag_start: frame_at + 4,
    };

    let mut walker = Walker {
        bytes,
        limits: *limits,
        cancel,
        tags: Vec::new(),
        top_level: 0,
        max_depth: 0,
    };
    let end = walker.stream(header.tag_start, bytes.len(), 0, true)?;
    if end != bytes.len() {
        return Err(Error::new(
            ErrorKind::Unterminated,
            end,
            format!("{} bytes follow the last tag", bytes.len() - end),
        ));
    }
    let Some(last) = walker.tags.iter().rev().find(|tag| tag.depth == 0) else {
        return Err(Error::new(
            ErrorKind::Unterminated,
            header.tag_start,
            "the payload holds no tag",
        ));
    };
    if last.code != END || last.length != 0 {
        return Err(Error::new(
            ErrorKind::Unterminated,
            last.offset,
            format!(
                "the last top-level tag is code {} of {} bytes, not a zero-length End tag",
                last.code, last.length
            ),
        ));
    }
    Ok(Document {
        header,
        tags: walker.tags,
        top_level: walker.top_level,
        max_depth: walker.max_depth,
        end,
    })
}

struct Walker<'a> {
    bytes: &'a [u8],
    limits: Limits,
    cancel: &'a AtomicBool,
    tags: Vec<Tag>,
    top_level: usize,
    max_depth: usize,
}

impl<'a> Walker<'a> {
    /// Walks records in `[start, end)`. `top` marks the top-level stream,
    /// which ends at the payload end instead of at an End tag.
    fn stream(
        &mut self,
        start: usize,
        end: usize,
        depth: usize,
        top: bool,
    ) -> Result<usize, Error> {
        if depth > self.limits.max_depth {
            return Err(Error::new(
                ErrorKind::Limit,
                start,
                format!(
                    "records nest deeper than the {} level limit",
                    self.limits.max_depth
                ),
            ));
        }
        self.max_depth = self.max_depth.max(depth);
        let mut pos = start;
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(Error::new(ErrorKind::Cancelled, pos, "cancelled"));
            }
            if pos == end {
                return Ok(pos);
            }
            if end - pos < 2 {
                return Err(Error::new(
                    ErrorKind::Truncated,
                    pos,
                    "the tag header is truncated",
                ));
            }
            if self.tags.len() >= self.limits.max_tags {
                return Err(Error::new(
                    ErrorKind::Limit,
                    pos,
                    format!("the payload holds more than {} tags", self.limits.max_tags),
                ));
            }
            let record_offset = pos;
            let word = u16::from_le_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            pos += 2;
            let code = word >> 6;
            let short_len = usize::from(word & 0x3F);
            let length = if short_len == 0x3F {
                if end - pos < 4 {
                    return Err(Error::new(
                        ErrorKind::Truncated,
                        record_offset,
                        "the extended tag length is truncated",
                    ));
                }
                let value = u32::from_le_bytes([
                    self.bytes[pos],
                    self.bytes[pos + 1],
                    self.bytes[pos + 2],
                    self.bytes[pos + 3],
                ]);
                pos += 4;
                value
            } else {
                short_len as u32
            };
            let body_start = pos;
            let body_end = body_start
                .checked_add(length as usize)
                .filter(|&body_end| body_end <= end)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Truncated,
                        record_offset,
                        format!(
                            "tag {code} declares {length} bytes, more than the {} left",
                            end - body_start
                        ),
                    )
                })?;
            self.tags.push(Tag {
                code,
                length,
                offset: record_offset,
                body: body_start..body_end,
                depth,
            });
            if top && depth == 0 {
                self.top_level += 1;
            }
            pos = body_end;
            if code == NESTED_TAG && length as usize >= NESTED_PREFIX_LEN {
                // Two u16 values, then a record stream that must fill the
                // body.
                let nested_start = body_start + NESTED_PREFIX_LEN;
                let nested_end = self.stream(nested_start, body_end, depth + 1, false)?;
                if nested_end != body_end {
                    return Err(Error::new(
                        ErrorKind::Unterminated,
                        nested_end,
                        "the nested record stream does not fill its tag body",
                    ));
                }
            }
            if !top && code == END && length == 0 {
                return Ok(pos);
            }
        }
    }
}
