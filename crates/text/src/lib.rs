//! Read-only text payloads: whether bytes are text, what encoding and language
//! they carry, and line-addressed access to them.
//!
//! Nothing here depends on the desktop framework. A viewer decides what to show;
//! this crate decides what the bytes are and how to read them one line at a
//! time, without loading the payload.
//!
//! The payload's own bytes are the evidence. An extension may name the language
//! of text, and never makes binary data text.

pub mod detect;
pub mod document;
pub mod encoding;
pub mod language;
pub mod search;
pub mod syntax;

pub use detect::{BinaryReason, Detection, TextInfo, detect, guess_encoding};
pub use document::{Document, Error, TAB_WIDTH};
pub use encoding::Encoding;
pub use language::Language;
pub use search::{Cursor, Load, Match, Results, STORE_LIMIT, Step, find};
pub use syntax::{Checkpoints, Span, State, Token, highlight};
