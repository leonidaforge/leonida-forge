//! Syntax highlighting with a lexical state carried from line to line.
//!
//! A line is coloured together with the state the previous line left, so a
//! comment, a template literal or a block scalar keeps its colour on every
//! line it covers. The state is a small value: a caller can store it every few
//! lines and resume from there instead of lexing the document from its start.
//!
//! Spans are byte ranges into the line, in order, and never overlap. Text
//! outside a span is drawn in the default foreground colour.

use crate::language::Language;

/// The kind of a highlighted token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    /// A markup tag name, or a section header.
    Tag,
    /// A property or attribute name.
    Attribute,
    String,
    Comment,
    Number,
    /// A control word of the language.
    Keyword,
    /// A literal such as `true`, `null` or an entity.
    Literal,
    /// Brackets, separators and operators that are given their own colour.
    Punctuation,
}

/// A highlighted byte range of one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub token: Token,
}

/// The lexical state between two lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum State {
    /// No construct is open.
    #[default]
    Plain,
    /// Inside `<!-- -->`.
    MarkupComment,
    /// Inside `<![CDATA[ ]]>`.
    MarkupCdata,
    /// Inside `<? ?>`.
    MarkupDeclaration,
    /// Inside a tag that has not closed yet.
    MarkupTag,
    /// Inside `/* */`.
    BlockComment,
    /// Inside a template literal.
    Template,
    /// Inside a Lua long comment with this many `=` in its brackets.
    LuaLongComment(u8),
    /// Inside a Lua long string with this many `=` in its brackets.
    LuaLongString(u8),
    /// Inside a TOML `"""` string.
    TomlBasic,
    /// Inside a TOML `'''` string.
    TomlLiteral,
    /// Inside a YAML block scalar opened at this indentation.
    YamlScalar { indent: u32 },
}

/// Highlights one line, and returns the state the next line starts with.
pub fn highlight(language: Language, state: State, line: &str) -> (Vec<Span>, State) {
    let mut lexer = Lexer::new(line);
    let state = match language {
        Language::Xml => markup(&mut lexer, false, state),
        Language::Html => markup(&mut lexer, true, state),
        Language::Json => {
            json(&mut lexer);
            State::Plain
        }
        Language::Yaml => yaml(&mut lexer, state),
        Language::Ini => ini(&mut lexer, false, State::Plain),
        Language::Toml => ini(&mut lexer, true, state),
        Language::Csv => {
            csv(&mut lexer);
            State::Plain
        }
        Language::Lua => lua(&mut lexer, state),
        Language::JavaScript => javascript(&mut lexer, state),
        Language::Plain => State::Plain,
    };
    (lexer.spans, state)
}

/// How often a caller should store the state, in lines.
pub const CHECKPOINT_INTERVAL: usize = 512;

/// The states a document has reached at its checkpoints.
///
/// A viewer stores the state at every checkpoint while it lexes, and resolves
/// the state before a far line by starting from the nearest one it knows.
#[derive(Debug, Clone)]
pub struct Checkpoints {
    states: Vec<Option<State>>,
}

impl Default for Checkpoints {
    fn default() -> Self {
        Self::new()
    }
}

impl Checkpoints {
    pub fn new() -> Self {
        Self { states: Vec::new() }
    }

    /// The state at the start of `line`, when `line` is a checkpoint.
    pub fn checkpoint(&mut self, line: usize, state: State) {
        if !line.is_multiple_of(CHECKPOINT_INTERVAL) {
            return;
        }
        let block = line / CHECKPOINT_INTERVAL;
        if self.states.len() <= block {
            self.states.resize(block + 1, None);
        }
        self.states[block] = Some(state);
    }

    /// The nearest checkpoint at or before `line`, and the state there.
    pub fn resolve(&self, line: usize) -> (usize, State) {
        let mut block = line / CHECKPOINT_INTERVAL;
        loop {
            if let Some(Some(state)) = self.states.get(block) {
                return (block * CHECKPOINT_INTERVAL, *state);
            }
            if block == 0 {
                return (0, State::Plain);
            }
            block -= 1;
        }
    }
}

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    at: usize,
    spans: Vec<Span>,
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            at: 0,
            spans: Vec::new(),
        }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.at + offset).copied()
    }

    fn starts_with(&self, pattern: &str) -> bool {
        self.bytes[self.at..].starts_with(pattern.as_bytes())
    }

    /// Advances by one character, never stopping inside one.
    fn bump(&mut self) {
        let len = self.text[self.at..]
            .chars()
            .next()
            .map_or(1, char::len_utf8);
        self.at = (self.at + len).min(self.bytes.len());
    }

    fn bump_bytes(&mut self, count: usize) {
        self.at = (self.at + count).min(self.bytes.len());
    }

    fn consume_rest(&mut self) {
        self.at = self.bytes.len();
    }

    fn skip_while(&mut self, predicate: impl Fn(u8) -> bool) {
        while self.peek().is_some_and(&predicate) {
            self.bump_bytes(1);
        }
    }

    /// Consumes up to and including `terminator`, or to the end of the line.
    fn until(&mut self, terminator: u8) {
        while let Some(byte) = self.peek() {
            self.bump_bytes(1);
            if byte == terminator {
                break;
            }
        }
    }

    /// Consumes up to and including `needle`. False when the line ends first.
    fn until_needle(&mut self, needle: &str) -> bool {
        while !self.done() {
            if self.starts_with(needle) {
                self.bump_bytes(needle.len());
                return true;
            }
            self.bump();
        }
        false
    }

    fn span(&mut self, start: usize, token: Token) {
        if start < self.at {
            self.spans.push(Span {
                start,
                end: self.at,
                token,
            });
        }
    }

    /// A quoted string starting at the current quote, ending at the same quote
    /// or the end of the line.
    fn quoted(&mut self, token: Token) {
        let start = self.at;
        let quote = self.peek().unwrap_or(b'"');
        self.bump_bytes(1);
        while let Some(byte) = self.peek() {
            if byte == b'\\' {
                self.bump_bytes(2);
                continue;
            }
            self.bump_bytes(1);
            if byte == quote {
                break;
            }
        }
        self.span(start, token);
    }

    /// An unescaped `quote`, for constructs that continue on the next line.
    fn unescaped(&mut self, quote: u8) -> bool {
        while let Some(byte) = self.peek() {
            if byte == b'\\' {
                self.bump_bytes(2);
                continue;
            }
            self.bump_bytes(1);
            if byte == quote {
                return true;
            }
        }
        false
    }

    fn number(&mut self) {
        let start = self.at;
        let negative =
            self.peek() == Some(b'-') && self.peek_at(1).is_some_and(|b| b.is_ascii_digit());
        if negative {
            self.bump_bytes(1);
        }
        self.skip_while(|byte| byte.is_ascii_digit());
        if self.peek() == Some(b'.') && self.peek_at(1).is_some_and(|b| b.is_ascii_digit()) {
            self.bump_bytes(1);
            self.skip_while(|byte| byte.is_ascii_digit());
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump_bytes(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump_bytes(1);
            }
            self.skip_while(|byte| byte.is_ascii_digit());
        }
        self.skip_while(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        self.span(start, Token::Number);
    }

    fn word_at(&mut self) -> Option<(usize, &'a str)> {
        let start = self.at;
        self.skip_while(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        let word = self.text.get(start..self.at)?;
        (!word.is_empty()).then_some((start, word))
    }

    /// A word from `keywords` in one colour and from `literals` in another.
    fn keyword(&mut self, keywords: &[&str], literals: &[&str]) {
        let Some((start, word)) = self.word_at() else {
            return;
        };
        if keywords.contains(&word) {
            self.span(start, Token::Keyword);
        } else if literals.contains(&word) {
            self.span(start, Token::Literal);
        }
    }

    fn rest(&self) -> &str {
        &self.text[self.at..]
    }
    /// The indentation of the line, in spaces and tabs.
    fn leading_indent(&self) -> u32 {
        let mut indent = 0;
        for c in self.text.chars() {
            match c {
                ' ' => indent += 1,
                '\t' => indent += 4,
                _ => break,
            }
        }
        indent
    }
}

// ---------------------------------------------------------------- markup

fn markup(lexer: &mut Lexer<'_>, html: bool, mut state: State) -> State {
    loop {
        match state {
            State::MarkupComment => {
                let start = lexer.at;
                if lexer.until_needle("-->") {
                    lexer.span(start, Token::Comment);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::Comment);
                    return State::MarkupComment;
                }
            }
            State::MarkupCdata => {
                let start = lexer.at;
                if lexer.until_needle("]]>") {
                    lexer.span(start, Token::Literal);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::Literal);
                    return State::MarkupCdata;
                }
            }
            State::MarkupDeclaration => {
                let start = lexer.at;
                if lexer.until_needle("?>") {
                    lexer.span(start, Token::Comment);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::Comment);
                    return State::MarkupDeclaration;
                }
            }
            State::MarkupTag => {
                if tag_body(lexer, html) {
                    state = State::Plain;
                } else {
                    return State::MarkupTag;
                }
            }
            _ => {
                while !lexer.done() {
                    if lexer.starts_with("<!--") {
                        let start = lexer.at;
                        lexer.bump_bytes(4);
                        if lexer.until_needle("-->") {
                            lexer.span(start, Token::Comment);
                        } else {
                            lexer.span(start, Token::Comment);
                            return State::MarkupComment;
                        }
                        continue;
                    }
                    if lexer.starts_with("<![CDATA[") {
                        let start = lexer.at;
                        lexer.bump_bytes(9);
                        if lexer.until_needle("]]>") {
                            lexer.span(start, Token::Literal);
                        } else {
                            lexer.span(start, Token::Literal);
                            return State::MarkupCdata;
                        }
                        continue;
                    }
                    if lexer.starts_with("<?") {
                        let start = lexer.at;
                        lexer.bump_bytes(2);
                        if lexer.until_needle("?>") {
                            lexer.span(start, Token::Comment);
                        } else {
                            lexer.span(start, Token::Comment);
                            return State::MarkupDeclaration;
                        }
                        continue;
                    }
                    match lexer.peek() {
                        Some(b'<') => {
                            if !tag(lexer, html) {
                                return State::MarkupTag;
                            }
                        }
                        Some(b'&') => entity(lexer),
                        Some(b'>') => {
                            let start = lexer.at;
                            lexer.bump_bytes(1);
                            lexer.span(start, Token::Punctuation);
                        }
                        _ => lexer.bump(),
                    }
                }
                return State::Plain;
            }
        }
    }
}

/// A tag from `<` to its closing `>`. False when the tag continues on the next
/// line.
fn tag(lexer: &mut Lexer<'_>, html: bool) -> bool {
    lexer.bump_bytes(1);
    if matches!(lexer.peek(), Some(b'/' | b'!' | b'?')) {
        lexer.bump_bytes(1);
    }
    let name_start = lexer.at;
    lexer.skip_while(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
    });
    let name = lexer
        .text
        .get(name_start..lexer.at)
        .unwrap_or_default()
        .to_string();
    if !name.is_empty() {
        lexer.span(name_start, Token::Tag);
        if html {
            let attribute = name.to_ascii_lowercase();
            if matches!(attribute.as_str(), "script" | "style") {
                // The body of these is not markup; leave it uncoloured so a
                // `<` inside a script does not start a tag.
                while !lexer.done() && lexer.peek() != Some(b'>') {
                    lexer.bump();
                }
            }
        }
    }
    tag_body(lexer, html)
}

/// The attributes of a tag, from the current position to its `>`.
fn tag_body(lexer: &mut Lexer<'_>, _html: bool) -> bool {
    while !lexer.done() {
        match lexer.peek() {
            Some(b'>') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
                return true;
            }
            Some(b'/') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
            }
            Some(b'=') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
            }
            Some(b'"' | b'\'') => lexer.quoted(Token::String),
            Some(byte) if byte.is_ascii_whitespace() => lexer.bump_bytes(1),
            Some(_) => {
                let start = lexer.at;
                lexer.skip_while(|byte| {
                    !byte.is_ascii_whitespace()
                        && !matches!(byte, b'=' | b'>' | b'/' | b'"' | b'\'')
                });
                if lexer.at == start {
                    lexer.bump();
                } else {
                    lexer.span(start, Token::Attribute);
                }
            }
            None => return false,
        }
    }
    false
}

/// `&name;` and `&#123;` in markup text.
fn entity(lexer: &mut Lexer<'_>) {
    let start = lexer.at;
    lexer.bump_bytes(1);
    lexer.skip_while(|byte| byte.is_ascii_alphanumeric() || byte == b'#');
    if lexer.peek() == Some(b';') {
        lexer.bump_bytes(1);
    }
    lexer.span(start, Token::Literal);
}

// ---------------------------------------------------------------- json

fn json(lexer: &mut Lexer<'_>) {
    while !lexer.done() {
        match lexer.peek() {
            Some(b'"') => {
                let start = lexer.at;
                lexer.quoted(Token::String);
                let mut look = lexer.at;
                while lexer.bytes.get(look) == Some(&b' ') {
                    look += 1;
                }
                if lexer.bytes.get(look) == Some(&b':')
                    && let Some(span) = lexer.spans.last_mut().filter(|span| span.start == start)
                {
                    // A string followed by a colon is a key.
                    span.token = Token::Attribute;
                }
            }
            Some(b'-' | b'0'..=b'9') => lexer.number(),
            Some(b't' | b'f' | b'n') => lexer.keyword(&[], &["true", "false", "null"]),
            Some(byte) if byte.is_ascii_alphabetic() => lexer.bump(),
            Some(b'{' | b'}' | b'[' | b']' | b',' | b':') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
            }
            _ => lexer.bump(),
        }
    }
}

// ---------------------------------------------------------------- yaml

fn yaml(lexer: &mut Lexer<'_>, state: State) -> State {
    if let State::YamlScalar { indent } = state {
        let blank = lexer.rest().trim().is_empty();
        if blank {
            // A blank line belongs to the scalar and ends nothing.
            return state;
        }
        let line_indent = lexer.leading_indent();
        if line_indent > indent {
            let start = lexer.at;
            lexer.consume_rest();
            lexer.span(start, Token::String);
            return state;
        }
    }
    let mut open_scalar = None;
    let line_indent = lexer.leading_indent();
    let mut at_line_start = true;
    while !lexer.done() {
        match lexer.peek() {
            Some(b'#') => {
                let start = lexer.at;
                lexer.consume_rest();
                lexer.span(start, Token::Comment);
            }
            Some(b'"' | b'\'') => lexer.quoted(Token::String),
            Some(b'-') if lexer.peek_at(1).is_none_or(|b| b == b' ' || b == b'\t') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
            }
            Some(b'-' | b'0'..=b'9') => lexer.number(),
            Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => {
                if at_line_start {
                    at_line_start = false;
                    let start = lexer.at;
                    lexer.skip_while(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b' ')
                    });
                    let mut look = lexer.at;
                    while lexer.bytes.get(look) == Some(&b' ') {
                        look += 1;
                    }
                    if lexer.bytes.get(look) == Some(&b':') {
                        lexer.span(start, Token::Attribute);
                        let value = lexer.text.get(look + 1..).unwrap_or("").trim();
                        if is_block_scalar(value) {
                            open_scalar = Some(line_indent);
                        }
                    }
                } else {
                    lexer.keyword(&[], &["true", "false", "null", "yes", "no"]);
                }
            }
            _ => {
                if !lexer.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
                    at_line_start = false;
                }
                lexer.bump();
            }
        }
    }
    match open_scalar {
        Some(indent) => State::YamlScalar { indent },
        None => State::Plain,
    }
}

/// Whether a YAML value opens a block scalar (`|`, `>`, with an optional
/// chomping or indentation indicator).
fn is_block_scalar(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('|' | '>'))
        && chars.all(|c| c == '+' || c == '-' || c.is_ascii_digit() || c == ' ' || c == '#')
}

// ---------------------------------------------------------------- ini and toml

fn ini(lexer: &mut Lexer<'_>, toml: bool, state: State) -> State {
    let mut state = state;
    loop {
        match state {
            State::TomlBasic | State::TomlLiteral => {
                let close = if state == State::TomlBasic {
                    "\"\"\""
                } else {
                    "'''"
                };
                let start = lexer.at;
                if lexer.until_needle(close) {
                    lexer.span(start, Token::String);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::String);
                    return state;
                }
            }
            _ => {
                while !lexer.done() {
                    match lexer.peek() {
                        Some(b'#') => {
                            let start = lexer.at;
                            lexer.consume_rest();
                            lexer.span(start, Token::Comment);
                        }
                        Some(b';') if !toml => {
                            let start = lexer.at;
                            lexer.consume_rest();
                            lexer.span(start, Token::Comment);
                        }
                        Some(b'[') => {
                            let start = lexer.at;
                            lexer.until(b']');
                            lexer.span(start, Token::Tag);
                        }
                        Some(b'"' | b'\'') if toml && lexer.starts_with("\"\"\"") => {
                            let start = lexer.at;
                            lexer.bump_bytes(3);
                            if lexer.until_needle("\"\"\"") {
                                lexer.span(start, Token::String);
                            } else {
                                lexer.span(start, Token::String);
                                return State::TomlBasic;
                            }
                        }
                        Some(b'"' | b'\'') if toml && lexer.starts_with("'''") => {
                            let start = lexer.at;
                            lexer.bump_bytes(3);
                            if lexer.until_needle("'''") {
                                lexer.span(start, Token::String);
                            } else {
                                lexer.span(start, Token::String);
                                return State::TomlLiteral;
                            }
                        }
                        Some(b'"' | b'\'') => lexer.quoted(Token::String),
                        Some(b'-' | b'0'..=b'9') => lexer.number(),
                        Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => {
                            // A name directly before `=` is a key; a bare word
                            // is a value.
                            let start = lexer.at;
                            lexer.skip_while(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                            });
                            let mut look = lexer.at;
                            while lexer.bytes.get(look) == Some(&b' ') {
                                look += 1;
                            }
                            if lexer.bytes.get(look) == Some(&b'=') {
                                lexer.span(start, Token::Attribute);
                            } else {
                                lexer.spans.push(Span {
                                    start,
                                    end: lexer.at,
                                    token: Token::Literal,
                                });
                            }
                        }
                        Some(b'=') => {
                            let start = lexer.at;
                            lexer.bump_bytes(1);
                            lexer.span(start, Token::Punctuation);
                        }
                        _ => lexer.bump(),
                    }
                }
                return State::Plain;
            }
        }
    }
}

// ---------------------------------------------------------------- csv

fn csv(lexer: &mut Lexer<'_>) {
    while !lexer.done() {
        match lexer.peek() {
            Some(b'"' | b'\'') => lexer.quoted(Token::String),
            Some(b',' | b'\t' | b';') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
            }
            _ => lexer.bump(),
        }
    }
}

// ---------------------------------------------------------------- lua

const LUA_KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "for", "function", "goto", "if", "in", "local",
    "not", "or", "repeat", "return", "then", "until", "while",
];
const LUA_LITERALS: &[&str] = &["true", "false", "nil"];

/// The number of `=` inside a Lua long bracket starting at the current `[`.
fn long_bracket(lexer: &Lexer<'_>) -> Option<u8> {
    let rest = lexer.rest().as_bytes();
    if rest.first() != Some(&b'[') {
        return None;
    }
    let equals = rest[1..].iter().take_while(|byte| **byte == b'=').count();
    if rest.get(1 + equals) == Some(&b'[') {
        u8::try_from(equals).ok()
    } else {
        None
    }
}

fn long_bracket_close(level: u8) -> String {
    let mut close = String::from("]");
    close.extend(std::iter::repeat_n('=', level as usize));
    close.push(']');
    close
}

fn lua(lexer: &mut Lexer<'_>, state: State) -> State {
    let mut state = state;
    'states: loop {
        match state {
            State::LuaLongComment(level) => {
                let start = lexer.at;
                let close = long_bracket_close(level);
                if lexer.until_needle(&close) {
                    lexer.span(start, Token::Comment);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::Comment);
                    return state;
                }
            }
            State::LuaLongString(level) => {
                let start = lexer.at;
                let close = long_bracket_close(level);
                if lexer.until_needle(&close) {
                    lexer.span(start, Token::String);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::String);
                    return state;
                }
            }
            _ => {
                while !lexer.done() {
                    if lexer.starts_with("--") {
                        let start = lexer.at;
                        lexer.bump_bytes(2);
                        if let Some(level) = long_bracket(lexer) {
                            lexer.bump_bytes(2 + level as usize);
                            state = State::LuaLongComment(level);
                            continue 'states;
                        }
                        lexer.consume_rest();
                        lexer.span(start, Token::Comment);
                        continue;
                    }
                    if let Some(level) = long_bracket(lexer) {
                        lexer.bump_bytes(2 + level as usize);
                        state = State::LuaLongString(level);
                        continue 'states;
                    }
                    match lexer.peek() {
                        Some(b'"' | b'\'') => lexer.quoted(Token::String),
                        Some(b'0'..=b'9') => lexer.number(),
                        Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => {
                            lexer.keyword(LUA_KEYWORDS, LUA_LITERALS)
                        }
                        _ => lexer.bump(),
                    }
                }
                return State::Plain;
            }
        }
    }
}

// ---------------------------------------------------------------- javascript

const JS_KEYWORDS: &[&str] = &[
    "async",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "default",
    "delete",
    "do",
    "else",
    "export",
    "extends",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "let",
    "new",
    "of",
    "return",
    "static",
    "switch",
    "this",
    "throw",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "yield",
];
const JS_LITERALS: &[&str] = &["true", "false", "null", "undefined"];

fn javascript(lexer: &mut Lexer<'_>, state: State) -> State {
    let mut state = state;
    loop {
        match state {
            State::BlockComment => {
                let start = lexer.at;
                if lexer.until_needle("*/") {
                    lexer.span(start, Token::Comment);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::Comment);
                    return state;
                }
            }
            State::Template => {
                let start = lexer.at;
                if lexer.unescaped(b'`') {
                    lexer.span(start, Token::String);
                    state = State::Plain;
                } else {
                    lexer.span(start, Token::String);
                    return state;
                }
            }
            _ => {
                while !lexer.done() {
                    if lexer.starts_with("//") {
                        let start = lexer.at;
                        lexer.consume_rest();
                        lexer.span(start, Token::Comment);
                        continue;
                    }
                    if lexer.starts_with("/*") {
                        let start = lexer.at;
                        lexer.bump_bytes(2);
                        if lexer.until_needle("*/") {
                            lexer.span(start, Token::Comment);
                        } else {
                            lexer.span(start, Token::Comment);
                            return State::BlockComment;
                        }
                        continue;
                    }
                    match lexer.peek() {
                        Some(b'"' | b'\'') => lexer.quoted(Token::String),
                        Some(b'`') => {
                            let start = lexer.at;
                            lexer.bump_bytes(1);
                            if lexer.unescaped(b'`') {
                                lexer.span(start, Token::String);
                            } else {
                                lexer.span(start, Token::String);
                                return State::Template;
                            }
                        }
                        Some(b'0'..=b'9') => lexer.number(),
                        Some(byte)
                            if byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$' =>
                        {
                            lexer.keyword(JS_KEYWORDS, JS_LITERALS)
                        }
                        _ => lexer.bump(),
                    }
                }
                return State::Plain;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(language: Language, state: State, line: &str) -> (Vec<(Token, String)>, State) {
        let (spans, state) = highlight(language, state, line);
        (
            spans
                .into_iter()
                .map(|span| (span.token, line[span.start..span.end].to_string()))
                .collect(),
            state,
        )
    }

    fn one(language: Language, line: &str) -> Vec<(Token, String)> {
        tokens(language, State::Plain, line).0
    }

    #[test]
    fn spans_are_ordered_inside_the_line() {
        for (language, line) in [
            (Language::Xml, "<a b=\"c\">text &amp; </a>"),
            (Language::Json, "{\"key\": [1, true, null]}"),
            (Language::Lua, "local x = 'a' -- note"),
            (Language::JavaScript, "const x = `t`; // note"),
            (Language::Ini, "[s]\nkey = \"v\""),
            (Language::Csv, "a,\"b\",c"),
        ] {
            let (spans, _) = highlight(language, State::Plain, line);
            let mut last = 0;
            for span in spans {
                assert!(span.start >= last, "{language:?} {line:?}");
                assert!(span.end > span.start, "{language:?} {line:?}");
                assert!(span.end <= line.len(), "{language:?} {line:?}");
                assert!(line.is_char_boundary(span.start));
                assert!(line.is_char_boundary(span.end));
                last = span.end;
            }
        }
    }

    #[test]
    fn xml_names_tags_attributes_and_strings() {
        let found = one(Language::Xml, "<Root name=\"value\">text</Root>");
        assert!(found.contains(&(Token::Tag, "Root".to_string())));
        assert!(found.contains(&(Token::Attribute, "name".to_string())));
        assert!(found.contains(&(Token::String, "\"value\"".to_string())));
    }

    #[test]
    fn json_separates_keys_from_values() {
        let found = one(Language::Json, "{\"key\": \"value\", \"n\": 12}");
        assert!(found.contains(&(Token::Attribute, "\"key\"".to_string())));
        assert!(found.contains(&(Token::String, "\"value\"".to_string())));
        assert!(found.contains(&(Token::Number, "12".to_string())));
    }

    #[test]
    fn comments_run_to_the_end_of_the_line() {
        let found = one(Language::Lua, "x = 1 -- why");
        assert_eq!(found.last(), Some(&(Token::Comment, "-- why".to_string())));
        let found = one(Language::JavaScript, "// note");
        assert_eq!(found, vec![(Token::Comment, "// note".to_string())]);
    }

    #[test]
    fn unterminated_strings_stop_at_the_line_end() {
        let found = one(Language::Lua, "x = 'unfinished");
        assert_eq!(
            found.last(),
            Some(&(Token::String, "'unfinished".to_string()))
        );
    }

    #[test]
    fn ini_highlights_sections_and_keys() {
        let found = one(Language::Ini, "value = 0.5");
        assert!(found.contains(&(Token::Attribute, "value".to_string())));
        assert!(found.contains(&(Token::Number, "0.5".to_string())));
        let found = one(Language::Ini, "[sound]");
        assert_eq!(found, vec![(Token::Tag, "[sound]".to_string())]);
    }

    #[test]
    fn an_xml_comment_carries_across_lines() {
        let (found, state) = tokens(Language::Xml, State::Plain, "text <!-- open");
        assert_eq!(found.last().unwrap().0, Token::Comment);
        assert_eq!(state, State::MarkupComment);
        let (found, state) = tokens(Language::Xml, state, "still a comment");
        assert_eq!(found, vec![(Token::Comment, "still a comment".to_string())]);
        assert_eq!(state, State::MarkupComment);
        let (found, state) = tokens(Language::Xml, state, "close --> <a>");
        assert_eq!(found[0], (Token::Comment, "close -->".to_string()));
        assert!(found.contains(&(Token::Tag, "a".to_string())));
        assert_eq!(state, State::Plain);
    }

    #[test]
    fn a_tag_that_spans_lines_stays_a_tag() {
        let (_, state) = tokens(Language::Xml, State::Plain, "<a");
        assert_eq!(state, State::MarkupTag);
        let (found, state) = tokens(Language::Xml, state, "  b=\"1\"");
        assert_eq!(
            found,
            vec![
                (Token::Attribute, "b".to_string()),
                (Token::Punctuation, "=".to_string()),
                (Token::String, "\"1\"".to_string())
            ]
        );
        assert_eq!(state, State::MarkupTag);
        let (_, state) = tokens(Language::Xml, state, ">");
        assert_eq!(state, State::Plain);
    }

    #[test]
    fn a_js_block_comment_carries_across_lines() {
        let (_, state) = tokens(Language::JavaScript, State::Plain, "let a = 1; /* open");
        assert_eq!(state, State::BlockComment);
        let (found, state) = tokens(Language::JavaScript, state, " middle");
        assert_eq!(found, vec![(Token::Comment, " middle".to_string())]);
        assert_eq!(state, State::BlockComment);
        let (found, state) = tokens(Language::JavaScript, state, "end */ let b = 2;");
        assert_eq!(found[0], (Token::Comment, "end */".to_string()));
        assert_eq!(state, State::Plain);
    }

    #[test]
    fn a_js_template_literal_carries_across_lines() {
        let (_, state) = tokens(Language::JavaScript, State::Plain, "const t = `line one");
        assert_eq!(state, State::Template);
        let (found, state) = tokens(Language::JavaScript, state, "line two");
        assert_eq!(found, vec![(Token::String, "line two".to_string())]);
        assert_eq!(state, State::Template);
        let (_, state) = tokens(Language::JavaScript, state, "last`;");
        assert_eq!(state, State::Plain);
    }

    #[test]
    fn a_lua_long_comment_and_string_carry_across_lines() {
        let (_, state) = tokens(Language::Lua, State::Plain, "--[[ open");
        assert_eq!(state, State::LuaLongComment(0));
        let (found, state) = tokens(Language::Lua, state, "inside");
        assert_eq!(found, vec![(Token::Comment, "inside".to_string())]);
        assert_eq!(state, State::LuaLongComment(0));
        let (_, state) = tokens(Language::Lua, state, "]] local s = [[open");
        assert_eq!(state, State::LuaLongString(0));
        let (found, state) = tokens(Language::Lua, state, "body");
        assert_eq!(found, vec![(Token::String, "body".to_string())]);
        let (_, state) = tokens(Language::Lua, state, "]]");
        assert_eq!(state, State::Plain);
    }

    #[test]
    fn a_lua_long_string_with_equals_uses_its_own_close() {
        let (_, state) = tokens(Language::Lua, State::Plain, "s = [==[open");
        assert_eq!(state, State::LuaLongString(2));
        let (found, state) = tokens(Language::Lua, state, "still ]] inside");
        assert_eq!(found, vec![(Token::String, "still ]] inside".to_string())]);
        assert_eq!(state, State::LuaLongString(2));
        let (_, state) = tokens(Language::Lua, state, "done]==]");
        assert_eq!(state, State::Plain);
    }

    #[test]
    fn a_toml_multiline_string_carries_across_lines() {
        let (_, state) = tokens(Language::Toml, State::Plain, "text = \"\"\"open");
        assert_eq!(state, State::TomlBasic);
        let (found, state) = tokens(Language::Toml, state, "inside");
        assert_eq!(found, vec![(Token::String, "inside".to_string())]);
        let (_, state) = tokens(Language::Toml, state, "close\"\"\"");
        assert_eq!(state, State::Plain);

        let (_, state) = tokens(Language::Toml, State::Plain, "raw = '''open");
        assert_eq!(state, State::TomlLiteral);
        let (_, state) = tokens(Language::Toml, state, "close'''");
        assert_eq!(state, State::Plain);
    }

    #[test]
    fn a_yaml_block_scalar_covers_its_indented_lines() {
        let (_, state) = tokens(Language::Yaml, State::Plain, "text: |");
        assert_eq!(state, State::YamlScalar { indent: 0 });
        let (found, state) = tokens(Language::Yaml, state, "  first line");
        assert_eq!(found, vec![(Token::String, "  first line".to_string())]);
        assert_eq!(state, State::YamlScalar { indent: 0 });
        let (found, state) = tokens(Language::Yaml, state, "");
        assert_eq!(found, Vec::new());
        assert_eq!(state, State::YamlScalar { indent: 0 });
        let (found, state) = tokens(Language::Yaml, state, "next: value");
        assert_eq!(state, State::Plain);
        assert!(found.contains(&(Token::Attribute, "next".to_string())));
    }

    #[test]
    fn checkpoints_resolve_to_the_nearest_known_state() {
        let mut checkpoints = Checkpoints::new();
        assert_eq!(checkpoints.resolve(10_000), (0, State::Plain));
        checkpoints.checkpoint(0, State::Plain);
        checkpoints.checkpoint(512, State::BlockComment);
        checkpoints.checkpoint(1024, State::Plain);
        assert_eq!(checkpoints.resolve(600), (512, State::BlockComment));
        assert_eq!(checkpoints.resolve(513), (512, State::BlockComment));
        assert_eq!(checkpoints.resolve(2048), (1024, State::Plain));
        assert_eq!(checkpoints.resolve(511), (0, State::Plain));
        // A line that is not a checkpoint is not stored.
        checkpoints.checkpoint(513, State::Template);
        assert_eq!(checkpoints.resolve(513), (512, State::BlockComment));
    }
}
