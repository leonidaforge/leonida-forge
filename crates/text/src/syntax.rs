//! Line-local syntax highlighting.
//!
//! Each line is coloured on its own. A comment or string that spans lines is
//! therefore not carried into the following line: the highlighter says where a
//! token starts and ends in one line, and claims nothing about the next. That
//! keeps the cost of one line proportional to that line, which is what a
//! viewport of a large file needs.
//!
//! Spans are byte ranges into the line, in order, and never overlap. Text
//! outside a span is rendered in the default foreground colour.

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

/// Highlights one line of `language`.
pub fn highlight(language: Language, line: &str) -> Vec<Span> {
    let mut lexer = Lexer::new(line);
    match language {
        Language::Xml => markup(&mut lexer, false),
        Language::Html => markup(&mut lexer, true),
        Language::Json => json(&mut lexer),
        Language::Yaml => yaml(&mut lexer),
        Language::Ini | Language::Toml => ini(&mut lexer, language),
        Language::Csv => csv(&mut lexer),
        Language::Lua => lua(&mut lexer),
        Language::JavaScript => javascript(&mut lexer),
        Language::Plain => {}
    }
    lexer.spans
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
        // Hex, binary and suffixed literals.
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
}

fn markup(lexer: &mut Lexer<'_>, html: bool) {
    while !lexer.done() {
        if lexer.starts_with("<!--") {
            let start = lexer.at;
            lexer.bump_bytes(4);
            while !lexer.done() && !lexer.starts_with("-->") {
                lexer.bump();
            }
            if lexer.starts_with("-->") {
                lexer.bump_bytes(3);
            }
            lexer.span(start, Token::Comment);
            continue;
        }
        if lexer.starts_with("<![CDATA[") {
            let start = lexer.at;
            lexer.bump_bytes(9);
            while !lexer.done() && !lexer.starts_with("]]>") {
                lexer.bump();
            }
            if lexer.starts_with("]]>") {
                lexer.bump_bytes(3);
            }
            lexer.span(start, Token::Literal);
            continue;
        }
        match lexer.peek() {
            Some(b'<') => tag(lexer, html),
            Some(b'&') => entity(lexer),
            Some(b'>') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
            }
            _ => lexer.bump(),
        }
    }
}

/// A tag from `<` to its closing `>`.
fn tag(lexer: &mut Lexer<'_>, html: bool) {
    let open = lexer.at;
    lexer.bump_bytes(1);
    if matches!(lexer.peek(), Some(b'/' | b'!' | b'?')) {
        lexer.bump_bytes(1);
    }
    let name_start = lexer.at;
    lexer.skip_while(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
    });
    let name = lexer.text.get(name_start..lexer.at).unwrap_or_default();
    let is_declaration =
        lexer.bytes.get(open + 1) == Some(&b'!') || lexer.bytes.get(open + 1) == Some(&b'?');
    if is_declaration {
        // `DOCTYPE`, processing-instruction targets and entity declarations
        // are one token up to the end of the tag.
        let start = open;
        while !lexer.done() && lexer.peek() != Some(b'>') {
            lexer.bump();
        }
        if lexer.peek() == Some(b'>') {
            lexer.bump_bytes(1);
        }
        lexer.span(start, Token::Comment);
        return;
    }
    if !name.is_empty() {
        lexer.span(name_start, Token::Tag);
        if html {
            let attribute = name.to_ascii_lowercase();
            if matches!(attribute.as_str(), "script" | "style") {
                while !lexer.done() && lexer.peek() != Some(b'>') {
                    lexer.bump();
                }
            }
        }
    }
    while !lexer.done() {
        match lexer.peek() {
            Some(b'>') => {
                let start = lexer.at;
                lexer.bump_bytes(1);
                lexer.span(start, Token::Punctuation);
                return;
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
            None => return,
        }
    }
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
                if lexer.bytes.get(look) == Some(&b':') {
                    // A string that is followed by a colon is a key.
                    if let Some(span) = lexer.spans.last_mut().filter(|span| span.start == start) {
                        span.token = Token::Attribute;
                    }
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

fn yaml(lexer: &mut Lexer<'_>) {
    let at_line_start = |lexer: &Lexer<'_>| {
        lexer.at == 0
            || lexer.text[..lexer.at]
                .chars()
                .rev()
                .find(|c| !matches!(c, ' ' | '\t'))
                .is_none_or(|c| c == '-')
    };
    while !lexer.done() {
        match lexer.peek() {
            Some(b'#') => {
                let start = lexer.at;
                let rest = lexer.bytes.len() - lexer.at;
                lexer.bump_bytes(rest);
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
                if at_line_start(lexer) {
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
                    }
                } else {
                    lexer.keyword(&[], &["true", "false", "null", "yes", "no"]);
                }
            }
            _ => lexer.bump(),
        }
    }
}

fn ini(lexer: &mut Lexer<'_>, language: Language) {
    let toml = language == Language::Toml;
    while !lexer.done() {
        match lexer.peek() {
            Some(b'#') | Some(b';') if !toml || lexer.peek() == Some(b'#') => {
                let start = lexer.at;
                let rest = lexer.bytes.len() - lexer.at;
                lexer.bump_bytes(rest);
                lexer.span(start, Token::Comment);
            }
            Some(b'[') => {
                let start = lexer.at;
                lexer.until(b']');
                lexer.span(start, Token::Tag);
            }
            Some(b'"' | b'\'') => lexer.quoted(Token::String),
            Some(b'-' | b'0'..=b'9') => lexer.number(),
            Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => {
                // A name directly before `=` is a key; a bare word is a value.
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
}

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

const LUA_KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "for", "function", "goto", "if", "in", "local",
    "not", "or", "repeat", "return", "then", "until", "while",
];
const LUA_LITERALS: &[&str] = &["true", "false", "nil"];

fn lua(lexer: &mut Lexer<'_>) {
    while !lexer.done() {
        match lexer.peek() {
            Some(b'-') if lexer.starts_with("--") => {
                let start = lexer.at;
                lexer.bump_bytes(2);
                if lexer.starts_with("[[") {
                    lexer.bump_bytes(2);
                    while !lexer.done() && !lexer.starts_with("]]") {
                        lexer.bump();
                    }
                    if lexer.starts_with("]]") {
                        lexer.bump_bytes(2);
                    }
                } else {
                    let rest = lexer.bytes.len() - lexer.at;
                    lexer.bump_bytes(rest);
                }
                lexer.span(start, Token::Comment);
            }
            Some(b'[') if lexer.starts_with("[[") => {
                let start = lexer.at;
                lexer.bump_bytes(2);
                while !lexer.done() && !lexer.starts_with("]]") {
                    lexer.bump();
                }
                if lexer.starts_with("]]") {
                    lexer.bump_bytes(2);
                }
                lexer.span(start, Token::String);
            }
            Some(b'"' | b'\'') => lexer.quoted(Token::String),
            Some(b'0'..=b'9') => lexer.number(),
            Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' => {
                lexer.keyword(LUA_KEYWORDS, LUA_LITERALS)
            }
            _ => lexer.bump(),
        }
    }
}

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

fn javascript(lexer: &mut Lexer<'_>) {
    while !lexer.done() {
        match lexer.peek() {
            Some(b'/') if lexer.starts_with("//") => {
                let start = lexer.at;
                let rest = lexer.bytes.len() - lexer.at;
                lexer.bump_bytes(rest);
                lexer.span(start, Token::Comment);
            }
            Some(b'/') if lexer.starts_with("/*") => {
                let start = lexer.at;
                lexer.bump_bytes(2);
                while !lexer.done() && !lexer.starts_with("*/") {
                    lexer.bump();
                }
                if lexer.starts_with("*/") {
                    lexer.bump_bytes(2);
                }
                lexer.span(start, Token::Comment);
            }
            Some(b'"' | b'\'' | b'`') => lexer.quoted(Token::String),
            Some(b'0'..=b'9') => lexer.number(),
            Some(byte) if byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$' => {
                lexer.keyword(JS_KEYWORDS, JS_LITERALS)
            }
            _ => lexer.bump(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(language: Language, line: &str) -> Vec<(Token, &str)> {
        highlight(language, line)
            .into_iter()
            .map(|span| (span.token, &line[span.start..span.end]))
            .collect()
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
            let spans = highlight(language, line);
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
        let found = tokens(Language::Xml, "<Root name=\"value\">text</Root>");
        assert!(found.contains(&(Token::Tag, "Root")));
        assert!(found.contains(&(Token::Attribute, "name")));
        assert!(found.contains(&(Token::String, "\"value\"")));
        assert!(found.contains(&(Token::Tag, "/Root")) || found.contains(&(Token::Tag, "Root")));
    }

    #[test]
    fn json_separates_keys_from_values() {
        let found = tokens(Language::Json, "{\"key\": \"value\", \"n\": 12}");
        assert!(found.contains(&(Token::Attribute, "\"key\"")));
        assert!(found.contains(&(Token::String, "\"value\"")));
        assert!(found.contains(&(Token::Number, "12")));
    }

    #[test]
    fn comments_run_to_the_end_of_the_line() {
        let found = tokens(Language::Lua, "x = 1 -- why");
        assert_eq!(found.last(), Some(&(Token::Comment, "-- why")));
        let found = tokens(Language::JavaScript, "// note");
        assert_eq!(found, vec![(Token::Comment, "// note")]);
    }

    #[test]
    fn unterminated_strings_stop_at_the_line_end() {
        let found = tokens(Language::Lua, "x = 'unfinished");
        assert_eq!(found.last(), Some(&(Token::String, "'unfinished")));
    }

    #[test]
    fn ini_highlights_sections_and_keys() {
        let found = tokens(Language::Ini, "value = 0.5");
        assert!(found.contains(&(Token::Attribute, "value")));
        assert!(found.contains(&(Token::Number, "0.5")));
        let found = tokens(Language::Ini, "[sound]");
        assert_eq!(found, vec![(Token::Tag, "[sound]")]);
    }
}
