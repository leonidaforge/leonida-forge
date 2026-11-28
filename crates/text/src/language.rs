//! Which textual language a payload is written in.
//!
//! The extension names a language; the bytes decide whether a payload is text
//! at all and may name a language when the extension does not. Recognition is
//! deliberately shallow: it selects a highlighter, and claims no parse.

/// A textual language this build highlights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Language {
    /// Text with no grammar recognised.
    #[default]
    Plain,
    Xml,
    Html,
    Json,
    Yaml,
    Ini,
    Toml,
    Csv,
    Lua,
    JavaScript,
}

impl Language {
    /// The name shown in the viewer.
    pub fn name(self) -> &'static str {
        match self {
            Language::Plain => "Plain text",
            Language::Xml => "XML",
            Language::Html => "HTML",
            Language::Json => "JSON",
            Language::Yaml => "YAML",
            Language::Ini => "INI",
            Language::Toml => "TOML",
            Language::Csv => "CSV",
            Language::Lua => "Lua",
            Language::JavaScript => "JavaScript",
        }
    }

    /// The language an extension names.
    ///
    /// `meta` and `pso` are included because the engine's earlier builds wrote
    /// XML under those extensions; a payload that is not XML still fails the
    /// text check on its own bytes, so the name can only ever be a hint.
    pub fn from_extension(extension: &str) -> Option<Self> {
        let extension = extension.trim_start_matches('.').to_ascii_lowercase();
        Some(match extension.as_str() {
            "xml" | "xsd" | "xsl" | "xslt" | "svg" | "meta" => Language::Xml,
            "html" | "htm" | "xhtml" => Language::Html,
            "json" | "jsonc" | "jsonl" | "ndjson" => Language::Json,
            "yaml" | "yml" => Language::Yaml,
            "ini" | "cfg" | "conf" | "properties" | "desktop" => Language::Ini,
            "toml" => Language::Toml,
            "csv" => Language::Csv,
            "tsv" | "tab" => Language::Csv,
            "lua" => Language::Lua,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "txt" | "text" | "log" | "md" | "markdown" | "dat" | "lst" | "nfo" => Language::Plain,
            _ => return None,
        })
    }

    /// Whether a name is one this build treats as text when it is opened.
    pub fn is_text_extension(extension: &str) -> bool {
        Self::from_extension(extension).is_some()
    }

    /// The language the head of a payload is written in, from its content
    /// alone. `None` when nothing distinctive was found.
    pub fn sniff(text: &str) -> Option<Self> {
        let head: String = text.chars().take(8 * 1024).collect();
        let trimmed = head.trim_start_matches(|c: char| c.is_whitespace());
        if trimmed.is_empty() {
            return None;
        }
        let lowered = trimmed
            .chars()
            .take(64)
            .collect::<String>()
            .to_ascii_lowercase();
        if lowered.starts_with("<!doctype html") || lowered.starts_with("<html") {
            return Some(Language::Html);
        }
        if lowered.starts_with("<?xml") || looks_like_markup(trimmed) {
            return Some(Language::Xml);
        }
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            // A bracket alone is not enough: `[Section]` starts an INI file and
            // `[1, 2]` a data file. JSON needs a quoted key or a value.
            if head.contains("\":") || head.contains("\",") || head.contains("\"}") {
                return Some(Language::Json);
            }
        }
        if trimmed.starts_with("---") || trimmed.starts_with("---\n") {
            return Some(Language::Yaml);
        }
        if let Some(language) = script_language(&head) {
            return Some(language);
        }
        if let Some(language) = structured_text(&head) {
            return Some(language);
        }
        None
    }
}

/// Whether the text begins with a tag, closing tag or comment.
fn looks_like_markup(text: &str) -> bool {
    let mut chars = text.chars();
    if chars.next() != Some('<') {
        return false;
    }
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '/' || c == '!')
}

/// Lua and JavaScript are told apart by the words that only one of them uses.
fn script_language(text: &str) -> Option<Language> {
    let words: Vec<&str> = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .take(400)
        .collect();
    let has = |word: &str| words.contains(&word);
    let lua = ["function", "local", "then", "end", "elseif", "nil"]
        .iter()
        .filter(|word| has(word))
        .count();
    let js = [
        "const",
        "let",
        "var",
        "=>",
        "undefined",
        "null",
        "document",
        "window",
    ]
    .iter()
    .filter(|word| has(word))
    .count();
    match (lua >= 2, js >= 2) {
        (true, false) => Some(Language::Lua),
        (false, true) => Some(Language::JavaScript),
        _ => None,
    }
}

/// Key/value and table formats, from the shape of their first lines.
fn structured_text(text: &str) -> Option<Language> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(40)
        .collect();
    if lines.is_empty() {
        return None;
    }
    let mut sections = 0;
    let mut assignments = 0;
    let mut mappings = 0;
    let mut table_arrays = 0;
    for line in &lines {
        if line.starts_with('[') && line.ends_with(']') {
            sections += 1;
            if line.contains('.') {
                table_arrays += 1;
            }
        } else if let Some((key, _)) = line.split_once('=') {
            if is_key(key) {
                assignments += 1;
            }
        } else if let Some((key, value)) = line.split_once(':')
            && is_key(key)
            && !value.trim().is_empty()
        {
            mappings += 1;
        }
    }
    let total = lines.len();
    if assignments > 0 && assignments * 2 >= total {
        return Some(if table_arrays > 0 {
            Language::Toml
        } else {
            Language::Ini
        });
    }
    if sections > 0 && assignments + sections >= total / 2 {
        return Some(Language::Ini);
    }
    if mappings * 2 >= total && mappings > 0 {
        return Some(Language::Yaml);
    }
    delimited(&lines)
}

fn is_key(key: &str) -> bool {
    let key = key.trim();
    !key.is_empty()
        && !key.starts_with('#')
        && !key.starts_with(';')
        && !key.starts_with("//")
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '"' | '\''))
}

/// A table whose rows carry the same number of separators on every line.
fn delimited(lines: &[&str]) -> Option<Language> {
    let sample = &lines[..lines.len().min(10)];
    for delimiter in ['\t', ',', ';'] {
        let counts: Vec<usize> = sample
            .iter()
            .map(|line| line.matches(delimiter).count())
            .collect();
        let first = counts[0];
        if first > 0 && counts.iter().all(|count| *count == first) {
            return Some(Language::Csv);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_name_their_language() {
        assert_eq!(Language::from_extension("XML"), Some(Language::Xml));
        assert_eq!(Language::from_extension(".lua"), Some(Language::Lua));
        assert_eq!(Language::from_extension("tsv"), Some(Language::Csv));
        assert_eq!(Language::from_extension("txt"), Some(Language::Plain));
        assert_eq!(Language::from_extension("zdr"), None);
        assert!(Language::is_text_extension("json"));
        assert!(!Language::is_text_extension("ttpf"));
    }

    #[test]
    fn markup_is_recognised_from_its_first_tag() {
        assert_eq!(
            Language::sniff("<?xml version=\"1.0\"?><a/>"),
            Some(Language::Xml)
        );
        assert_eq!(
            Language::sniff("<!DOCTYPE html><html></html>"),
            Some(Language::Html)
        );
        assert_eq!(Language::sniff("<CCombatInfoMgr>"), Some(Language::Xml));
        assert_eq!(Language::sniff("< not markup"), None);
    }

    #[test]
    fn json_needs_more_than_a_bracket() {
        assert_eq!(Language::sniff("{\"a\": 1}"), Some(Language::Json));
        assert_eq!(Language::sniff("[Section]\nKey=1\n"), Some(Language::Ini));
    }

    #[test]
    fn scripts_are_told_apart() {
        let lua = "local function f()\n  if x then return nil end\nend\n";
        assert_eq!(Language::sniff(lua), Some(Language::Lua));
        let js = "const x = () => { let y = null; return y; };\n";
        assert_eq!(Language::sniff(js), Some(Language::JavaScript));
    }

    #[test]
    fn key_value_files_are_recognised() {
        assert_eq!(
            Language::sniff("[sound]\nvolume = 0.5\nmusic = 0.2\n"),
            Some(Language::Ini)
        );
        assert_eq!(
            Language::sniff("title = \"x\"\n[table.name]\nvalue = 1\n"),
            Some(Language::Toml)
        );
        assert_eq!(
            Language::sniff("name: test\nvalue: 2\nother: 3\n"),
            Some(Language::Yaml)
        );
    }

    #[test]
    fn equal_separator_counts_are_a_table() {
        assert_eq!(
            Language::sniff("a\tb\tc\n1\t2\t3\n4\t5\t6\n"),
            Some(Language::Csv)
        );
        assert_eq!(Language::sniff("one two three\nfour five\n"), None);
    }
}
