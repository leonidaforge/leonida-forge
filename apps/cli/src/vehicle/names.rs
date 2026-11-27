//! The vehicle name list discovery matches against.
//!
//! A list is either the public vehicle dump (a JSON array of objects with a
//! `Name` field), an exported catalog file (objects with `modelName`), or a
//! plain text file with one name per line.

use std::collections::BTreeMap;
use std::path::Path;

/// Names keyed by their lowercase form, valued with the spelling the list uses.
#[derive(Debug, Default, Clone)]
pub struct Names(BTreeMap<String, String>);

impl Names {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The listed spelling of a model, matched without case.
    pub fn get(&self, model: &str) -> Option<&str> {
        self.0.get(&model.to_lowercase()).map(String::as_str)
    }

    fn insert(&mut self, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        self.0
            .entry(name.to_lowercase())
            .or_insert_with(|| name.to_string());
    }
}

/// Reads a name list. The first non-space byte selects JSON or text.
pub fn read(path: &Path) -> Result<Names, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        parse_json(&text)
    } else {
        Ok(read_from_text(&text))
    }
}

fn parse_text(text: &str) -> Names {
    let mut names = Names::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        names.insert(line);
    }
    names
}

/// [`read`] over text the caller already holds, in text form.
pub fn read_from_text(text: &str) -> Names {
    parse_text(text)
}

fn parse_json(text: &str) -> Result<Names, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|err| format!("the name list is not JSON: {err}"))?;
    let mut names = Names::default();
    if let Some(entries) = value.as_array() {
        for entry in entries {
            if let Some(name) = entry_name(entry) {
                names.insert(name);
            }
        }
        return Ok(names);
    }
    // A catalog document keeps its records under `records`.
    if let Some(records) = value.get("records").and_then(serde_json::Value::as_array) {
        for entry in records {
            if let Some(name) = entry_name(entry) {
                names.insert(name);
            }
        }
        return Ok(names);
    }
    Err("the name list is neither an array nor a document with records".to_string())
}

fn entry_name(entry: &serde_json::Value) -> Option<&str> {
    if let Some(name) = entry.as_str() {
        return Some(name);
    }
    for field in ["Name", "modelName", "model", "name"] {
        if let Some(name) = entry.get(field).and_then(serde_json::Value::as_str) {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_lines_are_read_and_comments_skipped() {
        let names = parse_text("# vehicles\nakane\n\n  cheetah2  \n");
        assert_eq!(names.len(), 2);
        assert_eq!(names.get("AKANE"), Some("akane"));
    }

    #[test]
    fn a_dump_array_and_a_catalog_document_both_read() {
        let dump = r#"[{"Name":"akane"},{"Name":"cheetah2"}]"#;
        assert_eq!(parse_json(dump).expect("dump").len(), 2);
        let catalog = r#"{"records":[{"modelName":"akane"}]}"#;
        assert_eq!(parse_json(catalog).expect("catalog").len(), 1);
    }

    #[test]
    fn a_duplicate_name_keeps_the_first_spelling() {
        let names = parse_text("Akane\nakane\n");
        assert_eq!(names.len(), 1);
        assert_eq!(names.get("akane"), Some("Akane"));
    }
}
