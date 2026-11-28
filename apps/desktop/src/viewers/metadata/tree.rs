//! The rows a metadata view shows, and which of them are visible.
//!
//! The rows are a pre-order walk of the decoded document: groups, structures,
//! enums, blocks, records and the values inside them. A row's `depth` says
//! where it sits, so collapsing a row hides the rows after it whose depth is
//! greater.
//!
//! Nothing here needs a window, so it can be tested on its own.

use std::collections::HashSet;

use lforge_rage9::psin::pso::names::Names;
use lforge_rage9::psin::pso::{
    ArrayElements, Block, Content, Document, Field, FieldValue, PoolEntry, Record, Reference,
    Scalar, Value,
};

/// The most rows a view builds. A very large container reports the limit
/// instead of exhausting memory.
pub const MAX_ROWS: usize = 200_000;
/// The most array elements or pool entries listed under one row.
const MAX_CHILDREN: usize = 512;
/// The most bytes of an unresolved value the detail line shows.
const MAX_BYTES_SHOWN: usize = 12;

/// How a row reads at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Group and structure headings.
    Normal,
    /// Hashes, offsets and other context.
    Muted,
    /// A resolved name.
    Accent,
    /// Something the decoder could not resolve.
    Warning,
}

/// One line of the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub depth: usize,
    pub label: String,
    pub detail: String,
    /// The text the copy action writes.
    pub copy: String,
    pub expandable: bool,
    pub tone: Tone,
}

/// The rows of one document and what the view says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub rows: Vec<Row>,
    pub status: &'static str,
    pub summary: String,
    pub issues: Vec<String>,
    /// Whether the row limit cut the walk short.
    pub truncated: bool,
}

impl Tree {
    /// The rows to draw: the expanded ones, in order. With a filter, the rows
    /// whose text matches and the ancestors that hold them, whether or not
    /// they are collapsed.
    pub fn visible(&self, collapsed: &HashSet<usize>, filter: &str) -> Vec<usize> {
        let needle = filter.trim().to_lowercase();
        if needle.is_empty() {
            return self.expanded(collapsed);
        }
        let mut keep: HashSet<usize> = HashSet::new();
        for (index, row) in self.rows.iter().enumerate() {
            if !contains(row, &needle) {
                continue;
            }
            keep.insert(index);
            // Walk back to the ancestors of this row.
            let mut depth = row.depth;
            let mut at = index;
            while depth > 0 && at > 0 {
                at -= 1;
                let candidate = &self.rows[at];
                if candidate.depth < depth {
                    depth = candidate.depth;
                    keep.insert(at);
                }
            }
        }
        (0..self.rows.len())
            .filter(|index| keep.contains(index))
            .collect()
    }

    /// The rows no collapsed ancestor hides.
    fn expanded(&self, collapsed: &HashSet<usize>) -> Vec<usize> {
        let mut out = Vec::with_capacity(self.rows.len());
        let mut hidden_at: Option<usize> = None;
        for (index, row) in self.rows.iter().enumerate() {
            if let Some(depth) = hidden_at {
                if row.depth > depth {
                    continue;
                }
                hidden_at = None;
            }
            out.push(index);
            if row.expandable && collapsed.contains(&index) {
                hidden_at = Some(row.depth);
            }
        }
        out
    }

    /// The index of the row that holds `index`, if any.
    pub fn parent(&self, index: usize) -> Option<usize> {
        let depth = self.rows.get(index)?.depth;
        if depth == 0 {
            return None;
        }
        self.rows[..index]
            .iter()
            .rposition(|row| row.depth < depth)
    }

    /// The rows a structure or block row folds away.
    pub fn descendants(&self, index: usize) -> usize {
        let Some(row) = self.rows.get(index) else {
            return 0;
        };
        self.rows[index + 1..]
            .iter()
            .take_while(|other| other.depth > row.depth)
            .count()
    }
}

fn contains(row: &Row, needle: &str) -> bool {
    row.label.to_lowercase().contains(needle) || row.detail.to_lowercase().contains(needle)
}

fn hash32(value: u32) -> String {
    format!("0x{value:08X}")
}

fn hash64(value: u64) -> String {
    format!("0x{value:016X}")
}

/// The name the index offers beside a hash, or nothing.
fn name_of(names: &Names, hash: u32) -> String {
    match names.lookup(hash) {
        [] => String::new(),
        [only] => format!("  \u{00B7}  {only}"),
        [first, rest @ ..] => format!("  \u{00B7}  {first} (+{})", rest.len()),
    }
}

fn bytes_text(bytes: &[u8]) -> String {
    let shown: Vec<String> = bytes
        .iter()
        .take(MAX_BYTES_SHOWN)
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let more = bytes.len().saturating_sub(MAX_BYTES_SHOWN);
    if more == 0 {
        shown.join(" ")
    } else {
        format!("{} … ({more} more)", shown.join(" "))
    }
}

fn scalar_text(scalar: &Scalar) -> String {
    match scalar {
        Scalar::Bool(inner) => inner.to_string(),
        Scalar::I8(inner) => inner.to_string(),
        Scalar::U8(inner) => inner.to_string(),
        Scalar::I16(inner) => inner.to_string(),
        Scalar::U16(inner) => inner.to_string(),
        Scalar::U32(inner) => inner.to_string(),
        Scalar::I32(inner) => inner.to_string(),
        Scalar::U64(inner) => inner.to_string(),
        Scalar::F16(inner) | Scalar::F32(inner) => format!("{inner}"),
        Scalar::Hash32(inner) => hash32(*inner),
        Scalar::Hash64(inner) => hash64(*inner),
        Scalar::Vector { values, count } => values[..usize::from(*count)]
            .iter()
            .map(|value| format!("{value}"))
            .collect::<Vec<String>>()
            .join(", "),
    }
}

fn reference_text(reference: &Reference) -> (String, Tone) {
    if reference.is_null() {
        return ("null".to_string(), Tone::Muted);
    }
    match reference.target {
        Some(target) => (
            format!(
                "block {} record {} {}",
                target.block,
                target.record,
                hash32(target.structure)
            ),
            Tone::Muted,
        ),
        None => (
            reference
                .fault
                .map_or_else(|| "unbound".to_string(), |fault| fault.text().to_string()),
            Tone::Warning,
        ),
    }
}

/// The detail text of one field value.
fn value_text(value: &Value, names: &Names) -> (String, Tone) {
    match value {
        Value::Scalar(scalar) => {
            let text = scalar_text(scalar);
            match scalar {
                Scalar::Hash32(inner) => match names.lookup(*inner) {
                    [] => (format!("hash32 {text}"), Tone::Muted),
                    _ => (format!("hash32 {text}{}", name_of(names, *inner)), Tone::Accent),
                },
                _ => (format!("{} {text}", scalar.type_name()), Tone::Normal),
            }
        }
        Value::Enum(inner) => {
            let named = inner
                .matches
                .iter()
                .map(|member| format!("{}{}", hash32(member.name), name_of(names, member.name)))
                .collect::<Vec<String>>()
                .join(", ");
            let text = format!("enum {} {}", hash32(inner.enumeration), inner.value);
            if named.is_empty() {
                let reason = if inner.defined {
                    "no member has this value"
                } else {
                    "the table defines no such enum"
                };
                (format!("{text}  \u{00B7}  {reason}"), Tone::Warning)
            } else {
                (format!("{text}  \u{00B7}  {named}"), Tone::Accent)
            }
        }
        Value::Structure(record) => (
            format!(
                "structure {}{}",
                hash32(record.structure),
                name_of(names, record.structure)
            ),
            Tone::Normal,
        ),
        Value::Reference(reference) => {
            let (text, tone) = reference_text(reference);
            (format!("reference \u{2192} {text}"), tone)
        }
        Value::Array(array) => {
            let head = format!("array[{}]", array.span.count);
            match &array.elements {
                Err(reason) => (format!("{head}  \u{00B7}  {reason}"), Tone::Warning),
                Ok(ArrayElements::Structure {
                    structure,
                    stride,
                    links,
                }) => (
                    format!(
                        "{head} of {stride} byte records {}{}  \u{00B7}  {} links",
                        hash32(*structure),
                        name_of(names, *structure),
                        links.len()
                    ),
                    Tone::Normal,
                ),
                Ok(ArrayElements::Reference { links }) => (
                    format!(
                        "{head} of references  \u{00B7}  {} bound",
                        bound(links)
                    ),
                    Tone::Normal,
                ),
                Ok(ArrayElements::Hash32 { values }) => (
                    format!("{head} of hash32 {}", sample_hashes(values, names)),
                    Tone::Normal,
                ),
                Ok(ArrayElements::Enum32 {
                    enumeration,
                    values,
                }) => (
                    format!(
                        "{head} of enum {} values {values:?}",
                        hash32(*enumeration)
                    ),
                    Tone::Normal,
                ),
            }
        }
        Value::Map(map) => {
            let head = format!("map[{}]", map.span.count);
            match &map.entries {
                Err(reason) => (format!("{head}  \u{00B7}  {reason}"), Tone::Warning),
                Ok((structure, records)) => (
                    format!(
                        "{head} of entries {}{}  \u{00B7}  {} entries",
                        hash32(*structure),
                        name_of(names, *structure),
                        records.len()
                    ),
                    Tone::Normal,
                ),
            }
        }
        Value::Bitset(bitset) => {
            let bits: Vec<String> = (0..64)
                .filter(|bit| bitset.bits & (1 << bit) != 0)
                .map(|bit| bit.to_string())
                .collect();
            let count = bitset
                .bit_count
                .map_or_else(|| "unknown count".to_string(), |count| format!("{count} bits"));
            (
                format!(
                    "bitset {count}  \u{00B7}  set: {}",
                    if bits.is_empty() {
                        "none".to_string()
                    } else {
                        bits.join(", ")
                    }
                ),
                Tone::Normal,
            )
        }
        Value::TextSlot { raw } => (format!("text slot  {}", bytes_text(raw)), Tone::Warning),
        Value::Descriptor { code, upper, .. } => (
            format!("element descriptor  \u{00B7}  type 0x{code:04X} upper {upper}"),
            Tone::Muted,
        ),
        Value::Unresolved { code, raw, .. } => (
            format!(
                "type 0x{code:04X} has no established width  \u{00B7}  {}",
                bytes_text(raw)
            ),
            Tone::Warning,
        ),
    }
}

fn bound(links: &[Reference]) -> usize {
    links.iter().filter(|reference| reference.target.is_some()).count()
}

fn sample_hashes(values: &[u32], names: &Names) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    let shown: Vec<String> = values
        .iter()
        .take(3)
        .map(|value| format!("{}{}", hash32(*value), name_of(names, *value)))
        .collect();
    if values.len() > 3 {
        format!("{} … ({} more)", shown.join(", "), values.len() - 3)
    } else {
        shown.join(", ")
    }
}

fn field_label(field: &Field, names: &Names) -> String {
    let mut label = hash32(field.name);
    let name = name_of(names, field.name);
    if !name.is_empty() {
        label.push_str(&name);
    }
    label
}

struct Walker<'a> {
    names: &'a Names,
    rows: Vec<Row>,
    truncated: bool,
}

impl<'a> Walker<'a> {
    fn new(names: &'a Names) -> Self {
        Self {
            names,
            rows: Vec::new(),
            truncated: false,
        }
    }

    fn push(&mut self, row: Row) -> bool {
        if self.rows.len() >= MAX_ROWS {
            self.truncated = true;
            return false;
        }
        self.rows.push(row);
        true
    }

    fn group(&mut self, depth: usize, label: String, detail: String, expandable: bool) {
        self.push(Row {
            depth,
            copy: format!("{label}  {detail}"),
            label,
            detail,
            expandable,
            tone: Tone::Normal,
        });
    }

    fn structure_rows(&mut self, structure: &lforge_rage9::psin::pso::Structure) {
        self.group(
            1,
            format!(
                "structure {}{}",
                hash32(structure.name),
                name_of(self.names, structure.name)
            ),
            format!(
                "{} bytes, {} fields  \u{00B7}  signature {}, flags {}",
                structure.size,
                structure.fields.len(),
                hash32(structure.signature),
                hash32(structure.flags)
            ),
            !structure.fields.is_empty(),
        );
        for field in &structure.fields {
            let extent = structure
                .extent(field)
                .map_or_else(String::new, |extent| format!("{extent} B"));
            let label = if field.is_descriptor() {
                format!("element descriptor (field {})", hash32(field.name))
            } else {
                field_label(field, self.names)
            };
            let detail = format!(
                "type 0x{:04X}  \u{00B7}  offset {}  \u{00B7}  {}  \u{00B7}  aux {}",
                field.code(),
                field.offset,
                if extent.is_empty() {
                    "no storage".to_string()
                } else {
                    extent
                },
                hash32(field.auxiliary)
            );
            let copy = format!("{label}  {detail}");
            self.push(Row {
                depth: 2,
                label,
                detail,
                copy,
                expandable: false,
                tone: Tone::Muted,
            });
        }
    }

    fn enum_rows(&mut self, enumeration: &lforge_rage9::psin::pso::Enumeration) {
        self.group(
            1,
            format!(
                "enum {}{}",
                hash32(enumeration.name),
                name_of(self.names, enumeration.name)
            ),
            format!("{} values", enumeration.values.len()),
            !enumeration.values.is_empty(),
        );
        for member in &enumeration.values {
            let label = format!(
                "member {}{}",
                hash32(member.name),
                name_of(self.names, member.name)
            );
            let detail = format!("value {}", member.value);
            self.push(Row {
                depth: 2,
                copy: format!("{label}  {detail}"),
                label,
                detail,
                expandable: false,
                tone: Tone::Muted,
            });
        }
    }

    fn block_rows(&mut self, block: &Block) {
        let (label, detail, expandable) = match &block.content {
            Content::Records {
                structure,
                stride,
                total,
                records,
            } => (
                format!("block {}  \u{00B7}  records", block.index),
                format!(
                    "type {}{}  \u{00B7}  {total} \u{00D7} {stride} B  \u{00B7}  {} decoded",
                    hash32(block.id),
                    name_of(self.names, *structure),
                    records.len()
                ),
                !records.is_empty(),
            ),
            Content::Pool {
                kind,
                total,
                entries,
            } => (
                format!("block {}  \u{00B7}  {}", block.index, kind.name()),
                format!("{total} elements  \u{00B7}  {} decoded", entries.len()),
                !entries.is_empty(),
            ),
            Content::Unsupported(reason) => (
                format!("block {}  \u{00B7}  unsupported", block.index),
                reason.clone(),
                false,
            ),
        };
        let tone = match &block.content {
            Content::Unsupported(_) => Tone::Warning,
            _ => Tone::Normal,
        };
        self.push(Row {
            depth: 1,
            copy: format!("{label}  {detail}"),
            label,
            detail,
            expandable,
            tone,
        });
        let base = 2;
        match &block.content {
            Content::Records { records, .. } => {
                let shown: Vec<&Record> = records.iter().take(MAX_CHILDREN).collect();
                for record in shown {
                    self.record_rows(base, record);
                }
                if records.len() > MAX_CHILDREN {
                    self.group(
                        base,
                        format!("… {} more records", records.len() - MAX_CHILDREN),
                        String::new(),
                        false,
                    );
                }
            }
            Content::Pool { entries, .. } => {
                for (index, entry) in entries.iter().take(MAX_CHILDREN).enumerate() {
                    let (text, tone) = match entry {
                        PoolEntry::Text(text) => (format!("\"{text}\""), Tone::Normal),
                        PoolEntry::Hash32(value) => (
                            format!("{}{}", hash32(*value), name_of(self.names, *value)),
                            if self.names.resolves(*value) {
                                Tone::Accent
                            } else {
                                Tone::Muted
                            },
                        ),
                        PoolEntry::Reference(word) | PoolEntry::Word64(word) => {
                            (hash64(*word), Tone::Muted)
                        }
                        PoolEntry::Word128(bytes) => (bytes_text(bytes), Tone::Muted),
                    };
                    self.push(Row {
                        depth: base,
                        label: format!("[{index}]"),
                        copy: text.clone(),
                        detail: text,
                        expandable: false,
                        tone,
                    });
                }
                if entries.len() > MAX_CHILDREN {
                    self.group(
                        base,
                        format!("… {} more elements", entries.len() - MAX_CHILDREN),
                        String::new(),
                        false,
                    );
                }
            }
            Content::Unsupported(_) => {}
        }
    }

    fn record_rows(&mut self, depth: usize, record: &Record) {
        let label = format!(
            "record {}  \u{00B7}  {}{}",
            record.offset,
            hash32(record.structure),
            name_of(self.names, record.structure)
        );
        let detail = format!("{} fields", record.fields.len());
        self.push(Row {
            depth,
            copy: format!("{label}  {detail}"),
            label,
            detail,
            expandable: !record.fields.is_empty(),
            tone: Tone::Normal,
        });
        for field in &record.fields {
            self.value_rows(depth + 1, field);
        }
    }

    fn value_rows(&mut self, depth: usize, field: &FieldValue) {
        let label = if field.field.is_descriptor() {
            format!("element descriptor  \u{00B7}  field {}", hash32(field.field.name))
        } else {
            field_label(&field.field, self.names)
        };
        let (text, tone) = value_text(&field.value, self.names);
        let expandable = self.has_children(&field.value);
        self.push(Row {
            depth,
            copy: format!("{label} = {text}"),
            label,
            detail: text,
            expandable,
            tone,
        });
        if !expandable {
            return;
        }
        match &field.value {
            Value::Structure(record) => {
                for inner in &record.fields {
                    self.value_rows(depth + 1, inner);
                }
            }
            Value::Array(array) => match &array.elements {
                Err(_) => {}
                Ok(ArrayElements::Structure { links, .. }) => {
                    for link in links.iter().take(MAX_CHILDREN) {
                        self.group(
                            depth + 1,
                            format!("[{index}] block {block}", index = link.index, block = link.target.block),
                            format!(
                                "record {} @{}  \u{00B7}  {}",
                                link.target.record,
                                link.target.offset,
                                hash32(link.target.structure)
                            ),
                            false,
                        );
                    }
                }
                Ok(ArrayElements::Reference { links }) => {
                    for (index, reference) in links.iter().take(MAX_CHILDREN).enumerate() {
                        let (text, tone) = reference_text(reference);
                        self.push(Row {
                            depth: depth + 1,
                            label: format!("[{index}]"),
                            copy: text.clone(),
                            detail: text,
                            expandable: false,
                            tone,
                        });
                    }
                }
                Ok(ArrayElements::Hash32 { values }) => {
                    for (index, value) in values.iter().take(MAX_CHILDREN).enumerate() {
                        self.push(Row {
                            depth: depth + 1,
                            label: format!("[{index}]"),
                            detail: format!("{}{}", hash32(*value), name_of(self.names, *value)),
                            copy: hash32(*value),
                            expandable: false,
                            tone: Tone::Muted,
                        });
                    }
                }
                Ok(ArrayElements::Enum32 { values, .. }) => {
                    for (index, value) in values.iter().take(MAX_CHILDREN).enumerate() {
                        self.push(Row {
                            depth: depth + 1,
                            label: format!("[{index}]"),
                            detail: value.to_string(),
                            copy: value.to_string(),
                            expandable: false,
                            tone: Tone::Muted,
                        });
                    }
                }
            },
            Value::Map(map) => {
                if let Ok((_, records)) = &map.entries {
                    for record in records.iter().take(MAX_CHILDREN) {
                        self.record_rows(depth + 1, record);
                    }
                }
            }
            _ => {}
        }
    }

    fn has_children(&self, value: &Value) -> bool {
        match value {
            Value::Structure(record) => !record.fields.is_empty(),
            Value::Array(array) => match &array.elements {
                Ok(ArrayElements::Structure { links, .. }) => !links.is_empty(),
                Ok(ArrayElements::Reference { links }) => !links.is_empty(),
                Ok(ArrayElements::Hash32 { values }) => !values.is_empty(),
                Ok(ArrayElements::Enum32 { values, .. }) => !values.is_empty(),
                Err(_) => false,
            },
            Value::Map(map) => map.entries.as_ref().is_ok_and(|(_, records)| !records.is_empty()),
            _ => false,
        }
    }
}

/// Builds the rows of one decoded document.
pub fn build(document: &Document, names: &Names) -> Tree {
    let records = document.record_count();
    let mut walker = Walker::new(names);
    walker.group(
        0,
        "schema".to_string(),
        format!(
            "{} structures, {} enums",
            document.structures.len(),
            document.enums.len()
        ),
        !document.structures.is_empty() || !document.enums.is_empty(),
    );
    for structure in &document.structures {
        walker.structure_rows(structure);
    }
    for enumeration in &document.enums {
        walker.enum_rows(enumeration);
    }
    walker.group(
        0,
        "instances".to_string(),
        format!("{} blocks, {records} records decoded", document.blocks.len()),
        !document.blocks.is_empty(),
    );
    for block in &document.blocks {
        walker.block_rows(block);
    }
    let issues = document.issues.clone();
    if !issues.is_empty() {
        walker.group(0, "issues".to_string(), format!("{} reported", issues.len()), true);
        for issue in &issues {
            walker.push(Row {
                depth: 1,
                label: issue.clone(),
                detail: String::new(),
                copy: issue.clone(),
                expandable: false,
                tone: Tone::Warning,
            });
        }
    }
    let status = if document.header_matches() == Some(false) || !issues.is_empty() {
        "partial"
    } else {
        "decoded"
    };
    let summary = match document.header {
        Some(header) => format!(
            "{} structures  \u{00B7}  {} blocks  \u{00B7}  {} records  \u{00B7}  {} roots",
            document.structures.len(),
            document.blocks.len(),
            records,
            header.roots
        ),
        None => format!(
            "{} structures  \u{00B7}  {} blocks  \u{00B7}  {} records",
            document.structures.len(),
            document.blocks.len(),
            records
        ),
    };
    Tree {
        rows: walker.rows,
        status,
        summary,
        issues,
        truncated: walker.truncated,
    }
}

#[cfg(test)]
mod tests;
