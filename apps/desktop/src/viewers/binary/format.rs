//! Content-based format recognition for the inspector.
//!
//! The recognition and parsing live in [`lforge_core::inspect`], shared with
//! the CLI, so a format means the same thing in both front ends. Only fields
//! the research documentation establishes are shown; a field whose meaning is
//! unknown is either omitted or labelled as unknown. The report is produced on
//! the thread that opens the file, never on the UI thread, and it never
//! contains payload bytes.

use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_core::inspect as recognition;
use lforge_core::inspect::Summary;

/// Blocks whose storage class is read for a report.
const SAMPLE_BLOCKS: usize = 8;

pub(super) struct Report {
    pub name: &'static str,
    /// How much of the format is parsed: `structural`, `header` or
    /// `recognition`.
    pub support: &'static str,
    /// Label and value pairs, in display order.
    pub fields: Vec<(&'static str, String)>,
    /// Why the format could not be parsed.
    pub error: Option<String>,
}

/// Recognises the file's format from its first bytes. `None` when nothing is
/// recognised.
pub(super) fn detect(source: &mut Source) -> Option<Report> {
    let len = source.len();
    let options = recognition::Options {
        sample: SAMPLE_BLOCKS,
        blocks: false,
        verify: false,
    };
    let report = recognition::inspect(source, len, &options, &AtomicBool::new(false)).ok()?;
    let format = report.format?;
    Some(Report {
        name: format.name,
        support: format.support,
        fields: fields(report.summary.as_ref()),
        error: report.failure.map(|failure| failure.message),
    })
}

fn fields(summary: Option<&Summary>) -> Vec<(&'static str, String)> {
    match summary {
        Some(Summary::Rds5 {
            version,
            records,
            blocks,
            classified,
            zlib_blocks,
            entries,
            uncompressed_total,
            warning,
        }) => {
            let mut fields = vec![
                ("Version", format!("0x{version:08X}")),
                ("Records", records.to_string()),
                (
                    "Blocks",
                    format!("{blocks} ({zlib_blocks} of {classified} zlib)"),
                ),
                ("Entries", entries.to_string()),
                (
                    "Uncompressed",
                    format!(
                        "{} ({} bytes)",
                        crate::files::format_size(u64::from(*uncompressed_total)),
                        crate::files::format_bytes_exact(u64::from(*uncompressed_total))
                    ),
                ),
            ];
            if let Some(warning) = warning {
                fields.push(("Note", warning.clone()));
            }
            fields
        }
        Some(Summary::Rbf0 {
            versioned,
            version,
            number_len,
            names,
            body,
        }) => {
            let mut fields = vec![
                (
                    "Header",
                    if *versioned {
                        format!("versioned (version {})", version.unwrap_or(0))
                    } else {
                        "versionless".to_string()
                    },
                ),
                ("Numbers", format!("{number_len} bytes")),
                ("Names", names.to_string()),
            ];
            if let Some(body) = body {
                fields.push((
                    "Objects",
                    format!("{} (depth {})", body.objects, body.depth),
                ));
                fields.push(("Fields", body.fields.to_string()));
                fields.push(("Definitions", body.definitions.to_string()));
                fields.push(("Attributes", body.attributes.to_string()));
                fields.push(("Text nodes", body.string_values.to_string()));
            }
            fields
        }
        Some(Summary::Gfx {
            version,
            declared_len,
            rect_len,
            frame_rate,
            frame_count,
            tags,
            max_depth,
        }) => vec![
            ("Version", version.to_string()),
            ("Declared length", declared_len.to_string()),
            ("RECT", format!("{rect_len} bytes")),
            (
                "Frame rate",
                format!("{}.{}", frame_rate >> 8, frame_rate & 0xFF),
            ),
            ("Frames", frame_count.to_string()),
            ("Tags", format!("{tags} (depth {max_depth})")),
        ],
        Some(Summary::Psin) | Some(Summary::Rpf9) | None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_psin_as_recognition_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        std::fs::write(&path, b"PSIN\x00\x00\x00\x00synthetic").unwrap();
        let mut source = Source::open(&path).unwrap();

        let report = detect(&mut source).expect("recognised");
        assert_eq!(report.name, "PSIN");
        assert_eq!(report.support, "recognition");
        assert!(report.fields.is_empty());
        assert!(report.error.is_none());
    }

    /// A minimal RBF0 document: a versioned header, a named root element and
    /// an empty body.
    fn rbf0_document() -> Vec<u8> {
        let mut bytes = b"RBF0".to_vec();
        bytes.extend_from_slice(&0xFFFBu16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(b"doc");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
        bytes
    }

    #[test]
    fn reports_the_parsed_rbf0_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.bin");
        std::fs::write(&path, rbf0_document()).unwrap();
        let mut source = Source::open(&path).unwrap();

        let report = detect(&mut source).expect("recognised");
        assert_eq!(report.name, "RBF0");
        assert_eq!(report.support, "structural");
        assert!(report.error.is_none());
        let fields = report
            .fields
            .iter()
            .map(|(label, value)| (*label, value.as_str()))
            .collect::<Vec<_>>();
        assert!(fields.contains(&("Objects", "1 (depth 0)")), "{fields:?}");
        assert!(fields.contains(&("Fields", "0")), "{fields:?}");
        assert!(fields.contains(&("Definitions", "1")), "{fields:?}");
        assert!(fields.contains(&("Attributes", "0")), "{fields:?}");
        assert!(fields.contains(&("Text nodes", "0")), "{fields:?}");
    }

    #[test]
    fn reports_an_rbf0_body_failure_with_the_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.bin");
        let mut bytes = rbf0_document();
        // A type-7 token in the body, which the grammar does not define.
        let at = bytes.len() - 2;
        bytes[at..].copy_from_slice(&0x7000u16.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        let mut source = Source::open(&path).unwrap();

        let report = detect(&mut source).expect("recognised");
        assert_eq!(report.name, "RBF0");
        assert!(report.error.is_some());
        assert!(
            report
                .fields
                .contains(&("Header", "versioned (version 1)".to_string()))
        );
    }

    #[test]
    fn leaves_unrecognised_data_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.bin");
        std::fs::write(&path, b"nothing to recognise here").unwrap();
        let mut source = Source::open(&path).unwrap();
        assert!(detect(&mut source).is_none());
    }
}
