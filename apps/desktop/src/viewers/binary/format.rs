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

/// Blocks whose storage selector is read for a report.
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
            word,
            flags,
            root_name_len,
        }) => vec![
            ("Version word", format!("0x{word:04X}")),
            ("Flags", flags.to_string()),
            ("Root name", format!("{root_name_len} bytes")),
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

    #[test]
    fn leaves_unrecognised_data_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.bin");
        std::fs::write(&path, b"nothing to recognise here").unwrap();
        let mut source = Source::open(&path).unwrap();
        assert!(detect(&mut source).is_none());
    }
}
