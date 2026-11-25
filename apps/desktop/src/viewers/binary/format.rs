//! Content-based format recognition for the inspector.
//!
//! Only fields the research documentation establishes are shown; a field whose
//! meaning is unknown is either omitted or labelled as unknown. The report is
//! produced on the thread that opens the file, never on the UI thread, and it
//! never contains payload bytes.

use std::sync::atomic::AtomicBool;

use lforge_binary::Source;
use lforge_rage9::rbf0;
use lforge_rage9::rds5::{self, Container, Storage};

/// Bytes read to recognise a format.
const SIGNATURE_LEN: usize = 16;
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
    let head = lforge_binary::read_at(source, 0, SIGNATURE_LEN).ok()?;
    if rds5::is_rds5(&head) {
        return Some(rds5_report(source));
    }
    if rbf0::is_rbf0(&head) {
        return Some(match rbf0::Header::parse(&head) {
            Ok(header) => Report {
                name: "RBF0",
                support: "header",
                fields: vec![
                    ("Version word", format!("0x{:04X}", header.word)),
                    ("Flags", header.flags.to_string()),
                    ("Root name", format!("{} bytes", header.root_name_len)),
                ],
                error: None,
            },
            Err(err) => Report {
                name: "RBF0",
                support: "header",
                fields: Vec::new(),
                error: Some(err.describe().to_string()),
            },
        });
    }
    if head.starts_with(b"PSIN") {
        return Some(Report {
            name: "PSIN",
            support: "recognition",
            fields: Vec::new(),
            error: None,
        });
    }
    if lforge_rage9::rpf::is_rpf9(&head) {
        return Some(Report {
            name: "RPF9",
            support: "recognition",
            fields: Vec::new(),
            error: None,
        });
    }
    None
}

fn rds5_report(source: &mut Source) -> Report {
    let len = source.len();
    let cancel = AtomicBool::new(false);
    let mut container = match Container::read(source, len, &rds5::Limits::default(), &cancel) {
        Ok(container) => container,
        Err(err) => {
            return Report {
                name: "RDS5",
                support: "structural",
                fields: Vec::new(),
                error: Some(err.to_string()),
            };
        }
    };
    let classified = container
        .classify(source, SAMPLE_BLOCKS, &cancel)
        .unwrap_or(0);
    let zlib = container
        .blocks
        .iter()
        .take(classified)
        .filter(|block| block.storage == Storage::Zlib)
        .count();
    let mut fields = vec![
        ("Version", format!("0x{:08X}", container.version)),
        ("Records", container.record_count().to_string()),
        (
            "Blocks",
            format!("{} ({zlib} of {classified} zlib)", container.blocks.len()),
        ),
        ("Entries", container.entry_count.to_string()),
        (
            "Uncompressed",
            format!(
                "{} ({} bytes)",
                crate::files::format_size(u64::from(container.uncompressed_total)),
                crate::files::format_bytes_exact(u64::from(container.uncompressed_total))
            ),
        ),
    ];
    if let Some(warning) = container.warnings.first() {
        fields.push(("Note", warning.clone()));
    }
    Report {
        name: "RDS5",
        support: "structural",
        fields,
        error: None,
    }
}
