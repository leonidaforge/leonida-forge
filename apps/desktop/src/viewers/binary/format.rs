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
        // The first descriptor's byte chain is reported when it can be
        // reconstructed. It is never decoded into pixels.
        texture: Some(0),
    };
    let report = recognition::inspect(source, len, &options, &AtomicBool::new(false)).ok()?;
    let format = report.format?;
    let mut fields = fields(report.summary.as_ref());
    if let Some(texture) = report.structure.get("texture")
        && texture.is_object()
    {
        fields.push((
            "Texture 0",
            format!(
                "{} × {}, format {}, {} block(s), {} bytes reconstructed",
                texture["width"],
                texture["height"],
                texture["format_id"],
                texture["block_count"],
                texture["decoded_len"],
            ),
        ));
        fields.push((
            "Representation",
            "reconstructed bytes, not a decoded image".into(),
        ));
    }
    Some(Report {
        name: format.name,
        support: format.support,
        fields,
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
        Some(Summary::Psin {
            family,
            sections,
            checksum,
            decoded,
        }) => {
            let mut fields = vec![
                ("Family", (*family).to_string()),
                ("Sections", sections.to_string()),
                ("Integrity", (*checksum).to_string()),
            ];
            match decoded {
                Some(counts) => {
                    fields.push((
                        "Schema",
                        format!("{} structures, {} fields", counts.structures, counts.fields),
                    ));
                    fields.push((
                        "Instances",
                        format!(
                            "{} blocks, {}/{} records",
                            counts.blocks, counts.records_decoded, counts.records
                        ),
                    ));
                    if counts.unsupported_blocks > 0 {
                        fields.push((
                            "Unsupported",
                            format!("{} blocks", counts.unsupported_blocks),
                        ));
                    }
                }
                None => fields.push(("Schema", "not decoded for this family".to_string())),
            }
            fields
        }
        Some(Summary::Edup {
            count,
            first_distinct,
            second_distinct,
            blob_len,
        }) => vec![
            ("Entries", count.to_string()),
            ("First field", format!("{first_distinct} distinct")),
            ("Second field", format!("{second_distinct} distinct")),
            ("Trailing blob", format!("{blob_len} bytes, opaque")),
            ("Key direction", "not evaluated".to_string()),
        ],
        Some(Summary::Adat {
            variant,
            streams,
            records,
            packets,
            blocks,
            violations,
            framing_checked,
        }) => vec![
            ("Variant", format!("0x{variant:04X}")),
            ("Streams", streams.to_string()),
            ("Chunk records", records.to_string()),
            ("Packets", format!("{packets} in {blocks} data blocks")),
            ("Framing", format!("{violations} violations")),
            (
                "Checked",
                if *framing_checked {
                    "every stream class is supported".to_string()
                } else {
                    "some streams are unclassified".to_string()
                },
            ),
            ("Audio", "inspection only; no decode".to_string()),
        ],
        Some(Summary::Kb2 {
            variant,
            frames,
            width,
            height,
            tracks,
            issues,
        }) => vec![
            ("Container", (*variant).to_string()),
            ("Frames", frames.to_string()),
            ("Dimensions", format!("{width} × {height}")),
            ("Audio tracks", tracks.to_string()),
            ("Issues", issues.to_string()),
            ("Video", "container only; no decode".to_string()),
        ],
        Some(Summary::MetaResource { object_type }) => vec![
            ("Tag", "0DRP".to_string()),
            ("Object type", format!("0x{object_type:02X}")),
            (
                "Structure",
                "the resource form; its tables are not decoded".to_string(),
            ),
        ],
        Some(Summary::Rpf9) | None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_psin_with_its_family() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.bin");
        // One section with an unsupported tag: the framing still parses.
        let mut bytes = b"PSIN".to_vec();
        bytes.extend_from_slice(&8u32.to_be_bytes());
        bytes.extend_from_slice(b"ZZZZ");
        bytes.extend_from_slice(&16u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        std::fs::write(&path, &bytes).unwrap();
        let mut source = Source::open(&path).unwrap();

        let report = detect(&mut source).expect("recognised");
        assert_eq!(report.name, "PSIN");
        assert_eq!(report.support, "structural");
        assert!(report.error.is_none());
        let fields = report
            .fields
            .iter()
            .map(|(label, value)| (*label, value.as_str()))
            .collect::<Vec<_>>();
        assert!(fields.contains(&("Family", "other")), "{fields:?}");
        assert!(fields.contains(&("Sections", "1")), "{fields:?}");
        assert!(fields.contains(&("Integrity", "unsupported")), "{fields:?}");
    }

    #[test]
    fn reports_an_edup_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edup.bin");
        let mut bytes = b"EDUP".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        std::fs::write(&path, bytes).unwrap();
        let mut source = Source::open(&path).unwrap();

        let report = detect(&mut source).expect("recognised");
        assert_eq!(report.name, "EDUP");
        assert!(report.error.is_none());
        let fields = report
            .fields
            .iter()
            .map(|(label, value)| (*label, value.as_str()))
            .collect::<Vec<_>>();
        assert!(fields.contains(&("Entries", "1")), "{fields:?}");
        assert!(
            fields.contains(&("Key direction", "not evaluated")),
            "{fields:?}"
        );
    }

    #[test]
    fn reports_an_adat_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("adat.bin");
        let mut bytes = vec![0u8; 0x1E];
        bytes[..4].copy_from_slice(b"ADAT");
        bytes[4..8].copy_from_slice(&0xFF21_0001u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x0C..0x10].copy_from_slice(&0x1Eu32.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        let mut source = Source::open(&path).unwrap();

        let report = detect(&mut source).expect("recognised");
        assert_eq!(report.name, "ADAT");
        assert!(report.error.is_none());
        let fields = report
            .fields
            .iter()
            .map(|(label, value)| (*label, value.as_str()))
            .collect::<Vec<_>>();
        assert!(fields.contains(&("Variant", "0xFF21")), "{fields:?}");
        assert!(
            fields.contains(&("Audio", "inspection only; no decode")),
            "{fields:?}"
        );
    }

    #[test]
    fn reports_a_kb2_container() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kb2.bin");
        let size = 0x30 + 4 * 3;
        let mut bytes = vec![0u8; size];
        bytes[..4].copy_from_slice(b"KB2j");
        bytes[4..8].copy_from_slice(&((size - 8) as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x0C..0x10].copy_from_slice(&4u32.to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x18..0x1C].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x1C..0x20].copy_from_slice(&30u32.to_le_bytes());
        bytes[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        for (index, value) in [0x3Cu32 | 1, 0x3C, size as u32].into_iter().enumerate() {
            let at = 0x30 + 4 * index;
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        std::fs::write(&path, bytes).unwrap();
        let mut source = Source::open(&path).unwrap();

        let report = detect(&mut source).expect("recognised");
        assert_eq!(report.name, "KB2");
        assert!(report.error.is_none());
        let fields = report
            .fields
            .iter()
            .map(|(label, value)| (*label, value.as_str()))
            .collect::<Vec<_>>();
        assert!(fields.contains(&("Container", "KB2j")), "{fields:?}");
        assert!(fields.contains(&("Dimensions", "16 × 16")), "{fields:?}");
        assert!(
            fields.contains(&("Video", "container only; no decode")),
            "{fields:?}"
        );
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
