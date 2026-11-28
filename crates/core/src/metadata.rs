//! One metadata document API over the formats this build decodes.
//!
//! A `.zmt` row holds a `PSIN` container or an `RBF0` payload, and the two are
//! different documents: `PSIN` carries a self-describing schema and instance
//! blocks, `RBF0` a name table and an element tree. This module picks the
//! decoder from the payload's own signature and gives both the same surface, so
//! the CLI, the exporter and the desktop viewer drive one workflow instead of
//! one per format.
//!
//! The formats keep their own representations. [`Document::Pso`] keeps hashes
//! as identities and never replaces one with a name; [`Document::Rbf0`] keeps
//! the names the payload stores. Neither is forced into the other's shape.

use lforge_rage9::psin::pso::names::Names;
use lforge_rage9::rbf0;
use serde_json::{Value as Json, json};

use crate::pso;

pub use lforge_rage9::psin::pso::Document as PsoDocument;
pub use lforge_rage9::rbf0::Document as Rbf0Document;

/// The schema of the JSON document each format writes.
pub const PSO_SCHEMA: &str = "leonida-forge.psin-document/1";
pub const RBF0_SCHEMA: &str = "leonida-forge.rbf0-document/1";

/// A decoded metadata document.
#[derive(Debug, Clone, PartialEq)]
pub enum Document {
    /// A `PSIN` container of the `LSCH` family.
    Pso(PsoDocument),
    /// An `RBF0` payload.
    Rbf0(Rbf0Document),
}

/// Why a payload is not a document this build decodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The payload starts with neither container's magic.
    Unknown,
    /// A `PSIN` container that did not decode.
    Pso(String),
    /// An `RBF0` payload that did not decode.
    Rbf0(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unknown => f.write_str("the payload is not a PSIN or RBF0 document"),
            Error::Pso(reason) => write!(f, "PSIN: {reason}"),
            Error::Rbf0(reason) => write!(f, "RBF0: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Decodes a metadata payload by its own signature.
///
/// `PSIN` is tried first because its magic is checked before anything is read
/// and `RBF0`'s is equally specific; the two never share four bytes.
pub fn decode(payload: &[u8]) -> Result<Document, Error> {
    if lforge_rage9::psin::is_psin(payload) {
        return lforge_rage9::psin::pso::decode(payload)
            .map(Document::Pso)
            .map_err(|err| Error::Pso(err.to_string()));
    }
    if rbf0::is_rbf0(payload) {
        let document = rbf0::decode(
            payload,
            &rbf0::Limits::default(),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .map_err(|err| Error::Rbf0(err.to_string()))?;
        return Ok(Document::Rbf0(document));
    }
    Err(Error::Unknown)
}

impl Document {
    /// `pso` or `rbf0`.
    pub fn format(&self) -> &'static str {
        match self {
            Document::Pso(_) => "pso",
            Document::Rbf0(_) => "rbf0",
        }
    }

    /// The schema of the JSON document this format writes.
    pub fn schema(&self) -> &'static str {
        match self {
            Document::Pso(_) => PSO_SCHEMA,
            Document::Rbf0(_) => RBF0_SCHEMA,
        }
    }

    /// `decoded`, `partial` or `failed`.
    pub fn status(&self) -> &'static str {
        match self {
            Document::Pso(document) => {
                let counts = pso::counts(document);
                let whole = counts.records_decoded == counts.records
                    && counts.unsupported_blocks == 0
                    && counts.header_matches != Some(false);
                if whole { "decoded" } else { "partial" }
            }
            Document::Rbf0(document) => document.status(),
        }
    }

    /// A one-line statement of what the document holds.
    pub fn summary(&self) -> String {
        match self {
            Document::Pso(document) => format!(
                "{} structures, {} blocks, {} records",
                document.structures.len(),
                document.blocks.len(),
                document.record_count()
            ),
            Document::Rbf0(document) => format!(
                "{} elements, {} names, depth {}",
                document.elements(),
                document.names.len(),
                document.depth()
            ),
        }
    }

    /// The document as JSON. `names` resolves hashes for a `PSIN` container
    /// and is unused by an `RBF0` document, which stores its own names.
    /// `sample` bounds the records written for a `PSIN` container.
    pub fn document_json(&self, names: &Names, sample: usize) -> Json {
        match self {
            Document::Pso(document) => pso::document_json(document, names, sample),
            Document::Rbf0(document) => crate::rbf0::document_json(document),
        }
    }

    /// The document as XML, with `source` naming where the bytes came from.
    /// `sample` bounds the records written for a `PSIN` container; an `RBF0`
    /// document is a tree and is always written whole.
    pub fn document_xml(&self, sample: usize, source: &[(&str, String)]) -> String {
        match self {
            Document::Pso(document) => pso::document_xml(document, sample, source),
            Document::Rbf0(document) => crate::rbf0::document_xml(document, source),
        }
    }

    /// The counts a status line shows, in one shape for both formats.
    pub fn counts_json(&self) -> Json {
        match self {
            Document::Pso(document) => {
                let counts = pso::counts(document);
                json!({
                    "format": "pso",
                    "structures": counts.structures,
                    "fields": counts.fields,
                    "enums": counts.enums,
                    "blocks": counts.blocks,
                    "records": counts.records,
                    "recordsDecoded": counts.records_decoded,
                    "roots": counts.roots,
                })
            }
            Document::Rbf0(document) => {
                let counts = crate::rbf0::counts(document);
                json!({
                    "format": "rbf0",
                    "names": counts.names,
                    "elements": counts.elements,
                    "depth": counts.depth,
                    "fields": counts.fields,
                    "attributes": counts.attributes,
                    "textNodes": counts.text_nodes,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rbf0_payload() -> Vec<u8> {
        // `RBF0`, the versioned header, then a root element `r` with no
        // attributes and no body.
        let mut bytes = b"RBF0".to_vec();
        bytes.extend_from_slice(&0xFFFB_u16.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]); // token: element, name index 0
        bytes.extend_from_slice(&1_u16.to_le_bytes()); // name length
        bytes.push(b'r');
        bytes.extend_from_slice(&[0; 4]); // reserved
        bytes.extend_from_slice(&0_u16.to_le_bytes()); // attribute count
        bytes.extend_from_slice(&[0xFF, 0xFF]); // terminator
        bytes
    }

    #[test]
    fn picks_the_decoder_from_the_signature() {
        let document = decode(&rbf0_payload()).expect("an RBF0 document");
        assert_eq!(document.format(), "rbf0");
        assert_eq!(document.schema(), RBF0_SCHEMA);
        assert_eq!(document.status(), "decoded");
        assert!(document.summary().contains("1 elements"));
        let counts = document.counts_json();
        assert_eq!(counts["format"], "rbf0");
        assert_eq!(counts["names"], 1);
    }

    #[test]
    fn refuses_a_payload_that_is_neither_container() {
        assert_eq!(decode(b"RDS5").unwrap_err(), Error::Unknown);
        assert_eq!(decode(&[]).unwrap_err(), Error::Unknown);
    }

    #[test]
    fn a_psin_signature_with_broken_framing_is_a_psin_error() {
        // The PSIN magic alone is not a container; the refusal must name the
        // format it tried rather than report an unknown payload.
        let error = decode(b"PSIN\x00\x00\x00\x00").unwrap_err();
        assert!(matches!(error, Error::Pso(_)), "{error}");
    }

    #[test]
    fn a_generated_document_is_a_document_of_its_own_format() {
        let document = decode(&rbf0_payload()).expect("an RBF0 document");
        let json = document.document_json(&Names::empty(), 0);
        assert_eq!(json["format"], "rbf0");
        let xml = document.document_xml(0, &[("row", "0".to_string())]);
        assert!(xml.contains(r#"generator="leonida-forge""#));
    }
}
