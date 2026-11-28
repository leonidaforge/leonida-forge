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

use lforge_rage9::odrp;
use lforge_rage9::psin::pso::Limits;
use lforge_rage9::psin::pso::names::Names;
use lforge_rage9::rbf0;
use lforge_rage9::rpf::resource::PageSplit;
use serde_json::{Value as Json, json};

use crate::pso;

pub use lforge_rage9::odrp::Document as OdrpDocument;
pub use lforge_rage9::psin::pso::Document as PsoDocument;
pub use lforge_rage9::rbf0::Document as Rbf0Document;

/// The schema of the JSON document each format writes.
pub const PSO_SCHEMA: &str = "leonida-forge.psin-document/1";
pub const RBF0_SCHEMA: &str = "leonida-forge.rbf0-document/1";
pub const ODRP_SCHEMA: &str = "leonida-forge.odrp-document/1";

/// A decoded metadata document.
#[derive(Debug, Clone, PartialEq)]
pub enum Document {
    /// A `PSIN` container of the `LSCH` family.
    Pso(PsoDocument),
    /// An `RBF0` payload.
    Rbf0(Rbf0Document),
    /// A `0DRP` metadata resource.
    Odrp(Box<OdrpDocument>),
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
    /// A `0DRP` resource that did not decode.
    Odrp(String),
    /// A `0DRP` resource whose graphics pages were not located.
    OdrpNeedsPages,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unknown => f.write_str("the payload is not a PSIN or RBF0 document"),
            Error::Pso(reason) => write!(f, "PSIN: {reason}"),
            Error::Rbf0(reason) => write!(f, "RBF0: {reason}"),
            Error::Odrp(reason) => write!(f, "0DRP: {reason}"),
            Error::OdrpNeedsPages => f.write_str(
                "0DRP: the resource has graphics pages, so its page table is needed to locate them",
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Decodes a metadata payload by its own signature.
///
/// `PSIN` is tried first because its magic is checked before anything is read
/// and `RBF0`'s is equally specific; the two never share four bytes. A
/// `0DRP` resource is recognised by its header shape and tag.
///
/// A resource with graphics pages needs the page split the caller reads from
/// the row's page table; [`decode_with_split`] takes it. Without it, only a
/// resource whose pages are all system data can be split.
pub fn decode(payload: &[u8]) -> Result<Document, Error> {
    decode_with_split(payload, None)
}

/// Decodes a metadata payload, splitting a `0DRP` resource with `split`.
pub fn decode_with_split(payload: &[u8], split: Option<PageSplit>) -> Result<Document, Error> {
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
    if odrp::is_odrp(payload) {
        let (system, graphics) = match split {
            Some(split) => {
                let system_len = usize::try_from(split.system_len)
                    .ok()
                    .filter(|len| *len <= payload.len())
                    .ok_or_else(|| {
                        Error::Odrp("the page split is larger than the payload".to_string())
                    })?;
                payload.split_at(system_len)
            }
            None => match graphics_pages(payload) {
                Some(0) => (payload, &[][..]),
                _ => return Err(Error::OdrpNeedsPages),
            },
        };
        let document = odrp::decode(system, graphics, &Limits::default())
            .map_err(|err| Error::Odrp(err.to_string()))?;
        return Ok(Document::Odrp(Box::new(document)));
    }
    Err(Error::Unknown)
}

/// The page counts a `0DRP` payload's page map declares.
fn graphics_pages(payload: &[u8]) -> Option<u8> {
    let map = lforge_rage9::resource::page_map_offset(payload)? as usize;
    Some(*payload.get(map + 9)?)
}

impl Document {
    /// `pso` or `rbf0`.
    pub fn format(&self) -> &'static str {
        match self {
            Document::Pso(_) => "pso",
            Document::Rbf0(_) => "rbf0",
            Document::Odrp(_) => "0drp",
        }
    }

    /// The schema of the JSON document this format writes.
    pub fn schema(&self) -> &'static str {
        match self {
            Document::Pso(_) => PSO_SCHEMA,
            Document::Rbf0(_) => RBF0_SCHEMA,
            Document::Odrp(_) => ODRP_SCHEMA,
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
            Document::Odrp(document) => document.status(),
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
            Document::Odrp(document) => format!(
                "{} structures, {} blocks, {} records, {} texts, depth {}",
                document.structures.len(),
                document.blocks.len(),
                document.record_count(),
                document.text_count(),
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
            Document::Odrp(document) => crate::odrp::document_json(document, names, sample),
        }
    }

    /// The document as XML, with `source` naming where the bytes came from.
    /// `sample` bounds the records written for a `PSIN` container; an `RBF0`
    /// document is a tree and is always written whole.
    pub fn document_xml(&self, sample: usize, source: &[(&str, String)]) -> String {
        match self {
            Document::Pso(document) => pso::document_xml(document, sample, source),
            Document::Rbf0(document) => crate::rbf0::document_xml(document, source),
            Document::Odrp(document) => crate::odrp::document_xml(document, sample, source),
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
            Document::Odrp(document) => crate::odrp::counts_json(document),
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

    /// A `0DRP` header with a page map that declares `graphics` graphics pages
    /// and nothing else; enough to test dispatch and the split.
    fn odrp_header(system_pages: u8, graphics_pages: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x100];
        let map = 0x80usize;
        bytes[8..16].copy_from_slice(&(0x5000_0000u64 | map as u64).to_le_bytes());
        bytes[0x10..0x14].copy_from_slice(b"0DRP");
        bytes[0x14] = 0x7A;
        bytes[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        bytes[map + 8] = system_pages;
        bytes[map + 9] = graphics_pages;
        bytes
    }

    #[test]
    fn a_resource_with_graphics_pages_needs_its_page_table() {
        let payload = odrp_header(1, 1);
        assert_eq!(decode(&payload).unwrap_err(), Error::OdrpNeedsPages);
        assert!(matches!(
            decode_with_split(&payload, None).unwrap_err(),
            Error::OdrpNeedsPages
        ));
    }

    #[test]
    fn a_split_past_the_payload_is_refused() {
        let payload = odrp_header(1, 1);
        let split = PageSplit {
            system_len: 0x1000,
            graphics_len: 0,
            system_pages: 1,
            graphics_pages: 1,
        };
        assert!(matches!(
            decode_with_split(&payload, Some(split)).unwrap_err(),
            Error::Odrp(_)
        ));
    }

    #[test]
    fn a_resource_shaped_payload_is_dispatched_to_the_resource_decoder() {
        // The tables are absent, so the decoder must report a resource
        // problem rather than an unknown payload.
        let payload = odrp_header(1, 0);
        assert!(matches!(decode(&payload).unwrap_err(), Error::Odrp(_)));
        assert_ne!(decode(&payload).unwrap_err(), Error::Unknown);
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
