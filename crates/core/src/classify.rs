//! One authoritative classification of an RPF9 entry.
//!
//! An entry has three independent properties that callers must not conflate:
//!
//! - its numeric **entry type**, stored in the table of contents;
//! - its **payload format**, established from the decoded bytes;
//! - the application's **capability**, which is what it can actually do with the
//!   bytes.
//!
//! A classification is computed from the entry metadata, a bounded decoded head
//! and, only for text, a bounded document validation. It never reads a payload
//! in full by default and never infers a format from the type alone.
//!
//! Only a verified format can supply an extension for an entry that has none.
//! A recognised format without an established extension stays unresolved; the
//! distinction is part of the model, not a caller decision.

use std::io::Read;

use lforge_binary::Source;
use lforge_rage9::rpf::metadata::{Entry, Error, Payload, StreamTransform};

use crate::inspect::{self, FormatInfo};

/// Decoded bytes a classification reads for identification.
pub const HEAD_LEN: usize = 64;
/// Largest payload that is read in full to validate an XML document.
pub const XML_LIMIT: u64 = 4 * 1024 * 1024;

/// The type ID of a nested RPF9 archive.
pub const ARCHIVE_TYPE: u8 = 0;

/// How strongly an identification is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// The available evidence establishes nothing useful.
    Unknown,
    /// A plausible hypothesis that independent checks do not confirm.
    Tentative,
    /// Several observations agree, but required structural evidence is missing.
    Probable,
    /// Repeated tests of real data and structural evidence agree.
    Verified,
}

impl Confidence {
    pub fn name(self) -> &'static str {
        match self {
            Confidence::Verified => "verified",
            Confidence::Probable => "probable",
            Confidence::Tentative => "tentative",
            Confidence::Unknown => "unknown",
        }
    }
}

/// How the payload is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Storage {
    /// The location record's compression mode.
    pub mode: u8,
    /// The chunk table's encoding, when a chunk table is present.
    pub encoding: Option<u8>,
    /// Whether the payload transform flag is set.
    pub transform: bool,
}

impl Storage {
    /// The storage shape as a stable label.
    pub fn label(&self) -> &'static str {
        match (self.encoding, self.mode) {
            (Some(2), _) => "chunked-2",
            (Some(3), _) => "chunked-3",
            (Some(4), _) => "chunked-4",
            (Some(_), _) => "chunked-other",
            (None, 0) => "stored",
            (None, 1) => "raw-deflate",
            (None, _) => "mode-other",
        }
    }
}

/// Whether the payload could be decoded, and why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadState {
    /// The decoded head was read.
    Decoded,
    /// The payload transform is required and no key state is available.
    TransformUnavailable,
    /// The payload transform is available but did not verify or run.
    TransformFailed(String),
    /// The entry's storage cannot be decoded.
    Undecodable(String),
    /// The metadata describing the payload is malformed.
    Malformed(String),
}

impl PayloadState {
    pub fn name(&self) -> &'static str {
        match self {
            PayloadState::Decoded => "decoded",
            PayloadState::TransformUnavailable => "transform-unavailable",
            PayloadState::TransformFailed(_) => "transform-failed",
            PayloadState::Undecodable(_) => "undecodable",
            PayloadState::Malformed(_) => "malformed",
        }
    }
}

/// A payload signature we can name without claiming a parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    /// A supported, structurally parsed format.
    Parsed(&'static str),
    /// `9FPR`: an RPF9 archive.
    Archive,
    /// An XML document.
    Xml,
    /// An image container signature.
    Image(&'static str),
    /// A named signature whose format is not established.
    Observed(&'static str),
    /// Eight zero bytes then a `0x5…` or `0x6…` pointer: a RAGE resource.
    Resource,
    /// Nothing that identifies the bytes.
    Unrecognised,
}

/// A resource system-segment header, as far as the decoded head shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceHeader {
    /// The `u64` at `+0x00`. Zero in every observed sample.
    pub first_word: u64,
    /// The `u64` at `+0x08`.
    pub pointer: u64,
    /// The pointer's segment nibble, 5 (system) or 6 (graphics).
    pub segment: u8,
    /// The page-map offset the pointer names.
    pub map_offset: u32,
}

impl ResourceHeader {
    /// Reads the header from a decoded head. `None` unless the first `u64` is
    /// zero and the second is a `0x5…`/`0x6…` pointer, the shape observed for
    /// resource entries.
    pub fn parse(head: &[u8]) -> Option<Self> {
        let first_word = u64::from_le_bytes(head.get(..8)?.try_into().ok()?);
        let pointer = u64::from_le_bytes(head.get(8..16)?.try_into().ok()?);
        if first_word != 0 || pointer >> 32 != 0 {
            return None;
        }
        // Observed pointers are `0x5…`/`0x6…` followed by a 28-bit offset.
        let segment = u8::try_from((pointer >> 28) & 0xF).ok()?;
        if !matches!(segment, 5 | 6) {
            return None;
        }
        Some(Self {
            first_word,
            pointer,
            segment,
            map_offset: (pointer & 0x0FFF_FFFF) as u32,
        })
    }
}

/// What the decoded head shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identification {
    /// A supported format.
    Format {
        format: FormatInfo,
        confidence: Confidence,
    },
    /// Eight zero bytes and a `0x5…`/`0x6…` pointer.
    Resource {
        header: ResourceHeader,
        confidence: Confidence,
    },
    /// An XML document, with its root element when it was validated.
    Xml {
        root: Option<String>,
        confidence: Confidence,
    },
    /// A named signature without an established format.
    Signature {
        signature: Signature,
        confidence: Confidence,
    },
    /// Nothing identifiable.
    Unrecognised,
}

impl Identification {
    /// The format id, when a supported format was recognised.
    pub fn format_id(&self) -> Option<&'static str> {
        match self {
            Identification::Format { format, .. } => Some(format.id),
            _ => None,
        }
    }

    /// The signature, whether or not it is a supported format.
    pub fn signature(&self) -> Signature {
        match self {
            Identification::Format { format, .. } => Signature::Parsed(format.id),
            Identification::Resource { .. } => Signature::Resource,
            Identification::Xml { .. } => Signature::Xml,
            Identification::Signature { signature, .. } => *signature,
            Identification::Unrecognised => Signature::Unrecognised,
        }
    }

    pub fn confidence(&self) -> Confidence {
        match self {
            Identification::Format { confidence, .. }
            | Identification::Resource { confidence, .. }
            | Identification::Xml { confidence, .. }
            | Identification::Signature { confidence, .. } => *confidence,
            Identification::Unrecognised => Confidence::Unknown,
        }
    }
}

/// Where an entry's extension comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extension {
    /// The archive supplied this extension. Stored exactly as it was found.
    Original(String),
    /// A verified mapping from the payload format.
    Content {
        extension: &'static str,
        confidence: Confidence,
    },
    /// A verified mapping from the entry type, when the payload agrees.
    Type {
        extension: &'static str,
        because: &'static str,
    },
    /// No verified extension.
    Unresolved { reason: &'static str },
}

impl Extension {
    /// The extension to display. An original extension is returned unchanged.
    pub fn resolved(&self) -> Option<&str> {
        match self {
            Extension::Original(extension) => Some(extension),
            Extension::Content { extension, .. } | Extension::Type { extension, .. } => {
                Some(extension)
            }
            Extension::Unresolved { .. } => None,
        }
    }

    /// Whether the extension may be applied automatically.
    pub fn verified(&self) -> bool {
        match self {
            Extension::Original(_) | Extension::Type { .. } => true,
            Extension::Content { confidence, .. } => *confidence == Confidence::Verified,
            Extension::Unresolved { .. } => false,
        }
    }

    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Extension::Unresolved { reason } => Some(reason),
            _ => None,
        }
    }
}

/// What the application can do with the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// An archive the archive commands open.
    Archive,
    /// A structural inspection without field meaning.
    Structural(&'static str),
    /// A text document shown as text.
    Text,
    /// A resource container whose asset class is not identified.
    Resource,
    /// Bytes only, through the binary viewer.
    Bytes,
    /// Nothing can be decoded.
    Unavailable(&'static str),
}

impl Capability {
    pub fn name(self) -> &'static str {
        match self {
            Capability::Archive => "archive",
            Capability::Structural(_) => "structural",
            Capability::Text => "text",
            Capability::Resource => "resource",
            Capability::Bytes => "bytes",
            Capability::Unavailable(_) => "unavailable",
        }
    }

    /// Why the capability is limited, when it is.
    pub fn reason(self) -> Option<&'static str> {
        match self {
            Capability::Unavailable(reason) => Some(reason),
            _ => None,
        }
    }
}

/// The classification of one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub entry_type: Option<u8>,
    pub storage: Option<Storage>,
    pub payload: PayloadState,
    pub identification: Identification,
    pub extension: Extension,
    pub capability: Capability,
    /// Why the entry is not identified or not supported, when it is not.
    pub reason: Option<String>,
}

impl Classification {
    /// The display extension, if the classification established one.
    pub fn extension(&self) -> Option<&str> {
        self.extension.resolved()
    }

    /// The format id, when a supported format was recognised.
    pub fn format_id(&self) -> Option<&'static str> {
        self.identification.format_id()
    }
}

/// One entry's inputs. `head` is the decoded bytes, or nothing when the decode
/// did not produce any.
pub struct Inputs<'a> {
    pub entry_type: Option<u8>,
    pub original_extension: Option<&'a str>,
    pub storage: Option<Storage>,
    pub payload: PayloadState,
    pub head: Option<&'a [u8]>,
}

/// Classifies one entry from its metadata and decoded head.
pub fn classify(inputs: Inputs<'_>) -> Classification {
    let identification = identify_from_head(inputs.head);
    assemble(
        inputs.entry_type,
        inputs.original_extension,
        inputs.storage,
        inputs.payload,
        identification,
    )
}

fn assemble(
    entry_type: Option<u8>,
    original_extension: Option<&str>,
    storage: Option<Storage>,
    payload: PayloadState,
    identification: Identification,
) -> Classification {
    let extension = resolve_extension(entry_type, original_extension, &identification, &payload);
    let capability = capability(&identification, &payload);
    let reason = reason(&payload, &identification, &extension);
    Classification {
        entry_type,
        storage,
        payload,
        identification,
        extension,
        capability,
        reason,
    }
}

/// Identifies a decoded head without running a parser.
pub fn identify_from_head(head: Option<&[u8]>) -> Identification {
    let Some(head) = head else {
        return Identification::Unrecognised;
    };
    if let Some(format) = inspect::recognise(head) {
        // A format whose recogniser walks its structure is established by the
        // head alone; one recognised by its identifier alone is probable.
        let confidence = if format.support == "structural" {
            Confidence::Verified
        } else {
            Confidence::Probable
        };
        return Identification::Format { format, confidence };
    }
    if let Some(header) = ResourceHeader::parse(head) {
        return Identification::Resource {
            header,
            confidence: Confidence::Probable,
        };
    }
    if let Some(signature) = observed_signature(head) {
        return Identification::Signature {
            signature,
            confidence: Confidence::Verified,
        };
    }
    if looks_like_xml(head) {
        return Identification::Xml {
            root: None,
            confidence: Confidence::Tentative,
        };
    }
    Identification::Unrecognised
}

/// Signatures whose name is established by observation but whose format is not.
fn observed_signature(head: &[u8]) -> Option<Signature> {
    const OBSERVED: [(&[u8], &str); 4] = [
        (b"MoVE", "move"),
        (b"SGD5", "sgd5"),
        (b"MHIU", "mhiu"),
        (b"SPS1", "sps1"),
    ];
    for (magic, name) in OBSERVED {
        if head.starts_with(magic) {
            return Some(Signature::Observed(name));
        }
    }
    if head.starts_with(b"DDS ") {
        return Some(Signature::Image("dds"));
    }
    if head.starts_with(b"\x89PNG") {
        return Some(Signature::Image("png"));
    }
    None
}

/// Whether the bytes begin like an XML document: an optional byte-order mark,
/// optional leading whitespace, then a declaration or an element.
pub fn looks_like_xml(head: &[u8]) -> bool {
    let bytes = skip_space(strip_bom(head));
    let bytes = skip_space(strip_bom(bytes));
    bytes.starts_with(b"<?xml") || bytes.starts_with(b"<")
}

/// Validates a whole document with an XML parser. Returns the root element name
/// when the document parses.
pub fn validate_xml(bytes: &[u8]) -> Option<String> {
    let bytes = strip_bom(bytes);
    let text = std::str::from_utf8(bytes).ok()?;
    let document = roxmltree::Document::parse(text).ok()?;
    Some(document.root_element().tag_name().name().to_string())
}

fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_prefix(&[0xEF, 0xBB, 0xBF])
        .or_else(|| bytes.strip_prefix(&[0xFF, 0xFE]))
        .or_else(|| bytes.strip_prefix(&[0xFE, 0xFF]))
        .unwrap_or(bytes)
}

fn skip_space(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn resolve_extension(
    entry_type: Option<u8>,
    original: Option<&str>,
    identification: &Identification,
    payload: &PayloadState,
) -> Extension {
    if let Some(extension) = original {
        return Extension::Original(extension.to_string());
    }
    if matches!(payload, PayloadState::TransformUnavailable) {
        return Extension::Unresolved {
            reason: "the payload is transformed and was not decoded",
        };
    }
    match identification {
        Identification::Format { format, .. } if format.id == "rpf9" => Extension::Content {
            extension: "rpf",
            confidence: Confidence::Verified,
        },
        Identification::Format { .. } => Extension::Unresolved {
            reason: "the format is recognised but no extension is established",
        },
        Identification::Xml {
            confidence: Confidence::Verified,
            ..
        } => Extension::Content {
            extension: "xml",
            confidence: Confidence::Verified,
        },
        Identification::Xml { .. } => Extension::Unresolved {
            reason: "the bytes look like XML but the document was not validated",
        },
        Identification::Resource { .. } => Extension::Unresolved {
            reason: "a resource container; the asset class is not identified",
        },
        Identification::Signature { .. } => Extension::Unresolved {
            reason: "the signature is known but no format or extension is established",
        },
        Identification::Unrecognised => {
            if entry_type == Some(ARCHIVE_TYPE) {
                Extension::Unresolved {
                    reason: "the entry is typed as an archive but its payload is not one",
                }
            } else {
                Extension::Unresolved {
                    reason: "no verified extension for these bytes",
                }
            }
        }
    }
}

fn capability(identification: &Identification, payload: &PayloadState) -> Capability {
    match payload {
        PayloadState::Decoded => {}
        PayloadState::TransformUnavailable => {
            return Capability::Unavailable("the payload transform needs key material");
        }
        PayloadState::TransformFailed(_) => {
            return Capability::Unavailable("the payload transform did not verify");
        }
        PayloadState::Undecodable(_) => {
            return Capability::Unavailable("the storage cannot be decoded");
        }
        PayloadState::Malformed(_) => {
            return Capability::Unavailable("the entry metadata is malformed");
        }
    }
    match identification {
        Identification::Format { format, .. } if format.id == "rpf9" => Capability::Archive,
        Identification::Format { format, .. } => Capability::Structural(format.id),
        Identification::Xml { .. } => Capability::Text,
        Identification::Resource { .. } => Capability::Resource,
        _ => Capability::Bytes,
    }
}

fn reason(
    payload: &PayloadState,
    identification: &Identification,
    extension: &Extension,
) -> Option<String> {
    match payload {
        PayloadState::TransformUnavailable => {
            return Some(
                "the payload is behind the transform and no key state is available".to_string(),
            );
        }
        PayloadState::TransformFailed(reason) => return Some(reason.clone()),
        PayloadState::Undecodable(reason) | PayloadState::Malformed(reason) => {
            return Some(reason.clone());
        }
        PayloadState::Decoded => {}
    }
    match identification {
        Identification::Unrecognised => Some("no known signature in the decoded head".to_string()),
        _ => extension.reason().map(str::to_string),
    }
}

/// Normalises an extension for display: no leading dot, lower case.
pub fn normalise_extension(extension: &str) -> String {
    extension.trim_start_matches('.').to_ascii_lowercase()
}

/// The sources one entry is read through.
pub struct Context<'a> {
    pub main: &'a Source,
    pub alternates: &'a [Option<Source>],
    /// The transform built for the entry, when one is available.
    pub transform: Option<&'a StreamTransform>,
    /// Why the transform could not be built, when it was attempted and failed.
    pub transform_failure: Option<&'a str>,
}

/// What a classification read from the payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// The decoded head the identification was made from.
    pub head: Vec<u8>,
    /// The decoded size, when the payload could be opened.
    pub payload_len: Option<u64>,
    /// How many bytes were read to validate an XML document.
    pub document_bytes: Option<u64>,
}

/// Classifies one entry. Reads at most [`HEAD_LEN`] decoded bytes, plus the rest
/// of a small XML document when the head looks like XML.
pub fn classify_entry(
    entry: &Entry,
    original_extension: Option<&str>,
    context: &Context<'_>,
) -> Classification {
    classify_entry_with_evidence(entry, original_extension, context).0
}

/// [`classify_entry`], with the bytes the classification was made from, so a
/// caller can record the evidence rather than ask for the payload again.
pub fn classify_entry_with_evidence(
    entry: &Entry,
    original_extension: Option<&str>,
    context: &Context<'_>,
) -> (Classification, Evidence) {
    let storage = storage_of(entry);
    let entry_type = entry.type_id();
    let transformed = matches!(entry.payload_transform, Ok(true));
    let mut payload = match build_payload(entry, context, transformed) {
        Ok(payload) => payload,
        Err(state) => {
            return (
                assemble(
                    entry_type,
                    original_extension,
                    storage,
                    state,
                    Identification::Unrecognised,
                ),
                Evidence::default(),
            );
        }
    };
    let mut evidence = Evidence {
        payload_len: Some(payload.len()),
        ..Evidence::default()
    };
    let mut bytes = vec![0u8; HEAD_LEN.min(usize::try_from(payload.len()).unwrap_or(0))];
    let mut read = 0;
    while read < bytes.len() {
        match payload.read(&mut bytes[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(err) => {
                return (
                    assemble(
                        entry_type,
                        original_extension,
                        storage,
                        PayloadState::Undecodable(err.to_string()),
                        Identification::Unrecognised,
                    ),
                    evidence,
                );
            }
        }
    }
    bytes.truncate(read);
    evidence.head = bytes.clone();
    let mut identification = identify_from_head(Some(&bytes));
    if matches!(identification, Identification::Xml { .. }) && payload.len() <= XML_LIMIT {
        let mut document = bytes;
        let target = usize::try_from(payload.len()).unwrap_or(0);
        document.resize(target, 0);
        let mut filled = target.min(read);
        while filled < document.len() {
            match payload.read(&mut document[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => break,
            }
        }
        document.truncate(filled);
        evidence.document_bytes = Some(filled as u64);
        identification = match validate_xml(&document) {
            Some(root) => Identification::Xml {
                root: Some(root),
                confidence: Confidence::Verified,
            },
            None => Identification::Xml {
                root: None,
                confidence: Confidence::Tentative,
            },
        };
    }
    (
        assemble(
            entry_type,
            original_extension,
            storage,
            PayloadState::Decoded,
            identification,
        ),
        evidence,
    )
}

fn storage_of(entry: &Entry) -> Option<Storage> {
    let location = match &entry.location {
        Ok(Some(location)) => *location,
        _ => return None,
    };
    let encoding = match &entry.chunks {
        Ok(Some(chunks)) => Some(chunks.encoding),
        _ => None,
    };
    Some(Storage {
        mode: location.mode,
        encoding,
        transform: matches!(entry.payload_transform, Ok(true)),
    })
}

fn build_payload(
    entry: &Entry,
    context: &Context<'_>,
    transformed: bool,
) -> Result<Payload, PayloadState> {
    if let Err(reason) = &entry.location {
        return Err(PayloadState::Malformed(reason.clone()));
    }
    if transformed {
        let Some(transform) = context.transform else {
            return Err(match context.transform_failure {
                Some(reason) => PayloadState::TransformFailed(reason.to_string()),
                None => PayloadState::TransformUnavailable,
            });
        };
        return entry
            .transformed_payload(context.main, context.alternates, transform.clone())
            .map_err(|err| match err {
                Error::Encoded { .. } => PayloadState::Undecodable(err.to_string()),
                other => PayloadState::TransformFailed(other.to_string()),
            });
    }
    entry
        .payload(context.main, context.alternates)
        .map_err(|err| PayloadState::Undecodable(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(bytes: &[u8]) -> Vec<u8> {
        let mut value = bytes.to_vec();
        value.resize(HEAD_LEN.max(bytes.len()), 0);
        value
    }

    fn storage() -> Option<Storage> {
        Some(Storage {
            mode: 0,
            encoding: Some(3),
            transform: false,
        })
    }

    fn run(entry_type: Option<u8>, original: Option<&str>, bytes: &[u8]) -> Classification {
        let owned = head(bytes);
        classify(Inputs {
            entry_type,
            original_extension: original,
            storage: storage(),
            payload: PayloadState::Decoded,
            head: Some(&owned),
        })
    }

    #[test]
    fn recognises_every_supported_signature() {
        let cases: [(&[u8], &str); 8] = [
            (b"RDS5", "rds5"),
            (b"RBF0", "rbf0"),
            (b"GFX*", "gfx"),
            (b"PSIN", "psin"),
            (b"EDUP", "edup"),
            (b"ADAT", "adat"),
            (b"KB2j", "kb2"),
            (b"KB2n", "kb2"),
        ];
        for (bytes, id) in cases {
            let classification = run(Some(255), None, bytes);
            assert_eq!(classification.format_id(), Some(id), "{id}");
            // Every one of these recognisers walks the payload's own framing
            // from the head, so the format is established by the head alone.
            assert_eq!(
                classification.identification.confidence(),
                Confidence::Verified,
                "{id} has a structural recogniser"
            );
            assert!(matches!(
                classification.capability,
                Capability::Structural(_)
            ));
            assert_eq!(
                classification.extension,
                Extension::Unresolved {
                    reason: "the format is recognised but no extension is established"
                },
                "{id} has no established extension"
            );
        }
    }

    #[test]
    fn a_format_recognised_by_its_identifier_alone_is_probable() {
        // The archive recogniser matches the magic only; the structure is
        // verified when a caller opens the archive.
        let classification = run(Some(0), None, b"9FPR\x10\x12\0\0");
        assert_eq!(
            classification.identification.confidence(),
            Confidence::Probable
        );
    }

    #[test]
    fn a_nested_archive_gets_its_extension_from_the_payload() {
        let classification = run(Some(0), None, b"9FPR\x10\x12\0\0");
        assert_eq!(classification.capability, Capability::Archive);
        assert_eq!(classification.extension(), Some("rpf"));
        assert!(classification.extension.verified());
    }

    #[test]
    fn a_type_zero_entry_whose_payload_is_not_an_archive_keeps_its_extension_unresolved() {
        let classification = run(Some(0), None, b"PSIN");
        assert_eq!(classification.format_id(), Some("psin"));
        assert!(classification.extension().is_none());
    }

    #[test]
    fn an_original_extension_is_preserved_exactly() {
        let classification = run(Some(255), Some("XML"), b"9FPR");
        assert_eq!(
            classification.extension,
            Extension::Original("XML".to_string())
        );
        assert_eq!(classification.extension(), Some("XML"));
        assert!(classification.extension.verified());
    }

    #[test]
    fn a_resource_header_is_recognised_but_not_an_asset_class() {
        let mut bytes = vec![0u8; 16];
        bytes[8..16].copy_from_slice(&0x5000_0310u64.to_le_bytes());
        let classification = run(Some(88), None, &bytes);
        let Identification::Resource { header, .. } = classification.identification else {
            panic!("expected a resource header");
        };
        assert_eq!(header.segment, 5);
        assert_eq!(header.map_offset, 0x310);
        assert_eq!(header.first_word, 0);
        assert_eq!(classification.capability, Capability::Resource);
        assert!(classification.extension().is_none());
        assert_eq!(
            classification.reason.as_deref(),
            Some("a resource container; the asset class is not identified")
        );
    }

    #[test]
    fn a_graphics_segment_pointer_is_a_resource_too() {
        let mut bytes = vec![0u8; 16];
        bytes[8..16].copy_from_slice(&0x6000_0040u64.to_le_bytes());
        let classification = run(Some(5), None, &bytes);
        let Identification::Resource { header, .. } = classification.identification else {
            panic!("expected a resource header");
        };
        assert_eq!(header.segment, 6);
    }

    #[test]
    fn an_all_zero_header_is_not_a_resource() {
        let classification = run(Some(96), None, &[0u8; 16]);
        assert_eq!(classification.identification, Identification::Unrecognised);
        assert_eq!(classification.capability, Capability::Bytes);
        assert!(classification.extension().is_none());
    }

    #[test]
    fn a_nonzero_first_word_is_not_a_resource() {
        let mut bytes = vec![0u8; 16];
        bytes[0] = 1;
        bytes[8..16].copy_from_slice(&0x5000_0040u64.to_le_bytes());
        let classification = run(Some(88), None, &bytes);
        assert_eq!(classification.identification, Identification::Unrecognised);
    }

    #[test]
    fn a_pointer_with_an_unexpected_segment_is_not_a_resource() {
        let mut bytes = vec![0u8; 16];
        bytes[8..16].copy_from_slice(&0x1000_0040u64.to_le_bytes());
        let classification = run(Some(88), None, &bytes);
        assert_eq!(classification.identification, Identification::Unrecognised);
    }

    #[test]
    fn a_truncated_head_identifies_nothing() {
        let classification = classify(Inputs {
            entry_type: Some(88),
            original_extension: None,
            storage: storage(),
            payload: PayloadState::Decoded,
            head: Some(&[0u8; 8]),
        });
        assert_eq!(classification.identification, Identification::Unrecognised);
    }

    #[test]
    fn an_unvalidated_xml_lookalike_keeps_its_extension_unresolved() {
        let classification = run(Some(255), None, b"<?xml version=\"1.0\"?>");
        assert!(matches!(
            classification.identification,
            Identification::Xml {
                root: None,
                confidence: Confidence::Tentative
            }
        ));
        assert_eq!(classification.capability, Capability::Text);
        assert!(classification.extension().is_none());
    }

    #[test]
    fn a_validated_xml_document_gets_the_xml_extension() {
        let classification = classify(Inputs {
            entry_type: Some(255),
            original_extension: None,
            storage: storage(),
            payload: PayloadState::Decoded,
            head: Some(b"<?xml version=\"1.0\"?><root/>"),
        });
        // The head alone is a document; the caller validates to reach Verified.
        assert!(classification.extension().is_none());
        assert_eq!(
            validate_xml(b"<?xml version=\"1.0\"?><root/>"),
            Some("root".to_string())
        );
        let validated = assemble(
            Some(255),
            None,
            storage(),
            PayloadState::Decoded,
            Identification::Xml {
                root: Some("root".to_string()),
                confidence: Confidence::Verified,
            },
        );
        assert_eq!(validated.extension(), Some("xml"));
        assert!(validated.extension.verified());
    }

    #[test]
    fn a_byte_order_mark_and_leading_space_are_accepted() {
        assert!(looks_like_xml(b"\xEF\xBB\xBF<?xml version=\"1.0\"?>"));
        assert!(looks_like_xml(b"  \n\t<root>"));
        assert!(looks_like_xml(b"\xEF\xBB\xBF  <root>"));
        assert!(!looks_like_xml(b"\x00\x00\x00"));
    }

    #[test]
    fn invalid_xml_is_rejected() {
        assert_eq!(validate_xml(b"<?xml version=\"1.0\"?><root>"), None);
        assert_eq!(validate_xml(b"<root></other>"), None);
        assert_eq!(validate_xml(b"not xml"), None);
    }

    #[test]
    fn observed_signatures_are_named_without_a_format() {
        for (bytes, name) in [
            (&b"MoVE"[..], "move"),
            (b"SGD5", "sgd5"),
            (b"MHIU", "mhiu"),
            (b"SPS1", "sps1"),
        ] {
            let classification = run(Some(64), None, bytes);
            assert_eq!(
                classification.identification.signature(),
                Signature::Observed(name)
            );
            assert_eq!(classification.format_id(), None);
            assert_eq!(classification.capability, Capability::Bytes);
            assert!(classification.extension().is_none());
        }
    }

    #[test]
    fn image_signatures_are_named_without_an_extension_mapping() {
        let dds = run(Some(255), None, b"DDS ");
        assert_eq!(dds.identification.signature(), Signature::Image("dds"));
        assert!(dds.extension().is_none());
        let png = run(Some(255), None, b"\x89PNG\r\n\x1a\n");
        assert_eq!(png.identification.signature(), Signature::Image("png"));
        assert!(png.extension().is_none());
    }

    #[test]
    fn a_transformed_payload_is_unavailable_and_not_guessed() {
        let classification = classify(Inputs {
            entry_type: Some(89),
            original_extension: None,
            storage: Some(Storage {
                mode: 0,
                encoding: Some(2),
                transform: true,
            }),
            payload: PayloadState::TransformUnavailable,
            head: None,
        });
        assert_eq!(
            classification.capability,
            Capability::Unavailable("the payload transform needs key material")
        );
        assert!(classification.extension().is_none());
        assert_eq!(
            classification.reason.as_deref(),
            Some("the payload is behind the transform and no key state is available")
        );
    }

    #[test]
    fn an_undecodable_payload_reports_the_reason() {
        let classification = classify(Inputs {
            entry_type: Some(11),
            original_extension: None,
            storage: storage(),
            payload: PayloadState::Undecodable("the compressed data is invalid".to_string()),
            head: None,
        });
        assert!(matches!(
            classification.capability,
            Capability::Unavailable(_)
        ));
        assert_eq!(
            classification.reason.as_deref(),
            Some("the compressed data is invalid")
        );
    }

    #[test]
    fn extensions_are_normalised_for_display_but_not_for_originals() {
        assert_eq!(normalise_extension(".PNG"), "png");
        assert_eq!(normalise_extension("XML"), "xml");
        assert_eq!(normalise_extension("rpf"), "rpf");
        let original = run(Some(255), Some(".XML"), b"9FPR");
        assert_eq!(original.extension(), Some(".XML"));
    }

    #[test]
    fn storage_labels_are_stable() {
        let cases = [
            (0, None, "stored"),
            (1, None, "raw-deflate"),
            (0, Some(2), "chunked-2"),
            (0, Some(3), "chunked-3"),
            (0, Some(4), "chunked-4"),
            (0, Some(9), "chunked-other"),
        ];
        for (mode, encoding, label) in cases {
            let storage = Storage {
                mode,
                encoding,
                transform: false,
            };
            assert_eq!(storage.label(), label);
        }
    }
}
