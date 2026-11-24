//! RSASSA-PKCS1-v1_5 with SHA-256 verification for the RPF9 metadata
//! signature.
//!
//! The engine fixes the scheme: a 256-byte signature, SHA-256, PKCS#1 v1.5
//! block type 1 and the SHA-256 DigestInfo payload. It also fixes the signed
//! spans, which are the metadata bytes after step 1 and before steps 4 and 5.
//!
//! The public key is read from the caller's executable. It is not bundled and
//! no storage address is assumed: candidate key-table entries are recognized by
//! their `(key_id << 32) | 0x05000000` store key and a valid DER
//! `rsaEncryption` SubjectPublicKeyInfo.
//!
//! Nothing here prints or returns key material, signature bytes or decrypted
//! metadata.

use std::fmt;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

use lforge_binary::pe::{ExecutableView, Section};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

use super::{Stored, u16_at, u32_at, u64_at};

/// Signature length fixed by the engine.
pub const SIGNATURE_LEN: usize = 0x100;
/// The only key-store namespace observed in the verifier.
const KEY_STORE_NAMESPACE: u64 = 0x0500_0000;
/// Larger key blobs are not read.
const MAX_KEY_BLOB: u64 = 64 * 1024;
/// Raw bytes read per key-table scan step.
const KEY_SCAN_CHUNK: usize = 1024 * 1024;
/// Key-table scan bounds.
const MAX_KEY_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const MAX_KEY_SCAN_OFFSETS: u64 = 33_554_432;
/// Offsets between cancellation checks.
const CANCEL_CHECK_OFFSETS: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// No B sub-block 6 or 2 exists.
    Missing,
    /// The signature record, spans or lengths are invalid.
    Malformed(&'static str),
    /// The record's message type is not 0 or 1.
    UnsupportedMessageType(u8),
    /// No key-table entry matches the archive's key identifier.
    KeyNotFound,
    /// More than one key-table entry matches.
    KeyAmbiguous,
    /// A matching key entry does not hold a usable RSA-2048 key.
    KeyMalformed(&'static str),
    /// The signature does not verify.
    Invalid,
    /// The caller cancelled the scan.
    Cancelled,
    /// A scan bound was exceeded.
    ResourceLimit { what: &'static str, limit: u64 },
    /// The executable could not be read.
    Image(&'static str),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Missing => f.write_str("no signature sub-block"),
            SignatureError::Malformed(reason) => write!(f, "malformed signature record: {reason}"),
            SignatureError::UnsupportedMessageType(kind) => {
                write!(f, "unsupported signature message type {kind}")
            }
            SignatureError::KeyNotFound => f.write_str("no verification key"),
            SignatureError::KeyAmbiguous => f.write_str("more than one verification key"),
            SignatureError::KeyMalformed(reason) => {
                write!(f, "malformed verification key: {reason}")
            }
            SignatureError::Invalid => f.write_str("signature does not verify"),
            SignatureError::Cancelled => f.write_str("cancelled"),
            SignatureError::ResourceLimit { what, limit } => {
                write!(f, "the {what} exceeds the limit of {limit}")
            }
            SignatureError::Image(reason) => {
                write!(f, "the executable could not be read: {reason}")
            }
        }
    }
}

impl std::error::Error for SignatureError {}

/// A parsed signature record. Its fields are not printed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SignatureRecord {
    pub message_type: u8,
    pub key_id: u32,
    pub signature: Range<usize>,
}

impl fmt::Debug for SignatureRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureRecord")
            .field("message_type", &self.message_type)
            .finish_non_exhaustive()
    }
}

/// Reads the signature record from the post-step-1 `B` block. Sub-block 6 is
/// preferred; sub-block 2 is the fallback with message type 0.
pub(crate) fn record(stored: &Stored, bytes: &[u8]) -> Result<SignatureRecord, SignatureError> {
    match record_for(stored, bytes, 6) {
        Err(SignatureError::Missing) => record_for(stored, bytes, 2),
        result => result,
    }
}

fn record_for(
    stored: &Stored,
    bytes: &[u8],
    sub_block: u16,
) -> Result<SignatureRecord, SignatureError> {
    let offset = stored
        .sub_block(bytes, sub_block)
        .ok_or(SignatureError::Missing)?;
    let b = stored.layout().b_block.clone();
    let start = b
        .start
        .checked_add(offset as usize)
        .ok_or(SignatureError::Malformed("the signature offset overflows"))?;
    let header_end = start
        .checked_add(4)
        .ok_or(SignatureError::Malformed("the signature header overflows"))?;
    let end = header_end
        .checked_add(SIGNATURE_LEN)
        .ok_or(SignatureError::Malformed("the signature length overflows"))?;
    if start < b.start || end > b.end || end > bytes.len() {
        return Err(SignatureError::Malformed(
            "the signature record lies outside the B block",
        ));
    }
    let (message_type, key_id) = if sub_block == 6 {
        (
            bytes[start],
            u16_at(bytes, start + 2)
                .map(u32::from)
                .ok_or(SignatureError::Malformed("short signature header"))?,
        )
    } else {
        (
            0,
            u32_at(bytes, start).ok_or(SignatureError::Malformed("short signature header"))?,
        )
    };
    if message_type > 1 {
        return Err(SignatureError::UnsupportedMessageType(message_type));
    }
    Ok(SignatureRecord {
        message_type,
        key_id,
        signature: header_end..end,
    })
}

/// The exact message spans the engine hashes, in order, over the post-step-1
/// metadata. The signature bytes are excluded.
pub(crate) fn message_spans(
    stored: &Stored,
    record: &SignatureRecord,
) -> Result<Vec<Range<usize>>, SignatureError> {
    let primary = stored.prefix().primary_len as usize;
    let metadata = stored.prefix().metadata_len as usize;
    let signature = &record.signature;
    if signature.end > metadata || signature.start > signature.end {
        return Err(SignatureError::Malformed(
            "the signature lies outside the metadata area",
        ));
    }
    if signature.start < 0x18 || signature.end > primary {
        return Err(SignatureError::Malformed(
            "the signed spans are outside the primary area",
        ));
    }
    let mut spans = Vec::with_capacity(4);
    spans.push(0..0x10);
    if record.message_type == 1 {
        spans.push(0x18..signature.start);
        spans.push(signature.end..primary);
    } else {
        spans.push(signature.end..primary);
    }
    if metadata > primary {
        spans.push(primary..metadata);
    }
    if spans
        .iter()
        .any(|span| span.start > span.end || span.end > metadata)
    {
        return Err(SignatureError::Malformed("a signed span is out of range"));
    }
    Ok(spans)
}

/// Concatenates the signed spans. The caller MUST have checked the spans.
pub(crate) fn message(bytes: &[u8], spans: &[Range<usize>]) -> Vec<u8> {
    let len = spans.iter().map(|span| span.len()).sum();
    let mut message = Vec::with_capacity(len);
    for span in spans {
        message.extend_from_slice(&bytes[span.clone()]);
    }
    message
}

/// Verifies a PKCS#1 v1.5 SHA-256 signature. The signature length MUST match
/// the modulus; the cryptographic library checks the padding and DigestInfo.
///
/// The engine hashes the signed message itself and passes that digest to the
/// RSA verifier, which applies SHA-256 again. The signed value is therefore the
/// double hash of the message.
pub fn verify_message(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    if signature.len() != key.size() || signature.len() != SIGNATURE_LEN {
        return Err(SignatureError::Malformed(
            "the signature length does not match the key",
        ));
    }
    let message_digest = Sha256::digest(message);
    let signed = Sha256::digest(message_digest);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &signed, signature)
        .map_err(|_| SignatureError::Invalid)
}

/// Resolves the public key for `key_id` from a static key-table entry in the
/// executable. One match is required.
pub fn resolve_public_key(
    image: &ExecutableView,
    key_id: u32,
    cancel: &AtomicBool,
) -> Result<RsaPublicKey, SignatureError> {
    let wanted = (u64::from(key_id) << 32) | KEY_STORE_NAMESPACE;
    let sections: Vec<&Section> = image
        .sections()
        .iter()
        .filter(|section| {
            section.is_read_only() && section.is_initialized() && !section.is_executable()
        })
        .collect();
    let scan_bytes: u64 = sections
        .iter()
        .map(|section| u64::from(section.raw_size))
        .sum();
    if scan_bytes > MAX_KEY_SCAN_BYTES {
        return Err(SignatureError::ResourceLimit {
            what: "key-table scan",
            limit: MAX_KEY_SCAN_BYTES,
        });
    }

    let mut found = Vec::new();
    let mut offsets = 0u64;
    for section in sections {
        scan_section(image, cancel, section, wanted, &mut offsets, &mut found)?;
    }
    match found.len() {
        0 => Err(SignatureError::KeyNotFound),
        1 => Ok(found.pop().expect("one key")),
        _ => Err(SignatureError::KeyAmbiguous),
    }
}

fn scan_section(
    image: &ExecutableView,
    cancel: &AtomicBool,
    section: &Section,
    wanted: u64,
    offsets: &mut u64,
    found: &mut Vec<RsaPublicKey>,
) -> Result<(), SignatureError> {
    let size = section.raw_size as usize;
    if size < 0x18 {
        return Ok(());
    }
    let base_rva = u64::from(section.virtual_address);
    let mut chunk_start = 0usize;
    while chunk_start + 0x18 <= size {
        if cancel.load(Ordering::Relaxed) {
            return Err(SignatureError::Cancelled);
        }
        let window = (size - chunk_start).min(KEY_SCAN_CHUNK);
        let read_len = (window + 0x18).min(size - chunk_start);
        let bytes = image
            .read_rva(base_rva + chunk_start as u64, read_len)
            .map_err(|_| SignatureError::Image("a data section cannot be read"))?;
        let mut local = 0usize;
        while local + 0x18 <= read_len && local < window {
            *offsets += 1;
            if *offsets > MAX_KEY_SCAN_OFFSETS {
                return Err(SignatureError::ResourceLimit {
                    what: "key-table scan steps",
                    limit: MAX_KEY_SCAN_OFFSETS,
                });
            }
            if offsets.is_multiple_of(CANCEL_CHECK_OFFSETS) && cancel.load(Ordering::Relaxed) {
                return Err(SignatureError::Cancelled);
            }
            let store_key = u64_at(&bytes, local).expect("checked length");
            if store_key == wanted {
                let pointer = u64_at(&bytes, local + 8).expect("checked length");
                let length = u64_at(&bytes, local + 16).expect("checked length");
                if length == 0 || length > MAX_KEY_BLOB {
                    return Err(SignatureError::KeyMalformed(
                        "the key blob length is not usable",
                    ));
                }
                let der = image
                    .read_va(pointer, length as usize)
                    .map_err(|_| SignatureError::KeyMalformed("the key blob cannot be read"))?;
                let key = RsaPublicKey::from_public_key_der(&der)
                    .map_err(|_| SignatureError::KeyMalformed("the key is not RSA SPKI"))?;
                if key.size() != SIGNATURE_LEN {
                    return Err(SignatureError::KeyMalformed("the key is not RSA-2048"));
                }
                let exponent = key.e();
                if exponent.bits() > 32
                    || exponent < &BigUint::from(3u32)
                    || exponent % BigUint::from(2u32) == BigUint::from(0u32)
                {
                    return Err(SignatureError::KeyMalformed(
                        "the RSA exponent is not usable",
                    ));
                }
                found.push(key);
            }
            local += 8;
        }
        chunk_start += KEY_SCAN_CHUNK;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use rand_core::OsRng;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};

    use super::{SignatureError, verify_message};

    const MESSAGE: &[u8] = b"synthetic RPF9 metadata";

    fn private() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048).expect("a synthetic RSA key"))
    }

    fn public() -> RsaPublicKey {
        RsaPublicKey::from(private())
    }

    fn sign(digest: &[u8]) -> Vec<u8> {
        private()
            .sign(Pkcs1v15Sign::new::<Sha256>(), digest)
            .expect("a synthetic signature")
    }

    fn engine_signature(message: &[u8]) -> Vec<u8> {
        let message_digest = Sha256::digest(message);
        sign(&Sha256::digest(message_digest))
    }

    #[test]
    fn verifies_the_engine_double_hash() {
        let signature = engine_signature(MESSAGE);
        assert!(verify_message(&public(), MESSAGE, &signature).is_ok());
    }

    #[test]
    fn rejects_a_single_hash_signature() {
        let signature = sign(&Sha256::digest(MESSAGE));
        assert!(matches!(
            verify_message(&public(), MESSAGE, &signature),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn rejects_a_mutated_message() {
        let signature = engine_signature(MESSAGE);
        assert!(matches!(
            verify_message(&public(), b"synthetic RPF9 metadat", &signature),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn rejects_a_mutated_signature() {
        let mut signature = engine_signature(MESSAGE);
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert!(matches!(
            verify_message(&public(), MESSAGE, &signature),
            Err(SignatureError::Invalid)
        ));
    }

    #[test]
    fn rejects_a_short_signature() {
        let signature = engine_signature(MESSAGE);
        assert!(matches!(
            verify_message(&public(), MESSAGE, &signature[..signature.len() - 1]),
            Err(SignatureError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_a_signature_from_another_key() {
        let other = RsaPrivateKey::new(&mut OsRng, 2048).expect("a second synthetic RSA key");
        let other_public = RsaPublicKey::from(&other);
        let signature = engine_signature(MESSAGE);
        assert!(matches!(
            verify_message(&other_public, MESSAGE, &signature),
            Err(SignatureError::Invalid)
        ));
    }
}
