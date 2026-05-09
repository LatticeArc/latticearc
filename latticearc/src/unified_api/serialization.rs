#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Serialization utilities for cryptographic types.
//!
//! Provides JSON serialization for encrypted data, signed data, and key pairs
//! using Base64 encoding for binary fields.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::unified_api::crypto_types::{EncryptedOutput, EncryptionScheme, HybridComponents};
use crate::unified_api::{
    error::{CoreError, Result},
    types::{KeyPair, SignedData},
};

/// Decode a base64 string, collapsing the error to a fixed message.
///
/// `base64::DecodeError::Display` includes byte position and offending
/// byte, both of which are attacker-controllable when the input came
/// from a deserialized envelope. Echoing them via `format!("{e}")`
/// gives an attacker a per-field fingerprint of which decode failed
/// and where; route the raw error to `tracing::debug!` and surface a
/// fixed string in the typed `CoreError` instead.
pub(crate) fn decode_b64_opaque(input: &str, field: &'static str) -> Result<Vec<u8>> {
    BASE64_ENGINE.decode(input).map_err(|e| {
        tracing::debug!(error = %e, field = field, "base64 decode rejected");
        CoreError::SerializationError("base64 decode failed".to_string())
    })
}

/// Decode a JSON string into `T`, collapsing the error to a fixed message.
///
/// `serde_json::Error::Display` includes line/column and offending
/// tokens. Same Pattern-6 reasoning as [`decode_b64_opaque`]: route
/// the raw error to `tracing::debug!` and surface a fixed string in
/// the typed `CoreError`.
pub(crate) fn decode_json_opaque<T: serde::de::DeserializeOwned>(
    data: &str,
    field: &'static str,
) -> Result<T> {
    serde_json::from_str(data).map_err(|e| {
        tracing::debug!(error = %e, field = field, "JSON decode rejected");
        CoreError::SerializationError("JSON decode failed".to_string())
    })
}

/// Decode CBOR bytes into `T`, collapsing the error to a fixed message.
///
/// `ciborium::Error::Display` includes byte offset and type-mismatch
/// detail, both attacker-controllable for a deserialized envelope.
/// Same Pattern-6 reasoning as [`decode_b64_opaque`] /
/// [`decode_json_opaque`].
pub(crate) fn decode_cbor_opaque<T: serde::de::DeserializeOwned>(
    data: &[u8],
    field: &'static str,
) -> Result<T> {
    ciborium::from_reader(data).map_err(|e| {
        tracing::debug!(error = %e, field = field, "CBOR decode rejected");
        CoreError::SerializationError("CBOR decode failed".to_string())
    })
}

/// Serializable form of signed data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSignedData {
    /// Base64-encoded original data
    pub data: String,
    /// Signature metadata
    pub metadata: SerializableSignedMetadata,
    /// Signature scheme identifier
    pub scheme: String,
    /// Timestamp of signing
    pub timestamp: u64,
}

/// Serializable signed data metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSignedMetadata {
    /// Base64-encoded signature
    pub signature: String,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Base64-encoded public key
    pub public_key: String,
    /// Key identifier (optional)
    pub key_id: Option<String>,
}

/// Serializable form of a key pair.
///
/// `SerializableKeyPair` deliberately does NOT implement `Clone`. Duplicating
/// a serialized keypair would transiently double the number of base64-encoded
/// private-key copies in memory. When two independent instances are genuinely
/// needed (e.g., for serialization roundtrip tests), construct them separately
/// from the same source key via [`SerializableKeyPair::from`].
#[derive(Serialize, Deserialize)]
pub struct SerializableKeyPair {
    /// Base64-encoded public key.
    public_key: String,
    /// Base64-encoded private key.
    private_key: String,
}

impl SerializableKeyPair {
    /// Create a new `SerializableKeyPair` from base64-encoded key strings.
    #[must_use]
    pub fn new(public_key: String, private_key: String) -> Self {
        Self { public_key, private_key }
    }

    /// Returns the base64-encoded public key.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Returns the base64-encoded private key.
    #[must_use]
    pub fn private_key(&self) -> &str {
        &self.private_key
    }
}

impl std::fmt::Debug for SerializableKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerializableKeyPair")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for SerializableKeyPair {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.private_key.as_bytes().ct_eq(other.private_key.as_bytes())
    }
}

impl Drop for SerializableKeyPair {
    fn drop(&mut self) {
        // Zeroize private key string bytes before deallocation to prevent
        // sensitive key material from lingering in freed heap memory.
        self.private_key.zeroize();
    }
}

impl From<&SignedData> for SerializableSignedData {
    fn from(signed: &SignedData) -> Self {
        Self {
            data: BASE64_ENGINE.encode(&signed.data),
            metadata: SerializableSignedMetadata {
                signature: BASE64_ENGINE.encode(&signed.metadata.signature),
                signature_algorithm: signed.metadata.signature_algorithm.clone(),
                public_key: BASE64_ENGINE.encode(&signed.metadata.public_key),
                key_id: signed.metadata.key_id.clone(),
            },
            scheme: signed.scheme.clone(),
            timestamp: signed.timestamp,
        }
    }
}

impl TryFrom<SerializableSignedData> for SignedData {
    type Error = CoreError;

    fn try_from(serializable: SerializableSignedData) -> Result<Self> {
        let data = decode_b64_opaque(&serializable.data, "data")?;
        let signature = decode_b64_opaque(&serializable.metadata.signature, "metadata.signature")?;
        let public_key =
            decode_b64_opaque(&serializable.metadata.public_key, "metadata.public_key")?;

        // Cross-verify the metadata `signature_algorithm` against the
        // top-level `scheme`. Without this check `signature_algorithm`
        // is a decorative field — verify dispatches on `scheme`, so an
        // attacker could replace `signature_algorithm` with arbitrary
        // text and verification would still succeed, misleading any
        // consumer that displays or logs it for audit / UX purposes.
        // The sign side sets both to the same value, so disagreement
        // signals tampering. Both fields are attacker-controlled, so
        // the typed error must not echo them.
        if serializable.metadata.signature_algorithm != serializable.scheme {
            tracing::debug!(
                metadata_algorithm = %serializable.metadata.signature_algorithm,
                scheme = %serializable.scheme,
                "SignedData rejected: metadata.signature_algorithm disagrees with scheme"
            );
            return Err(CoreError::SerializationError("SignedData metadata mismatch".to_string()));
        }

        Ok(SignedData::new(
            data,
            crate::types::SignedMetadata::new(
                signature,
                serializable.metadata.signature_algorithm,
                public_key,
                serializable.metadata.key_id,
            ),
            serializable.scheme,
            serializable.timestamp,
        ))
    }
}

impl From<&KeyPair> for SerializableKeyPair {
    fn from(keypair: &KeyPair) -> Self {
        Self {
            public_key: BASE64_ENGINE.encode(keypair.public_key().as_slice()),
            private_key: BASE64_ENGINE.encode(keypair.private_key().expose_secret()),
        }
    }
}

impl TryFrom<SerializableKeyPair> for KeyPair {
    type Error = CoreError;

    fn try_from(serializable: SerializableKeyPair) -> Result<Self> {
        let public_key_bytes = decode_b64_opaque(&serializable.public_key, "public_key")?;
        let private_key_bytes = decode_b64_opaque(&serializable.private_key, "private_key")?;

        let public_key = crate::types::PublicKey::new(public_key_bytes);
        let private_key = crate::types::PrivateKey::new(private_key_bytes);

        Ok(KeyPair::new(public_key, private_key))
    }
}

/// Serializes signed data to a JSON string.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn serialize_signed_data(signed: &SignedData) -> Result<String> {
    let serializable = SerializableSignedData::from(signed);
    serde_json::to_string(&serializable).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// Deserializes signed data from a JSON string.
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - Base64 decoding of the data, signature, or public key fails
pub fn deserialize_signed_data(data: &str) -> Result<SignedData> {
    enforce_max_input_size(data, "SignedData")?;
    let serializable: SerializableSignedData = decode_json_opaque(data, "SignedData")?;
    serializable.try_into()
}

/// Serializes a keypair to a JSON string.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn serialize_keypair(keypair: &KeyPair) -> Result<String> {
    let serializable = SerializableKeyPair::from(keypair);
    serde_json::to_string(&serializable).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// Deserializes a keypair from a JSON string.
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - Base64 decoding of the public key or private key fails
pub fn deserialize_keypair(data: &str) -> Result<KeyPair> {
    enforce_max_input_size(data, "KeyPair")?;
    let serializable: SerializableKeyPair = decode_json_opaque(data, "KeyPair")?;
    serializable.try_into()
}

// ============================================================================
// EncryptedOutput serialization (with hybrid support)
// ============================================================================

/// Serializable form of `EncryptedOutput`.
///
/// Includes hybrid component support (KEM ciphertext + ephemeral ECDH key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableEncryptedOutput {
    /// Format version (`2` for `EncryptedOutput`)
    pub version: u8,
    /// Encryption scheme identifier (e.g., `"aes-256-gcm"`)
    pub scheme: String,
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded AEAD nonce (12 bytes)
    pub nonce: String,
    /// Base64-encoded AEAD authentication tag (16 bytes)
    pub tag: String,
    /// Hybrid components (present only for hybrid schemes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid_data: Option<SerializableHybridComponents>,
    /// Unix timestamp when encryption was performed
    pub timestamp: u64,
    /// Optional key identifier for key management
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// Serializable hybrid components (KEM ciphertext + ephemeral ECDH key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableHybridComponents {
    /// Base64-encoded ML-KEM ciphertext (1088 bytes for ML-KEM-768)
    pub ml_kem_ciphertext: String,
    /// Base64-encoded X25519 ephemeral public key (32 bytes)
    pub ecdh_ephemeral_pk: String,
}

impl From<&EncryptedOutput> for SerializableEncryptedOutput {
    fn from(output: &EncryptedOutput) -> Self {
        Self {
            version: 2,
            scheme: output.scheme().as_str().to_string(),
            ciphertext: BASE64_ENGINE.encode(output.ciphertext()),
            nonce: BASE64_ENGINE.encode(output.nonce()),
            tag: BASE64_ENGINE.encode(output.tag()),
            hybrid_data: output.hybrid_data().map(|hd| SerializableHybridComponents {
                ml_kem_ciphertext: BASE64_ENGINE.encode(hd.ml_kem_ciphertext()),
                ecdh_ephemeral_pk: BASE64_ENGINE.encode(hd.ecdh_ephemeral_pk()),
            }),
            timestamp: output.timestamp(),
            key_id: output.key_id().map(str::to_owned),
        }
    }
}

impl TryFrom<SerializableEncryptedOutput> for EncryptedOutput {
    type Error = CoreError;

    fn try_from(ser: SerializableEncryptedOutput) -> Result<Self> {
        // Defense-in-depth: reject excessively large serialized
        // payloads before base64 decode. Caps are per-field, not just
        // on `ciphertext`: a crafted envelope with a 10 MiB nonce
        // would otherwise bypass the ciphertext-only check.
        const MAX_CIPHERTEXT_B64: usize = 10 * 1024 * 1024; // 10 MiB
        // AEAD nonce is 12 B raw → ~16 B b64; AEAD tag is 16 B → ~24 B
        // b64. Leave generous slack so future schemes that use longer
        // nonces (e.g. 24-byte XChaCha20-Poly1305) still fit.
        const MAX_NONCE_B64: usize = 64;
        const MAX_TAG_B64: usize = 64;
        // ML-KEM ciphertext is 768/1088/1568 B raw → up to ~2092 B
        // b64. ECDH ephemeral PK is 32 B → ~44 B b64.
        const MAX_KEM_CT_B64: usize = 4096;
        const MAX_ECDH_PK_B64: usize = 256;

        let check_field_len = |field: &str, len: usize, cap: usize| -> Result<()> {
            if len > cap {
                return Err(CoreError::SerializationError(format!(
                    "Serialized {} size {} exceeds maximum of {} bytes",
                    field, len, cap
                )));
            }
            Ok(())
        };
        check_field_len("ciphertext", ser.ciphertext.len(), MAX_CIPHERTEXT_B64)?;
        check_field_len("nonce", ser.nonce.len(), MAX_NONCE_B64)?;
        check_field_len("tag", ser.tag.len(), MAX_TAG_B64)?;
        if let Some(hd) = ser.hybrid_data.as_ref() {
            check_field_len("ml_kem_ciphertext", hd.ml_kem_ciphertext.len(), MAX_KEM_CT_B64)?;
            check_field_len("ecdh_ephemeral_pk", hd.ecdh_ephemeral_pk.len(), MAX_ECDH_PK_B64)?;
        }

        // `ser.scheme` is attacker-controlled JSON. Don't echo the
        // raw value in the typed error.
        let scheme = EncryptionScheme::parse_str(&ser.scheme).ok_or_else(|| {
            tracing::debug!(received = %ser.scheme, "EncryptedOutput rejected: unknown encryption scheme");
            CoreError::SerializationError("Unknown encryption scheme".to_string())
        })?;

        let ciphertext = decode_b64_opaque(&ser.ciphertext, "ciphertext")?;
        let nonce = decode_b64_opaque(&ser.nonce, "nonce")?;
        let tag = decode_b64_opaque(&ser.tag, "tag")?;

        let hybrid_data = ser
            .hybrid_data
            .map(|hd| -> Result<HybridComponents> {
                let ml_kem_ciphertext =
                    decode_b64_opaque(&hd.ml_kem_ciphertext, "ml_kem_ciphertext")?;
                let ecdh_ephemeral_pk =
                    decode_b64_opaque(&hd.ecdh_ephemeral_pk, "ecdh_ephemeral_pk")?;
                Ok(HybridComponents::new(ml_kem_ciphertext, ecdh_ephemeral_pk))
            })
            .transpose()?;

        // Cross-verify the top-level `nonce` and `tag` fields against
        // the copies embedded in `ciphertext` for SYMMETRIC schemes.
        //
        // Symmetric schemes (AES-256-GCM, ChaCha20-Poly1305) pack the
        // wire format as `nonce(12) || actual_ciphertext || tag(16)`
        // INSIDE the `ciphertext` field, AND duplicate the nonce/tag
        // into the top-level fields. The decrypt path consumes only
        // the packed bytes — without this check the top-level fields
        // are decorative, and a third-party tool that authenticates
        // against `ser.tag` would silently pass even if `ser.tag` was
        // zeroed out.
        //
        // Hybrid (`requires_hybrid_key`) and PQ-only
        // (`requires_pq_key`) schemes use a different wire layout:
        // `ciphertext` holds only the AEAD ciphertext bytes (no
        // embedded nonce/tag prefix or suffix), and the top-level
        // `nonce` / `tag` are the canonical values consumed by
        // decrypt. There is nothing to cross-verify in those cases —
        // the top-level fields are authoritative, not decorative —
        // so the check is skipped.
        //
        // Constant-time comparison mirrors the AEAD tag-equality
        // discipline (no oracle on which half disagreed); mismatch
        // collapses to `DecryptionFailed` (Pattern 6 — distinguishable
        // errors here would let an attacker probe which field they
        // were allowed to tamper).
        if scheme.requires_symmetric_key() {
            const AEAD_NONCE_LEN: usize = 12;
            const AEAD_TAG_LEN: usize = 16;
            const AEAD_FRAME_LEN: usize = AEAD_NONCE_LEN + AEAD_TAG_LEN; // 28
            if ciphertext.len() < AEAD_FRAME_LEN {
                // Too-short ciphertext can't carry an embedded nonce
                // and tag — that's a structural error. Reject here
                // (Pattern 6: same opaque variant as below) rather
                // than skipping the consistency check and letting
                // the AEAD path reject; previously the gate quietly
                // passed and the M5 cross-check could be bypassed by
                // a deliberately-malformed short ciphertext.
                return Err(CoreError::DecryptionFailed("decryption failed".to_string()));
            }
            let embedded_nonce = ciphertext
                .get(..AEAD_NONCE_LEN)
                .ok_or_else(|| CoreError::DecryptionFailed("decryption failed".to_string()))?;
            let tag_start = ciphertext.len().saturating_sub(AEAD_TAG_LEN);
            let embedded_tag = ciphertext
                .get(tag_start..)
                .ok_or_else(|| CoreError::DecryptionFailed("decryption failed".to_string()))?;
            // `subtle::ConstantTimeEq` for slices already short-
            // circuits on length mismatch internally — no separate
            // `len.ct_eq()` is needed (and adding one is dead
            // combinatorics). Just `ct_eq` the bytes directly.
            use subtle::ConstantTimeEq;
            let consistent: bool = (nonce.ct_eq(embedded_nonce) & tag.ct_eq(embedded_tag)).into();
            if !consistent {
                return Err(CoreError::DecryptionFailed("decryption failed".to_string()));
            }
        }

        EncryptedOutput::new(scheme, ciphertext, nonce, tag, hybrid_data, ser.timestamp, ser.key_id)
            .map_err(|e| CoreError::SerializationError(e.to_string()))
    }
}

/// Serializes `EncryptedOutput` to a JSON string.
///
/// This is the canonical serialization for data encrypted with the unified API.
/// It supports hybrid encryption components (ML-KEM ciphertext + X25519
/// ephemeral key).
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn serialize_encrypted_output(output: &EncryptedOutput) -> Result<String> {
    let serializable = SerializableEncryptedOutput::from(output);
    serde_json::to_string(&serializable).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// Deserializes `EncryptedOutput` from a JSON string.
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - Base64 decoding of any binary field fails
/// - The scheme string is unrecognized
pub fn deserialize_encrypted_output(data: &str) -> Result<EncryptedOutput> {
    enforce_max_input_size(data, "EncryptedOutput")?;
    let serializable: SerializableEncryptedOutput = decode_json_opaque(data, "EncryptedOutput")?;
    serializable.try_into()
}

/// Maximum accepted JSON-input size for any deserializer in this module.
///
/// Bounds heap allocation by `serde_json::from_str` BEFORE the parse —
/// the per-field caps in the various `TryFrom` impls fire too late
/// (`serde_json` has already allocated the full base64 String into the
/// `Serializable*` shape by the time those checks run). 16 MiB is well
/// above any legitimate envelope (the largest single ciphertext field
/// allows 10 MiB + base64 expansion + envelope overhead) and well below
/// the bands that would let a single inbound JSON payload exhaust a
/// process's working set on a typical 8 GiB server.
// 16 MiB was too generous — it sat above the per-field
// 10 MiB cap (line 290) plus base64 expansion (~13.4 MiB worst case)
// plus envelope overhead, so the per-field rejection always fired
// AFTER `serde_json::from_str` already materialized the full
// `SerializableEncryptedOutput` (raw JSON + decoded String + decoded
// Vec — ~2.5× per accepted message). Tighten to 12 MiB so the input
// gate fires before any serde allocation on payloads that would only
// be rejected at the field-cap stage.
pub(crate) const MAX_DESERIALIZE_INPUT_SIZE: usize = 12 * 1024 * 1024;

fn enforce_max_input_size(data: &str, kind: &'static str) -> Result<()> {
    if data.len() > MAX_DESERIALIZE_INPUT_SIZE {
        return Err(CoreError::SerializationError(format!(
            "{kind} JSON input size {} exceeds maximum of {} bytes",
            data.len(),
            MAX_DESERIALIZE_INPUT_SIZE
        )));
    }
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test/bench scaffolding: lints suppressed for this module"
)]
mod tests {
    use super::*;
    use crate::types::{CryptoPayload, PrivateKey, SignedMetadata};
    use crate::unified_api::crypto_types::{EncryptedOutput, EncryptionScheme, HybridComponents};

    fn make_signed_data() -> SignedData {
        // The production sign path (`api.rs:1019-1029`) sets
        // `metadata.signature_algorithm = scheme.clone()` — the two
        // fields must agree on every produced record.'s S4
        // fix elevates that producer-side guarantee to a deserializer
        // invariant, so test fixtures must match the production
        // shape. The earlier test data here used a mismatched pair
        // (`"ML-DSA-65"` vs `"ML-DSA-65+Ed25519"`), which only
        // worked because the deserializer was previously a passthrough.
        CryptoPayload::new(
            vec![1, 2, 3, 4],
            SignedMetadata::new(
                vec![0xBB; 64],
                "ML-DSA-65+Ed25519".to_string(),
                vec![0xCC; 32],
                Some("sig-key-001".to_string()),
            ),
            "ML-DSA-65+Ed25519".to_string(),
            1700000002,
        )
    }

    fn make_keypair() -> KeyPair {
        KeyPair::new(crate::types::PublicKey::new(vec![1u8; 32]), PrivateKey::new(vec![2u8; 64]))
    }

    // --- SignedData serialization ---

    #[test]
    fn test_signed_data_roundtrip() {
        let original = make_signed_data();
        let json = serialize_signed_data(&original).unwrap();
        let deserialized = deserialize_signed_data(&json).unwrap();

        assert_eq!(original.data, deserialized.data);
        assert_eq!(original.metadata.signature, deserialized.metadata.signature);
        assert_eq!(
            original.metadata.signature_algorithm,
            deserialized.metadata.signature_algorithm
        );
        assert_eq!(original.metadata.public_key, deserialized.metadata.public_key);
        assert_eq!(original.metadata.key_id, deserialized.metadata.key_id);
        assert_eq!(original.scheme, deserialized.scheme);
        assert_eq!(original.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_signed_data_from_trait_succeeds() {
        let original = make_signed_data();
        let serializable = SerializableSignedData::from(&original);
        assert!(!serializable.data.is_empty());
        assert_eq!(serializable.metadata.signature_algorithm, "ML-DSA-65+Ed25519");
    }

    #[test]
    fn test_signed_data_try_from_invalid_base64_fails() {
        let bad = SerializableSignedData {
            data: "not-valid!!!".to_string(),
            metadata: SerializableSignedMetadata {
                signature: BASE64_ENGINE.encode(b"sig"),
                signature_algorithm: "test".to_string(),
                public_key: BASE64_ENGINE.encode(b"pk"),
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<SignedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_data_try_from_invalid_signature_fails() {
        let bad = SerializableSignedData {
            data: BASE64_ENGINE.encode(b"data"),
            metadata: SerializableSignedMetadata {
                signature: "not-valid!!!".to_string(),
                signature_algorithm: "test".to_string(),
                public_key: BASE64_ENGINE.encode(b"pk"),
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<SignedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_data_try_from_invalid_public_key_fails() {
        let bad = SerializableSignedData {
            data: BASE64_ENGINE.encode(b"data"),
            metadata: SerializableSignedMetadata {
                signature: BASE64_ENGINE.encode(b"sig"),
                signature_algorithm: "test".to_string(),
                public_key: "not-valid!!!".to_string(),
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<SignedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_signed_data_invalid_json_fails() {
        let result = deserialize_signed_data("not json");
        assert!(result.is_err());
    }

    // --- KeyPair serialization ---

    #[test]
    fn test_keypair_roundtrip() {
        let original = make_keypair();
        let json = serialize_keypair(&original).unwrap();
        let deserialized = deserialize_keypair(&json).unwrap();

        assert_eq!(original.public_key(), deserialized.public_key());
        assert_eq!(
            original.private_key().expose_secret(),
            deserialized.private_key().expose_secret()
        );
    }

    #[test]
    fn test_keypair_from_trait_succeeds() {
        let original = make_keypair();
        let serializable = SerializableKeyPair::from(&original);
        assert!(!serializable.public_key.is_empty());
        assert!(!serializable.private_key.is_empty());
    }

    #[test]
    fn test_keypair_try_from_invalid_public_key_fails() {
        let bad = SerializableKeyPair {
            public_key: "not-valid!!!".to_string(),
            private_key: BASE64_ENGINE.encode(b"secret"),
        };
        let result: std::result::Result<KeyPair, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_try_from_invalid_private_key_fails() {
        let bad = SerializableKeyPair {
            public_key: BASE64_ENGINE.encode(b"public"),
            private_key: "not-valid!!!".to_string(),
        };
        let result: std::result::Result<KeyPair, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_keypair_invalid_json_fails() {
        let result = deserialize_keypair("not json");
        assert!(result.is_err());
    }

    // --- EncryptedOutput serialization ---

    fn make_encrypted_output_symmetric() -> EncryptedOutput {
        // The wire layout requires the top-level `nonce`/`tag` to
        // match the embedded copies in `ciphertext` for symmetric
        // schemes — wire layout is `nonce(12) || actual_ct || tag(16)`.
        // Build the fixture ciphertext with that invariant so the
        // deserializer's cross-check passes.
        let nonce: Vec<u8> = (1..=12).collect();
        let tag = vec![0xAA_u8; 16];
        let inner = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cap = nonce.len().saturating_add(inner.len()).saturating_add(tag.len());
        let mut ct = Vec::with_capacity(cap);
        ct.extend_from_slice(&nonce);
        ct.extend_from_slice(&inner);
        ct.extend_from_slice(&tag);
        EncryptedOutput::new(
            EncryptionScheme::Aes256Gcm,
            ct,
            nonce,
            tag,
            None,
            1_700_000_000,
            Some("key-001".to_string()),
        )
        .expect("valid symmetric shape")
    }

    fn make_encrypted_output_hybrid() -> EncryptedOutput {
        EncryptedOutput::new(
            EncryptionScheme::HybridMlKem768Aes256Gcm,
            vec![0xBE, 0xEF, 0xCA, 0xFE],
            vec![0u8; 12],
            vec![0xBB; 16],
            Some(HybridComponents::new(vec![0xCC; 1088], vec![0xDD; 32])),
            1_700_000_001,
            None,
        )
        .expect("valid hybrid shape")
    }

    #[test]
    fn test_encrypted_output_symmetric_roundtrip() {
        let original = make_encrypted_output_symmetric();
        let json = serialize_encrypted_output(&original).unwrap();
        let deserialized = deserialize_encrypted_output(&json).unwrap();

        assert_eq!(original.scheme(), deserialized.scheme());
        assert_eq!(original.ciphertext(), deserialized.ciphertext());
        assert_eq!(original.nonce(), deserialized.nonce());
        assert_eq!(original.tag(), deserialized.tag());
        assert!(deserialized.hybrid_data().is_none());
        assert_eq!(original.timestamp(), deserialized.timestamp());
        assert_eq!(original.key_id(), deserialized.key_id());
    }

    #[test]
    fn test_encrypted_output_hybrid_roundtrip() {
        let original = make_encrypted_output_hybrid();
        let json = serialize_encrypted_output(&original).unwrap();
        let deserialized = deserialize_encrypted_output(&json).unwrap();

        assert_eq!(original.scheme(), deserialized.scheme());
        assert_eq!(original.ciphertext(), deserialized.ciphertext());
        assert_eq!(original.nonce(), deserialized.nonce());
        assert_eq!(original.tag(), deserialized.tag());
        assert_eq!(original.timestamp(), deserialized.timestamp());
        assert_eq!(original.key_id(), deserialized.key_id());

        let orig_hd = original.hybrid_data().unwrap();
        let deser_hd = deserialized.hybrid_data().unwrap();
        assert_eq!(orig_hd.ml_kem_ciphertext(), deser_hd.ml_kem_ciphertext());
        assert_eq!(orig_hd.ecdh_ephemeral_pk(), deser_hd.ecdh_ephemeral_pk());
    }

    #[test]
    fn test_encrypted_output_version_field_succeeds() {
        let output = make_encrypted_output_symmetric();
        let json = serialize_encrypted_output(&output).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(raw["version"], 2);
    }

    #[test]
    fn test_encrypted_output_scheme_as_string_succeeds() {
        let output = make_encrypted_output_hybrid();
        let json = serialize_encrypted_output(&output).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(raw["scheme"], "hybrid-ml-kem-768-aes-256-gcm");
    }

    #[test]
    fn test_encrypted_output_hybrid_data_omitted_when_none_succeeds() {
        let output = make_encrypted_output_symmetric();
        let json = serialize_encrypted_output(&output).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(raw.get("hybrid_data").is_none());
    }

    #[test]
    fn test_encrypted_output_key_id_omitted_when_none_succeeds() {
        let output = make_encrypted_output_hybrid(); // key_id is None
        let json = serialize_encrypted_output(&output).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(raw.get("key_id").is_none());
    }

    #[test]
    fn test_encrypted_output_unknown_scheme_rejected_fails() {
        let json = r#"{"version":2,"scheme":"fake-999","ciphertext":"AAAA","nonce":"AAAA","tag":"AAAA","timestamp":0}"#;
        let result = deserialize_encrypted_output(json);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("Unknown encryption scheme"));
    }

    #[test]
    fn test_encrypted_output_invalid_ciphertext_base64_fails() {
        let json = r#"{"version":2,"scheme":"aes-256-gcm","ciphertext":"not-valid!!!","nonce":"AAAA","tag":"AAAA","timestamp":0}"#;
        let result = deserialize_encrypted_output(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_output_invalid_hybrid_base64_fails() {
        let json = r#"{"version":2,"scheme":"hybrid-ml-kem-768-aes-256-gcm","ciphertext":"AAAA","nonce":"AAAA","tag":"AAAA","hybrid_data":{"ml_kem_ciphertext":"not-valid!!!","ecdh_ephemeral_pk":"AAAA"},"timestamp":0}"#;
        let result = deserialize_encrypted_output(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_output_invalid_json_fails() {
        let result = deserialize_encrypted_output("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_output_all_schemes_roundtrip() {
        let schemes = [
            EncryptionScheme::Aes256Gcm,
            EncryptionScheme::ChaCha20Poly1305,
            EncryptionScheme::HybridMlKem512Aes256Gcm,
            EncryptionScheme::HybridMlKem768Aes256Gcm,
            EncryptionScheme::HybridMlKem1024Aes256Gcm,
        ];
        // Symmetric schemes require `nonce(12) || ct || tag(16)`
        // packed in `ciphertext`. For
        // hybrid schemes the layout is different — `ciphertext` is
        // just the AEAD output and the deserializer accepts any
        // matching pair. We construct a single packed buffer and
        // feed it to both arms; the hybrid arm ignores the embedded
        // nonce/tag.
        let nonce = vec![0u8; 12];
        let tag = vec![0u8; 16];
        let inner = vec![1u8, 2, 3];
        let cap = nonce.len().saturating_add(inner.len()).saturating_add(tag.len());
        let mut packed = Vec::with_capacity(cap);
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&inner);
        packed.extend_from_slice(&tag);
        for scheme in &schemes {
            let output = EncryptedOutput::new(
                scheme.clone(),
                if scheme.requires_symmetric_key() { packed.clone() } else { inner.clone() },
                nonce.clone(),
                tag.clone(),
                if scheme.requires_hybrid_key() {
                    Some(HybridComponents::new(vec![0xAA; 32], vec![0xBB; 32]))
                } else {
                    None
                },
                42,
                None,
            )
            .expect("valid shape for each scheme above");
            let json = serialize_encrypted_output(&output).unwrap();
            let restored = deserialize_encrypted_output(&json).unwrap();
            assert_eq!(output.scheme(), restored.scheme(), "scheme mismatch for {:?}", scheme);
        }
    }

    #[test]
    fn test_serializable_encrypted_output_clone_debug_work_correctly_succeeds() {
        let output = make_encrypted_output_symmetric();
        let ser = SerializableEncryptedOutput::from(&output);
        let cloned = ser.clone();
        assert_eq!(cloned.scheme, ser.scheme);
        let debug = format!("{:?}", ser);
        assert!(debug.contains("SerializableEncryptedOutput"));
    }

    // --- Serializable struct debug/clone ---

    #[test]
    fn test_serializable_signed_data_clone_debug_work_correctly_succeeds() {
        let original = make_signed_data();
        let ser = SerializableSignedData::from(&original);
        let cloned = ser.clone();
        assert_eq!(cloned.scheme, ser.scheme);
        let debug = format!("{:?}", ser);
        assert!(debug.contains("SerializableSignedData"));
    }

    #[test]
    fn test_serializable_keypair_debug_succeeds() {
        let original = make_keypair();
        let ser = SerializableKeyPair::from(&original);
        let debug = format!("{:?}", ser);
        assert!(debug.contains("SerializableKeyPair"));
    }

    #[test]
    fn test_serializable_keypair_two_instances_from_same_source_are_equal() {
        // Replacement for the removed clone test: two independently-constructed
        // instances from the same source key serialize to the same bytes for
        // both public and private components.
        let original = make_keypair();
        let ser_a = SerializableKeyPair::from(&original);
        let ser_b = SerializableKeyPair::from(&original);
        assert_eq!(ser_a.public_key, ser_b.public_key);
        assert_eq!(ser_a.private_key, ser_b.private_key);
    }
}
