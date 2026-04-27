//! Type-safe encryption types for the unified API.
//!
//! These types eliminate silent degradation by making key-scheme mismatches
//! a compile-time or early-runtime error rather than a silent fallback.
//!
//! # Design Principles
//!
//! - `EncryptKey` / `DecryptKey` encode what kind of key the caller provides
//! - `EncryptionScheme` replaces string-based dispatch with an enum
//! - `EncryptedOutput` unifies symmetric and hybrid ciphertext formats
//! - Key-scheme mismatches return `Err`, never silently degrade

use std::fmt;

use crate::hybrid::kem_hybrid::{HybridKemPublicKey, HybridKemSecretKey};
use crate::hybrid::pq_only::{PqOnlyPublicKey, PqOnlySecretKey};
use crate::primitives::kem::ml_kem::MlKemSecurityLevel;

/// What kind of key the caller is providing for encryption.
///
/// This enum forces callers to explicitly declare their key type,
/// preventing the old bug where symmetric keys silently degraded
/// hybrid schemes to AES-GCM.
///
/// # Examples
///
/// ```rust,no_run
/// use latticearc::unified_api::crypto_types::EncryptKey;
///
/// // Symmetric key for AES-256-GCM or ChaCha20-Poly1305
/// let sym_key = [0u8; 32];
/// let key = EncryptKey::Symmetric(&sym_key);
///
/// // Hybrid key for ML-KEM-768 + X25519
/// // let (pk, _sk) = latticearc::generate_hybrid_keypair().unwrap();
/// // let key = EncryptKey::Hybrid(&pk);
/// ```
#[non_exhaustive]
pub enum EncryptKey<'a> {
    /// Symmetric key (AES-256-GCM, ChaCha20-Poly1305).
    /// Must be exactly 32 bytes for both algorithms.
    Symmetric(&'a [u8]),
    /// Hybrid PQ public key (ML-KEM + X25519).
    /// Used for hybrid encryption with KEM encapsulation.
    Hybrid(&'a HybridKemPublicKey),
    /// PQ-only public key (ML-KEM, no X25519).
    /// Used for pure post-quantum encryption without a classical component.
    PqOnly(&'a PqOnlyPublicKey),
}

impl fmt::Debug for EncryptKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symmetric(key) => f
                .debug_tuple("EncryptKey::Symmetric")
                .field(&format!("[{} bytes]", key.len()))
                .finish(),
            Self::Hybrid(_) => f.debug_tuple("EncryptKey::Hybrid").field(&"[REDACTED]").finish(),
            Self::PqOnly(_) => f.debug_tuple("EncryptKey::PqOnly").field(&"[REDACTED]").finish(),
        }
    }
}

/// What kind of key the caller is providing for decryption.
///
/// Mirrors `EncryptKey` for the decryption path. The scheme stored
/// in `EncryptedOutput` determines which variant is expected.
#[non_exhaustive]
pub enum DecryptKey<'a> {
    /// Symmetric key for AES-256-GCM or ChaCha20-Poly1305.
    Symmetric(&'a [u8]),
    /// Hybrid PQ secret key for ML-KEM + X25519 decapsulation.
    Hybrid(&'a HybridKemSecretKey),
    /// PQ-only secret key for ML-KEM decapsulation (no X25519).
    PqOnly(&'a PqOnlySecretKey),
}

impl fmt::Debug for DecryptKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symmetric(key) => f
                .debug_tuple("DecryptKey::Symmetric")
                .field(&format!("[{} bytes]", key.len()))
                .finish(),
            Self::Hybrid(_) => f.debug_tuple("DecryptKey::Hybrid").field(&"[REDACTED]").finish(),
            Self::PqOnly(_) => f.debug_tuple("DecryptKey::PqOnly").field(&"[REDACTED]").finish(),
        }
    }
}

/// Type-safe encryption scheme selection.
///
/// Replaces string-based dispatch (`"hybrid-ml-kem-768-aes-256-gcm"` etc.)
/// with an enum that can be pattern-matched exhaustively.
///
/// # Scheme Categories
///
/// | Variant | Key Type | Algorithm |
/// |---------|----------|-----------|
/// | `Aes256Gcm` | Symmetric(32B) | AES-256-GCM |
/// | `ChaCha20Poly1305` | Symmetric(32B) | ChaCha20-Poly1305 |
/// | `HybridMlKem512Aes256Gcm` | Hybrid | ML-KEM-512 + X25519 + HKDF + AES-256-GCM |
/// | `HybridMlKem768Aes256Gcm` | Hybrid | ML-KEM-768 + X25519 + HKDF + AES-256-GCM |
/// | `HybridMlKem1024Aes256Gcm` | Hybrid | ML-KEM-1024 + X25519 + HKDF + AES-256-GCM |
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncryptionScheme {
    /// AES-256-GCM symmetric encryption.
    Aes256Gcm,
    /// ChaCha20-Poly1305 symmetric encryption (fast without AES-NI).
    ChaCha20Poly1305,
    /// Hybrid ML-KEM-512 + X25519 + HKDF-SHA256 + AES-256-GCM.
    HybridMlKem512Aes256Gcm,
    /// Hybrid ML-KEM-768 + X25519 + HKDF-SHA256 + AES-256-GCM (default).
    HybridMlKem768Aes256Gcm,
    /// Hybrid ML-KEM-1024 + X25519 + HKDF-SHA256 + AES-256-GCM.
    HybridMlKem1024Aes256Gcm,
    /// PQ-only ML-KEM-512 + HKDF-SHA256 + AES-256-GCM (no X25519).
    PqMlKem512Aes256Gcm,
    /// PQ-only ML-KEM-768 + HKDF-SHA256 + AES-256-GCM (no X25519).
    PqMlKem768Aes256Gcm,
    /// PQ-only ML-KEM-1024 + HKDF-SHA256 + AES-256-GCM (no X25519).
    PqMlKem1024Aes256Gcm,
}

impl EncryptionScheme {
    /// Returns `true` if this scheme requires a hybrid (PQ + classical) key.
    #[must_use]
    pub const fn requires_hybrid_key(&self) -> bool {
        matches!(
            self,
            Self::HybridMlKem512Aes256Gcm
                | Self::HybridMlKem768Aes256Gcm
                | Self::HybridMlKem1024Aes256Gcm
        )
    }

    /// Returns `true` if this scheme requires a PQ-only key (no classical component).
    #[must_use]
    pub const fn requires_pq_key(&self) -> bool {
        matches!(
            self,
            Self::PqMlKem512Aes256Gcm | Self::PqMlKem768Aes256Gcm | Self::PqMlKem1024Aes256Gcm
        )
    }

    /// Returns `true` if this scheme uses a symmetric key.
    #[must_use]
    pub const fn requires_symmetric_key(&self) -> bool {
        matches!(self, Self::Aes256Gcm | Self::ChaCha20Poly1305)
    }

    /// Returns the ML-KEM security level for hybrid or PQ-only schemes,
    /// or `None` for symmetric.
    #[must_use]
    pub const fn ml_kem_level(&self) -> Option<MlKemSecurityLevel> {
        match self {
            Self::HybridMlKem512Aes256Gcm | Self::PqMlKem512Aes256Gcm => {
                Some(MlKemSecurityLevel::MlKem512)
            }
            Self::HybridMlKem768Aes256Gcm | Self::PqMlKem768Aes256Gcm => {
                Some(MlKemSecurityLevel::MlKem768)
            }
            Self::HybridMlKem1024Aes256Gcm | Self::PqMlKem1024Aes256Gcm => {
                Some(MlKemSecurityLevel::MlKem1024)
            }
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => None,
        }
    }

    /// Convert a hybrid scheme to its PQ-only equivalent at the same NIST level.
    ///
    /// Returns `None` for symmetric or already-PQ-only schemes.
    #[must_use]
    pub const fn to_pq_equivalent(&self) -> Option<Self> {
        match self {
            Self::HybridMlKem512Aes256Gcm => Some(Self::PqMlKem512Aes256Gcm),
            Self::HybridMlKem768Aes256Gcm => Some(Self::PqMlKem768Aes256Gcm),
            Self::HybridMlKem1024Aes256Gcm => Some(Self::PqMlKem1024Aes256Gcm),
            _ => None,
        }
    }

    /// Returns the string identifier for serialization and logging.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::HybridMlKem512Aes256Gcm => "hybrid-ml-kem-512-aes-256-gcm",
            Self::HybridMlKem768Aes256Gcm => "hybrid-ml-kem-768-aes-256-gcm",
            Self::HybridMlKem1024Aes256Gcm => "hybrid-ml-kem-1024-aes-256-gcm",
            Self::PqMlKem512Aes256Gcm => "pq-ml-kem-512-aes-256-gcm",
            Self::PqMlKem768Aes256Gcm => "pq-ml-kem-768-aes-256-gcm",
            Self::PqMlKem1024Aes256Gcm => "pq-ml-kem-1024-aes-256-gcm",
        }
    }

    /// Parse a scheme string into an `EncryptionScheme`.
    ///
    /// Returns `None` for unrecognized strings (e.g. signature schemes).
    #[must_use]
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            "hybrid-ml-kem-512-aes-256-gcm" => Some(Self::HybridMlKem512Aes256Gcm),
            "hybrid-ml-kem-768-aes-256-gcm" => Some(Self::HybridMlKem768Aes256Gcm),
            "hybrid-ml-kem-1024-aes-256-gcm" => Some(Self::HybridMlKem1024Aes256Gcm),
            "pq-ml-kem-512-aes-256-gcm" => Some(Self::PqMlKem512Aes256Gcm),
            "pq-ml-kem-768-aes-256-gcm" => Some(Self::PqMlKem768Aes256Gcm),
            "pq-ml-kem-1024-aes-256-gcm" => Some(Self::PqMlKem1024Aes256Gcm),
            _ => None,
        }
    }
}

impl fmt::Display for EncryptionScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Hybrid-specific components stored alongside the symmetric ciphertext.
///
/// These fields are only present when `EncryptedOutput.scheme` is a hybrid variant.
/// They contain the KEM ciphertext and ephemeral ECDH public key needed for
/// the recipient to derive the same shared secret.
///
/// # Security: non-CT `PartialEq`
///
/// The derived `PartialEq` uses `Vec::eq` (non-constant-time) on the byte
/// fields. This type carries already-produced ciphertext (KEM ct, ephemeral
/// PK) — not a decryption-time MAC check — so equality here is not a
/// classical MAC oracle. Still: **do not introduce `==` on this type in any
/// auth / freshness / replay check**; keep comparisons in test code only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridComponents {
    /// ML-KEM ciphertext (1088 bytes for ML-KEM-768).
    ml_kem_ciphertext: Vec<u8>,
    /// X25519 ephemeral public key (32 bytes). Empty for PQ-only schemes.
    ecdh_ephemeral_pk: Vec<u8>,
}

impl HybridComponents {
    /// Create new hybrid components from KEM ciphertext and ECDH ephemeral public key.
    #[must_use]
    pub fn new(ml_kem_ciphertext: Vec<u8>, ecdh_ephemeral_pk: Vec<u8>) -> Self {
        Self { ml_kem_ciphertext, ecdh_ephemeral_pk }
    }

    /// Returns the ML-KEM ciphertext bytes.
    #[must_use]
    pub fn ml_kem_ciphertext(&self) -> &[u8] {
        &self.ml_kem_ciphertext
    }

    /// Returns the X25519 ephemeral public key bytes. Empty for PQ-only schemes.
    #[must_use]
    pub fn ecdh_ephemeral_pk(&self) -> &[u8] {
        &self.ecdh_ephemeral_pk
    }

    /// Consumes self and returns `(ml_kem_ciphertext, ecdh_ephemeral_pk)`.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.ml_kem_ciphertext, self.ecdh_ephemeral_pk)
    }
}

/// Unified encrypted output replacing both `EncryptedData` and `HybridEncryptionResult`.
///
/// This type carries all information needed for decryption regardless of whether
/// the encryption was symmetric or hybrid. The `scheme` field (an enum, not a string)
/// determines which decryption path to use.
///
/// # Invariants
///
/// - `scheme.requires_hybrid_key()` → `hybrid_data.is_some()` with non-empty ECDH key
/// - `scheme.requires_pq_key()` → `hybrid_data.is_some()` with empty ECDH key (KEM ciphertext only)
/// - `scheme.requires_symmetric_key()` → `hybrid_data.is_none()`
/// - `nonce` is always 12 bytes (AES-GCM and ChaCha20-Poly1305 both use 96-bit nonces)
/// - `tag` is always 16 bytes (both AEAD algorithms produce 128-bit tags)
///
/// # Security: non-CT `PartialEq`
///
/// Derived `PartialEq` compares the `tag` field via `Vec::eq` (non-CT). The
/// tag is already-produced authentication data, not a MAC being checked
/// against an expected value (that check lives inside aws-lc-rs / the
/// chacha20poly1305 crate). So equality here is not a MAC oracle today —
/// but **do not introduce `==` on this type in any auth / freshness /
/// replay check**; keep comparisons in test code only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedOutput {
    /// The encryption scheme used (determines decryption path).
    scheme: EncryptionScheme,
    /// The encrypted data (symmetric ciphertext).
    ciphertext: Vec<u8>,
    /// AEAD nonce (12 bytes).
    nonce: Vec<u8>,
    /// AEAD authentication tag (16 bytes).
    tag: Vec<u8>,
    /// Hybrid-specific components (KEM ciphertext + ephemeral ECDH key).
    /// Present only for hybrid schemes.
    hybrid_data: Option<HybridComponents>,
    /// Unix timestamp when encryption was performed.
    timestamp: u64,
    /// Optional key identifier for key management systems.
    key_id: Option<String>,
}

impl EncryptedOutput {
    /// Create a new `EncryptedOutput` with all fields specified.
    #[must_use]
    pub fn new(
        scheme: EncryptionScheme,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        tag: Vec<u8>,
        hybrid_data: Option<HybridComponents>,
        timestamp: u64,
        key_id: Option<String>,
    ) -> Self {
        // Enforce PQ-only invariant: ecdh_ephemeral_pk must be empty
        debug_assert!(
            !scheme.requires_pq_key()
                || hybrid_data.as_ref().is_some_and(|h| h.ecdh_ephemeral_pk.is_empty()),
            "PQ-only scheme must have hybrid_data with empty ecdh_ephemeral_pk"
        );
        Self { scheme, ciphertext, nonce, tag, hybrid_data, timestamp, key_id }
    }

    /// Return the encryption scheme used.
    #[must_use]
    pub fn scheme(&self) -> &EncryptionScheme {
        &self.scheme
    }

    /// Return the encrypted ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Return the AEAD nonce (12 bytes).
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Return the AEAD authentication tag (16 bytes).
    #[must_use]
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Return a reference to the hybrid components, if present.
    #[must_use]
    pub fn hybrid_data(&self) -> Option<&HybridComponents> {
        self.hybrid_data.as_ref()
    }

    /// Return the Unix timestamp when encryption was performed.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Return the optional key identifier.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Return a new `EncryptedOutput` with the given key identifier set.
    ///
    /// Consumes `self` and returns a modified copy, following a builder pattern.
    #[must_use]
    pub fn with_key_id(mut self, key_id: Option<String>) -> Self {
        self.key_id = key_id;
        self
    }

    /// Serialize this `EncryptedOutput` to a JSON string.
    ///
    /// Inherent-method form of [`crate::unified_api::serialization::serialize_encrypted_output`]
    /// — the most common use case (encrypt → store → load → decrypt) shouldn't
    /// require hunting down a free function.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SerializationError` on JSON encoding failure
    /// (extremely rare — this serializer can't fail for any value of
    /// `EncryptedOutput`).
    pub fn to_json(&self) -> crate::unified_api::error::Result<String> {
        crate::unified_api::serialization::serialize_encrypted_output(self)
    }

    /// Parse an `EncryptedOutput` previously produced by [`to_json`](Self::to_json).
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SerializationError` if the input is not valid
    /// JSON, missing required fields, or contains base64-undecodable bytes.
    pub fn from_json(s: &str) -> crate::unified_api::error::Result<Self> {
        crate::unified_api::serialization::deserialize_encrypted_output(s)
    }

    /// Serialize this `EncryptedOutput` to a self-contained byte string
    /// suitable for on-disk persistence or network transport.
    ///
    /// Internal format is JSON (encoded as UTF-8 bytes) for v0.8.
    /// `EncryptionScheme` is `#[non_exhaustive]`, which makes a stable
    /// `serde` derive non-trivial; until that lands, callers who need a
    /// more compact binary representation should layer their own
    /// serializer on top of the typed accessors (`scheme()`, `ciphertext()`,
    /// etc.). Round-trip is guaranteed via [`from_bytes`](Self::from_bytes).
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SerializationError` on JSON encoding failure
    /// (extremely rare).
    pub fn to_bytes(&self) -> crate::unified_api::error::Result<Vec<u8>> {
        self.to_json().map(String::into_bytes)
    }

    /// Parse an `EncryptedOutput` previously produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SerializationError` if the input is not valid
    /// UTF-8 / JSON or doesn't deserialize into the `EncryptedOutput` shape.
    pub fn from_bytes(bytes: &[u8]) -> crate::unified_api::error::Result<Self> {
        let s = std::str::from_utf8(bytes).map_err(|e| {
            crate::unified_api::error::CoreError::SerializationError(format!("UTF-8 decode: {e}"))
        })?;
        Self::from_json(s)
    }
}

// ============================================================================
// Conversions between EncryptedOutput and legacy EncryptedData
// ============================================================================

use crate::types::types::{CryptoPayload, EncryptedData, EncryptedMetadata};

/// Convert `EncryptedOutput` to legacy `EncryptedData` for serialization.
///
/// The `ciphertext` field (which contains nonce || ct || tag for symmetric schemes)
/// is stored directly in `EncryptedData.data`.
impl From<EncryptedOutput> for EncryptedData {
    fn from(output: EncryptedOutput) -> Self {
        let EncryptedOutput { scheme, ciphertext, nonce, tag, hybrid_data: _, timestamp, key_id } =
            output;
        CryptoPayload {
            data: ciphertext,
            metadata: EncryptedMetadata {
                nonce,
                tag: if tag.is_empty() { None } else { Some(tag) },
                key_id,
            },
            scheme: scheme.to_string(),
            timestamp,
        }
    }
}

/// Convert legacy `EncryptedData` to `EncryptedOutput` for decryption.
///
/// The scheme string is parsed into an `EncryptionScheme` enum.
/// Returns an error for unrecognized schemes instead of silently defaulting.
impl TryFrom<EncryptedData> for EncryptedOutput {
    type Error = crate::types::error::TypeError;

    fn try_from(data: EncryptedData) -> Result<Self, Self::Error> {
        let scheme = EncryptionScheme::parse_str(&data.scheme)
            .ok_or_else(|| crate::types::error::TypeError::UnknownScheme(data.scheme.clone()))?;
        Ok(Self {
            scheme,
            ciphertext: data.data,
            nonce: data.metadata.nonce,
            tag: data.metadata.tag.unwrap_or_default(),
            hybrid_data: None,
            timestamp: data.timestamp,
            key_id: data.metadata.key_id,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_scheme_as_str_roundtrip() {
        let schemes = [
            EncryptionScheme::Aes256Gcm,
            EncryptionScheme::ChaCha20Poly1305,
            EncryptionScheme::HybridMlKem512Aes256Gcm,
            EncryptionScheme::HybridMlKem768Aes256Gcm,
            EncryptionScheme::HybridMlKem1024Aes256Gcm,
            EncryptionScheme::PqMlKem512Aes256Gcm,
            EncryptionScheme::PqMlKem768Aes256Gcm,
            EncryptionScheme::PqMlKem1024Aes256Gcm,
        ];
        for scheme in &schemes {
            let s = scheme.as_str();
            let parsed = EncryptionScheme::parse_str(s).unwrap();
            assert_eq!(&parsed, scheme);
        }
    }

    #[test]
    fn test_encryption_scheme_display_succeeds() {
        assert_eq!(format!("{}", EncryptionScheme::Aes256Gcm), "aes-256-gcm");
        assert_eq!(
            format!("{}", EncryptionScheme::HybridMlKem768Aes256Gcm),
            "hybrid-ml-kem-768-aes-256-gcm"
        );
    }

    #[test]
    fn test_encryption_scheme_requires_key_type_succeeds() {
        assert!(EncryptionScheme::Aes256Gcm.requires_symmetric_key());
        assert!(!EncryptionScheme::Aes256Gcm.requires_hybrid_key());
        assert!(!EncryptionScheme::Aes256Gcm.requires_pq_key());
        assert!(EncryptionScheme::ChaCha20Poly1305.requires_symmetric_key());
        assert!(!EncryptionScheme::ChaCha20Poly1305.requires_hybrid_key());

        assert!(!EncryptionScheme::HybridMlKem768Aes256Gcm.requires_symmetric_key());
        assert!(EncryptionScheme::HybridMlKem768Aes256Gcm.requires_hybrid_key());
        assert!(!EncryptionScheme::HybridMlKem768Aes256Gcm.requires_pq_key());
        assert!(EncryptionScheme::HybridMlKem512Aes256Gcm.requires_hybrid_key());
        assert!(EncryptionScheme::HybridMlKem1024Aes256Gcm.requires_hybrid_key());

        // PQ-only schemes
        assert!(EncryptionScheme::PqMlKem512Aes256Gcm.requires_pq_key());
        assert!(EncryptionScheme::PqMlKem768Aes256Gcm.requires_pq_key());
        assert!(EncryptionScheme::PqMlKem1024Aes256Gcm.requires_pq_key());
        assert!(!EncryptionScheme::PqMlKem768Aes256Gcm.requires_hybrid_key());
        assert!(!EncryptionScheme::PqMlKem768Aes256Gcm.requires_symmetric_key());
    }

    #[test]
    fn test_encryption_scheme_from_str_unknown_succeeds() {
        assert!(EncryptionScheme::parse_str("unknown-scheme").is_none());
        assert!(EncryptionScheme::parse_str("hybrid-ml-dsa-65-ed25519").is_none());
    }

    #[test]
    fn test_encryption_scheme_clone_eq_succeeds() {
        let a = EncryptionScheme::HybridMlKem768Aes256Gcm;
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, EncryptionScheme::Aes256Gcm);
    }

    #[test]
    fn test_encrypted_output_symmetric_succeeds() {
        let output = EncryptedOutput {
            scheme: EncryptionScheme::Aes256Gcm,
            ciphertext: vec![0xDE, 0xAD],
            nonce: vec![0u8; 12],
            tag: vec![0xAA; 16],
            hybrid_data: None,
            timestamp: 1700000000,
            key_id: Some("key-001".to_string()),
        };
        assert!(output.hybrid_data.is_none());
        assert!(output.scheme.requires_symmetric_key());
    }

    #[test]
    fn test_encrypted_output_hybrid_succeeds() {
        let output = EncryptedOutput {
            scheme: EncryptionScheme::HybridMlKem768Aes256Gcm,
            ciphertext: vec![0xBE, 0xEF],
            nonce: vec![0u8; 12],
            tag: vec![0xBB; 16],
            hybrid_data: Some(HybridComponents {
                ml_kem_ciphertext: vec![0xCC; 1088],
                ecdh_ephemeral_pk: vec![0xDD; 32],
            }),
            timestamp: 1700000001,
            key_id: None,
        };
        assert!(output.hybrid_data.is_some());
        assert!(output.scheme.requires_hybrid_key());
    }

    #[test]
    fn test_encrypted_output_pq_only_invariant_succeeds() {
        let output = EncryptedOutput {
            scheme: EncryptionScheme::PqMlKem768Aes256Gcm,
            ciphertext: vec![0xAA; 32],
            nonce: vec![0u8; 12],
            tag: vec![0xBB; 16],
            hybrid_data: Some(HybridComponents {
                ml_kem_ciphertext: vec![0xCC; 1088],
                ecdh_ephemeral_pk: vec![], // PQ-only: empty ECDH key
            }),
            timestamp: 1700000002,
            key_id: None,
        };
        assert!(output.scheme.requires_pq_key());
        assert!(!output.scheme.requires_hybrid_key());
        assert!(output.hybrid_data.is_some());
        // PQ-only invariant: ECDH key must be empty
        assert!(output.hybrid_data.as_ref().unwrap().ecdh_ephemeral_pk.is_empty());
    }

    #[test]
    fn test_encrypted_output_pq_only_to_legacy_roundtrip() {
        let output = EncryptedOutput::new(
            EncryptionScheme::PqMlKem768Aes256Gcm,
            vec![0xDE, 0xAD],
            vec![0u8; 12],
            vec![0xAA; 16],
            Some(HybridComponents {
                ml_kem_ciphertext: vec![0xCC; 1088],
                ecdh_ephemeral_pk: vec![],
            }),
            1700000000,
            Some("pq-key-001".to_string()),
        );
        // Convert to legacy EncryptedData and back
        let legacy: EncryptedData = output.into();
        assert_eq!(legacy.scheme, "pq-ml-kem-768-aes-256-gcm");
        let restored = EncryptedOutput::try_from(legacy).unwrap();
        assert_eq!(restored.scheme(), &EncryptionScheme::PqMlKem768Aes256Gcm);
    }

    #[test]
    fn test_hybrid_components_clone_eq_succeeds() {
        let a =
            HybridComponents { ml_kem_ciphertext: vec![1, 2, 3], ecdh_ephemeral_pk: vec![4, 5, 6] };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_encrypt_key_debug_redacts_succeeds() {
        let key = [0u8; 32];
        let ek = EncryptKey::Symmetric(&key);
        let debug = format!("{:?}", ek);
        assert!(debug.contains("Symmetric"));
        assert!(debug.contains("32 bytes"));
        // Should not contain actual key bytes
        assert!(!debug.contains("0, 0, 0"));
    }

    #[test]
    fn test_decrypt_key_debug_redacts_succeeds() {
        let key = [0u8; 32];
        let dk = DecryptKey::Symmetric(&key);
        let debug = format!("{:?}", dk);
        assert!(debug.contains("Symmetric"));
        assert!(debug.contains("32 bytes"));
    }
}
