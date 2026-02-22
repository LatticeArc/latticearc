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

use crate::hybrid::kem_hybrid::{HybridPublicKey, HybridSecretKey};
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
/// use latticearc::types::crypto_types::EncryptKey;
///
/// // Symmetric key for AES-256-GCM or ChaCha20-Poly1305
/// let sym_key = [0u8; 32];
/// let key = EncryptKey::Symmetric(&sym_key);
///
/// // Hybrid key for ML-KEM-768 + X25519
/// // let (pk, _sk) = latticearc::generate_hybrid_keypair().unwrap();
/// // let key = EncryptKey::Hybrid(&pk);
/// ```
pub enum EncryptKey<'a> {
    /// Symmetric key (AES-256-GCM, ChaCha20-Poly1305).
    /// Must be exactly 32 bytes for both algorithms.
    Symmetric(&'a [u8]),
    /// Hybrid PQ public key (ML-KEM-768 + X25519).
    /// Used for true hybrid encryption with KEM encapsulation.
    Hybrid(&'a HybridPublicKey),
}

impl fmt::Debug for EncryptKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symmetric(key) => f
                .debug_tuple("EncryptKey::Symmetric")
                .field(&format!("[{} bytes]", key.len()))
                .finish(),
            Self::Hybrid(_) => f.debug_tuple("EncryptKey::Hybrid").field(&"[REDACTED]").finish(),
        }
    }
}

/// What kind of key the caller is providing for decryption.
///
/// Mirrors `EncryptKey` for the decryption path. The scheme stored
/// in `EncryptedOutput` determines which variant is expected.
pub enum DecryptKey<'a> {
    /// Symmetric key for AES-256-GCM or ChaCha20-Poly1305.
    Symmetric(&'a [u8]),
    /// Hybrid PQ secret key for ML-KEM-768 + X25519 decapsulation.
    Hybrid(&'a HybridSecretKey),
}

impl fmt::Debug for DecryptKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symmetric(key) => f
                .debug_tuple("DecryptKey::Symmetric")
                .field(&format!("[{} bytes]", key.len()))
                .finish(),
            Self::Hybrid(_) => f.debug_tuple("DecryptKey::Hybrid").field(&"[REDACTED]").finish(),
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
}

impl EncryptionScheme {
    /// Returns `true` if this scheme requires a hybrid (asymmetric PQ) key.
    #[must_use]
    pub const fn requires_hybrid_key(&self) -> bool {
        matches!(
            self,
            Self::HybridMlKem512Aes256Gcm
                | Self::HybridMlKem768Aes256Gcm
                | Self::HybridMlKem1024Aes256Gcm
        )
    }

    /// Returns `true` if this scheme uses a symmetric key.
    #[must_use]
    pub const fn requires_symmetric_key(&self) -> bool {
        matches!(self, Self::Aes256Gcm | Self::ChaCha20Poly1305)
    }

    /// Returns the ML-KEM security level for hybrid schemes, or `None` for symmetric.
    #[must_use]
    pub const fn ml_kem_level(&self) -> Option<MlKemSecurityLevel> {
        match self {
            Self::HybridMlKem512Aes256Gcm => Some(MlKemSecurityLevel::MlKem512),
            Self::HybridMlKem768Aes256Gcm => Some(MlKemSecurityLevel::MlKem768),
            Self::HybridMlKem1024Aes256Gcm => Some(MlKemSecurityLevel::MlKem1024),
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => None,
        }
    }

    /// Returns the legacy string identifier for backward compatibility with
    /// serialization and logging.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::HybridMlKem512Aes256Gcm => "hybrid-ml-kem-512-aes-256-gcm",
            Self::HybridMlKem768Aes256Gcm => "hybrid-ml-kem-768-aes-256-gcm",
            Self::HybridMlKem1024Aes256Gcm => "hybrid-ml-kem-1024-aes-256-gcm",
        }
    }

    /// Parse a legacy scheme string into an `EncryptionScheme`.
    ///
    /// Returns `None` for unrecognized strings (e.g. signature schemes).
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            "hybrid-ml-kem-512-aes-256-gcm" => Some(Self::HybridMlKem512Aes256Gcm),
            "hybrid-ml-kem-768-aes-256-gcm" => Some(Self::HybridMlKem768Aes256Gcm),
            "hybrid-ml-kem-1024-aes-256-gcm" => Some(Self::HybridMlKem1024Aes256Gcm),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridComponents {
    /// ML-KEM ciphertext (1088 bytes for ML-KEM-768).
    pub ml_kem_ciphertext: Vec<u8>,
    /// X25519 ephemeral public key (32 bytes).
    pub ecdh_ephemeral_pk: Vec<u8>,
}

/// Unified encrypted output replacing both `EncryptedData` and `HybridEncryptionResult`.
///
/// This type carries all information needed for decryption regardless of whether
/// the encryption was symmetric or hybrid. The `scheme` field (an enum, not a string)
/// determines which decryption path to use.
///
/// # Invariants
///
/// - `scheme.requires_hybrid_key()` ↔ `hybrid_data.is_some()`
/// - `scheme.requires_symmetric_key()` ↔ `hybrid_data.is_none()`
/// - `nonce` is always 12 bytes (AES-GCM and ChaCha20-Poly1305 both use 96-bit nonces)
/// - `tag` is always 16 bytes (both AEAD algorithms produce 128-bit tags)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedOutput {
    /// The encryption scheme used (determines decryption path).
    pub scheme: EncryptionScheme,
    /// The encrypted data (symmetric ciphertext).
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (12 bytes).
    pub nonce: Vec<u8>,
    /// AEAD authentication tag (16 bytes).
    pub tag: Vec<u8>,
    /// Hybrid-specific components (KEM ciphertext + ephemeral ECDH key).
    /// Present only for hybrid schemes.
    pub hybrid_data: Option<HybridComponents>,
    /// Unix timestamp when encryption was performed.
    pub timestamp: u64,
    /// Optional key identifier for key management systems.
    pub key_id: Option<String>,
}

// ============================================================================
// Conversions between EncryptedOutput and legacy EncryptedData
// ============================================================================

use super::types::{CryptoPayload, EncryptedData, EncryptedMetadata};

/// Convert `EncryptedOutput` to legacy `EncryptedData` for serialization.
///
/// The `ciphertext` field (which contains nonce || ct || tag for symmetric schemes)
/// is stored directly in `EncryptedData.data`.
impl From<EncryptedOutput> for EncryptedData {
    fn from(output: EncryptedOutput) -> Self {
        CryptoPayload {
            data: output.ciphertext,
            metadata: EncryptedMetadata {
                nonce: output.nonce,
                tag: if output.tag.is_empty() { None } else { Some(output.tag) },
                key_id: output.key_id,
            },
            scheme: output.scheme.to_string(),
            timestamp: output.timestamp,
        }
    }
}

/// Convert legacy `EncryptedData` to `EncryptedOutput` for decryption.
///
/// The scheme string is parsed into an `EncryptionScheme` enum.
/// Returns an error for unrecognized schemes instead of silently defaulting.
impl TryFrom<EncryptedData> for EncryptedOutput {
    type Error = super::error::TypeError;

    fn try_from(data: EncryptedData) -> Result<Self, Self::Error> {
        let scheme = EncryptionScheme::from_str(&data.scheme)
            .ok_or_else(|| super::error::TypeError::UnknownScheme(data.scheme.clone()))?;
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
        ];
        for scheme in &schemes {
            let s = scheme.as_str();
            let parsed = EncryptionScheme::from_str(s).unwrap();
            assert_eq!(&parsed, scheme);
        }
    }

    #[test]
    fn test_encryption_scheme_display() {
        assert_eq!(format!("{}", EncryptionScheme::Aes256Gcm), "aes-256-gcm");
        assert_eq!(
            format!("{}", EncryptionScheme::HybridMlKem768Aes256Gcm),
            "hybrid-ml-kem-768-aes-256-gcm"
        );
    }

    #[test]
    fn test_encryption_scheme_requires_key_type() {
        assert!(EncryptionScheme::Aes256Gcm.requires_symmetric_key());
        assert!(!EncryptionScheme::Aes256Gcm.requires_hybrid_key());
        assert!(EncryptionScheme::ChaCha20Poly1305.requires_symmetric_key());
        assert!(!EncryptionScheme::ChaCha20Poly1305.requires_hybrid_key());

        assert!(!EncryptionScheme::HybridMlKem768Aes256Gcm.requires_symmetric_key());
        assert!(EncryptionScheme::HybridMlKem768Aes256Gcm.requires_hybrid_key());
        assert!(EncryptionScheme::HybridMlKem512Aes256Gcm.requires_hybrid_key());
        assert!(EncryptionScheme::HybridMlKem1024Aes256Gcm.requires_hybrid_key());
    }

    #[test]
    fn test_encryption_scheme_from_str_unknown() {
        assert!(EncryptionScheme::from_str("unknown-scheme").is_none());
        assert!(EncryptionScheme::from_str("hybrid-ml-dsa-65-ed25519").is_none());
    }

    #[test]
    fn test_encryption_scheme_clone_eq() {
        let a = EncryptionScheme::HybridMlKem768Aes256Gcm;
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, EncryptionScheme::Aes256Gcm);
    }

    #[test]
    fn test_encrypted_output_symmetric() {
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
    fn test_encrypted_output_hybrid() {
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
    fn test_hybrid_components_clone_eq() {
        let a =
            HybridComponents { ml_kem_ciphertext: vec![1, 2, 3], ecdh_ephemeral_pk: vec![4, 5, 6] };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_encrypt_key_debug_redacts() {
        let key = [0u8; 32];
        let ek = EncryptKey::Symmetric(&key);
        let debug = format!("{:?}", ek);
        assert!(debug.contains("Symmetric"));
        assert!(debug.contains("32 bytes"));
        // Should not contain actual key bytes
        assert!(!debug.contains("0, 0, 0"));
    }

    #[test]
    fn test_decrypt_key_debug_redacts() {
        let key = [0u8; 32];
        let dk = DecryptKey::Symmetric(&key);
        let debug = format!("{:?}", dk);
        assert!(debug.contains("Symmetric"));
        assert!(debug.contains("32 bytes"));
    }
}
