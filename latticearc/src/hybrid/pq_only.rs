#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! PQ-Only Encryption Module
//!
//! Provides post-quantum-only encryption using ML-KEM key encapsulation
//! combined with AES-256-GCM symmetric encryption, without any classical
//! (X25519) component. This is the PQ-only counterpart to the hybrid
//! encryption in [`crate::hybrid::encrypt_hybrid`].
//!
//! # When to Use
//!
//! - CNSA 2.0 compliance (pure PQ required)
//! - Government/defense use cases mandating no classical algorithms
//! - Post-transition deployments where classical is no longer needed
//!
//! # Security Properties
//!
//! - IND-CCA2 security from ML-KEM (FIPS 203)
//! - Authenticated encryption via AES-256-GCM (FIPS validated)
//! - HKDF-SHA256 key derivation with domain separation
//!
//! # Differences from Hybrid
//!
//! | Property | Hybrid | PQ-Only |
//! |----------|--------|---------|
//! | KEM | ML-KEM + X25519 | ML-KEM only |
//! | Key derivation | HKDF over both shared secrets | HKDF over ML-KEM shared secret |
//! | Security guarantee | Secure if EITHER is secure | Secure if ML-KEM is secure |
//! | CNSA 2.0 compliant | No (contains classical) | Yes |

use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{AeadCipher, TAG_LEN};
use crate::primitives::kdf::hkdf::hkdf;
use crate::primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

/// Error types for PQ-only encryption operations.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PqOnlyError {
    /// Error during ML-KEM key encapsulation.
    #[error("KEM error: {0}")]
    KemError(String),
    /// Error during symmetric encryption.
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    /// Error during symmetric decryption or authentication failure.
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    /// Error during key derivation.
    #[error("Key derivation error: {0}")]
    KdfError(String),
    /// Invalid input parameters.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// Key generation failure.
    #[error("Key generation error: {0}")]
    KeyGenError(String),
}

// ============================================================================
// PQ-Only Key Types
// ============================================================================

/// PQ-only public key wrapping an ML-KEM public key.
///
/// Unlike [`HybridKemPublicKey`](crate::hybrid::kem_hybrid::HybridKemPublicKey),
/// this type contains only the ML-KEM component — no X25519.
#[derive(Clone)]
pub struct PqOnlyPublicKey {
    /// The ML-KEM public key.
    ml_kem_pk: MlKemPublicKey,
    /// The security level this key was generated at.
    security_level: MlKemSecurityLevel,
}

impl std::fmt::Debug for PqOnlyPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqOnlyPublicKey")
            .field("security_level", &self.security_level)
            .field("pk_len", &self.ml_kem_pk.as_bytes().len())
            .finish()
    }
}

impl PqOnlyPublicKey {
    /// Create a `PqOnlyPublicKey` from raw ML-KEM public key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid for the specified security level.
    pub fn from_bytes(level: MlKemSecurityLevel, pk_bytes: &[u8]) -> Result<Self, PqOnlyError> {
        let ml_kem_pk = MlKemPublicKey::new(level, pk_bytes.to_vec())
            .map_err(|e| PqOnlyError::InvalidInput(format!("Invalid ML-KEM public key: {e}")))?;
        Ok(Self { ml_kem_pk, security_level: level })
    }

    /// Returns the ML-KEM security level.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }

    /// Returns the raw ML-KEM public key bytes.
    #[must_use]
    pub fn ml_kem_pk_bytes(&self) -> &[u8] {
        self.ml_kem_pk.as_bytes()
    }

    /// Returns a reference to the inner ML-KEM public key.
    #[must_use]
    pub fn ml_kem_pk(&self) -> &MlKemPublicKey {
        &self.ml_kem_pk
    }
}

/// PQ-only secret key wrapping an ML-KEM secret key.
///
/// Unlike [`HybridKemSecretKey`](crate::hybrid::kem_hybrid::HybridKemSecretKey),
/// this type contains only the ML-KEM component — no X25519.
///
/// # Security
///
/// - The inner `MlKemSecretKey` is zeroized on drop by its own `Drop` impl.
/// - `Clone` is intentionally NOT implemented to prevent copies of secret material.
/// - Debug output is redacted to prevent accidental key leakage.
pub struct PqOnlySecretKey {
    /// The ML-KEM secret key (zeroized on drop by `MlKemSecretKey`).
    ml_kem_sk: MlKemSecretKey,
    /// The security level this key was generated at.
    security_level: MlKemSecurityLevel,
}

impl std::fmt::Debug for PqOnlySecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqOnlySecretKey")
            .field("security_level", &self.security_level)
            .field("sk", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for PqOnlySecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.ml_kem_sk.ct_eq(&other.ml_kem_sk)
    }
}

impl PqOnlySecretKey {
    /// Create a `PqOnlySecretKey` from raw ML-KEM secret key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid for the specified security level.
    pub fn from_bytes(level: MlKemSecurityLevel, sk_bytes: &[u8]) -> Result<Self, PqOnlyError> {
        let ml_kem_sk = MlKemSecretKey::new(level, sk_bytes.to_vec())
            .map_err(|e| PqOnlyError::InvalidInput(format!("Invalid ML-KEM secret key: {e}")))?;
        Ok(Self { ml_kem_sk, security_level: level })
    }

    /// Returns the ML-KEM security level.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }

    /// Returns the raw ML-KEM secret key bytes.
    #[must_use]
    pub fn ml_kem_sk_bytes(&self) -> &[u8] {
        self.ml_kem_sk.as_bytes()
    }

    /// Returns a reference to the inner ML-KEM secret key.
    #[must_use]
    pub fn ml_kem_sk(&self) -> &MlKemSecretKey {
        &self.ml_kem_sk
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a PQ-only keypair at ML-KEM-768 (default security level).
///
/// Returns `(public_key, secret_key)` for PQ-only encryption.
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_pq_keypair() -> Result<(PqOnlyPublicKey, PqOnlySecretKey), PqOnlyError> {
    generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem768)
}

/// Generate a PQ-only keypair at a specific ML-KEM security level.
///
/// # Arguments
///
/// * `level` - ML-KEM security level:
///   - `MlKem512` — NIST Category 1
///   - `MlKem768` — NIST Category 3
///   - `MlKem1024` — NIST Category 5
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_pq_keypair_with_level(
    level: MlKemSecurityLevel,
) -> Result<(PqOnlyPublicKey, PqOnlySecretKey), PqOnlyError> {
    let (pk, sk) = MlKem::generate_keypair(level)
        .map_err(|e| PqOnlyError::KeyGenError(format!("ML-KEM keygen failed: {e}")))?;

    Ok((
        PqOnlyPublicKey { ml_kem_pk: pk, security_level: level },
        PqOnlySecretKey { ml_kem_sk: sk, security_level: level },
    ))
}

// ============================================================================
// PQ-Only Encrypt / Decrypt
// ============================================================================

/// PQ-only encrypted output components.
///
/// Returned by [`encrypt_pq_only`] for integration with [`EncryptedOutput`](crate::unified_api::crypto_types::EncryptedOutput).
pub struct PqOnlyCiphertext {
    /// ML-KEM ciphertext (for decapsulation).
    ml_kem_ciphertext: Vec<u8>,
    /// Symmetric ciphertext (AES-256-GCM encrypted payload).
    symmetric_ciphertext: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes).
    nonce: [u8; 12],
    /// AES-256-GCM authentication tag (16 bytes).
    tag: [u8; TAG_LEN],
}

impl PqOnlyCiphertext {
    /// Returns the ML-KEM ciphertext bytes.
    #[must_use]
    pub fn ml_kem_ciphertext(&self) -> &[u8] {
        &self.ml_kem_ciphertext
    }

    /// Returns the symmetric ciphertext bytes.
    #[must_use]
    pub fn symmetric_ciphertext(&self) -> &[u8] {
        &self.symmetric_ciphertext
    }

    /// Returns the AES-256-GCM nonce (12 bytes).
    #[must_use]
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Returns the AES-256-GCM authentication tag (16 bytes).
    #[must_use]
    pub fn tag(&self) -> &[u8; TAG_LEN] {
        &self.tag
    }

    /// Consumes self and returns `(ml_kem_ciphertext, symmetric_ciphertext, nonce, tag)`.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, [u8; 12], [u8; TAG_LEN]) {
        (self.ml_kem_ciphertext, self.symmetric_ciphertext, self.nonce, self.tag)
    }
}

/// Encrypt data using PQ-only ML-KEM + HKDF + AES-256-GCM.
///
/// # Algorithm
///
/// 1. ML-KEM encapsulate with the public key → (shared_secret, kem_ciphertext)
/// 2. HKDF-SHA256(shared_secret, info=`PQ_ONLY_ENCRYPTION_INFO`) → 32-byte AES key
/// 3. AES-256-GCM encrypt(plaintext) → (ciphertext, nonce, tag)
///
/// # Security
///
/// - IND-CCA2 security from ML-KEM (FIPS 203)
/// - AES-256-GCM nonce generated internally from OS CSPRNG (SP 800-38D §8.2)
/// - HKDF key derivation uses `PQ_ONLY_ENCRYPTION_INFO` domain separation (SP 800-56C)
/// - ML-KEM shared secret is not exposed to callers
///
/// # Errors
///
/// Returns an error if encapsulation, key derivation, or encryption fails.
pub fn encrypt_pq_only(
    pk: &PqOnlyPublicKey,
    plaintext: &[u8],
) -> Result<PqOnlyCiphertext, PqOnlyError> {
    // 1. ML-KEM encapsulate
    let (shared_secret, kem_ct) = MlKem::encapsulate(pk.ml_kem_pk())
        .map_err(|e| PqOnlyError::KemError(format!("ML-KEM encapsulation failed: {e}")))?;

    // 2. HKDF key derivation with PQ-only domain separation
    let hkdf_result = hkdf(
        shared_secret.as_bytes(),
        None,
        Some(crate::types::domains::PQ_ONLY_ENCRYPTION_INFO),
        32,
    )
    .map_err(|e| PqOnlyError::KdfError(format!("HKDF failed: {e}")))?;

    // 3. AES-256-GCM encrypt
    let cipher = AesGcm256::new(hkdf_result.key())
        .map_err(|e| PqOnlyError::EncryptionError(format!("AES-GCM init failed: {e}")))?;
    let nonce = AesGcm256::generate_nonce();
    let (ciphertext, tag) = cipher
        .encrypt(&nonce, plaintext, None)
        .map_err(|e| PqOnlyError::EncryptionError(format!("AES-GCM encrypt failed: {e}")))?;

    Ok(PqOnlyCiphertext {
        ml_kem_ciphertext: kem_ct.into_bytes(),
        symmetric_ciphertext: ciphertext,
        nonce,
        tag,
    })
}

/// Decrypt data encrypted by [`encrypt_pq_only`].
///
/// # Algorithm
///
/// 1. ML-KEM decapsulate(kem_ciphertext, secret_key) → shared_secret
/// 2. HKDF-SHA256(shared_secret, info=`PQ_ONLY_ENCRYPTION_INFO`) → 32-byte AES key
/// 3. AES-256-GCM decrypt(ciphertext, nonce, tag) → plaintext
///
/// # Security
///
/// - Decrypt errors are opaque ("decryption failed") per SP 800-38D §5.2.2
/// - ML-KEM shared secret is wrapped and not exposed to callers
/// - HKDF key derivation uses `PQ_ONLY_ENCRYPTION_INFO` domain separation (SP 800-56C)
/// - Plaintext is returned in `Zeroizing<Vec<u8>>` for automatic cleanup
///
/// # Errors
///
/// Returns an error if decapsulation, key derivation, or decryption fails.
pub fn decrypt_pq_only(
    sk: &PqOnlySecretKey,
    kem_ciphertext: &[u8],
    symmetric_ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; TAG_LEN],
) -> Result<Zeroizing<Vec<u8>>, PqOnlyError> {
    // 1. ML-KEM decapsulate
    let ct = MlKemCiphertext::new(sk.security_level(), kem_ciphertext.to_vec())
        .map_err(|e| PqOnlyError::KemError(format!("Invalid ML-KEM ciphertext: {e}")))?;
    let shared_secret = MlKem::decapsulate(sk.ml_kem_sk(), &ct)
        .map_err(|e| PqOnlyError::KemError(format!("ML-KEM decapsulation failed: {e}")))?;

    // 2. HKDF key derivation (must match encrypt path)
    let hkdf_result = hkdf(
        shared_secret.as_bytes(),
        None,
        Some(crate::types::domains::PQ_ONLY_ENCRYPTION_INFO),
        32,
    )
    .map_err(|e| PqOnlyError::KdfError(format!("HKDF failed: {e}")))?;

    // 3. AES-256-GCM decrypt
    let cipher = AesGcm256::new(hkdf_result.key())
        .map_err(|e| PqOnlyError::DecryptionError(format!("AES-GCM init failed: {e}")))?;
    cipher.decrypt(nonce, symmetric_ciphertext, tag, None).map_err(|_aead_err| {
        // SECURITY: Opaque error per SP 800-38D §5.2.2
        PqOnlyError::DecryptionError("decryption failed".to_string())
    })
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
    fn test_generate_pq_keypair_default_succeeds() {
        let (pk, sk) = generate_pq_keypair().expect("keygen should succeed");
        assert_eq!(pk.security_level(), MlKemSecurityLevel::MlKem768);
        assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem768);
    }

    #[test]
    fn test_generate_pq_keypair_all_levels_succeeds() {
        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, sk) = generate_pq_keypair_with_level(level).expect("keygen should succeed");
            assert_eq!(pk.security_level(), level);
            assert_eq!(sk.security_level(), level);
        }
    }

    #[test]
    fn test_encrypt_decrypt_pq_only_roundtrip_768() {
        let (pk, sk) = generate_pq_keypair().unwrap();
        let plaintext = b"PQ-only roundtrip test data";

        let ct = encrypt_pq_only(&pk, plaintext).expect("encrypt should succeed");
        let decrypted = decrypt_pq_only(
            &sk,
            ct.ml_kem_ciphertext(),
            ct.symmetric_ciphertext(),
            ct.nonce(),
            ct.tag(),
        )
        .expect("decrypt should succeed");

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_pq_only_all_levels_roundtrip() {
        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, sk) = generate_pq_keypair_with_level(level).unwrap();
            let plaintext = b"Test all security levels";

            let ct = encrypt_pq_only(&pk, plaintext).expect("encrypt should succeed");
            let decrypted = decrypt_pq_only(
                &sk,
                ct.ml_kem_ciphertext(),
                ct.symmetric_ciphertext(),
                ct.nonce(),
                ct.tag(),
            )
            .expect("decrypt should succeed");

            assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        }
    }

    #[test]
    fn test_encrypt_pq_only_empty_data_succeeds() {
        let (pk, sk) = generate_pq_keypair().unwrap();
        let ct = encrypt_pq_only(&pk, b"").expect("empty data should encrypt");
        let decrypted = decrypt_pq_only(
            &sk,
            ct.ml_kem_ciphertext(),
            ct.symmetric_ciphertext(),
            ct.nonce(),
            ct.tag(),
        )
        .expect("empty data should decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_pq_only_wrong_key_fails() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let (_pk2, sk2) = generate_pq_keypair().unwrap();
        let ct = encrypt_pq_only(&pk, b"secret").unwrap();

        let result = decrypt_pq_only(
            &sk2,
            ct.ml_kem_ciphertext(),
            ct.symmetric_ciphertext(),
            ct.nonce(),
            ct.tag(),
        );
        assert!(result.is_err(), "Wrong key should fail");
    }

    #[test]
    fn test_encrypt_pq_only_different_ciphertexts() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let ct1 = encrypt_pq_only(&pk, b"same data").unwrap();
        let ct2 = encrypt_pq_only(&pk, b"same data").unwrap();
        assert_ne!(
            ct1.ml_kem_ciphertext(),
            ct2.ml_kem_ciphertext(),
            "Random KEM should produce different ciphertexts"
        );
    }

    #[test]
    fn test_pq_only_public_key_debug_no_leak() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let debug = format!("{:?}", pk);
        assert!(debug.contains("PqOnlyPublicKey"));
        assert!(debug.contains("MlKem768"));
    }

    #[test]
    fn test_pq_only_secret_key_debug_redacted() {
        let (_pk, sk) = generate_pq_keypair().unwrap();
        let debug = format!("{:?}", sk);
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_pq_only_public_key_from_bytes_wrong_length_fails() {
        let result = PqOnlyPublicKey::from_bytes(MlKemSecurityLevel::MlKem768, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pq_only_secret_key_from_bytes_wrong_length_fails() {
        let result = PqOnlySecretKey::from_bytes(MlKemSecurityLevel::MlKem768, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pq_only_public_key_from_bytes_roundtrip() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let bytes = pk.ml_kem_pk_bytes().to_vec();
        let pk2 = PqOnlyPublicKey::from_bytes(pk.security_level(), &bytes).unwrap();
        assert_eq!(pk2.security_level(), pk.security_level());
        assert_eq!(pk2.ml_kem_pk_bytes(), pk.ml_kem_pk_bytes());
    }
}
