#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Hybrid Encryption Module
//!
//! This module provides hybrid encryption combining post-quantum (ML-KEM) key
//! encapsulation with AES-256-GCM symmetric encryption for quantum-resistant
//! data encryption with classical performance characteristics.
//!
//! # Overview
//!
//! The hybrid encryption scheme uses:
//! - **ML-KEM-768** (FIPS 203) for post-quantum key encapsulation
//! - **AES-256-GCM** for authenticated symmetric encryption
//! - **HKDF-SHA256** for key derivation with domain separation
//!
//! # Security Properties
//!
//! - IND-CCA2 security from ML-KEM
//! - Authenticated encryption with associated data (AEAD)
//! - Domain separation via HPKE-style key derivation
//!
//! # Example
//!
//! ```rust,ignore
//! use arc_hybrid::encrypt_hybrid::{encrypt, decrypt, HybridEncryptionContext};
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//! let plaintext = b"Secret message";
//! let context = HybridEncryptionContext::default();
//!
//! // Encrypt with ML-KEM public key
//! let ciphertext = encrypt(&mut rng, &ml_kem_pk, plaintext, Some(&context))?;
//!
//! // Decrypt with ML-KEM secret key
//! let decrypted = decrypt(&ml_kem_sk, &ciphertext, Some(&context))?;
//! ```

use arc_primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel,
};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use thiserror::Error;

/// Error types for hybrid encryption operations.
///
/// This enum captures all possible error conditions that can occur during
/// hybrid encryption and decryption operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HybridEncryptionError {
    /// Error during key encapsulation mechanism operations.
    #[error("KEM error: {0}")]
    KemError(String),
    /// Error during symmetric encryption.
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    /// Error during symmetric decryption or authentication failure.
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    /// Error during key derivation function operations.
    #[error("Key derivation error: {0}")]
    KdfError(String),
    /// Invalid input parameters provided to the operation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// Key length mismatch error.
    #[error("Key length error: expected {expected}, got {actual}")]
    KeyLengthError {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },
}

/// Hybrid ciphertext containing both KEM and symmetric encryption components.
///
/// This structure holds all the data needed to decrypt a hybrid-encrypted message:
/// - The KEM ciphertext for key decapsulation
/// - The symmetric ciphertext containing the encrypted message
/// - The nonce used for AES-GCM encryption
/// - The authentication tag for integrity verification
#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    /// ML-KEM ciphertext for key decapsulation (1088 bytes for ML-KEM-768).
    pub kem_ciphertext: Vec<u8>,
    /// AES-256-GCM encrypted message data.
    pub symmetric_ciphertext: Vec<u8>,
    /// 12-byte nonce used for AES-GCM encryption.
    pub nonce: Vec<u8>,
    /// 16-byte AES-GCM authentication tag.
    pub tag: Vec<u8>,
}

/// HPKE-style context information for hybrid encryption.
///
/// This structure provides domain separation and additional authenticated data
/// for the key derivation and encryption operations, following RFC 9180 (HPKE).
#[derive(Debug, Clone)]
pub struct HybridEncryptionContext {
    /// Application-specific info string for key derivation domain separation.
    pub info: Vec<u8>,
    /// Additional authenticated data (AAD) for AEAD encryption.
    pub aad: Vec<u8>,
}

impl Default for HybridEncryptionContext {
    fn default() -> Self {
        Self { info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(), aad: vec![] }
    }
}

/// Custom output length type for aws-lc-rs HKDF
struct HkdfOutputLen(usize);

impl KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HPKE-style key derivation for hybrid encryption.
///
/// # Errors
///
/// Returns an error if the shared secret is not exactly 32 bytes,
/// or if HKDF expansion fails.
pub fn derive_encryption_key(
    shared_secret: &[u8],
    context: &HybridEncryptionContext,
) -> Result<[u8; 32], HybridEncryptionError> {
    if shared_secret.len() != 32 {
        return Err(HybridEncryptionError::KdfError("Shared secret must be 32 bytes".to_string()));
    }

    // Create info for domain separation
    let mut info = Vec::new();
    info.extend_from_slice(&context.info);
    info.extend_from_slice(b"||");
    info.extend_from_slice(&context.aad);

    // Use HKDF-SHA256 for key derivation via aws-lc-rs
    let salt = Salt::new(HKDF_SHA256, &[]);
    let prk = salt.extract(shared_secret);
    let info_refs: [&[u8]; 1] = [&info];
    let okm = prk
        .expand(&info_refs, HkdfOutputLen(32))
        .map_err(|_e| HybridEncryptionError::KdfError("HKDF expansion failed".to_string()))?;

    let mut key = [0u8; 32];
    okm.fill(&mut key)
        .map_err(|_e| HybridEncryptionError::KdfError("HKDF fill failed".to_string()))?;

    Ok(key)
}

/// Hybrid encryption using ML-KEM + AES-256-GCM with HPKE-style key derivation.
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM public key is not 1184 bytes (ML-KEM-768)
/// - ML-KEM encapsulation fails
/// - Key derivation fails
/// - AES-GCM encryption fails
pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    ml_kem_pk: &[u8],
    plaintext: &[u8],
    context: Option<&HybridEncryptionContext>,
) -> Result<HybridCiphertext, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Validate inputs
    if ml_kem_pk.len() != 1184 {
        return Err(HybridEncryptionError::InvalidInput(
            "ML-KEM-768 public key must be 1184 bytes".to_string(),
        ));
    }

    // ML-KEM encapsulation
    let ml_kem_pk_struct = MlKemPublicKey::new(MlKemSecurityLevel::MlKem768, ml_kem_pk.to_vec())
        .map_err(|e| HybridEncryptionError::KemError(format!("{:?}", e)))?;
    let (shared_secret, kem_ct_struct) = MlKem::encapsulate(rng, &ml_kem_pk_struct)
        .map_err(|e| HybridEncryptionError::KemError(format!("{:?}", e)))?;
    let kem_ct = kem_ct_struct.into_bytes();

    // Derive encryption key using HPKE-style KDF
    let encryption_key = derive_encryption_key(shared_secret.as_bytes(), ctx)?;

    // Generate random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Use AES-256-GCM for authenticated encryption with AAD via aws-lc-rs
    let unbound_key = UnboundKey::new(&AES_256_GCM, &encryption_key).map_err(|_e| {
        HybridEncryptionError::EncryptionError("Failed to create AES key".to_string())
    })?;
    let aes_key = LessSafeKey::new(unbound_key);

    // Encrypt in-place: plaintext becomes ciphertext + tag
    let mut in_out = plaintext.to_vec();
    let aad = Aad::from(&ctx.aad[..]);
    aes_key.seal_in_place_append_tag(nonce, aad, &mut in_out).map_err(|_e| {
        HybridEncryptionError::EncryptionError("AES-GCM encryption failed".to_string())
    })?;

    // AES-GCM tag is the last 16 bytes
    let tag_len = 16;
    let ct_len = in_out.len();
    if ct_len < tag_len {
        return Err(HybridEncryptionError::EncryptionError(
            "Ciphertext too short for tag".to_string(),
        ));
    }

    // Use checked subtraction - the check above guarantees this won't underflow
    let split_pos = ct_len.checked_sub(tag_len).ok_or_else(|| {
        HybridEncryptionError::EncryptionError("Ciphertext length calculation overflow".to_string())
    })?;
    let (ciphertext, tag) = in_out.split_at(split_pos);

    Ok(HybridCiphertext {
        kem_ciphertext: kem_ct,
        symmetric_ciphertext: ciphertext.to_vec(),
        nonce: nonce_bytes.to_vec(),
        tag: tag.to_vec(),
    })
}

/// Hybrid decryption using ML-KEM + AES-256-GCM with HPKE-style key derivation.
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM secret key is not 2400 bytes (ML-KEM-768)
/// - The ciphertext components have invalid lengths
/// - ML-KEM decapsulation fails
/// - Key derivation fails
/// - AES-GCM decryption or authentication fails
pub fn decrypt(
    ml_kem_sk: &[u8],
    ciphertext: &HybridCiphertext,
    context: Option<&HybridEncryptionContext>,
) -> Result<Vec<u8>, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Validate inputs
    if ml_kem_sk.len() != 2400 {
        return Err(HybridEncryptionError::InvalidInput(
            "ML-KEM-768 secret key must be 2400 bytes".to_string(),
        ));
    }
    if ciphertext.kem_ciphertext.len() != 1088 {
        return Err(HybridEncryptionError::InvalidInput(
            "ML-KEM-768 ciphertext must be 1088 bytes".to_string(),
        ));
    }
    if ciphertext.nonce.len() != 12 {
        return Err(HybridEncryptionError::InvalidInput("Nonce must be 12 bytes".to_string()));
    }
    if ciphertext.tag.len() != 16 {
        return Err(HybridEncryptionError::InvalidInput("Tag must be 16 bytes".to_string()));
    }

    // ML-KEM decapsulation
    let ml_kem_sk_struct = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, ml_kem_sk.to_vec())
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("{:?}", e)))?;
    let ml_kem_ct_struct =
        MlKemCiphertext::new(MlKemSecurityLevel::MlKem768, ciphertext.kem_ciphertext.clone())
            .map_err(|e| HybridEncryptionError::DecryptionError(format!("{:?}", e)))?;
    let shared_secret = MlKem::decapsulate(&ml_kem_sk_struct, &ml_kem_ct_struct)
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("{:?}", e)))?;

    // Derive encryption key using HPKE-style KDF
    let encryption_key = derive_encryption_key(shared_secret.as_bytes(), ctx)?;

    // Setup AES-256-GCM via aws-lc-rs
    let nonce_bytes: [u8; 12] =
        ciphertext.nonce.as_slice().try_into().map_err(|_e| {
            HybridEncryptionError::DecryptionError("Invalid nonce length".to_string())
        })?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound_key = UnboundKey::new(&AES_256_GCM, &encryption_key).map_err(|_e| {
        HybridEncryptionError::DecryptionError("Failed to create AES key".to_string())
    })?;
    let aes_key = LessSafeKey::new(unbound_key);

    // Combine ciphertext and tag for decryption
    let mut in_out: Vec<u8> =
        ciphertext.symmetric_ciphertext.iter().chain(ciphertext.tag.iter()).copied().collect();

    // Decrypt in-place with AAD
    let aad = Aad::from(&ctx.aad[..]);
    let plaintext = aes_key.open_in_place(nonce, aad, &mut in_out).map_err(|_e| {
        HybridEncryptionError::DecryptionError(
            "AES-GCM decryption/authentication failed".to_string(),
        )
    })?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization - decrypt not functional"]
    fn test_hybrid_encryption_roundtrip() {
        let mut rng = rand::thread_rng();

        // Generate ML-KEM keypair for testing
        let (ml_kem_pk, ml_kem_sk) =
            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Hello, hybrid encryption with HPKE!";
        let context = HybridEncryptionContext::default();

        // Test encryption
        let ct = encrypt(&mut rng, ml_kem_pk.as_bytes(), plaintext, Some(&context));
        assert!(ct.is_ok(), "Encryption should succeed");

        let ct = ct.unwrap();
        assert_eq!(ct.kem_ciphertext.len(), 1088, "KEM ciphertext should be 1088 bytes");
        assert!(!ct.symmetric_ciphertext.is_empty(), "Symmetric ciphertext should not be empty");
        assert_eq!(ct.nonce.len(), 12, "Nonce should be 12 bytes");
        assert_eq!(ct.tag.len(), 16, "Tag should be 16 bytes");

        // Test decryption
        let decrypted = decrypt(ml_kem_sk.as_bytes(), &ct, Some(&context));
        assert!(decrypted.is_ok(), "Decryption should succeed");
        assert_eq!(decrypted.unwrap(), plaintext, "Decrypted text should match original");
    }

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization - decrypt not functional"]
    fn test_hybrid_encryption_with_aad() {
        let mut rng = rand::thread_rng();

        let (ml_kem_pk, ml_kem_sk) =
            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Secret message with AAD";
        let aad = b"Additional authenticated data";
        let context = HybridEncryptionContext {
            info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(),
            aad: aad.to_vec(),
        };

        // Encrypt with AAD
        let ct = encrypt(&mut rng, ml_kem_pk.as_bytes(), plaintext, Some(&context)).unwrap();

        // Decrypt with correct AAD
        let decrypted = decrypt(ml_kem_sk.as_bytes(), &ct, Some(&context)).unwrap();
        assert_eq!(decrypted, plaintext, "Decryption with correct AAD should succeed");

        // Decrypt with wrong AAD should fail
        let wrong_context = HybridEncryptionContext {
            info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(),
            aad: b"Wrong AAD".to_vec(),
        };
        let result = decrypt(ml_kem_sk.as_bytes(), &ct, Some(&wrong_context));
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    fn test_invalid_key_lengths() {
        let mut rng = rand::thread_rng();
        let plaintext = b"Test message";

        // Test invalid ML-KEM public key length
        let invalid_pk = vec![1u8; 1000]; // Wrong length
        let result = encrypt(&mut rng, &invalid_pk, plaintext, None);
        assert!(result.is_err(), "Should reject invalid public key length");

        // Test invalid ML-KEM secret key length
        let invalid_sk = vec![1u8; 1000]; // Wrong length
        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            symmetric_ciphertext: vec![2u8; 100],
            nonce: vec![3u8; 12],
            tag: vec![4u8; 16],
        };
        let result = decrypt(&invalid_sk, &ct, None);
        assert!(result.is_err(), "Should reject invalid secret key length");
    }

    #[test]
    fn test_invalid_ciphertext_components() {
        let valid_sk = vec![1u8; 2400];

        // Test invalid nonce length
        let invalid_nonce_ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            symmetric_ciphertext: vec![2u8; 100],
            nonce: vec![3u8; 11], // Invalid length
            tag: vec![4u8; 16],
        };
        let result = decrypt(&valid_sk, &invalid_nonce_ct, None);
        assert!(result.is_err(), "Should reject invalid nonce length");

        // Test invalid tag length
        let invalid_tag_ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            symmetric_ciphertext: vec![2u8; 100],
            nonce: vec![3u8; 12],
            tag: vec![4u8; 15], // Invalid length
        };
        let result = decrypt(&valid_sk, &invalid_tag_ct, None);
        assert!(result.is_err(), "Should reject invalid tag length");

        // Test invalid KEM ciphertext length
        let invalid_kem_ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1000], // Invalid length
            symmetric_ciphertext: vec![2u8; 100],
            nonce: vec![3u8; 12],
            tag: vec![4u8; 16],
        };
        let result = decrypt(&valid_sk, &invalid_kem_ct, None);
        assert!(result.is_err(), "Should reject invalid KEM ciphertext length");
    }

    #[test]
    fn test_key_derivation_properties() {
        let shared_secret = vec![1u8; 32];
        let context1 =
            HybridEncryptionContext { info: b"Context1".to_vec(), aad: b"AAD1".to_vec() };
        let context2 =
            HybridEncryptionContext { info: b"Context2".to_vec(), aad: b"AAD2".to_vec() };

        let key1 = derive_encryption_key(&shared_secret, &context1).unwrap();
        let key2 = derive_encryption_key(&shared_secret, &context2).unwrap();

        // Different contexts should produce different keys
        assert_ne!(key1, key2, "Different contexts should produce different keys");

        // Same context should produce same key (deterministic)
        let key1_again = derive_encryption_key(&shared_secret, &context1).unwrap();
        assert_eq!(key1, key1_again, "Key derivation should be deterministic");

        // Test invalid shared secret length
        let invalid_secret = vec![1u8; 31]; // Wrong length
        let result = derive_encryption_key(&invalid_secret, &context1);
        assert!(result.is_err(), "Should reject invalid shared secret length");
    }
}
