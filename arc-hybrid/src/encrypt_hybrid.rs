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

use crate::kem_hybrid::{self, EncapsulatedKey, HybridPublicKey, HybridSecretKey};
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
    /// X25519 ephemeral public key for ECDH (32 bytes). Empty for legacy ML-KEM-only ciphertexts.
    pub ecdh_ephemeral_pk: Vec<u8>,
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
    if shared_secret.len() != 32 && shared_secret.len() != 64 {
        return Err(HybridEncryptionError::KdfError(
            "Shared secret must be 32 bytes (ML-KEM) or 64 bytes (hybrid)".to_string(),
        ));
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
        ecdh_ephemeral_pk: vec![], // Legacy ML-KEM-only path — no ECDH
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

/// True hybrid encryption using ML-KEM-768 + X25519 + AES-256-GCM.
///
/// This function performs real hybrid key encapsulation (combining post-quantum
/// ML-KEM with classical X25519 ECDH via HKDF) before AES-256-GCM encryption.
/// Security holds if *either* ML-KEM or X25519 remains secure.
///
/// # Errors
///
/// Returns an error if:
/// - Hybrid KEM encapsulation fails
/// - Key derivation fails
/// - AES-GCM encryption fails
pub fn encrypt_hybrid<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    hybrid_pk: &HybridPublicKey,
    plaintext: &[u8],
    context: Option<&HybridEncryptionContext>,
) -> Result<HybridCiphertext, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Hybrid KEM encapsulation (ML-KEM-768 + X25519 ECDH + HKDF)
    let encapsulated = kem_hybrid::encapsulate(rng, hybrid_pk)
        .map_err(|e| HybridEncryptionError::KemError(format!("{}", e)))?;

    // Derive AES-256 encryption key from 64-byte hybrid shared secret
    let encryption_key = derive_encryption_key(&encapsulated.shared_secret, ctx)?;

    // Generate random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // AES-256-GCM authenticated encryption
    let unbound_key = UnboundKey::new(&AES_256_GCM, &encryption_key).map_err(|_e| {
        HybridEncryptionError::EncryptionError("Failed to create AES key".to_string())
    })?;
    let aes_key = LessSafeKey::new(unbound_key);

    let mut in_out = plaintext.to_vec();
    let aad = Aad::from(&ctx.aad[..]);
    aes_key.seal_in_place_append_tag(nonce, aad, &mut in_out).map_err(|_e| {
        HybridEncryptionError::EncryptionError("AES-GCM encryption failed".to_string())
    })?;

    let tag_len = 16;
    let ct_len = in_out.len();
    let split_pos = ct_len.checked_sub(tag_len).ok_or_else(|| {
        HybridEncryptionError::EncryptionError("Ciphertext length calculation overflow".to_string())
    })?;
    let (ciphertext, tag) = in_out.split_at(split_pos);

    Ok(HybridCiphertext {
        kem_ciphertext: encapsulated.ml_kem_ct.clone(),
        ecdh_ephemeral_pk: encapsulated.ecdh_pk.clone(),
        symmetric_ciphertext: ciphertext.to_vec(),
        nonce: nonce_bytes.to_vec(),
        tag: tag.to_vec(),
    })
}

/// True hybrid decryption using ML-KEM-768 + X25519 + AES-256-GCM.
///
/// This function performs real hybrid key decapsulation (ML-KEM decapsulation +
/// X25519 ECDH agreement, combined via HKDF) before AES-256-GCM decryption.
///
/// # Errors
///
/// Returns an error if:
/// - The ciphertext components have invalid lengths
/// - Hybrid KEM decapsulation fails
/// - Key derivation fails
/// - AES-GCM decryption or authentication fails
pub fn decrypt_hybrid(
    hybrid_sk: &HybridSecretKey,
    ciphertext: &HybridCiphertext,
    context: Option<&HybridEncryptionContext>,
) -> Result<Vec<u8>, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Validate ciphertext structure
    if ciphertext.kem_ciphertext.len() != 1088 {
        return Err(HybridEncryptionError::InvalidInput(
            "ML-KEM-768 ciphertext must be 1088 bytes".to_string(),
        ));
    }
    if ciphertext.ecdh_ephemeral_pk.len() != 32 {
        return Err(HybridEncryptionError::InvalidInput(
            "X25519 ephemeral public key must be 32 bytes".to_string(),
        ));
    }
    if ciphertext.nonce.len() != 12 {
        return Err(HybridEncryptionError::InvalidInput("Nonce must be 12 bytes".to_string()));
    }
    if ciphertext.tag.len() != 16 {
        return Err(HybridEncryptionError::InvalidInput("Tag must be 16 bytes".to_string()));
    }

    // Reconstruct EncapsulatedKey for kem_hybrid::decapsulate
    let encapsulated = EncapsulatedKey {
        ml_kem_ct: ciphertext.kem_ciphertext.clone(),
        ecdh_pk: ciphertext.ecdh_ephemeral_pk.clone(),
        shared_secret: zeroize::Zeroizing::new(vec![]), // placeholder — decapsulate recovers this
    };

    // Hybrid KEM decapsulation (ML-KEM + X25519 ECDH + HKDF)
    let shared_secret = kem_hybrid::decapsulate(hybrid_sk, &encapsulated)
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("{}", e)))?;

    // Derive AES-256 encryption key from 64-byte hybrid shared secret
    let encryption_key = derive_encryption_key(&shared_secret, ctx)?;

    // AES-256-GCM authenticated decryption
    let nonce_bytes: [u8; 12] =
        ciphertext.nonce.as_slice().try_into().map_err(|_e| {
            HybridEncryptionError::DecryptionError("Invalid nonce length".to_string())
        })?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound_key = UnboundKey::new(&AES_256_GCM, &encryption_key).map_err(|_e| {
        HybridEncryptionError::DecryptionError("Failed to create AES key".to_string())
    })?;
    let aes_key = LessSafeKey::new(unbound_key);

    let mut in_out: Vec<u8> =
        ciphertext.symmetric_ciphertext.iter().chain(ciphertext.tag.iter()).copied().collect();

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
    #[ignore = "ML-KEM DecapsulationKey cannot be reconstructed from raw bytes"]
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
    #[ignore = "ML-KEM DecapsulationKey cannot be reconstructed from raw bytes"]
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
            ecdh_ephemeral_pk: vec![],
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
            ecdh_ephemeral_pk: vec![],
            symmetric_ciphertext: vec![2u8; 100],
            nonce: vec![3u8; 11], // Invalid length
            tag: vec![4u8; 16],
        };
        let result = decrypt(&valid_sk, &invalid_nonce_ct, None);
        assert!(result.is_err(), "Should reject invalid nonce length");

        // Test invalid tag length
        let invalid_tag_ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            ecdh_ephemeral_pk: vec![],
            symmetric_ciphertext: vec![2u8; 100],
            nonce: vec![3u8; 12],
            tag: vec![4u8; 15], // Invalid length
        };
        let result = decrypt(&valid_sk, &invalid_tag_ct, None);
        assert!(result.is_err(), "Should reject invalid tag length");

        // Test invalid KEM ciphertext length
        let invalid_kem_ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1000], // Invalid length
            ecdh_ephemeral_pk: vec![],
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

        // Test 64-byte hybrid shared secret is accepted
        let hybrid_secret = vec![1u8; 64];
        let result = derive_encryption_key(&hybrid_secret, &context1);
        assert!(result.is_ok(), "Should accept 64-byte hybrid shared secret");
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_roundtrip() {
        let mut rng = rand::thread_rng();

        // Generate hybrid keypair (ML-KEM-768 + X25519)
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let plaintext = b"Hello, true hybrid encryption!";
        let context = HybridEncryptionContext::default();

        // Encrypt with true hybrid (ML-KEM + X25519 + HKDF + AES-GCM)
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, Some(&context)).unwrap();

        assert_eq!(ct.kem_ciphertext.len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
        assert_eq!(ct.ecdh_ephemeral_pk.len(), 32, "X25519 ephemeral PK should be 32 bytes");
        assert!(!ct.symmetric_ciphertext.is_empty(), "Symmetric ciphertext should not be empty");
        assert_eq!(ct.nonce.len(), 12, "Nonce should be 12 bytes");
        assert_eq!(ct.tag.len(), 16, "Tag should be 16 bytes");

        // Decrypt with true hybrid
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&context)).unwrap();
        assert_eq!(decrypted, plaintext, "Decrypted text should match original");
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_with_aad() {
        let mut rng = rand::thread_rng();

        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let plaintext = b"Secret message with AAD";
        let aad = b"Additional authenticated data";
        let context = HybridEncryptionContext {
            info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(),
            aad: aad.to_vec(),
        };

        // Encrypt with AAD
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, Some(&context)).unwrap();

        // Decrypt with correct AAD
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&context)).unwrap();
        assert_eq!(decrypted, plaintext, "Decryption with correct AAD should succeed");

        // Decrypt with wrong AAD should fail
        let wrong_context = HybridEncryptionContext {
            info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(),
            aad: b"Wrong AAD".to_vec(),
        };
        let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&wrong_context));
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_different_ciphertexts() {
        let mut rng = rand::thread_rng();

        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let plaintext = b"Same plaintext, different ciphertexts";

        let ct1 = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, None).unwrap();
        let ct2 = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, None).unwrap();

        // Ciphertexts should differ (randomized encapsulation + nonce)
        assert_ne!(ct1.kem_ciphertext, ct2.kem_ciphertext);
        assert_ne!(ct1.ecdh_ephemeral_pk, ct2.ecdh_ephemeral_pk);

        // Both should decrypt correctly
        let dec1 = decrypt_hybrid(&hybrid_sk, &ct1, None).unwrap();
        let dec2 = decrypt_hybrid(&hybrid_sk, &ct2, None).unwrap();
        assert_eq!(dec1, plaintext);
        assert_eq!(dec2, plaintext);
    }

    #[test]
    fn test_error_display_variants() {
        let kem_err = HybridEncryptionError::KemError("kem fail".to_string());
        assert!(kem_err.to_string().contains("kem fail"));

        let enc_err = HybridEncryptionError::EncryptionError("enc fail".to_string());
        assert!(enc_err.to_string().contains("enc fail"));

        let dec_err = HybridEncryptionError::DecryptionError("dec fail".to_string());
        assert!(dec_err.to_string().contains("dec fail"));

        let kdf_err = HybridEncryptionError::KdfError("kdf fail".to_string());
        assert!(kdf_err.to_string().contains("kdf fail"));

        let input_err = HybridEncryptionError::InvalidInput("bad input".to_string());
        assert!(input_err.to_string().contains("bad input"));

        let key_err = HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 };
        let msg = key_err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_error_eq_and_clone() {
        let err1 = HybridEncryptionError::KemError("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = HybridEncryptionError::KemError("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_hybrid_ciphertext_clone_debug() {
        let ct = HybridCiphertext {
            kem_ciphertext: vec![1, 2, 3],
            ecdh_ephemeral_pk: vec![4, 5],
            symmetric_ciphertext: vec![6, 7, 8],
            nonce: vec![9; 12],
            tag: vec![10; 16],
        };
        let ct2 = ct.clone();
        assert_eq!(ct.kem_ciphertext, ct2.kem_ciphertext);
        assert_eq!(ct.ecdh_ephemeral_pk, ct2.ecdh_ephemeral_pk);

        let debug_str = format!("{:?}", ct);
        assert!(debug_str.contains("HybridCiphertext"));
    }

    #[test]
    fn test_encryption_context_default() {
        let ctx = HybridEncryptionContext::default();
        assert_eq!(ctx.info, b"LatticeArc-Hybrid-Encryption-v1");
        assert!(ctx.aad.is_empty());
    }

    #[test]
    fn test_encryption_context_clone_debug() {
        let ctx =
            HybridEncryptionContext { info: b"custom-info".to_vec(), aad: b"custom-aad".to_vec() };
        let ctx2 = ctx.clone();
        assert_eq!(ctx.info, ctx2.info);
        assert_eq!(ctx.aad, ctx2.aad);

        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("HybridEncryptionContext"));
    }

    #[test]
    fn test_derive_key_invalid_lengths() {
        let ctx = HybridEncryptionContext::default();

        // Too short (31 bytes)
        assert!(derive_encryption_key(&[0u8; 31], &ctx).is_err());

        // Too long (65 bytes)
        assert!(derive_encryption_key(&[0u8; 65], &ctx).is_err());

        // 1 byte
        assert!(derive_encryption_key(&[0u8; 1], &ctx).is_err());

        // Empty
        assert!(derive_encryption_key(&[], &ctx).is_err());

        // 33 bytes (between valid sizes)
        assert!(derive_encryption_key(&[0u8; 33], &ctx).is_err());
    }

    #[test]
    fn test_derive_key_different_secrets_differ() {
        let ctx = HybridEncryptionContext::default();
        let secret_a = [1u8; 32];
        let secret_b = [2u8; 32];

        let key_a = derive_encryption_key(&secret_a, &ctx).unwrap();
        let key_b = derive_encryption_key(&secret_b, &ctx).unwrap();

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_64_byte_hybrid_secret() {
        let ctx = HybridEncryptionContext::default();
        let secret = [42u8; 64];
        let key = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(key.len(), 32);

        // Deterministic
        let key2 = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_decrypt_hybrid_invalid_kem_ct_length() {
        let mut rng = rand::thread_rng();
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 500], // Wrong: should be 1088
            ecdh_ephemeral_pk: vec![2u8; 32],
            symmetric_ciphertext: vec![3u8; 64],
            nonce: vec![4u8; 12],
            tag: vec![5u8; 16],
        };
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
    }

    #[test]
    fn test_decrypt_hybrid_invalid_ecdh_pk_length() {
        let mut rng = rand::thread_rng();
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            ecdh_ephemeral_pk: vec![2u8; 16], // Wrong: should be 32
            symmetric_ciphertext: vec![3u8; 64],
            nonce: vec![4u8; 12],
            tag: vec![5u8; 16],
        };
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
    }

    #[test]
    fn test_decrypt_hybrid_invalid_nonce_length() {
        let mut rng = rand::thread_rng();
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            ecdh_ephemeral_pk: vec![2u8; 32],
            symmetric_ciphertext: vec![3u8; 64],
            nonce: vec![4u8; 8], // Wrong: should be 12
            tag: vec![5u8; 16],
        };
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_invalid_tag_length() {
        let mut rng = rand::thread_rng();
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            ecdh_ephemeral_pk: vec![2u8; 32],
            symmetric_ciphertext: vec![3u8; 64],
            nonce: vec![4u8; 12],
            tag: vec![5u8; 10], // Wrong: should be 16
        };
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_tampered_ciphertext() {
        let mut rng = rand::thread_rng();
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let plaintext = b"Test message for tampering";
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, None).unwrap();

        // Tamper with symmetric ciphertext
        let mut tampered = ct.clone();
        if let Some(byte) = tampered.symmetric_ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_hybrid(&hybrid_sk, &tampered, None).is_err());

        // Tamper with tag
        let mut tampered_tag = ct;
        if let Some(byte) = tampered_tag.tag.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_hybrid(&hybrid_sk, &tampered_tag, None).is_err());
    }

    #[test]
    fn test_encrypt_hybrid_empty_plaintext() {
        let mut rng = rand::thread_rng();
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let plaintext = b"";
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_hybrid_large_plaintext() {
        let mut rng = rand::thread_rng();
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let plaintext = vec![0xABu8; 10_000];
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, &plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // --- ML-KEM-only encrypt() tests (encapsulation works, decapsulation blocked) ---

    #[test]
    fn test_ml_kem_encrypt_succeeds() {
        let mut rng = rand::thread_rng();
        let (ml_kem_pk, _ml_kem_sk) =
            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Encrypt-only test";
        let ct = encrypt(&mut rng, ml_kem_pk.as_bytes(), plaintext, None);
        assert!(ct.is_ok(), "ML-KEM-only encrypt should succeed");

        let ct = ct.unwrap();
        assert_eq!(ct.kem_ciphertext.len(), 1088);
        assert!(ct.ecdh_ephemeral_pk.is_empty(), "ML-KEM-only path has no ECDH key");
        assert!(!ct.symmetric_ciphertext.is_empty());
        assert_eq!(ct.nonce.len(), 12);
        assert_eq!(ct.tag.len(), 16);
    }

    #[test]
    fn test_ml_kem_encrypt_with_custom_context() {
        let mut rng = rand::thread_rng();
        let (ml_kem_pk, _) =
            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

        let ctx = HybridEncryptionContext {
            info: b"Custom-Info-Domain".to_vec(),
            aad: b"Custom-AAD".to_vec(),
        };
        let ct = encrypt(&mut rng, ml_kem_pk.as_bytes(), b"test data", Some(&ctx));
        assert!(ct.is_ok(), "Should encrypt with custom context");
    }

    #[test]
    fn test_ml_kem_encrypt_produces_unique_ciphertexts() {
        let mut rng = rand::thread_rng();
        let (ml_kem_pk, _) =
            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Determinism test";
        let ct1 = encrypt(&mut rng, ml_kem_pk.as_bytes(), plaintext, None).unwrap();
        let ct2 = encrypt(&mut rng, ml_kem_pk.as_bytes(), plaintext, None).unwrap();

        // Randomized: different KEM ciphertext and nonce each time
        assert_ne!(ct1.kem_ciphertext, ct2.kem_ciphertext);
        assert_ne!(ct1.nonce, ct2.nonce);
    }

    #[test]
    fn test_ml_kem_encrypt_empty_plaintext() {
        let mut rng = rand::thread_rng();
        let (ml_kem_pk, _) =
            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

        let ct = encrypt(&mut rng, ml_kem_pk.as_bytes(), b"", None);
        assert!(ct.is_ok(), "Should encrypt empty plaintext");
        let ct = ct.unwrap();
        assert!(ct.symmetric_ciphertext.is_empty(), "Empty plaintext → empty ciphertext");
        assert_eq!(ct.tag.len(), 16, "Tag is always 16 bytes");
    }

    #[test]
    fn test_decrypt_invalid_ml_kem_sk_length() {
        let sk = vec![0u8; 100]; // Wrong length
        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            ecdh_ephemeral_pk: vec![],
            symmetric_ciphertext: vec![2u8; 64],
            nonce: vec![3u8; 12],
            tag: vec![4u8; 16],
        };
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("2400"));
    }

    #[test]
    fn test_decrypt_invalid_kem_ciphertext_length() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 500], // Wrong
            ecdh_ephemeral_pk: vec![],
            symmetric_ciphertext: vec![2u8; 64],
            nonce: vec![3u8; 12],
            tag: vec![4u8; 16],
        };
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("1088"));
    }

    #[test]
    fn test_decrypt_invalid_nonce_length() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            ecdh_ephemeral_pk: vec![],
            symmetric_ciphertext: vec![2u8; 64],
            nonce: vec![3u8; 10], // Wrong
            tag: vec![4u8; 16],
        };
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("12"));
    }

    #[test]
    fn test_decrypt_invalid_tag_length() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext {
            kem_ciphertext: vec![1u8; 1088],
            ecdh_ephemeral_pk: vec![],
            symmetric_ciphertext: vec![2u8; 64],
            nonce: vec![3u8; 12],
            tag: vec![4u8; 8], // Wrong
        };
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("16"));
    }

    #[test]
    fn test_encrypt_hybrid_with_none_context_uses_default() {
        let mut rng = rand::thread_rng();
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let plaintext = b"Default context test";
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_hybrid_with_none_context_uses_default() {
        let mut rng = rand::thread_rng();
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let default_ctx = HybridEncryptionContext::default();
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, b"ctx test", Some(&default_ctx)).unwrap();
        // Decrypt with None context should also use default
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted, b"ctx test");
    }

    #[test]
    fn test_encrypt_with_none_context_uses_default() {
        let mut rng = rand::thread_rng();
        let (ml_kem_pk, _) =
            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();

        // encrypt() with None should use default context internally
        let ct = encrypt(&mut rng, ml_kem_pk.as_bytes(), b"none ctx", None);
        assert!(ct.is_ok());
    }

    // ========================================================================
    // Additional coverage: derive_encryption_key and error paths
    // ========================================================================

    #[test]
    fn test_derive_encryption_key_with_64_byte_secret() {
        let secret = [0xAA; 64]; // Hybrid 64-byte shared secret
        let ctx = HybridEncryptionContext::default();
        let key = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_encryption_key_invalid_length() {
        let ctx = HybridEncryptionContext::default();
        // 16 bytes is neither 32 nor 64
        let result = derive_encryption_key(&[0u8; 16], &ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let secret = [0xBB; 32];
        let ctx = HybridEncryptionContext::default();
        let k1 = derive_encryption_key(&secret, &ctx).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(k1, k2, "Same inputs must produce same key");
    }

    #[test]
    fn test_derive_encryption_key_different_contexts_differ() {
        let secret = [0xCC; 32];
        let ctx1 = HybridEncryptionContext { info: b"ctx1".to_vec(), aad: vec![] };
        let ctx2 = HybridEncryptionContext { info: b"ctx2".to_vec(), aad: vec![] };
        let k1 = derive_encryption_key(&secret, &ctx1).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx2).unwrap();
        assert_ne!(k1, k2, "Different contexts must produce different keys");
    }

    #[test]
    fn test_derive_encryption_key_with_aad() {
        let secret = [0xDD; 32];
        let ctx_no_aad = HybridEncryptionContext::default();
        let ctx_with_aad = HybridEncryptionContext {
            info: b"LatticeArc-Hybrid-Encryption-v1".to_vec(),
            aad: b"extra-data".to_vec(),
        };
        let k1 = derive_encryption_key(&secret, &ctx_no_aad).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx_with_aad).unwrap();
        assert_ne!(k1, k2, "Different AAD must produce different keys");
    }

    #[test]
    fn test_encrypt_hybrid_custom_context() {
        let mut rng = rand::thread_rng();
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let ctx = HybridEncryptionContext {
            info: b"custom-app-info".to_vec(),
            aad: b"custom-aad".to_vec(),
        };

        let plaintext = b"Custom context encryption";
        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, plaintext, Some(&ctx)).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_hybrid_wrong_context_fails() {
        let mut rng = rand::thread_rng();
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair(&mut rng).unwrap();

        let ctx1 = HybridEncryptionContext { info: b"context-1".to_vec(), aad: b"aad-1".to_vec() };
        let ctx2 = HybridEncryptionContext { info: b"context-2".to_vec(), aad: b"aad-2".to_vec() };

        let ct = encrypt_hybrid(&mut rng, &hybrid_pk, b"test", Some(&ctx1)).unwrap();
        let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx2));
        assert!(result.is_err(), "Wrong context must fail decryption");
    }

    #[test]
    fn test_hybrid_encryption_error_display_all() {
        let errors = vec![
            HybridEncryptionError::KemError("kem".into()),
            HybridEncryptionError::EncryptionError("enc".into()),
            HybridEncryptionError::DecryptionError("dec".into()),
            HybridEncryptionError::InvalidInput("inp".into()),
            HybridEncryptionError::KdfError("kdf".into()),
            HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 },
        ];
        for err in &errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty());
        }
    }
}
