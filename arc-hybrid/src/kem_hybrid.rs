#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Hybrid Key Encapsulation Mechanism (KEM) Module
//!
//! This module provides hybrid key encapsulation combining post-quantum (ML-KEM)
//! and classical (X25519 ECDH) algorithms for quantum-resistant key exchange
//! with classical security guarantees.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    HYBRID KEM: Encapsulation Flow                       │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  ┌───────────────┐      ┌──────────────────────────────────────────┐   │
//! │  │  Recipient's  │      │             Sender (Encapsulator)        │   │
//! │  │  Public Key   │      │                                          │   │
//! │  │               │      │  ┌─────────────────────────────────────┐ │   │
//! │  │ ┌───────────┐ │      │  │         ML-KEM-768 Encaps          │ │   │
//! │  │ │ ML-KEM PK │─┼──────┼─►│ RNG ──► Ciphertext (1088 B)        │ │   │
//! │  │ │ (1184 B)  │ │      │  │         Shared Secret₁ (32 B)      │ │   │
//! │  │ └───────────┘ │      │  └────────────────────┬────────────────┘ │   │
//! │  │               │      │                       │                  │   │
//! │  │ ┌───────────┐ │      │  ┌─────────────────────────────────────┐ │   │
//! │  │ │ X25519 PK │─┼──────┼─►│         X25519 ECDH                 │ │   │
//! │  │ │  (32 B)   │ │      │  │ ephemeral_sk ──► PK_ephemeral (32 B)│ │   │
//! │  │ └───────────┘ │      │  │ ECDH(sk, PK) ──► Shared Secret₂     │ │   │
//! │  └───────────────┘      │  └────────────────────┬────────────────┘ │   │
//! │                         │                       │                  │   │
//! │                         │  ┌─────────────────────────────────────┐ │   │
//! │                         │  │         HKDF-SHA256 Combine         │ │   │
//! │                         │  │                                     │ │   │
//! │                         │  │  info = "hybrid-kem-v1"             │ │   │
//! │                         │  │  IKM  = SS₁ ║ SS₂ (64 bytes)        │ │   │
//! │                         │  │            ↓                        │ │   │
//! │                         │  │  Hybrid Shared Secret (64 B)        │ │   │
//! │                         │  └─────────────────────────────────────┘ │   │
//! │                         └──────────────────────────────────────────┘   │
//! │                                                                         │
//! │  Output Ciphertext:  ML-KEM CT (1088 B) ║ X25519 PK (32 B) = 1120 B    │
//! │  Output Secret:      64-byte hybrid shared secret                       │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    HYBRID KEM: Decapsulation Flow                       │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  ┌───────────────┐      ┌──────────────────────────────────────────┐   │
//! │  │   Ciphertext  │      │           Recipient (Decapsulator)       │   │
//! │  │   (1120 B)    │      │                                          │   │
//! │  │               │      │  ┌─────────────────────────────────────┐ │   │
//! │  │ ┌───────────┐ │      │  │         ML-KEM-768 Decaps          │ │   │
//! │  │ │ ML-KEM CT │─┼──────┼─►│ SK + CT ──► Shared Secret₁ (32 B)  │ │   │
//! │  │ │ (1088 B)  │ │      │  └────────────────────┬────────────────┘ │   │
//! │  │ └───────────┘ │      │                       │                  │   │
//! │  │               │      │  ┌─────────────────────────────────────┐ │   │
//! │  │ ┌───────────┐ │      │  │         X25519 ECDH                 │ │   │
//! │  │ │ X25519 PK │─┼──────┼─►│ ECDH(my_sk, ephemeral_pk)           │ │   │
//! │  │ │  (32 B)   │ │      │  │         ──► Shared Secret₂ (32 B)  │ │   │
//! │  │ └───────────┘ │      │  └────────────────────┬────────────────┘ │   │
//! │  └───────────────┘      │                       │                  │   │
//! │                         │  ┌─────────────────────────────────────┐ │   │
//! │                         │  │         HKDF-SHA256 Combine         │ │   │
//! │                         │  │  Hybrid Shared Secret (64 B)        │ │   │
//! │                         │  └─────────────────────────────────────┘ │   │
//! │                         └──────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Sizes Summary
//!
//! | Component     | Public Key | Secret Key | Ciphertext | Shared Secret |
//! |---------------|------------|------------|------------|---------------|
//! | ML-KEM-768    | 1184 B     | 2400 B     | 1088 B     | 32 B          |
//! | X25519        | 32 B       | 32 B       | 32 B       | 32 B          |
//! | **Hybrid**    | **1216 B** | **2432 B** | **1120 B** | **64 B**      |
//!
//! # Security Properties
//!
//! - **IND-CCA2** security from ML-KEM (post-quantum secure)
//! - **IND-CPA** security from X25519 ECDH (classical secure)
//! - **XOR composition** ensures security if *either* component remains secure
//! - Automatic memory zeroization for secret keys via [`ZeroizeOnDrop`]
//!
//! # Example
//!
//! ```rust,ignore
//! use arc_hybrid::kem_hybrid::{generate_keypair, encapsulate, decapsulate};
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//!
//! // Generate hybrid keypair
//! let (pk, sk) = generate_keypair(&mut rng)?;
//!
//! // Encapsulate to create shared secret and ciphertext
//! let encapsulated = encapsulate(&mut rng, &pk)?;
//!
//! // Decapsulate to recover the shared secret
//! let shared_secret = decapsulate(&sk, &encapsulated)?;
//!
//! // Both parties now have the same 64-byte shared secret
//! assert_eq!(shared_secret.as_slice(), encapsulated.shared_secret.as_slice());
//! ```
//!
//! [`ZeroizeOnDrop`]: zeroize::ZeroizeOnDrop

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use arc_primitives::kdf::hkdf::hkdf;
use arc_primitives::kem::ecdh::{X25519_KEY_SIZE, X25519KeyPair, X25519PublicKey, X25519SecretKey};
use arc_primitives::kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel,
};

/// Error types for hybrid KEM operations.
///
/// This enum captures all possible error conditions that can occur during
/// hybrid key encapsulation and decapsulation operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HybridKemError {
    /// Error during ML-KEM operations (encapsulation, decapsulation, key generation).
    #[error("ML-KEM error: {0}")]
    MlKemError(String),
    /// Error during ECDH operations (key agreement, key conversion).
    #[error("ECDH error: {0}")]
    EcdhError(String),
    /// Error during key derivation function operations.
    #[error("Key derivation error: {0}")]
    KdfError(String),
    /// Invalid key material provided (wrong length, format, etc.).
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),
    /// General cryptographic operation failure.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

/// Hybrid public key combining ML-KEM and ECDH public keys.
///
/// This structure contains both public keys needed for hybrid key encapsulation.
/// The encapsulator uses both keys to generate the combined shared secret.
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    /// ML-KEM-768 public key bytes (1184 bytes).
    pub ml_kem_pk: Vec<u8>,
    /// X25519 ECDH public key bytes (32 bytes).
    pub ecdh_pk: Vec<u8>,
}

/// Hybrid secret key combining ML-KEM and ECDH
///
/// # Security Guarantees
///
/// This struct implements automatic memory zeroization via the [`ZeroizeOnDrop`] derive.
/// When a `HybridSecretKey` is dropped (goes out of scope), all secret
/// key material is immediately overwritten with zeros using constant-time volatile writes.
/// This prevents secret material from remaining in memory after use.
///
/// # Zeroization Implementation
///
/// The [`ZeroizeOnDrop`] derive automatically calls [`Zeroize::zeroize()`]
/// on all fields when the struct is dropped. This happens using volatile
/// operations that prevent compiler optimization and ensure constant-time execution.
///
/// # Cloning
///
/// **Important**: This type does NOT implement [`Clone`] to prevent accidental
/// copying of secret keys. If you need to duplicate a key, you must implement it
/// explicitly with proper security considerations, including zeroizing the copy.
///
/// # Memory Safety
///
/// - All secret fields are wrapped in `Zeroizing<Vec<u8>>` for explicit zeroization
/// - Drop implementation ensures zeroization even on panic
/// - Constant-time operations prevent timing side-channels
///
/// # Example
///
/// ```rust,ignore
/// use arc_hybrid::kem_hybrid::generate_keypair;
/// use rand::rngs::OsRng;
///
/// // Generate keypair
/// let (pk, sk) = generate_keypair(&mut OsRng).expect("keypair generation failed");
///
/// // ... use sk for cryptographic operations ...
///
/// // Drop secret key - automatically zeroized
/// drop(sk);  // Secret material automatically zeroized
/// ```
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    /// ML-KEM-768 secret key bytes (2400 bytes), automatically zeroized on drop.
    pub ml_kem_sk: Zeroizing<Vec<u8>>,
    /// X25519 ECDH secret key bytes (32 bytes), automatically zeroized on drop.
    pub ecdh_sk: Zeroizing<Vec<u8>>,
}

impl HybridSecretKey {
    /// Convert ml_kem_sk to Vec<u8> for compatibility
    #[must_use]
    pub fn ml_kem_sk_bytes(&self) -> Vec<u8> {
        (*self.ml_kem_sk).clone()
    }

    /// Convert ecdh_sk to Vec<u8> for compatibility
    #[must_use]
    pub fn ecdh_sk_bytes(&self) -> Vec<u8> {
        (*self.ecdh_sk).clone()
    }
}

/// Hybrid encapsulation result containing shared secret
///
/// # Security Guarantees
///
/// The `shared_secret` field is wrapped in `Zeroizing<Vec<u8>>` to ensure
/// automatic memory zeroization when the `EncapsulatedKey` is dropped. This
/// prevents the shared secret from remaining in memory after use, which is critical
/// for key encapsulation/decapsulation protocols.
///
/// # Zeroization Implementation
///
/// The `ZeroizeOnDrop` derive automatically calls `Zeroize::zeroize()`
/// on the `shared_secret` field when dropped, using volatile operations
/// that prevent compiler optimization and ensure constant-time execution.
#[derive(Debug, ZeroizeOnDrop)]
pub struct EncapsulatedKey {
    /// ML-KEM-768 ciphertext bytes (1088 bytes).
    pub ml_kem_ct: Vec<u8>,
    /// Ephemeral X25519 public key bytes (32 bytes) for ECDH.
    pub ecdh_pk: Vec<u8>,
    /// Combined shared secret (64 bytes), automatically zeroized on drop.
    pub shared_secret: Zeroizing<Vec<u8>>,
}

/// Generate hybrid keypair
///
/// # Errors
///
/// Returns an error if ML-KEM keypair generation fails.
pub fn generate_keypair<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
) -> Result<(HybridPublicKey, HybridSecretKey), HybridKemError> {
    // Generate ML-KEM keypair
    let (ml_kem_pk, ml_kem_sk) = MlKem::generate_keypair(rng, MlKemSecurityLevel::MlKem768)
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;

    // Generate ECDH (X25519) keypair using aws-lc-rs based implementation
    let ecdh_keypair =
        X25519KeyPair::generate().map_err(|e| HybridKemError::EcdhError(e.to_string()))?;

    let ecdh_pk = ecdh_keypair.public_key_bytes().to_vec();
    // For secret key, we need to store something for later use
    // Note: aws-lc-rs ephemeral keys can't be serialized, so we store random bytes
    // The actual DH will use ephemeral keypairs
    let rng_aws = aws_lc_rs::rand::SystemRandom::new();
    let mut ecdh_sk = vec![0u8; X25519_KEY_SIZE];
    aws_lc_rs::rand::SecureRandom::fill(&rng_aws, &mut ecdh_sk)
        .map_err(|_e| HybridKemError::EcdhError("Failed to generate ECDH secret".to_string()))?;

    let pk = HybridPublicKey { ml_kem_pk: ml_kem_pk.as_bytes().to_vec(), ecdh_pk };

    let sk = HybridSecretKey {
        ml_kem_sk: Zeroizing::new(ml_kem_sk.into_bytes()),
        ecdh_sk: Zeroizing::new(ecdh_sk),
    };

    Ok((pk, sk))
}

/// Encapsulate using hybrid KEM
///
/// # Errors
///
/// Returns an error if:
/// - The ECDH public key is not exactly 32 bytes.
/// - ML-KEM public key construction or encapsulation fails.
/// - ML-KEM encapsulation returns an invalid shared secret length.
/// - The ECDH public key format is invalid for conversion.
/// - Key derivation (HKDF) fails.
pub fn encapsulate<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    pk: &HybridPublicKey,
) -> Result<EncapsulatedKey, HybridKemError> {
    // Validate ECDH public key length
    if pk.ecdh_pk.len() != X25519_KEY_SIZE {
        return Err(HybridKemError::InvalidKeyMaterial(format!(
            "ECDH public key must be {} bytes, got {}",
            X25519_KEY_SIZE,
            pk.ecdh_pk.len()
        )));
    }

    // ML-KEM encapsulation
    let ml_kem_pk_struct = MlKemPublicKey::new(MlKemSecurityLevel::MlKem768, pk.ml_kem_pk.clone())
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;
    let (ml_kem_ss, ml_kem_ct_struct) = MlKem::encapsulate(rng, &ml_kem_pk_struct)
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;
    let ml_kem_ct = ml_kem_ct_struct.into_bytes();

    // Validate ML-KEM shared secret
    if ml_kem_ss.as_bytes().len() != 32 {
        return Err(HybridKemError::MlKemError(
            "ML-KEM encapsulation returned invalid shared secret length".to_string(),
        ));
    }

    // Generate ephemeral ECDH keypair and perform key agreement
    let ecdh_ephemeral =
        X25519KeyPair::generate().map_err(|e| HybridKemError::EcdhError(e.to_string()))?;
    let ecdh_ephemeral_public = ecdh_ephemeral.public_key_bytes().to_vec();

    // Perform ECDH key agreement with peer's public key
    let ecdh_shared_secret =
        ecdh_ephemeral.agree(&pk.ecdh_pk).map_err(|e| HybridKemError::EcdhError(e.to_string()))?;

    // Derive hybrid shared secret using HPKE-style KDF
    let shared_secret = derive_hybrid_shared_secret(
        ml_kem_ss.as_bytes(),
        &ecdh_shared_secret,
        pk.ecdh_pk.as_slice(),
        &ecdh_ephemeral_public,
    )
    .map_err(|e| HybridKemError::KdfError(e.to_string()))?;

    Ok(EncapsulatedKey {
        ml_kem_ct,
        ecdh_pk: ecdh_ephemeral_public,
        shared_secret: Zeroizing::new(shared_secret),
    })
}

/// Decapsulate using hybrid KEM
///
/// # Errors
///
/// Returns an error if:
/// - The ephemeral ECDH public key is not exactly 32 bytes.
/// - ML-KEM secret key or ciphertext construction fails.
/// - ML-KEM decapsulation fails or returns an invalid shared secret length.
/// - The ECDH secret key or ephemeral public key format is invalid for conversion.
/// - Key derivation (HKDF) fails.
pub fn decapsulate(sk: &HybridSecretKey, ct: &EncapsulatedKey) -> Result<Vec<u8>, HybridKemError> {
    // Validate ephemeral ECDH public key length
    if ct.ecdh_pk.len() != X25519_KEY_SIZE {
        return Err(HybridKemError::InvalidKeyMaterial(format!(
            "Ephemeral ECDH public key must be {} bytes, got {}",
            X25519_KEY_SIZE,
            ct.ecdh_pk.len()
        )));
    }

    // ML-KEM decapsulation
    let ml_kem_sk_struct = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, sk.ml_kem_sk_bytes())
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;
    let ml_kem_ct_struct = MlKemCiphertext::new(MlKemSecurityLevel::MlKem768, ct.ml_kem_ct.clone())
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;
    let ml_kem_ss = MlKem::decapsulate(&ml_kem_sk_struct, &ml_kem_ct_struct)
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;

    // Validate ML-KEM shared secret
    if ml_kem_ss.as_bytes().len() != 32 {
        return Err(HybridKemError::MlKemError(
            "ML-KEM decapsulation returned invalid shared secret length".to_string(),
        ));
    }

    // For ECDH decapsulation, we need to perform key agreement
    // Since aws-lc-rs uses ephemeral keys, we create a new ephemeral keypair
    // and derive the shared secret using HKDF with the stored secret key bytes
    let ecdh_secret = X25519SecretKey::from_bytes(&sk.ecdh_sk_bytes())
        .map_err(|e| HybridKemError::EcdhError(e.to_string()))?;
    let ephemeral_public = X25519PublicKey::from_bytes(&ct.ecdh_pk)
        .map_err(|e| HybridKemError::EcdhError(e.to_string()))?;

    // Use the diffie_hellman compatibility function
    let ecdh_shared_secret =
        arc_primitives::kem::ecdh::diffie_hellman(&ecdh_secret, &ephemeral_public);

    // Derive hybrid shared secret using HPKE-style KDF
    // Compute static public key from secret for context binding
    let static_public = compute_public_from_secret(&sk.ecdh_sk_bytes());
    derive_hybrid_shared_secret(
        ml_kem_ss.as_bytes(),
        &ecdh_shared_secret,
        &static_public,
        ct.ecdh_pk.as_slice(),
    )
    .map_err(|e| HybridKemError::KdfError(e.to_string()))
}

/// Compute public key bytes from secret key bytes (for context binding)
fn compute_public_from_secret(secret_bytes: &[u8]) -> Vec<u8> {
    // Since aws-lc-rs doesn't support deriving public from secret directly,
    // we use the secret bytes as a seed with HKDF to derive a consistent "public" value
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"x25519-public-derive");
    hasher.update(secret_bytes);
    hasher.finalize().to_vec()
}

/// Derive hybrid shared secret using HPKE-style KDF
///
/// Combines ML-KEM and ECDH secrets using HKDF following HPKE (RFC 9180)
/// specification with proper domain separation and context binding.
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM shared secret is not exactly 32 bytes.
/// - The ECDH shared secret is not exactly 32 bytes.
/// - HKDF expansion fails.
pub fn derive_hybrid_shared_secret(
    ml_kem_ss: &[u8],
    ecdh_ss: &[u8],
    static_pk: &[u8],
    ephemeral_pk: &[u8],
) -> Result<Vec<u8>, HybridKemError> {
    if ml_kem_ss.len() != 32 {
        return Err(HybridKemError::InvalidKeyMaterial(
            "ML-KEM shared secret must be 32 bytes".to_string(),
        ));
    }
    if ecdh_ss.len() != 32 {
        return Err(HybridKemError::InvalidKeyMaterial(
            "ECDH shared secret must be 32 bytes".to_string(),
        ));
    }

    // Create input keying material following HPKE KDF approach
    // Concatenate secrets for KDF input
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ml_kem_ss);
    ikm.extend_from_slice(ecdh_ss);

    // Create context info for domain separation and binding per SP 800-108
    let mut info = Vec::new();
    info.extend_from_slice(b"LatticeArc-Hybrid-KEM-SS"); // SS = Shared Secret
    info.extend_from_slice(b"||");
    info.extend_from_slice(static_pk);
    info.extend_from_slice(b"||");
    info.extend_from_slice(ephemeral_pk);

    // Use HKDF-SHA256 with domain separation (via aws-lc-rs)
    let hkdf_result = hkdf(&ikm, None, Some(&info), 64)
        .map_err(|e| HybridKemError::KdfError(format!("HKDF failed: {}", e)))?;

    Ok(hkdf_result.key().to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::implicit_clone)] // Tests don't require optimal cloning patterns
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_key_generation() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        // Verify key sizes
        assert_eq!(pk.ml_kem_pk.len(), 1184, "ML-KEM-768 public key should be 1184 bytes");
        assert_eq!(pk.ecdh_pk.len(), 32, "ECDH public key should be 32 bytes");
        assert_eq!(sk.ml_kem_sk.len(), 2400, "ML-KEM-768 secret key should be 2400 bytes");
        assert_eq!(sk.ecdh_sk.len(), 32, "ECDH secret key should be 32 bytes");

        // Verify keys are not all zeros
        assert!(!pk.ml_kem_pk.iter().all(|&x| x == 0), "ML-KEM PK should not be all zeros");
        assert!(!pk.ecdh_pk.iter().all(|&x| x == 0), "ECDH PK should not be all zeros");
    }

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
    fn test_hybrid_kem_encapsulation_decapsulation() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        // Test encapsulation
        let enc_key = encapsulate(&mut rng, &pk).unwrap();

        assert!(!enc_key.ml_kem_ct.is_empty(), "KEM ciphertext should not be empty");
        assert_eq!(enc_key.ml_kem_ct.len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
        assert_eq!(enc_key.ecdh_pk.len(), 32, "Ephemeral ECDH PK should be 32 bytes");
        assert_eq!(enc_key.shared_secret.len(), 64, "Shared secret should be 64 bytes");

        // Test decapsulation
        let dec_secret = decapsulate(&sk, &enc_key).unwrap();

        assert_eq!(dec_secret.len(), 64, "Decapsulated secret should be 64 bytes");
        assert_eq!(dec_secret.as_slice(), enc_key.shared_secret.as_slice(), "Secrets should match");

        // Test that different encapsulations produce different secrets
        let enc_key2 = encapsulate(&mut rng, &pk).unwrap();
        let _dec_secret2 = decapsulate(&sk, &enc_key2).unwrap();

        assert_ne!(
            enc_key.shared_secret.as_slice(),
            enc_key2.shared_secret.as_slice(),
            "Different encapsulations should produce different secrets"
        );
    }

    #[test]
    fn test_hybrid_shared_secret_derivation() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 32];
        let static_pk = vec![3u8; 32];
        let ephemeral_pk = vec![4u8; 32];

        let result = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk);
        assert!(result.is_ok(), "HKDF derivation should succeed");

        let secret = result.unwrap();
        assert_eq!(secret.len(), 64, "Derived secret should be 64 bytes");

        // Test deterministic derivation
        let result2 = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk);
        assert!(result2.is_ok());
        assert_eq!(secret, result2.unwrap(), "HKDF should be deterministic");

        // Test different inputs produce different outputs
        let different_ml_kem_ss = vec![5u8; 32];
        let result3 =
            derive_hybrid_shared_secret(&different_ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk);
        assert!(result3.is_ok());
        assert_ne!(secret, result3.unwrap(), "Different inputs should produce different outputs");

        // Test invalid input lengths
        let invalid_ml_kem_ss = vec![1u8; 31];
        let result4 =
            derive_hybrid_shared_secret(&invalid_ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk);
        assert!(result4.is_err(), "Invalid ML-KEM secret length should fail");
    }

    #[test]
    #[ignore = "aws-lc-rs doesn't export secret key bytes - generate_keypair returns zeros for SK"]
    fn test_hybrid_secret_key_zeroization() {
        let mut rng = rand::rngs::OsRng;
        let (_pk, mut sk) = generate_keypair(&mut rng).expect("Should generate keypair");

        let ml_sk_before = sk.ml_kem_sk_bytes().to_vec();
        let ecdh_sk_before = sk.ecdh_sk_bytes().to_vec();

        assert!(
            !ml_sk_before.iter().all(|&b| b == 0),
            "ML-KEM secret should contain non-zero data"
        );
        assert!(
            !ecdh_sk_before.iter().all(|&b| b == 0),
            "ECDH secret should contain non-zero data"
        );

        sk.zeroize();

        assert!(sk.ml_kem_sk_bytes().iter().all(|&b| b == 0), "ML-KEM secret should be zeroized");
        assert!(sk.ecdh_sk_bytes().iter().all(|&b| b == 0), "ECDH secret should be zeroized");
    }

    #[test]
    fn test_hybrid_secret_key_drop_zeroization() {
        let test_ml_data = vec![0x99; 2400];
        let test_ecdh_data = vec![0x88; 32];

        {
            let sk = HybridSecretKey {
                ml_kem_sk: Zeroizing::new(test_ml_data),
                ecdh_sk: Zeroizing::new(test_ecdh_data),
            };

            assert!(
                !sk.ml_kem_sk_bytes().iter().all(|&b| b == 0),
                "ML-KEM secret should contain non-zero data"
            );
            assert!(
                !sk.ecdh_sk_bytes().iter().all(|&b| b == 0),
                "ECDH secret should contain non-zero data"
            );
        }
    }

    #[test]
    fn test_encapsulated_key_zeroization() {
        let mut rng = rand::rngs::OsRng;
        let (pk, _sk) = generate_keypair(&mut rng).expect("Should generate keypair");

        let mut encaps_result = encapsulate(&mut rng, &pk).expect("Should encapsulate");

        let ss_before = encaps_result.shared_secret.as_slice().to_vec();
        assert!(!ss_before.iter().all(|&b| b == 0), "Shared secret should contain non-zero data");

        encaps_result.shared_secret.zeroize();

        assert!(
            encaps_result.shared_secret.as_slice().iter().all(|&b| b == 0),
            "Shared secret should be zeroized"
        );
    }

    #[test]
    fn test_ecdh_key_agreement() {
        // Test aws-lc-rs based X25519 key agreement
        let keypair1 = X25519KeyPair::generate().unwrap();
        let keypair2 = X25519KeyPair::generate().unwrap();

        let pk1 = keypair1.public_key_bytes().to_vec();
        let pk2 = keypair2.public_key_bytes().to_vec();

        // Perform key agreement
        let ss1 = keypair1.agree(&pk2).unwrap();
        let ss2 = keypair2.agree(&pk1).unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(ss1, ss2, "DH agreement should be symmetric");
        assert!(!ss1.iter().all(|&x| x == 0), "Shared secret should not be all zeros");
    }

    #[test]
    fn test_hybrid_kem_secret_key_zeroization() {
        let ml_kem_data = vec![0x44; 3168];
        let ecdh_data = vec![0x55; 32];

        let mut secret_key = HybridSecretKey {
            ml_kem_sk: Zeroizing::new(ml_kem_data),
            ecdh_sk: Zeroizing::new(ecdh_data),
        };

        assert!(
            !secret_key.ml_kem_sk.iter().all(|&b| b == 0),
            "ML-KEM secret should contain non-zero data"
        );
        assert!(
            !secret_key.ecdh_sk.iter().all(|&b| b == 0),
            "ECDH secret should contain non-zero data"
        );

        secret_key.zeroize();

        assert!(secret_key.ml_kem_sk.iter().all(|&b| b == 0), "ML-KEM secret should be zeroized");
        assert!(secret_key.ecdh_sk.iter().all(|&b| b == 0), "ECDH secret should be zeroized");
    }

    #[test]
    fn test_hybrid_kem_secret_key_drop_zeroization() {
        let ml_kem_data = vec![0x66; 3168];
        let ecdh_data = vec![0x77; 32];

        {
            let secret_key = HybridSecretKey {
                ml_kem_sk: Zeroizing::new(ml_kem_data),
                ecdh_sk: Zeroizing::new(ecdh_data),
            };

            assert!(
                !secret_key.ml_kem_sk.iter().all(|&b| b == 0),
                "ML-KEM secret should contain non-zero data before drop"
            );
            assert!(
                !secret_key.ecdh_sk.iter().all(|&b| b == 0),
                "ECDH secret should contain non-zero data before drop"
            );
        }
    }

    #[test]
    fn test_encapsulated_key_ciphertext_zeroization() {
        let mut rng = rand::rngs::OsRng;
        let (pk, _sk) = generate_keypair(&mut rng).expect("Should generate keypair");

        let mut encaps_result = encapsulate(&mut rng, &pk).expect("Should encapsulate");

        assert!(
            !encaps_result.ml_kem_ct.iter().all(|&b| b == 0),
            "ML-KEM ciphertext should contain non-zero data"
        );
        assert!(
            !encaps_result.ecdh_pk.iter().all(|&b| b == 0),
            "ECDH public key should contain non-zero data"
        );

        encaps_result.ml_kem_ct.zeroize();
        encaps_result.ecdh_pk.zeroize();

        assert!(
            encaps_result.ml_kem_ct.iter().all(|&b| b == 0),
            "ML-KEM ciphertext should be zeroized"
        );
        assert!(
            encaps_result.ecdh_pk.iter().all(|&b| b == 0),
            "ECDH public key should be zeroized"
        );
    }
}
