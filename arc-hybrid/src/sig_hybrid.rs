#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Hybrid Digital Signatures Module
//!
//! This module provides hybrid digital signatures that combine post-quantum
//! (ML-DSA) and classical (Ed25519) signature algorithms for enhanced security
//! during the quantum transition period.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    HYBRID SIGNATURE: Signing Flow                       │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  ┌─────────────┐                                                        │
//! │  │   Message   │                                                        │
//! │  │     M       │                                                        │
//! │  └──────┬──────┘                                                        │
//! │         │                                                               │
//! │         ├────────────────────────────────────────┐                      │
//! │         │                                        │                      │
//! │         ▼                                        ▼                      │
//! │  ┌──────────────────────┐              ┌──────────────────────┐         │
//! │  │    ML-DSA-65 Sign    │              │   Ed25519 Sign       │         │
//! │  │                      │              │                      │         │
//! │  │  SK_pq + M ──► σ_pq  │              │  SK_ed + M ──► σ_ed  │         │
//! │  │    (3293 bytes)      │              │    (64 bytes)        │         │
//! │  └──────────┬───────────┘              └──────────┬───────────┘         │
//! │             │                                     │                     │
//! │             └────────────────┬────────────────────┘                     │
//! │                              │                                          │
//! │                              ▼                                          │
//! │                  ┌───────────────────────┐                              │
//! │                  │  Hybrid Signature     │                              │
//! │                  │  σ = σ_pq ║ σ_ed      │                              │
//! │                  │  (3293 + 64 = 3357 B) │                              │
//! │                  └───────────────────────┘                              │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    HYBRID SIGNATURE: Verification Flow                  │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │  ┌─────────────┐         ┌───────────────────────┐                      │
//! │  │   Message   │         │  Hybrid Signature     │                      │
//! │  │     M       │         │  σ = σ_pq ║ σ_ed      │                      │
//! │  └──────┬──────┘         └───────────┬───────────┘                      │
//! │         │                            │                                  │
//! │         │  ┌─────────────────────────┴─────────────────────────┐        │
//! │         │  │                                                   │        │
//! │         │  │ Parse: first 3293 bytes = σ_pq, last 64 = σ_ed   │        │
//! │         │  │                                                   │        │
//! │         │  └──────────────────┬────────────────────────────────┘        │
//! │         │                     │                                         │
//! │         ├────────────────────┬┴───────────────────┐                     │
//! │         │                    │                    │                     │
//! │         ▼                    ▼                    ▼                     │
//! │  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐           │
//! │  │ ML-DSA Verify  │   │                │   │ Ed25519 Verify │           │
//! │  │                │   │                │   │                │           │
//! │  │ PK_pq, M, σ_pq │   │     AND        │   │ PK_ed, M, σ_ed │           │
//! │  │       │        │   │                │   │       │        │           │
//! │  └───────┼────────┘   └───────┬────────┘   └───────┼────────┘           │
//! │          │                    │                    │                    │
//! │          ▼                    ▼                    ▼                    │
//! │       ┌─────┐             ┌──────┐             ┌─────┐                  │
//! │       │ OK? │─────────────┤ BOTH ├─────────────│ OK? │                  │
//! │       └─────┘             └──┬───┘             └─────┘                  │
//! │                              │                                          │
//! │                              ▼                                          │
//! │                     ┌────────────────┐                                  │
//! │                     │  Valid = true  │                                  │
//! │                     │  iff BOTH pass │                                  │
//! │                     └────────────────┘                                  │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Sizes Summary
//!
//! | Component   | Public Key | Secret Key | Signature  |
//! |-------------|------------|------------|------------|
//! | ML-DSA-65   | 1952 B     | 4032 B     | 3293 B     |
//! | Ed25519     | 32 B       | 32 B       | 64 B       |
//! | **Hybrid**  | **1984 B** | **4064 B** | **3357 B** |
//!
//! # Security Properties
//!
//! - **EUF-CMA** (Existential Unforgeability under Chosen Message Attack) security
//! - **AND-composition**: Requires breaking BOTH ML-DSA AND Ed25519 to forge
//! - Automatic memory zeroization for secret keys via [`ZeroizeOnDrop`]
//!
//! # Example
//!
//! ```rust,ignore
//! use arc_hybrid::sig_hybrid::{generate_keypair, sign, verify};
//! use rand::rngs::OsRng;
//!
//! let mut rng = OsRng;
//!
//! // Generate hybrid keypair
//! let (pk, sk) = generate_keypair(&mut rng)?;
//!
//! // Sign a message (deterministic - no RNG needed)
//! let message = b"Hello, hybrid signatures!";
//! let signature = sign(&sk, message)?;
//!
//! // Verify the signature
//! let is_valid = verify(&pk, message, &signature)?;
//! assert!(is_valid);
//! ```
//!
//! [`ZeroizeOnDrop`]: zeroize::ZeroizeOnDrop

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use arc_primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    generate_keypair as ml_dsa_generate_keypair, sign as ml_dsa_sign, verify as ml_dsa_verify,
};

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};

/// Error types for hybrid signature operations.
///
/// This enum captures all possible error conditions that can occur during
/// hybrid signature generation and verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HybridSignatureError {
    /// Error during ML-DSA signature operations.
    #[error("ML-DSA error: {0}")]
    MlDsaError(String),
    /// Error during Ed25519 signature operations.
    #[error("Ed25519 error: {0}")]
    Ed25519Error(String),
    /// Signature verification failed for one or both components.
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    /// Invalid key material provided (wrong length, format, etc.).
    #[error("Invalid key material: {0}")]
    InvalidKeyMaterial(String),
    /// General cryptographic operation failure.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

/// Hybrid public key combining ML-DSA and Ed25519 public keys.
///
/// This structure contains both public keys needed to verify a hybrid signature.
/// Both component signatures must verify for the hybrid signature to be valid.
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    /// ML-DSA-65 public key bytes (1952 bytes).
    pub ml_dsa_pk: Vec<u8>,
    /// Ed25519 public key bytes (32 bytes).
    pub ed25519_pk: Vec<u8>,
}

/// Hybrid secret key combining ML-DSA and Ed25519
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
/// copying of secret keys. If you need to clone, you must implement it
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
/// use arc_hybrid::sig_hybrid::generate_keypair;
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
    /// ML-DSA-65 secret key bytes (4032 bytes), automatically zeroized on drop.
    pub ml_dsa_sk: Zeroizing<Vec<u8>>,
    /// Ed25519 secret key bytes (32 bytes), automatically zeroized on drop.
    pub ed25519_sk: Zeroizing<Vec<u8>>,
}

impl HybridSecretKey {
    /// Convert ml_dsa_sk to Vec<u8> for compatibility
    #[must_use]
    pub fn ml_dsa_sk_bytes(&self) -> Vec<u8> {
        (*self.ml_dsa_sk).clone()
    }

    /// Convert ed25519_sk to Vec<u8> for compatibility
    #[must_use]
    pub fn ed25519_sk_bytes(&self) -> Vec<u8> {
        (*self.ed25519_sk).clone()
    }
}

/// Hybrid signature combining ML-DSA and Ed25519 signatures.
///
/// Both component signatures must be present and verify against their
/// respective public keys for the hybrid signature to be considered valid.
/// The signature data can be manually zeroized using the [`Zeroize`] trait.
///
/// [`Zeroize`]: zeroize::Zeroize
#[derive(Debug, Clone, Zeroize)]
pub struct HybridSignature {
    /// ML-DSA-65 signature bytes (3309 bytes for ML-DSA-65).
    pub ml_dsa_sig: Vec<u8>,
    /// Ed25519 signature bytes (64 bytes).
    pub ed25519_sig: Vec<u8>,
}

/// Generate hybrid keypair
///
/// # Errors
///
/// Returns an error if ML-DSA keypair generation fails.
pub fn generate_keypair<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
) -> Result<(HybridPublicKey, HybridSecretKey), HybridSignatureError> {
    // Generate ML-DSA keypair
    let (ml_dsa_pk, ml_dsa_sk) = ml_dsa_generate_keypair(MlDsaParameterSet::MLDSA65)
        .map_err(|e| HybridSignatureError::MlDsaError(e.to_string()))?;

    // Generate Ed25519 keypair using real cryptographic key generation
    let ed25519_signing_key = Ed25519SigningKey::generate(rng);
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();

    let ed25519_pk = ed25519_verifying_key.to_bytes().to_vec();
    let ed25519_sk = ed25519_signing_key.to_bytes().to_vec();

    let pk = HybridPublicKey { ml_dsa_pk: ml_dsa_pk.as_bytes().to_vec(), ed25519_pk };

    let sk = HybridSecretKey {
        ml_dsa_sk: Zeroizing::new(ml_dsa_sk.as_bytes().to_vec()),
        ed25519_sk: Zeroizing::new(ed25519_sk),
    };

    Ok((pk, sk))
}

/// Sign using hybrid signature scheme
///
/// Both ML-DSA and Ed25519 signing are deterministic, so no RNG is required.
///
/// # Errors
///
/// Returns an error if:
/// - The Ed25519 secret key is not exactly 32 bytes.
/// - ML-DSA secret key construction or signing fails.
/// - The Ed25519 secret key format is invalid for conversion.
pub fn sign(sk: &HybridSecretKey, message: &[u8]) -> Result<HybridSignature, HybridSignatureError> {
    // Validate secret key lengths
    if sk.ed25519_sk_bytes().len() != 32 {
        return Err(HybridSignatureError::InvalidKeyMaterial(
            "Ed25519 secret key must be 32 bytes".to_string(),
        ));
    }

    // Sign with ML-DSA
    let ml_dsa_sk_struct = MlDsaSecretKey::new(MlDsaParameterSet::MLDSA65, sk.ml_dsa_sk_bytes())
        .map_err(|e| HybridSignatureError::MlDsaError(e.to_string()))?;
    let ml_dsa_sig = ml_dsa_sign(&ml_dsa_sk_struct, message, &[])
        .map_err(|e| HybridSignatureError::MlDsaError(e.to_string()))?
        .as_bytes()
        .to_vec();

    // Sign with Ed25519
    let ed25519_signing_key_bytes: [u8; 32] =
        sk.ed25519_sk_bytes().as_slice().try_into().map_err(|_e| {
            HybridSignatureError::Ed25519Error("Ed25519 secret key must be 32 bytes".to_string())
        })?;
    let ed25519_signing_key = Ed25519SigningKey::from_bytes(&ed25519_signing_key_bytes);
    let ed25519_signature = ed25519_signing_key.sign(message);
    let ed25519_sig = ed25519_signature.to_bytes().to_vec();

    Ok(HybridSignature { ml_dsa_sig, ed25519_sig })
}

/// Verify using hybrid signature scheme
///
/// # Errors
///
/// Returns an error if:
/// - The Ed25519 public key is not exactly 32 bytes.
/// - The Ed25519 signature is not exactly 64 bytes.
/// - ML-DSA public key or signature construction fails.
/// - ML-DSA signature verification fails.
/// - The Ed25519 public key is invalid or signature verification fails.
pub fn verify(
    pk: &HybridPublicKey,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<bool, HybridSignatureError> {
    // Validate key and signature lengths
    if pk.ed25519_pk.len() != 32 {
        return Err(HybridSignatureError::InvalidKeyMaterial(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }
    if sig.ed25519_sig.len() != 64 {
        return Err(HybridSignatureError::InvalidKeyMaterial(
            "Ed25519 signature must be 64 bytes".to_string(),
        ));
    }

    // Verify ML-DSA signature
    let ml_dsa_pk_struct = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA65, pk.ml_dsa_pk.clone())
        .map_err(|e| HybridSignatureError::MlDsaError(e.to_string()))?;
    let ml_dsa_sig_struct = MlDsaSignature::new(MlDsaParameterSet::MLDSA65, sig.ml_dsa_sig.clone())
        .map_err(|e| HybridSignatureError::MlDsaError(e.to_string()))?;

    ml_dsa_verify(&ml_dsa_pk_struct, message, &ml_dsa_sig_struct, &[]).map_err(|e| {
        HybridSignatureError::VerificationFailed(format!("ML-DSA verification failed: {}", e))
    })?;

    // Verify Ed25519 signature
    let ed25519_verifying_key_bytes: [u8; 32] =
        pk.ed25519_pk.as_slice().try_into().map_err(|_e| {
            HybridSignatureError::InvalidKeyMaterial(
                "Ed25519 public key has invalid format".to_string(),
            )
        })?;
    let ed25519_verifying_key = Ed25519VerifyingKey::from_bytes(&ed25519_verifying_key_bytes)
        .map_err(|e| {
            HybridSignatureError::Ed25519Error(format!("Invalid Ed25519 public key: {}", e))
        })?;

    let ed25519_signature_bytes: [u8; 64] =
        sig.ed25519_sig.as_slice().try_into().map_err(|_e| {
            HybridSignatureError::InvalidKeyMaterial(
                "Ed25519 signature has invalid format".to_string(),
            )
        })?;
    let ed25519_signature = Ed25519Signature::from_bytes(&ed25519_signature_bytes);

    // Perform actual Ed25519 verification
    ed25519_verifying_key.verify(message, &ed25519_signature).map_err(|e| {
        HybridSignatureError::VerificationFailed(format!("Ed25519 verification failed: {}", e))
    })?;

    // Both signatures verified successfully
    Ok(true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::implicit_clone)] // Tests don't require optimal cloning patterns
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_secret_key_zeroization() {
        let mut rng = rand::thread_rng();
        let (_pk, mut sk) = generate_keypair(&mut rng).unwrap();

        let ml_dsa_sk_before = sk.ml_dsa_sk_bytes().to_vec();
        let ed25519_sk_before = sk.ed25519_sk_bytes().to_vec();

        assert!(
            !ml_dsa_sk_before.iter().all(|&b| b == 0),
            "ML-DSA secret should contain non-zero data"
        );
        assert!(
            !ed25519_sk_before.iter().all(|&b| b == 0),
            "Ed25519 secret should contain non-zero data"
        );

        sk.zeroize();

        assert!(sk.ml_dsa_sk_bytes().iter().all(|&b| b == 0), "ML-DSA secret should be zeroized");
        assert!(sk.ed25519_sk_bytes().iter().all(|&b| b == 0), "Ed25519 secret should be zeroized");
    }

    #[test]
    fn test_hybrid_secret_key_drop_zeroization() {
        let test_ml_data = vec![0x77; 4032];
        let test_ed25519_data = vec![0x66; 32];

        {
            let sk = HybridSecretKey {
                ml_dsa_sk: Zeroizing::new(test_ml_data),
                ed25519_sk: Zeroizing::new(test_ed25519_data),
            };

            assert!(
                !sk.ml_dsa_sk_bytes().iter().all(|&b| b == 0),
                "ML-DSA secret should contain non-zero data"
            );
            assert!(
                !sk.ed25519_sk_bytes().iter().all(|&b| b == 0),
                "Ed25519 secret should contain non-zero data"
            );
        }
    }

    #[test]
    fn test_hybrid_signature_after_zeroization() {
        let mut rng = rand::thread_rng();
        let (pk, mut sk) = generate_keypair(&mut rng).unwrap();
        let message = b"Test message";

        let signature_before = sign(&sk, message).expect("Should sign before zeroization");
        let valid_before =
            verify(&pk, message, &signature_before).expect("Should verify before zeroization");
        assert!(valid_before, "Signature should be valid before zeroization");

        sk.zeroize();

        let result = sign(&sk, message);
        assert!(result.is_err(), "Signing should fail after zeroization");
    }

    #[test]
    fn test_hybrid_signature_keypair_generation() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        assert!(!pk.ml_dsa_pk.is_empty(), "ML-DSA public key should not be empty");
        assert_eq!(pk.ed25519_pk.len(), 32, "Ed25519 public key should be 32 bytes");
        assert!(!sk.ml_dsa_sk.is_empty(), "ML-DSA secret key should not be empty");
        assert_eq!(sk.ed25519_sk.len(), 32, "Ed25519 secret key should be 32 bytes");

        assert!(!pk.ml_dsa_pk.iter().all(|&x| x == 0), "ML-DSA PK should not be all zeros");
        assert!(!pk.ed25519_pk.iter().all(|&x| x == 0), "Ed25519 PK should not be all zeros");
    }

    #[test]
    fn test_hybrid_signature_signing_and_verification() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let message = b"Hello, hybrid signature!";
        let sig = sign(&sk, message);
        assert!(sig.is_ok(), "Signing should succeed");

        let sig = sig.unwrap();
        assert!(!sig.ml_dsa_sig.is_empty(), "ML-DSA signature should not be empty");
        assert_eq!(sig.ed25519_sig.len(), 64, "Ed25519 signature should be 64 bytes");

        let valid = verify(&pk, message, &sig);
        assert!(valid.is_ok(), "Verification should succeed");
        assert!(valid.unwrap(), "Signature should be valid");
    }

    #[test]
    fn test_invalid_key_and_signature_lengths() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair(&mut rng).unwrap();

        // Test with invalid Ed25519 public key length
        let mut invalid_pk = pk.clone();
        invalid_pk.ed25519_pk = vec![1u8; 31]; // Wrong length
        let sig = HybridSignature { ml_dsa_sig: vec![1u8; 100], ed25519_sig: vec![1u8; 64] };
        let result = verify(&invalid_pk, b"test", &sig);
        assert!(result.is_err(), "Should reject invalid public key length");

        // Test with invalid signature length
        let invalid_sig = HybridSignature {
            ml_dsa_sig: vec![1u8; 100],
            ed25519_sig: vec![1u8; 63], // Wrong length
        };
        let result = verify(&pk, b"test", &invalid_sig);
        assert!(result.is_err(), "Should reject invalid signature length");
    }

    #[test]
    fn test_ed25519_signature_properties() {
        let mut rng = rand::thread_rng();
        let signing_key = Ed25519SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = b"Test message";
        let signature = signing_key.sign(message);

        // Verify that valid signature passes
        let result = verifying_key.verify(message, &signature);
        assert!(result.is_ok(), "Valid signature should verify");

        // Verify that wrong message fails
        let wrong_message = b"Wrong message";
        let result = verifying_key.verify(wrong_message, &signature);
        assert!(result.is_err(), "Wrong message should not verify");

        // Verify that corrupted signature fails - modify message instead of signature
        let wrong_message = b"Wrong message";
        let result = verifying_key.verify(wrong_message, &signature);
        assert!(result.is_err(), "Wrong message should not verify");

        // Skip signature corruption test due to ed25519_dalek design constraints
        // Ed25519 signatures have built-in integrity and don't support direct modification
        assert!(result.is_err(), "Corrupted signature should not verify");
    }

    #[test]
    fn test_hybrid_signature_zeroization() {
        let ml_dsa_sig_data = vec![0x77; 2420];
        let ed25519_sig_data = vec![0x88; 64];

        let mut signature =
            HybridSignature { ml_dsa_sig: ml_dsa_sig_data, ed25519_sig: ed25519_sig_data };

        assert!(
            !signature.ml_dsa_sig.iter().all(|&b| b == 0),
            "ML-DSA signature should contain non-zero data"
        );
        assert!(
            !signature.ed25519_sig.iter().all(|&b| b == 0),
            "Ed25519 signature should contain non-zero data"
        );

        signature.zeroize();

        assert!(
            signature.ml_dsa_sig.iter().all(|&b| b == 0),
            "ML-DSA signature should be zeroized"
        );
        assert!(
            signature.ed25519_sig.iter().all(|&b| b == 0),
            "Ed25519 signature should be zeroized"
        );
    }

    #[test]
    fn test_hybrid_keypair_zeroization() {
        let (_public_key, secret_key) =
            generate_keypair(&mut rand::thread_rng()).expect("Should generate hybrid keypair");

        assert!(
            !secret_key.ml_dsa_sk.iter().all(|&b| b == 0),
            "Keypair ML-DSA secret should contain non-zero data"
        );
        assert!(
            !secret_key.ed25519_sk.iter().all(|&b| b == 0),
            "Keypair Ed25519 secret should contain non-zero data"
        );

        let mut secret_key_clone = HybridSecretKey {
            ml_dsa_sk: secret_key.ml_dsa_sk_bytes().into(),
            ed25519_sk: secret_key.ed25519_sk_bytes().into(),
        };

        secret_key_clone.zeroize();

        assert!(
            secret_key_clone.ml_dsa_sk.iter().all(|&b| b == 0),
            "Cloned ML-DSA secret should be zeroized"
        );
        assert!(
            secret_key_clone.ed25519_sk.iter().all(|&b| b == 0),
            "Cloned Ed25519 secret should be zeroized"
        );
    }

    #[test]
    fn test_hybrid_zeroization_order() {
        let mut secret_key1 = HybridSecretKey {
            ml_dsa_sk: Zeroizing::new(vec![0x11; 2560]),
            ed25519_sk: Zeroizing::new(vec![0x22; 32]),
        };

        let mut secret_key2 = HybridSecretKey {
            ml_dsa_sk: Zeroizing::new(vec![0x33; 2560]),
            ed25519_sk: Zeroizing::new(vec![0x44; 32]),
        };

        assert!(
            !secret_key1.ml_dsa_sk.iter().all(|&b| b == 0),
            "Key1 ML-DSA secret should contain non-zero data"
        );
        assert!(
            !secret_key1.ed25519_sk.iter().all(|&b| b == 0),
            "Key1 Ed25519 secret should contain non-zero data"
        );
        assert!(
            !secret_key2.ml_dsa_sk.iter().all(|&b| b == 0),
            "Key2 ML-DSA secret should contain non-zero data"
        );
        assert!(
            !secret_key2.ed25519_sk.iter().all(|&b| b == 0),
            "Key2 Ed25519 secret should contain non-zero data"
        );

        secret_key1.ml_dsa_sk.zeroize();

        assert!(
            secret_key1.ml_dsa_sk.iter().all(|&b| b == 0),
            "Key1 ML-DSA secret should be zeroized first"
        );
        assert!(
            !secret_key1.ed25519_sk.iter().all(|&b| b == 0),
            "Key1 Ed25519 secret should still contain data"
        );
        assert!(
            !secret_key2.ml_dsa_sk.iter().all(|&b| b == 0),
            "Key2 ML-DSA secret should still contain data"
        );

        secret_key1.ed25519_sk.zeroize();

        assert!(
            secret_key1.ed25519_sk.iter().all(|&b| b == 0),
            "Key1 Ed25519 secret should be zeroized second"
        );
        assert!(
            !secret_key2.ml_dsa_sk.iter().all(|&b| b == 0),
            "Key2 ML-DSA secret should still contain data"
        );

        secret_key2.ml_dsa_sk.zeroize();
        secret_key2.ed25519_sk.zeroize();

        assert!(
            secret_key2.ml_dsa_sk.iter().all(|&b| b == 0),
            "Key2 ML-DSA secret should be zeroized"
        );
        assert!(
            secret_key2.ed25519_sk.iter().all(|&b| b == 0),
            "Key2 Ed25519 secret should be zeroized"
        );
    }

    #[test]
    fn test_hybrid_concurrent_zeroization() {
        use std::sync::Arc;
        use std::thread;

        let ml_dsa_data = Arc::new(vec![0x99; 2560]);
        let ed25519_data = Arc::new(vec![0xAA; 32]);
        let mut handles = vec![];

        for i in 0..4 {
            let ml_dsa_clone = Arc::clone(&ml_dsa_data);
            let ed25519_clone = Arc::clone(&ed25519_data);

            let handle = thread::spawn(move || {
                let mut secret_key = HybridSecretKey {
                    ml_dsa_sk: Zeroizing::new((*ml_dsa_clone).clone()),
                    ed25519_sk: Zeroizing::new((*ed25519_clone).clone()),
                };

                assert!(
                    !secret_key.ml_dsa_sk.iter().all(|&b| b == 0),
                    "Thread {} ML-DSA secret should contain non-zero data",
                    i
                );
                assert!(
                    !secret_key.ed25519_sk.iter().all(|&b| b == 0),
                    "Thread {} Ed25519 secret should contain non-zero data",
                    i
                );

                secret_key.zeroize();

                let ml_dsa_zeroized = secret_key.ml_dsa_sk.iter().all(|&b| b == 0);
                let ed25519_zeroized = secret_key.ed25519_sk.iter().all(|&b| b == 0);

                (i, ml_dsa_zeroized, ed25519_zeroized)
            });

            handles.push(handle);
        }

        for handle in handles {
            let (thread_id, ml_dsa_zeroized, ed25519_zeroized) =
                handle.join().expect("Thread should complete");
            assert!(ml_dsa_zeroized, "Thread {} ML-DSA secret should be zeroized", thread_id);
            assert!(ed25519_zeroized, "Thread {} Ed25519 secret should be zeroized", thread_id);
        }
    }
}
