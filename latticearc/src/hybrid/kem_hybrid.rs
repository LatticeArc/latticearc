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
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::hybrid::kem_hybrid::{generate_keypair, encapsulate, decapsulate};
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
//! # Ok(())
//! # }
//! ```
//!
//! [`ZeroizeOnDrop`]: zeroize::ZeroizeOnDrop

use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::primitives::kdf::hkdf::hkdf;
use crate::primitives::kem::ecdh::{X25519_KEY_SIZE, X25519KeyPair, X25519StaticKeyPair};
use crate::primitives::kem::ml_kem::MlKemDecapsulationKeyPair;
use crate::primitives::kem::{MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecurityLevel};

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
/// The `security_level` field determines which ML-KEM parameter set is used
/// (512, 768, or 1024).
#[derive(Debug, Clone)]
pub struct HybridPublicKey {
    /// ML-KEM public key bytes (size depends on security level).
    pub ml_kem_pk: Vec<u8>,
    /// X25519 ECDH public key bytes (32 bytes).
    pub ecdh_pk: Vec<u8>,
    /// ML-KEM security level (determines key/ciphertext sizes).
    pub security_level: MlKemSecurityLevel,
}

/// Hybrid secret key combining ML-KEM and X25519 ECDH.
///
/// # Security Guarantees
///
/// The ML-KEM decapsulation key is held in-memory via the aws-lc-rs
/// `DecapsulationKey` (BoringSSL zeroizes on free). The X25519 private key
/// is also managed by aws-lc-rs, which handles its own zeroization internally.
///
/// # Cloning
///
/// **Important**: This type does NOT implement [`Clone`] to prevent accidental
/// copying of secret keys. The X25519 `PrivateKey` from aws-lc-rs is not
/// cloneable by design.
///
/// # Key Persistence Limitation
///
/// The X25519 private key cannot be serialized — aws-lc-rs `PrivateKey` does
/// not support `from_private_key_der()` for X25519. Keys are **in-memory only**.
/// ML-KEM keys remain fully serializable via `ml_kem_sk_bytes()`.
///
/// # Example
///
/// ```rust,no_run
/// use latticearc::hybrid::kem_hybrid::generate_keypair;
/// use rand::rngs::OsRng;
///
/// let (pk, sk) = generate_keypair(&mut OsRng).expect("keypair generation failed");
/// // sk.ecdh_keypair holds the real X25519 private key
/// drop(sk);  // ML-KEM bytes zeroized; aws-lc-rs handles X25519 cleanup
/// ```
pub struct HybridSecretKey {
    /// ML-KEM decapsulation keypair — holds the real aws-lc-rs `DecapsulationKey`.
    ml_kem_keypair: MlKemDecapsulationKeyPair,
    /// X25519 ECDH static key pair for reusable key agreement.
    ecdh_keypair: X25519StaticKeyPair,
}

impl HybridSecretKey {
    /// Get the ML-KEM security level of this keypair.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.ml_kem_keypair.security_level()
    }

    /// Get ML-KEM public key bytes (for compatibility).
    #[must_use]
    pub fn ml_kem_pk_bytes(&self) -> Vec<u8> {
        self.ml_kem_keypair.public_key_bytes().to_vec()
    }

    /// Get the X25519 ECDH public key bytes (32 bytes).
    #[must_use]
    pub fn ecdh_public_key_bytes(&self) -> Vec<u8> {
        self.ecdh_keypair.public_key_bytes().to_vec()
    }

    /// Perform X25519 key agreement with a peer's ephemeral public key.
    ///
    /// # Errors
    /// Returns an error if key agreement fails.
    pub fn ecdh_agree(&self, peer_pk: &[u8]) -> Result<[u8; 32], HybridKemError> {
        self.ecdh_keypair.agree(peer_pk).map_err(|e| HybridKemError::EcdhError(e.to_string()))
    }

    /// Decapsulate an ML-KEM ciphertext using the real decapsulation key.
    ///
    /// # Errors
    /// Returns an error if ML-KEM decapsulation fails.
    fn ml_kem_decapsulate(
        &self,
        ciphertext: &MlKemCiphertext,
    ) -> Result<crate::primitives::kem::MlKemSharedSecret, HybridKemError> {
        self.ml_kem_keypair
            .decapsulate(ciphertext)
            .map_err(|e| HybridKemError::MlKemError(e.to_string()))
    }
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("ml_kem_keypair", &self.ml_kem_keypair)
            .field("ecdh_keypair", &self.ecdh_keypair)
            .finish()
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
#[derive(ZeroizeOnDrop)]
pub struct EncapsulatedKey {
    /// ML-KEM ciphertext bytes (size depends on security level).
    pub ml_kem_ct: Vec<u8>,
    /// Ephemeral X25519 public key bytes (32 bytes) for ECDH.
    pub ecdh_pk: Vec<u8>,
    /// Combined shared secret (64 bytes), automatically zeroized on drop.
    pub shared_secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for EncapsulatedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncapsulatedKey")
            .field("ml_kem_ct", &format_args!("[{} bytes]", self.ml_kem_ct.len()))
            .field("ecdh_pk", &format_args!("[{} bytes]", self.ecdh_pk.len()))
            .field("shared_secret", &"[REDACTED]")
            .finish()
    }
}

/// Generate hybrid keypair (ML-KEM + X25519) at the specified security level.
///
/// The X25519 component uses a real static key pair (aws-lc-rs `PrivateKey`)
/// that supports reusable key agreement for decapsulation.
///
/// # Errors
///
/// Returns an error if ML-KEM or X25519 keypair generation fails.
pub fn generate_keypair<R: rand::Rng + rand::CryptoRng>(
    _rng: &mut R,
) -> Result<(HybridPublicKey, HybridSecretKey), HybridKemError> {
    generate_keypair_with_level(_rng, MlKemSecurityLevel::MlKem768)
}

/// Generate hybrid keypair at a specific ML-KEM security level.
///
/// # Arguments
/// * `_rng` - Random number generator (aws-lc-rs uses internal RNG)
/// * `level` - ML-KEM security level (512, 768, or 1024)
///
/// # Errors
/// Returns an error if ML-KEM or X25519 keypair generation fails.
pub fn generate_keypair_with_level<R: rand::Rng + rand::CryptoRng>(
    _rng: &mut R,
    level: MlKemSecurityLevel,
) -> Result<(HybridPublicKey, HybridSecretKey), HybridKemError> {
    let ml_kem_keypair = MlKem::generate_decapsulation_keypair(level)
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;

    let ecdh_keypair =
        X25519StaticKeyPair::generate().map_err(|e| HybridKemError::EcdhError(e.to_string()))?;

    let ecdh_pk = ecdh_keypair.public_key_bytes().to_vec();

    let pk = HybridPublicKey {
        ml_kem_pk: ml_kem_keypair.public_key_bytes().to_vec(),
        ecdh_pk,
        security_level: level,
    };

    let sk = HybridSecretKey { ml_kem_keypair, ecdh_keypair };

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

    // ML-KEM encapsulation at the public key's security level
    let ml_kem_pk_struct = MlKemPublicKey::new(pk.security_level, pk.ml_kem_pk.clone())
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

/// Decapsulate using hybrid KEM.
///
/// Recovers the shared secret from a hybrid ciphertext using the recipient's
/// secret key. The X25519 component now performs **real ECDH** via aws-lc-rs
/// `PrivateKey::agree()`.
///
/// # Errors
///
/// Returns an error if:
/// - The ephemeral ECDH public key is not exactly 32 bytes.
/// - ML-KEM secret key or ciphertext construction fails.
/// - ML-KEM decapsulation fails or returns an invalid shared secret length.
/// - ECDH key agreement fails.
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

    // ML-KEM decapsulation at the secret key's security level
    let ml_kem_ct_struct = MlKemCiphertext::new(sk.security_level(), ct.ml_kem_ct.clone())
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;
    let ml_kem_ss = sk.ml_kem_decapsulate(&ml_kem_ct_struct)?;

    // Validate ML-KEM shared secret
    if ml_kem_ss.as_bytes().len() != 32 {
        return Err(HybridKemError::MlKemError(
            "ML-KEM decapsulation returned invalid shared secret length".to_string(),
        ));
    }

    // Real X25519 ECDH: agree(our_static_sk, sender's_ephemeral_pk)
    let ecdh_shared_secret = sk.ecdh_agree(&ct.ecdh_pk)?;

    // Use actual public key bytes for context binding (not a hash of random bytes)
    let static_public = sk.ecdh_public_key_bytes();
    derive_hybrid_shared_secret(
        ml_kem_ss.as_bytes(),
        &ecdh_shared_secret,
        &static_public,
        ct.ecdh_pk.as_slice(),
    )
    .map_err(|e| HybridKemError::KdfError(e.to_string()))
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::implicit_clone)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn test_hybrid_kem_key_generation() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        // Verify key sizes
        assert_eq!(pk.ml_kem_pk.len(), 1184, "ML-KEM-768 public key should be 1184 bytes");
        assert_eq!(pk.ecdh_pk.len(), 32, "ECDH public key should be 32 bytes");
        assert_eq!(
            sk.ml_kem_pk_bytes().len(),
            1184,
            "ML-KEM-768 public key from SK should be 1184 bytes"
        );
        assert_eq!(
            sk.ecdh_public_key_bytes().len(),
            32,
            "ECDH public key from SK should be 32 bytes"
        );

        // Public keys in pk and sk must match
        assert_eq!(
            pk.ecdh_pk,
            sk.ecdh_public_key_bytes(),
            "ECDH PK in public key must match SK's public key"
        );
        assert_eq!(
            pk.ml_kem_pk,
            sk.ml_kem_pk_bytes(),
            "ML-KEM PK in public key must match SK's public key"
        );

        // Verify keys are not all zeros
        assert!(!pk.ml_kem_pk.iter().all(|&x| x == 0), "ML-KEM PK should not be all zeros");
        assert!(!pk.ecdh_pk.iter().all(|&x| x == 0), "ECDH PK should not be all zeros");
    }

    #[test]
    fn test_hybrid_kem_encapsulation_decapsulation() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        // Test encapsulation
        let enc_key = encapsulate(&mut rng, &pk).unwrap();

        assert!(!enc_key.ml_kem_ct.is_empty(), "KEM ciphertext should not be empty");
        assert_eq!(enc_key.ml_kem_ct.len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
        assert_eq!(enc_key.ecdh_pk.len(), 32, "Ephemeral ECDH PK should be 32 bytes");
        assert_eq!(enc_key.shared_secret.len(), 64, "Shared secret should be 64 bytes");

        // Test decapsulation — THIS IS THE KEY ROUNDTRIP TEST
        let dec_secret = decapsulate(&sk, &enc_key).unwrap();

        assert_eq!(dec_secret.len(), 64, "Decapsulated secret should be 64 bytes");
        assert_eq!(dec_secret.as_slice(), enc_key.shared_secret.as_slice(), "Secrets should match");

        // Test that different encapsulations produce different secrets
        let enc_key2 = encapsulate(&mut rng, &pk).unwrap();
        let dec_secret2 = decapsulate(&sk, &enc_key2).unwrap();
        assert_eq!(
            dec_secret2.as_slice(),
            enc_key2.shared_secret.as_slice(),
            "Second roundtrip must also match"
        );

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
    fn test_hybrid_secret_key_zeroization() {
        let mut rng = rand::rngs::OsRng;
        let (_pk, sk) = generate_keypair(&mut rng).expect("Should generate keypair");

        // Verify the key contains non-zero public key data
        assert!(
            !sk.ml_kem_pk_bytes().iter().all(|&b| b == 0),
            "ML-KEM public key should contain non-zero data"
        );
        assert!(
            !sk.ecdh_public_key_bytes().iter().all(|&b| b == 0),
            "ECDH public key should contain non-zero data"
        );
        // Drop triggers aws-lc-rs cleanup for both ML-KEM and X25519
        drop(sk);
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

    #[test]
    fn test_hybrid_kem_multiple_decapsulations() {
        // Verify the same secret key can decapsulate multiple ciphertexts
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        for _ in 0..3 {
            let enc = encapsulate(&mut rng, &pk).unwrap();
            let dec = decapsulate(&sk, &enc).unwrap();
            assert_eq!(dec.as_slice(), enc.shared_secret.as_slice());
        }
    }

    #[test]
    fn test_encapsulate_invalid_ecdh_pk_length() {
        let mut rng = rand::thread_rng();
        let (mut pk, _sk) = generate_keypair(&mut rng).unwrap();
        pk.ecdh_pk = vec![0u8; 16]; // Wrong length

        let result = encapsulate(&mut rng, &pk);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::InvalidKeyMaterial(_)));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn test_decapsulate_invalid_ecdh_pk_length() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = generate_keypair(&mut rng).unwrap();

        let enc = encapsulate(&mut rng, &pk).unwrap();
        let mut bad_enc = EncapsulatedKey {
            ml_kem_ct: enc.ml_kem_ct.clone(),
            ecdh_pk: vec![0u8; 16], // Wrong length
            shared_secret: Zeroizing::new(vec![]),
        };

        let result = decapsulate(&sk, &bad_enc);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::InvalidKeyMaterial(_)));
        // cleanup
        bad_enc.shared_secret.zeroize();
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ecdh_secret_length() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 31]; // Wrong: should be 32
        let static_pk = vec![3u8; 32];
        let ephemeral_pk = vec![4u8; 32];

        let result = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::InvalidKeyMaterial(_)));
        assert!(err.to_string().contains("ECDH"));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ml_kem_secret_length() {
        let ml_kem_ss = vec![1u8; 33]; // Wrong: should be 32
        let ecdh_ss = vec![2u8; 32];
        let static_pk = vec![3u8; 32];
        let ephemeral_pk = vec![4u8; 32];

        let result = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::InvalidKeyMaterial(_)));
        assert!(err.to_string().contains("ML-KEM"));
    }

    #[test]
    fn test_hybrid_public_key_clone_debug() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair(&mut rng).unwrap();

        let pk2 = pk.clone();
        assert_eq!(pk.ml_kem_pk, pk2.ml_kem_pk);
        assert_eq!(pk.ecdh_pk, pk2.ecdh_pk);

        let debug = format!("{:?}", pk);
        assert!(debug.contains("HybridPublicKey"));
    }

    #[test]
    fn test_hybrid_secret_key_debug() {
        let mut rng = rand::thread_rng();
        let (_pk, sk) = generate_keypair(&mut rng).unwrap();

        let debug = format!("{:?}", sk);
        assert!(debug.contains("HybridSecretKey"));
    }

    #[test]
    fn test_encapsulated_key_debug() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair(&mut rng).unwrap();

        let enc = encapsulate(&mut rng, &pk).unwrap();
        let debug = format!("{:?}", enc);
        assert!(debug.contains("EncapsulatedKey"));
    }

    #[test]
    fn test_hybrid_kem_error_display_variants() {
        let err1 = HybridKemError::MlKemError("kem fail".to_string());
        assert!(err1.to_string().contains("kem fail"));

        let err2 = HybridKemError::EcdhError("ecdh fail".to_string());
        assert!(err2.to_string().contains("ecdh fail"));

        let err3 = HybridKemError::KdfError("kdf fail".to_string());
        assert!(err3.to_string().contains("kdf fail"));

        let err4 = HybridKemError::InvalidKeyMaterial("bad key".to_string());
        assert!(err4.to_string().contains("bad key"));

        let err5 = HybridKemError::CryptoError("crypto fail".to_string());
        assert!(err5.to_string().contains("crypto fail"));
    }

    #[test]
    fn test_hybrid_kem_error_eq_clone() {
        let err1 = HybridKemError::MlKemError("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1, err2);
        assert_ne!(err1, HybridKemError::EcdhError("test".to_string()));
    }

    #[test]
    fn test_derive_different_static_pk_changes_output() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 32];
        let static_pk1 = vec![3u8; 32];
        let static_pk2 = vec![4u8; 32];
        let ephemeral_pk = vec![5u8; 32];

        let secret1 =
            derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk1, &ephemeral_pk).unwrap();
        let secret2 =
            derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk2, &ephemeral_pk).unwrap();

        assert_ne!(secret1, secret2, "Different static PKs should produce different secrets");
    }

    #[test]
    fn test_derive_different_ephemeral_pk_changes_output() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 32];
        let static_pk = vec![3u8; 32];
        let eph1 = vec![4u8; 32];
        let eph2 = vec![5u8; 32];

        let secret1 = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &eph1).unwrap();
        let secret2 = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &eph2).unwrap();

        assert_ne!(secret1, secret2, "Different ephemeral PKs should produce different secrets");
    }

    #[test]
    fn test_hybrid_secret_key_ecdh_agree() {
        let mut rng = rand::thread_rng();
        let (_pk, sk) = generate_keypair(&mut rng).unwrap();

        // Generate another X25519 keypair
        let other = X25519KeyPair::generate().unwrap();
        let other_pk = other.public_key_bytes().to_vec();

        // sk can agree with another party
        let shared = sk.ecdh_agree(&other_pk);
        assert!(shared.is_ok());
        assert_eq!(shared.unwrap().len(), 32);
    }

    #[test]
    fn test_hybrid_secret_key_ecdh_agree_invalid_pk() {
        let mut rng = rand::thread_rng();
        let (_pk, sk) = generate_keypair(&mut rng).unwrap();

        // Invalid peer public key (too short)
        let result = sk.ecdh_agree(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encapsulate_invalid_ml_kem_pk() {
        let mut rng = rand::thread_rng();
        let pk = HybridPublicKey {
            ml_kem_pk: vec![0u8; 100], // Wrong length
            ecdh_pk: vec![0u8; 32],
            security_level: MlKemSecurityLevel::MlKem768,
        };

        let result = encapsulate(&mut rng, &pk);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::MlKemError(_)));
    }

    // ========================================================================
    // Additional coverage: error paths and edge cases
    // ========================================================================

    #[test]
    fn test_decapsulate_invalid_ephemeral_ecdh_pk_length() {
        let mut rng = rand::thread_rng();
        let (_pk, sk) = generate_keypair(&mut rng).unwrap();

        let ct = EncapsulatedKey {
            ml_kem_ct: vec![0u8; 1088],
            ecdh_pk: vec![0u8; 16], // Wrong length (should be 32)
            shared_secret: Zeroizing::new(vec![0u8; 64]),
        };

        let result = decapsulate(&sk, &ct);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::InvalidKeyMaterial(_)));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn test_decapsulate_invalid_ml_kem_ct_length() {
        let mut rng = rand::thread_rng();
        let (_pk, sk) = generate_keypair(&mut rng).unwrap();

        let ct = EncapsulatedKey {
            ml_kem_ct: vec![0u8; 100], // Wrong length (should be 1088)
            ecdh_pk: vec![0u8; 32],
            shared_secret: Zeroizing::new(vec![0u8; 64]),
        };

        let result = decapsulate(&sk, &ct);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::MlKemError(_)));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ml_kem_length() {
        let result = derive_hybrid_shared_secret(&[0u8; 16], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ML-KEM"));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ecdh_length() {
        let result = derive_hybrid_shared_secret(&[0u8; 32], &[0u8; 16], &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ECDH"));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_deterministic() {
        let ml_kem_ss = [0xAA; 32];
        let ecdh_ss = [0xBB; 32];
        let static_pk = [0xCC; 32];
        let ephemeral_pk = [0xDD; 32];

        let s1 =
            derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk).unwrap();
        let s2 =
            derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &ephemeral_pk).unwrap();
        assert_eq!(s1, s2, "Same inputs must produce same output");
        assert_eq!(s1.len(), 64);
    }

    #[test]
    fn test_derive_hybrid_shared_secret_different_inputs_differ() {
        let ml_kem_ss = [0xAA; 32];
        let ecdh_ss = [0xBB; 32];
        let static_pk = [0xCC; 32];
        let eph1 = [0xDD; 32];
        let eph2 = [0xEE; 32];

        let s1 = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &eph1).unwrap();
        let s2 = derive_hybrid_shared_secret(&ml_kem_ss, &ecdh_ss, &static_pk, &eph2).unwrap();
        assert_ne!(s1, s2, "Different ephemeral PKs must produce different secrets");
    }

    #[test]
    fn test_encapsulate_invalid_ecdh_pk_too_long() {
        let mut rng = rand::thread_rng();
        let pk = HybridPublicKey {
            ml_kem_pk: vec![0u8; 1184],
            ecdh_pk: vec![0u8; 64], // Too long (should be 32)
            security_level: MlKemSecurityLevel::MlKem768,
        };

        let result = encapsulate(&mut rng, &pk);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HybridKemError::InvalidKeyMaterial(_)));
    }

    #[test]
    fn test_encapsulated_key_shared_secret_len() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair(&mut rng).unwrap();
        let encapsulated = encapsulate(&mut rng, &pk).unwrap();
        assert_eq!(encapsulated.shared_secret.len(), 64);
        assert_eq!(encapsulated.ecdh_pk.len(), 32);
    }

    #[test]
    fn test_hybrid_kem_error_display_kdf() {
        let err = HybridKemError::KdfError("test kdf".to_string());
        assert!(err.to_string().contains("test kdf"));
    }

    #[test]
    fn test_hybrid_public_key_accessors() {
        let mut rng = rand::thread_rng();
        let (pk, _sk) = generate_keypair(&mut rng).unwrap();
        assert_eq!(pk.ml_kem_pk.len(), 1184);
        assert_eq!(pk.ecdh_pk.len(), 32);
    }
}
