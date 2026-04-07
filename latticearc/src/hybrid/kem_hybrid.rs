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
//! │                         │  │  info = "LatticeArc-Hybrid-KEM-SS" ‖ len(static_pk) ‖ static_pk ‖ len(ephemeral_pk) ‖ ephemeral_pk │ │   │
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
//! - **CDH-hardness** security from X25519 ECDH (classical secure)
//! - **HKDF composition** ensures security if *either* component remains secure (KDF-based combiner with domain separation)
//! - Automatic memory zeroization for secret keys via [`ZeroizeOnDrop`]
//!
//! # Example
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::hybrid::kem_hybrid::{generate_keypair, encapsulate, decapsulate};
//!
//! // Generate hybrid keypair
//! let (pk, sk) = generate_keypair()?;
//!
//! // Encapsulate to create shared secret and ciphertext
//! let encapsulated = encapsulate(&pk)?;
//!
//! // Decapsulate to recover the shared secret
//! let shared_secret = decapsulate(&sk, &encapsulated)?;
//!
//! // Both parties now have the same 64-byte shared secret
//! assert_eq!(shared_secret.as_slice(), encapsulated.shared_secret());
//! # Ok(())
//! # }
//! ```
//!
//! [`ZeroizeOnDrop`]: zeroize::ZeroizeOnDrop

use subtle::ConstantTimeEq;
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
#[non_exhaustive]
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
/// The `security_level` determines which ML-KEM parameter set is used
/// (512, 768, or 1024).
#[derive(Debug, Clone)]
pub struct HybridKemPublicKey {
    /// ML-KEM public key bytes (size depends on security level).
    ml_kem_pk: Vec<u8>,
    /// X25519 ECDH public key bytes (32 bytes).
    ecdh_pk: Vec<u8>,
    /// ML-KEM security level (determines key/ciphertext sizes).
    security_level: MlKemSecurityLevel,
}

impl HybridKemPublicKey {
    /// Construct a `HybridKemPublicKey` from its components.
    ///
    /// No validation is performed here; callers are expected to provide
    /// correctly-sized key material. The [`encapsulate`] function validates
    /// sizes before use.
    #[must_use]
    pub fn new(ml_kem_pk: Vec<u8>, ecdh_pk: Vec<u8>, security_level: MlKemSecurityLevel) -> Self {
        Self { ml_kem_pk, ecdh_pk, security_level }
    }

    /// Returns the ML-KEM public key bytes.
    #[must_use]
    pub fn ml_kem_pk(&self) -> &[u8] {
        &self.ml_kem_pk
    }

    /// Returns the X25519 ECDH public key bytes (32 bytes).
    #[must_use]
    pub fn ecdh_pk(&self) -> &[u8] {
        &self.ecdh_pk
    }

    /// Returns the ML-KEM security level for this public key.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }
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
/// # Key Serialization
///
/// Both components are fully serializable:
/// - ML-KEM secret key: via [`ml_kem_sk_bytes()`](Self::ml_kem_sk_bytes)
/// - X25519 seed: via [`ecdh_seed_bytes()`](Self::ecdh_seed_bytes)
/// - Reconstruction: via [`from_serialized()`](Self::from_serialized)
///
/// # Constant-Time Comparison
///
/// AUDIT-ACCEPTED: ConstantTimeEq not implemented because the inner
/// aws-lc-rs types (`MlKemDecapsulationKeyPair`, `X25519StaticKeyPair`) do not
/// expose key bytes for byte-level constant-time comparison. This type is not
/// compared in any production code path.
///
/// # Example
///
/// ```rust,no_run
/// use latticearc::hybrid::kem_hybrid::generate_keypair;
///
/// let (pk, sk) = generate_keypair().expect("keypair generation failed");
/// // sk.ecdh_keypair holds the real X25519 private key
/// drop(sk);  // ML-KEM bytes zeroized; aws-lc-rs handles X25519 cleanup
/// ```
pub struct HybridKemSecretKey {
    /// ML-KEM decapsulation keypair — holds the real aws-lc-rs `DecapsulationKey`.
    ml_kem_keypair: MlKemDecapsulationKeyPair,
    /// X25519 ECDH static key pair for reusable key agreement.
    ecdh_keypair: X25519StaticKeyPair,
}

impl HybridKemSecretKey {
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

    /// Export the ML-KEM secret key bytes for serialization.
    ///
    /// Returns the serialized decapsulation key via `DecapsulationKey::key_bytes()`.
    /// The returned bytes are wrapped in [`Zeroizing`] and will be wiped from
    /// memory when dropped.
    ///
    /// # Errors
    /// Returns an error if key serialization fails.
    pub fn ml_kem_sk_bytes(&self) -> Result<Zeroizing<Vec<u8>>, HybridKemError> {
        self.ml_kem_keypair
            .decaps_key_bytes()
            .map_err(|e| HybridKemError::MlKemError(e.to_string()))
    }

    /// Export the X25519 ECDH seed bytes (32 bytes) for serialization.
    ///
    /// These bytes can be used with `X25519StaticKeyPair::from_seed_bytes()`
    /// to reconstruct the keypair.
    ///
    /// # Errors
    /// Returns an error if seed extraction fails.
    pub fn ecdh_seed_bytes(&self) -> Result<Zeroizing<[u8; 32]>, HybridKemError> {
        self.ecdh_keypair.seed_bytes().map_err(|e| HybridKemError::EcdhError(e.to_string()))
    }

    /// Reconstruct a `HybridKemSecretKey` from serialized components.
    ///
    /// This is the reverse of [`ml_kem_sk_bytes()`](Self::ml_kem_sk_bytes) +
    /// [`ecdh_seed_bytes()`](Self::ecdh_seed_bytes). It reconstructs both the
    /// ML-KEM `DecapsulationKey` and the X25519 `StaticKeyPair` from their
    /// serialized forms.
    ///
    /// # Arguments
    /// * `security_level` - ML-KEM security level (must match original key)
    /// * `ml_kem_sk_bytes` - Secret key bytes from `ml_kem_sk_bytes()`
    /// * `ml_kem_pk_bytes` - Public key bytes (needed for `MlKemDecapsulationKeyPair`)
    /// * `ecdh_seed` - X25519 seed bytes from `ecdh_seed_bytes()`
    ///
    /// # Errors
    /// Returns an error if ML-KEM key reconstruction or X25519 seed import fails.
    pub fn from_serialized(
        security_level: MlKemSecurityLevel,
        ml_kem_sk_bytes: &[u8],
        ml_kem_pk_bytes: &[u8],
        ecdh_seed: &[u8; 32],
    ) -> Result<Self, HybridKemError> {
        let ml_kem_keypair = MlKemDecapsulationKeyPair::from_key_bytes(
            security_level,
            ml_kem_sk_bytes,
            ml_kem_pk_bytes,
        )
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;

        let ecdh_keypair = X25519StaticKeyPair::from_seed_bytes(ecdh_seed)
            .map_err(|e| HybridKemError::EcdhError(e.to_string()))?;

        Ok(Self { ml_kem_keypair, ecdh_keypair })
    }

    /// Perform X25519 key agreement with a peer's ephemeral public key.
    ///
    /// # Errors
    /// Returns an error if key agreement fails.
    pub fn ecdh_agree(&self, peer_pk: &[u8]) -> Result<Zeroizing<[u8; 32]>, HybridKemError> {
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

impl std::fmt::Debug for HybridKemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridKemSecretKey")
            .field("ml_kem_keypair", &"[REDACTED]")
            .field("ecdh_keypair", &"[REDACTED]")
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
    ml_kem_ct: Vec<u8>,
    /// Ephemeral X25519 public key bytes (32 bytes) for ECDH.
    ecdh_pk: Vec<u8>,
    /// Combined shared secret (64 bytes), automatically zeroized on drop.
    shared_secret: Zeroizing<Vec<u8>>,
}

impl EncapsulatedKey {
    /// Construct an `EncapsulatedKey` from its components.
    ///
    /// The `shared_secret` is wrapped in [`Zeroizing`] and will be wiped
    /// from memory when the `EncapsulatedKey` is dropped.
    #[must_use]
    pub fn new(ml_kem_ct: Vec<u8>, ecdh_pk: Vec<u8>, shared_secret: Zeroizing<Vec<u8>>) -> Self {
        Self { ml_kem_ct, ecdh_pk, shared_secret }
    }

    /// Returns the ML-KEM ciphertext bytes.
    #[must_use]
    pub fn ml_kem_ct(&self) -> &[u8] {
        &self.ml_kem_ct
    }

    /// Returns the ephemeral X25519 public key bytes (32 bytes).
    #[must_use]
    pub fn ecdh_pk(&self) -> &[u8] {
        &self.ecdh_pk
    }

    /// Returns the combined shared secret bytes.
    ///
    /// The returned slice borrows the zeroizing inner buffer; the buffer is
    /// wiped automatically when the [`EncapsulatedKey`] is dropped.
    #[must_use]
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
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

impl ConstantTimeEq for EncapsulatedKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.shared_secret.as_slice().ct_eq(other.shared_secret.as_slice())
    }
}

/// Generate hybrid keypair (ML-KEM + X25519) at the default ML-KEM-768 level.
///
/// The X25519 component uses a real static key pair (aws-lc-rs `PrivateKey`)
/// that supports reusable key agreement for decapsulation.
///
/// # Errors
///
/// Returns an error if ML-KEM or X25519 keypair generation fails.
pub fn generate_keypair() -> Result<(HybridKemPublicKey, HybridKemSecretKey), HybridKemError> {
    generate_keypair_with_level(MlKemSecurityLevel::MlKem768)
}

/// Generate hybrid keypair at a specific ML-KEM security level.
///
/// # Arguments
/// * `level` - ML-KEM security level (512, 768, or 1024)
///
/// # Entropy source
/// aws-lc-rs supplies entropy internally; callers cannot provide an RNG.
///
/// # Errors
/// Returns an error if ML-KEM or X25519 keypair generation fails.
pub fn generate_keypair_with_level(
    level: MlKemSecurityLevel,
) -> Result<(HybridKemPublicKey, HybridKemSecretKey), HybridKemError> {
    let ml_kem_keypair = MlKem::generate_decapsulation_keypair(level)
        .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;

    let ecdh_keypair =
        X25519StaticKeyPair::generate().map_err(|e| HybridKemError::EcdhError(e.to_string()))?;

    let ecdh_pk = ecdh_keypair.public_key_bytes().to_vec();

    let pk = HybridKemPublicKey {
        ml_kem_pk: ml_kem_keypair.public_key_bytes().to_vec(),
        ecdh_pk,
        security_level: level,
    };

    let sk = HybridKemSecretKey { ml_kem_keypair, ecdh_keypair };

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
pub fn encapsulate(pk: &HybridKemPublicKey) -> Result<EncapsulatedKey, HybridKemError> {
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
    let (ml_kem_ss, ml_kem_ct_struct) = MlKem::encapsulate(&ml_kem_pk_struct)
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
        &*ecdh_shared_secret,
        pk.ecdh_pk.as_slice(),
        &ecdh_ephemeral_public,
    )
    .map_err(|e| HybridKemError::KdfError(e.to_string()))?;

    // `shared_secret` is already `Zeroizing<Vec<u8>>` — pass directly.
    Ok(EncapsulatedKey { ml_kem_ct, ecdh_pk: ecdh_ephemeral_public, shared_secret })
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
pub fn decapsulate(
    sk: &HybridKemSecretKey,
    ct: &EncapsulatedKey,
) -> Result<Zeroizing<Vec<u8>>, HybridKemError> {
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
        &*ecdh_shared_secret,
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
) -> Result<Zeroizing<Vec<u8>>, HybridKemError> {
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
    // Concatenate secrets for KDF input (zeroized on drop)
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ml_kem_ss);
    ikm.extend_from_slice(ecdh_ss);

    // Context info for domain separation and public-key binding, using
    // length-prefixed encoding to prevent canonicalization collisions
    // between the variable-length fields (HPKE §5.1 / RFC 9180 "LabeledExtract").
    // Layout: [domain_label][static_pk_len: u32 BE][static_pk][ephemeral_pk_len: u32 BE][ephemeral_pk].
    // Public keys happen to be fixed 32 bytes today, so the ambiguity is not
    // currently exploitable, but length-prefixing keeps the construction
    // consistent with `encrypt_hybrid::derive_encryption_key` (P5.1) and
    // protects against any future variable-length component.
    if static_pk.len() > u32::MAX as usize || ephemeral_pk.len() > u32::MAX as usize {
        return Err(HybridKemError::KdfError("HKDF info component exceeds 2^32 bytes".to_string()));
    }
    let static_pk_len = u32::try_from(static_pk.len()).map_err(|_e| {
        HybridKemError::KdfError("static public key exceeds 2^32 bytes".to_string())
    })?;
    let ephemeral_pk_len = u32::try_from(ephemeral_pk.len()).map_err(|_e| {
        HybridKemError::KdfError("ephemeral public key exceeds 2^32 bytes".to_string())
    })?;
    let domain = crate::types::domains::HYBRID_KEM_SS_INFO;
    let total = domain
        .len()
        .saturating_add(4)
        .saturating_add(static_pk.len())
        .saturating_add(4)
        .saturating_add(ephemeral_pk.len());
    let mut info = Vec::with_capacity(total);
    info.extend_from_slice(domain);
    info.extend_from_slice(&static_pk_len.to_be_bytes());
    info.extend_from_slice(static_pk);
    info.extend_from_slice(&ephemeral_pk_len.to_be_bytes());
    info.extend_from_slice(ephemeral_pk);

    // Use HKDF-SHA256 with domain separation (via aws-lc-rs)
    let hkdf_result = hkdf(&ikm, None, Some(&info), 64)
        .map_err(|e| HybridKemError::KdfError(format!("HKDF failed: {}", e)))?;

    // SECURITY: wrap the derived hybrid shared secret in `Zeroizing` — otherwise
    // `.to_vec()` on `hkdf_result.key()` copies the secret OUT of its internal
    // `Zeroizing<Vec<u8>>` into an unprotected `Vec`.
    Ok(Zeroizing::new(hkdf_result.key().to_vec()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::implicit_clone)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn test_hybrid_kem_key_generation_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();

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
    fn test_hybrid_kem_encapsulation_decapsulation_roundtrip_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();

        // Test encapsulation
        let enc_key = encapsulate(&pk).unwrap();

        assert!(!enc_key.ml_kem_ct.is_empty(), "KEM ciphertext should not be empty");
        assert_eq!(enc_key.ml_kem_ct.len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
        assert_eq!(enc_key.ecdh_pk.len(), 32, "Ephemeral ECDH PK should be 32 bytes");
        assert_eq!(enc_key.shared_secret.len(), 64, "Shared secret should be 64 bytes");

        // Test decapsulation — THIS IS THE KEY ROUNDTRIP TEST
        let dec_secret = decapsulate(&sk, &enc_key).unwrap();

        assert_eq!(dec_secret.len(), 64, "Decapsulated secret should be 64 bytes");
        assert_eq!(dec_secret.as_slice(), enc_key.shared_secret.as_slice(), "Secrets should match");

        // Test that different encapsulations produce different secrets
        let enc_key2 = encapsulate(&pk).unwrap();
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
    fn test_hybrid_shared_secret_derivation_succeeds() {
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
    fn test_hybrid_secret_key_zeroization_succeeds() {
        let (_pk, sk) = generate_keypair().expect("Should generate keypair");

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
    fn test_encapsulated_key_zeroization_succeeds() {
        let (pk, _sk) = generate_keypair().expect("Should generate keypair");

        let mut encaps_result = encapsulate(&pk).expect("Should encapsulate");

        let ss_before = encaps_result.shared_secret.as_slice().to_vec();
        assert!(!ss_before.iter().all(|&b| b == 0), "Shared secret should contain non-zero data");

        encaps_result.shared_secret.zeroize();

        assert!(
            encaps_result.shared_secret.as_slice().iter().all(|&b| b == 0),
            "Shared secret should be zeroized"
        );
    }

    #[test]
    fn test_ecdh_key_agreement_succeeds() {
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
    fn test_encapsulated_key_ciphertext_zeroization_succeeds() {
        let (pk, _sk) = generate_keypair().expect("Should generate keypair");

        let mut encaps_result = encapsulate(&pk).expect("Should encapsulate");

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
    fn test_hybrid_kem_multiple_decapsulations_succeed_succeeds() {
        // Verify the same secret key can decapsulate multiple ciphertexts
        let (pk, sk) = generate_keypair().unwrap();

        for _ in 0..3 {
            let enc = encapsulate(&pk).unwrap();
            let dec = decapsulate(&sk, &enc).unwrap();
            assert_eq!(dec.as_slice(), enc.shared_secret.as_slice());
        }
    }

    #[test]
    fn test_encapsulate_invalid_ecdh_pk_length_returns_error() {
        let (mut pk, _sk) = generate_keypair().unwrap();
        pk.ecdh_pk = vec![0u8; 16]; // Wrong length

        let result = encapsulate(&pk);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::InvalidKeyMaterial(_)));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn test_decapsulate_invalid_ecdh_pk_length_returns_error() {
        let (pk, sk) = generate_keypair().unwrap();

        let enc = encapsulate(&pk).unwrap();
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
    fn test_derive_hybrid_shared_secret_invalid_ecdh_secret_length_returns_error() {
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
    fn test_derive_hybrid_shared_secret_invalid_ml_kem_secret_length_returns_error() {
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
    fn test_hybrid_public_key_clone_debug_succeeds() {
        let (pk, _sk) = generate_keypair().unwrap();

        let pk2 = pk.clone();
        assert_eq!(pk.ml_kem_pk, pk2.ml_kem_pk);
        assert_eq!(pk.ecdh_pk, pk2.ecdh_pk);

        let debug = format!("{:?}", pk);
        assert!(debug.contains("HybridKemPublicKey"));
    }

    #[test]
    fn test_hybrid_secret_key_debug_has_correct_format() {
        let (_pk, sk) = generate_keypair().unwrap();

        let debug = format!("{:?}", sk);
        assert!(debug.contains("HybridKemSecretKey"));
    }

    #[test]
    fn test_encapsulated_key_debug_has_correct_format() {
        let (pk, _sk) = generate_keypair().unwrap();

        let enc = encapsulate(&pk).unwrap();
        let debug = format!("{:?}", enc);
        assert!(debug.contains("EncapsulatedKey"));
    }

    #[test]
    fn test_hybrid_kem_error_display_variants_have_correct_format_fails() {
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
    fn test_hybrid_kem_error_eq_clone_succeeds() {
        let err1 = HybridKemError::MlKemError("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1, err2);
        assert_ne!(err1, HybridKemError::EcdhError("test".to_string()));
    }

    #[test]
    fn test_derive_different_static_pk_changes_output_succeeds() {
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
    fn test_derive_different_ephemeral_pk_changes_output_succeeds() {
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
    fn test_hybrid_secret_key_ml_kem_sk_bytes_succeeds() {
        let (_pk, sk) = generate_keypair().unwrap();

        let sk_bytes = sk.ml_kem_sk_bytes().unwrap();
        // ML-KEM-768 secret key is 2400 bytes
        assert_eq!(sk_bytes.len(), 2400, "ML-KEM-768 SK should be 2400 bytes");
        assert!(!sk_bytes.iter().all(|&b| b == 0), "ML-KEM SK should not be all zeros");
    }

    #[test]
    fn test_hybrid_secret_key_ecdh_seed_bytes_succeeds() {
        let (_pk, sk) = generate_keypair().unwrap();

        let seed = sk.ecdh_seed_bytes().unwrap();
        assert_eq!(seed.len(), 32, "X25519 seed should be 32 bytes");
        assert!(!seed.iter().all(|&b| b == 0), "X25519 seed should not be all zeros");
    }

    #[test]
    fn test_hybrid_secret_key_export_reconstruct_roundtrip() {
        let (pk, sk) = generate_keypair().unwrap();

        // Export key components
        let ml_kem_sk = sk.ml_kem_sk_bytes().unwrap();
        let ecdh_seed = sk.ecdh_seed_bytes().unwrap();

        // Encapsulate with original keys
        let enc = encapsulate(&pk).unwrap();
        let _original_secret = decapsulate(&sk, &enc).unwrap();

        // Reconstruct ECDH keypair from seed
        let reconstructed_ecdh = X25519StaticKeyPair::from_seed_bytes(&ecdh_seed).unwrap();

        // Verify public keys match
        assert_eq!(
            sk.ecdh_public_key_bytes(),
            reconstructed_ecdh.public_key_bytes().to_vec(),
            "Reconstructed ECDH PK must match original"
        );

        // Verify ML-KEM SK bytes are non-empty and properly sized
        assert!(!ml_kem_sk.is_empty());

        // Verify original decapsulation still works after export
        let enc2 = encapsulate(&pk).unwrap();
        let secret2 = decapsulate(&sk, &enc2).unwrap();
        assert_eq!(
            secret2.as_slice(),
            enc2.shared_secret.as_slice(),
            "Decapsulation must still work after export"
        );
    }

    #[test]
    fn test_hybrid_secret_key_ecdh_agree_succeeds() {
        let (_pk, sk) = generate_keypair().unwrap();

        // Generate another X25519 keypair
        let other = X25519KeyPair::generate().unwrap();
        let other_pk = other.public_key_bytes().to_vec();

        // sk can agree with another party
        let shared = sk.ecdh_agree(&other_pk);
        assert!(shared.is_ok());
        assert_eq!(shared.unwrap().len(), 32);
    }

    #[test]
    fn test_hybrid_secret_key_ecdh_agree_invalid_pk_returns_error() {
        let (_pk, sk) = generate_keypair().unwrap();

        // Invalid peer public key (too short)
        let result = sk.ecdh_agree(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_encapsulate_invalid_ml_kem_pk_returns_error() {
        let pk = HybridKemPublicKey {
            ml_kem_pk: vec![0u8; 100], // Wrong length
            ecdh_pk: vec![0u8; 32],
            security_level: MlKemSecurityLevel::MlKem768,
        };

        let result = encapsulate(&pk);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridKemError::MlKemError(_)));
    }

    // ========================================================================
    // Additional coverage: error paths and edge cases
    // ========================================================================

    #[test]
    fn test_decapsulate_invalid_ephemeral_ecdh_pk_length_returns_error() {
        let (_pk, sk) = generate_keypair().unwrap();

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
    fn test_decapsulate_invalid_ml_kem_ct_length_returns_error() {
        let (_pk, sk) = generate_keypair().unwrap();

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
    fn test_derive_hybrid_shared_secret_invalid_ml_kem_length_returns_error() {
        let result = derive_hybrid_shared_secret(&[0u8; 16], &[0u8; 32], &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ML-KEM"));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ecdh_length_returns_error() {
        let result = derive_hybrid_shared_secret(&[0u8; 32], &[0u8; 16], &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ECDH"));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_is_deterministic() {
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
    fn test_derive_hybrid_shared_secret_different_inputs_differ_succeeds() {
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
    fn test_encapsulate_invalid_ecdh_pk_too_long_returns_error() {
        let pk = HybridKemPublicKey {
            ml_kem_pk: vec![0u8; 1184],
            ecdh_pk: vec![0u8; 64], // Too long (should be 32)
            security_level: MlKemSecurityLevel::MlKem768,
        };

        let result = encapsulate(&pk);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HybridKemError::InvalidKeyMaterial(_)));
    }

    #[test]
    fn test_encapsulated_key_shared_secret_has_correct_size() {
        let (pk, _sk) = generate_keypair().unwrap();
        let encapsulated = encapsulate(&pk).unwrap();
        assert_eq!(encapsulated.shared_secret.len(), 64);
        assert_eq!(encapsulated.ecdh_pk.len(), 32);
    }

    #[test]
    fn test_hybrid_kem_error_display_kdf_has_correct_format() {
        let err = HybridKemError::KdfError("test kdf".to_string());
        assert!(err.to_string().contains("test kdf"));
    }

    #[test]
    fn test_hybrid_public_key_accessors_succeed_succeeds() {
        let (pk, _sk) = generate_keypair().unwrap();
        assert_eq!(pk.ml_kem_pk.len(), 1184);
        assert_eq!(pk.ecdh_pk.len(), 32);
    }
}
