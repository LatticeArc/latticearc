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
//! │                         │  │  info = "LatticeArc-Hybrid-KEM-SS-v1" ‖ len(static_pk) ‖ static_pk ‖ len(ephemeral_pk) ‖ ephemeral_pk │ │   │
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
//! // Both parties now have the same 64-byte shared secret.
//! // Secret comparison uses `ct_eq` per invariant I-5.
//! use subtle::ConstantTimeEq;
//! let lhs: &[u8] = shared_secret.expose_secret();
//! let rhs: &[u8] = encapsulated.expose_secret();
//! assert!(bool::from(lhs.ct_eq(rhs)));
//! # Ok(())
//! # }
//! ```
//!
//! [`ZeroizeOnDrop`]: zeroize::ZeroizeOnDrop

use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::log_crypto_operation_error;
use crate::primitives::kdf::hkdf::hkdf;
use crate::primitives::kem::ecdh::{X25519_KEY_SIZE, X25519KeyPair, X25519StaticKeyPair};
use crate::primitives::kem::ml_kem::MlKemDecapsulationKeyPair;
use crate::primitives::kem::{MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecurityLevel};
use crate::unified_api::logging::op;

/// Error types for hybrid KEM operations.
///
/// This enum captures all possible error conditions that can occur during
/// hybrid key encapsulation and decapsulation operations.
// PartialEq intentionally not derived (see `HybridSignatureError`).
#[derive(Debug, Clone, Error)]
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
    /// Hybrid decapsulation failed. Single opaque variant per Pattern 6 — does
    /// not distinguish wrong-length ECDH PK from ML-KEM rejection from HKDF
    /// failure, since the input ciphertext is adversary-controlled and any
    /// distinguisher would constitute a padding-oracle leak.
    #[error("Hybrid decapsulation failed")]
    DecapsulationFailed,
    /// Hybrid encapsulation failed. Single opaque variant per Pattern 6
    /// "encrypt-side defense in depth" — symmetric to
    /// [`Self::DecapsulationFailed`]. Encap inputs are caller-controlled
    /// (the recipient PK), but `e.to_string()` from upstream crates can
    /// leak version-dependent error wording into application logs;
    /// collapsing to one variant keeps the surface stable across
    /// dependency upgrades and removes a class of accidental disclosure.
    /// Per-stage detail is preserved via internal trace events
    /// (`log_crypto_operation_error!(op::HYBRID_KEM_ENCAPSULATE...)`).
    #[error("Hybrid encapsulation failed")]
    EncapsulationFailed,
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

    /// Current `to_bytes` / `from_bytes` wire-format version.
    ///
    /// Bumped whenever the on-disk layout changes in a non-backward-
    /// compatible way (new fields, reordering, changed length-prefix
    /// width). Old parsers reject buffers carrying a version they don't
    /// recognize via [`HybridKemError::InvalidKeyMaterial`]; new parsers
    /// can branch on the version to support multiple historical layouts.
    pub const WIRE_FORMAT_VERSION: u8 = 1;

    /// Serialize this `HybridKemPublicKey` to a self-describing byte string.
    ///
    /// Wire layout (v1):
    /// `[format_version: u8 = 1] [level_tag: u8] [ml_kem_pk_len: u32 BE] [ml_kem_pk] [ecdh_pk_len: u32 BE] [ecdh_pk]`.
    /// Level tag mapping: `1 = MlKem512`, `2 = MlKem768`, `3 = MlKem1024`
    /// (v1 is exhausted at 3 and the format-version prefix exists so a
    /// future ML-KEM-2048 / composite scheme can ship as v2 without
    /// breaking v1 parsers). [`from_bytes`] is the round-trip inverse.
    ///
    /// # Errors
    ///
    /// Returns `HybridKemError::InvalidKeyMaterial` if either component
    /// public key exceeds `u32::MAX` bytes (4 GiB). Real ML-KEM and
    /// X25519 public keys are bounded well below this limit, so the
    /// error path is unreachable in practice — but `?`-propagation
    /// matches the symmetric posture of `append_lenp_field` in
    /// `unified_api::audit`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, HybridKemError> {
        let level_tag: u8 = match self.security_level {
            MlKemSecurityLevel::MlKem512 => 1,
            MlKemSecurityLevel::MlKem768 => 2,
            MlKemSecurityLevel::MlKem1024 => 3,
        };
        let mut out = Vec::with_capacity(
            1usize
                .saturating_add(1)
                .saturating_add(4)
                .saturating_add(self.ml_kem_pk.len())
                .saturating_add(4)
                .saturating_add(self.ecdh_pk.len()),
        );
        out.push(Self::WIRE_FORMAT_VERSION);
        out.push(level_tag);
        // Lengths are bounded by `MlKemPublicKey::MAX_PK_BYTES` (well
        // under u32::MAX) so `try_from` always succeeds for any real
        // PK. The previous `unwrap_or(u32::MAX)` was an asymmetric
        // saturation that would let a 5 GiB component PK silently
        // collide with a 4 GiB component PK on the wire — propagate
        // structurally instead, matching `audit::append_lenp_field`.
        let ml_len = u32::try_from(self.ml_kem_pk.len()).map_err(|_e| {
            HybridKemError::InvalidKeyMaterial("ml_kem_pk length exceeds 2^32 bytes".to_string())
        })?;
        let ed_len = u32::try_from(self.ecdh_pk.len()).map_err(|_e| {
            HybridKemError::InvalidKeyMaterial("ecdh_pk length exceeds 2^32 bytes".to_string())
        })?;
        out.extend_from_slice(&ml_len.to_be_bytes());
        out.extend_from_slice(&self.ml_kem_pk);
        out.extend_from_slice(&ed_len.to_be_bytes());
        out.extend_from_slice(&self.ecdh_pk);
        Ok(out)
    }

    /// Parse a `HybridKemPublicKey` previously produced by [`to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns `HybridKemError::InvalidKeyMaterial` on any structural failure
    /// (truncated buffer, unknown format version, unknown level tag,
    /// length-prefix overflow). The parser does NOT validate the inner
    /// ML-KEM PK bytes — that work happens at first use via [`encapsulate`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridKemError> {
        let inv = || {
            HybridKemError::InvalidKeyMaterial(
                "malformed HybridKemPublicKey wire format".to_string(),
            )
        };
        let format_version = *bytes.first().ok_or_else(inv)?;
        if format_version != Self::WIRE_FORMAT_VERSION {
            return Err(HybridKemError::InvalidKeyMaterial(format!(
                "unsupported HybridKemPublicKey wire-format version {format_version} \
                 (this build supports v{})",
                Self::WIRE_FORMAT_VERSION
            )));
        }
        let level_tag = *bytes.get(1).ok_or_else(inv)?;
        let security_level = match level_tag {
            1 => MlKemSecurityLevel::MlKem512,
            2 => MlKemSecurityLevel::MlKem768,
            3 => MlKemSecurityLevel::MlKem1024,
            _ => return Err(inv()),
        };
        let mut cursor = 2usize;
        let read_len = |buf: &[u8], at: usize| -> Result<u32, HybridKemError> {
            let slice = buf.get(at..at.checked_add(4).ok_or_else(inv)?).ok_or_else(inv)?;
            let arr: [u8; 4] = slice.try_into().map_err(|_e| inv())?;
            Ok(u32::from_be_bytes(arr))
        };
        // validate the prefixed lengths against the
        // claimed security level BEFORE the `to_vec()` slice — pre-fix,
        // a buffer claiming Level 5 but carrying a Level 3-shaped
        // ML-KEM PK parsed successfully and failed opaquely at first
        // encap.
        let ml_len = usize::try_from(read_len(bytes, cursor)?).map_err(|_e| inv())?;
        if ml_len != security_level.public_key_size() {
            return Err(HybridKemError::InvalidKeyMaterial(format!(
                "ML-KEM PK length {} does not match security level {} (expects {})",
                ml_len,
                security_level.name(),
                security_level.public_key_size()
            )));
        }
        cursor = cursor.checked_add(4).ok_or_else(inv)?;
        let ml_end = cursor.checked_add(ml_len).ok_or_else(inv)?;
        let ml_kem_pk = bytes.get(cursor..ml_end).ok_or_else(inv)?.to_vec();
        cursor = ml_end;
        let ed_len = usize::try_from(read_len(bytes, cursor)?).map_err(|_e| inv())?;
        if ed_len != X25519_KEY_SIZE {
            return Err(HybridKemError::InvalidKeyMaterial(format!(
                "X25519 PK length {} does not match expected {}",
                ed_len, X25519_KEY_SIZE
            )));
        }
        cursor = cursor.checked_add(4).ok_or_else(inv)?;
        let ed_end = cursor.checked_add(ed_len).ok_or_else(inv)?;
        let ecdh_pk = bytes.get(cursor..ed_end).ok_or_else(inv)?.to_vec();
        if ed_end != bytes.len() {
            return Err(inv());
        }
        Ok(Self { ml_kem_pk, ecdh_pk, security_level })
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
/// Implements [`subtle::ConstantTimeEq`] via the serialized byte-level
/// accessors [`ml_kem_sk_bytes()`](Self::ml_kem_sk_bytes) and
/// [`ecdh_seed_bytes()`](Self::ecdh_seed_bytes). Two secret keys compare
/// equal iff (a) their security levels match, (b) their ML-KEM
/// decapsulation key bytes are equal, and (c) their X25519 seed bytes are
/// equal — each compared in constant time via `subtle`.
///
/// **Intentionally no [`PartialEq`] / [`Eq`] impl.** Comparison is
/// CT-only via `ct_eq`; attempting `==` on a `HybridKemSecretKey` is a
/// compile error, not a silent non-CT check.
///
/// **Secret-material surfacing.** During a `ct_eq` call both sides'
/// serialized ML-KEM and X25519 seed bytes briefly reside on the caller's
/// stack (wrapped in `Zeroizing`, cleared on drop). The comparison does
/// not leave residues beyond the call.
///
/// Cost: two `Zeroizing<Vec<u8>>` heap allocations (ML-KEM side) plus two
/// stack `[u8; 32]` copies (ECDH side) per compare. Acceptable outside
/// tight loops; for hot-path deduplication, prefer comparing key IDs.
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
    /// Cached concatenation of (ML-KEM sk bytes || ECDH seed bytes),
    /// populated at construction and used exclusively by `ct_eq` so that
    /// the constant-time comparison never has to re-serialize through
    /// aws-lc-rs FFI on the hot path. The FFI round-trips have non-trivial
    /// allocation/cache variance that dominates measured timing on shared
    /// CI runners and masks the `subtle::ConstantTimeEq` signal the dudect
    /// gate is meant to verify. Caching makes `ct_eq` a pure byte compare.
    ///
    /// `Zeroizing` wipes the buffer on drop; the underlying aws-lc-rs
    /// keypairs retain the authoritative copy for all crypto operations.
    ct_compare_bytes: Zeroizing<Vec<u8>>,
}

impl HybridKemSecretKey {
    /// Single internal constructor — owns the invariant that
    /// `ct_compare_bytes` equals `decaps_key_bytes() || seed_bytes()` of
    /// the two keypair fields. Every construction path in this module
    /// must go through here so the cache cannot diverge from the
    /// authoritative key material.
    fn new(
        ml_kem_keypair: MlKemDecapsulationKeyPair,
        ecdh_keypair: X25519StaticKeyPair,
    ) -> Result<Self, HybridKemError> {
        let ml_kem_sk = ml_kem_keypair
            .decaps_key_bytes()
            .map_err(|e| HybridKemError::MlKemError(e.to_string()))?;
        let ecdh_seed =
            ecdh_keypair.seed_bytes().map_err(|e| HybridKemError::EcdhError(e.to_string()))?;
        let mut buf = Vec::with_capacity(ml_kem_sk.len().saturating_add(ecdh_seed.len()));
        buf.extend_from_slice(&ml_kem_sk[..]);
        buf.extend_from_slice(&ecdh_seed[..]);
        Ok(Self { ml_kem_keypair, ecdh_keypair, ct_compare_bytes: Zeroizing::new(buf) })
    }

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

        Self::new(ml_kem_keypair, ecdh_keypair)
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
            .field("ct_compare_bytes", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for HybridKemSecretKey {
    /// Constant-time comparison of two hybrid secret keys.
    ///
    /// Compares the pre-computed `ct_compare_bytes` cache (ML-KEM
    /// decapsulation-key bytes concatenated with X25519 seed bytes) via
    /// `subtle::ConstantTimeEq`. The cache is populated once at
    /// construction, so `ct_eq` on the hot path never touches aws-lc-rs
    /// FFI — it's a pure byte compare.
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        use subtle::Choice;

        // `MlKemSecurityLevel` is not `#[repr(u8)]`, so do not rely on
        // discriminant-cast ordering.
        let level_match = Choice::from(u8::from(self.security_level() == other.security_level()));

        // `subtle::ConstantTimeEq` on `[u8]` returns `Choice::from(0)` on
        // length mismatch, which happens only when security levels differ.
        // `level_match` is then already 0, so the non-CT length check
        // inside subtle leaks only the non-secret security level.
        let bytes_match = self.ct_compare_bytes.ct_eq(&other.ct_compare_bytes);

        level_match & bytes_match
    }
}

/// Size in bytes of a combined hybrid shared secret (HKDF-SHA256 output,
/// concatenation-free derivation; see [`derive_hybrid_shared_secret`]).
pub const HYBRID_SHARED_SECRET_LEN: usize = 64;

/// Hybrid encapsulation result containing the shared secret.
///
/// # Security Guarantees
///
/// The `shared_secret` field is a [`SecretBytes<64>`][crate::types::SecretBytes]
/// — stack-allocated and zeroized on drop via the `ZeroizeOnDrop` derive, using
/// volatile writes that the compiler cannot optimize away. Stack allocation
/// (invariant I-2) avoids both heap-allocator size fingerprinting and the
/// `Vec` reallocation path that could free an unzeroized buffer.
///
/// Access goes through [`Self::expose_secret`] (invariant I-8); `PartialEq`/
/// `Eq` are not implemented (invariants I-5/I-6) — use [`ConstantTimeEq`] for
/// equality checks.
#[derive(ZeroizeOnDrop)]
pub struct EncapsulatedKey {
    /// ML-KEM ciphertext bytes (size depends on security level).
    ml_kem_ct: Vec<u8>,
    /// Ephemeral X25519 public key bytes (32 bytes) for ECDH.
    ecdh_pk: Vec<u8>,
    /// Combined shared secret (64 bytes, stack-allocated, zeroized on drop).
    ///
    /// Per Secret Type Invariant I-2, fixed-size secrets use
    /// [`SecretBytes<N>`] rather than `Zeroizing<Vec<u8>>`: no heap allocator
    /// metadata leaks the secret size, and there is no realloc path that
    /// could free an unzeroized buffer.
    shared_secret: crate::types::SecretBytes<HYBRID_SHARED_SECRET_LEN>,
}

impl EncapsulatedKey {
    /// Construct an `EncapsulatedKey` from its components.
    ///
    /// The `shared_secret` is a stack-allocated [`SecretBytes<64>`] that is
    /// wiped from memory when the `EncapsulatedKey` is dropped.
    #[must_use]
    pub fn new(
        ml_kem_ct: Vec<u8>,
        ecdh_pk: Vec<u8>,
        shared_secret: crate::types::SecretBytes<HYBRID_SHARED_SECRET_LEN>,
    ) -> Self {
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

    /// Expose the combined shared secret bytes (64 bytes).
    ///
    /// Sealed accessor per Secret Type Invariant I-8
    /// (`docs/SECRET_TYPE_INVARIANTS.md`). The returned array borrows the
    /// stack-backed `SecretBytes<64>` inside the [`EncapsulatedKey`]; the
    /// buffer is wiped automatically when the outer struct is dropped.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; HYBRID_SHARED_SECRET_LEN] {
        self.shared_secret.expose_secret()
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
        // Compare all three fields. `shared_secret` must be constant-time
        // (invariants I-5/I-6). `ml_kem_ct` and `ecdh_pk` are public wire
        // material — their contents are not secret, but we still use `ct_eq`
        // so a caller's `a.ct_eq(&b)` reports "same encapsulation result"
        // rather than "same shared secret only", which would be a surprising
        // semantic given the outer type's name.
        self.ml_kem_ct.ct_eq(&other.ml_kem_ct)
            & self.ecdh_pk.ct_eq(&other.ecdh_pk)
            & self.shared_secret.ct_eq(&other.shared_secret)
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
#[must_use = "generated keypair must be stored or used"]
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
#[must_use = "generated keypair must be stored or used"]
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

    let sk = HybridKemSecretKey::new(ml_kem_keypair, ecdh_keypair)?;

    Ok((pk, sk))
}

/// Encapsulate using hybrid KEM.
///
/// # Errors
///
/// Returns `HybridKemError::EncapsulationFailed` (a unit variant) on
/// any failure. Per Pattern 6 (error opacity), the ECDH PK length
/// pre-check, ML-KEM PK construction, ML-KEM encapsulation result
/// length, ECDH PK format conversion, and HKDF derivation all
/// collapse into the same opaque variant — see internal tracing under
/// `op::HYBRID_KEM_ENCAPSULATE` for per-stage diagnostics.
pub fn encapsulate(pk: &HybridKemPublicKey) -> Result<EncapsulatedKey, HybridKemError> {
    // Pattern 6 "encrypt-side defense in depth": symmetric to
    // `decapsulate`. All upstream-Display leaks (`e.to_string()`) collapse
    // to one opaque variant for the caller; per-stage detail goes to the
    // internal trace under `op::HYBRID_KEM_ENCAPSULATE`.
    //
    // The recipient PK is *not* assumed adversary-free: TOFU and server-
    // supplied-key flows let an attacker vary the wire-supplied PK length
    // to enumerate which security levels this `encapsulate` accepts. The
    // length pre-check therefore folds into the same opaque variant as
    // every other failure mode — matching `decapsulate`'s symmetry.
    let opaque = || HybridKemError::EncapsulationFailed;

    if pk.ecdh_pk.len() != X25519_KEY_SIZE {
        log_crypto_operation_error!(op::HYBRID_KEM_ENCAPSULATE, "ECDH PK wrong length");
        return Err(opaque());
    }

    // ML-KEM encapsulation at the public key's security level
    let ml_kem_pk_struct =
        MlKemPublicKey::new(pk.security_level, pk.ml_kem_pk.clone()).map_err(|_e| {
            log_crypto_operation_error!(
                op::HYBRID_KEM_ENCAPSULATE,
                "ML-KEM PK construction failed"
            );
            opaque()
        })?;
    let (ml_kem_ss, ml_kem_ct_struct) = MlKem::encapsulate(&ml_kem_pk_struct).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_KEM_ENCAPSULATE, "ML-KEM encapsulate failed");
        opaque()
    })?;
    let ml_kem_ct = ml_kem_ct_struct.into_bytes();

    // Validate ML-KEM shared secret
    if ml_kem_ss.expose_secret().len() != 32 {
        log_crypto_operation_error!(op::HYBRID_KEM_ENCAPSULATE, "ML-KEM SS length invalid");
        return Err(opaque());
    }

    // Generate ephemeral ECDH keypair and perform key agreement
    let ecdh_ephemeral = X25519KeyPair::generate().map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_KEM_ENCAPSULATE, "ECDH keypair generation failed");
        opaque()
    })?;
    let ecdh_ephemeral_public = ecdh_ephemeral.public_key_bytes().to_vec();

    // Perform ECDH key agreement with peer's public key
    let ecdh_shared_secret = ecdh_ephemeral.agree(&pk.ecdh_pk).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_KEM_ENCAPSULATE, "ECDH agree failed");
        opaque()
    })?;

    // Derive hybrid shared secret using HPKE-style KDF
    let shared_secret = derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: ml_kem_ss.expose_secret(),
        ecdh_ss: &*ecdh_shared_secret,
        ecdh_static_pk: pk.ecdh_pk.as_slice(),
        ml_kem_static_pk: pk.ml_kem_pk.as_slice(),
        ephemeral_pk: &ecdh_ephemeral_public,
        kem_ct: &ml_kem_ct,
    })
    .map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_KEM_ENCAPSULATE, "HKDF combiner failed");
        opaque()
    })?;

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
/// Returns `HybridKemError::DecapsulationFailed` on any failure. Per
/// Pattern 6 (error opacity), the ephemeral ECDH PK length check,
/// ML-KEM SK/CT construction, ML-KEM decapsulation result length,
/// ECDH key agreement, and HKDF derivation all collapse into the same
/// opaque variant — see internal tracing under
/// `op::HYBRID_KEM_DECAPSULATE` for per-stage diagnostics.
pub fn decapsulate(
    sk: &HybridKemSecretKey,
    ct: &EncapsulatedKey,
) -> Result<crate::types::SecretBytes<HYBRID_SHARED_SECRET_LEN>, HybridKemError> {
    // The `shared_secret` field of `EncapsulatedKey` is irrelevant on
    // the decapsulate side — the secret is recovered from `sk` and the
    // KEM/ECDH ciphertexts. Forward to `decapsulate_from_parts` which
    // takes only the parts that are actually used. Callers that
    // already have a full `EncapsulatedKey` keep this entry point;
    // callers that have separate ciphertext slices should prefer
    // `decapsulate_from_parts` to avoid building a placeholder
    // shared-secret value.
    decapsulate_from_parts(sk, ct.ml_kem_ct.as_slice(), ct.ecdh_pk.as_slice())
}

/// Hybrid KEM decapsulation from raw ciphertext parts.
///
/// Equivalent to [`decapsulate`] but takes the ML-KEM ciphertext and
/// X25519 ephemeral public key directly, avoiding the need to build an
/// [`EncapsulatedKey`] whose `shared_secret` field is unused on this
/// path.
///
/// # Errors
///
/// Same as [`decapsulate`] — every failure path collapses to opaque
/// `DecapsulationFailed`.
pub fn decapsulate_from_parts(
    sk: &HybridKemSecretKey,
    ml_kem_ct: &[u8],
    ecdh_pk: &[u8],
) -> Result<crate::types::SecretBytes<HYBRID_SHARED_SECRET_LEN>, HybridKemError> {
    // Pattern 6 (opaque return + internal trace): every failure path
    // collapses to `DecapsulationFailed` for the caller (oracle prevention
    // — see [`HybridKemError::DecapsulationFailed`]) but emits a per-stage
    // `log_crypto_operation_error!` with a stable stage tag so operators
    // can debug via correlation_id without the API surface leaking.
    let opaque = || HybridKemError::DecapsulationFailed;

    if ecdh_pk.len() != X25519_KEY_SIZE {
        log_crypto_operation_error!(op::HYBRID_KEM_DECAPSULATE, "ECDH PK length invalid");
        return Err(opaque());
    }

    let ml_kem_ct_struct =
        MlKemCiphertext::new(sk.security_level(), ml_kem_ct.to_vec()).map_err(|_e| {
            log_crypto_operation_error!(
                op::HYBRID_KEM_DECAPSULATE,
                "ML-KEM CT construction failed"
            );
            opaque()
        })?;
    let ml_kem_ss = sk.ml_kem_decapsulate(&ml_kem_ct_struct).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_KEM_DECAPSULATE, "ML-KEM decapsulation failed");
        opaque()
    })?;

    if ml_kem_ss.expose_secret().len() != 32 {
        log_crypto_operation_error!(op::HYBRID_KEM_DECAPSULATE, "ML-KEM SS length invalid");
        return Err(opaque());
    }

    let ecdh_shared_secret = sk.ecdh_agree(ecdh_pk).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_KEM_DECAPSULATE, "ECDH agree failed");
        opaque()
    })?;

    let static_public = sk.ecdh_public_key_bytes();
    let ml_kem_static_pk = sk.ml_kem_pk_bytes();
    derive_hybrid_shared_secret(HybridSharedSecretInputs {
        ml_kem_ss: ml_kem_ss.expose_secret(),
        ecdh_ss: &*ecdh_shared_secret,
        ecdh_static_pk: &static_public,
        ml_kem_static_pk: &ml_kem_static_pk,
        ephemeral_pk: ecdh_pk,
        kem_ct: ml_kem_ct,
    })
    .map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_KEM_DECAPSULATE, "HKDF combiner failed");
        opaque()
    })
}

/// Named-field inputs to [`derive_hybrid_shared_secret`].
///
/// All four fields are `&[u8]` today (ML-KEM and ECDH shared secrets are
/// both 32 bytes; public keys are fixed 32 bytes for the supported
/// levels). Calling a 4×`&[u8]` positional function is easy to get wrong:
/// accidentally swapping the ML-KEM and ECDH secrets would still compile
/// but silently derive the wrong secret and break interop. This struct
/// forces callers to name each input at the callsite, so a swap becomes
/// a compile error on the field name.
pub struct HybridSharedSecretInputs<'a> {
    /// ML-KEM decapsulated shared secret (32 bytes). First leg of the IKM.
    pub ml_kem_ss: &'a [u8],
    /// ECDH (X25519) agreed shared secret (32 bytes). Second leg of the IKM.
    pub ecdh_ss: &'a [u8],
    /// Static recipient ECDH (X25519) public key. Binds the derivation
    /// to the intended ECDH peer identity. Renamed from `static_pk`
    /// in to disambiguate from the new `ml_kem_static_pk`
    /// (HPKE §5.1 wants both legs bound at the combiner, not just one).
    pub ecdh_static_pk: &'a [u8],
    /// Static recipient ML-KEM public key. The previous
    /// combiner only bound the X25519 static PK; the AEAD-AAD layer
    /// bound the ML-KEM PK but the
    /// combiner did not. HPKE / X-Wing guidance is to bind both legs
    /// at the combiner, so a substituted ML-KEM PK cannot yield the
    /// same shared secret even if the AEAD layer is stripped.
    pub ml_kem_static_pk: &'a [u8],
    /// Ephemeral sender public key. Binds the derivation to this specific
    /// session. Included in the HKDF `info` field with a length prefix.
    pub ephemeral_pk: &'a [u8],
    /// ML-KEM ciphertext that produced `ml_kem_ss`. Bound into the HKDF
    /// `info` so a substituted ciphertext cannot yield the same shared
    /// secret. Aligns the construction with X-Wing / KitchenSink
    /// guidance; the AEAD-AAD layer above already binds `kem_ct` for
    /// defense in depth, but binding it in the combiner is the
    /// transcript-conformant location.
    pub kem_ct: &'a [u8],
}

// Manual Debug: never derive Debug on types holding secret byte slices.
// `ml_kem_ss` and `ecdh_ss` are live shared secrets; logging their hex
// via derived Debug would leak them through any tracing/dbg! path.
impl std::fmt::Debug for HybridSharedSecretInputs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSharedSecretInputs")
            .field("ml_kem_ss", &"[REDACTED; 32]")
            .field("ecdh_ss", &"[REDACTED; 32]")
            .field("ecdh_static_pk_len", &self.ecdh_static_pk.len())
            .field("ml_kem_static_pk_len", &self.ml_kem_static_pk.len())
            .field("ephemeral_pk_len", &self.ephemeral_pk.len())
            .field("kem_ct_len", &self.kem_ct.len())
            .finish()
    }
}

/// Derive hybrid shared secret using HPKE-style KDF.
///
/// Combines ML-KEM and ECDH secrets using HKDF following HPKE (RFC 9180)
/// specification with proper domain separation and context binding. See
/// [`HybridSharedSecretInputs`] for parameter meaning — callers construct
/// that struct with named fields so the ML-KEM/ECDH legs cannot be
/// silently swapped at the callsite.
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM shared secret is not exactly 32 bytes.
/// - The ECDH shared secret is not exactly 32 bytes.
/// - HKDF expansion fails.
pub fn derive_hybrid_shared_secret(
    inputs: HybridSharedSecretInputs<'_>,
) -> Result<crate::types::SecretBytes<HYBRID_SHARED_SECRET_LEN>, HybridKemError> {
    let HybridSharedSecretInputs {
        ml_kem_ss,
        ecdh_ss,
        ecdh_static_pk,
        ml_kem_static_pk,
        ephemeral_pk,
        kem_ct,
    } = inputs;
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

    // Input keying material: concatenation of the two 32-byte shared secrets.
    // Stack-allocated fixed-size buffer (invariant I-2); dropped (and
    // zeroized) when the function returns. Bounds are statically correct —
    // both inputs are 32 bytes (verified above) and 32 + 32 == 64.
    let ikm = {
        let mut ikm_raw = [0u8; 64];
        ikm_raw[..32].copy_from_slice(ml_kem_ss);
        ikm_raw[32..].copy_from_slice(ecdh_ss);
        crate::types::SecretBytes::<64>::new(ikm_raw)
    };

    // Context info for domain separation and public-key binding, using
    // length-prefixed encoding to prevent canonicalization collisions
    // between the variable-length fields (HPKE §5.1 / RFC 9180 "LabeledExtract").
    // Layout (BREAKING WIRE FORMAT — bump the domain separator on any
    // change here):
    //   [domain]
    //   [ecdh_static_pk_len: u32 BE][ecdh_static_pk]
    //   [ml_kem_static_pk_len: u32 BE][ml_kem_static_pk]
    //   [ephemeral_pk_len: u32 BE][ephemeral_pk]
    //   [kem_ct_len: u32 BE][kem_ct]
    // The previous layout omitted ml_kem_static_pk; the AEAD-AAD layer
    // bound it but the combiner did not,
    // so a peer-substituted ML-KEM PK with the same X25519 PK would
    // produce the same shared secret pre-AEAD. HPKE §5.1 wants both
    // legs bound at the combiner.
    if ecdh_static_pk.len() > u32::MAX as usize
        || ml_kem_static_pk.len() > u32::MAX as usize
        || ephemeral_pk.len() > u32::MAX as usize
        || kem_ct.len() > u32::MAX as usize
    {
        return Err(HybridKemError::KdfError("HKDF info component exceeds 2^32 bytes".to_string()));
    }
    let ecdh_static_pk_len = u32::try_from(ecdh_static_pk.len()).map_err(|_e| {
        HybridKemError::KdfError("ECDH static public key exceeds 2^32 bytes".to_string())
    })?;
    let ml_kem_static_pk_len = u32::try_from(ml_kem_static_pk.len()).map_err(|_e| {
        HybridKemError::KdfError("ML-KEM static public key exceeds 2^32 bytes".to_string())
    })?;
    let ephemeral_pk_len = u32::try_from(ephemeral_pk.len()).map_err(|_e| {
        HybridKemError::KdfError("ephemeral public key exceeds 2^32 bytes".to_string())
    })?;
    let kem_ct_len = u32::try_from(kem_ct.len())
        .map_err(|_e| HybridKemError::KdfError("KEM ciphertext exceeds 2^32 bytes".to_string()))?;
    let domain = crate::types::domains::HYBRID_KEM_SS_INFO;
    let total = domain
        .len()
        .saturating_add(4)
        .saturating_add(ecdh_static_pk.len())
        .saturating_add(4)
        .saturating_add(ml_kem_static_pk.len())
        .saturating_add(4)
        .saturating_add(ephemeral_pk.len())
        .saturating_add(4)
        .saturating_add(kem_ct.len());
    let mut info = Vec::with_capacity(total);
    info.extend_from_slice(domain);
    info.extend_from_slice(&ecdh_static_pk_len.to_be_bytes());
    info.extend_from_slice(ecdh_static_pk);
    info.extend_from_slice(&ml_kem_static_pk_len.to_be_bytes());
    info.extend_from_slice(ml_kem_static_pk);
    info.extend_from_slice(&ephemeral_pk_len.to_be_bytes());
    info.extend_from_slice(ephemeral_pk);
    info.extend_from_slice(&kem_ct_len.to_be_bytes());
    info.extend_from_slice(kem_ct);

    // HKDF-SHA256 with zero-length salt (`None`), matching HPKE (RFC 9180 §5.1).
    // RFC 5869 §2.2 permits zero salt when IKM is already uniformly random;
    // here IKM is ML-KEM_ss || ECDH_ss — two independent 256-bit secrets from
    // honest-party KEM/DH outputs, so Extract's salt is not doing entropy
    // extraction. Domain separation + key binding live in `info` instead.
    let hkdf_result = hkdf(ikm.expose_secret(), None, Some(&info), HYBRID_SHARED_SECRET_LEN)
        .map_err(|_e| {
            log_crypto_operation_error!(op::HYBRID_KEM_DERIVE, "HKDF failed");
            HybridKemError::KdfError("KDF failed".to_string())
        })?;

    // HKDF returns a slice of exactly the requested length
    // (HYBRID_SHARED_SECRET_LEN, passed above). The `try_into` can only fail
    // if the underlying `hkdf` contract is violated; we surface that as a KDF
    // error rather than panic, keeping this function total.
    let key_array: [u8; HYBRID_SHARED_SECRET_LEN] =
        hkdf_result.expose_secret().try_into().map_err(|_e| {
            log_crypto_operation_error!(op::HYBRID_KEM_DERIVE, "HKDF output length mismatch");
            HybridKemError::KdfError("KDF output length mismatch".to_string())
        })?;
    Ok(crate::types::SecretBytes::new(key_array))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test/bench scaffolding: lints suppressed for this module"
)]
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
        assert_eq!(
            dec_secret.expose_secret(),
            enc_key.shared_secret.expose_secret(),
            "Secrets should match"
        );

        // Test that different encapsulations produce different secrets
        let enc_key2 = encapsulate(&pk).unwrap();
        let dec_secret2 = decapsulate(&sk, &enc_key2).unwrap();
        assert_eq!(
            dec_secret2.expose_secret(),
            enc_key2.shared_secret.expose_secret(),
            "Second roundtrip must also match"
        );

        assert_ne!(
            enc_key.shared_secret.expose_secret(),
            enc_key2.shared_secret.expose_secret(),
            "Different encapsulations should produce different secrets"
        );
    }

    #[test]
    fn test_hybrid_shared_secret_derivation_succeeds() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 32];
        let static_pk = vec![3u8; 32];
        let ephemeral_pk = vec![4u8; 32];

        let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        });
        assert!(result.is_ok(), "HKDF derivation should succeed");

        let secret = result.unwrap();
        assert_eq!(secret.len(), 64, "Derived secret should be 64 bytes");

        // Test deterministic derivation
        let result2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        });
        assert!(result2.is_ok());
        assert!(bool::from(secret.ct_eq(&result2.unwrap())), "HKDF should be deterministic");

        // Test different inputs produce different outputs
        let different_ml_kem_ss = vec![5u8; 32];
        let result3 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &different_ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        });
        assert!(result3.is_ok());
        assert!(
            !bool::from(secret.ct_eq(&result3.unwrap())),
            "Different inputs should produce different outputs"
        );

        // Test invalid input lengths
        let invalid_ml_kem_ss = vec![1u8; 31];
        let result4 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &invalid_ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        });
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

        let ss_before = encaps_result.shared_secret.expose_secret().to_vec();
        assert!(!ss_before.iter().all(|&b| b == 0), "Shared secret should contain non-zero data");

        encaps_result.shared_secret.zeroize();

        assert!(
            encaps_result.shared_secret.expose_secret().iter().all(|&b| b == 0),
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
            assert_eq!(dec.expose_secret(), enc.shared_secret.expose_secret());
        }
    }

    #[test]
    fn test_encapsulate_invalid_ecdh_pk_length_returns_error() {
        let (mut pk, _sk) = generate_keypair().unwrap();
        pk.ecdh_pk = vec![0u8; 16]; // Wrong length

        let result = encapsulate(&pk);
        assert!(result.is_err());
        // Pattern 6 (TOFU follow-up): the ECDH PK length pre-check now
        // collapses into the same opaque variant as every other
        // encapsulate failure; trace tag goes to the private log.
        assert!(matches!(result.unwrap_err(), HybridKemError::EncapsulationFailed));
    }

    #[test]
    fn test_decapsulate_invalid_ecdh_pk_length_returns_error() {
        let (pk, sk) = generate_keypair().unwrap();

        let enc = encapsulate(&pk).unwrap();
        let mut bad_enc = EncapsulatedKey {
            ml_kem_ct: enc.ml_kem_ct.clone(),
            ecdh_pk: vec![0u8; 16], // Wrong length
            shared_secret: crate::types::SecretBytes::zero(),
        };

        let result = decapsulate(&sk, &bad_enc);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Pattern 6: decapsulate collapses every distinguishable failure
        // (length, KEM, ECDH, KDF) into the opaque `DecapsulationFailed`
        // variant so callers cannot tell padding/MAC failures apart.
        assert!(matches!(err, HybridKemError::DecapsulationFailed));
        // cleanup
        bad_enc.shared_secret.zeroize();
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ecdh_secret_length_returns_error() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 31]; // Wrong: should be 32
        let static_pk = vec![3u8; 32];
        let ephemeral_pk = vec![4u8; 32];

        let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        });
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

        let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        });
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
    fn test_hybrid_secret_key_ct_eq_reflexive() {
        let (pk, sk) = generate_keypair().unwrap();
        let ml_sk_bytes = sk.ml_kem_sk_bytes().unwrap();
        let ec_bytes = sk.ecdh_seed_bytes().unwrap();
        let sk_copy = HybridKemSecretKey::from_serialized(
            sk.security_level(),
            &ml_sk_bytes,
            &pk.ml_kem_pk,
            &ec_bytes,
        )
        .expect("from_serialized");
        assert!(
            bool::from(sk.ct_eq(&sk_copy)),
            "a hybrid secret key must ct_eq a byte-for-byte reconstruction of itself",
        );
        // Symmetry on the equal case.
        assert!(bool::from(sk_copy.ct_eq(&sk)), "ct_eq must be symmetric on equal keys");
    }

    #[test]
    fn test_hybrid_secret_key_ct_eq_distinct_keys_are_not_equal() {
        let (_pk_a, sk_a) = generate_keypair().unwrap();
        let (_pk_b, sk_b) = generate_keypair().unwrap();
        assert!(
            !bool::from(sk_a.ct_eq(&sk_b)),
            "two independently generated secret keys must not ct_eq",
        );
        // Symmetry: ct_eq is commutative. Locked in here because the
        // existing impl is XOR-based and could regress if rewritten.
        assert_eq!(
            bool::from(sk_a.ct_eq(&sk_b)),
            bool::from(sk_b.ct_eq(&sk_a)),
            "ct_eq must be symmetric",
        );
    }

    #[test]
    fn test_hybrid_secret_key_ct_eq_different_security_levels() {
        let (_pk_768, sk_768) = generate_keypair_with_level(MlKemSecurityLevel::MlKem768).unwrap();
        let (_pk_1024, sk_1024) =
            generate_keypair_with_level(MlKemSecurityLevel::MlKem1024).unwrap();
        assert!(
            !bool::from(sk_768.ct_eq(&sk_1024)),
            "ML-KEM-768 and ML-KEM-1024 secret keys must not ct_eq",
        );
    }

    #[test]
    fn test_hybrid_secret_key_ct_eq_differing_ml_kem_key_not_equal() {
        // Same level + same ECDH seed + different ML-KEM key must not ct_eq.
        // Guarantees the ml_match leg is load-bearing — a regression that
        // drops ml_match would still pass level_match and ec_match and
        // incorrectly report equality.
        let (_pk_a, sk_a) = generate_keypair().unwrap();
        let (pk_b, sk_b) = generate_keypair().unwrap();
        let ec_a = sk_a.ecdh_seed_bytes().unwrap();

        // Rebuild sk_b with sk_a's ECDH seed and its own ML-KEM key.
        let ml_sk_b = sk_b.ml_kem_sk_bytes().unwrap();
        let sk_b_with_a_ec = HybridKemSecretKey::from_serialized(
            sk_b.security_level(),
            &ml_sk_b,
            &pk_b.ml_kem_pk,
            &ec_a,
        )
        .expect("from_serialized");

        // The two keys now share level + ECDH seed but differ in ML-KEM.
        assert!(
            !bool::from(sk_a.ct_eq(&sk_b_with_a_ec)),
            "secret keys with differing ML-KEM halves must not ct_eq",
        );
    }

    #[test]
    fn test_hybrid_secret_key_ct_eq_differing_ecdh_seed_not_equal() {
        let (pk, sk_a) = generate_keypair().unwrap();
        let ml_sk_bytes = sk_a.ml_kem_sk_bytes().unwrap();
        let ec_a = sk_a.ecdh_seed_bytes().unwrap();
        let mut ec_b = *ec_a;
        ec_b[0] ^= 0x01;
        let sk_b = HybridKemSecretKey::from_serialized(
            sk_a.security_level(),
            &ml_sk_bytes,
            &pk.ml_kem_pk,
            &ec_b,
        )
        .expect("from_serialized with flipped ECDH seed");
        assert!(
            !bool::from(sk_a.ct_eq(&sk_b)),
            "secret keys with differing ECDH seeds must not ct_eq",
        );
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
    fn test_hybrid_kem_error_clone_round_trips() {
        let err1 = HybridKemError::MlKemError("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1.to_string(), err2.to_string());
        assert!(matches!(err2, HybridKemError::MlKemError(_)));
        assert!(!matches!(err1, HybridKemError::EcdhError(_)));
    }

    #[test]
    fn test_derive_different_static_pk_changes_output_succeeds() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 32];
        let static_pk1 = vec![3u8; 32];
        let static_pk2 = vec![4u8; 32];
        let ephemeral_pk = vec![5u8; 32];

        let secret1 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk1,
            ml_kem_static_pk: &static_pk1,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        })
        .unwrap();
        let secret2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk2,
            ml_kem_static_pk: &static_pk2,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        })
        .unwrap();

        assert!(
            !bool::from(secret1.ct_eq(&secret2)),
            "Different static PKs should produce different secrets"
        );
    }

    #[test]
    fn test_derive_different_ephemeral_pk_changes_output_succeeds() {
        let ml_kem_ss = vec![1u8; 32];
        let ecdh_ss = vec![2u8; 32];
        let static_pk = vec![3u8; 32];
        let eph1 = vec![4u8; 32];
        let eph2 = vec![5u8; 32];

        let secret1 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &eph1,
            kem_ct: &[],
        })
        .unwrap();
        let secret2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &eph2,
            kem_ct: &[],
        })
        .unwrap();

        assert!(
            !bool::from(secret1.ct_eq(&secret2)),
            "Different ephemeral PKs should produce different secrets"
        );
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
            secret2.expose_secret(),
            enc2.shared_secret.expose_secret(),
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
        // Pattern 6 (#49): encapsulate collapses every failure path into
        // EncapsulationFailed so the call site cannot tell whether the
        // ML-KEM PK or the ECDH PK was the malformed component.
        assert!(matches!(err, HybridKemError::EncapsulationFailed));
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
            shared_secret: crate::types::SecretBytes::zero(),
        };

        let result = decapsulate(&sk, &ct);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Pattern 6 opacity: every decap failure path collapses to
        // `DecapsulationFailed`. The specific reason ("ECDH ephemeral PK
        // wrong length") is intentionally hidden so the API cannot serve
        // as a length/padding/MAC oracle.
        assert!(matches!(err, HybridKemError::DecapsulationFailed));
    }

    #[test]
    fn test_decapsulate_invalid_ml_kem_ct_length_returns_error() {
        let (_pk, sk) = generate_keypair().unwrap();

        let ct = EncapsulatedKey {
            ml_kem_ct: vec![0u8; 100], // Wrong length (should be 1088)
            ecdh_pk: vec![0u8; 32],
            shared_secret: crate::types::SecretBytes::zero(),
        };

        let result = decapsulate(&sk, &ct);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Pattern 6 opacity: ML-KEM ciphertext length errors are also
        // collapsed to `DecapsulationFailed` to deny any oracle.
        assert!(matches!(err, HybridKemError::DecapsulationFailed));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ml_kem_length_returns_error() {
        let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &[0u8; 16],
            ecdh_ss: &[0u8; 32],
            ecdh_static_pk: &[0u8; 32],
            ml_kem_static_pk: &[0u8; 32],
            ephemeral_pk: &[0u8; 32],
            kem_ct: &[],
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ML-KEM"));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_invalid_ecdh_length_returns_error() {
        let result = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &[0u8; 32],
            ecdh_ss: &[0u8; 16],
            ecdh_static_pk: &[0u8; 32],
            ml_kem_static_pk: &[0u8; 32],
            ephemeral_pk: &[0u8; 32],
            kem_ct: &[],
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ECDH"));
    }

    #[test]
    fn test_derive_hybrid_shared_secret_is_deterministic() {
        let ml_kem_ss = [0xAA; 32];
        let ecdh_ss = [0xBB; 32];
        let static_pk = [0xCC; 32];
        let ephemeral_pk = [0xDD; 32];

        let s1 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        })
        .unwrap();
        let s2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &ephemeral_pk,
            kem_ct: &[],
        })
        .unwrap();
        assert!(bool::from(s1.ct_eq(&s2)), "Same inputs must produce same output");
        assert_eq!(s1.len(), 64);
    }

    #[test]
    fn test_derive_hybrid_shared_secret_different_inputs_differ_succeeds() {
        let ml_kem_ss = [0xAA; 32];
        let ecdh_ss = [0xBB; 32];
        let static_pk = [0xCC; 32];
        let eph1 = [0xDD; 32];
        let eph2 = [0xEE; 32];

        let s1 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &eph1,
            kem_ct: &[],
        })
        .unwrap();
        let s2 = derive_hybrid_shared_secret(HybridSharedSecretInputs {
            ml_kem_ss: &ml_kem_ss,
            ecdh_ss: &ecdh_ss,
            ecdh_static_pk: &static_pk,
            ml_kem_static_pk: &static_pk,
            ephemeral_pk: &eph2,
            kem_ct: &[],
        })
        .unwrap();
        assert!(
            !bool::from(s1.ct_eq(&s2)),
            "Different ephemeral PKs must produce different secrets"
        );
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
        // Pattern 6 (TOFU follow-up): see
        // `test_encapsulate_invalid_ecdh_pk_length_returns_error` note.
        assert!(matches!(result.unwrap_err(), HybridKemError::EncapsulationFailed));
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
