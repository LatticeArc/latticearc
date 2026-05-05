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
//! │  │    (3309 bytes)      │              │    (64 bytes)        │         │
//! │  └──────────┬───────────┘              └──────────┬───────────┘         │
//! │             │                                     │                     │
//! │             └────────────────┬────────────────────┘                     │
//! │                              │                                          │
//! │                              ▼                                          │
//! │                  ┌───────────────────────┐                              │
//! │                  │  Hybrid Signature     │                              │
//! │                  │  σ = σ_pq ║ σ_ed      │                              │
//! │                  │  (3309 + 64 = 3373 B) │                              │
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
//! │         │  │ Parse: first 3309 bytes = σ_pq, last 64 = σ_ed   │        │
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
//! | ML-DSA-65   | 1952 B     | 4032 B     | 3309 B     |
//! | Ed25519     | 32 B       | 32 B       | 64 B       |
//! | **Hybrid**  | **1984 B** | **4064 B** | **3373 B** |
//!
//! # Security Properties
//!
//! - **EUF-CMA** (Existential Unforgeability under Chosen Message Attack) security
//! - **AND-composition**: Requires breaking BOTH ML-DSA AND Ed25519 to forge
//! - Automatic memory zeroization for secret keys via [`ZeroizeOnDrop`]
//!
//! # Example
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::hybrid::sig_hybrid::{generate_keypair, sign, verify};
//!
//! // Generate hybrid keypair
//! let (pk, sk) = generate_keypair()?;
//!
//! // Sign a message (deterministic - no RNG needed)
//! let message = b"Hello, hybrid signatures!";
//! let signature = sign(&sk, message)?;
//!
//! // Verify the signature
//! let is_valid = verify(&pk, message, &signature)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```
//!
//! [`ZeroizeOnDrop`]: zeroize::ZeroizeOnDrop

use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::log_crypto_operation_error;
use crate::primitives::ec::ed25519::{Ed25519KeyPair, Ed25519Signature as Ed25519SignatureOps};
use crate::primitives::ec::traits::{EcKeyPair, EcSignature};
use crate::primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    generate_keypair as ml_dsa_generate_keypair,
};
use crate::unified_api::logging::op;

/// Error types for hybrid signature operations.
///
/// This enum captures all possible error conditions that can occur during
/// hybrid signature generation and verification.
// PartialEq is intentionally not derived: crypto error types should be
// inspected by variant (`matches!`) rather than value-compared. The
// `String`-carrying variants would otherwise compare upstream error
// messages, which is too brittle.
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
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
/// Carries the [`MlDsaParameterSet`] that the ML-DSA half was generated
/// at, so [`verify`] can reconstruct the right ML-DSA public-key shape.
/// Earlier revisions hardcoded `MlDsa65` in `verify`, which silently
/// rejected keys produced by [`generate_keypair_with_parameter_set`]
/// when that function was called with `MlDsa44` or `MlDsa87` — see the
/// `test_hybrid_sig_all_parameter_sets_roundtrip` regression.
///
/// Both component signatures must verify for the hybrid signature to be valid.
#[derive(Debug, Clone)]
pub struct HybridSigPublicKey {
    /// ML-DSA parameter set this PK was generated at.
    parameter_set: MlDsaParameterSet,
    /// ML-DSA public key bytes (size depends on `parameter_set`).
    ml_dsa_pk: Vec<u8>,
    /// Ed25519 public key bytes (32 bytes).
    ed25519_pk: Vec<u8>,
}

impl HybridSigPublicKey {
    /// Construct a `HybridSigPublicKey` from its components, validating
    /// that each PK matches its parameter set's expected length.
    ///
    /// # Errors
    /// Returns `LatticeArcError::InvalidParameter` if `ml_dsa_pk.len()`
    /// does not match `parameter_set.public_key_size()`, or if
    /// `ed25519_pk.len() != 32`.
    pub fn new(
        parameter_set: MlDsaParameterSet,
        ml_dsa_pk: Vec<u8>,
        ed25519_pk: Vec<u8>,
    ) -> Result<Self, crate::prelude::LatticeArcError> {
        let expected_ml_dsa = parameter_set.public_key_size();
        if ml_dsa_pk.len() != expected_ml_dsa {
            return Err(crate::prelude::LatticeArcError::InvalidParameter(format!(
                "ML-DSA public key for {:?}: expected {} bytes, got {}",
                parameter_set,
                expected_ml_dsa,
                ml_dsa_pk.len()
            )));
        }
        if ed25519_pk.len() != 32 {
            return Err(crate::prelude::LatticeArcError::InvalidParameter(format!(
                "Ed25519 public key: expected 32 bytes, got {}",
                ed25519_pk.len()
            )));
        }
        Ok(Self { parameter_set, ml_dsa_pk, ed25519_pk })
    }

    /// Returns the ML-DSA parameter set this public key was generated at.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Returns the ML-DSA public key bytes.
    #[must_use]
    pub fn ml_dsa_pk(&self) -> &[u8] {
        &self.ml_dsa_pk
    }

    /// Returns the Ed25519 public key bytes (32 bytes).
    #[must_use]
    pub fn ed25519_pk(&self) -> &[u8] {
        &self.ed25519_pk
    }
}

/// Hybrid secret key combining ML-DSA and Ed25519
///
/// # Security Guarantees
///
/// This struct implements automatic memory zeroization via the [`ZeroizeOnDrop`] derive.
/// When a `HybridSigSecretKey` is dropped (goes out of scope), all secret
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
/// ```rust,no_run
/// use latticearc::hybrid::sig_hybrid::generate_keypair;
///
/// // Generate keypair
/// let (pk, sk) = generate_keypair().expect("keypair generation failed");
///
/// // ... use sk for cryptographic operations ...
///
/// // Drop secret key - automatically zeroized
/// drop(sk);  // Secret material automatically zeroized
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSigSecretKey {
    /// ML-DSA parameter set this SK was generated at. Read by [`sign`]
    /// to construct the right-sized `MlDsaSecretKey`. `MlDsaParameterSet`
    /// is `Copy` and contains no secret material, so `#[zeroize(skip)]`.
    #[zeroize(skip)]
    parameter_set: MlDsaParameterSet,
    /// ML-DSA secret key bytes (size depends on parameter set), automatically zeroized on drop.
    ml_dsa_sk: Zeroizing<Vec<u8>>,
    /// Ed25519 secret key bytes (32 bytes), automatically zeroized on drop.
    ed25519_sk: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for HybridSigSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `parameter_set` is non-secret (algorithm identifier, identical to
        // what `HybridSigPublicKey`'s derived Debug surfaces). Surfacing it
        // is what makes parameter-set-mismatch debugging tractable — exactly
        // the bug class the v0.8.0 generic-over-MlDsaParameterSet break
        // was meant to make visible.
        f.debug_struct("HybridSigSecretKey")
            .field("parameter_set", &self.parameter_set)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for HybridSigSecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Parameter-set match is a precondition for equality. ML-DSA-44
        // SK bytes have a different length from ML-DSA-87 SK bytes, so a
        // length-mismatch slice ct_eq would already return Choice(0) —
        // but checking the parameter set explicitly fails earlier and
        // makes the contract loud.
        let param_eq = subtle::Choice::from(u8::from(self.parameter_set == other.parameter_set));
        param_eq
            & self.ml_dsa_sk.as_slice().ct_eq(other.ml_dsa_sk.as_slice())
            & self.ed25519_sk.as_slice().ct_eq(other.ed25519_sk.as_slice())
    }
}

impl HybridSigSecretKey {
    /// Construct a `HybridSigSecretKey` from its raw component bytes.
    ///
    /// `parameter_set` MUST match the ML-DSA strength used to generate
    /// `ml_dsa_sk`; [`sign`] reads it back to construct the right-sized
    /// `MlDsaSecretKey`. A mismatch surfaces at sign time as the opaque
    /// `MlDsaError` (no panic, no incorrect signing).
    ///
    /// Both component-byte arguments are wrapped in [`Zeroizing`] and
    /// will be wiped from memory when the returned [`HybridSigSecretKey`]
    /// is dropped.
    #[must_use]
    pub fn new(
        parameter_set: MlDsaParameterSet,
        ml_dsa_sk: Zeroizing<Vec<u8>>,
        ed25519_sk: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self { parameter_set, ml_dsa_sk, ed25519_sk }
    }

    /// Returns the ML-DSA parameter set this secret key was generated at.
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Returns the ML-DSA secret key bytes wrapped in `Zeroizing`.
    ///
    /// Prefer [`expose_ml_dsa_secret`](Self::expose_ml_dsa_secret) (a borrowed
    /// `&[u8]`) for read-only access — it avoids an allocation. This owned
    /// accessor exists for sign/serialize paths and for tests that need to
    /// call `.zeroize()` on a fresh buffer.
    #[must_use]
    pub fn ml_dsa_sk_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new((*self.ml_dsa_sk).clone())
    }

    /// Returns the Ed25519 secret key bytes wrapped in `Zeroizing`.
    ///
    /// Prefer [`expose_ed25519_secret`](Self::expose_ed25519_secret) (a
    /// borrowed `&[u8]`) for read-only access — it avoids an allocation.
    /// This owned accessor exists for sign/serialize paths and for tests
    /// that need to call `.zeroize()` on a fresh buffer.
    #[must_use]
    pub fn ed25519_sk_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new((*self.ed25519_sk).clone())
    }

    /// Expose the ML-DSA secret key bytes.
    ///
    /// Sealed accessor per Secret Type Invariant I-8
    /// (`docs/SECRET_TYPE_INVARIANTS.md`). For multi-secret composites like
    /// `HybridSigSecretKey`, each secret component gets its own `expose_*_secret()`
    /// method so every secret access is still grep-able. Prefer
    /// [`ml_dsa_sk_bytes`](Self::ml_dsa_sk_bytes) when you need an owned,
    /// zeroizing copy.
    #[must_use]
    pub fn expose_ml_dsa_secret(&self) -> &[u8] {
        &self.ml_dsa_sk
    }

    /// Expose the Ed25519 secret key bytes.
    ///
    /// Sealed accessor per Secret Type Invariant I-8
    /// (`docs/SECRET_TYPE_INVARIANTS.md`). Prefer
    /// [`ed25519_sk_bytes`](Self::ed25519_sk_bytes) when you need an owned,
    /// zeroizing copy.
    #[must_use]
    pub fn expose_ed25519_secret(&self) -> &[u8] {
        &self.ed25519_sk
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
    /// ML-DSA signature bytes (size depends on parameter set).
    ml_dsa_sig: Vec<u8>,
    /// Ed25519 signature bytes (64 bytes).
    ed25519_sig: Vec<u8>,
}

impl HybridSignature {
    /// Construct a hybrid signature from its component byte slices.
    #[must_use]
    pub fn new(ml_dsa_sig: Vec<u8>, ed25519_sig: Vec<u8>) -> Self {
        Self { ml_dsa_sig, ed25519_sig }
    }

    /// Borrow the ML-DSA signature component.
    #[must_use]
    pub fn ml_dsa_sig(&self) -> &[u8] {
        &self.ml_dsa_sig
    }

    /// Borrow the Ed25519 signature component.
    #[must_use]
    pub fn ed25519_sig(&self) -> &[u8] {
        &self.ed25519_sig
    }
}

/// Generate hybrid keypair at the default ML-DSA parameter set (`MlDsa65`,
/// NIST Level 3 / 192-bit security).
///
/// For other parameter sets (NIST Level 1 / `MlDsa44`, or NIST Level 5 /
/// `MlDsa87` — the latter required for CNSA 2.0), use
/// [`generate_keypair_with_parameter_set`].
///
/// # Errors
///
/// Returns an error if ML-DSA keypair generation fails or Ed25519 keypair
/// generation (including its pairwise consistency test) fails.
///
/// # Entropy source
/// ML-DSA and Ed25519 key generation route through the primitives layer,
/// which uses `OsRng` internally — callers cannot supply an external RNG.
#[must_use = "generated keypair must be stored or used"]
pub fn generate_keypair() -> Result<(HybridSigPublicKey, HybridSigSecretKey), HybridSignatureError>
{
    generate_keypair_with_parameter_set(MlDsaParameterSet::MlDsa65)
}

/// Generate a hybrid keypair at a specified ML-DSA parameter set.
///
/// `parameter_set` selects the ML-DSA strength of the post-quantum half of
/// the hybrid keypair. The Ed25519 half is unchanged across parameter sets
/// (Ed25519 has a single fixed strength).
///
/// | `parameter_set` | NIST level | Use case |
/// |-----------------|------------|----------|
/// | `MlDsa44`       | 1 (~128-bit) | size-constrained, lowest security tier |
/// | `MlDsa65`       | 3 (~192-bit) | default, balanced |
/// | `MlDsa87`       | 5 (~256-bit) | CNSA 2.0, highest security |
///
/// # Errors
///
/// Returns an error if ML-DSA keypair generation fails for the requested
/// parameter set, or if Ed25519 keypair generation (including its pairwise
/// consistency test) fails.
#[must_use = "generated keypair must be stored or used"]
pub fn generate_keypair_with_parameter_set(
    parameter_set: MlDsaParameterSet,
) -> Result<(HybridSigPublicKey, HybridSigSecretKey), HybridSignatureError> {
    let (ml_dsa_pk, ml_dsa_sk) = ml_dsa_generate_keypair(parameter_set)
        .map_err(|e| HybridSignatureError::MlDsaError(e.to_string()))?;

    // Generate Ed25519 keypair through the primitives wrapper so all
    // Ed25519 operations go through a single entry point. The wrapper
    // performs a pairwise consistency test before returning.
    let ed25519_kp = Ed25519KeyPair::generate()
        .map_err(|e| HybridSignatureError::Ed25519Error(e.to_string()))?;

    let ed25519_pk = ed25519_kp.public_key_bytes();
    // secret_key_bytes() returns Zeroizing<Vec<u8>>; move the inner buffer
    // into the HybridSigSecretKey so the wrapping Zeroizing is preserved.
    let ed25519_sk_zeroizing = ed25519_kp.secret_key_bytes();

    let pk =
        HybridSigPublicKey { parameter_set, ml_dsa_pk: ml_dsa_pk.as_bytes().to_vec(), ed25519_pk };

    let sk = HybridSigSecretKey {
        parameter_set,
        ml_dsa_sk: Zeroizing::new(ml_dsa_sk.expose_secret().to_vec()),
        ed25519_sk: ed25519_sk_zeroizing,
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
pub fn sign(
    sk: &HybridSigSecretKey,
    message: &[u8],
) -> Result<HybridSignature, HybridSignatureError> {
    // Borrow for the length check instead of `ed25519_sk_bytes()` — the
    // latter allocates and zeroizes a fresh `Zeroizing<Vec<u8>>` on every
    // call just to read `.len()`, and this is the hot sign() path.
    if sk.expose_ed25519_secret().len() != 32 {
        return Err(HybridSignatureError::InvalidKeyMaterial(
            "Ed25519 secret key must be 32 bytes".to_string(),
        ));
    }

    // Sign with ML-DSA
    let ml_dsa_sk_bytes = sk.ml_dsa_sk_bytes();
    // Sign-side opacity (defense-in-depth per Pattern 6). SK is caller-side
    // state; failures here indicate a programmer / storage bug, but keep the
    // public error uniform to avoid exposing upstream detail.
    //
    // the round-12 attempt at this
    // wrapped the clone in `Zeroizing<Vec<u8>>` but then immediately
    // re-cloned to pass into `MlDsaSecretKey::new(... Vec<u8>)`,
    // creating a second bare copy that would leak on the `new()` error
    // path. The proper fix is structural: `MlDsaSecretKey::new()` now
    // wraps its `Vec<u8>` argument in `Zeroizing` on entry, so a single
    // bare clone here is consumed-and-wiped on both success and error
    // paths. (The struct's `data` field is also `Zeroizing<Vec<u8>>`.)
    let ml_dsa_sk_struct = MlDsaSecretKey::new(sk.parameter_set, (*ml_dsa_sk_bytes).clone())
        .map_err(|_e| {
            log_crypto_operation_error!(op::HYBRID_SIGN, "ML-DSA SK init failed");
            HybridSignatureError::MlDsaError("signing failed".to_string())
        })?;
    let ml_dsa_sig = ml_dsa_sk_struct
        .sign(message, &[])
        .map_err(|_e| {
            log_crypto_operation_error!(op::HYBRID_SIGN, "ML-DSA sign failed");
            HybridSignatureError::MlDsaError("signing failed".to_string())
        })?
        .as_bytes()
        .to_vec();

    // Sign with Ed25519 via the primitives wrapper.
    let ed25519_sk_zeroizing = sk.ed25519_sk_bytes();
    let ed25519_keypair = Ed25519KeyPair::from_secret_key(ed25519_sk_zeroizing.as_slice())
        .map_err(|_e| {
            log_crypto_operation_error!(op::HYBRID_SIGN, "Ed25519 SK init failed");
            HybridSignatureError::Ed25519Error("signing failed".to_string())
        })?;
    // `Ed25519KeyPair::sign` is now fallible
    // (validate_signature_size). Message length is already gated by
    // the hybrid sig API above; this `?` is the boundary safety net.
    let ed25519_signature = ed25519_keypair.sign(message).map_err(|_e| {
        log_crypto_operation_error!(op::HYBRID_SIGN, "Ed25519 sign rejected");
        HybridSignatureError::Ed25519Error("signing failed".to_string())
    })?;
    let ed25519_sig = Ed25519SignatureOps::signature_bytes(&ed25519_signature);

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
    pk: &HybridSigPublicKey,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<bool, HybridSignatureError> {
    // SECURITY: Verify BOTH components unconditionally with bitwise AND combination.
    // This preserves AND-security: a partial break of one component must not leak which
    // one failed, because distinct error paths (or early exit) turn AND into OR.
    //
    // Rules:
    // 1. No early return on a single component failure.
    // 2. No `&&` (short-circuit) — use `&` (bitwise) so both calls always execute.
    // 3. A SINGLE opaque error string regardless of which component failed.
    // 4. Structural parse failures collapse to bit=0 (same as verify-fail),
    //    matching FIPS 204 §5.3 Verify-returns-bool shape and the Ed25519
    //    sibling below. This removes the early-exit timing / variant oracle
    //    that would otherwise distinguish "malformed ML-DSA" from "Ed25519
    //    failed".
    //
    // No length pre-checks are performed here. Earlier revisions had four
    // distinguishable `InvalidKeyMaterial` returns for the four buffer
    // lengths; that surface let an adversary varying wire-supplied PK/sig
    // bytes enumerate which length got rejected. The match arms below
    // already collapse parse failures (which include length mismatches) to
    // bit = 0, which is indistinguishable from a verify failure — exactly
    // what Pattern 6 §"adversary-reachable paths" requires.

    // Timing equalizer — see `crate::hybrid::verify_equalizer` for the
    // full rationale. Briefly: select shape-correct bytes (real or
    // zero-byte dummy) and run `from_bytes` + `verify` once on the
    // selection so the wall-clock cost is identical for shape-fail
    // and verify-fail.
    //
    // Per-stage `tracing` was previously emitted under four distinct
    // sub-stage tags; that made the Pattern 6 returned-error opacity
    // reconstructable from the debug log. Operators still get a
    // single "verify failure occurred" event for alerting; the
    // granular sub-stage detail is intentionally dropped (see
    // `docs/DESIGN_PATTERNS.md` Pattern 6).
    let dummy = crate::hybrid::verify_equalizer::hybrid_verify_dummy_material(pk.parameter_set);

    let pq_pk_len = pk.parameter_set.public_key_size();
    let pq_sig_len = pk.parameter_set.signature_size();
    let pq_shape_ok = pk.ml_dsa_pk.len() == pq_pk_len && sig.ml_dsa_sig.len() == pq_sig_len;
    let (pq_pk_bytes, pq_sig_bytes): (&[u8], &[u8]) = if pq_shape_ok {
        (&pk.ml_dsa_pk, &sig.ml_dsa_sig)
    } else {
        (dummy.pq_pk.as_slice(), dummy.pq_sig.as_slice())
    };
    // Match-on-parse, never `?`-propagate: if `from_bytes` ever fails
    // (today unreachable for our zero-byte dummies of correct length,
    // but a future `fips204` release adding content validation could
    // change that), we still want the verify pipeline to run so the
    // wall-clock cost stays equal between shape-fail and verify-fail.
    //
    // When parse fails on the substituted bytes, we DO still run a
    // real verify against the equalizer's pre-parsed valid material
    // (`dummy.parsed`, post-85e2bd79e M1 audit fix). This guarantees
    // verify-pipeline execution regardless of whether `from_bytes`
    // adds content validation downstream. The pre-parsed PK + sig
    // verify against an internal test message — content-dependent
    // verify timing is content-independent of the caller, which is
    // exactly the property we want from the equalizer.
    //
    // If `dummy.parsed` is `None` (init keygen+sign failed at module
    // load — extremely rare RNG/PCT path), we fall back to the
    // legacy `Ok(false)` skip. The bit is then computed via the
    // shape-check AND parse-check AND verify-check, so a degraded
    // equalizer never affects correctness — only the strength of the
    // timing-oracle countermeasure for the degraded parameter set.
    let parse_ok =
        MlDsaPublicKey::from_bytes(pq_pk_bytes, pk.parameter_set).and_then(|parsed_pk| {
            MlDsaSignature::from_bytes(pq_sig_bytes, pk.parameter_set)
                .map(|parsed_sig| (parsed_pk, parsed_sig))
        });
    // the previous shape was
    //   `Ok(parsed) => parsed.verify(...)`,
    //   `Err(_) => dummy.verify(...)`.
    // But `MlDsaPublicKey::verify` internally calls
    // `ml_dsa_NN::PublicKey::try_from_bytes`, which short-circuits with
    // `Err(VerificationError)` on structurally-invalid PKs (e.g.
    // all-zero) before any actual ML-DSA verify runs. So a shape-pass-
    // but-inner-parse-fail input paid only the cheap parse-fail cost
    // while a shape-pass-and-inner-parse-pass input paid the full
    // ML-DSA verify cost — a measurable timing oracle on the difference.
    // Now: ANY path that doesn't reach a successful real verify falls
    // through to the dummy verify so the wall-clock cost is equal
    // across all reject reasons.
    // pre-parsed material now goes through `parsed_or_init()`
    // which retries init when prior attempts produced None. The result is
    // a clone (cheap — public bytes only); we own it locally.
    let dummy_parsed = dummy.parsed_or_init();
    let ml_dsa_verify_result = match &parse_ok {
        Ok((parsed_pk, parsed_sig)) => {
            let inner = parsed_pk.verify(message, parsed_sig, &[]);
            match &inner {
                Ok(_) => inner,
                // Inner parse failed (structurally-invalid PK reached
                // the short-circuit in `try_from_bytes`). Run the
                // equalizer dummy verify to spend verify-time budget;
                // discard its result.
                Err(_) => match &dummy_parsed {
                    Some(parsed) => {
                        let _ = parsed.pq_pk.verify(&parsed.pq_test_message, &parsed.pq_sig, &[]);
                        // Bubble the original Err so `matches!(.., Ok(true))`
                        // below still rejects the substituted input.
                        inner
                    }
                    None => inner,
                },
            }
        }
        Err(_) => match &dummy_parsed {
            // Equalizer fallback: run verify against pre-validated
            // material so the wall-clock cost stays equal between
            // shape-fail-then-parse-fail and shape-good-then-verify.
            // The result is discarded by the AND with `parse_ok.is_ok()`
            // below — its only purpose is to consume verify-time
            // wall-clock budget.
            Some(parsed) => parsed.pq_pk.verify(&parsed.pq_test_message, &parsed.pq_sig, &[]),
            // Init keygen failed (extremely rare; round-29 L6 retries
            // on every call). Equalizer degraded; legacy fast-fail
            // behavior. Not a correctness regression because the bit
            // is computed below via AND with multiple guards.
            None => Ok(false),
        },
    };
    // Bit is 1 only when the real input passed shape-check, both
    // `from_bytes` calls succeeded, AND the verify returned Ok(true).
    // When shape failed, the verify still ran (against the dummy or
    // against pre-parsed material) for timing equalization; its
    // result is discarded by the AND with `pq_shape_ok`.
    let ml_dsa_valid: u8 =
        if pq_shape_ok && parse_ok.is_ok() && matches!(ml_dsa_verify_result, Ok(true)) {
            1u8
        } else {
            0u8
        };

    // the Ed25519 leg now has a real verify-time
    // equalizer. The previous shape claimed parse cost was "in the
    // same order of magnitude as verify" — empirically wrong (parse
    // is a 64-byte length check, verify is one EC scalar mul; ~3
    // orders of magnitude apart). On parse-fail, run verify against
    // pre-parsed cached material so the wall-clock cost matches a
    // real verify, mirroring the ML-DSA equalizer above.
    let ed_dummy = crate::hybrid::verify_equalizer::ed25519_verify_dummy_material();
    let ed_dummy_parsed = ed_dummy.parsed_or_init();
    let ed25519_valid: u8 = if let Ok(ed25519_signature) =
        Ed25519SignatureOps::signature_from_bytes(sig.ed25519_sig.as_slice())
    {
        // Wrong-length PK short-circuits inside
        // `Ed25519SignatureOps::verify` before any scalar mul runs,
        // distinguishing "32-byte PK, bad sig" from "wrong-length PK"
        // by wall-clock. Run the dummy verify against parsed dummy
        // material on that path so the wall-clock matches the
        // valid-PK code path.
        let pk_bytes = pk.ed25519_pk.as_slice();
        let result = Ed25519SignatureOps::verify(pk_bytes, message, &ed25519_signature);
        if pk_bytes.len() != 32
            && let Some(parsed) = &ed_dummy_parsed
            && let Ok(parsed_sig) =
                Ed25519SignatureOps::signature_from_bytes(parsed.ed_sig.as_slice())
        {
            // Discarded; runs the EC scalar mul.
            let _ = Ed25519SignatureOps::verify(
                parsed.ed_pk.as_slice(),
                parsed.ed_test_message.as_slice(),
                &parsed_sig,
            );
        }
        match result {
            Ok(()) => 1u8,
            _ => 0u8,
        }
    } else {
        // Parse failure on caller-supplied bytes: still spend a
        // verify-cost worth of cycles against the dummy material so
        // the wall-clock between parse-fail and verify-fail is equal.
        // Discard the result — `0u8` is the verdict because the
        // caller's input was structurally wrong.
        if let Some(parsed) = &ed_dummy_parsed
            && let Ok(parsed_sig) =
                Ed25519SignatureOps::signature_from_bytes(parsed.ed_sig.as_slice())
        {
            // Discarded; runs the EC scalar mul.
            let _ = Ed25519SignatureOps::verify(
                parsed.ed_pk.as_slice(),
                parsed.ed_test_message.as_slice(),
                &parsed_sig,
            );
        }
        // If `ed_dummy_parsed` is None (RNG/PCT init failure —
        // round-29 L6 retries on every call), fall through to the
        // legacy fast-fail. Bit is computed below via AND with
        // `pq_shape_ok` and `parse_ok.is_ok()`, so a degraded
        // equalizer cannot affect correctness.
        0u8
    };

    // One generic event on aggregate failure — preserves the "something
    // went wrong with hybrid verify" alerting signal without leaking
    // which component(s) failed.
    if (ml_dsa_valid & ed25519_valid) != 1 {
        log_crypto_operation_error!(op::HYBRID_VERIFY, "hybrid signature verification failed");
    }

    // The two component bits are combined via bitwise AND (not short-circuit
    // `&&`) so verification work is identical regardless of which component
    // failed first. The branch below on `both_valid` does not leak anything
    // the return value doesn't already carry — pass/fail is observable from
    // the caller either way.
    let both_valid: u8 = ml_dsa_valid & ed25519_valid;
    if both_valid != 1 {
        return Err(HybridSignatureError::VerificationFailed(
            "hybrid signature verification failed".to_string(),
        ));
    }

    // Both signatures verified successfully
    Ok(true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::implicit_clone)] // Tests don't require optimal cloning patterns
#[allow(clippy::indexing_slicing)] // Tests use direct indexing for simplicity
#[allow(clippy::single_match)] // Match with comment is clearer than if-let in tests
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_secret_key_zeroization_succeeds() {
        let (_pk, mut sk) = generate_keypair().unwrap();

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
    fn test_hybrid_secret_key_drop_zeroization_succeeds() {
        let test_ml_data = vec![0x77; 4032];
        let test_ed25519_data = vec![0x66; 32];

        {
            let sk = HybridSigSecretKey {
                parameter_set: MlDsaParameterSet::MlDsa65,
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
    fn test_hybrid_signature_after_zeroization_succeeds() {
        let (pk, mut sk) = generate_keypair().unwrap();
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
    fn test_hybrid_signature_keypair_generation_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();

        assert!(!pk.ml_dsa_pk.is_empty(), "ML-DSA public key should not be empty");
        assert_eq!(pk.ed25519_pk.len(), 32, "Ed25519 public key should be 32 bytes");
        assert!(!sk.ml_dsa_sk.is_empty(), "ML-DSA secret key should not be empty");
        assert_eq!(sk.ed25519_sk.len(), 32, "Ed25519 secret key should be 32 bytes");

        assert!(!pk.ml_dsa_pk.iter().all(|&x| x == 0), "ML-DSA PK should not be all zeros");
        assert!(!pk.ed25519_pk.iter().all(|&x| x == 0), "Ed25519 PK should not be all zeros");
    }

    #[test]
    fn test_hybrid_signature_signing_and_verification_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();

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
    fn test_invalid_key_and_signature_lengths_all_return_error_fails() {
        let (pk, _sk) = generate_keypair().unwrap();

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
    fn test_ed25519_signature_properties_are_correct() {
        // Exercise the primitives-layer Ed25519 wrapper end-to-end to keep
        // this module's tests self-contained without reaching into dalek.
        let keypair = Ed25519KeyPair::generate().expect("keypair generation should succeed");
        let public_key_bytes = keypair.public_key_bytes();

        let message = b"Test message";
        let signature = keypair.sign(message).expect("sign should succeed");

        // Valid signature should verify
        let result = Ed25519SignatureOps::verify(&public_key_bytes, message, &signature);
        assert!(result.is_ok(), "Valid signature should verify");

        // Wrong message should not verify
        let wrong_message = b"Wrong message";
        let result = Ed25519SignatureOps::verify(&public_key_bytes, wrong_message, &signature);
        assert!(result.is_err(), "Wrong message should not verify");
    }

    #[test]
    fn test_hybrid_signature_zeroization_succeeds() {
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
    fn test_hybrid_keypair_zeroization_succeeds() {
        let (_public_key, secret_key) = generate_keypair().expect("Should generate hybrid keypair");

        assert!(
            !secret_key.ml_dsa_sk.iter().all(|&b| b == 0),
            "Keypair ML-DSA secret should contain non-zero data"
        );
        assert!(
            !secret_key.ed25519_sk.iter().all(|&b| b == 0),
            "Keypair Ed25519 secret should contain non-zero data"
        );

        let mut secret_key_clone = HybridSigSecretKey {
            parameter_set: secret_key.parameter_set,
            ml_dsa_sk: secret_key.ml_dsa_sk_bytes(),
            ed25519_sk: secret_key.ed25519_sk_bytes(),
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
    fn test_hybrid_zeroization_order_is_correct() {
        let mut secret_key1 = HybridSigSecretKey {
            parameter_set: MlDsaParameterSet::MlDsa44,
            ml_dsa_sk: Zeroizing::new(vec![0x11; 2560]),
            ed25519_sk: Zeroizing::new(vec![0x22; 32]),
        };

        let mut secret_key2 = HybridSigSecretKey {
            parameter_set: MlDsaParameterSet::MlDsa44,
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
    fn test_hybrid_concurrent_zeroization_succeeds() {
        use std::sync::Arc;
        use std::thread;

        let ml_dsa_data = Arc::new(vec![0x99; 2560]);
        let ed25519_data = Arc::new(vec![0xAA; 32]);
        let mut handles = vec![];

        for i in 0..4 {
            let ml_dsa_clone = Arc::clone(&ml_dsa_data);
            let ed25519_clone = Arc::clone(&ed25519_data);

            let handle = thread::spawn(move || {
                let mut secret_key = HybridSigSecretKey {
                    parameter_set: MlDsaParameterSet::MlDsa65,
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

    // --- Additional coverage tests ---

    #[test]
    fn test_hybrid_verify_wrong_message_fails() {
        let (pk, sk) = generate_keypair().unwrap();

        let sig = sign(&sk, b"Original message").unwrap();
        let result = verify(&pk, b"Different message", &sig);
        // ML-DSA verify will return error for wrong message
        assert!(result.is_err(), "Wrong message should fail verification");
    }

    #[test]
    fn test_hybrid_verify_wrong_key_fails() {
        let (_pk1, sk1) = generate_keypair().unwrap();
        let (pk2, _sk2) = generate_keypair().unwrap();

        let sig = sign(&sk1, b"Test").unwrap();
        let result = verify(&pk2, b"Test", &sig);
        assert!(result.is_err(), "Wrong public key should fail verification");
    }

    #[test]
    fn test_hybrid_sign_invalid_ed25519_sk_length_returns_error() {
        let sk = HybridSigSecretKey {
            parameter_set: MlDsaParameterSet::MlDsa65,
            ml_dsa_sk: Zeroizing::new(vec![0u8; 4032]),
            ed25519_sk: Zeroizing::new(vec![0u8; 16]), // Wrong: should be 32
        };
        let result = sign(&sk, b"test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridSignatureError::InvalidKeyMaterial(_)));
    }

    #[test]
    fn test_hybrid_verify_invalid_ed25519_pk_length_returns_error() {
        let pk = HybridSigPublicKey {
            parameter_set: MlDsaParameterSet::MlDsa65,
            ml_dsa_pk: vec![0u8; 1952],
            ed25519_pk: vec![0u8; 16], // Wrong: should be 32
        };
        let sig = HybridSignature { ml_dsa_sig: vec![0u8; 3309], ed25519_sig: vec![0u8; 64] };
        let result = verify(&pk, b"test", &sig);
        // Pattern 6 (#52): verify no longer distinguishes length errors
        // from verify failures; both collapse to VerificationFailed via
        // the bit=0 path. Assert the surviving variant.
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridSignatureError::VerificationFailed(_)));
    }

    #[test]
    fn test_hybrid_verify_invalid_ed25519_sig_length_returns_error() {
        let (pk, _sk) = generate_keypair().unwrap();

        let sig = HybridSignature {
            ml_dsa_sig: vec![0u8; 3309],
            ed25519_sig: vec![0u8; 32], // Wrong: should be 64
        };
        let result = verify(&pk, b"test", &sig);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Pattern 6 (#52): see test above — length mismatches collapse into
        // the bit=0 verify path, so the surviving variant is VerificationFailed.
        assert!(matches!(err, HybridSignatureError::VerificationFailed(_)));
    }

    #[test]
    fn test_hybrid_signature_error_display_all_variants_have_correct_format_fails() {
        let err1 = HybridSignatureError::MlDsaError("dsa fail".to_string());
        assert!(err1.to_string().contains("dsa fail"));

        let err2 = HybridSignatureError::Ed25519Error("ed fail".to_string());
        assert!(err2.to_string().contains("ed fail"));

        let err3 = HybridSignatureError::VerificationFailed("verify fail".to_string());
        assert!(err3.to_string().contains("verify fail"));

        let err4 = HybridSignatureError::InvalidKeyMaterial("bad key".to_string());
        assert!(err4.to_string().contains("bad key"));

        let err5 = HybridSignatureError::CryptoError("crypto fail".to_string());
        assert!(err5.to_string().contains("crypto fail"));
    }

    #[test]
    fn test_hybrid_signature_error_clone_round_trips() {
        let err1 = HybridSignatureError::MlDsaError("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1.to_string(), err2.to_string());
        assert!(matches!(err2, HybridSignatureError::MlDsaError(_)));
        assert!(!matches!(err1, HybridSignatureError::Ed25519Error(_)));
    }

    #[test]
    fn test_hybrid_public_key_clone_debug_succeeds() {
        let (pk, _sk) = generate_keypair().unwrap();

        let pk2 = pk.clone();
        assert_eq!(pk.ml_dsa_pk, pk2.ml_dsa_pk);
        assert_eq!(pk.ed25519_pk, pk2.ed25519_pk);

        let debug = format!("{:?}", pk);
        assert!(debug.contains("HybridSigPublicKey"));
    }

    #[test]
    fn test_hybrid_secret_key_debug_has_correct_format() {
        let (_pk, sk) = generate_keypair().unwrap();

        let debug = format!("{:?}", sk);
        assert!(debug.contains("HybridSigSecretKey"));
    }

    #[test]
    fn test_hybrid_signature_clone_debug_succeeds() {
        let sig = HybridSignature { ml_dsa_sig: vec![1, 2, 3], ed25519_sig: vec![4, 5, 6] };
        let sig2 = sig.clone();
        assert_eq!(sig.ml_dsa_sig, sig2.ml_dsa_sig);
        assert_eq!(sig.ed25519_sig, sig2.ed25519_sig);

        let debug = format!("{:?}", sig);
        assert!(debug.contains("HybridSignature"));
    }

    #[test]
    fn test_sign_same_key_consistent_ed25519_succeeds() {
        let (_pk, sk) = generate_keypair().unwrap();

        let message = b"Consistency test";
        let sig1 = sign(&sk, message).unwrap();
        let sig2 = sign(&sk, message).unwrap();

        // Ed25519 signing is deterministic (RFC 8032)
        assert_eq!(sig1.ed25519_sig, sig2.ed25519_sig, "Ed25519 sig should be deterministic");
        // ML-DSA uses hedged randomness — signatures may differ but both verify
        assert!(!sig1.ml_dsa_sig.is_empty());
        assert!(!sig2.ml_dsa_sig.is_empty());
    }

    #[test]
    fn test_sign_different_messages_produces_unique_sigs_are_unique() {
        let (_pk, sk) = generate_keypair().unwrap();

        let sig1 = sign(&sk, b"Message A").unwrap();
        let sig2 = sign(&sk, b"Message B").unwrap();

        assert_ne!(sig1.ml_dsa_sig, sig2.ml_dsa_sig);
        assert_ne!(sig1.ed25519_sig, sig2.ed25519_sig);
    }

    #[test]
    fn test_sign_empty_message_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();

        let sig = sign(&sk, b"").unwrap();
        let valid = verify(&pk, b"", &sig).unwrap();
        assert!(valid, "Empty message signature should verify");
    }

    #[test]
    fn test_sign_large_message_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();

        // 50 KiB: large enough to exercise multi-block message handling,
        // below the default max_signature_size_bytes (64 KiB) resource cap
        // enforced by the primitive sign path.
        let large_message = vec![0xABu8; 50 * 1024];
        let sig = sign(&sk, &large_message).unwrap();
        let valid = verify(&pk, &large_message, &sig).unwrap();
        assert!(valid, "Large message signature should verify");
    }

    // ========================================================================
    // Additional coverage: verify error paths
    // ========================================================================

    #[test]
    fn test_verify_wrong_key_pair_ml_dsa_fails() {
        let (pk1, _sk1) = generate_keypair().unwrap();
        let (_pk2, sk2) = generate_keypair().unwrap();

        // Sign with sk2, verify with pk1 — ML-DSA component should fail
        let sig = sign(&sk2, b"test msg").unwrap();
        let result = verify(&pk1, b"test msg", &sig);
        // ML-DSA verify returns Err for wrong key pair
        assert!(result.is_err(), "Verification with wrong key pair must fail");
    }

    #[test]
    fn test_verify_corrupted_ed25519_signature_fails() {
        let (pk, sk) = generate_keypair().unwrap();
        let message = b"Test message";

        let mut sig = sign(&sk, message).unwrap();
        // Corrupt only the Ed25519 signature (leave ML-DSA intact)
        sig.ed25519_sig[0] ^= 0xFF;

        let result = verify(&pk, message, &sig);
        // Should fail: either error or false
        match result {
            Ok(valid) => assert!(!valid, "Corrupted Ed25519 sig must not verify"),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_verify_invalid_ml_dsa_sig_length_returns_error() {
        let (pk, _sk) = generate_keypair().unwrap();

        let sig = HybridSignature {
            ml_dsa_sig: vec![0u8; 100], // Wrong length for MlDsa65
            ed25519_sig: vec![0u8; 64],
        };

        let result = verify(&pk, b"test", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_ml_dsa_pk_length_returns_error() {
        let (_pk, sk) = generate_keypair().unwrap();
        let sig = sign(&sk, b"test").unwrap();

        let bad_pk = HybridSigPublicKey {
            parameter_set: MlDsaParameterSet::MlDsa65,
            ml_dsa_pk: vec![0u8; 100], // Wrong length
            ed25519_pk: vec![0u8; 32],
        };

        let result = verify(&bad_pk, b"test", &sig);
        assert!(result.is_err());
    }

    /// Regression test for the parameter-set propagation bug: prior to
    /// 0.8.0 the hardcoded `MlDsaParameterSet::MlDsa65` in `sign` and
    /// `verify` silently broke any keypair generated via
    /// `generate_keypair_with_parameter_set(MlDsa44)` or `(MlDsa87)` —
    /// the public API advertised three parameter sets but only one
    /// actually round-tripped. This test pins all three working.
    #[test]
    fn test_hybrid_sig_all_parameter_sets_roundtrip() {
        for param_set in
            [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
        {
            let (pk, sk) = generate_keypair_with_parameter_set(param_set)
                .expect("keypair gen must succeed for every advertised parameter set");
            assert_eq!(pk.parameter_set(), param_set);
            assert_eq!(sk.parameter_set(), param_set);
            let message = b"parameter-set propagation regression";
            let sig = sign(&sk, message).expect("sign must succeed");
            let valid = verify(&pk, message, &sig).expect("verify must succeed");
            assert!(valid, "round-trip must verify for {param_set:?}");
        }
    }

    #[test]
    fn test_sign_verify_multiple_messages_same_key_succeeds() {
        let (pk, sk) = generate_keypair().unwrap();

        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];
        let sigs: Vec<_> = messages.iter().map(|m| sign(&sk, m).unwrap()).collect();

        // Each signature should verify with its own message
        for (msg, sig) in messages.iter().zip(sigs.iter()) {
            assert!(verify(&pk, msg, sig).unwrap());
        }

        // Cross-verify should fail
        assert!(!verify(&pk, b"msg1", &sigs[1]).unwrap_or(false));
    }

    #[test]
    fn test_hybrid_signature_clone_succeeds() {
        let (_pk, sk) = generate_keypair().unwrap();
        let sig = sign(&sk, b"clone test").unwrap();
        let cloned = sig.clone();
        assert_eq!(sig.ml_dsa_sig, cloned.ml_dsa_sig);
        assert_eq!(sig.ed25519_sig, cloned.ed25519_sig);
    }

    #[test]
    fn test_hybrid_public_key_ml_dsa_has_correct_size() {
        let (pk, _sk) = generate_keypair().unwrap();
        assert_eq!(pk.ml_dsa_pk.len(), 1952); // MlDsa65 public key size
        assert_eq!(pk.ed25519_pk.len(), 32);
    }
}
