#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: SLH-DSA has fixed-size keys/signatures per security level.
// All indexing is bounded by validated lengths checked before access.
// The fips205 crate handles the actual cryptographic operations.
#![allow(clippy::indexing_slicing)]

//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//!
//! This module provides SLH-DSA signatures as specified in FIPS 205.
//! All cryptographic operations use the audited `fips205` crate.
//!
//! # Security Levels
//!
//! - **SLH-DSA-SHAKE-128s**: NIST security level 1 (quantum security ~128 bits)
//! - **SLH-DSA-SHAKE-192s**: NIST security level 3 (quantum security ~192 bits)
//! - **SLH-DSA-SHAKE-256s**: NIST security level 5 (quantum security ~256 bits)
//!
//! # Example
//!
//! ```rust
//! use latticearc::primitives::sig::slh_dsa::{SlhDsaSecurityLevel, SigningKey, VerifyingKey};
//!
//! // Generate a key pair
//! let (signing_key, verifying_key) = SigningKey::generate(SlhDsaSecurityLevel::Shake128s)?;
//!
//! // Sign a message (None = no context string)
//! let message = b"Hello, SLH-DSA!";
//! let signature = signing_key.sign(message, &[])?;
//!
//! // Verify the signature (None = no context string)
//! let is_valid = verifying_key.verify(message, &signature, &[])?;
//! assert!(is_valid);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use fips205::slh_dsa_shake_128s as shake_128s;
use fips205::slh_dsa_shake_192s as shake_192s;
use fips205::slh_dsa_shake_256s as shake_256s;
use fips205::traits::{SerDes, Signer, Verifier};
use subtle::{Choice, ConstantTimeEq};
use tracing::instrument;
use zeroize::{Zeroize, Zeroizing};

use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in SLH-DSA operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlhDsaError {
    /// Random number generation failed
    #[error("Random number generation failed")]
    RngError,

    /// Pairwise Consistency Test (FIPS 140-3 §9.2 / IG 10.3.A) failed.
    /// Distinct from `RngError` because PCT failure indicates a
    /// corrupted keypair, not transient entropy depletion. Round-20
    /// audit fix #12: a FIPS error-state monitor must be able to
    /// distinguish "retry with fresh entropy" from "discard this
    /// keypair, generate a new one, and investigate."
    #[error("Pairwise Consistency Test failed (FIPS 140-3 §9.2)")]
    PctFailed,

    /// Invalid public key (malformed or corrupted)
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid secret key (malformed or corrupted)
    #[error("Invalid secret key")]
    InvalidSecretKey,

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    // `DeserializationError` removed — declared but never
    // returned by any production path. SLH-DSA byte-shape errors surface
    // as `InvalidPublicKey` / `InvalidSecretKey` / `VerificationFailed`.
    // Safe under `#[non_exhaustive]`: external matches must already have
    // a fallback arm, and no production code ever produced this variant.
    /// Context string too long (max 255 bytes)
    #[error("Context string too long (max 255 bytes)")]
    ContextTooLong,

    /// Message length exceeds the configured resource limit.
    ///
    /// SLH-DSA signing cost scales with message length; this guard prevents
    /// unbounded-message DoS when callers bypass the unified-api resource
    /// checks.
    ///
    /// kept for ABI compatibility but no longer returned from
    /// `sign()` — the cap-rejection now collapses to `SigningFailed` so
    /// the sign path matches Pattern 6 opacity (round-26 M1 closed the
    /// verify-side; this completes the sign-side symmetry). Will be
    /// removed in a future major bump alongside `DeserializationError`.
    #[deprecated(note = "Round-28 H7: sign() now returns SigningFailed for cap rejection; \
                this variant is no longer reachable from production code.")]
    #[error("Message exceeds signature resource limit")]
    MessageTooLong,

    /// Signing failed for an internal reason (resource cap, upstream
    /// error, etc.). Opaque per Pattern 6 — the specific cause is
    /// preserved via `tracing::debug!` for operator diagnostics.
    #[error("SLH-DSA signing failed")]
    SigningFailed,
}

// ============================================================================
// Security Levels
// ============================================================================

/// SLH-DSA security levels exposed by this crate.
///
/// FIPS 205 defines twelve parameter sets (`{SHAKE,SHA2} × {128,192,256} ×
/// {s,f}`). LatticeArc currently exposes only the three SHAKE-`s` variants
/// (small signatures, slower signing); the remaining nine — SHA2 hash
/// instantiation and the `f` (fast-signing, larger-signature) variants —
/// are not yet wired through the unified API. The enum is
/// `#[non_exhaustive]` so adding them later is a non-breaking change for
/// downstream `match` statements.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SlhDsaSecurityLevel {
    /// SLH-DSA-SHAKE-128s: NIST Level 1 (quantum security ~128 bits)
    /// Smaller keys and signatures, slower signing
    Shake128s = 1,

    /// SLH-DSA-SHAKE-192s: NIST Level 3 (quantum security ~192 bits)
    /// Balanced security and signing speed
    Shake192s = 2,

    /// SLH-DSA-SHAKE-256s: NIST Level 5 (quantum security ~256 bits)
    /// Highest security, larger keys and signatures, slower signing
    Shake256s = 3,
}

impl SlhDsaSecurityLevel {
    /// Returns the NIST security level (1-5)
    #[must_use]
    pub const fn nist_level(&self) -> u8 {
        match self {
            SlhDsaSecurityLevel::Shake128s => 1,
            SlhDsaSecurityLevel::Shake192s => 3,
            SlhDsaSecurityLevel::Shake256s => 5,
        }
    }

    /// Returns the public key size in bytes
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            SlhDsaSecurityLevel::Shake128s => shake_128s::PK_LEN,
            SlhDsaSecurityLevel::Shake192s => shake_192s::PK_LEN,
            SlhDsaSecurityLevel::Shake256s => shake_256s::PK_LEN,
        }
    }

    /// Returns the secret key size in bytes
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            SlhDsaSecurityLevel::Shake128s => shake_128s::SK_LEN,
            SlhDsaSecurityLevel::Shake192s => shake_192s::SK_LEN,
            SlhDsaSecurityLevel::Shake256s => shake_256s::SK_LEN,
        }
    }

    /// Returns the signature size in bytes
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            SlhDsaSecurityLevel::Shake128s => shake_128s::SIG_LEN,
            SlhDsaSecurityLevel::Shake192s => shake_192s::SIG_LEN,
            SlhDsaSecurityLevel::Shake256s => shake_256s::SIG_LEN,
        }
    }
}

// ============================================================================
// Verifying Key (Public Key)
// ============================================================================

/// SLH-DSA verifying key (public key)
///
/// Wrapper around the audited fips205 crate's public key.
///
/// # Memory layout — intentional over-allocation
///
/// `bytes` is statically sized to `shake_256s::PK_LEN` (the maximum across
/// all three security variants), leaving up to `shake_256s::PK_LEN -
/// shake_128s::PK_LEN = 32` bytes unused for `Shake128s` keys (16 bytes for
/// `Shake192s`). The trailing bytes are zero-initialized and ignored — `len`
/// records the active prefix.
///
/// This trade-off was chosen deliberately:
/// - **Stack-allocated** ([`u8`; N]) per invariant I-2 (see
///   `docs/SECRET_TYPE_INVARIANTS.md`); no heap allocation per key.
/// - **Non-generic** — a single concrete type that works across all three
///   security levels without propagating `<L: SlhDsaSecurityLevel>` generics
///   through every consumer.
/// - **Public material** — the unused tail bytes carry no information about
///   the actual public key (they are pre-zero), so the over-allocation has
///   no security cost.
///
/// Alternative designs were considered and rejected: a `Box<[u8; N]>` per
/// variant trades the stack waste for one heap allocation per key plus
/// indirection; a `Vec<u8>` adds heap + capacity tracking; an enum with one
/// variant per security level still uses `max(variant sizes)` of stack
/// (Rust's enum sizing) so it does not actually save bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    /// The security level used
    security_level: SlhDsaSecurityLevel,

    /// The underlying public key bytes. Sized to fit the largest variant
    /// (Shake256s = 64 bytes); the trailing `PK_LEN - len` bytes are
    /// guaranteed zero. The `[u8; PK_LEN]` is initialized via `[0u8;
    /// PK_LEN]` in [`Self::new`] before the variant-specific prefix is
    /// `copy_from_slice`-d into it, so trailing bytes are never
    /// uninitialized. `Clone` (derived) preserves all bytes verbatim,
    /// keeping the invariant under copy. See type-level "Memory layout"
    /// docs for rationale.
    bytes: [u8; shake_256s::PK_LEN],

    /// The actual length of the public key (per `security_level`).
    len: usize,
}

impl VerifyingKey {
    /// Creates a new verifying key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn new(security_level: SlhDsaSecurityLevel, bytes: &[u8]) -> Result<Self, SlhDsaError> {
        let expected_len = security_level.public_key_size();
        if bytes.len() != expected_len {
            return Err(SlhDsaError::InvalidPublicKey);
        }

        let mut key_bytes = [0u8; shake_256s::PK_LEN];
        key_bytes[..expected_len].copy_from_slice(bytes);

        // the previous implementation called
        // `try_from_bytes` here as eager validation, then `verify()`
        // called it again on every signature check — two parses per
        // PK, with the constructor's parsed result immediately
        // discarded. The struct stores raw bytes only, so caching the
        // parsed PK would require a typestate enum; since the parse
        // is re-done in verify anyway, drop the eager call. Length is
        // still validated above (`expected_len` check), and content
        // validity is detected on first verify with the same opaque
        // `InvalidPublicKey` error. PCT-based keygen flows
        // (`SigningKey::generate` → `pct_slh_dsa`) still exercise
        // both sign and verify on a fresh keypair so correctness
        // regressions are caught at construction time.

        Ok(VerifyingKey { security_level, bytes: key_bytes, len: expected_len })
    }

    /// Returns the security level
    #[must_use]
    pub fn security_level(&self) -> SlhDsaSecurityLevel {
        self.security_level
    }

    /// Returns the verifying key as bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Serializes the verifying key to bytes
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Deserializes a verifying key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn from_bytes(
        bytes: &[u8],
        security_level: SlhDsaSecurityLevel,
    ) -> Result<Self, SlhDsaError> {
        Self::new(security_level, bytes)
    }

    /// Verifies a signature on a message
    ///
    /// # Arguments
    ///
    /// * `message` - The message to verify
    /// * `signature` - The signature to verify
    /// * `context` - Optional context string (max 255 bytes, typically empty)
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` otherwise.
    ///
    /// `context` is the FIPS 205 context string; pass `&[]` for domain-neutral
    /// verification. Matches the signature-API shape of ML-DSA and FN-DSA.
    ///
    /// # Errors
    /// Returns an error if the context is too long (>255 bytes) or the
    /// key/signature is malformed.
    #[instrument(level = "debug", skip(self, message, signature, context), fields(security_level = ?self.security_level, message_len = message.len(), signature_len = signature.len(), context_len = context.len()))]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        context: &[u8],
    ) -> Result<bool, SlhDsaError> {
        // SLH-DSA verify hashes the entire message before traversing the
        // hyper-tree; an attacker who can submit arbitrary bytes through
        // any verify entry point can force unbounded hashing work. The
        // bound here mirrors the one in `sign()`.
        // collapse into the generic
        // verification-failure variant. `MessageTooLong` on verify
        // leaked the configured cap to a probing attacker.
        if let Err(e) = crate::primitives::resource_limits::validate_signature_size(message.len()) {
            tracing::debug!(error = ?e, msg_len = message.len(), "SLH-DSA verify rejected: message exceeds resource limit");
            return Err(SlhDsaError::VerificationFailed);
        }

        let ctx = context;

        // Validate context length
        if ctx.len() > 255 {
            return Err(SlhDsaError::ContextTooLong);
        }

        let is_valid = match self.security_level {
            SlhDsaSecurityLevel::Shake128s => {
                let pk_bytes: [u8; shake_128s::PK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let pk = shake_128s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let sig_bytes: [u8; shake_128s::SIG_LEN] =
                    signature.try_into().map_err(|_e| SlhDsaError::VerificationFailed)?;
                pk.verify(message, &sig_bytes, ctx)
            }
            SlhDsaSecurityLevel::Shake192s => {
                let pk_bytes: [u8; shake_192s::PK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let pk = shake_192s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let sig_bytes: [u8; shake_192s::SIG_LEN] =
                    signature.try_into().map_err(|_e| SlhDsaError::VerificationFailed)?;
                pk.verify(message, &sig_bytes, ctx)
            }
            SlhDsaSecurityLevel::Shake256s => {
                let pk_bytes: [u8; shake_256s::PK_LEN] =
                    self.as_bytes().try_into().map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let pk = shake_256s::PublicKey::try_from_bytes(&pk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidPublicKey)?;
                let sig_bytes: [u8; shake_256s::SIG_LEN] =
                    signature.try_into().map_err(|_e| SlhDsaError::VerificationFailed)?;
                pk.verify(message, &sig_bytes, ctx)
            }
        };

        Ok(is_valid)
    }
}

// ============================================================================
// Signing Key (Secret Key)
// ============================================================================

/// SLH-DSA signing key (secret key)
///
/// This is a wrapper around the audited fips205 crate's private key.
/// Secret keys are zeroized on drop to prevent memory leaks.
///
/// # Security
///
/// - Does not implement `Clone` to prevent unzeroized copies
/// - Implements `ConstantTimeEq` for timing-safe comparisons
/// - Zeroized on drop via custom `Drop` implementation
pub struct SigningKey {
    /// The security level used
    security_level: SlhDsaSecurityLevel,

    /// The underlying secret key bytes (zeroized on drop). Sized to the
    /// largest variant (Shake256s = 128 bytes); trailing `SK_LEN - len`
    /// bytes are always zero. See [`VerifyingKey`]'s "Memory layout" docs
    /// for the rationale (same trade-off applies here).
    bytes: [u8; shake_256s::SK_LEN],

    /// The actual length of the secret key (per `security_level`).
    len: usize,

    /// The verifying key (public key)
    verifying_key: VerifyingKey,
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare security level in constant time
        let level_eq = (self.security_level as u8).ct_eq(&(other.security_level as u8));
        // Compare length in constant time
        let len_eq = self.len.ct_eq(&other.len);
        // Compare bytes in constant time (only up to the actual length)
        let bytes_eq = self.bytes[..self.len].ct_eq(&other.bytes[..other.len]);
        level_eq & len_eq & bytes_eq
    }
}

// `PartialEq`/`Eq` are intentionally NOT implemented on SLH-DSA `SigningKey`.
// See invariants I-5/I-6 in `docs/SECRET_TYPE_INVARIANTS.md`. Use
// `ConstantTimeEq::ct_eq` for comparisons.

impl SigningKey {
    /// Generates a new signing key with the specified security level
    ///
    /// Uses the audited fips205 crate's `try_keygen()` function.
    /// After key generation, a FIPS 140-3 Pairwise Consistency Test (PCT)
    /// is performed to verify the keypair is valid.
    ///
    /// # Arguments
    ///
    /// * `security_level` - The security level to use
    ///
    /// # Returns
    ///
    /// Returns a tuple of (signing_key, verifying_key)
    ///
    /// # Errors
    ///
    /// Returns `SlhDsaError::RngError` if random number generation fails or PCT fails
    #[instrument(level = "debug", fields(security_level = ?security_level, nist_level = security_level.nist_level()))]
    pub fn generate(
        security_level: SlhDsaSecurityLevel,
    ) -> Result<(Self, VerifyingKey), SlhDsaError> {
        let (signing_key, verifying_key) = match security_level {
            SlhDsaSecurityLevel::Shake128s => {
                let (pk, sk) = shake_128s::try_keygen().map_err(|_e| SlhDsaError::RngError)?;
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        let pk_bytes = pk.into_bytes();
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_128s::PK_LEN,
                };
                let signing_key = SigningKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::SK_LEN];
                        let sk_bytes = sk.into_bytes();
                        b[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                        b
                    },
                    len: shake_128s::SK_LEN,
                    verifying_key: verifying_key.clone(),
                };
                (signing_key, verifying_key)
            }
            SlhDsaSecurityLevel::Shake192s => {
                let (pk, sk) = shake_192s::try_keygen().map_err(|_e| SlhDsaError::RngError)?;
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        let pk_bytes = pk.into_bytes();
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_192s::PK_LEN,
                };
                let signing_key = SigningKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::SK_LEN];
                        let sk_bytes = sk.into_bytes();
                        b[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                        b
                    },
                    len: shake_192s::SK_LEN,
                    verifying_key: verifying_key.clone(),
                };
                (signing_key, verifying_key)
            }
            SlhDsaSecurityLevel::Shake256s => {
                let (pk, sk) = shake_256s::try_keygen().map_err(|_e| SlhDsaError::RngError)?;
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        let pk_bytes = pk.into_bytes();
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_256s::PK_LEN,
                };
                let signing_key = SigningKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::SK_LEN];
                        let sk_bytes = sk.into_bytes();
                        b[..sk_bytes.len()].copy_from_slice(&sk_bytes);
                        b
                    },
                    len: shake_256s::SK_LEN,
                    verifying_key: verifying_key.clone(),
                };
                (signing_key, verifying_key)
            }
        };

        // FIPS 140-3 Pairwise Consistency Test (PCT)
        // Sign and verify a test message to ensure the keypair is consistent.
        // PCT failure now maps to the dedicated
        // `PctFailed` variant. The previous `RngError` mapping let a
        // FIPS error-state monitor mis-categorize a corrupted-keypair
        // event as transient entropy failure and likely retry — wrong
        // semantics for both FIPS and operational triage.
        crate::primitives::pct::pct_slh_dsa(&verifying_key, &signing_key)
            .map_err(|_e| SlhDsaError::PctFailed)?;

        Ok((signing_key, verifying_key))
    }

    /// Creates a new signing key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn new(security_level: SlhDsaSecurityLevel, bytes: &[u8]) -> Result<Self, SlhDsaError> {
        let expected_len = security_level.secret_key_size();
        if bytes.len() != expected_len {
            return Err(SlhDsaError::InvalidSecretKey);
        }

        let mut key_bytes = Zeroizing::new([0u8; shake_256s::SK_LEN]);
        key_bytes[..expected_len].copy_from_slice(bytes);

        match security_level {
            SlhDsaSecurityLevel::Shake128s => {
                if bytes.len() != shake_128s::SK_LEN {
                    return Err(SlhDsaError::InvalidSecretKey);
                }
                let mut sk_bytes: Zeroizing<[u8; shake_128s::SK_LEN]> =
                    Zeroizing::new([0u8; shake_128s::SK_LEN]);
                sk_bytes.copy_from_slice(bytes);
                let sk = shake_128s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let pk_bytes = sk.get_public_key().into_bytes();
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_128s::PK_LEN,
                };
                Ok(SigningKey {
                    security_level,
                    bytes: *key_bytes,
                    len: expected_len,
                    verifying_key,
                })
            }
            SlhDsaSecurityLevel::Shake192s => {
                if bytes.len() != shake_192s::SK_LEN {
                    return Err(SlhDsaError::InvalidSecretKey);
                }
                let mut sk_bytes: Zeroizing<[u8; shake_192s::SK_LEN]> =
                    Zeroizing::new([0u8; shake_192s::SK_LEN]);
                sk_bytes.copy_from_slice(bytes);
                let sk = shake_192s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let pk_bytes = sk.get_public_key().into_bytes();
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_192s::PK_LEN,
                };
                Ok(SigningKey {
                    security_level,
                    bytes: *key_bytes,
                    len: expected_len,
                    verifying_key,
                })
            }
            SlhDsaSecurityLevel::Shake256s => {
                if bytes.len() != shake_256s::SK_LEN {
                    return Err(SlhDsaError::InvalidSecretKey);
                }
                let mut sk_bytes: Zeroizing<[u8; shake_256s::SK_LEN]> =
                    Zeroizing::new([0u8; shake_256s::SK_LEN]);
                sk_bytes.copy_from_slice(bytes);
                let sk = shake_256s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let pk_bytes = sk.get_public_key().into_bytes();
                let verifying_key = VerifyingKey {
                    security_level,
                    bytes: {
                        let mut b = [0u8; shake_256s::PK_LEN];
                        b[..pk_bytes.len()].copy_from_slice(&pk_bytes);
                        b
                    },
                    len: shake_256s::PK_LEN,
                };
                Ok(SigningKey {
                    security_level,
                    bytes: *key_bytes,
                    len: expected_len,
                    verifying_key,
                })
            }
        }
    }

    /// Returns the security level
    #[must_use]
    pub fn security_level(&self) -> SlhDsaSecurityLevel {
        self.security_level
    }

    /// Expose the signing key bytes.
    ///
    /// Sealed accessor per Secret Type Invariant I-8
    /// (`docs/SECRET_TYPE_INVARIANTS.md`).
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Serializes the signing key to bytes
    ///
    /// Returns `Zeroizing<Vec<u8>>` to ensure the secret key bytes are zeroized on drop.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.expose_secret().to_vec())
    }

    /// Deserializes a signing key from bytes
    ///
    /// # Errors
    /// Returns an error if the key length is incorrect or the key is malformed.
    pub fn from_bytes(
        bytes: &[u8],
        security_level: SlhDsaSecurityLevel,
    ) -> Result<Self, SlhDsaError> {
        Self::new(security_level, bytes)
    }

    /// Returns the verifying key (public key) associated with this signing key
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Signs a message using this signing key
    ///
    /// Uses the audited fips205 crate's `try_sign()` function with hedging enabled
    /// for better security against side-channel attacks.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `context` - Optional context string (max 255 bytes, typically empty)
    ///
    /// # Returns
    ///
    /// Returns the signature as a byte vector
    ///
    /// `context` is the FIPS 205 context string; pass `&[]` for domain-neutral
    /// signatures. Matches the signature-API shape of ML-DSA and FN-DSA.
    ///
    /// # Errors
    ///
    /// Returns `SlhDsaError::RngError` if random number generation fails, or
    /// `SlhDsaError::ContextTooLong` if `context` exceeds 255 bytes, or
    /// `SlhDsaError::SigningFailed` if the message exceeds the resource
    /// limit (round-28 H7 collapsed the previous `MessageTooLong` variant
    /// for Pattern 6 sign-side opacity; the `MessageTooLong` variant is
    /// now `#[deprecated]`).
    #[instrument(level = "debug", skip(self, message, context), fields(security_level = ?self.security_level, message_len = message.len(), context_len = context.len()))]
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>, SlhDsaError> {
        // DoS bound: SLH-DSA signing cost scales with message length.
        // collapse the resource-cap rejection
        // to the new `SigningFailed` variant. Cap probing was the same
        // leak round-26 M1 closed on the verify-side; this completes
        // the sign-side symmetry. Trace captures the actual cause for
        // operator diagnostics.
        crate::primitives::resource_limits::validate_signature_size(message.len()).map_err(
            |e| {
                tracing::debug!(error = ?e, msg_len = message.len(), "SLH-DSA sign rejected: message exceeds resource limit");
                SlhDsaError::SigningFailed
            },
        )?;

        let ctx = context;

        // Validate context length
        if ctx.len() > 255 {
            return Err(SlhDsaError::ContextTooLong);
        }

        match self.security_level {
            SlhDsaSecurityLevel::Shake128s => {
                if self.expose_secret().len() != shake_128s::SK_LEN {
                    return Err(SlhDsaError::InvalidSecretKey);
                }
                let mut sk_bytes: Zeroizing<[u8; shake_128s::SK_LEN]> =
                    Zeroizing::new([0u8; shake_128s::SK_LEN]);
                sk_bytes.copy_from_slice(self.expose_secret());
                let sk = shake_128s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sig = sk.try_sign(message, ctx, true).map_err(|_e| SlhDsaError::RngError)?;
                Ok(sig.as_ref().to_vec())
            }
            SlhDsaSecurityLevel::Shake192s => {
                if self.expose_secret().len() != shake_192s::SK_LEN {
                    return Err(SlhDsaError::InvalidSecretKey);
                }
                let mut sk_bytes: Zeroizing<[u8; shake_192s::SK_LEN]> =
                    Zeroizing::new([0u8; shake_192s::SK_LEN]);
                sk_bytes.copy_from_slice(self.expose_secret());
                let sk = shake_192s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sig = sk.try_sign(message, ctx, true).map_err(|_e| SlhDsaError::RngError)?;
                Ok(sig.as_ref().to_vec())
            }
            SlhDsaSecurityLevel::Shake256s => {
                if self.expose_secret().len() != shake_256s::SK_LEN {
                    return Err(SlhDsaError::InvalidSecretKey);
                }
                let mut sk_bytes: Zeroizing<[u8; shake_256s::SK_LEN]> =
                    Zeroizing::new([0u8; shake_256s::SK_LEN]);
                sk_bytes.copy_from_slice(self.expose_secret());
                let sk = shake_256s::PrivateKey::try_from_bytes(&sk_bytes)
                    .map_err(|_e| SlhDsaError::InvalidSecretKey)?;
                let sig = sk.try_sign(message, ctx, true).map_err(|_e| SlhDsaError::RngError)?;
                Ok(sig.as_ref().to_vec())
            }
        }
    }

    /// Signs a message and returns the verifying key for convenience
    ///
    /// # Errors
    /// Returns an error if the context is too long or random number generation fails.
    pub fn sign_with_key(
        &self,
        message: &[u8],
        context: &[u8],
    ) -> Result<(Vec<u8>, &VerifyingKey), SlhDsaError> {
        let signature = self.sign(message, context)?;
        Ok((signature, &self.verifying_key))
    }
}

// Zeroize the signing key on drop to prevent memory leaks
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

// Implement Zeroize for SigningKey to allow explicit zeroization
impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("security_level", &self.security_level)
            .field("bytes", &"[REDACTED]")
            .field("verifying_key", &"[PUBLIC KEY]")
            .finish()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::explicit_iter_loop)] // Tests use iterator style
#[allow(clippy::redundant_clone)] // Tests clone for independent modification
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unnecessary_cast)]
mod tests {
    use super::*;

    // Test 1: Key generation works for all security levels
    #[test]
    fn test_slh_dsa_key_generation_all_levels_succeeds() {
        for level in [
            SlhDsaSecurityLevel::Shake128s,
            SlhDsaSecurityLevel::Shake192s,
            SlhDsaSecurityLevel::Shake256s,
        ] {
            let (sk, pk) = SigningKey::generate(level).expect("Key generation failed");
            assert_eq!(sk.security_level(), level);
            assert_eq!(pk.security_level(), level);
            assert_eq!(
                pk.as_bytes().len(),
                level.public_key_size(),
                "Public key size mismatch for {:?}",
                level
            );
            assert_eq!(
                sk.expose_secret().len(),
                level.secret_key_size(),
                "Secret key size mismatch for {:?}",
                level
            );
        }
    }

    // Test 2: Sign and verify round-trip
    #[test]
    fn test_sign_verify_roundtrip() {
        for level in [
            SlhDsaSecurityLevel::Shake128s,
            SlhDsaSecurityLevel::Shake192s,
            SlhDsaSecurityLevel::Shake256s,
        ] {
            let (sk, pk) = SigningKey::generate(level).expect("Key generation failed");
            let message = b"Test message for SLH-DSA";
            let signature = sk.sign(message, &[]).expect("Signing failed");

            assert_eq!(
                signature.len(),
                level.signature_size(),
                "Signature size mismatch for {:?}",
                level
            );

            let is_valid = pk.verify(message, &signature, &[]).expect("Verification failed");
            assert!(is_valid, "Signature verification failed for {:?}", level);
        }
    }

    // Test 3: Verify rejects invalid signatures
    #[test]
    fn test_verify_invalid_signature_fails() {
        let (sk, pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let mut signature = sk.sign(message, &[]).expect("Signing failed");

        // Corrupt the signature
        signature[0] ^= 0xFF;

        let is_valid = pk.verify(message, &signature, &[]).expect("Verification failed");
        assert!(!is_valid, "Verification should fail for corrupted signature");
    }

    // Test 4: Verify rejects wrong message
    #[test]
    fn test_verify_wrong_message_fails() {
        let (sk, pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let wrong_message = b"Wrong message";
        let signature = sk.sign(message, &[]).expect("Signing failed");

        let is_valid = pk.verify(wrong_message, &signature, &[]).expect("Verification failed");
        assert!(!is_valid, "Verification should fail for wrong message");
    }

    // Test 5: Serialization and deserialization
    #[test]
    fn test_slh_dsa_serialization_roundtrip() {
        for level in [
            SlhDsaSecurityLevel::Shake128s,
            SlhDsaSecurityLevel::Shake192s,
            SlhDsaSecurityLevel::Shake256s,
        ] {
            let (sk, pk) = SigningKey::generate(level).expect("Key generation failed");

            // Serialize and deserialize public key
            let pk_bytes = pk.to_bytes();
            let pk_restored = VerifyingKey::from_bytes(&pk_bytes, level)
                .expect("Public key deserialization failed");
            assert_eq!(pk, pk_restored);

            // Serialize and deserialize secret key
            let sk_bytes = sk.to_bytes();
            let sk_restored = SigningKey::from_bytes(&sk_bytes, level)
                .expect("Secret key deserialization failed");
            assert_eq!(sk.security_level(), sk_restored.security_level());
            assert_eq!(sk.expose_secret(), sk_restored.expose_secret());

            // Verify that restored key works
            let message = b"Test message";
            let signature = sk_restored.sign(message, &[]).expect("Signing failed");
            let is_valid =
                pk_restored.verify(message, &signature, &[]).expect("Verification failed");
            assert!(is_valid, "Signature verification failed after deserialization");
        }
    }

    // Test 6: Invalid key handling
    #[test]
    fn test_invalid_key_handling_returns_error() {
        // Invalid public key (wrong size)
        let result = VerifyingKey::new(SlhDsaSecurityLevel::Shake128s, &[0u8; 16]);
        assert!(matches!(result, Err(SlhDsaError::InvalidPublicKey)));

        // Invalid secret key (wrong size)
        let result = SigningKey::new(SlhDsaSecurityLevel::Shake128s, &[0u8; 16]);
        assert!(matches!(result, Err(SlhDsaError::InvalidSecretKey)));
    }

    // Test 7: Context string handling
    #[test]
    fn test_slh_dsa_context_string_sign_verify_roundtrip() {
        let (sk, pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let context = b"Test context";

        // Sign with context
        let signature = sk.sign(message, context).expect("Signing with context failed");

        // Verify with context
        let is_valid = pk.verify(message, &signature, context).expect("Verification failed");
        assert!(is_valid, "Signature verification failed with context");

        // Verify with wrong context should fail
        let is_valid =
            pk.verify(message, &signature, b"Wrong context").expect("Verification failed");
        assert!(!is_valid, "Verification should fail with wrong context");
    }

    // Test 8: Context string too long
    #[test]
    fn test_context_too_long_returns_error() {
        let (sk, _) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let long_context = vec![0u8; 256]; // 256 bytes, max is 255

        let result = sk.sign(message, &long_context);
        assert!(matches!(result, Err(SlhDsaError::ContextTooLong)));
    }

    // Test 9: Empty message signing
    #[test]
    fn test_slh_dsa_empty_message_sign_verify_roundtrip() {
        let (sk, pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"";

        let signature = sk.sign(message, &[]).expect("Signing empty message failed");
        let is_valid = pk.verify(message, &signature, &[]).expect("Verification failed");
        assert!(is_valid, "Signature verification failed for empty message");
    }

    // Test 10: Large message signing
    #[test]
    fn test_slh_dsa_large_message_sign_verify_roundtrip() {
        let (sk, pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let message = vec![0u8; 65536]; // 64 KB message

        let signature = sk.sign(&message, &[]).expect("Signing large message failed");
        let is_valid = pk.verify(&message, &signature, &[]).expect("Verification failed");
        assert!(is_valid, "Signature verification failed for large message");
    }

    // Test 11: Multiple signatures with same key
    #[test]
    fn test_slh_dsa_multiple_signatures_all_verify_succeeds() {
        let (sk, pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");

        for i in 0..10 {
            let message = format!("Test message {}", i).as_bytes().to_vec();
            let signature = sk.sign(&message, &[]).expect("Signing failed");
            let is_valid = pk.verify(&message, &signature, &[]).expect("Verification failed");
            assert!(is_valid, "Signature verification failed for message {}", i);
        }
    }

    // Test 12: Security level constants
    #[test]
    fn test_slh_dsa_security_level_constants_match_spec_succeeds() {
        // Check NIST levels
        assert_eq!(SlhDsaSecurityLevel::Shake128s.nist_level(), 1);
        assert_eq!(SlhDsaSecurityLevel::Shake192s.nist_level(), 3);
        assert_eq!(SlhDsaSecurityLevel::Shake256s.nist_level(), 5);

        // Check key and signature sizes
        assert_eq!(SlhDsaSecurityLevel::Shake128s.public_key_size(), shake_128s::PK_LEN);
        assert_eq!(SlhDsaSecurityLevel::Shake128s.secret_key_size(), shake_128s::SK_LEN);
        assert_eq!(SlhDsaSecurityLevel::Shake128s.signature_size(), shake_128s::SIG_LEN);

        assert_eq!(SlhDsaSecurityLevel::Shake192s.public_key_size(), shake_192s::PK_LEN);
        assert_eq!(SlhDsaSecurityLevel::Shake192s.secret_key_size(), shake_192s::SK_LEN);
        assert_eq!(SlhDsaSecurityLevel::Shake192s.signature_size(), shake_192s::SIG_LEN);

        assert_eq!(SlhDsaSecurityLevel::Shake256s.public_key_size(), shake_256s::PK_LEN);
        assert_eq!(SlhDsaSecurityLevel::Shake256s.secret_key_size(), shake_256s::SK_LEN);
        assert_eq!(SlhDsaSecurityLevel::Shake256s.signature_size(), shake_256s::SIG_LEN);
    }

    #[test]
    fn test_slh_dsa_secret_key_zeroization_succeeds() {
        let (mut sk, _pk) = SigningKey::generate(SlhDsaSecurityLevel::Shake128s)
            .expect("Key generation should succeed");

        let sk_bytes_before = sk.expose_secret().to_vec();
        assert!(
            !sk_bytes_before.iter().all(|&b| b == 0),
            "Secret key should contain non-zero data"
        );

        sk.zeroize();

        let sk_bytes_after = sk.expose_secret();
        assert!(sk_bytes_after.iter().all(|&b| b == 0), "Secret key should be zeroized");
    }

    #[test]
    fn test_slh_dsa_all_security_levels_zeroization_succeeds() {
        let levels = [
            SlhDsaSecurityLevel::Shake128s,
            SlhDsaSecurityLevel::Shake192s,
            SlhDsaSecurityLevel::Shake256s,
        ];

        for level in levels.iter() {
            let (mut sk, _pk) =
                SigningKey::generate(*level).expect("Key generation should succeed");

            let sk_bytes_before = sk.expose_secret().to_vec();
            assert!(
                !sk_bytes_before.iter().all(|&b| b == 0),
                "Secret key for {:?} should contain non-zero data",
                level
            );

            sk.zeroize();

            let sk_bytes_after = sk.expose_secret();
            assert!(
                sk_bytes_after.iter().all(|&b| b == 0),
                "Secret key for {:?} should be zeroized",
                level
            );
        }
    }

    #[test]
    fn test_slh_dsa_signing_after_zeroization_succeeds() {
        let (mut sk, pk) = SigningKey::generate(SlhDsaSecurityLevel::Shake128s)
            .expect("Key generation should succeed");
        let message = b"Test message";

        let signature_before = sk.sign(message, &[]).expect("Signing should succeed");
        let is_valid_before =
            pk.verify(message, &signature_before, &[]).expect("Verification should succeed");
        assert!(is_valid_before, "Signature should be valid before zeroization");

        sk.zeroize();

        let result = sk.sign(message, &[]);
        assert!(result.is_err(), "Signing should fail after zeroization");
    }

    // Test 13: VerifyingKey::verify returns Result
    #[test]
    fn test_slh_dsa_verify_returns_ok_result_succeeds() {
        let (sk, pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let message = b"Test message";
        let signature = sk.sign(message, &[]).expect("Signing failed");

        // Valid signature should return Ok(true)
        let result = pk.verify(message, &signature, &[]);
        assert!(matches!(result, Ok(true)));

        // Invalid signature should return Ok(false), not Err
        let mut invalid_sig = signature.clone();
        invalid_sig[0] ^= 0xFF;
        let result = pk.verify(message, &invalid_sig, &[]);
        assert!(matches!(result, Ok(false)));
    }

    /// the
    /// resource-cap gate at the top of `sign()` rejects oversized
    /// messages before reaching the upstream slh-dsa crate. Round-28
    /// collapsed the variant to the opaque `SigningFailed` (was
    /// distinguishable `MessageTooLong`).
    #[test]
    fn test_slh_dsa_sign_oversized_message_rejects_opaquely() {
        let (sk, _pk) =
            SigningKey::generate(SlhDsaSecurityLevel::Shake128s).expect("Key generation failed");
        let oversize: Vec<u8> = vec![0u8; (64 * 1024) + 1];
        let err = sk.sign(&oversize, &[]).expect_err("oversized message must be rejected");
        assert!(matches!(err, SlhDsaError::SigningFailed), "expected SigningFailed, got {err:?}");
    }
}
