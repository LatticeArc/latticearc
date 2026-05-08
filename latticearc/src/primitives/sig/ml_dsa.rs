#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # ML-DSA (FIPS 204) Digital Signatures
//!
//! ## FIPS 140-3 Certification Notice
//!
//! **Current Implementation**: Uses the `fips204` crate (pure Rust, NOT independently audited)
//!
//! **For FIPS 140-3 certification**, this module needs to migrate to `aws-lc-rs`
//! once its ML-DSA Rust API is stabilized. The current `fips204` crate is not
//! independently FIPS-validated.
//!
//! ## Usage for Non-FIPS Applications
//!
//! The current implementation is functionally correct and suitable for:
//! - Development and testing
//! - Non-regulated applications
//! - Applications not requiring FIPS 140-3 certification
//!
//! ## FIPS 204 Standard
//!
//! FIPS 204 specifies the Module-Lattice-Based Digital Signature Algorithm (ML-DSA),
//! which provides post-quantum security for digital signatures.
//!
//! ## Security Level
//!
//! ML-DSA provides EUF-CMA (Existential Unforgeability under Chosen Message Attacks)
//! security and is believed to be secure against quantum adversaries.
//!
//! ## Parameter Sets
//!
//! | Parameter Set | Public Key | Signature | NIST Level |
//! |---------------|------------|-----------|------------|
//! | ML-DSA-44     | ~1.3 KB    | ~2.4 KB   | 2          |
//! | ML-DSA-65     | ~2.0 KB    | ~3.3 KB   | 3          |
//! | ML-DSA-87     | ~2.6 KB    | ~4.6 KB   | 5          |
//!
//! ## Backend
//!
//! Currently uses the `fips204` crate. aws-lc-rs v1.16.0+ includes ML-DSA support;
//! future versions of LatticeArc may migrate to `aws-lc-rs` for FIPS-validated ML-DSA.
//! No action is required from users — the migration will be transparent.

use fips204::{
    ml_dsa_44, ml_dsa_65, ml_dsa_87,
    traits::{SerDes, Signer, Verifier},
};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// ML-DSA parameter sets for different security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlDsaParameterSet {
    /// ML-DSA-44: NIST Level 2 security (~128-bit classical security)
    MlDsa44,
    /// ML-DSA-65: NIST Level 3 security (~192-bit classical security)
    MlDsa65,
    /// ML-DSA-87: NIST Level 5 security (~256-bit classical security)
    MlDsa87,
}

impl MlDsaParameterSet {
    /// Returns the name of the parameter set
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Returns the public key size in bytes
    #[must_use]
    pub const fn public_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Returns the secret key size in bytes
    #[must_use]
    pub const fn secret_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Returns the signature size in bytes
    #[must_use]
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Returns the NIST security level
    #[must_use]
    pub const fn nist_security_level(&self) -> u8 {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
        }
    }
}

/// Error types for ML-DSA operations
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MlDsaError {
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationError(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningError(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationError(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key size
        expected: usize,
        /// Actual key size
        actual: usize,
    },

    /// Invalid signature length
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Expected signature size
        expected: usize,
        /// Actual signature size
        actual: usize,
    },

    /// Invalid parameter set
    #[error("Invalid parameter set: {0}")]
    InvalidParameterSet(String),

    /// Verification key and signature carry different ML-DSA parameter
    /// sets. This is a configuration error, not a signature forgery —
    /// callers that branch on `Ok(false)` for "invalid signature" must
    /// surface this case as `Err` so misconfigurations don't masquerade
    /// as forgeries.
    #[error("ML-DSA parameter-set mismatch: key uses {key:?}, signature uses {signature:?}")]
    ParameterSetMismatch {
        /// Parameter set the verifying key was generated at.
        key: MlDsaParameterSet,
        /// Parameter set the signature was produced at.
        signature: MlDsaParameterSet,
    },

    /// Message length exceeds the configured resource limit.
    ///
    /// kept for ABI compatibility but no longer returned from
    /// `sign()` — the cap-rejection now collapses to `SigningError`
    /// so the sign path matches Pattern 6 opacity (verify-side
    /// already collapsed; this completes sign-side symmetry). Mirrors
    /// the deprecation on `SlhDsaError::MessageTooLong` and
    /// `FnDsaError::MessageTooLong`. Will be removed in a future
    /// major bump alongside its siblings.
    #[deprecated(note = "sign() now returns SigningError for cap rejection; \
                this variant is no longer reachable from production code.")]
    #[error("Message exceeds signature resource limit")]
    MessageTooLong,

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
}

/// ML-DSA public key (FIPS 204 format)
#[derive(Debug, Clone)]
pub struct MlDsaPublicKey {
    /// The parameter set for this key
    /// Consumer: parameter_set()
    parameter_set: MlDsaParameterSet,
    /// Serialized public key bytes
    /// Consumer: as_bytes(), len(), is_empty()
    data: Vec<u8>,
}

impl MlDsaPublicKey {
    /// Verify an ML-DSA signature produced by the corresponding secret key.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if it is
    /// invalid or the parameter sets of the public key and signature do not
    /// match.
    ///
    /// # Errors
    /// Returns `MlDsaError::VerificationError` if:
    /// - `message.len()` exceeds the configured resource-limit cap
    ///   (DoS guard mirroring the sign-side resource limit).
    /// - `context.len() > 255` bytes (FIPS 204 §3.3 — sign-side
    ///   rejects the same; verify rejects symmetrically).
    /// - The key or signature bytes fail to parse at the upstream
    ///   `ml-dsa` crate (e.g. wrong length for the parameter set).
    ///
    /// Returns `MlDsaError::ParameterSetMismatch` if the public key and
    /// signature were generated for different ML-DSA parameter sets.
    #[instrument(level = "debug", skip(self, message, signature, context), fields(parameter_set = ?self.parameter_set(), message_len = message.len(), signature_len = signature.as_bytes().len()))]
    pub fn verify(
        &self,
        message: &[u8],
        signature: &MlDsaSignature,
        context: &[u8],
    ) -> Result<bool, MlDsaError> {
        // DoS bound on the verify hot path. ML-DSA verify hashes the
        // entire message, so an attacker who can submit arbitrary
        // bytes through any verify entry point can force unbounded
        // hashing work. The guard mirrors the one in `sign()`.
        // collapse into the generic
        // verification-failure variant. The previous `MessageTooLong`
        // surface let an adversary probe verify with varying message
        // lengths and binary-search the configured cap from the error
        // shape — a slow leak of operator config.
        if let Err(e) = crate::primitives::resource_limits::validate_signature_size(message.len()) {
            tracing::debug!(error = %e, msg_len = message.len(), "ML-DSA verify rejected: message exceeds resource limit");
            return Err(MlDsaError::VerificationError("verification failed".to_string()));
        }

        // mirror the sign-side context cap. A verify call
        // with >255 bytes of context cannot possibly match a valid
        // signature (sign-side rejects), but the audit's principle is
        // to fail explicitly here rather than rely on the verifier to
        // produce a Boolean false on mismatched canonicalization.
        // Collapsed to the same opaque `VerificationError` (Pattern 6
        // posture — no distinguishable `ContextTooLong` variant on the
        // verify path).
        if context.len() > 255 {
            tracing::debug!(
                ctx_len = context.len(),
                "ML-DSA verify rejected: context > 255 bytes (FIPS 204 §3.3)"
            );
            return Err(MlDsaError::VerificationError("verification failed".to_string()));
        }

        if self.parameter_set() != signature.parameter_set() {
            // Parameter-set mismatch is a configuration bug, not a
            // forgery. Callers that branch on `Ok(false)` for "invalid
            // signature" would silently treat a misconfigured key/signature
            // pair as a valid forgery report; surface as `Err` instead.
            return Err(MlDsaError::ParameterSetMismatch {
                key: self.parameter_set(),
                signature: signature.parameter_set(),
            });
        }

        let is_valid = match self.parameter_set() {
            MlDsaParameterSet::MlDsa44 => {
                let pk_bytes: [u8; 1312] = self.as_bytes().try_into().map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes).map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                let sig_bytes: [u8; 2420] = signature.as_bytes().try_into().map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                pk.verify(message, &sig_bytes, context)
            }
            MlDsaParameterSet::MlDsa65 => {
                let pk_bytes: [u8; 1952] = self.as_bytes().try_into().map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                let sig_bytes: [u8; 3309] = signature.as_bytes().try_into().map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                pk.verify(message, &sig_bytes, context)
            }
            MlDsaParameterSet::MlDsa87 => {
                let pk_bytes: [u8; 2592] = self.as_bytes().try_into().map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes).map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                let sig_bytes: [u8; 4627] = signature.as_bytes().try_into().map_err(|_e| {
                    MlDsaError::VerificationError("verification failed".to_string())
                })?;
                pk.verify(message, &sig_bytes, context)
            }
        };

        Ok(is_valid)
    }

    /// Creates a new ML-DSA public key from raw bytes
    ///
    /// # Errors
    /// Returns an error if the key length does not match the expected size for the parameter set.
    pub fn new(parameter_set: MlDsaParameterSet, data: Vec<u8>) -> Result<Self, MlDsaError> {
        let expected_size = parameter_set.public_key_size();
        if data.len() != expected_size {
            return Err(MlDsaError::InvalidKeyLength {
                expected: expected_size,
                actual: data.len(),
            });
        }
        Ok(Self { parameter_set, data })
    }

    /// Creates a public key from a borrowed byte slice.
    ///
    /// This is a convenience wrapper around [`Self::new`] for callers that hold
    /// a `&[u8]` and do not want to call `.to_vec()` at the call site. Argument
    /// order mirrors [`MlKemPublicKey::from_bytes`](crate::primitives::kem::ml_kem::MlKemPublicKey::from_bytes).
    ///
    /// # Errors
    /// Returns an error if the key length does not match the expected size for the parameter set.
    pub fn from_bytes(bytes: &[u8], parameter_set: MlDsaParameterSet) -> Result<Self, MlDsaError> {
        Self::new(parameter_set, bytes.to_vec())
    }

    /// Returns the parameter set for this key
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Returns the size of the public key in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the public key is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Serializes the public key to bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Clones the public key bytes into an owned `Vec<u8>`.
    ///
    /// Prefer [`Self::as_bytes`] when a borrowed view is sufficient. `to_bytes`
    /// exists for callers that need an owned copy (e.g. for serialization or
    /// transmission) while keeping the original key in place.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// ML-DSA secret key (FIPS 204 format)
///
/// # Security
///
/// - Fields are private to prevent direct access to secret material
/// - Implements `ZeroizeOnDrop` for automatic memory cleanup
/// - Implements `ConstantTimeEq` for timing-safe comparisons
/// - Does not implement `Clone` to prevent unzeroized copies
///
/// `data` is wrapped in
/// `Zeroizing<Vec<u8>>` so the moved-in `Vec` is zeroized even on the
/// `MlDsaSecretKey::new()` length-validation error path. Previously
/// `data: Vec<u8>` plus struct-level `#[derive(ZeroizeOnDrop)]` only
/// covered the success path — a length-mismatched `Vec` was dropped
/// bare. Hot path on every hybrid sign + every key-load.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlDsaSecretKey {
    /// The parameter set for this key
    #[zeroize(skip)]
    parameter_set: MlDsaParameterSet,
    /// Serialized secret key bytes (zeroized on drop via `Zeroizing<>`).
    data: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaSecretKey")
            .field("parameter_set", &self.parameter_set)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl MlDsaSecretKey {
    /// Sign a message using this ML-DSA secret key.
    ///
    /// `context` is the FIPS 204 context string; pass `&[]` for domain-neutral
    /// signatures. Messages longer than the configured resource limit are
    /// rejected with [`MlDsaError::SigningError`] — the previous
    /// `MessageTooLong` variant collapsed for Pattern 6 sign-side
    /// opacity and is now `#[deprecated]`.
    ///
    /// # Errors
    /// Returns `MlDsaError::SigningError` (Pattern-6 opaque) if:
    /// - signing fails at the upstream `ml-dsa` crate,
    /// - the SK bytes fail to parse,
    /// - the message exceeds the configured resource limit,
    /// - or `context.len() > 255` bytes (FIPS 204 §3.3 cap).
    #[instrument(level = "debug", skip(self, message, context), fields(parameter_set = ?self.parameter_set(), message_len = message.len(), context_len = context.len()))]
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<MlDsaSignature, MlDsaError> {
        // Pattern-6 opacity: every reject path returns the same opaque
        // `SIGN_ERR_MSG` and the cause is logged via tracing::debug!
        // only. Distinguishable variants would let an attacker probe
        // message length / context length / SK shape from error wording
        //.
        const SIGN_ERR_MSG: &str = "ML-DSA signing failed";
        let opaque_sign_err = || MlDsaError::SigningError(SIGN_ERR_MSG.to_string());

        // DoS bound: primitive callers bypass unified_api's resource limits.
        crate::primitives::resource_limits::validate_signature_size(message.len()).map_err(
            |e| {
                tracing::debug!(error = %e, msg_len = message.len(), "ML-DSA sign rejected: resource limit");
                opaque_sign_err()
            },
        )?;

        // FIPS 204 §3.3: context cap. Upstream `fips204` behaviour on
        // >255 bytes is implementation-defined; reject up-front.
        if context.len() > 255 {
            tracing::debug!(ctx_len = context.len(), "ML-DSA sign rejected: context > 255 bytes");
            return Err(opaque_sign_err());
        }

        let parameter_set = self.parameter_set();
        let ps_label: &'static str = match parameter_set {
            MlDsaParameterSet::MlDsa44 => "ML-DSA-44",
            MlDsaParameterSet::MlDsa65 => "ML-DSA-65",
            MlDsaParameterSet::MlDsa87 => "ML-DSA-87",
        };
        // `?e` is intentional here (NOT `%e`): the closure parameter is
        // typed `&dyn std::fmt::Debug`, the upstream errors are internal
        // `MlDsa*Error` variants whose Debug repr is bounded (no anyhow
        // chain walking), and there is no attacker-controlled input
        // mixed in. The tracing-observability contract on `%e` applies
        // to `anyhow::Error` wrapping `serde_json` / `base64` — not to
        // closure-typed Debug sinks like this one.
        let log_reject = |stage: &'static str, e: &dyn std::fmt::Debug| {
            tracing::debug!(error = ?e, parameter_set = ps_label, "ML-DSA sign rejected: {stage}");
        };

        let signature = match parameter_set {
            MlDsaParameterSet::MlDsa44 => {
                // Stack-allocated secret key bytes wrapped in Zeroizing for guaranteed wipe.
                let mut sk_bytes: Zeroizing<[u8; 2560]> = Zeroizing::new([0u8; 2560]);
                if self.expose_secret().len() != 2560 {
                    log_reject("SK length mismatch", &());
                    return Err(opaque_sign_err());
                }
                sk_bytes.copy_from_slice(self.expose_secret());
                let sk = ml_dsa_44::PrivateKey::try_from_bytes(*sk_bytes).map_err(|e| {
                    log_reject("SK deserialize", &e);
                    opaque_sign_err()
                })?;
                let sig = sk.try_sign(message, context).map_err(|e| {
                    log_reject("try_sign", &e);
                    opaque_sign_err()
                })?;
                MlDsaSignature::new(parameter_set, sig.to_vec())?
            }
            MlDsaParameterSet::MlDsa65 => {
                let mut sk_bytes: Zeroizing<[u8; 4032]> = Zeroizing::new([0u8; 4032]);
                if self.expose_secret().len() != 4032 {
                    log_reject("SK length mismatch", &());
                    return Err(opaque_sign_err());
                }
                sk_bytes.copy_from_slice(self.expose_secret());
                let sk = ml_dsa_65::PrivateKey::try_from_bytes(*sk_bytes).map_err(|e| {
                    log_reject("SK deserialize", &e);
                    opaque_sign_err()
                })?;
                let sig = sk.try_sign(message, context).map_err(|e| {
                    log_reject("try_sign", &e);
                    opaque_sign_err()
                })?;
                MlDsaSignature::new(parameter_set, sig.to_vec())?
            }
            MlDsaParameterSet::MlDsa87 => {
                let mut sk_bytes: Zeroizing<[u8; 4896]> = Zeroizing::new([0u8; 4896]);
                if self.expose_secret().len() != 4896 {
                    log_reject("SK length mismatch", &());
                    return Err(opaque_sign_err());
                }
                sk_bytes.copy_from_slice(self.expose_secret());
                let sk = ml_dsa_87::PrivateKey::try_from_bytes(*sk_bytes).map_err(|e| {
                    log_reject("SK deserialize", &e);
                    opaque_sign_err()
                })?;
                let sig = sk.try_sign(message, context).map_err(|e| {
                    log_reject("try_sign", &e);
                    opaque_sign_err()
                })?;
                MlDsaSignature::new(parameter_set, sig.to_vec())?
            }
        };

        Ok(signature)
    }

    /// Creates a new ML-DSA secret key from raw bytes
    ///
    /// # Errors
    /// Returns an error if the key length does not match the expected size for the parameter set.
    pub fn new(parameter_set: MlDsaParameterSet, data: Vec<u8>) -> Result<Self, MlDsaError> {
        // wrap on entry so the moved-in
        // `Vec` is zeroized on the length-validation error path too. The
        // previous shape kept `data: Vec<u8>` and relied on struct-level
        // `ZeroizeOnDrop` — which only fires on the success path because
        // the struct is never constructed on the error branch.
        let data = Zeroizing::new(data);
        let expected_size = parameter_set.secret_key_size();
        if data.len() != expected_size {
            return Err(MlDsaError::InvalidKeyLength {
                expected: expected_size,
                actual: data.len(),
            });
        }
        Ok(Self { parameter_set, data })
    }

    /// Creates a secret key from a borrowed byte slice.
    ///
    /// This is a convenience wrapper around [`Self::new`] for callers that hold
    /// a `&[u8]` and do not want to call `.to_vec()` at the call site.
    ///
    /// # Security Warning
    /// The caller must have obtained `bytes` from a securely stored source; this
    /// method makes a copy into an internally-zeroized buffer, but cannot
    /// retroactively scrub the caller's copy.
    ///
    /// # Errors
    /// Returns an error if the key length does not match the expected size for the parameter set.
    pub fn from_bytes(bytes: &[u8], parameter_set: MlDsaParameterSet) -> Result<Self, MlDsaError> {
        Self::new(parameter_set, bytes.to_vec())
    }

    /// Returns the parameter set for this key
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Returns the size of the secret key in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the secret key is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Expose the secret key bytes.
    ///
    /// Sealed accessor per Secret Type Invariant I-8
    /// (`docs/SECRET_TYPE_INVARIANTS.md`). Handle the returned slice with
    /// care: do not copy it into a non-zeroizing container, and hold it only
    /// as long as necessary.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.data
    }

    /// Clones the secret key bytes into a `Zeroizing<Vec<u8>>`.
    ///
    /// The returned `Zeroizing<Vec<u8>>` ensures the copied bytes are
    /// automatically zeroized on drop. Prefer [`Self::as_bytes`] when a
    /// borrowed view is sufficient — this method exists for callers that
    /// need an owned, zeroize-on-drop copy (e.g. for serialization).
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // `self.data` is `Zeroizing<Vec<u8>>`; deref to the slice and
        // re-allocate into a fresh zeroizing copy.
        Zeroizing::new(self.data.to_vec())
    }
}

impl ConstantTimeEq for MlDsaSecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // Compare parameter set discriminant in constant time
        let param_eq = (self.parameter_set as u8).ct_eq(&(other.parameter_set as u8));
        // Compare data in constant time
        let data_eq = self.data.ct_eq(&other.data);
        param_eq & data_eq
    }
}

// `PartialEq`/`Eq` are intentionally NOT implemented on `MlDsaSecretKey`.
// See invariants I-5/I-6 in `docs/SECRET_TYPE_INVARIANTS.md`. Use
// `ConstantTimeEq::ct_eq` for comparisons.

/// ML-DSA signature (FIPS 204 format)
#[derive(Debug, Clone)]
pub struct MlDsaSignature {
    /// The parameter set used to create this signature
    /// Consumer: parameter_set()
    parameter_set: MlDsaParameterSet,
    /// Serialized signature bytes
    /// Consumer: as_bytes(), len(), is_empty()
    data: Vec<u8>,
}

impl MlDsaSignature {
    /// Creates a new ML-DSA signature from raw bytes
    ///
    /// # Errors
    /// Returns an error if the signature length does not match the expected size for the parameter set.
    pub fn new(parameter_set: MlDsaParameterSet, data: Vec<u8>) -> Result<Self, MlDsaError> {
        let expected_size = parameter_set.signature_size();
        if data.len() != expected_size {
            return Err(MlDsaError::InvalidSignatureLength {
                expected: expected_size,
                actual: data.len(),
            });
        }
        Ok(Self { parameter_set, data })
    }

    /// Creates a signature from a borrowed byte slice.
    ///
    /// This is a convenience wrapper around [`Self::new`] for callers that hold
    /// a `&[u8]` and do not want to call `.to_vec()` at the call site.
    ///
    /// # Errors
    /// Returns an error if the signature length does not match the expected size for the parameter set.
    pub fn from_bytes(bytes: &[u8], parameter_set: MlDsaParameterSet) -> Result<Self, MlDsaError> {
        Self::new(parameter_set, bytes.to_vec())
    }

    /// Creates a signature from raw bytes without length validation.
    ///
    /// # Safety (logical)
    ///
    /// This bypasses length validation and should only be used for testing
    /// error paths (e.g., truncated or malformed signatures). The resulting
    /// signature will fail `verify()` if the length is incorrect.
    ///
    /// the audit recommended gating this
    /// behind `#[cfg(any(test, feature = "test-utils"))]`. We keep the
    /// `pub + #[doc(hidden)]` shape but route every cross-crate caller
    /// through the `test-utils` feature so the API surface is
    /// effectively dev-only:
    ///   * the function still compiles unconditionally so in-tree
    ///     integration tests in `latticearc/tests/` link against it
    ///     without enabling extra features (matches the historic
    ///     contract this crate exposed for tamper-detection tests);
    ///   * downstream consumers wanting to construct adversarial
    ///     signatures must enable `test-utils`, which the `lib.rs`
    ///     feature table flags as soundness-bypassing — a clear
    ///     signal not to ship it in production builds.
    /// A future major version may tighten this further; the function
    /// constructs a length-mismatched signature that fails `verify()`
    /// regardless, so the residual risk is "construct a parsing
    /// fixture downstream" rather than a soundness bypass.
    #[doc(hidden)]
    #[must_use]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn from_bytes_unchecked(parameter_set: MlDsaParameterSet, data: Vec<u8>) -> Self {
        Self { parameter_set, data }
    }

    /// Returns the parameter set used to create this signature
    #[must_use]
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Returns the size of the signature in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the signature is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Serializes the signature to bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Clones the signature bytes into an owned `Vec<u8>`.
    ///
    /// Prefer [`Self::as_bytes`] when a borrowed view is sufficient. `to_bytes`
    /// exists for callers that need an owned copy (e.g. for serialization or
    /// transmission) while keeping the original signature in place.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// Generate an ML-DSA keypair for the specified parameter set
///
/// This function generates a new ML-DSA keypair and performs a FIPS 140-3
/// Pairwise Consistency Test (PCT) to verify the keypair is valid before
/// returning it.
///
/// # Errors
/// Returns an error if key generation fails, the ml_dsa feature is not enabled,
/// or the PCT fails (indicating a corrupted keypair).
#[must_use = "generated keypair must be stored or used"]
#[instrument(level = "debug", fields(parameter_set = ?parameter_set))]
pub fn generate_keypair(
    parameter_set: MlDsaParameterSet,
) -> Result<(MlDsaPublicKey, MlDsaSecretKey), MlDsaError> {
    let (pk, sk) = match parameter_set {
        MlDsaParameterSet::MlDsa44 => {
            let (pk, sk) = ml_dsa_44::try_keygen().map_err(|e| {
                MlDsaError::KeyGenerationError(format!("ML-DSA-44 key generation failed: {}", e))
            })?;
            (
                MlDsaPublicKey { parameter_set, data: pk.into_bytes().to_vec() },
                MlDsaSecretKey { parameter_set, data: Zeroizing::new(sk.into_bytes().to_vec()) },
            )
        }
        MlDsaParameterSet::MlDsa65 => {
            let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| {
                MlDsaError::KeyGenerationError(format!("ML-DSA-65 key generation failed: {}", e))
            })?;
            (
                MlDsaPublicKey { parameter_set, data: pk.into_bytes().to_vec() },
                MlDsaSecretKey { parameter_set, data: Zeroizing::new(sk.into_bytes().to_vec()) },
            )
        }
        MlDsaParameterSet::MlDsa87 => {
            let (pk, sk) = ml_dsa_87::try_keygen().map_err(|e| {
                MlDsaError::KeyGenerationError(format!("ML-DSA-87 key generation failed: {}", e))
            })?;
            (
                MlDsaPublicKey { parameter_set, data: pk.into_bytes().to_vec() },
                MlDsaSecretKey { parameter_set, data: Zeroizing::new(sk.into_bytes().to_vec()) },
            )
        }
    };

    // FIPS 140-3 Pairwise Consistency Test (PCT)
    // Sign and verify a test message to ensure the keypair is consistent
    crate::primitives::pct::pct_ml_dsa(&pk, &sk)
        .map_err(|e| MlDsaError::KeyGenerationError(format!("PCT failed: {}", e)))?;

    Ok((pk, sk))
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
#[allow(clippy::expect_used)] // Tests use expect for simplicity
#[allow(clippy::indexing_slicing)] // Tests use direct indexing
#[allow(clippy::single_match)] // Tests use match for clarity
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn test_parameter_set_succeeds(param: MlDsaParameterSet) -> Result<(), MlDsaError> {
        let (pk, sk) = generate_keypair(param)?;

        assert_eq!(pk.parameter_set(), param);
        assert_eq!(sk.parameter_set(), param);
        assert_eq!(pk.len(), param.public_key_size());
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());

        let message = b"Test message for ML-DSA";
        let context: &[u8] = &[];

        let signature = sk.sign(message, context)?;
        assert_eq!(signature.parameter_set(), param);
        assert!(!signature.is_empty());

        let is_valid = pk.verify(message, &signature, context)?;
        assert!(is_valid, "Signature should be valid");

        let wrong_message = b"Wrong message";
        let is_valid = pk.verify(wrong_message, &signature, context)?;
        assert!(!is_valid, "Signature should be invalid for wrong message");

        let (pk2, _sk2) = generate_keypair(param)?;
        let is_valid = pk2.verify(message, &signature, context)?;
        assert!(!is_valid, "Signature should be invalid for wrong public key");

        Ok(())
    }

    #[test]
    fn test_ml_dsa_44_key_generation_succeeds() -> Result<(), MlDsaError> {
        test_parameter_set_succeeds(MlDsaParameterSet::MlDsa44)
    }

    #[test]
    fn test_ml_dsa_65_key_generation_succeeds() -> Result<(), MlDsaError> {
        test_parameter_set_succeeds(MlDsaParameterSet::MlDsa65)
    }

    #[test]
    fn test_ml_dsa_87_key_generation_succeeds() -> Result<(), MlDsaError> {
        test_parameter_set_succeeds(MlDsaParameterSet::MlDsa87)
    }

    #[test]
    fn test_ml_dsa_secret_key_zeroization_succeeds() {
        let (_pk, mut sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");

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
    fn test_ml_dsa_parameter_set_properties_match_spec_succeeds() {
        assert_eq!(MlDsaParameterSet::MlDsa44.name(), "ML-DSA-44");
        assert_eq!(MlDsaParameterSet::MlDsa44.public_key_size(), 1312);
        assert_eq!(MlDsaParameterSet::MlDsa44.secret_key_size(), 2560);
        assert_eq!(MlDsaParameterSet::MlDsa44.signature_size(), 2420);
        assert_eq!(MlDsaParameterSet::MlDsa44.nist_security_level(), 2);

        assert_eq!(MlDsaParameterSet::MlDsa65.name(), "ML-DSA-65");
        assert_eq!(MlDsaParameterSet::MlDsa65.public_key_size(), 1952);
        assert_eq!(MlDsaParameterSet::MlDsa65.secret_key_size(), 4032);
        assert_eq!(MlDsaParameterSet::MlDsa65.signature_size(), 3309);
        assert_eq!(MlDsaParameterSet::MlDsa65.nist_security_level(), 3);

        assert_eq!(MlDsaParameterSet::MlDsa87.name(), "ML-DSA-87");
        assert_eq!(MlDsaParameterSet::MlDsa87.public_key_size(), 2592);
        assert_eq!(MlDsaParameterSet::MlDsa87.secret_key_size(), 4896);
        assert_eq!(MlDsaParameterSet::MlDsa87.signature_size(), 4627);
        assert_eq!(MlDsaParameterSet::MlDsa87.nist_security_level(), 5);
    }

    #[test]
    fn test_ml_dsa_empty_message_sign_verify_roundtrip() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"";

        let signature = sk.sign(message, &[]).expect("Signing should succeed");
        let is_valid = pk.verify(message, &signature, &[]).expect("Verification should succeed");

        assert!(is_valid, "Empty message should sign and verify correctly");
    }

    #[test]
    fn test_ml_dsa_large_message_sign_verify_roundtrip() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let mut message = vec![0u8; 10_000];
        crate::primitives::rand::secure_rng().fill_bytes(&mut message);

        let signature = sk.sign(&message, &[]).expect("Signing should succeed");
        let is_valid = pk.verify(&message, &signature, &[]).expect("Verification should succeed");

        assert!(is_valid, "Large message should sign and verify correctly");
    }

    // Corrupted signature tests
    #[test]
    fn test_ml_dsa_corrupted_signature_first_byte_fails_verification_fails() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"Test message for corruption";
        let context: &[u8] = &[];

        let mut signature = sk.sign(message, context).expect("Signing should succeed");

        // Corrupt first byte of signature
        signature.data[0] ^= 0xFF;

        let is_valid =
            pk.verify(message, &signature, context).expect("Verification should not error");
        assert!(!is_valid, "Corrupted signature (first byte) must fail verification");
    }

    #[test]
    fn test_ml_dsa_corrupted_signature_middle_byte_fails_verification_fails() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"Test message for corruption";
        let context: &[u8] = &[];

        let mut signature = sk.sign(message, context).expect("Signing should succeed");

        // Corrupt middle byte of signature
        let middle_idx = signature.data.len() / 2;
        signature.data[middle_idx] ^= 0xFF;

        let is_valid =
            pk.verify(message, &signature, context).expect("Verification should not error");
        assert!(!is_valid, "Corrupted signature (middle byte) must fail verification");
    }

    #[test]
    fn test_ml_dsa_corrupted_signature_last_byte_fails_verification_fails() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"Test message for corruption";
        let context: &[u8] = &[];

        let mut signature = sk.sign(message, context).expect("Signing should succeed");

        // Corrupt last byte of signature
        let last_idx = signature.data.len() - 1;
        signature.data[last_idx] ^= 0xFF;

        let is_valid =
            pk.verify(message, &signature, context).expect("Verification should not error");
        assert!(!is_valid, "Corrupted signature (last byte) must fail verification");
    }

    #[test]
    fn test_ml_dsa_corrupted_signature_multiple_bytes_fails_verification_fails() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa65).expect("Key generation should succeed");
        let message = b"Test message for corruption";
        let context: &[u8] = &[];

        let mut signature = sk.sign(message, context).expect("Signing should succeed");

        // Corrupt multiple bytes at different positions
        let sig_len = signature.data.len();
        signature.data[0] ^= 0xFF;
        signature.data[100] ^= 0xFF;
        signature.data[sig_len - 1] ^= 0xFF;

        let is_valid =
            pk.verify(message, &signature, context).expect("Verification should not error");
        assert!(!is_valid, "Corrupted signature (multiple bytes) must fail verification");
    }

    // Context string tests
    #[test]
    fn test_ml_dsa_context_string_variations_bind_signature_is_correct() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"Test message with context";

        // Test with non-empty context
        let context1 = b"context string 1";
        let signature1 = sk.sign(message, context1).expect("Signing should succeed");
        let is_valid =
            pk.verify(message, &signature1, context1).expect("Verification should succeed");
        assert!(is_valid, "Signature with context1 should verify with same context");

        // Test with different context (should fail)
        let context2 = b"context string 2";
        let is_valid =
            pk.verify(message, &signature1, context2).expect("Verification should succeed");
        assert!(!is_valid, "Signature with context1 must fail verification with context2");

        // Test with empty context (should fail)
        let is_valid = pk.verify(message, &signature1, &[]).expect("Verification should succeed");
        assert!(!is_valid, "Signature with context1 must fail verification with empty context");
    }

    #[test]
    fn test_ml_dsa_empty_vs_nonempty_context_are_distinct_are_unique() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa87).expect("Key generation should succeed");
        let message = b"Test message";

        // Sign with empty context
        let empty_context: &[u8] = &[];
        let sig_empty = sk.sign(message, empty_context).expect("Signing should succeed");

        // Sign with non-empty context
        let non_empty_context = b"test context";
        let sig_nonempty = sk.sign(message, non_empty_context).expect("Signing should succeed");

        // Verify each signature with its own context
        assert!(
            pk.verify(message, &sig_empty, empty_context).expect("Verification should succeed")
        );
        assert!(
            pk.verify(message, &sig_nonempty, non_empty_context)
                .expect("Verification should succeed")
        );

        // Cross-verification should fail
        assert!(
            !pk.verify(message, &sig_empty, non_empty_context)
                .expect("Verification should succeed")
        );
        assert!(
            !pk.verify(message, &sig_nonempty, empty_context).expect("Verification should succeed")
        );
    }

    #[test]
    fn test_ml_dsa_long_context_string_sign_verify_roundtrip() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"Test message";

        // Test with maximum allowed context (255 bytes)
        let long_context = vec![0xAB; 255];
        let signature =
            sk.sign(message, &long_context).expect("Signing should succeed with max context");
        let is_valid =
            pk.verify(message, &signature, &long_context).expect("Verification should succeed");
        assert!(is_valid, "Signature with max-length context should verify");

        // Verify fails with different long context
        let different_context = vec![0xCD; 255];
        let is_valid = pk
            .verify(message, &signature, &different_context)
            .expect("Verification should succeed");
        assert!(!is_valid, "Signature must fail with different long context");
    }

    // Signature malleability resistance tests
    #[test]
    fn test_ml_dsa_signature_uniqueness_both_verify_succeeds() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"Test message for uniqueness";
        let context: &[u8] = &[];

        // Generate two signatures for the same message
        let sig1 = sk.sign(message, context).expect("First signing should succeed");
        let sig2 = sk.sign(message, context).expect("Second signing should succeed");

        // Both signatures should verify
        assert!(pk.verify(message, &sig1, context).expect("Verification should succeed"));
        assert!(pk.verify(message, &sig2, context).expect("Verification should succeed"));

        // Note: ML-DSA is randomized, so signatures may differ
        // This test verifies both are valid (no malleability exploitation)
    }

    #[test]
    fn test_ml_dsa_cross_parameter_set_incompatibility_fails() {
        let (_pk44, sk44) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let (pk65, _sk65) =
            generate_keypair(MlDsaParameterSet::MlDsa65).expect("Key generation should succeed");

        let message = b"Test cross-parameter incompatibility";
        let context: &[u8] = &[];

        let signature44 = sk44.sign(message, context).expect("Signing with MlDsa44 should succeed");

        // Verify signature44 fails with MlDsa65 public key (wrong parameter set)
        let result = pk65.verify(message, &signature44, context);
        // Should either error or return false
        match result {
            Ok(is_valid) => assert!(!is_valid, "Cross-parameter verification must fail"),
            Err(_) => {} // Error is also acceptable for incompatible parameter sets
        }
    }

    #[test]
    fn test_ml_dsa_invalid_signature_length_fails() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let message = b"Test message";
        let context: &[u8] = &[];

        let mut signature = sk.sign(message, context).expect("Signing should succeed");

        // Truncate signature (invalid length)
        signature.data.truncate(signature.data.len() - 10);

        let result = pk.verify(message, &signature, context);
        assert!(result.is_err(), "Verification with truncated signature should error");
    }

    #[test]
    fn test_ml_dsa_same_message_all_signatures_verify_succeeds() {
        let (pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa65).expect("Key generation should succeed");
        let message = b"Determinism test message";
        let context = b"test context";

        // Sign the same message multiple times
        let sig1 = sk.sign(message, context).expect("First signing should succeed");
        let sig2 = sk.sign(message, context).expect("Second signing should succeed");
        let sig3 = sk.sign(message, context).expect("Third signing should succeed");

        // All signatures should verify correctly
        assert!(pk.verify(message, &sig1, context).expect("Verification should succeed"));
        assert!(pk.verify(message, &sig2, context).expect("Verification should succeed"));
        assert!(pk.verify(message, &sig3, context).expect("Verification should succeed"));

        // Note: ML-DSA uses randomized signing, so signatures will differ
        // This test verifies all are valid (cryptographic soundness)
    }

    #[test]
    fn test_ml_dsa_all_parameter_sets_sign_verify_succeeds() {
        for param in
            [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
        {
            let (pk, sk) = generate_keypair(param).expect("Key generation should succeed");
            let message = b"Comprehensive test for all parameter sets";
            let context = b"test";

            // Test basic sign/verify
            let signature = sk.sign(message, context).expect("Signing should succeed");
            assert!(pk.verify(message, &signature, context).expect("Verification should succeed"));

            // Test wrong message
            let wrong_msg = b"wrong message";
            assert!(
                !pk.verify(wrong_msg, &signature, context).expect("Verification should succeed")
            );

            // Test wrong context
            let wrong_ctx = b"wrong";
            assert!(
                !pk.verify(message, &signature, wrong_ctx).expect("Verification should succeed")
            );

            // Test corrupted signature
            let mut corrupted_sig = signature.clone();
            corrupted_sig.data[0] ^= 0xFF;
            assert!(
                !pk.verify(message, &corrupted_sig, context).expect("Verification should succeed")
            );
        }
    }

    // ========================================================================
    // Phase 4: Additional coverage tests
    // ========================================================================

    #[test]
    fn test_ml_dsa_secret_key_constant_time_eq_is_correct() {
        let (_, sk1) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let (_, sk2) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");

        // Secret-key equality goes through `ct_eq` (invariants I-5/I-6).
        assert!(bool::from(sk1.ct_eq(&sk1)));
        assert!(!bool::from(sk1.ct_eq(&sk2)));
    }

    // ========================================================================
    // Error path coverage tests
    // ========================================================================

    #[test]
    fn test_ml_dsa_public_key_new_wrong_length_fails() {
        let result = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa44, vec![0u8; 100]);
        assert!(result.is_err());
        match result.unwrap_err() {
            MlDsaError::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 1312);
                assert_eq!(actual, 100);
            }
            other => panic!("Expected InvalidKeyLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_ml_dsa_secret_key_new_wrong_length_fails() {
        let result = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa65, vec![0u8; 100]);
        assert!(result.is_err());
        match result.unwrap_err() {
            MlDsaError::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 4032);
                assert_eq!(actual, 100);
            }
            other => panic!("Expected InvalidKeyLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_ml_dsa_signature_new_wrong_length_fails() {
        let result = MlDsaSignature::new(MlDsaParameterSet::MlDsa87, vec![0u8; 100]);
        assert!(result.is_err());
        match result.unwrap_err() {
            MlDsaError::InvalidSignatureLength { expected, actual } => {
                assert_eq!(expected, 4627);
                assert_eq!(actual, 100);
            }
            other => panic!("Expected InvalidSignatureLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_ml_dsa_public_key_new_valid_lengths_succeeds() {
        let pk44 = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa44, vec![0u8; 1312]);
        assert!(pk44.is_ok());
        let pk65 = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa65, vec![0u8; 1952]);
        assert!(pk65.is_ok());
        let pk87 = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa87, vec![0u8; 2592]);
        assert!(pk87.is_ok());
    }

    #[test]
    fn test_ml_dsa_secret_key_accessors_return_correct_values_succeeds() {
        let (_, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        assert_eq!(sk.parameter_set(), MlDsaParameterSet::MlDsa44);
        assert_eq!(sk.len(), 2560);
        assert!(!sk.is_empty());
        assert_eq!(sk.expose_secret().len(), 2560);
    }

    #[test]
    fn test_ml_dsa_signature_accessors_return_correct_values_succeeds() {
        let (_, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let sig = sk.sign(b"test", &[]).expect("Signing should succeed");
        assert_eq!(sig.parameter_set(), MlDsaParameterSet::MlDsa44);
        assert_eq!(sig.len(), 2420);
        assert!(!sig.is_empty());
        assert_eq!(sig.as_bytes().len(), 2420);
    }

    #[test]
    fn test_ml_dsa_error_display_all_variants_are_non_empty_fails() {
        let err = MlDsaError::KeyGenerationError("test".to_string());
        assert!(format!("{err}").contains("test"));

        let err = MlDsaError::SigningError("sign fail".to_string());
        assert!(format!("{err}").contains("sign fail"));

        let err = MlDsaError::VerificationError("verify fail".to_string());
        assert!(format!("{err}").contains("verify fail"));

        let err = MlDsaError::InvalidParameterSet("bad param".to_string());
        assert!(format!("{err}").contains("bad param"));

        let err = MlDsaError::CryptoError("crypto fail".to_string());
        assert!(format!("{err}").contains("crypto fail"));

        let err = MlDsaError::InvalidKeyLength { expected: 32, actual: 16 };
        let msg = format!("{err}");
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));

        let err = MlDsaError::InvalidSignatureLength { expected: 2420, actual: 100 };
        let msg = format!("{err}");
        assert!(msg.contains("2420"));
        assert!(msg.contains("100"));
    }

    #[test]
    fn test_ml_dsa_parameter_set_clone_copy_eq_is_correct() {
        let p = MlDsaParameterSet::MlDsa65;
        let p2 = p;
        assert_eq!(p, p2);
        let p3 = p;
        assert_eq!(p, p3);
        let debug = format!("{:?}", p);
        assert!(debug.contains("MlDsa65"));
    }

    #[test]
    fn test_ml_dsa_public_key_as_bytes_has_correct_length_has_correct_size() {
        let (pk, _) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        assert_eq!(pk.as_bytes().len(), 1312);
        assert_eq!(pk.as_bytes().len(), 1312);
    }

    #[test]
    fn test_ml_dsa_verify_mismatched_parameter_sets_returns_err() {
        let (pk44, sk44) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let sig44 = sk44.sign(b"test", &[]).expect("Signing should succeed");

        // Create a signature claiming to be MlDsa65 but with MlDsa44 data
        let mismatched_sig =
            MlDsaSignature { parameter_set: MlDsaParameterSet::MlDsa65, data: sig44.data };

        // verify() returns Err(ParameterSetMismatch) for parameter-set
        // mismatch — this is a configuration error, not a forgery, so
        // callers cannot conflate it with `Ok(false)` for a real invalid
        // signature.
        let result = pk44.verify(b"test", &mismatched_sig, &[]);
        match result {
            Err(MlDsaError::ParameterSetMismatch { key, signature }) => {
                assert_eq!(key, MlDsaParameterSet::MlDsa44);
                assert_eq!(signature, MlDsaParameterSet::MlDsa65);
            }
            other => panic!("expected ParameterSetMismatch, got {other:?}"),
        }
    }

    // ---- Coverage: parameter set sizes and empty message ----

    #[test]
    fn test_ml_dsa_parameter_set_sizes_match_spec_has_correct_size() {
        // MlDsa44
        assert_eq!(MlDsaParameterSet::MlDsa44.public_key_size(), 1312);
        assert_eq!(MlDsaParameterSet::MlDsa44.secret_key_size(), 2560);
        assert_eq!(MlDsaParameterSet::MlDsa44.signature_size(), 2420);

        // MlDsa65
        assert_eq!(MlDsaParameterSet::MlDsa65.public_key_size(), 1952);
        assert_eq!(MlDsaParameterSet::MlDsa65.secret_key_size(), 4032);
        assert_eq!(MlDsaParameterSet::MlDsa65.signature_size(), 3309);

        // MlDsa87
        assert_eq!(MlDsaParameterSet::MlDsa87.public_key_size(), 2592);
        assert_eq!(MlDsaParameterSet::MlDsa87.secret_key_size(), 4896);
        assert_eq!(MlDsaParameterSet::MlDsa87.signature_size(), 4627);
    }

    #[test]
    fn test_ml_dsa_sign_empty_message_succeeds() -> Result<(), MlDsaError> {
        let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44)?;
        let empty_msg: &[u8] = b"";

        let sig = sk.sign(empty_msg, &[])?;
        let valid = pk.verify(empty_msg, &sig, &[])?;
        assert!(valid, "Empty message signature should be valid");
        Ok(())
    }

    #[test]
    fn test_ml_dsa_sign_with_context_succeeds() -> Result<(), MlDsaError> {
        let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44)?;
        let message = b"Message with context";
        let context = b"application-context";

        let sig = sk.sign(message, context)?;
        let valid = pk.verify(message, &sig, context)?;
        assert!(valid, "Signature with context should be valid");

        // Wrong context should fail
        let valid_wrong_ctx = pk.verify(message, &sig, b"wrong-context")?;
        assert!(!valid_wrong_ctx, "Wrong context should fail verification");
        Ok(())
    }

    #[test]
    fn test_ml_dsa_signature_len_and_is_empty_returns_correct_values_succeeds() {
        let (_pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa44).expect("Key generation should succeed");
        let sig = sk.sign(b"test", &[]).expect("Signing should succeed");

        assert_eq!(sig.len(), MlDsaParameterSet::MlDsa44.signature_size());
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_ml_dsa_secret_key_parameter_set_returns_correct_set_succeeds() {
        let (_pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa65).expect("Key generation should succeed");
        assert_eq!(sk.parameter_set(), MlDsaParameterSet::MlDsa65);
    }

    /// An oversized message must be rejected by `sign()` before
    /// reaching the upstream crate. The cap-rejection variant
    /// collapsed to the opaque `SigningError` (was a distinguishable
    /// `MessageTooLong`) so a caller probing the cap cannot recover
    /// its configured value from the returned variant.
    #[test]
    fn test_ml_dsa_sign_oversized_message_rejects_opaquely() {
        let (_pk, sk) =
            generate_keypair(MlDsaParameterSet::MlDsa65).expect("Key generation should succeed");
        let oversize: Vec<u8> = vec![0u8; (64 * 1024) + 1];
        let err = sk.sign(&oversize, b"").expect_err("oversized message must be rejected");
        assert!(matches!(err, MlDsaError::SigningError(_)), "expected SigningError, got {err:?}");
    }
}
