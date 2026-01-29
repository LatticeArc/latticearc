#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Error types for LatticeArc cryptographic operations.
//!
//! This module defines the error types used throughout the LatticeArc library,
//! including [`CryptoError`] for general cryptographic errors, [`VerificationError`]
//! for signature and proof verification failures, and [`HardwareError`] for
//! hardware acceleration issues.

use subtle::Choice;
use thiserror::Error;

/// General cryptographic errors.
///
/// This enum represents errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid key length.
    ///
    /// This occurs when a key has the wrong length for the chosen algorithm.
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Invalid input.
    ///
    /// This occurs when input data is invalid (e.g., empty, malformed).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Encryption failed.
    ///
    /// This occurs when encryption operation fails.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    ///
    /// This occurs when decryption operation fails.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Signature verification failed.
    ///
    /// This occurs when signature verification fails.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid signature.
    ///
    /// This occurs when a signature is invalid.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Key derivation failed.
    ///
    /// This occurs when key derivation operation fails.
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Hardware error.
    ///
    /// This occurs when hardware acceleration fails.
    #[error("Hardware error: {0}")]
    HardwareError(#[from] HardwareError),

    /// Configuration error.
    ///
    /// This occurs when configuration is invalid.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Not implemented.
    ///
    /// This occurs when a feature is not implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    /// Invalid nonce.
    ///
    /// This occurs when a nonce is invalid.
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Invalid tag.
    ///
    /// This occurs when an authentication tag is invalid.
    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    /// Invalid ciphertext.
    ///
    /// This occurs when ciphertext is invalid.
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Unsupported algorithm.
    ///
    /// This occurs when algorithm is not supported.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Random number generation failed.
    ///
    /// This occurs when random number generation fails.
    #[error("Random number generation failed: {0}")]
    RandomError(String),

    /// Serialization error.
    ///
    /// This occurs when serialization/deserialization fails.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Zeroization failed.
    ///
    /// This occurs when zeroization of sensitive data fails.
    #[error("Zeroization failed")]
    ZeroizationFailed,
}

/// Verification errors.
///
/// This enum represents errors that can occur during verification operations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
    /// Signature is invalid.
    #[error("Signature verification failed")]
    SignatureInvalid,

    /// Proof is invalid.
    #[error("Proof verification failed")]
    ProofInvalid,

    /// Authentication failed.
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Proof of possession is invalid.
    #[error("Proof of possession invalid")]
    PopInvalid,
}

impl VerificationError {
    /// Convert this error to a constant-time `Choice`.
    ///
    /// This is useful for constant-time comparisons.
    ///
    /// # Returns
    ///
    /// `Choice::from(0)` for all errors
    pub fn into_choice(self) -> Choice {
        match self {
            VerificationError::SignatureInvalid
            | VerificationError::ProofInvalid
            | VerificationError::AuthenticationFailed
            | VerificationError::PopInvalid => Choice::from(0),
        }
    }
}

/// Hardware errors.
///
/// This enum represents errors that can occur during hardware operations.
#[derive(Debug, Error)]
pub enum HardwareError {
    /// Hardware not available.
    ///
    /// This occurs when requested hardware is not available.
    #[error("Hardware not available: {0}")]
    NotAvailable(String),

    /// Hardware initialization failed.
    ///
    /// This occurs when hardware initialization fails.
    #[error("Hardware initialization failed: {0}")]
    InitializationFailed(String),

    /// Hardware acceleration failed.
    ///
    /// This occurs when hardware acceleration operation fails.
    #[error("Hardware acceleration failed: {0}")]
    AccelerationFailed(String),

    /// Hardware fallback to CPU failed.
    ///
    /// This occurs when fallback to CPU fails.
    #[error("Hardware fallback to CPU failed: {0}")]
    FallbackFailed(String),

    /// Hardware detection failed.
    ///
    /// This occurs when hardware detection fails.
    #[error("Hardware detection failed: {0}")]
    DetectionFailed(String),

    /// Hardware timeout.
    ///
    /// This occurs when hardware operation times out.
    #[error("Hardware timeout: {0}")]
    Timeout(String),

    /// Hardware driver error.
    ///
    /// This occurs when hardware driver error occurs.
    #[error("Hardware driver error: {0}")]
    DriverError(String),
}
