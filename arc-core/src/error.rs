//! Error types for LatticeArc Core operations.
//!
//! Provides a comprehensive error enum covering all cryptographic operations,
//! configuration validation, hardware issues, and authentication failures.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use thiserror::Error;

/// Errors that can occur during LatticeArc Core operations.
///
/// This enum covers all error conditions from cryptographic operations,
/// configuration validation, hardware acceleration, and authentication.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Invalid input provided to an operation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Key length does not match expected size.
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },

    /// Encryption operation failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Key derivation function failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid nonce provided.
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Hardware-related error occurred.
    #[error("Hardware error: {0}")]
    HardwareError(String),

    /// Configuration validation error.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Cryptographic scheme selection failed.
    #[error("Scheme selection failed: {0}")]
    SchemeSelectionFailed(String),

    /// Authentication operation failed.
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Zero-trust verification check failed.
    #[error("Zero-trust verification failed: {0}")]
    ZeroTrustVerificationFailed(String),

    /// Zero Trust authentication is required but not provided.
    ///
    /// This error occurs when a cryptographic operation requires a
    /// `VerifiedSession` but none was provided or established.
    #[error("Authentication required: {0}")]
    AuthenticationRequired(String),

    /// The session has expired and needs re-authentication.
    ///
    /// Sessions have a limited lifetime for security. When this error
    /// occurs, establish a new session using `VerifiedSession::establish()`.
    #[error("Session expired")]
    SessionExpired,

    /// Requested operation is not supported.
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Memory allocation or management error.
    #[error("Memory allocation failed: {0}")]
    MemoryError(String),

    /// Standard I/O error.
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// ML-KEM cryptographic operation error.
    #[error("ML-KEM error: {0}")]
    MlKemError(#[from] arc_primitives::kem::ml_kem::MlKemError),

    /// ML-DSA signature operation error.
    #[error("ML-DSA error: {0}")]
    MlDsaError(#[from] arc_primitives::sig::ml_dsa::MlDsaError),

    /// SLH-DSA signature operation error.
    #[error("SLH-DSA error: {0}")]
    SlhDsaError(#[from] arc_primitives::sig::slh_dsa::SlhDsaError),

    /// Serialization or deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Recoverable error with suggested action.
    #[error("Recoverable error: {message}. Suggestion: {suggestion}")]
    Recoverable {
        /// Error message describing what went wrong.
        message: String,
        /// Suggested action to recover from this error.
        suggestion: String,
    },

    /// Hardware acceleration is unavailable.
    #[error("Hardware acceleration unavailable: {reason}. Fallback: {fallback}")]
    HardwareUnavailable {
        /// Reason why hardware acceleration is unavailable.
        reason: String,
        /// Fallback strategy to use.
        fallback: String,
    },

    /// Entropy source has been depleted.
    #[error("Entropy source depleted: {message}. Action: {action}")]
    EntropyDepleted {
        /// Description of the entropy depletion.
        message: String,
        /// Recommended action to address the issue.
        action: String,
    },

    /// Key generation operation failed.
    #[error("Key generation failed: {reason}. Recovery: {recovery}")]
    KeyGenerationFailed {
        /// Reason for the key generation failure.
        reason: String,
        /// Recovery steps to address the failure.
        recovery: String,
    },

    /// Cryptographic self-test failed.
    #[error("Self-test failed: {component}. Status: {status}")]
    SelfTestFailed {
        /// Component that failed the self-test.
        component: String,
        /// Status or details of the failure.
        status: String,
    },

    /// Requested feature is not available.
    #[error("Feature not available: {0}")]
    FeatureNotAvailable(String),

    /// Invalid signature detected.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid cryptographic key.
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Feature is not yet implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    /// Signature creation failed.
    #[error("Signature failed: {0}")]
    SignatureFailed(String),

    /// Hardware Security Module error.
    #[error("HSM error: {0}")]
    HsmError(String),

    /// Resource limit has been exceeded.
    #[error("Resource limit exceeded: {0}")]
    ResourceExceeded(String),

    /// Invalid key lifecycle state transition attempted.
    #[error("Invalid key state transition: {from:?} -> {to:?}")]
    InvalidStateTransition {
        /// Original key state.
        from: crate::key_lifecycle::KeyLifecycleState,
        /// Target key state that was rejected.
        to: crate::key_lifecycle::KeyLifecycleState,
    },

    /// Audit storage operation failed.
    #[error("Audit error: {0}")]
    AuditError(String),
}

/// A specialized Result type for LatticeArc Core operations.
pub type Result<T> = std::result::Result<T, CoreError>;
