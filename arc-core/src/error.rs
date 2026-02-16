//! Error types for LatticeArc Core operations.
//!
//! Provides a comprehensive error enum covering all cryptographic operations,
//! configuration validation, hardware issues, and authentication failures.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use thiserror::Error;

// Re-export TypeError from arc-types so downstream consumers can handle it
// (returned by config validate() methods and CryptoPolicyEngine methods)
pub use arc_types::error::TypeError;

/// Errors that can occur during LatticeArc Core operations.
///
/// This enum covers all error conditions from cryptographic operations,
/// configuration validation, hardware acceleration, and authentication.
#[derive(Debug, Error)]
#[non_exhaustive]
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

/// Conversion from pure-Rust `TypeError` (arc-types) into FFI-aware `CoreError`.
///
/// This allows the `?` operator to work seamlessly when arc-types functions
/// (which return `TypeError`) are called from arc-core functions (which return `CoreError`).
impl From<TypeError> for CoreError {
    fn from(err: TypeError) -> Self {
        match err {
            TypeError::InvalidStateTransition { from, to } => {
                CoreError::InvalidStateTransition { from, to }
            }
            TypeError::ConfigurationError(msg) => CoreError::ConfigurationError(msg),
            _ => CoreError::InvalidInput(err.to_string()),
        }
    }
}

/// A specialized Result type for LatticeArc Core operations.
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_core_error_display_invalid_input() {
        let err = CoreError::InvalidInput("bad data".to_string());
        assert_eq!(format!("{err}"), "Invalid input: bad data");
    }

    #[test]
    fn test_core_error_display_invalid_key_length() {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: 16 };
        assert_eq!(format!("{err}"), "Invalid key length: expected 32, got 16");
    }

    #[test]
    fn test_core_error_display_encryption_failed() {
        let err = CoreError::EncryptionFailed("buffer too small".to_string());
        assert_eq!(format!("{err}"), "Encryption failed: buffer too small");
    }

    #[test]
    fn test_core_error_display_decryption_failed() {
        let err = CoreError::DecryptionFailed("auth tag mismatch".to_string());
        assert_eq!(format!("{err}"), "Decryption failed: auth tag mismatch");
    }

    #[test]
    fn test_core_error_display_verification_failed() {
        let err = CoreError::VerificationFailed;
        assert_eq!(format!("{err}"), "Signature verification failed");
    }

    #[test]
    fn test_core_error_display_session_expired() {
        let err = CoreError::SessionExpired;
        assert_eq!(format!("{err}"), "Session expired");
    }

    #[test]
    fn test_core_error_display_recoverable() {
        let err = CoreError::Recoverable {
            message: "temporary failure".to_string(),
            suggestion: "retry after 5s".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("temporary failure"));
        assert!(msg.contains("retry after 5s"));
    }

    #[test]
    fn test_core_error_display_hardware_unavailable() {
        let err = CoreError::HardwareUnavailable {
            reason: "no AES-NI".to_string(),
            fallback: "software AES".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("no AES-NI"));
        assert!(msg.contains("software AES"));
    }

    #[test]
    fn test_core_error_display_entropy_depleted() {
        let err = CoreError::EntropyDepleted {
            message: "pool empty".to_string(),
            action: "wait and retry".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("pool empty"));
        assert!(msg.contains("wait and retry"));
    }

    #[test]
    fn test_core_error_display_key_generation_failed() {
        let err = CoreError::KeyGenerationFailed {
            reason: "insufficient entropy".to_string(),
            recovery: "seed from HSM".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("insufficient entropy"));
        assert!(msg.contains("seed from HSM"));
    }

    #[test]
    fn test_core_error_display_self_test_failed() {
        let err = CoreError::SelfTestFailed {
            component: "AES-GCM".to_string(),
            status: "KAT mismatch".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("AES-GCM"));
        assert!(msg.contains("KAT mismatch"));
    }

    #[test]
    fn test_core_error_display_serialization() {
        let err = CoreError::SerializationError("invalid JSON".to_string());
        assert_eq!(format!("{err}"), "Serialization error: invalid JSON");
    }

    #[test]
    fn test_core_error_display_feature_not_available() {
        let err = CoreError::FeatureNotAvailable("HSM support".to_string());
        assert_eq!(format!("{err}"), "Feature not available: HSM support");
    }

    #[test]
    fn test_core_error_display_not_implemented() {
        let err = CoreError::NotImplemented("FN-DSA Level 5".to_string());
        assert_eq!(format!("{err}"), "Not implemented: FN-DSA Level 5");
    }

    #[test]
    fn test_core_error_display_hsm_error() {
        let err = CoreError::HsmError("connection lost".to_string());
        assert_eq!(format!("{err}"), "HSM error: connection lost");
    }

    #[test]
    fn test_core_error_display_resource_exceeded() {
        let err = CoreError::ResourceExceeded("max connections".to_string());
        assert_eq!(format!("{err}"), "Resource limit exceeded: max connections");
    }

    #[test]
    fn test_core_error_display_audit_error() {
        let err = CoreError::AuditError("write failed".to_string());
        assert_eq!(format!("{err}"), "Audit error: write failed");
    }

    #[test]
    fn test_core_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: CoreError = io_err.into();
        let msg = format!("{err}");
        assert!(msg.contains("file missing"));
    }

    #[test]
    fn test_core_error_debug() {
        let err = CoreError::InvalidInput("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidInput"));
    }

    #[test]
    fn test_core_error_all_simple_variants() {
        // Ensure all simple string variants produce correct output
        let cases: Vec<(CoreError, &str)> = vec![
            (CoreError::KeyDerivationFailed("kdf".to_string()), "Key derivation failed: kdf"),
            (CoreError::InvalidNonce("nonce".to_string()), "Invalid nonce: nonce"),
            (CoreError::HardwareError("hw".to_string()), "Hardware error: hw"),
            (CoreError::ConfigurationError("cfg".to_string()), "Configuration error: cfg"),
            (CoreError::SchemeSelectionFailed("sel".to_string()), "Scheme selection failed: sel"),
            (CoreError::AuthenticationFailed("auth".to_string()), "Authentication failed: auth"),
            (
                CoreError::ZeroTrustVerificationFailed("zt".to_string()),
                "Zero-trust verification failed: zt",
            ),
            (CoreError::AuthenticationRequired("req".to_string()), "Authentication required: req"),
            (CoreError::UnsupportedOperation("op".to_string()), "Unsupported operation: op"),
            (CoreError::MemoryError("mem".to_string()), "Memory allocation failed: mem"),
            (CoreError::InvalidSignature("sig".to_string()), "Invalid signature: sig"),
            (CoreError::InvalidKey("key".to_string()), "Invalid key: key"),
            (CoreError::SignatureFailed("sf".to_string()), "Signature failed: sf"),
        ];

        for (error, expected_msg) in cases {
            assert_eq!(format!("{error}"), expected_msg);
        }
    }
}
