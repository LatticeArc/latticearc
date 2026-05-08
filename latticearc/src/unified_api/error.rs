//! Error types for LatticeArc Core operations.
//!
//! Provides a comprehensive error enum covering all cryptographic operations,
//! configuration validation, hardware issues, and authentication failures.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use thiserror::Error;

// Re-export TypeError from types module so downstream consumers can handle it
// (returned by config validate() methods and CryptoPolicyEngine methods)
pub use crate::types::error::TypeError;

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
    MlKemError(#[from] crate::primitives::kem::ml_kem::MlKemError),

    /// ML-DSA signature operation error.
    #[error("ML-DSA error: {0}")]
    MlDsaError(#[from] crate::primitives::sig::ml_dsa::MlDsaError),

    /// SLH-DSA signature operation error.
    #[error("SLH-DSA error: {0}")]
    SlhDsaError(#[from] crate::primitives::sig::slh_dsa::SlhDsaError),

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
        from: crate::unified_api::KeyLifecycleState,
        /// Target key state that was rejected.
        to: crate::unified_api::KeyLifecycleState,
    },

    /// Audit storage operation failed.
    #[error("Audit error: {0}")]
    AuditError(String),

    /// Operation violates the configured compliance mode.
    ///
    /// Returned when an algorithm or scheme is not permitted under the active
    /// compliance policy (e.g., FIPS 140-3 rejecting ChaCha20-Poly1305, or
    /// CNSA 2.0 rejecting classical-only algorithms like Ed25519).
    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),

    /// Internal/infrastructural failure that doesn't fit a more specific
    /// category. Used as the catch-all destination when mapping
    /// `LatticeArcError` variants that don't have a `CoreError` peer (e.g.,
    /// `RandomError`, generic `IoError(String)`).
    #[error("Internal error: {0}")]
    Internal(String),

    /// A ciphertext was rejected because its stamped `EncryptedOutput.timestamp`
    /// is older than the receiver's configured `CryptoConfig::max_age` window.
    ///
    /// Returned exclusively by the convenience-API replay-protection guard
    ///. Distinct from `ResourceExceeded` (which signals
    /// "the data itself is too big") so callers can pattern-match
    /// `CoreError::Replay { .. }` and react appropriately — e.g., prompt
    /// the sender to re-encrypt with a fresh timestamp, or alert on a
    /// suspected replay attack.
    ///
    /// # Pattern 6 exception
    ///
    /// This variant carries non-opaque fields (`age_seconds`,
    /// `max_age_seconds`) on what IS an adversary-reachable code path
    /// (`decrypt`). Pattern 6 normally requires opaque returned errors
    /// on such paths. The carve-out is acceptable here because:
    ///
    /// 1. Neither field is derived from secret material. `age_seconds`
    ///    is `now - encrypted.timestamp()` where the timestamp is a
    ///    public field stamped at encrypt; `max_age_seconds` is the
    ///    receiver's own configuration value, supplied through
    ///    `CryptoConfig::max_age` and not derivable from any secret.
    /// 2. The information leaked is identical to what an attacker
    ///    already infers from observing the API: a Replay rejection
    ///    means "your stamped age was too old"; an attacker tuning a
    ///    replay attack already knows the stamp they sent and can
    ///    binary-search the receiver's `max_age` purely from
    ///    request-acceptance vs request-rejection on the wire.
    /// 3. Operators need both fields to diagnose clock-skew false
    ///    rejections vs. configuration tightening events; collapsing
    ///    to the opaque `DecryptionError` would force them through
    ///    private logs for a routine operational signal.
    ///
    /// audit approved this carve-out;
    /// requires the inline justification per `docs/DESIGN_PATTERNS.md`
    /// Pattern 12 ("inline `#[allow]` justification" convention).
    #[error(
        "Replay rejected: stamped age {age_seconds}s exceeds configured max_age {max_age_seconds}s. Re-encrypt with a fresh timestamp, or relax CryptoConfig::max_age."
    )]
    Replay {
        /// Observed age (seconds) — `now - encrypted.timestamp()`.
        age_seconds: u64,
        /// Configured replay window (seconds).
        max_age_seconds: u64,
    },
}

/// Conversion from `LatticeArcError` (the lower-level prelude error type) into `CoreError`.
///
/// Lets `?` compose across layers: a function returning `Result<T, CoreError>`
/// can call into prelude code returning `Result<T, LatticeArcError>` without
/// the caller falling back to `Box<dyn Error>`. The mapping preserves the
/// failure category (encryption / serialization / IO / etc.) with a
/// stringified inner message — fine for diagnostic surface, not intended as
/// a security boundary (callers must not pattern-match on the message).
impl From<crate::prelude::LatticeArcError> for CoreError {
    fn from(err: crate::prelude::LatticeArcError) -> Self {
        use crate::prelude::LatticeArcError as L;
        match err {
            L::EncryptionError(s) => CoreError::EncryptionFailed(s),
            L::DecryptionError(s) => CoreError::DecryptionFailed(s),
            L::SerializationError(s) => CoreError::SerializationError(s),
            L::IoError(s) => CoreError::Internal(format!("I/O: {s}")),
            L::InvalidInput(s) => CoreError::InvalidInput(s),
            L::InvalidData(s) => CoreError::InvalidInput(s),
            L::RandomError => CoreError::Internal("RNG failure".to_string()),
            other => CoreError::Internal(other.to_string()),
        }
    }
}

/// Conversion from pure-Rust `TypeError` into FFI-aware `CoreError`.
///
/// This allows the `?` operator to work seamlessly when [`types`](crate::types) functions
/// (which return `TypeError`) are called from [`unified_api`](crate::unified_api) functions (which return `CoreError`).
impl From<TypeError> for CoreError {
    fn from(err: TypeError) -> Self {
        match err {
            TypeError::InvalidStateTransition { from, to } => {
                CoreError::InvalidStateTransition { from, to }
            }
            TypeError::ConfigurationError(msg) => CoreError::ConfigurationError(msg),
            TypeError::UnknownScheme(scheme) => {
                CoreError::ConfigurationError(format!("Unknown encryption scheme: {scheme}"))
            }
            TypeError::InvalidAuditInput(msg) => {
                CoreError::ConfigurationError(format!("Audit input invalid: {msg}"))
            }
        }
    }
}

/// A specialized Result type for LatticeArc Core operations.
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_error_display_invalid_input_has_correct_format() {
        let err = CoreError::InvalidInput("bad data".to_string());
        assert_eq!(format!("{err}"), "Invalid input: bad data");
    }

    #[test]
    fn test_core_error_display_invalid_key_length_has_correct_format() {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: 16 };
        assert_eq!(format!("{err}"), "Invalid key length: expected 32, got 16");
    }

    #[test]
    fn test_core_error_display_encryption_failed_has_correct_format() {
        let err = CoreError::EncryptionFailed("buffer too small".to_string());
        assert_eq!(format!("{err}"), "Encryption failed: buffer too small");
    }

    #[test]
    fn test_core_error_display_decryption_failed_has_correct_format() {
        let err = CoreError::DecryptionFailed("auth tag mismatch".to_string());
        assert_eq!(format!("{err}"), "Decryption failed: auth tag mismatch");
    }

    #[test]
    fn test_core_error_display_verification_failed_has_correct_format() {
        let err = CoreError::VerificationFailed;
        assert_eq!(format!("{err}"), "Signature verification failed");
    }

    #[test]
    fn test_core_error_display_session_expired_has_correct_format() {
        let err = CoreError::SessionExpired;
        assert_eq!(format!("{err}"), "Session expired");
    }

    #[test]
    fn test_core_error_display_recoverable_includes_message_and_suggestion_fails() {
        let err = CoreError::Recoverable {
            message: "temporary failure".to_string(),
            suggestion: "retry after 5s".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("temporary failure"));
        assert!(msg.contains("retry after 5s"));
    }

    #[test]
    fn test_core_error_display_hardware_unavailable_includes_reason_and_fallback_fails() {
        let err = CoreError::HardwareUnavailable {
            reason: "no AES-NI".to_string(),
            fallback: "software AES".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("no AES-NI"));
        assert!(msg.contains("software AES"));
    }

    #[test]
    fn test_core_error_display_entropy_depleted_includes_message_and_action_fails() {
        let err = CoreError::EntropyDepleted {
            message: "pool empty".to_string(),
            action: "wait and retry".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("pool empty"));
        assert!(msg.contains("wait and retry"));
    }

    #[test]
    fn test_core_error_display_key_generation_failed_includes_reason_and_recovery_fails() {
        let err = CoreError::KeyGenerationFailed {
            reason: "insufficient entropy".to_string(),
            recovery: "seed from HSM".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("insufficient entropy"));
        assert!(msg.contains("seed from HSM"));
    }

    #[test]
    fn test_core_error_display_self_test_failed_includes_component_and_status_fails() {
        let err = CoreError::SelfTestFailed {
            component: "AES-GCM".to_string(),
            status: "KAT mismatch".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("AES-GCM"));
        assert!(msg.contains("KAT mismatch"));
    }

    #[test]
    fn test_core_error_display_serialization_has_correct_format() {
        let err = CoreError::SerializationError("invalid JSON".to_string());
        assert_eq!(format!("{err}"), "Serialization error: invalid JSON");
    }

    #[test]
    fn test_core_error_display_feature_not_available_fails() {
        let err = CoreError::FeatureNotAvailable("HSM support".to_string());
        assert_eq!(format!("{err}"), "Feature not available: HSM support");
    }

    #[test]
    fn test_core_error_display_not_implemented_has_correct_format() {
        let err = CoreError::NotImplemented("FN-DSA Level 5".to_string());
        assert_eq!(format!("{err}"), "Not implemented: FN-DSA Level 5");
    }

    #[test]
    fn test_core_error_display_hsm_error_has_correct_format() {
        let err = CoreError::HsmError("connection lost".to_string());
        assert_eq!(format!("{err}"), "HSM error: connection lost");
    }

    #[test]
    fn test_core_error_display_resource_exceeded_has_correct_format() {
        let err = CoreError::ResourceExceeded("max connections".to_string());
        assert_eq!(format!("{err}"), "Resource limit exceeded: max connections");
    }

    #[test]
    fn test_core_error_display_audit_error_has_correct_format() {
        let err = CoreError::AuditError("write failed".to_string());
        assert_eq!(format!("{err}"), "Audit error: write failed");
    }

    #[test]
    fn test_core_error_from_io_error_converts_correctly_fails() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: CoreError = io_err.into();
        let msg = format!("{err}");
        assert!(msg.contains("file missing"));
    }

    #[test]
    fn test_core_error_debug_contains_variant_name_fails() {
        let err = CoreError::InvalidInput("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidInput"));
    }

    #[test]
    fn test_core_error_all_simple_variants_have_correct_format_fails() {
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
            (
                CoreError::ComplianceViolation("FIPS rejects chacha".to_string()),
                "Compliance violation: FIPS rejects chacha",
            ),
            (CoreError::Internal("RNG failure".to_string()), "Internal error: RNG failure"),
        ];

        for (error, expected_msg) in cases {
            assert_eq!(format!("{error}"), expected_msg);
        }
    }

    #[test]
    fn test_core_error_from_lattice_arc_error_random_maps_to_internal_succeeds() {
        let inner = crate::prelude::LatticeArcError::RandomError;
        let err: CoreError = inner.into();
        assert!(matches!(err, CoreError::Internal(_)));
        assert_eq!(format!("{err}"), "Internal error: RNG failure");
    }

    #[test]
    fn test_core_error_replay_display_includes_both_ages_succeeds() {
        let err = CoreError::Replay { age_seconds: 600, max_age_seconds: 300 };
        let msg = format!("{err}");
        assert!(msg.contains("600"), "Replay Display must surface the observed age");
        assert!(msg.contains("300"), "Replay Display must surface the configured max_age");
        assert!(
            msg.contains("max_age"),
            "Replay Display must mention max_age so the operator knows where to look"
        );
    }

    #[test]
    fn test_core_error_from_lattice_arc_error_encryption_maps_to_encryption_failed_succeeds() {
        let inner = crate::prelude::LatticeArcError::EncryptionError("aead".to_string());
        let err: CoreError = inner.into();
        assert!(matches!(err, CoreError::EncryptionFailed(s) if s == "aead"));
    }
}
