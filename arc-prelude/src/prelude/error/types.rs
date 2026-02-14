//! Core Error Types for LatticeArc
//!
//! This module defines the comprehensive error types used throughout
//! the LatticeArc library for cryptographic operations.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use thiserror::Error;

/// Error type conversion implementations.
pub mod conversions;
/// Error recovery strategies and utilities.
pub mod recovery;

/// Result type alias for `LatticeArc` operations
pub type Result<T> = std::result::Result<T, LatticeArcError>;

/// Comprehensive error type for all `LatticeArc` operations
///
/// This enum covers all possible error conditions that can occur during
/// cryptographic operations, key management, serialization, and I/O.
#[derive(Debug, Error, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LatticeArcError {
    /// Encryption operation failed
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    /// Decryption operation failed
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    /// Key generation failed
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),
    /// Invalid or corrupted key
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    /// KEM encapsulation failed
    #[error("KEM encapsulation error: {0}")]
    EncapsulationError(String),
    /// KEM decapsulation failed
    #[error("KEM decapsulation error: {0}")]
    DecapsulationError(String),
    /// Digital signature operation failed
    #[error("Signing error: {0}")]
    SigningError(String),
    /// Authentication failed
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationError,
    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid signature length
    #[error("Invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength {
        /// Expected length
        expected: usize,
        /// Actual length
        got: usize,
    },

    /// Signature verification error
    #[error("Signature verification error: {0}")]
    SignatureVerificationError(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, actual {actual}")]
    InvalidKeyLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },
    /// Serialization/deserialization failed
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// Deserialization failed
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    /// I/O operation failed
    #[error("I/O error: {0}")]
    IoError(String),
    /// Random number generation failed
    #[error("Random number generation failed")]
    RandomError,
    /// Unsupported protocol version
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
    /// Invalid envelope format
    #[error("Invalid envelope: {0}")]
    InvalidEnvelope(String),
    /// Invalid format
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),
    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// Service unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    /// Security violation
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    /// Compliance violation
    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),
    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    /// CPU feature not available
    #[error("CPU feature not available: {0}")]
    CpuFeatureNotAvailable(String),
    /// Memory allocation failed
    #[error("Memory error: {0}")]
    MemoryError(String),
    /// Circuit breaker is open
    #[error("Circuit breaker is open")]
    CircuitBreakerOpen,
    /// System resources exhausted
    #[error("System resources exhausted")]
    ResourceExhausted,
    /// Required feature not enabled
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
    /// Audit logging failed
    #[error("Audit error: {0}")]
    AuditError(String),
    /// HSM operation failed
    #[error("HSM error: {0}")]
    HsmError(String),
    /// PIN verification failed
    #[error("PIN verification failed")]
    PinIncorrect,
    /// PIN account locked due to too many failed attempts
    #[error("PIN account locked due to too many failed attempts")]
    PinLocked,
    /// Cloud KMS operation failed
    #[error("Cloud KMS error: {0}")]
    CloudKmsError(String),
    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(String),
    /// Network operation failed
    #[error("Network error: {0}")]
    NetworkError(String),
    /// TLS operation failed
    #[error("TLS error: {0}")]
    TlsError(String),
    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
    /// Formal verification failed
    #[error("Formal verification failed: {0}")]
    VerificationFailed(String),
    /// Fuzzing test failed
    #[error("Fuzzing error: {0}")]
    FuzzingError(String),
    /// Development tool error
    #[error("Development tool error: {0}")]
    DevToolError(String),
    /// Migration operation failed
    #[error("Migration error: {0}")]
    MigrationError(String),
    /// Performance profiling error
    #[error("Profiling error: {0}")]
    ProfilingError(String),
    /// Side channel mitigation failed
    #[error("Side channel error: {0}")]
    SideChannelError(String),
    /// Async operation failed
    #[error("Async error: {0}")]
    AsyncError(String),
    /// WASM-specific error
    #[error("WASM error: {0}")]
    WasmError(String),
    /// Access denied due to insufficient permissions
    #[error("Access denied: {0}")]
    AccessDenied(String),
    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    /// Invalid elliptic curve point
    #[error("Invalid elliptic curve point")]
    InvalidPoint,
    /// Resource or permission expired
    #[error("Expired: {0}")]
    Expired(String),
    /// Hardware acceleration error
    #[error("Hardware error: {0}")]
    HardwareError(String),
    /// Invalid operation attempted
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    /// Concurrency-related error
    #[error("Concurrency error: {0}")]
    ConcurrencyError(String),
    /// Timeout error
    #[error("Timeout: {0}")]
    TimeoutError(String),
    /// CAVP validation error
    #[error("Validation error: {message}")]
    ValidationError {
        /// Validation error message
        message: String,
    },

    // ============================================================================
    // Zero-Knowledge Proof Errors
    // ============================================================================
    /// Zero-knowledge proof error
    #[error("ZKP error: {0}")]
    ZkpError(String),
}

/// Type alias for TimeCapsuleError
pub type TimeCapsuleError = LatticeArcError;

// Re-export recovery types and functions
pub use recovery::{
    ErrorRecoveryStrategy, ErrorSeverity, attempt_error_recovery, get_error_severity,
    is_recoverable_error, requires_security_response,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_arc_error_display_messages() {
        let cases: Vec<(LatticeArcError, &str)> = vec![
            (LatticeArcError::EncryptionError("aes".to_string()), "Encryption error: aes"),
            (LatticeArcError::DecryptionError("gcm".to_string()), "Decryption error: gcm"),
            (LatticeArcError::KeyGenerationError("rng".to_string()), "Key generation error: rng"),
            (LatticeArcError::InvalidKey("bad".to_string()), "Invalid key: bad"),
            (
                LatticeArcError::EncapsulationError("kem".to_string()),
                "KEM encapsulation error: kem",
            ),
            (LatticeArcError::DecapsulationError("dk".to_string()), "KEM decapsulation error: dk"),
            (LatticeArcError::SigningError("sig".to_string()), "Signing error: sig"),
            (
                LatticeArcError::AuthenticationError("auth".to_string()),
                "Authentication error: auth",
            ),
            (LatticeArcError::VerificationError, "Signature verification failed"),
            (LatticeArcError::InvalidSignature("bad".to_string()), "Invalid signature: bad"),
            (LatticeArcError::SerializationError("json".to_string()), "Serialization error: json"),
            (LatticeArcError::IoError("disk".to_string()), "I/O error: disk"),
            (LatticeArcError::RandomError, "Random number generation failed"),
            (LatticeArcError::CircuitBreakerOpen, "Circuit breaker is open"),
            (LatticeArcError::ResourceExhausted, "System resources exhausted"),
            (LatticeArcError::PinIncorrect, "PIN verification failed"),
            (LatticeArcError::PinLocked, "PIN account locked due to too many failed attempts"),
            (LatticeArcError::InvalidPoint, "Invalid elliptic curve point"),
            (LatticeArcError::ZkpError("proof".to_string()), "ZKP error: proof"),
        ];

        for (error, expected) in cases {
            assert_eq!(format!("{error}"), expected);
        }
    }

    #[test]
    fn test_lattice_arc_error_structured_variants() {
        let err = LatticeArcError::InvalidSignatureLength { expected: 64, got: 32 };
        let msg = format!("{err}");
        assert!(msg.contains("64"));
        assert!(msg.contains("32"));

        let err = LatticeArcError::InvalidKeyLength { expected: 32, actual: 16 };
        let msg = format!("{err}");
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));

        let err = LatticeArcError::ValidationError { message: "fail".to_string() };
        assert_eq!(format!("{err}"), "Validation error: fail");
    }

    #[test]
    fn test_lattice_arc_error_clone_eq() {
        let err = LatticeArcError::EncryptionError("test".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);

        let different = LatticeArcError::DecryptionError("test".to_string());
        assert_ne!(err, different);
    }

    #[test]
    fn test_lattice_arc_error_debug() {
        let err = LatticeArcError::EncryptionError("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("EncryptionError"));
    }

    #[test]
    fn test_lattice_arc_error_serialization() {
        let err = LatticeArcError::InvalidInput("bad data".to_string());
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("InvalidInput"));

        let deserialized: LatticeArcError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deserialized);
    }

    #[test]
    fn test_lattice_arc_error_serialization_unit_variants() {
        let variants = vec![
            LatticeArcError::VerificationError,
            LatticeArcError::RandomError,
            LatticeArcError::CircuitBreakerOpen,
            LatticeArcError::ResourceExhausted,
            LatticeArcError::PinIncorrect,
            LatticeArcError::PinLocked,
            LatticeArcError::InvalidPoint,
        ];

        for err in variants {
            let json = serde_json::to_string(&err).unwrap();
            let deserialized: LatticeArcError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, deserialized);
        }
    }

    #[test]
    fn test_lattice_arc_error_serialization_structured() {
        let err = LatticeArcError::InvalidKeyLength { expected: 32, actual: 16 };
        let json = serde_json::to_string(&err).unwrap();
        let deserialized: LatticeArcError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deserialized);

        let err = LatticeArcError::InvalidSignatureLength { expected: 64, got: 48 };
        let json = serde_json::to_string(&err).unwrap();
        let deserialized: LatticeArcError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deserialized);
    }

    #[test]
    fn test_lattice_arc_error_unsupported_version() {
        let err = LatticeArcError::UnsupportedVersion(42);
        assert_eq!(format!("{err}"), "Unsupported version: 42");

        let json = serde_json::to_string(&err).unwrap();
        let deserialized: LatticeArcError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deserialized);
    }

    #[test]
    fn test_lattice_arc_error_remaining_display() {
        // Cover remaining variants for Display completeness
        let remaining: Vec<(LatticeArcError, &str)> = vec![
            (LatticeArcError::DeserializationError("x".to_string()), "Deserialization error: x"),
            (LatticeArcError::InvalidEnvelope("x".to_string()), "Invalid envelope: x"),
            (LatticeArcError::InvalidFormat("x".to_string()), "Invalid format: x"),
            (LatticeArcError::InvalidConfiguration("x".to_string()), "Invalid configuration: x"),
            (LatticeArcError::InvalidData("x".to_string()), "Invalid data: x"),
            (LatticeArcError::InvalidInput("x".to_string()), "Invalid input: x"),
            (LatticeArcError::ServiceUnavailable("x".to_string()), "Service unavailable: x"),
            (LatticeArcError::SecurityViolation("x".to_string()), "Security violation: x"),
            (LatticeArcError::PolicyViolation("x".to_string()), "Policy violation: x"),
            (LatticeArcError::ComplianceViolation("x".to_string()), "Compliance violation: x"),
            (LatticeArcError::InvalidParameter("x".to_string()), "Invalid parameter: x"),
            (LatticeArcError::NotImplemented("x".to_string()), "Not implemented: x"),
            (
                LatticeArcError::CpuFeatureNotAvailable("x".to_string()),
                "CPU feature not available: x",
            ),
            (LatticeArcError::MemoryError("x".to_string()), "Memory error: x"),
            (LatticeArcError::FeatureNotEnabled("x".to_string()), "Feature not enabled: x"),
            (LatticeArcError::AuditError("x".to_string()), "Audit error: x"),
            (LatticeArcError::HsmError("x".to_string()), "HSM error: x"),
            (LatticeArcError::CloudKmsError("x".to_string()), "Cloud KMS error: x"),
            (LatticeArcError::DatabaseError("x".to_string()), "Database error: x"),
            (LatticeArcError::NetworkError("x".to_string()), "Network error: x"),
            (LatticeArcError::TlsError("x".to_string()), "TLS error: x"),
            (LatticeArcError::KeyDerivationError("x".to_string()), "Key derivation error: x"),
            (LatticeArcError::VerificationFailed("x".to_string()), "Formal verification failed: x"),
            (LatticeArcError::FuzzingError("x".to_string()), "Fuzzing error: x"),
            (LatticeArcError::DevToolError("x".to_string()), "Development tool error: x"),
            (LatticeArcError::MigrationError("x".to_string()), "Migration error: x"),
            (LatticeArcError::ProfilingError("x".to_string()), "Profiling error: x"),
            (LatticeArcError::SideChannelError("x".to_string()), "Side channel error: x"),
            (LatticeArcError::AsyncError("x".to_string()), "Async error: x"),
            (LatticeArcError::WasmError("x".to_string()), "WASM error: x"),
            (LatticeArcError::AccessDenied("x".to_string()), "Access denied: x"),
            (LatticeArcError::Unauthorized("x".to_string()), "Unauthorized: x"),
            (LatticeArcError::Expired("x".to_string()), "Expired: x"),
            (LatticeArcError::HardwareError("x".to_string()), "Hardware error: x"),
            (LatticeArcError::InvalidOperation("x".to_string()), "Invalid operation: x"),
            (LatticeArcError::ConcurrencyError("x".to_string()), "Concurrency error: x"),
            (LatticeArcError::TimeoutError("x".to_string()), "Timeout: x"),
            (
                LatticeArcError::SignatureVerificationError("x".to_string()),
                "Signature verification error: x",
            ),
        ];

        for (error, expected) in remaining {
            assert_eq!(format!("{error}"), expected, "Failed for: {:?}", error);
        }
    }

    #[test]
    fn test_time_capsule_error_alias() {
        // TimeCapsuleError is just an alias for LatticeArcError
        let err: TimeCapsuleError = LatticeArcError::InvalidInput("test".to_string());
        assert_eq!(format!("{err}"), "Invalid input: test");
    }
}
