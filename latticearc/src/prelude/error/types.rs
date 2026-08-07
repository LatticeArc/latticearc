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

/// Result type alias for `LatticeArc` operations
pub type Result<T> = std::result::Result<T, LatticeArcError>;

/// Comprehensive error type for all `LatticeArc` operations
///
/// This enum covers all possible error conditions that can occur during
/// cryptographic operations, key management, serialization, and I/O.
///
/// `Serialize` is kept so that error variants can be emitted to outbound
/// audit / observability sinks. `Deserialize` is intentionally **not**
/// derived — errors are always produced internally by this crate, never
/// received over the wire from an untrusted source. Allowing arbitrary
/// `LatticeArcError` values to be deserialized would let an attacker who
/// controls a deserialization input inject sensitive variants
/// (`SecurityViolation`, `ComplianceViolation`, etc.) into local
/// error-handling logic.
#[derive(Debug, Error, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
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

    /// Message length exceeds the configured signature resource limit.
    ///
    /// Matches the shape used by `MlDsaError::MessageTooLong` and
    /// `SlhDsaError::MessageTooLong` — unit variant, no payload (the length
    /// is already known to the sender; carrying it would add no info).
    #[error("Message exceeds signature resource limit")]
    MessageTooLong,
    /// Authentication failed
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
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
    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),
    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// Security violation
    #[error("Security violation: {0}")]
    SecurityViolation(String),
    /// Compliance violation
    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),
    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    /// Memory allocation failed
    #[error("Memory error: {0}")]
    MemoryError(String),
    /// System resources exhausted
    #[error("System resources exhausted")]
    ResourceExhausted,
    /// Required feature not enabled
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
    /// HSM operation failed
    #[error("HSM error: {0}")]
    HsmError(String),
    /// Network operation failed
    #[error("Network error: {0}")]
    NetworkError(String),
    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
    /// Formal verification failed
    #[error("Formal verification failed: {0}")]
    VerificationFailed(String),
    /// Access denied due to insufficient permissions
    #[error("Access denied: {0}")]
    AccessDenied(String),
    /// Hardware acceleration error
    #[error("Hardware error: {0}")]
    HardwareError(String),
    /// Invalid operation attempted
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    /// Concurrency-related error
    #[error("Concurrency error: {0}")]
    ConcurrencyError(String),
    /// CAVP validation error
    #[error("Validation error: {message}")]
    ValidationError {
        /// Validation error message
        message: String,
    },
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test/bench scaffolding: lints suppressed for this module")]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_arc_error_display_messages_match_expected_strings_fails() {
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
            (LatticeArcError::InvalidSignature("bad".to_string()), "Invalid signature: bad"),
            (LatticeArcError::SerializationError("json".to_string()), "Serialization error: json"),
            (LatticeArcError::IoError("disk".to_string()), "I/O error: disk"),
            (LatticeArcError::RandomError, "Random number generation failed"),
            (LatticeArcError::ResourceExhausted, "System resources exhausted"),
        ];

        for (error, expected) in cases {
            assert_eq!(format!("{error}"), expected);
        }
    }

    #[test]
    fn test_lattice_arc_error_structured_variants_display_correct_messages_fails() {
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
    fn test_lattice_arc_error_clone_eq_same_values_are_equal_fails() {
        let err = LatticeArcError::EncryptionError("test".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);

        let different = LatticeArcError::DecryptionError("test".to_string());
        assert_ne!(err, different);
    }

    #[test]
    fn test_lattice_arc_error_debug_contains_variant_name_fails() {
        let err = LatticeArcError::EncryptionError("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("EncryptionError"));
    }

    #[test]
    fn test_lattice_arc_error_serializes_outbound() {
        // Serialization is kept for outbound audit / observability sinks.
        // Deserialization is deliberately NOT supported (see the type-level
        // doc comment).
        let err = LatticeArcError::InvalidInput("bad data".to_string());
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("InvalidInput"));
        assert!(json.contains("bad data"));
    }

    #[test]
    fn test_lattice_arc_error_serializes_unit_variants() {
        for err in [LatticeArcError::RandomError, LatticeArcError::ResourceExhausted] {
            let json = serde_json::to_string(&err).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_lattice_arc_error_serializes_structured_variants() {
        let err = LatticeArcError::InvalidKeyLength { expected: 32, actual: 16 };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("32"));
        assert!(json.contains("16"));

        let err = LatticeArcError::InvalidSignatureLength { expected: 64, got: 48 };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("64"));
        assert!(json.contains("48"));
    }

    #[test]
    fn test_lattice_arc_error_remaining_display_messages_match_expected_fails() {
        // Cover remaining variants for Display completeness
        let remaining: Vec<(LatticeArcError, &str)> = vec![
            (LatticeArcError::DeserializationError("x".to_string()), "Deserialization error: x"),
            (LatticeArcError::InvalidConfiguration("x".to_string()), "Invalid configuration: x"),
            (LatticeArcError::InvalidData("x".to_string()), "Invalid data: x"),
            (LatticeArcError::InvalidInput("x".to_string()), "Invalid input: x"),
            (LatticeArcError::SecurityViolation("x".to_string()), "Security violation: x"),
            (LatticeArcError::ComplianceViolation("x".to_string()), "Compliance violation: x"),
            (LatticeArcError::InvalidParameter("x".to_string()), "Invalid parameter: x"),
            (LatticeArcError::NotImplemented("x".to_string()), "Not implemented: x"),
            (LatticeArcError::MemoryError("x".to_string()), "Memory error: x"),
            (LatticeArcError::FeatureNotEnabled("x".to_string()), "Feature not enabled: x"),
            (LatticeArcError::HsmError("x".to_string()), "HSM error: x"),
            (LatticeArcError::NetworkError("x".to_string()), "Network error: x"),
            (LatticeArcError::KeyDerivationError("x".to_string()), "Key derivation error: x"),
            (LatticeArcError::VerificationFailed("x".to_string()), "Formal verification failed: x"),
            (LatticeArcError::AccessDenied("x".to_string()), "Access denied: x"),
            (LatticeArcError::HardwareError("x".to_string()), "Hardware error: x"),
            (LatticeArcError::InvalidOperation("x".to_string()), "Invalid operation: x"),
            (LatticeArcError::ConcurrencyError("x".to_string()), "Concurrency error: x"),
            (
                LatticeArcError::SignatureVerificationError("x".to_string()),
                "Signature verification error: x",
            ),
        ];

        for (error, expected) in remaining {
            assert_eq!(format!("{error}"), expected, "Failed for: {:?}", error);
        }
    }
}
