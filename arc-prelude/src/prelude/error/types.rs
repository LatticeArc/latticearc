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
