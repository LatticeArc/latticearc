#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Comprehensive TLS Error Handling Infrastructure
//!
//! This module provides a robust error handling system for TLS operations including:
//! - Detailed error types with codes and severity levels
//! - Error context and recovery hints
//! - Structured error information for debugging
//! - Compatibility with external libraries

use std::fmt;

use chrono::{DateTime, Utc};
use thiserror::Error;

/// Error severity levels for categorizing TLS errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Informational - operation succeeded but with warnings
    Info,
    /// Warning - operation completed but with potential issues
    Warning,
    /// Error - operation failed but may be recoverable
    Error,
    /// Critical - operation failed and requires intervention
    Critical,
}

/// TLS operation phase where error occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationPhase {
    /// Initial connection establishment
    ConnectionSetup,
    /// TLS handshake (ClientHello, ServerHello, etc.)
    Handshake,
    /// Certificate verification and validation
    CertificateVerification,
    /// Key exchange (ECDHE, ML-KEM, hybrid)
    KeyExchange,
    /// Post-handshake data transfer
    DataTransfer,
    /// Connection closure
    Teardown,
    /// Configuration and initialization
    Initialization,
}

/// Standard TLS error codes for easy identification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Connection errors (1000-1099)
    /// Connection was actively refused by the remote host.
    ConnectionRefused = 1001,
    /// Connection attempt timed out.
    ConnectionTimeout = 1002,
    /// Connection was reset by the remote host.
    ConnectionReset = 1003,
    /// DNS resolution failed for the hostname.
    DnsResolutionFailed = 1004,

    // Handshake errors (2000-2099)
    /// TLS handshake failed.
    HandshakeFailed = 2001,
    /// Protocol version mismatch between client and server.
    ProtocolVersionMismatch = 2002,
    /// No common cipher suite available.
    CipherSuiteMismatch = 2003,
    /// Invalid handshake message received.
    InvalidHandshakeMessage = 2004,
    /// Unexpected message received during handshake.
    UnexpectedMessage = 2005,
    /// Handshake timed out.
    HandshakeTimeout = 2006,

    // Certificate errors (3000-3099)
    /// Failed to parse certificate.
    CertificateParseError = 3001,
    /// Certificate has expired.
    CertificateExpired = 3002,
    /// Certificate is not yet valid.
    CertificateNotYetValid = 3003,
    /// Certificate has been revoked.
    CertificateRevoked = 3004,
    /// Certificate is invalid.
    CertificateInvalid = 3005,
    /// Certificate chain is incomplete.
    CertificateChainIncomplete = 3006,
    /// Certificate hostname does not match.
    CertificateHostnameMismatch = 3007,
    /// Certificate is self-signed.
    CertificateSelfSigned = 3008,
    /// Certificate is not valid for the requested name.
    CertificateNotValidForName = 3009,
    /// Certificate name validation failed with context.
    CertificateNotValidForNameContext = 3010,
    /// Certificate contains unknown critical extension.
    CertificateUnknownCriticalExtension = 3011,
    /// Certificate has invalid DER encoding.
    CertificateBadDer = 3012,
    /// Certificate has invalid DER sequence.
    CertificateBadDerSequence = 3013,
    /// Certificate has invalid DER time format.
    CertificateBadDerTime = 3014,
    /// Certificate signature is invalid.
    CertificateSignatureInvalid = 3015,
    /// Certificate is not valid for the intended purpose.
    CertificateNotValidForPurpose = 3016,

    // Key exchange errors (4000-4099)
    /// Key exchange failed.
    KeyExchangeFailed = 4001,
    /// Invalid public key provided.
    InvalidPublicKey = 4002,
    /// Invalid private key provided.
    InvalidPrivateKey = 4003,
    /// Key generation failed.
    KeyGenerationFailed = 4004,
    /// KEM encapsulation failed.
    EncapsulationFailed = 4005,
    /// KEM decapsulation failed.
    DecapsulationFailed = 4006,
    /// Post-quantum cryptography is not available.
    PqNotAvailable = 4007,
    /// Hybrid KEM operation failed.
    HybridKemFailed = 4008,

    // Crypto provider errors (5000-5099)
    /// Crypto provider initialization failed.
    CryptoProviderInitFailed = 5001,
    /// Crypto provider is not supported.
    CryptoProviderNotSupported = 5002,
    /// Invalid key material provided.
    InvalidKeyMaterial = 5003,
    /// Signature verification failed.
    SignatureVerificationFailed = 5004,
    /// HMAC operation failed.
    HmacFailed = 5005,
    /// Cipher operation failed.
    CipherOperationFailed = 5006,

    // IO errors (6000-6099)
    /// General I/O error.
    IoError = 6001,
    /// Read operation failed.
    ReadError = 6002,
    /// Write operation failed.
    WriteError = 6003,
    /// Unexpected end of file.
    UnexpectedEof = 6004,

    // Configuration errors (7000-7099)
    /// Invalid configuration.
    InvalidConfig = 7001,
    /// Required certificate is missing.
    MissingCertificate = 7002,
    /// Required private key is missing.
    MissingPrivateKey = 7003,
    /// Invalid cipher suite specified.
    InvalidCipherSuite = 7004,
    /// Invalid protocol version specified.
    InvalidProtocolVersion = 7005,

    // Resource errors (8000-8099)
    /// Memory allocation failed.
    MemoryAllocationFailed = 8001,
    /// Too many concurrent connections.
    TooManyConnections = 8002,
    /// Resource has been exhausted.
    ResourceExhausted = 8003,

    // Internal errors (9000-9099)
    /// Internal error occurred.
    InternalError = 9001,
    /// Requested operation is not supported.
    UnsupportedOperation = 9002,
    /// Internal invariant was violated.
    InvariantViolation = 9003,
    /// Unexpected state encountered.
    UnexpectedState = 9004,
    /// Unclassified error.
    Other = 9999,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Connection errors
            ErrorCode::ConnectionRefused => write!(f, "CONNECTION_REFUSED"),
            ErrorCode::ConnectionTimeout => write!(f, "CONNECTION_TIMEOUT"),
            ErrorCode::ConnectionReset => write!(f, "CONNECTION_RESET"),
            ErrorCode::DnsResolutionFailed => write!(f, "DNS_RESOLUTION_FAILED"),

            // Handshake errors
            ErrorCode::HandshakeFailed => write!(f, "HANDSHAKE_FAILED"),
            ErrorCode::ProtocolVersionMismatch => write!(f, "PROTOCOL_VERSION_MISMATCH"),
            ErrorCode::CipherSuiteMismatch => write!(f, "CIPHER_SUITE_MISMATCH"),
            ErrorCode::InvalidHandshakeMessage => write!(f, "INVALID_HANDSHAKE_MESSAGE"),
            ErrorCode::UnexpectedMessage => write!(f, "UNEXPECTED_MESSAGE"),
            ErrorCode::HandshakeTimeout => write!(f, "HANDSHAKE_TIMEOUT"),

            // Certificate errors
            ErrorCode::CertificateParseError => write!(f, "CERTIFICATE_PARSE_ERROR"),
            ErrorCode::CertificateExpired => write!(f, "CERTIFICATE_EXPIRED"),
            ErrorCode::CertificateNotYetValid => write!(f, "CERTIFICATE_NOT_YET_VALID"),
            ErrorCode::CertificateRevoked => write!(f, "CERTIFICATE_REVOKED"),
            ErrorCode::CertificateInvalid => write!(f, "CERTIFICATE_INVALID"),
            ErrorCode::CertificateChainIncomplete => write!(f, "CERTIFICATE_CHAIN_INCOMPLETE"),
            ErrorCode::CertificateHostnameMismatch => write!(f, "CERTIFICATE_HOSTNAME_MISMATCH"),
            ErrorCode::CertificateSelfSigned => write!(f, "CERTIFICATE_SELF_SIGNED"),
            ErrorCode::CertificateNotValidForName => write!(f, "CERTIFICATE_NOT_VALID_FOR_NAME"),
            ErrorCode::CertificateNotValidForNameContext => {
                write!(f, "CERTIFICATE_NOT_VALID_FOR_NAME_CONTEXT")
            }
            ErrorCode::CertificateUnknownCriticalExtension => {
                write!(f, "CERTIFICATE_UNKNOWN_CRITICAL_EXTENSION")
            }
            ErrorCode::CertificateBadDer => write!(f, "CERTIFICATE_BAD_DER"),
            ErrorCode::CertificateBadDerSequence => write!(f, "CERTIFICATE_BAD_DER_SEQUENCE"),
            ErrorCode::CertificateBadDerTime => write!(f, "CERTIFICATE_BAD_DER_TIME"),
            ErrorCode::CertificateSignatureInvalid => write!(f, "CERTIFICATE_SIGNATURE_INVALID"),
            ErrorCode::CertificateNotValidForPurpose => {
                write!(f, "CERTIFICATE_NOT_VALID_FOR_PURPOSE")
            }

            // Key exchange errors
            ErrorCode::KeyExchangeFailed => write!(f, "KEY_EXCHANGE_FAILED"),
            ErrorCode::InvalidPublicKey => write!(f, "INVALID_PUBLIC_KEY"),
            ErrorCode::InvalidPrivateKey => write!(f, "INVALID_PRIVATE_KEY"),
            ErrorCode::KeyGenerationFailed => write!(f, "KEY_GENERATION_FAILED"),
            ErrorCode::EncapsulationFailed => write!(f, "ENCAPSULATION_FAILED"),
            ErrorCode::DecapsulationFailed => write!(f, "DECAPSULATION_FAILED"),
            ErrorCode::PqNotAvailable => write!(f, "PQ_NOT_AVAILABLE"),
            ErrorCode::HybridKemFailed => write!(f, "HYBRID_KEM_FAILED"),

            // Crypto provider errors
            ErrorCode::CryptoProviderInitFailed => write!(f, "CRYPTO_PROVIDER_INIT_FAILED"),
            ErrorCode::CryptoProviderNotSupported => write!(f, "CRYPTO_PROVIDER_NOT_SUPPORTED"),
            ErrorCode::InvalidKeyMaterial => write!(f, "INVALID_KEY_MATERIAL"),
            ErrorCode::SignatureVerificationFailed => write!(f, "SIGNATURE_VERIFICATION_FAILED"),
            ErrorCode::HmacFailed => write!(f, "HMAC_FAILED"),
            ErrorCode::CipherOperationFailed => write!(f, "CIPHER_OPERATION_FAILED"),

            // IO errors
            ErrorCode::IoError => write!(f, "IO_ERROR"),
            ErrorCode::ReadError => write!(f, "READ_ERROR"),
            ErrorCode::WriteError => write!(f, "WRITE_ERROR"),
            ErrorCode::UnexpectedEof => write!(f, "UNEXPECTED_EOF"),

            // Configuration errors
            ErrorCode::InvalidConfig => write!(f, "INVALID_CONFIG"),
            ErrorCode::MissingCertificate => write!(f, "MISSING_CERTIFICATE"),
            ErrorCode::MissingPrivateKey => write!(f, "MISSING_PRIVATE_KEY"),
            ErrorCode::InvalidCipherSuite => write!(f, "INVALID_CIPHER_SUITE"),
            ErrorCode::InvalidProtocolVersion => write!(f, "INVALID_PROTOCOL_VERSION"),

            // Resource errors
            ErrorCode::MemoryAllocationFailed => write!(f, "MEMORY_ALLOCATION_FAILED"),
            ErrorCode::TooManyConnections => write!(f, "TOO_MANY_CONNECTIONS"),
            ErrorCode::ResourceExhausted => write!(f, "RESOURCE_EXHAUSTED"),

            // Internal errors
            ErrorCode::InternalError => write!(f, "INTERNAL_ERROR"),
            ErrorCode::UnsupportedOperation => write!(f, "UNSUPPORTED_OPERATION"),
            ErrorCode::InvariantViolation => write!(f, "INVARIANT_VIOLATION"),
            ErrorCode::UnexpectedState => write!(f, "UNEXPECTED_STATE"),
            ErrorCode::Other => write!(f, "OTHER"),
        }
    }
}

/// Recovery hints for error handling
#[derive(Debug, Clone)]
pub enum RecoveryHint {
    /// No recovery possible
    NoRecovery,
    /// Retry the operation
    Retry {
        /// Maximum number of retry attempts.
        max_attempts: u32,
        /// Backoff delay in milliseconds between attempts.
        backoff_ms: u64,
    },
    /// Fall back to a different mode (e.g., Hybrid -> Classic)
    Fallback {
        /// Description of the fallback strategy.
        description: String,
    },
    /// Reconfigure and retry
    Reconfigure {
        /// Configuration field to modify.
        field: String,
        /// Suggested new value or approach.
        suggestion: String,
    },
    /// Contact support or administrator
    ContactSupport {
        /// Message to include when contacting support.
        message: String,
    },
    /// Update system time or check NTP
    CheckSystemTime,
    /// Check network connectivity
    CheckNetworkConnectivity,
    /// Verify certificate files
    VerifyCertificates,
    /// Check resource limits
    CheckResourceLimits,
}

/// Detailed TLS error context
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Unique error ID for tracking
    pub error_id: String,
    /// Error code
    pub code: ErrorCode,
    /// Error severity
    pub severity: ErrorSeverity,
    /// Operation phase where error occurred
    pub phase: OperationPhase,
    /// Peer information (if available)
    pub peer_addr: Option<String>,
    /// Domain name (for SNI)
    pub domain: Option<String>,
    /// Timestamp when error occurred
    pub timestamp: DateTime<Utc>,
    /// Additional context fields
    pub extra: std::collections::HashMap<String, String>,
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self {
            error_id: generate_error_id(),
            code: ErrorCode::InternalError,
            severity: ErrorSeverity::Error,
            phase: OperationPhase::Initialization,
            peer_addr: None,
            domain: None,
            timestamp: Utc::now(),
            extra: std::collections::HashMap::new(),
        }
    }
}

/// Generate unique error ID
fn generate_error_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ERROR_COUNTER: AtomicU64 = AtomicU64::new(1);
    let counter = ERROR_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("TLSERR_{:016x}", counter)
}

/// Comprehensive TLS error type
#[derive(Error, Debug)]
pub enum TlsError {
    /// IO operation error
    #[error("IO error: {message}")]
    Io {
        /// Human-readable error message.
        message: String,
        /// Underlying source error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// TLS protocol error
    #[error("TLS protocol error: {message}")]
    Tls {
        /// Human-readable error message.
        message: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// TLS handshake error
    #[error("TLS handshake error: {message}")]
    Handshake {
        /// Human-readable error message.
        message: String,
        /// Handshake state when error occurred.
        state: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Certificate error
    #[error("Certificate error: {message}")]
    Certificate {
        /// Human-readable error message.
        message: String,
        /// Certificate subject name.
        subject: Option<String>,
        /// Certificate issuer name.
        issuer: Option<String>,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Key exchange error
    #[error("Key exchange error: {message}")]
    KeyExchange {
        /// Human-readable error message.
        message: String,
        /// Key exchange method in use.
        method: String,
        /// Specific operation that failed.
        operation: Option<String>,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Configuration error
    #[error("Configuration error: {message}")]
    Config {
        /// Human-readable error message.
        message: String,
        /// Configuration field that caused the error.
        field: Option<String>,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Unsupported cipher suite
    #[error("Unsupported cipher suite: {cipher_suite}")]
    UnsupportedCipherSuite {
        /// The unsupported cipher suite name.
        cipher_suite: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Unsupported protocol version
    #[error("Unsupported protocol version: {version}")]
    UnsupportedVersion {
        /// The unsupported protocol version.
        version: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Post-quantum key exchange not available
    #[error("Post-quantum key exchange not available")]
    PqNotAvailable {
        /// Human-readable error message.
        message: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Hybrid KEM error
    #[error("Hybrid key exchange error: {message}")]
    HybridKem {
        /// Human-readable error message.
        message: String,
        /// Component that failed (classical or PQ).
        component: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Invalid key material
    #[error("Invalid key material: {message}")]
    InvalidKeyMaterial {
        /// Human-readable error message.
        message: String,
        /// Type of key that was invalid.
        key_type: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Crypto provider initialization error
    #[error("Crypto provider error: {message}")]
    CryptoProvider {
        /// Human-readable error message.
        message: String,
        /// Name of the crypto provider.
        provider: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Resource error
    #[error("Resource error: {message}")]
    Resource {
        /// Human-readable error message.
        message: String,
        /// Type of resource that caused the error.
        resource_type: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal {
        /// Human-readable error message.
        message: String,
        /// Error code for classification.
        code: ErrorCode,
        /// Detailed error context.
        context: ErrorContext,
        /// Recovery hint for handling.
        recovery: RecoveryHint,
    },
}

impl TlsError {
    /// Get error code
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            TlsError::Io { code, .. } => *code,
            TlsError::Tls { code, .. } => *code,
            TlsError::Handshake { code, .. } => *code,
            TlsError::Certificate { code, .. } => *code,
            TlsError::KeyExchange { code, .. } => *code,
            TlsError::Config { code, .. } => *code,
            TlsError::UnsupportedCipherSuite { code, .. } => *code,
            TlsError::UnsupportedVersion { code, .. } => *code,
            TlsError::PqNotAvailable { code, .. } => *code,
            TlsError::HybridKem { code, .. } => *code,
            TlsError::InvalidKeyMaterial { code, .. } => *code,
            TlsError::CryptoProvider { code, .. } => *code,
            TlsError::Resource { code, .. } => *code,
            TlsError::Internal { code, .. } => *code,
        }
    }

    /// Get error severity
    #[must_use]
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            TlsError::Io { context, .. } => context.severity,
            TlsError::Tls { context, .. } => context.severity,
            TlsError::Handshake { context, .. } => context.severity,
            TlsError::Certificate { context, .. } => context.severity,
            TlsError::KeyExchange { context, .. } => context.severity,
            TlsError::Config { context, .. } => context.severity,
            TlsError::UnsupportedCipherSuite { context, .. } => context.severity,
            TlsError::UnsupportedVersion { context, .. } => context.severity,
            TlsError::PqNotAvailable { context, .. } => context.severity,
            TlsError::HybridKem { context, .. } => context.severity,
            TlsError::InvalidKeyMaterial { context, .. } => context.severity,
            TlsError::CryptoProvider { context, .. } => context.severity,
            TlsError::Resource { context, .. } => context.severity,
            TlsError::Internal { context, .. } => context.severity,
        }
    }

    /// Get error context
    #[must_use]
    pub fn context(&self) -> &ErrorContext {
        match self {
            TlsError::Io { context, .. } => context,
            TlsError::Tls { context, .. } => context,
            TlsError::Certificate { context, .. } => context,
            TlsError::KeyExchange { context, .. } => context,
            TlsError::CryptoProvider { context, .. } => context,
            TlsError::Config { context, .. } => context,
            // Recovery and Context variants don't exist in current TlsError
            _ => {
                // For variants without context, return a static empty context
                static EMPTY_CONTEXT: std::sync::LazyLock<ErrorContext> =
                    std::sync::LazyLock::new(ErrorContext::default);
                &EMPTY_CONTEXT
            }
        }
    }

    /// Get recovery hint
    #[must_use]
    pub fn recovery_hint(&self) -> &RecoveryHint {
        match self {
            TlsError::Io { recovery, .. } => recovery,
            TlsError::Tls { recovery, .. } => recovery,
            TlsError::Handshake { recovery, .. } => recovery,
            TlsError::Certificate { recovery, .. } => recovery,
            TlsError::KeyExchange { recovery, .. } => recovery,
            TlsError::Config { recovery, .. } => recovery,
            TlsError::UnsupportedCipherSuite { recovery, .. } => recovery,
            TlsError::UnsupportedVersion { recovery, .. } => recovery,
            TlsError::PqNotAvailable { recovery, .. } => recovery,
            TlsError::HybridKem { recovery, .. } => recovery,
            TlsError::InvalidKeyMaterial { recovery, .. } => recovery,
            TlsError::CryptoProvider { recovery, .. } => recovery,
            TlsError::Resource { recovery, .. } => recovery,
            TlsError::Internal { recovery, .. } => recovery,
        }
    }

    /// Check if error is recoverable
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        !matches!(self.recovery_hint(), RecoveryHint::NoRecovery)
    }

    /// Check if error allows fallback
    #[must_use]
    pub fn supports_fallback(&self) -> bool {
        matches!(self.recovery_hint(), RecoveryHint::Fallback { .. })
    }
}

// Conversion from std::io::Error
impl From<std::io::Error> for TlsError {
    fn from(err: std::io::Error) -> Self {
        let (code, severity, recovery) = match err.kind() {
            std::io::ErrorKind::ConnectionRefused => (
                ErrorCode::ConnectionRefused,
                ErrorSeverity::Error,
                RecoveryHint::CheckNetworkConnectivity,
            ),
            std::io::ErrorKind::ConnectionReset => (
                ErrorCode::ConnectionReset,
                ErrorSeverity::Warning,
                RecoveryHint::Retry { max_attempts: 3, backoff_ms: 1000 },
            ),
            std::io::ErrorKind::TimedOut => (
                ErrorCode::ConnectionTimeout,
                ErrorSeverity::Error,
                RecoveryHint::Retry { max_attempts: 2, backoff_ms: 2000 },
            ),
            std::io::ErrorKind::UnexpectedEof => (
                ErrorCode::UnexpectedEof,
                ErrorSeverity::Error,
                RecoveryHint::Retry { max_attempts: 1, backoff_ms: 500 },
            ),
            std::io::ErrorKind::NotFound => {
                (ErrorCode::IoError, ErrorSeverity::Critical, RecoveryHint::NoRecovery)
            }
            std::io::ErrorKind::PermissionDenied => {
                (ErrorCode::IoError, ErrorSeverity::Critical, RecoveryHint::NoRecovery)
            }
            _ => (ErrorCode::IoError, ErrorSeverity::Error, RecoveryHint::NoRecovery),
        };

        let mut context = ErrorContext::default();
        context.code = code;
        context.severity = severity;
        context.phase = OperationPhase::ConnectionSetup;
        context.extra.insert("io_kind".to_string(), format!("{:?}", err.kind()));

        TlsError::Io {
            message: err.to_string(),
            source: Some(Box::new(err)),
            code,
            context,
            recovery,
        }
    }
}

// Conversion from rustls::Error
impl From<rustls::Error> for TlsError {
    fn from(err: rustls::Error) -> Self {
        let (code, severity, phase, recovery) = match &err {
            rustls::Error::InvalidMessage(_) => (
                ErrorCode::InvalidHandshakeMessage,
                ErrorSeverity::Error,
                OperationPhase::Handshake,
                RecoveryHint::NoRecovery,
            ),
            rustls::Error::AlertReceived(_) => (
                ErrorCode::HandshakeFailed,
                ErrorSeverity::Warning,
                OperationPhase::Handshake,
                RecoveryHint::NoRecovery,
            ),
            rustls::Error::HandshakeNotComplete => (
                ErrorCode::HandshakeFailed,
                ErrorSeverity::Error,
                OperationPhase::Handshake,
                RecoveryHint::Retry { max_attempts: 1, backoff_ms: 0 },
            ),
            rustls::Error::PeerIncompatible(_) => (
                ErrorCode::ProtocolVersionMismatch,
                ErrorSeverity::Error,
                OperationPhase::Handshake,
                RecoveryHint::Fallback {
                    description: "Try with different protocol version or cipher suite".to_string(),
                },
            ),
            rustls::Error::PeerMisbehaved(_) => (
                ErrorCode::HandshakeFailed,
                ErrorSeverity::Critical,
                OperationPhase::Handshake,
                RecoveryHint::NoRecovery,
            ),
            rustls::Error::NoCertificatesPresented => (
                ErrorCode::MissingCertificate,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::Reconfigure {
                    field: "client authentication".to_string(),
                    suggestion: "Enable or disable client authentication as needed".to_string(),
                },
            ),

            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired) => (
                ErrorCode::CertificateExpired,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::CheckSystemTime,
            ),
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName) => (
                ErrorCode::CertificateNotValidForName,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::VerifyCertificates,
            ),
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForNameContext { expected: _, presented: _ },
            ) => (
                ErrorCode::CertificateNotValidForNameContext,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::VerifyCertificates,
            ),
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnhandledCriticalExtension,
            ) => (
                ErrorCode::CertificateUnknownCriticalExtension,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::VerifyCertificates,
            ),
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature) => (
                ErrorCode::CertificateSignatureInvalid,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::VerifyCertificates,
            ),
            rustls::Error::InvalidCertificate(rustls::CertificateError::InvalidPurpose) => (
                ErrorCode::CertificateNotValidForPurpose,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::VerifyCertificates,
            ),
            rustls::Error::InvalidCertificate(_) => (
                ErrorCode::CertificateInvalid,
                ErrorSeverity::Error,
                OperationPhase::CertificateVerification,
                RecoveryHint::VerifyCertificates,
            ),
            rustls::Error::General(_) => (
                ErrorCode::HandshakeFailed,
                ErrorSeverity::Error,
                OperationPhase::Handshake,
                RecoveryHint::Retry { max_attempts: 2, backoff_ms: 1000 },
            ),
            _ => (
                ErrorCode::HandshakeFailed,
                ErrorSeverity::Error,
                OperationPhase::Handshake,
                RecoveryHint::NoRecovery,
            ),
        };

        let mut context = ErrorContext::default();
        context.code = code;
        context.severity = severity;
        context.phase = phase;
        context.extra.insert("rustls_error".to_string(), err.to_string());

        TlsError::Tls { message: err.to_string(), code, context, recovery }
    }
}

// Conversion from HybridKemError
impl From<arc_hybrid::kem::HybridKemError> for TlsError {
    fn from(err: arc_hybrid::kem::HybridKemError) -> Self {
        let mut context = ErrorContext::default();
        context.code = ErrorCode::HybridKemFailed;
        context.severity = ErrorSeverity::Error;
        context.phase = OperationPhase::KeyExchange;
        context.extra.insert("hybrid_kem_error".to_string(), err.to_string());

        TlsError::HybridKem {
            message: err.to_string(),
            component: "X25519MLKEM768".to_string(),
            code: ErrorCode::HybridKemFailed,
            context,
            recovery: RecoveryHint::Fallback {
                description: "Consider using classical ECDHE only".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_display() {
        assert_eq!(ErrorCode::ConnectionRefused.to_string(), "CONNECTION_REFUSED");
        assert_eq!(ErrorCode::HandshakeFailed.to_string(), "HANDSHAKE_FAILED");
    }

    #[test]
    fn test_error_context_default() {
        let context = ErrorContext::default();
        assert!(!context.error_id.is_empty());
        assert_eq!(context.code, ErrorCode::InternalError);
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let tls_err = TlsError::from(io_err);
        assert_eq!(tls_err.code(), ErrorCode::ConnectionRefused);
        assert_eq!(tls_err.severity(), ErrorSeverity::Error);
    }

    #[test]
    fn test_error_recoverability() {
        let recoverable_err =
            TlsError::from(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "test"));
        assert!(recoverable_err.is_recoverable());
    }

    #[test]
    fn test_error_fallback_support() {
        let mut context = ErrorContext::default();
        context.code = ErrorCode::PqNotAvailable;
        context.severity = ErrorSeverity::Warning;
        context.phase = OperationPhase::KeyExchange;

        let err = TlsError::PqNotAvailable {
            message: "PQ not available".to_string(),
            code: ErrorCode::PqNotAvailable,
            context,
            recovery: RecoveryHint::Fallback { description: "Fall back to classical".to_string() },
        };

        assert!(err.supports_fallback());
    }
}
