//! Error Recovery Strategies
//!
//! This module provides functions for error recovery and severity assessment,
//! enabling graceful handling of failures in cryptographic operations.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use super::LatticeArcError;

/// Error recovery strategy.
///
/// Defines the strategy to use when recovering from an error.
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorRecoveryStrategy {
    /// Retry the operation with exponential backoff.
    Retry {
        /// Maximum number of retry attempts.
        max_attempts: usize,
        /// Base delay between retries in milliseconds.
        delay_ms: u64,
    },
    /// Fall back to an alternative approach.
    Fallback {
        /// Description of the alternative approach.
        alternative: String,
    },
    /// Degrade to reduced functionality.
    Degrade {
        /// Description of reduced functionality.
        reduced_functionality: String,
    },
    /// Ignore the error and continue.
    Ignore,
    /// Fail immediately without recovery.
    Fail,
}

/// Error severity level for NIST compliance.
///
/// Used to classify errors by their impact on security and operations.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum ErrorSeverity {
    /// Low severity - minimal impact.
    Low = 1,
    /// Medium severity - moderate impact.
    Medium = 2,
    /// High severity - significant impact.
    High = 3,
    /// Critical severity - severe impact.
    Critical = 4,
}

/// Attempt error recovery based on error type.
///
/// Uses wildcard match intentionally: new error variants default to
/// no recovery strategy (None) until explicitly handled.
#[must_use]
#[allow(clippy::wildcard_enum_match_arm)]
pub fn attempt_error_recovery(error: &LatticeArcError) -> Option<ErrorRecoveryStrategy> {
    match error {
        LatticeArcError::NetworkError(_) => {
            Some(ErrorRecoveryStrategy::Retry { max_attempts: 3, delay_ms: 1000 })
        }
        LatticeArcError::TimeoutError(_) => {
            Some(ErrorRecoveryStrategy::Retry { max_attempts: 2, delay_ms: 500 })
        }
        LatticeArcError::ServiceUnavailable(_) => {
            Some(ErrorRecoveryStrategy::Retry { max_attempts: 5, delay_ms: 2000 })
        }
        LatticeArcError::CircuitBreakerOpen => {
            Some(ErrorRecoveryStrategy::Retry { max_attempts: 1, delay_ms: 10000 })
        }
        LatticeArcError::ResourceExhausted => Some(ErrorRecoveryStrategy::Degrade {
            reduced_functionality: "Reduced parallelism".to_string(),
        }),
        LatticeArcError::HardwareError(_) => {
            Some(ErrorRecoveryStrategy::Fallback { alternative: "Software fallback".to_string() })
        }
        LatticeArcError::FeatureNotEnabled(_) => Some(ErrorRecoveryStrategy::Fail),
        _ => None, // No recovery strategy for other errors
    }
}

/// Check if error is recoverable.
///
/// Returns true if a recovery strategy exists for the given error type.
#[must_use]
pub fn is_recoverable_error(error: &LatticeArcError) -> bool {
    attempt_error_recovery(error).is_some()
}

/// Get error severity for compliance reporting.
///
/// Uses wildcard match intentionally: new error variants default to
/// Low severity until explicitly categorized.
#[must_use]
#[allow(clippy::wildcard_enum_match_arm)]
pub fn get_error_severity(error: &LatticeArcError) -> ErrorSeverity {
    match error {
        LatticeArcError::EncryptionError(_)
        | LatticeArcError::DecryptionError(_)
        | LatticeArcError::KeyGenerationError(_)
        | LatticeArcError::SigningError(_)
        | LatticeArcError::VerificationError
        | LatticeArcError::InvalidSignature(_) => ErrorSeverity::Critical,

        LatticeArcError::AuthenticationError(_)
        | LatticeArcError::AccessDenied(_)
        | LatticeArcError::Unauthorized(_)
        | LatticeArcError::SecurityViolation(_)
        | LatticeArcError::PolicyViolation(_)
        | LatticeArcError::ComplianceViolation(_) => ErrorSeverity::High,

        LatticeArcError::NetworkError(_)
        | LatticeArcError::DatabaseError(_)
        | LatticeArcError::IoError(_)
        | LatticeArcError::HardwareError(_)
        | LatticeArcError::ServiceUnavailable(_) => ErrorSeverity::Medium,

        _ => ErrorSeverity::Low,
    }
}

/// Check if error requires immediate security response.
///
/// Returns true for Critical and High severity errors that require
/// immediate attention from security personnel.
#[must_use]
pub fn requires_security_response(error: &LatticeArcError) -> bool {
    matches!(get_error_severity(error), ErrorSeverity::Critical | ErrorSeverity::High)
}
