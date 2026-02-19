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

#[cfg(test)]
mod tests {
    use super::*;

    // === ErrorRecoveryStrategy tests ===

    #[test]
    fn test_recovery_strategy_retry() {
        let strategy = ErrorRecoveryStrategy::Retry { max_attempts: 3, delay_ms: 1000 };
        assert_eq!(strategy, ErrorRecoveryStrategy::Retry { max_attempts: 3, delay_ms: 1000 });
    }

    #[test]
    fn test_recovery_strategy_fallback() {
        let strategy = ErrorRecoveryStrategy::Fallback { alternative: "use backup".to_string() };
        assert!(matches!(strategy, ErrorRecoveryStrategy::Fallback { .. }));
    }

    #[test]
    fn test_recovery_strategy_degrade() {
        let strategy =
            ErrorRecoveryStrategy::Degrade { reduced_functionality: "limited".to_string() };
        assert!(matches!(strategy, ErrorRecoveryStrategy::Degrade { .. }));
    }

    #[test]
    fn test_recovery_strategy_ignore() {
        let strategy = ErrorRecoveryStrategy::Ignore;
        assert_eq!(strategy, ErrorRecoveryStrategy::Ignore);
    }

    #[test]
    fn test_recovery_strategy_fail() {
        let strategy = ErrorRecoveryStrategy::Fail;
        assert_eq!(strategy, ErrorRecoveryStrategy::Fail);
    }

    #[test]
    fn test_recovery_strategy_clone_and_debug() {
        let strategy = ErrorRecoveryStrategy::Retry { max_attempts: 2, delay_ms: 500 };
        let cloned = strategy.clone();
        assert_eq!(strategy, cloned);
        let debug = format!("{:?}", strategy);
        assert!(debug.contains("Retry"));
    }

    // === ErrorSeverity tests ===

    #[test]
    fn test_error_severity_ordering() {
        assert!(ErrorSeverity::Low < ErrorSeverity::Medium);
        assert!(ErrorSeverity::Medium < ErrorSeverity::High);
        assert!(ErrorSeverity::High < ErrorSeverity::Critical);
    }

    #[test]
    fn test_error_severity_values() {
        assert_eq!(ErrorSeverity::Low as u8, 1);
        assert_eq!(ErrorSeverity::Medium as u8, 2);
        assert_eq!(ErrorSeverity::High as u8, 3);
        assert_eq!(ErrorSeverity::Critical as u8, 4);
    }

    #[test]
    fn test_error_severity_clone_copy() {
        let s = ErrorSeverity::High;
        let c = s;
        assert_eq!(s, c);
    }

    // === attempt_error_recovery tests ===

    #[test]
    fn test_recovery_network_error() {
        let err = LatticeArcError::NetworkError("connection lost".to_string());
        let strategy = attempt_error_recovery(&err);
        assert!(matches!(strategy, Some(ErrorRecoveryStrategy::Retry { max_attempts: 3, .. })));
    }

    #[test]
    fn test_recovery_timeout_error() {
        let err = LatticeArcError::TimeoutError("timed out".to_string());
        let strategy = attempt_error_recovery(&err);
        assert!(matches!(strategy, Some(ErrorRecoveryStrategy::Retry { max_attempts: 2, .. })));
    }

    #[test]
    fn test_recovery_service_unavailable() {
        let err = LatticeArcError::ServiceUnavailable("503".to_string());
        let strategy = attempt_error_recovery(&err);
        assert!(matches!(strategy, Some(ErrorRecoveryStrategy::Retry { max_attempts: 5, .. })));
    }

    #[test]
    fn test_recovery_circuit_breaker() {
        let err = LatticeArcError::CircuitBreakerOpen;
        let strategy = attempt_error_recovery(&err);
        assert!(matches!(strategy, Some(ErrorRecoveryStrategy::Retry { max_attempts: 1, .. })));
    }

    #[test]
    fn test_recovery_resource_exhausted() {
        let err = LatticeArcError::ResourceExhausted;
        let strategy = attempt_error_recovery(&err);
        assert!(matches!(strategy, Some(ErrorRecoveryStrategy::Degrade { .. })));
    }

    #[test]
    fn test_recovery_hardware_error() {
        let err = LatticeArcError::HardwareError("HSM failure".to_string());
        let strategy = attempt_error_recovery(&err);
        assert!(matches!(strategy, Some(ErrorRecoveryStrategy::Fallback { .. })));
    }

    #[test]
    fn test_recovery_feature_not_enabled() {
        let err = LatticeArcError::FeatureNotEnabled("async".to_string());
        let strategy = attempt_error_recovery(&err);
        assert_eq!(strategy, Some(ErrorRecoveryStrategy::Fail));
    }

    #[test]
    fn test_recovery_no_strategy() {
        let err = LatticeArcError::EncryptionError("AES failed".to_string());
        let strategy = attempt_error_recovery(&err);
        assert!(strategy.is_none());
    }

    // === is_recoverable_error tests ===

    #[test]
    fn test_is_recoverable_network() {
        assert!(is_recoverable_error(&LatticeArcError::NetworkError("x".to_string())));
    }

    #[test]
    fn test_is_not_recoverable_encryption() {
        assert!(!is_recoverable_error(&LatticeArcError::EncryptionError("x".to_string())));
    }

    // === get_error_severity tests ===

    #[test]
    fn test_severity_critical_for_crypto_errors() {
        assert_eq!(
            get_error_severity(&LatticeArcError::EncryptionError("x".to_string())),
            ErrorSeverity::Critical
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::DecryptionError("x".to_string())),
            ErrorSeverity::Critical
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::KeyGenerationError("x".to_string())),
            ErrorSeverity::Critical
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::SigningError("x".to_string())),
            ErrorSeverity::Critical
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::VerificationError),
            ErrorSeverity::Critical
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::InvalidSignature("x".to_string())),
            ErrorSeverity::Critical
        );
    }

    #[test]
    fn test_severity_high_for_auth_errors() {
        assert_eq!(
            get_error_severity(&LatticeArcError::AuthenticationError("x".to_string())),
            ErrorSeverity::High
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::AccessDenied("x".to_string())),
            ErrorSeverity::High
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::Unauthorized("x".to_string())),
            ErrorSeverity::High
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::SecurityViolation("x".to_string())),
            ErrorSeverity::High
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::PolicyViolation("x".to_string())),
            ErrorSeverity::High
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::ComplianceViolation("x".to_string())),
            ErrorSeverity::High
        );
    }

    #[test]
    fn test_severity_medium_for_infra_errors() {
        assert_eq!(
            get_error_severity(&LatticeArcError::NetworkError("x".to_string())),
            ErrorSeverity::Medium
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::DatabaseError("x".to_string())),
            ErrorSeverity::Medium
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::IoError("x".to_string())),
            ErrorSeverity::Medium
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::HardwareError("x".to_string())),
            ErrorSeverity::Medium
        );
        assert_eq!(
            get_error_severity(&LatticeArcError::ServiceUnavailable("x".to_string())),
            ErrorSeverity::Medium
        );
    }

    #[test]
    fn test_severity_low_for_other_errors() {
        assert_eq!(
            get_error_severity(&LatticeArcError::InvalidInput("x".to_string())),
            ErrorSeverity::Low
        );
        assert_eq!(get_error_severity(&LatticeArcError::RandomError), ErrorSeverity::Low);
    }

    // === requires_security_response tests ===

    #[test]
    fn test_requires_response_for_crypto() {
        assert!(requires_security_response(&LatticeArcError::EncryptionError("x".to_string())));
    }

    #[test]
    fn test_requires_response_for_auth() {
        assert!(requires_security_response(&LatticeArcError::AccessDenied("x".to_string())));
    }

    #[test]
    fn test_no_response_for_low() {
        assert!(!requires_security_response(&LatticeArcError::InvalidInput("x".to_string())));
    }

    #[test]
    fn test_no_response_for_medium() {
        assert!(!requires_security_response(&LatticeArcError::NetworkError("x".to_string())));
    }
}
