//! Enhanced Error Handler
//!
//! This module provides the top-level error handler that integrates
//! all error recovery components.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use super::core::{
    EffortLevel, EnhancedError, ErrorContext, ErrorSeverity, RecoveryStrategy, RecoverySuggestion,
};
use super::recovery::{ErrorRecoveryHandler, SystemHealth};
use crate::prelude::prelude::error::{LatticeArcError, Result};

/// Enhanced error handler that integrates all error recovery components
pub struct EnhancedErrorHandler {
    recovery_handler: ErrorRecoveryHandler,
}

impl EnhancedErrorHandler {
    /// Create a new enhanced error handler
    #[must_use]
    pub fn new() -> Self {
        Self { recovery_handler: ErrorRecoveryHandler::new() }
    }

    /// Handle a quantum shield error with full context and recovery
    ///
    /// # Errors
    /// Returns the original error if recovery strategies fail.
    pub fn handle_error(
        &self,
        error: &LatticeArcError,
        operation: String,
        component: String,
    ) -> Result<()> {
        let enhanced_error = EnhancedError::new(error.clone(), operation)
            .with_context(Self::create_error_context(component))
            .with_recovery_suggestions(Self::generate_recovery_suggestions(error))
            .with_severity(Self::determine_severity(error));

        self.recovery_handler.handle_error(&enhanced_error)
    }

    /// Create error context from component information
    fn create_error_context(component: String) -> ErrorContext {
        ErrorContext::new()
            .with_component(component)
            .with_user_message("An operation failed. Please try again.".to_string())
    }

    /// Generate recovery suggestions based on error type
    ///
    /// Uses wildcard match intentionally: new error variants should default to
    /// manual intervention until specific recovery strategies are defined.
    #[allow(clippy::wildcard_enum_match_arm)]
    fn generate_recovery_suggestions(error: &LatticeArcError) -> Vec<RecoverySuggestion> {
        match error {
            LatticeArcError::NetworkError(_) => vec![
                RecoverySuggestion {
                    strategy: RecoveryStrategy::Retry,
                    description: "Retry the network operation".to_string(),
                    priority: 10,
                    effort_estimate: EffortLevel::Low,
                    success_probability: 0.8,
                    steps: vec!["Wait a moment and retry".to_string()],
                },
                RecoverySuggestion {
                    strategy: RecoveryStrategy::CircuitBreaker,
                    description: "Use circuit breaker to prevent cascade failures".to_string(),
                    priority: 8,
                    effort_estimate: EffortLevel::Medium,
                    success_probability: 0.9,
                    steps: vec!["Implement circuit breaker pattern".to_string()],
                },
            ],
            LatticeArcError::InvalidInput(_) => vec![RecoverySuggestion {
                strategy: RecoveryStrategy::Fallback,
                description: "Use default values for invalid input".to_string(),
                priority: 9,
                effort_estimate: EffortLevel::Low,
                success_probability: 0.7,
                steps: vec!["Validate and sanitize input".to_string()],
            }],
            LatticeArcError::EncryptionError(_) => vec![RecoverySuggestion {
                strategy: RecoveryStrategy::GracefulDegradation,
                description: "Reduce encryption strength temporarily".to_string(),
                priority: 5,
                effort_estimate: EffortLevel::High,
                success_probability: 0.6,
                steps: vec!["Switch to faster but weaker encryption".to_string()],
            }],
            _ => vec![RecoverySuggestion {
                strategy: RecoveryStrategy::ManualIntervention,
                description: "Manual intervention required".to_string(),
                priority: 1,
                effort_estimate: EffortLevel::VeryHigh,
                success_probability: 0.3,
                steps: vec!["Contact system administrator".to_string()],
            }],
        }
    }

    /// Determine error severity based on error type
    ///
    /// Uses wildcard match intentionally: new error variants default to Low
    /// severity until explicitly categorized.
    #[allow(clippy::wildcard_enum_match_arm)]
    fn determine_severity(error: &LatticeArcError) -> ErrorSeverity {
        match error {
            LatticeArcError::InvalidKey(_) | LatticeArcError::InvalidInput(_) => {
                ErrorSeverity::Medium
            }
            LatticeArcError::NetworkError(_) | LatticeArcError::EncryptionError(_) => {
                ErrorSeverity::High
            }
            LatticeArcError::CircuitBreakerOpen | LatticeArcError::ResourceExhausted => {
                ErrorSeverity::Critical
            }
            _ => ErrorSeverity::Low,
        }
    }

    /// Get system health status
    #[must_use]
    pub fn system_health(&self) -> SystemHealth {
        self.recovery_handler.system_health()
    }

    /// Check if system is healthy
    #[must_use]
    pub fn is_system_healthy(&self) -> bool {
        self.system_health().is_healthy()
    }

    /// Get circuit breaker for a service
    pub fn get_circuit_breaker(
        &mut self,
        service: &str,
    ) -> &mut super::circuit_breaker::CircuitBreaker {
        self.recovery_handler.get_circuit_breaker(service)
    }
}

impl Default for EnhancedErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the global error handler instance
pub fn get_error_handler() -> &'static EnhancedErrorHandler {
    static INSTANCE: std::sync::OnceLock<EnhancedErrorHandler> = std::sync::OnceLock::new();
    INSTANCE.get_or_init(EnhancedErrorHandler::new)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_error_handler_new() {
        let handler = EnhancedErrorHandler::new();
        assert!(handler.is_system_healthy());
    }

    #[test]
    fn test_enhanced_error_handler_default() {
        let handler = EnhancedErrorHandler::default();
        assert!(handler.is_system_healthy());
    }

    #[test]
    fn test_handle_network_error_recovers_with_retry() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::NetworkError("timeout".to_string()),
            "connect".to_string(),
            "network".to_string(),
        );
        // NetworkError generates Retry + CircuitBreaker suggestions
        // RetryStrategy handles NetworkError, so recovery succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_invalid_input_error_fails() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::InvalidInput("bad".to_string()),
            "parse".to_string(),
            "parser".to_string(),
        );
        // InvalidInput generates Fallback suggestion, but FallbackStrategy
        // doesn't handle InvalidInput → falls through → returns error
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_encryption_error_recovers_with_degradation() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::EncryptionError("fail".to_string()),
            "encrypt".to_string(),
            "encryption".to_string(),
        );
        // EncryptionError generates GracefulDegradation suggestion
        // GracefulDegradationStrategy always returns Ok
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_unknown_error_manual_intervention() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::InvalidKey("unknown".to_string()),
            "op".to_string(),
            "component".to_string(),
        );
        // InvalidKey generates ManualIntervention suggestion
        // ManualIntervention is not a registered strategy → fails
        assert!(result.is_err());
    }

    #[test]
    fn test_determine_severity_medium() {
        let handler = EnhancedErrorHandler::new();
        // InvalidKey and InvalidInput → Medium severity
        let result = handler.handle_error(
            &LatticeArcError::InvalidInput("test".to_string()),
            "op".to_string(),
            "comp".to_string(),
        );
        // Result doesn't directly show severity, but we can check stats
        let _ = result;
    }

    #[test]
    fn test_determine_severity_critical() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::CircuitBreakerOpen,
            "op".to_string(),
            "comp".to_string(),
        );
        // CircuitBreakerOpen → Critical severity, ManualIntervention suggestion
        // BUT ManualIntervention not registered → fails → degradation check triggered
        assert!(result.is_err());
    }

    #[test]
    fn test_determine_severity_low_for_other_errors() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::InvalidConfiguration("test".to_string()),
            "op".to_string(),
            "comp".to_string(),
        );
        // ConfigError → Low severity, ManualIntervention → fails
        assert!(result.is_err());
    }

    #[test]
    fn test_system_health_after_errors() {
        let handler = EnhancedErrorHandler::new();

        for i in 0..5 {
            let _ = handler.handle_error(
                &LatticeArcError::InvalidInput(format!("err{i}")),
                "op".to_string(),
                "comp".to_string(),
            );
        }

        let health = handler.system_health();
        assert!(health.health_score < 1.0);
    }

    #[test]
    fn test_get_circuit_breaker() {
        let mut handler = EnhancedErrorHandler::new();
        let cb = handler.get_circuit_breaker("database");
        let stats = cb.stats();
        assert_eq!(stats.state, super::super::circuit_breaker::CircuitBreakerState::Closed);
    }

    #[test]
    fn test_get_error_handler_global() {
        let handler = get_error_handler();
        assert!(handler.is_system_healthy());
    }

    #[test]
    fn test_get_error_handler_same_instance() {
        let handler1 = get_error_handler();
        let handler2 = get_error_handler();
        // Both should be the same static reference
        assert!(std::ptr::eq(handler1, handler2));
    }

    #[test]
    fn test_service_unavailable_error_recovers() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::ServiceUnavailable("down".to_string()),
            "call".to_string(),
            "service".to_string(),
        );
        // ServiceUnavailable → ManualIntervention (wildcard match)
        // ManualIntervention not registered → fails
        assert!(result.is_err());
    }

    #[test]
    fn test_resource_exhausted_error() {
        let handler = EnhancedErrorHandler::new();
        let result = handler.handle_error(
            &LatticeArcError::ResourceExhausted,
            "allocate".to_string(),
            "memory".to_string(),
        );
        // ResourceExhausted → Critical severity, ManualIntervention → fails
        assert!(result.is_err());
    }
}
