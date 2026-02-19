//! Core Error Structures and Basic Error Handling
//!
//! This module contains the fundamental error types and structures used
//! throughout the error recovery system.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::prelude::error::LatticeArcError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Enhanced error information with context and recovery suggestions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedError {
    /// Original error
    pub error: LatticeArcError,
    /// Error context and additional information
    pub context: ErrorContext,
    /// Recovery suggestions
    pub recovery_suggestions: Vec<RecoverySuggestion>,
    /// Timestamp when error occurred
    pub timestamp: DateTime<Utc>,
    /// Error severity level
    pub severity: ErrorSeverity,
    /// Unique error ID for tracking
    pub error_id: String,
    /// Operation that caused the error
    pub operation: String,
    /// Stack trace (if available)
    pub stack_trace: Option<String>,
}

/// Error context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// User-friendly error message
    pub user_message: String,
    /// Technical details for debugging
    pub technical_details: HashMap<String, String>,
    /// Related component or module
    pub component: String,
    /// Operation parameters (sanitized)
    pub parameters: HashMap<String, String>,
    /// System state information
    pub system_state: HashMap<String, String>,
}

/// Recovery suggestion with priority and implementation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySuggestion {
    /// Recovery strategy identifier
    pub strategy: RecoveryStrategy,
    /// Human-readable description
    pub description: String,
    /// Priority level (higher = more recommended)
    pub priority: u8,
    /// Estimated time to implement
    pub effort_estimate: EffortLevel,
    /// Success probability (0.0 to 1.0)
    pub success_probability: f64,
    /// Implementation steps
    pub steps: Vec<String>,
}

/// Error severity levels for classification and handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Low severity - informational, no immediate action required
    Low,
    /// Medium severity - requires attention but not urgent
    Medium,
    /// High severity - requires immediate attention
    High,
    /// Critical severity - system stability at risk, immediate action required
    Critical,
}

/// Recovery strategy types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Retry the failed operation with backoff.
    Retry,
    /// Fall back to an alternative approach.
    Fallback,
    /// Use circuit breaker to prevent cascading failures.
    CircuitBreaker,
    /// Gracefully degrade functionality.
    GracefulDegradation,
    /// Require manual intervention.
    ManualIntervention,
}

/// Effort level estimates for recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffortLevel {
    /// Low effort required.
    Low,
    /// Medium effort required.
    Medium,
    /// High effort required.
    High,
    /// Very high effort required.
    VeryHigh,
}

impl EnhancedError {
    /// Create a new enhanced error
    #[must_use]
    pub fn new(error: LatticeArcError, operation: String) -> Self {
        use rand::Rng;

        let error_id = format!("ERR-{}", rand::rngs::OsRng.r#gen::<u64>());
        let timestamp = Utc::now();

        Self {
            error,
            context: ErrorContext::new(),
            recovery_suggestions: Vec::new(),
            timestamp,
            severity: ErrorSeverity::Medium,
            error_id,
            operation,
            stack_trace: Self::capture_stack_trace(),
        }
    }

    /// Add context information
    #[must_use]
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = context;
        self
    }

    /// Add recovery suggestions
    #[must_use]
    pub fn with_recovery_suggestions(mut self, suggestions: Vec<RecoverySuggestion>) -> Self {
        self.recovery_suggestions = suggestions;
        self
    }

    /// Set severity level
    #[must_use]
    pub fn with_severity(mut self, severity: ErrorSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Capture stack trace if available.
    /// Returns Option to match disabled version - always returns Some when enabled.
    #[cfg(feature = "std-backtrace")]
    #[allow(clippy::unnecessary_wraps)]
    fn capture_stack_trace() -> Option<String> {
        Some(format!("{:?}", backtrace::Backtrace::new()))
    }

    /// Returns None when backtrace feature is disabled - Option type required
    /// to match signature of the feature-enabled version.
    #[cfg(not(feature = "std-backtrace"))]
    #[allow(clippy::unnecessary_wraps)]
    fn capture_stack_trace() -> Option<String> {
        None
    }

    /// Get user-friendly error message
    #[must_use]
    pub fn user_message(&self) -> &str {
        if self.context.user_message.is_empty() {
            "An error occurred"
        } else {
            &self.context.user_message
        }
    }

    /// Check if error is recoverable
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        !self.recovery_suggestions.is_empty()
    }
}

impl ErrorContext {
    /// Create new error context
    #[must_use]
    pub fn new() -> Self {
        Self {
            user_message: String::new(),
            technical_details: HashMap::new(),
            component: String::new(),
            parameters: HashMap::new(),
            system_state: HashMap::new(),
        }
    }

    /// Set user message
    #[must_use]
    pub fn with_user_message(mut self, message: String) -> Self {
        self.user_message = message;
        self
    }

    /// Add technical detail
    #[must_use]
    pub fn add_technical_detail(mut self, key: String, value: String) -> Self {
        self.technical_details.insert(key, value);
        self
    }

    /// Set component
    #[must_use]
    pub fn with_component(mut self, component: String) -> Self {
        self.component = component;
        self
    }

    /// Add parameter
    #[must_use]
    pub fn add_parameter(mut self, key: String, value: String) -> Self {
        self.parameters.insert(key, value);
        self
    }

    /// Add system state
    #[must_use]
    pub fn add_system_state(mut self, key: String, value: String) -> Self {
        self.system_state.insert(key, value);
        self
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_error_context_new_defaults() {
        let ctx = ErrorContext::new();
        assert!(ctx.user_message.is_empty());
        assert!(ctx.technical_details.is_empty());
        assert!(ctx.component.is_empty());
        assert!(ctx.parameters.is_empty());
        assert!(ctx.system_state.is_empty());
    }

    #[test]
    fn test_error_context_default_matches_new() {
        let ctx = ErrorContext::default();
        assert!(ctx.user_message.is_empty());
        assert!(ctx.component.is_empty());
    }

    #[test]
    fn test_error_context_builder_pattern() {
        let ctx = ErrorContext::new()
            .with_user_message("Something failed".to_string())
            .with_component("encryption".to_string())
            .add_technical_detail("algorithm".to_string(), "AES-256".to_string())
            .add_parameter("key_size".to_string(), "256".to_string())
            .add_system_state("memory".to_string(), "ok".to_string());

        assert_eq!(ctx.user_message, "Something failed");
        assert_eq!(ctx.component, "encryption");
        assert_eq!(ctx.technical_details.get("algorithm").unwrap(), "AES-256");
        assert_eq!(ctx.parameters.get("key_size").unwrap(), "256");
        assert_eq!(ctx.system_state.get("memory").unwrap(), "ok");
    }

    #[test]
    fn test_enhanced_error_new() {
        let error = LatticeArcError::InvalidInput("bad input".to_string());
        let enhanced = EnhancedError::new(error, "encrypt".to_string());

        assert_eq!(enhanced.operation, "encrypt");
        assert!(enhanced.error_id.starts_with("ERR-"));
        assert_eq!(enhanced.severity, ErrorSeverity::Medium);
        assert!(enhanced.recovery_suggestions.is_empty());
        // stack_trace depends on std-backtrace feature flag
        #[cfg(feature = "std-backtrace")]
        assert!(enhanced.stack_trace.is_some());
        #[cfg(not(feature = "std-backtrace"))]
        assert!(enhanced.stack_trace.is_none());
    }

    #[test]
    fn test_enhanced_error_with_context() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let ctx = ErrorContext::new().with_component("test-comp".to_string());
        let enhanced = EnhancedError::new(error, "op".to_string()).with_context(ctx);

        assert_eq!(enhanced.context.component, "test-comp");
    }

    #[test]
    fn test_enhanced_error_with_severity() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let enhanced =
            EnhancedError::new(error, "op".to_string()).with_severity(ErrorSeverity::Critical);

        assert_eq!(enhanced.severity, ErrorSeverity::Critical);
    }

    #[test]
    fn test_enhanced_error_with_recovery_suggestions() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let suggestions = vec![RecoverySuggestion {
            strategy: RecoveryStrategy::Retry,
            description: "Retry the operation".to_string(),
            priority: 10,
            effort_estimate: EffortLevel::Low,
            success_probability: 0.8,
            steps: vec!["Wait and retry".to_string()],
        }];

        let enhanced =
            EnhancedError::new(error, "op".to_string()).with_recovery_suggestions(suggestions);

        assert_eq!(enhanced.recovery_suggestions.len(), 1);
        assert!(enhanced.is_recoverable());
    }

    #[test]
    fn test_enhanced_error_not_recoverable_when_no_suggestions() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let enhanced = EnhancedError::new(error, "op".to_string());
        assert!(!enhanced.is_recoverable());
    }

    #[test]
    fn test_enhanced_error_user_message_default() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let enhanced = EnhancedError::new(error, "op".to_string());
        assert_eq!(enhanced.user_message(), "An error occurred");
    }

    #[test]
    fn test_enhanced_error_user_message_custom() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let ctx = ErrorContext::new().with_user_message("Custom message".to_string());
        let enhanced = EnhancedError::new(error, "op".to_string()).with_context(ctx);
        assert_eq!(enhanced.user_message(), "Custom message");
    }

    #[test]
    fn test_error_severity_ordering() {
        assert!(ErrorSeverity::Low < ErrorSeverity::Medium);
        assert!(ErrorSeverity::Medium < ErrorSeverity::High);
        assert!(ErrorSeverity::High < ErrorSeverity::Critical);
    }

    #[test]
    fn test_error_severity_eq() {
        assert_eq!(ErrorSeverity::Low, ErrorSeverity::Low);
        assert_ne!(ErrorSeverity::Low, ErrorSeverity::High);
    }

    #[test]
    fn test_recovery_strategy_variants() {
        let strategies = vec![
            RecoveryStrategy::Retry,
            RecoveryStrategy::Fallback,
            RecoveryStrategy::CircuitBreaker,
            RecoveryStrategy::GracefulDegradation,
            RecoveryStrategy::ManualIntervention,
        ];
        for s in &strategies {
            assert_eq!(*s, *s);
        }
        assert_ne!(RecoveryStrategy::Retry, RecoveryStrategy::Fallback);
    }

    #[test]
    fn test_effort_level_variants() {
        let levels =
            vec![EffortLevel::Low, EffortLevel::Medium, EffortLevel::High, EffortLevel::VeryHigh];
        for l in &levels {
            assert_eq!(*l, *l);
        }
        assert_ne!(EffortLevel::Low, EffortLevel::High);
    }

    #[test]
    fn test_enhanced_error_clone_and_debug() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let enhanced = EnhancedError::new(error, "op".to_string());
        let cloned = enhanced.clone();

        assert_eq!(cloned.operation, enhanced.operation);
        assert_eq!(cloned.error_id, enhanced.error_id);

        let debug = format!("{:?}", enhanced);
        assert!(debug.contains("EnhancedError"));
    }

    #[test]
    fn test_recovery_suggestion_clone_and_debug() {
        let suggestion = RecoverySuggestion {
            strategy: RecoveryStrategy::Retry,
            description: "Retry".to_string(),
            priority: 5,
            effort_estimate: EffortLevel::Low,
            success_probability: 0.9,
            steps: vec!["Step 1".to_string()],
        };
        let cloned = suggestion.clone();
        assert_eq!(cloned.priority, 5);
        assert_eq!(cloned.strategy, RecoveryStrategy::Retry);

        let debug = format!("{:?}", suggestion);
        assert!(debug.contains("Retry"));
    }

    #[test]
    fn test_error_context_clone_and_debug() {
        let ctx = ErrorContext::new().with_component("test".to_string());
        let cloned = ctx.clone();
        assert_eq!(cloned.component, "test");

        let debug = format!("{:?}", ctx);
        assert!(debug.contains("ErrorContext"));
    }

    #[test]
    fn test_enhanced_error_serialization() {
        let error = LatticeArcError::InvalidInput("test".to_string());
        let enhanced = EnhancedError::new(error, "op".to_string());

        let json = serde_json::to_string(&enhanced).unwrap();
        assert!(json.contains("InvalidInput"));
        assert!(json.contains("op"));

        let deserialized: EnhancedError = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.operation, "op");
    }
}
