//! Core Error Structures and Basic Error Handling
//!
//! This module contains the fundamental error types and structures used
//! throughout the error recovery system.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::prelude::error::LatticeArcError;
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

        let error_id = format!("ERR-{}", rand::thread_rng().r#gen::<u64>());
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
