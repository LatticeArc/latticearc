//! Error Recovery Module
//!
//! This module provides comprehensive error handling with recovery mechanisms,
//! circuit breakers, graceful degradation, and system health monitoring.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// Circuit breaker for external service failure protection.
pub mod circuit_breaker;
/// Core error structures and basic error handling.
pub mod core;
/// Graceful degradation management.
pub mod degradation;
/// Enhanced error handler integration.
pub mod handler;
/// Error recovery handler and system health.
pub mod recovery;

// Re-exports for convenient access
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState, CircuitBreakerStats,
};
pub use core::{
    EffortLevel, EnhancedError, ErrorContext, ErrorSeverity, RecoveryStrategy, RecoverySuggestion,
};
pub use degradation::{DegradationStrategy, GracefulDegradationManager, ServiceDegradationInfo};
pub use handler::{EnhancedErrorHandler, get_error_handler};
pub use recovery::{ErrorRecoveryHandler, ErrorStatistics, SystemHealth};
