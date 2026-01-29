//! Error Handling Module
//!
//! This module provides comprehensive error types and recovery mechanisms
//! for the LatticeArc library.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

/// Enhanced error handling with recovery mechanisms.
pub mod error_recovery;
/// Core error types and result handling.
pub mod types;

// Re-export error types and recovery mechanisms
pub use error_recovery::{
    EffortLevel, EnhancedError, ErrorRecoveryHandler, ErrorSeverity, RecoveryStrategy,
    SystemHealth, get_error_handler,
};
pub use types::{
    ErrorRecoveryStrategy, LatticeArcError, Result, TimeCapsuleError, attempt_error_recovery,
    get_error_severity, is_recoverable_error, requires_security_response,
};
