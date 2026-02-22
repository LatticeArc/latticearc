//! Error types for pure-Rust type operations.
//!
//! Provides error types for configuration validation, key lifecycle transitions,
//! and other non-FFI error conditions.

use thiserror::Error;

use crate::types::key_lifecycle::KeyLifecycleState;

/// Errors for pure-Rust type operations in `arc-types`.
///
/// These errors cover non-FFI conditions like configuration validation
/// and key lifecycle state transition violations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TypeError {
    /// Invalid key lifecycle state transition attempted.
    #[error("Invalid key state transition: {from:?} -> {to:?}")]
    InvalidStateTransition {
        /// Original key state.
        from: KeyLifecycleState,
        /// Target key state that was rejected.
        to: KeyLifecycleState,
    },

    /// Configuration validation error.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Unrecognized encryption scheme string in legacy data.
    #[error("Unknown encryption scheme: {0}")]
    UnknownScheme(String),
}

/// A specialized Result type for `arc-types` operations.
pub type Result<T> = std::result::Result<T, TypeError>;
