//! Error types for the ZKP module.

use thiserror::Error;

/// Result type for ZKP operations
pub type Result<T> = std::result::Result<T, ZkpError>;

/// Errors that can occur during ZKP operations
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ZkpError {
    /// Invalid commitment
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid scalar value
    #[error("Invalid scalar value")]
    InvalidScalar,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid or oversized input — used for transcript-construction guards
    /// (e.g. Fiat-Shamir length prefixes that don't fit in u32).
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
