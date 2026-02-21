//! Error types for arc-zkp

use thiserror::Error;

/// Result type for ZKP operations
pub type Result<T> = std::result::Result<T, ZkpError>;

/// Errors that can occur during ZKP operations
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
}
