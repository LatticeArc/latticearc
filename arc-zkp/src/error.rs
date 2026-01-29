//! Error types for arc-zkp

use thiserror::Error;

/// Result type for ZKP operations
pub type Result<T> = std::result::Result<T, ZkpError>;

/// Errors that can occur during ZKP operations
#[derive(Debug, Error)]
pub enum ZkpError {
    /// Proof verification failed
    #[error("Proof verification failed")]
    VerificationFailed,

    /// Invalid proof format
    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    /// Invalid commitment
    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    /// Commitment opening failed
    #[error("Commitment opening failed: values do not match")]
    CommitmentOpeningFailed,

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid scalar value
    #[error("Invalid scalar value")]
    InvalidScalar,

    /// Random number generation failed
    #[error("Random number generation failed")]
    RngFailed,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid challenge
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
}
