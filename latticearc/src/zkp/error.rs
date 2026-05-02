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

    /// Empty Fiat-Shamir domain separator. Required so that two distinct
    /// protocols cannot share the same challenge oracle.
    #[error("Fiat-Shamir domain separator must not be empty")]
    InvalidDomainSeparator,

    /// Verification failed for any reason on an adversary-reachable verify
    /// path. Returned in place of more granular variants (`InvalidScalar`,
    /// `InvalidPublicKey`, `SerializationError`, `InvalidCommitment`,
    /// etc.) so an attacker who crafts a hostile proof or opening cannot
    /// distinguish *which* sub-check rejected — that distinction is a
    /// structural side channel that leaks proof shape. The detailed
    /// reason is logged via `tracing::debug!` at the rejection site for
    /// developer diagnosis without exposing it on the error path.
    #[error("verification failed")]
    VerificationFailed,
}
