//! Error types for arc-primitives crate.

/// Errors that can occur in cryptographic primitive operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A required feature is not available in this build.
    #[error("Feature not available: {0}")]
    FeatureNotAvailable(String),

    /// The input provided to an operation was invalid.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Encryption operation failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Failed to serialize data.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Failed to deserialize data.
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Generic error for operations that don't fit other categories.
    #[error("{0}")]
    Other(String),

    /// Error from ML-KEM operations.
    #[error("ML-KEM error: {0}")]
    MlKem(#[from] crate::kem::ml_kem::MlKemError),

    /// Operation exceeded resource limits.
    #[error("Resource limit exceeded: {0}")]
    ResourceExceeded(String),

    /// Key validation failed during import or use.
    #[error("Key validation failed")]
    KeyValidationFailed,

    /// A cryptographically weak key was detected.
    #[error("Weak key detected")]
    WeakKey,

    /// The key format is invalid or unsupported.
    #[error("Invalid key format")]
    InvalidKeyFormat,
}

/// Result type alias for arc-primitives operations.
pub type Result<T> = std::result::Result<T, Error>;
