#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]

use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_key_derivations_per_call: usize,
    pub max_encryption_size_bytes: usize,
    pub max_signature_size_bytes: usize,
    pub max_decryption_size_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_key_derivations_per_call: 1000,
            max_encryption_size_bytes: 100 * 1024 * 1024,
            max_signature_size_bytes: 64 * 1024,
            max_decryption_size_bytes: 100 * 1024 * 1024,
        }
    }
}

impl ResourceLimits {
    #[must_use]
    pub fn new(
        max_key_derivations: usize,
        max_encryption_size: usize,
        max_signature_size: usize,
        max_decryption_size: usize,
    ) -> Self {
        Self {
            max_key_derivations_per_call: max_key_derivations,
            max_encryption_size_bytes: max_encryption_size,
            max_signature_size_bytes: max_signature_size,
            max_decryption_size_bytes: max_decryption_size,
        }
    }

    /// Validates that the key derivation count does not exceed the limit.
    ///
    /// # Errors
    /// Returns an error if the count exceeds the maximum allowed key derivations per call.
    pub fn validate_key_derivation_count(count: usize) -> Result<()> {
        let limits = ResourceLimits::default();
        if count > limits.max_key_derivations_per_call {
            return Err(ResourceError::KeyDerivationLimitExceeded {
                requested: count,
                limit: limits.max_key_derivations_per_call,
            });
        }
        Ok(())
    }

    /// Validates that the encryption size does not exceed the limit.
    ///
    /// # Errors
    /// Returns an error if the size exceeds the maximum allowed encryption size in bytes.
    pub fn validate_encryption_size(size: usize) -> Result<()> {
        let limits = ResourceLimits::default();
        if size > limits.max_encryption_size_bytes {
            return Err(ResourceError::EncryptionSizeLimitExceeded {
                requested: size,
                limit: limits.max_encryption_size_bytes,
            });
        }
        Ok(())
    }

    /// Validates that the signature size does not exceed the limit.
    ///
    /// # Errors
    /// Returns an error if the size exceeds the maximum allowed signature size in bytes.
    pub fn validate_signature_size(size: usize) -> Result<()> {
        let limits = ResourceLimits::default();
        if size > limits.max_signature_size_bytes {
            return Err(ResourceError::SignatureSizeLimitExceeded {
                requested: size,
                limit: limits.max_signature_size_bytes,
            });
        }
        Ok(())
    }

    /// Validates that the decryption size does not exceed the limit.
    ///
    /// # Errors
    /// Returns an error if the size exceeds the maximum allowed decryption size in bytes.
    pub fn validate_decryption_size(size: usize) -> Result<()> {
        let limits = ResourceLimits::default();
        if size > limits.max_decryption_size_bytes {
            return Err(ResourceError::DecryptionSizeLimitExceeded {
                requested: size,
                limit: limits.max_decryption_size_bytes,
            });
        }
        Ok(())
    }
}

pub struct ResourceLimitsManager {
    limits: Arc<RwLock<ResourceLimits>>,
}

impl ResourceLimitsManager {
    #[must_use]
    pub fn new() -> Self {
        Self { limits: Arc::new(RwLock::new(ResourceLimits::default())) }
    }

    #[must_use]
    pub fn with_limits(limits: ResourceLimits) -> Self {
        Self { limits: Arc::new(RwLock::new(limits)) }
    }

    #[must_use]
    pub fn get_limits(&self) -> ResourceLimits {
        self.limits.read().clone()
    }

    pub fn update_limits(&self, limits: ResourceLimits) {
        *self.limits.write() = limits;
    }

    /// Validates that the key derivation count does not exceed the configured limit.
    ///
    /// # Errors
    /// Returns an error if the count exceeds the maximum allowed key derivations per call.
    pub fn validate_key_derivation_count(&self, count: usize) -> Result<()> {
        let limits = self.limits.read();
        if count > limits.max_key_derivations_per_call {
            return Err(ResourceError::KeyDerivationLimitExceeded {
                requested: count,
                limit: limits.max_key_derivations_per_call,
            });
        }
        Ok(())
    }

    /// Validates that the encryption size does not exceed the configured limit.
    ///
    /// # Errors
    /// Returns an error if the size exceeds the maximum allowed encryption size in bytes.
    pub fn validate_encryption_size(&self, size: usize) -> Result<()> {
        let limits = self.limits.read();
        if size > limits.max_encryption_size_bytes {
            return Err(ResourceError::EncryptionSizeLimitExceeded {
                requested: size,
                limit: limits.max_encryption_size_bytes,
            });
        }
        Ok(())
    }

    /// Validates that the signature size does not exceed the configured limit.
    ///
    /// # Errors
    /// Returns an error if the size exceeds the maximum allowed signature size in bytes.
    pub fn validate_signature_size(&self, size: usize) -> Result<()> {
        let limits = self.limits.read();
        if size > limits.max_signature_size_bytes {
            return Err(ResourceError::SignatureSizeLimitExceeded {
                requested: size,
                limit: limits.max_signature_size_bytes,
            });
        }
        Ok(())
    }

    /// Validates that the decryption size does not exceed the configured limit.
    ///
    /// # Errors
    /// Returns an error if the size exceeds the maximum allowed decryption size in bytes.
    pub fn validate_decryption_size(&self, size: usize) -> Result<()> {
        let limits = self.limits.read();
        if size > limits.max_decryption_size_bytes {
            return Err(ResourceError::DecryptionSizeLimitExceeded {
                requested: size,
                limit: limits.max_decryption_size_bytes,
            });
        }
        Ok(())
    }
}

impl Default for ResourceLimitsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("Key derivation limit exceeded: requested {requested}, limit {limit}")]
    KeyDerivationLimitExceeded { requested: usize, limit: usize },

    #[error("Encryption size limit exceeded: requested {requested}, limit {limit}")]
    EncryptionSizeLimitExceeded { requested: usize, limit: usize },

    #[error("Signature size limit exceeded: requested {requested}, limit {limit}")]
    SignatureSizeLimitExceeded { requested: usize, limit: usize },

    #[error("Decryption size limit exceeded: requested {requested}, limit {limit}")]
    DecryptionSizeLimitExceeded { requested: usize, limit: usize },
}

pub type Result<T> = std::result::Result<T, ResourceError>;

lazy_static::lazy_static! {
    static ref GLOBAL_RESOURCE_LIMITS: ResourceLimitsManager = ResourceLimitsManager::new();
}

#[must_use]
pub fn get_global_resource_limits() -> &'static ResourceLimitsManager {
    &GLOBAL_RESOURCE_LIMITS
}

/// Validates key derivation count against global resource limits.
///
/// # Errors
/// Returns an error if the count exceeds the maximum allowed key derivations per call.
pub fn validate_key_derivation_count(count: usize) -> Result<()> {
    get_global_resource_limits().validate_key_derivation_count(count)
}

/// Validates encryption size against global resource limits.
///
/// # Errors
/// Returns an error if the size exceeds the maximum allowed encryption size in bytes.
pub fn validate_encryption_size(size: usize) -> Result<()> {
    get_global_resource_limits().validate_encryption_size(size)
}

/// Validates signature size against global resource limits.
///
/// # Errors
/// Returns an error if the size exceeds the maximum allowed signature size in bytes.
pub fn validate_signature_size(size: usize) -> Result<()> {
    get_global_resource_limits().validate_signature_size(size)
}

/// Validates decryption size against global resource limits.
///
/// # Errors
/// Returns an error if the size exceeds the maximum allowed decryption size in bytes.
pub fn validate_decryption_size(size: usize) -> Result<()> {
    get_global_resource_limits().validate_decryption_size(size)
}
