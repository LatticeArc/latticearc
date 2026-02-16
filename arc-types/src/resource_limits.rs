//! Resource limits for cryptographic operations.
//!
//! Provides configurable limits on encryption size, signature size, decryption size,
//! and key derivation count to prevent denial-of-service via oversized inputs.

use std::sync::{Arc, LazyLock, RwLock};

/// Configurable resource limits for cryptographic operations.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum number of key derivations per single call.
    pub max_key_derivations_per_call: usize,
    /// Maximum encryption input size in bytes.
    pub max_encryption_size_bytes: usize,
    /// Maximum signature input size in bytes.
    pub max_signature_size_bytes: usize,
    /// Maximum decryption input size in bytes.
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
    /// Creates a new `ResourceLimits` with the specified values.
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

/// Thread-safe manager for runtime-configurable resource limits.
pub struct ResourceLimitsManager {
    limits: Arc<RwLock<ResourceLimits>>,
}

impl ResourceLimitsManager {
    /// Creates a new `ResourceLimitsManager` with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self { limits: Arc::new(RwLock::new(ResourceLimits::default())) }
    }

    /// Creates a new `ResourceLimitsManager` with the specified limits.
    #[must_use]
    pub fn with_limits(limits: ResourceLimits) -> Self {
        Self { limits: Arc::new(RwLock::new(limits)) }
    }

    /// Returns a clone of the current resource limits.
    #[must_use]
    pub fn get_limits(&self) -> ResourceLimits {
        self.limits.read().map(|guard| guard.clone()).unwrap_or_default()
    }

    /// Updates the resource limits to the specified values.
    pub fn update_limits(&self, limits: ResourceLimits) {
        if let Ok(mut guard) = self.limits.write() {
            *guard = limits;
        }
    }

    /// Validates that the key derivation count does not exceed the configured limit.
    ///
    /// # Errors
    /// Returns an error if the count exceeds the maximum allowed key derivations per call.
    pub fn validate_key_derivation_count(&self, count: usize) -> Result<()> {
        let limits = self.get_limits();
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
        let limits = self.get_limits();
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
        let limits = self.get_limits();
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
        let limits = self.get_limits();
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

/// Errors from resource limit validation.
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    /// Key derivation count exceeds configured limit.
    #[error("Key derivation limit exceeded: requested {requested}, limit {limit}")]
    KeyDerivationLimitExceeded {
        /// Number of derivations requested.
        requested: usize,
        /// Maximum allowed derivations.
        limit: usize,
    },

    /// Encryption input size exceeds configured limit.
    #[error("Encryption size limit exceeded: requested {requested}, limit {limit}")]
    EncryptionSizeLimitExceeded {
        /// Size in bytes requested.
        requested: usize,
        /// Maximum allowed size in bytes.
        limit: usize,
    },

    /// Signature input size exceeds configured limit.
    #[error("Signature size limit exceeded: requested {requested}, limit {limit}")]
    SignatureSizeLimitExceeded {
        /// Size in bytes requested.
        requested: usize,
        /// Maximum allowed size in bytes.
        limit: usize,
    },

    /// Decryption input size exceeds configured limit.
    #[error("Decryption size limit exceeded: requested {requested}, limit {limit}")]
    DecryptionSizeLimitExceeded {
        /// Size in bytes requested.
        requested: usize,
        /// Maximum allowed size in bytes.
        limit: usize,
    },
}

/// A specialized Result type for resource limit operations.
pub type Result<T> = std::result::Result<T, ResourceError>;

static GLOBAL_RESOURCE_LIMITS: LazyLock<ResourceLimitsManager> =
    LazyLock::new(ResourceLimitsManager::new);

/// Returns a reference to the global resource limits manager.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
        assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 64 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_resource_limits_new() {
        let limits = ResourceLimits::new(500, 50 * 1024 * 1024, 32 * 1024, 50 * 1024 * 1024);
        assert_eq!(limits.max_key_derivations_per_call, 500);
        assert_eq!(limits.max_encryption_size_bytes, 50 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 32 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 50 * 1024 * 1024);
    }

    #[test]
    fn test_validate_within_limits() {
        assert!(ResourceLimits::validate_key_derivation_count(100).is_ok());
        assert!(ResourceLimits::validate_encryption_size(1024).is_ok());
        assert!(ResourceLimits::validate_signature_size(1024).is_ok());
        assert!(ResourceLimits::validate_decryption_size(1024).is_ok());
    }

    #[test]
    fn test_validate_exceeds_limits() {
        assert!(ResourceLimits::validate_key_derivation_count(1001).is_err());
        assert!(ResourceLimits::validate_encryption_size(100 * 1024 * 1024 + 1).is_err());
        assert!(ResourceLimits::validate_signature_size(64 * 1024 + 1).is_err());
        assert!(ResourceLimits::validate_decryption_size(100 * 1024 * 1024 + 1).is_err());
    }

    #[test]
    fn test_validate_zero_values() {
        assert!(ResourceLimits::validate_key_derivation_count(0).is_ok());
        assert!(ResourceLimits::validate_encryption_size(0).is_ok());
        assert!(ResourceLimits::validate_signature_size(0).is_ok());
        assert!(ResourceLimits::validate_decryption_size(0).is_ok());
    }

    #[test]
    fn test_manager_with_custom_limits() {
        let custom = ResourceLimits::new(200, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 200);
        assert_eq!(limits.max_encryption_size_bytes, 1024);
    }

    #[test]
    fn test_manager_update_limits() {
        let manager = ResourceLimitsManager::new();
        assert_eq!(manager.get_limits().max_key_derivations_per_call, 1000);

        let new_limits = ResourceLimits::new(50, 1024, 512, 2048);
        manager.update_limits(new_limits);
        assert_eq!(manager.get_limits().max_key_derivations_per_call, 50);
    }

    #[test]
    fn test_manager_validate_methods() {
        let custom = ResourceLimits::new(10, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        assert!(manager.validate_key_derivation_count(10).is_ok());
        assert!(manager.validate_key_derivation_count(11).is_err());
        assert!(manager.validate_encryption_size(1024).is_ok());
        assert!(manager.validate_encryption_size(1025).is_err());
        assert!(manager.validate_signature_size(512).is_ok());
        assert!(manager.validate_signature_size(513).is_err());
        assert!(manager.validate_decryption_size(2048).is_ok());
        assert!(manager.validate_decryption_size(2049).is_err());
    }

    #[test]
    fn test_global_validate_functions() {
        assert!(validate_key_derivation_count(500).is_ok());
        assert!(validate_key_derivation_count(1001).is_err());
        assert!(validate_encryption_size(1024).is_ok());
        assert!(validate_signature_size(1024).is_ok());
        assert!(validate_decryption_size(1024).is_ok());
    }

    #[test]
    fn test_resource_error_display() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let msg = format!("{}", err);
        assert!(msg.contains("2000"));
        assert!(msg.contains("1000"));
    }
}
