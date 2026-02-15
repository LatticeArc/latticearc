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

static GLOBAL_RESOURCE_LIMITS: std::sync::LazyLock<ResourceLimitsManager> =
    std::sync::LazyLock::new(ResourceLimitsManager::new);

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

    // === ResourceLimits struct tests ===

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
    fn test_resource_limits_clone_debug() {
        let limits = ResourceLimits::default();
        let cloned = limits.clone();
        assert_eq!(cloned.max_key_derivations_per_call, limits.max_key_derivations_per_call);
        let debug = format!("{:?}", limits);
        assert!(debug.contains("ResourceLimits"));
    }

    // === Static validation methods ===

    #[test]
    fn test_validate_key_derivation_count_within_limit() {
        assert!(ResourceLimits::validate_key_derivation_count(100).is_ok());
        assert!(ResourceLimits::validate_key_derivation_count(1000).is_ok());
    }

    #[test]
    fn test_validate_key_derivation_count_exceeds_limit() {
        let result = ResourceLimits::validate_key_derivation_count(1001);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::KeyDerivationLimitExceeded { requested, limit } => {
                assert_eq!(requested, 1001);
                assert_eq!(limit, 1000);
            }
            other => panic!("Expected KeyDerivationLimitExceeded, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_encryption_size_within_limit() {
        assert!(ResourceLimits::validate_encryption_size(1024).is_ok());
        assert!(ResourceLimits::validate_encryption_size(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_validate_encryption_size_exceeds_limit() {
        let result = ResourceLimits::validate_encryption_size(100 * 1024 * 1024 + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::EncryptionSizeLimitExceeded { requested, limit } => {
                assert_eq!(requested, 100 * 1024 * 1024 + 1);
                assert_eq!(limit, 100 * 1024 * 1024);
            }
            other => panic!("Expected EncryptionSizeLimitExceeded, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_signature_size_within_limit() {
        assert!(ResourceLimits::validate_signature_size(1024).is_ok());
        assert!(ResourceLimits::validate_signature_size(64 * 1024).is_ok());
    }

    #[test]
    fn test_validate_signature_size_exceeds_limit() {
        let result = ResourceLimits::validate_signature_size(64 * 1024 + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::SignatureSizeLimitExceeded { requested, limit } => {
                assert_eq!(requested, 64 * 1024 + 1);
                assert_eq!(limit, 64 * 1024);
            }
            other => panic!("Expected SignatureSizeLimitExceeded, got: {:?}", other),
        }
    }

    #[test]
    fn test_validate_decryption_size_within_limit() {
        assert!(ResourceLimits::validate_decryption_size(1024).is_ok());
        assert!(ResourceLimits::validate_decryption_size(100 * 1024 * 1024).is_ok());
    }

    #[test]
    fn test_validate_decryption_size_exceeds_limit() {
        let result = ResourceLimits::validate_decryption_size(100 * 1024 * 1024 + 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResourceError::DecryptionSizeLimitExceeded { requested, limit } => {
                assert_eq!(requested, 100 * 1024 * 1024 + 1);
                assert_eq!(limit, 100 * 1024 * 1024);
            }
            other => panic!("Expected DecryptionSizeLimitExceeded, got: {:?}", other),
        }
    }

    // === ResourceLimitsManager tests ===

    #[test]
    fn test_manager_new_default() {
        let manager = ResourceLimitsManager::new();
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
    }

    #[test]
    fn test_manager_default_trait() {
        let manager = ResourceLimitsManager::default();
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
    }

    #[test]
    fn test_manager_with_custom_limits() {
        let custom = ResourceLimits::new(200, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        let limits = manager.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 200);
        assert_eq!(limits.max_encryption_size_bytes, 1024);
        assert_eq!(limits.max_signature_size_bytes, 512);
        assert_eq!(limits.max_decryption_size_bytes, 2048);
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
    fn test_manager_validate_key_derivation_count() {
        let custom = ResourceLimits::new(10, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        assert!(manager.validate_key_derivation_count(10).is_ok());
        assert!(manager.validate_key_derivation_count(11).is_err());
    }

    #[test]
    fn test_manager_validate_encryption_size() {
        let custom = ResourceLimits::new(10, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        assert!(manager.validate_encryption_size(1024).is_ok());
        assert!(manager.validate_encryption_size(1025).is_err());
    }

    #[test]
    fn test_manager_validate_signature_size() {
        let custom = ResourceLimits::new(10, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        assert!(manager.validate_signature_size(512).is_ok());
        assert!(manager.validate_signature_size(513).is_err());
    }

    #[test]
    fn test_manager_validate_decryption_size() {
        let custom = ResourceLimits::new(10, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        assert!(manager.validate_decryption_size(2048).is_ok());
        assert!(manager.validate_decryption_size(2049).is_err());
    }

    // === Global functions tests ===

    #[test]
    fn test_get_global_resource_limits() {
        let global = get_global_resource_limits();
        let limits = global.get_limits();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
    }

    #[test]
    fn test_global_validate_key_derivation_count() {
        assert!(validate_key_derivation_count(500).is_ok());
        assert!(validate_key_derivation_count(1001).is_err());
    }

    #[test]
    fn test_global_validate_encryption_size() {
        assert!(validate_encryption_size(1024).is_ok());
        assert!(validate_encryption_size(100 * 1024 * 1024 + 1).is_err());
    }

    #[test]
    fn test_global_validate_signature_size() {
        assert!(validate_signature_size(1024).is_ok());
        assert!(validate_signature_size(64 * 1024 + 1).is_err());
    }

    #[test]
    fn test_global_validate_decryption_size() {
        assert!(validate_decryption_size(1024).is_ok());
        assert!(validate_decryption_size(100 * 1024 * 1024 + 1).is_err());
    }

    // === ResourceError tests ===

    #[test]
    fn test_resource_error_display() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let msg = format!("{}", err);
        assert!(msg.contains("2000"));
        assert!(msg.contains("1000"));

        let err = ResourceError::EncryptionSizeLimitExceeded { requested: 200, limit: 100 };
        let msg = format!("{}", err);
        assert!(msg.contains("200"));
        assert!(msg.contains("100"));

        let err = ResourceError::SignatureSizeLimitExceeded { requested: 300, limit: 256 };
        let msg = format!("{}", err);
        assert!(msg.contains("300"));
        assert!(msg.contains("256"));

        let err = ResourceError::DecryptionSizeLimitExceeded { requested: 500, limit: 400 };
        let msg = format!("{}", err);
        assert!(msg.contains("500"));
        assert!(msg.contains("400"));
    }

    #[test]
    fn test_resource_error_debug() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let debug = format!("{:?}", err);
        assert!(debug.contains("KeyDerivationLimitExceeded"));
    }

    // === Edge case: zero values ===

    #[test]
    fn test_validate_zero_values() {
        assert!(ResourceLimits::validate_key_derivation_count(0).is_ok());
        assert!(ResourceLimits::validate_encryption_size(0).is_ok());
        assert!(ResourceLimits::validate_signature_size(0).is_ok());
        assert!(ResourceLimits::validate_decryption_size(0).is_ok());
    }
}
