//! Resource limits for cryptographic operations.
//!
//! Provides configurable limits on encryption size, signature size, decryption
//! size, and key-derivation count to prevent denial-of-service via oversized
//! inputs. The limits are enforced by `aead::aes_gcm`, `aead::chacha20poly1305`,
//! `hybrid::encrypt_hybrid`, and the signature primitives before any
//! cryptographic work is performed.
//!
//! # Default limits
//!
//! | Field | Default | Rationale |
//! |---|---|---|
//! | `max_key_derivations_per_call` | `1000` | Bounds CPU per HKDF/PBKDF2 batch |
//! | `max_encryption_size_bytes` | `100 MiB` (`100 * 1024 * 1024`) | One-shot AEAD path; stream beyond this size |
//! | `max_signature_size_bytes` | `64 KiB` (`64 * 1024`) | Pre-hash signature input cap |
//! | `max_decryption_size_bytes` | `100 MiB` (`100 * 1024 * 1024`) | Symmetric to encryption cap |
//! | `max_aad_size_bytes` | `1 MiB` (`1024 * 1024`) | AEAD additional-authenticated-data cap (round-26 audit fix H8) |
//!
//! Override at runtime via [`ResourceLimitsManager::with_limits`] /
//! [`ResourceLimitsManager::update_limits`]. The `100 MiB` AEAD cap is a
//! conservative one-shot ceiling — applications that need to seal larger
//! payloads should chunk into framed records or raise the limit explicitly.

use std::sync::{Arc, LazyLock, RwLock};

/// Configurable resource limits for cryptographic operations.
///
/// See the [module documentation](self) for the default values and the
/// modules that enforce them.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum number of key derivations per single call. Default: `1000`.
    pub max_key_derivations_per_call: usize,
    /// Maximum encryption input size in bytes. Default: `100 * 1024 * 1024`
    /// (100 MiB).
    pub max_encryption_size_bytes: usize,
    /// Maximum signature input size in bytes. Default: `64 * 1024` (64 KiB).
    pub max_signature_size_bytes: usize,
    /// Maximum decryption input size in bytes. Default: `100 * 1024 * 1024`
    /// (100 MiB).
    pub max_decryption_size_bytes: usize,
    /// Maximum AEAD additional-authenticated-data (AAD) size in bytes.
    /// Default: `1024 * 1024` (1 MiB).
    ///
    /// Round-26 audit fix (H8): AEAD MACs run linear time over AAD, so an
    /// attacker-controlled AAD bypasses the plaintext/ciphertext caps and
    /// turns into a CPU-amplification DoS. The 1 MiB default is a
    /// conservative ceiling — applications that legitimately need larger
    /// AADs (rare; most protocols cap AAD in the kilobytes) should raise
    /// the limit explicitly.
    pub max_aad_size_bytes: usize,
}

impl Default for ResourceLimits {
    /// Returns the default limits documented on each field of
    /// [`ResourceLimits`] and at the [module level](self).
    fn default() -> Self {
        Self {
            max_key_derivations_per_call: 1000,
            max_encryption_size_bytes: 100 * 1024 * 1024,
            max_signature_size_bytes: 64 * 1024,
            max_decryption_size_bytes: 100 * 1024 * 1024,
            max_aad_size_bytes: 1024 * 1024,
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
            max_aad_size_bytes: 1024 * 1024,
        }
    }

    /// Creates a new `ResourceLimits` with all five fields specified
    /// explicitly. Use this when the caller cares about the AAD cap
    /// (round-26 audit fix H8); use [`Self::new`] when the default
    /// 1 MiB AAD cap is acceptable.
    #[must_use]
    pub fn with_aad_limit(
        max_key_derivations: usize,
        max_encryption_size: usize,
        max_signature_size: usize,
        max_decryption_size: usize,
        max_aad_size: usize,
    ) -> Self {
        Self {
            max_key_derivations_per_call: max_key_derivations,
            max_encryption_size_bytes: max_encryption_size,
            max_signature_size_bytes: max_signature_size,
            max_decryption_size_bytes: max_decryption_size,
            max_aad_size_bytes: max_aad_size,
        }
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
    ///
    /// # Errors
    /// Returns `ResourceError::LockPoisoned` if the internal lock was poisoned.
    pub fn get_limits(&self) -> Result<ResourceLimits> {
        self.limits.read().map(|guard| guard.clone()).map_err(|_poison| ResourceError::LockPoisoned)
    }

    /// Updates the resource limits to the specified values.
    ///
    /// # Errors
    /// Returns `ResourceError::LockPoisoned` if the internal lock was poisoned.
    pub fn update_limits(&self, limits: ResourceLimits) -> Result<()> {
        let mut guard = self.limits.write().map_err(|_poison| ResourceError::LockPoisoned)?;
        *guard = limits;
        Ok(())
    }

    /// Validates that the key derivation count does not exceed the configured limit.
    ///
    /// # Errors
    /// Returns an error if the count exceeds the maximum allowed key derivations per call.
    pub fn validate_key_derivation_count(&self, count: usize) -> Result<()> {
        let limits = self.get_limits()?;
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
        let limits = self.get_limits()?;
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
        let limits = self.get_limits()?;
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
        let limits = self.get_limits()?;
        if size > limits.max_decryption_size_bytes {
            return Err(ResourceError::DecryptionSizeLimitExceeded {
                requested: size,
                limit: limits.max_decryption_size_bytes,
            });
        }
        Ok(())
    }

    /// Validates that the AEAD AAD size does not exceed the configured limit.
    ///
    /// Round-26 audit fix (H8): AEAD MACs run linear time over the AAD,
    /// so an attacker-controlled AAD bypasses the plaintext/ciphertext
    /// caps and turns into a CPU-amplification DoS. Every AEAD encrypt
    /// and decrypt entrypoint must call this before passing AAD to the
    /// underlying primitive.
    ///
    /// # Errors
    /// Returns an error if the size exceeds the maximum allowed AAD size in bytes.
    pub fn validate_aad_size(&self, size: usize) -> Result<()> {
        let limits = self.get_limits()?;
        if size > limits.max_aad_size_bytes {
            return Err(ResourceError::AadSizeLimitExceeded {
                requested: size,
                limit: limits.max_aad_size_bytes,
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
#[non_exhaustive]
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

    /// AEAD AAD size exceeds configured limit. Round-26 audit fix (H8).
    #[error("AAD size limit exceeded: requested {requested}, limit {limit}")]
    AadSizeLimitExceeded {
        /// Size in bytes requested.
        requested: usize,
        /// Maximum allowed size in bytes.
        limit: usize,
    },

    /// Internal lock was poisoned by a panicked thread.
    #[error("Resource limits lock poisoned — a thread panicked while holding the lock")]
    LockPoisoned,
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

/// Validates AEAD AAD size against global resource limits. Round-26
/// audit fix (H8): every AEAD encrypt/decrypt entrypoint must call this
/// before passing AAD to the underlying primitive.
///
/// # Errors
/// Returns an error if the size exceeds the maximum allowed AAD size in bytes.
pub fn validate_aad_size(size: usize) -> Result<()> {
    get_global_resource_limits().validate_aad_size(size)
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // These proofs work on `ResourceLimitsManager::with_limits(...)` rather
    // than the global manager so Kani can fully model the underlying state.
    // The biconditional check (size > limit ⇔ Err) is the DoS property we
    // care about: no caller-supplied size can bypass the cap without hitting
    // the error branch.

    /// Proves `validate_encryption_size` errors exactly when input exceeds the
    /// configured limit. Closes the DoS path: no `size > limit` slips through.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_encryption_size_biconditional() {
        let size: usize = kani::any();
        let limit: usize = kani::any();
        kani::assume(limit > 0);

        let limits =
            ResourceLimits { max_encryption_size_bytes: limit, ..ResourceLimits::default() };
        let manager = ResourceLimitsManager::with_limits(limits);
        let result = manager.validate_encryption_size(size);

        if size > limit {
            kani::assert(result.is_err(), "validate_encryption_size must err when size > limit");
        } else {
            kani::assert(result.is_ok(), "validate_encryption_size must Ok when size ≤ limit");
        }
    }

    /// Same property for decryption — decryption-side caps must also fire.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_decryption_size_biconditional() {
        let size: usize = kani::any();
        let limit: usize = kani::any();
        kani::assume(limit > 0);

        let limits =
            ResourceLimits { max_decryption_size_bytes: limit, ..ResourceLimits::default() };
        let manager = ResourceLimitsManager::with_limits(limits);
        let result = manager.validate_decryption_size(size);

        if size > limit {
            kani::assert(result.is_err(), "decryption size > limit must Err");
        } else {
            kani::assert(result.is_ok(), "decryption size ≤ limit must Ok");
        }
    }

    /// Proves `validate_key_derivation_count(0)` always succeeds — the
    /// identity case (no-op callers) must not trip a DoS guard regardless
    /// of how the limit is configured.
    #[kani::proof]
    fn validate_key_derivation_count_accepts_zero() {
        let limit: usize = kani::any();
        kani::assume(limit > 0);
        let limits =
            ResourceLimits { max_key_derivations_per_call: limit, ..ResourceLimits::default() };
        let manager = ResourceLimitsManager::with_limits(limits);
        let result = manager.validate_key_derivation_count(0);
        kani::assert(result.is_ok(), "count=0 must not trip the KDF limit (any limit > 0)");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limits_default_succeeds() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_key_derivations_per_call, 1000);
        assert_eq!(limits.max_encryption_size_bytes, 100 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 64 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_resource_limits_new_succeeds() {
        let limits = ResourceLimits::new(500, 50 * 1024 * 1024, 32 * 1024, 50 * 1024 * 1024);
        assert_eq!(limits.max_key_derivations_per_call, 500);
        assert_eq!(limits.max_encryption_size_bytes, 50 * 1024 * 1024);
        assert_eq!(limits.max_signature_size_bytes, 32 * 1024);
        assert_eq!(limits.max_decryption_size_bytes, 50 * 1024 * 1024);
    }

    #[test]
    fn test_manager_with_custom_limits_succeeds() {
        let custom = ResourceLimits::new(200, 1024, 512, 2048);
        let manager = ResourceLimitsManager::with_limits(custom);
        let limits = manager.get_limits().unwrap();
        assert_eq!(limits.max_key_derivations_per_call, 200);
        assert_eq!(limits.max_encryption_size_bytes, 1024);
    }

    #[test]
    fn test_manager_update_limits_succeeds() {
        let manager = ResourceLimitsManager::new();
        assert_eq!(manager.get_limits().unwrap().max_key_derivations_per_call, 1000);

        let new_limits = ResourceLimits::new(50, 1024, 512, 2048);
        manager.update_limits(new_limits).unwrap();
        assert_eq!(manager.get_limits().unwrap().max_key_derivations_per_call, 50);
    }

    #[test]
    fn test_manager_validate_methods_succeeds() {
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
    fn test_global_validate_functions_succeeds() {
        assert!(validate_key_derivation_count(500).is_ok());
        assert!(validate_key_derivation_count(1001).is_err());
        assert!(validate_encryption_size(1024).is_ok());
        assert!(validate_signature_size(1024).is_ok());
        assert!(validate_decryption_size(1024).is_ok());
    }

    #[test]
    fn test_resource_error_display_fails() {
        let err = ResourceError::KeyDerivationLimitExceeded { requested: 2000, limit: 1000 };
        let msg = format!("{}", err);
        assert!(msg.contains("2000"));
        assert!(msg.contains("1000"));
    }

    /// Forced-poison test: confirms that when the inner `RwLock` is poisoned
    /// (a thread panicked while holding the lock), every public method on
    /// `ResourceLimitsManager` returns `ResourceError::LockPoisoned` rather
    /// than panicking, propagating the wrong error, or returning incorrect
    /// data.
    #[test]
    fn test_resource_limits_manager_returns_lock_poisoned_after_panic() {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        use std::sync::Arc;
        use std::thread;

        let manager = Arc::new(ResourceLimitsManager::new());

        // The lock is poisoned during stack unwinding: when the panic begins,
        // `_guard` drops while `std::thread::panicking()` is still true, which
        // sets the poison flag. `catch_unwind` only absorbs the panic *after*
        // that drop, so `join()` returns `Ok(())` instead of propagating —
        // keeping the test's failure mode focused on the assertions below.
        let manager_clone = Arc::clone(&manager);
        let join = thread::spawn(move || {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let _guard = manager_clone.limits.write().expect("acquire write lock");
                panic!("intentional panic to poison the lock");
            }));
        });
        join.join().expect("poisoning thread joined");

        // Every public method that touches the lock must surface LockPoisoned.
        match manager.get_limits() {
            Err(ResourceError::LockPoisoned) => {}
            other => panic!("get_limits() expected LockPoisoned, got {other:?}"),
        }
        match manager.update_limits(ResourceLimits::default()) {
            Err(ResourceError::LockPoisoned) => {}
            other => panic!("update_limits() expected LockPoisoned, got {other:?}"),
        }
        match manager.validate_key_derivation_count(1) {
            Err(ResourceError::LockPoisoned) => {}
            other => panic!("validate_key_derivation_count expected LockPoisoned, got {other:?}"),
        }
        match manager.validate_encryption_size(1) {
            Err(ResourceError::LockPoisoned) => {}
            other => panic!("validate_encryption_size expected LockPoisoned, got {other:?}"),
        }
        match manager.validate_signature_size(1) {
            Err(ResourceError::LockPoisoned) => {}
            other => panic!("validate_signature_size expected LockPoisoned, got {other:?}"),
        }
        match manager.validate_decryption_size(1) {
            Err(ResourceError::LockPoisoned) => {}
            other => panic!("validate_decryption_size expected LockPoisoned, got {other:?}"),
        }
    }
}
