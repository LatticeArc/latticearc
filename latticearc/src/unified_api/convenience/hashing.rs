//! Hashing, HMAC, and key derivation operations
//!
//! This module provides cryptographic hashing, HMAC, and key derivation functions.
//!
//! ## Zero Trust Enforcement
//!
//! HMAC and key derivation functions use `SecurityMode` to specify verification behavior:
//! - `SecurityMode::Verified(&session)`: Validates session before operation
//! - `SecurityMode::Unverified`: Skips session validation
//!
//! Hash functions are stateless and don't require a security mode.
//!
//! For opt-out scenarios where Zero Trust verification is not required or not possible,
//! use the `_unverified` variants.

use tracing::debug;

use subtle::ConstantTimeEq;

use crate::log_crypto_operation_error;
use crate::primitives::hash::sha3::sha3_256 as hash_sha3_256;
use crate::primitives::mac::hmac::hmac_sha256;
// the previous `validate_key_derivation_count(1)`
// no-op was removed (passing `1` to a per-call cap is structurally
// useless — it always succeeds whenever the global limit is ≥1). The
// real DoS bound on this path is enforced by `validate_signature_size`
// at the AEAD/KDF entrypoints upstream. The import is no longer needed
// at this site; a future per-process derivation counter would re-import
// it from `resource_limits`.
use crate::unified_api::CoreConfig;
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::logging::op;
use crate::unified_api::zero_trust::SecurityMode;

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of HKDF key derivation.
///
/// Returns `Zeroizing<Vec<u8>>` so the derived key material is wiped on
/// drop. The previous `Vec<u8>` return left the caller's copy as plain
/// heap memory; with `Zeroizing` the wipe happens automatically once the
/// caller's binding goes out of scope.
fn derive_key_hkdf(
    password: &[u8],
    salt: &[u8],
    length: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let result = crate::primitives::kdf::hkdf::hkdf(
        password,
        Some(salt),
        Some(crate::types::domains::DERIVE_KEY_INFO),
        length,
    )
    .map_err(|e| CoreError::KeyDerivationFailed(format!("HKDF failed: {e}")))?;
    // consume the HkdfResult via
    // `into_zeroizing` so we don't allocate an un-zeroed transient
    // `Vec<u8>` between the `expose_secret().to_vec()` and the
    // re-wrap.
    Ok(result.into_zeroizing())
}

/// Internal implementation of HKDF key derivation with caller-supplied info string.
fn derive_key_hkdf_with_info(
    password: &[u8],
    salt: &[u8],
    length: usize,
    info: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let result = crate::primitives::kdf::hkdf::hkdf(password, Some(salt), Some(info), length)
        .map_err(|e| CoreError::KeyDerivationFailed(format!("HKDF failed: {e}")))?;
    // consume the HkdfResult via
    // `into_zeroizing` so we don't allocate an un-zeroed transient
    // `Vec<u8>` between the `expose_secret().to_vec()` and the
    // re-wrap.
    Ok(result.into_zeroizing())
}

/// Internal implementation of key derivation with caller-supplied info string.
fn derive_key_with_info_internal(
    password: &[u8],
    salt: &[u8],
    length: usize,
    info: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    crate::log_crypto_operation_start!(
        "key_derivation_info",
        algorithm = "HKDF-SHA256",
        output_len = length,
        info_len = info.len()
    );

    // per-call no-op `validate_key_derivation_count(1)`
    // removed. See module-level comment.

    if salt.is_empty() {
        let err = CoreError::InvalidInput("Salt cannot be empty".to_string());
        log_crypto_operation_error!(op::KEY_DERIVATION_INFO, err);
        return Err(err);
    }

    if length == 0 {
        let err = CoreError::InvalidInput("Length cannot be zero".to_string());
        log_crypto_operation_error!(op::KEY_DERIVATION_INFO, err);
        return Err(err);
    }

    if info.is_empty() {
        let err = CoreError::InvalidInput("Info string cannot be empty".to_string());
        log_crypto_operation_error!(op::KEY_DERIVATION_INFO, err);
        return Err(err);
    }

    let result = derive_key_hkdf_with_info(password, salt, length, info);

    match &result {
        Ok(_) => {
            crate::log_crypto_operation_complete!(
                "key_derivation_info",
                algorithm = "HKDF-SHA256",
                output_len = length
            );
            debug!(
                algorithm = "HKDF-SHA256",
                output_len = length,
                info_len = info.len(),
                "Key derivation with custom info completed"
            );
        }
        Err(e) => {
            log_crypto_operation_error!(op::KEY_DERIVATION_INFO, e);
        }
    }

    result
}

/// Internal implementation of key derivation.
fn derive_key_internal(
    password: &[u8],
    salt: &[u8],
    length: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    crate::log_crypto_operation_start!(
        "key_derivation",
        algorithm = "HKDF-SHA256",
        output_len = length
    );

    // per-call no-op removed. See M23 note above.

    if salt.is_empty() {
        let err = CoreError::InvalidInput("Salt cannot be empty".to_string());
        log_crypto_operation_error!(op::KEY_DERIVATION, err);
        return Err(err);
    }

    if length == 0 {
        let err = CoreError::InvalidInput("Length cannot be zero".to_string());
        log_crypto_operation_error!(op::KEY_DERIVATION, err);
        return Err(err);
    }

    let result = derive_key_hkdf(password, salt, length);

    match &result {
        Ok(_) => {
            crate::log_crypto_operation_complete!(
                "key_derivation",
                algorithm = "HKDF-SHA256",
                output_len = length
            );
            debug!(algorithm = "HKDF-SHA256", output_len = length, "Key derivation completed");
        }
        Err(e) => {
            log_crypto_operation_error!(op::KEY_DERIVATION, e);
        }
    }

    result
}

/// Internal implementation of HMAC.
fn hmac_internal(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    crate::log_crypto_operation_start!(op::HMAC, algorithm = "HMAC-SHA256", data_len = data.len());

    if key.is_empty() {
        let err = CoreError::InvalidInput("HMAC key must not be empty".to_string());
        log_crypto_operation_error!(op::HMAC, err);
        return Err(err);
    }

    // Delegate to primitives::mac::hmac (backed by aws-lc-rs HMAC-SHA256).
    let tag = hmac_sha256(key, data).map_err(|e| {
        let err = CoreError::InvalidInput(format!("HMAC computation failed: {e}"));
        log_crypto_operation_error!(op::HMAC, err);
        err
    })?;
    let result = tag.to_vec();
    crate::log_crypto_operation_complete!(
        "hmac",
        algorithm = "HMAC-SHA256",
        tag_len = result.len()
    );
    debug!(algorithm = "HMAC-SHA256", data_len = data.len(), "HMAC computed");

    Ok(result)
}

/// Internal implementation of HMAC verification.
fn hmac_verify_internal(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool> {
    crate::log_crypto_operation_start!(
        "hmac_verify",
        algorithm = "HMAC-SHA256",
        data_len = data.len()
    );

    if key.is_empty() {
        let err = CoreError::InvalidInput("HMAC key must not be empty".to_string());
        log_crypto_operation_error!(op::HMAC_VERIFY, err);
        return Err(err);
    }

    if tag.len() != 32 {
        let err = CoreError::InvalidInput(format!("HMAC tag must be 32 bytes, got {}", tag.len()));
        log_crypto_operation_error!(op::HMAC_VERIFY, err);
        return Err(err);
    }

    let expected = hmac_internal(key, data)?;

    // Compare slices directly via `ConstantTimeEq`, which works on
    // `&[u8]` without copying into fixed-size arrays. The previous
    // shape used `[u8; 32]::copy_from_slice(...)`, which panics on
    // length mismatch — even though both lengths are statically
    // guaranteed here (tag was validated to be 32 bytes above; expected
    // is HMAC-SHA256's 32-byte output), it's a latent panic path in a
    // function with `panic_in_result_fn = "deny"` lints. Removing the
    // copies removes both the lint risk and the small heap-write cost.
    let valid: bool = tag.ct_eq(expected.as_slice()).into();

    crate::log_crypto_operation_complete!(
        op::HMAC_VERIFY,
        algorithm = "HMAC-SHA256",
        valid = valid
    );
    debug!(algorithm = "HMAC-SHA256", valid = valid, "HMAC verification completed");

    Ok(valid)
}

// ============================================================================
// Hash Functions (Stateless - No Session Required)
// ============================================================================

/// Hash data using SHA3-256.
///
/// This function is infallible and returns the computed hash directly.
/// Hash operations are stateless and don't require a verified session.
#[inline]
#[must_use]
pub fn hash_data(data: &[u8]) -> [u8; 32] {
    debug!(algorithm = "SHA3-256", data_len = data.len(), "Hashing data");
    let result = hash_sha3_256(data);
    debug!(algorithm = "SHA3-256", "Hash completed");
    result
}

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

/// Derive a key from high-entropy input keying material using HKDF-SHA256
/// (RFC 5869 / SP 800-56C).
///
/// # Do NOT use this for passwords
///
/// HKDF is designed for *high-entropy* inputs: Diffie-Hellman shared secrets,
/// raw random bytes from a CSPRNG, output of another KEM, and so on. It
/// performs **no work factor** and provides **zero brute-force resistance**
/// against low-entropy inputs. Passing a user passphrase here gives an
/// attacker who steals the ciphertext a line-rate password oracle.
///
/// For password-based key derivation, use
/// [`crate::primitives::kdf::pbkdf2::pbkdf2`] with at least 600,000 iterations
/// of HMAC-SHA256 (OWASP 2023 recommendation) and a **fresh per-user random
/// salt** stored alongside the ciphertext. A complete worked example lives in
/// `examples/complete_secure_workflow.rs`.
///
/// The `ikm` parameter is named as such to make this contract explicit — it
/// is *input keying material*, not a password.
///
/// # Security modes
///
/// - `SecurityMode::Verified(&session)`: Validates the session before derivation
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example (HKDF with a DH shared secret — correct use)
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{derive_key, SecurityMode};
/// // `shared_secret` is e.g. the output of X25519 or ML-KEM — high entropy.
/// # let shared_secret = [0u8; 32];
/// # let salt = [0u8; 16]; // per-session random salt, optional
/// let key = derive_key(&shared_secret, &salt, 32, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The resource limit for key derivation operations is exceeded
/// - The salt is empty
/// - The requested length is zero
/// - The HKDF expansion operation fails
pub fn derive_key(
    ikm: &[u8],
    salt: &[u8],
    length: usize,
    mode: SecurityMode,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    mode.validate()?;
    derive_key_internal(ikm, salt, length)
}

/// Compute HMAC-SHA256 of data.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before HMAC computation
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{hmac, SecurityMode, VerifiedSession};
/// # let data = b"data";
/// # let key = b"key";
/// # let pk = [0u8; 32];
/// # let sk = [0u8; 32];
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let tag = hmac(data, key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let tag = hmac(data, key, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The HMAC key is empty
#[inline]
pub fn hmac(data: &[u8], key: &[u8], mode: SecurityMode) -> Result<Vec<u8>> {
    mode.validate()?;
    hmac_internal(key, data)
}

/// Check HMAC-SHA256 tag in constant time.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before HMAC verification
/// - `SecurityMode::Unverified`: Skips session validation
///
/// The function name uses "check" rather than "verify" to avoid confusion with
/// the Zero Trust `_unverified` suffix pattern.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{hmac_check, SecurityMode, VerifiedSession};
/// # let data = b"data";
/// # let key = b"key";
/// # let tag = &[0u8; 32];
/// # let pk = [0u8; 32];
/// # let sk = [0u8; 32];
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let is_valid = hmac_check(data, key, tag, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let is_valid = hmac_check(data, key, tag, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The HMAC key is empty
/// - The tag is not exactly 32 bytes
#[inline]
pub fn hmac_check(data: &[u8], key: &[u8], tag: &[u8], mode: SecurityMode) -> Result<bool> {
    mode.validate()?;
    hmac_verify_internal(key, data, tag)
}

/// Derive a key from a password and salt using HKDF with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The configuration validation fails
/// - The salt is empty or length is zero
/// - The HKDF expansion operation fails
pub fn derive_key_with_config(
    password: &[u8],
    salt: &[u8],
    length: usize,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    mode.validate()?;
    config.validate()?;
    derive_key_internal(password, salt, length)
}

/// Compute HMAC-SHA256 of data with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The configuration validation fails
/// - The HMAC key is empty
#[inline]
pub fn hmac_with_config(
    data: &[u8],
    key: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    hmac_internal(key, data)
}

/// Check HMAC-SHA256 tag in constant time with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The configuration validation fails
/// - The HMAC key is empty or tag is invalid
#[inline]
pub fn hmac_check_with_config(
    data: &[u8],
    key: &[u8],
    tag: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    config.validate()?;
    hmac_verify_internal(key, data, tag)
}

// ============================================================================
// Unverified API (Opt-Out Functions)
// ============================================================================
// These functions are for scenarios where Zero Trust verification is not required or not possible.

/// Derive a key using HKDF-SHA256 with a caller-supplied info string for domain separation.
///
/// This function is identical to [`derive_key`] except that the HKDF expansion
/// step uses the caller-provided `info` parameter instead of the library default.
/// Different `info` values produce different keys from the same input keying
/// material, enabling safe domain separation across multiple derivation contexts.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The resource limit for key derivation operations is exceeded
/// - The salt is empty
/// - The requested length is zero
/// - The info string is empty
/// - The HKDF expansion operation fails
pub fn derive_key_with_info(
    password: &[u8],
    salt: &[u8],
    length: usize,
    info: &[u8],
    mode: SecurityMode,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    mode.validate()?;
    derive_key_with_info_internal(password, salt, length, info)
}

// ============================================================================
// Unverified API (Opt-Out) — see `convenience::mod` docs for the shared
// security guidance on when to use `_unverified` variants.
// ============================================================================

/// Derive a key using HKDF-SHA256 with a caller-supplied info string without
/// Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The resource limit for key derivation operations is exceeded
/// - The salt is empty
/// - The requested length is zero
/// - The info string is empty
/// - The HKDF expansion operation fails
pub fn derive_key_with_info_unverified(
    password: &[u8],
    salt: &[u8],
    length: usize,
    info: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    derive_key_with_info(password, salt, length, info, SecurityMode::Unverified)
}

/// Derive a key from a password and salt using HKDF without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The resource limit for key derivation operations is exceeded
/// - The salt is empty
/// - The requested length is zero
/// - The HKDF expansion operation fails
pub fn derive_key_unverified(
    password: &[u8],
    salt: &[u8],
    length: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    derive_key(password, salt, length, SecurityMode::Unverified)
}

/// Compute HMAC-SHA256 of data without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The HMAC key is empty
#[inline]
pub fn hmac_unverified(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    hmac(data, key, SecurityMode::Unverified)
}

/// Check HMAC-SHA256 tag in constant time without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The HMAC key is empty
/// - The tag is not exactly 32 bytes
#[inline]
pub fn hmac_check_unverified(data: &[u8], key: &[u8], tag: &[u8]) -> Result<bool> {
    hmac_check(data, key, tag, SecurityMode::Unverified)
}

/// Derive a key with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The salt is empty or length is zero
/// - The HKDF expansion operation fails
pub fn derive_key_with_config_unverified(
    password: &[u8],
    salt: &[u8],
    length: usize,
    config: &CoreConfig,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    derive_key_with_config(password, salt, length, config, SecurityMode::Unverified)
}

/// Compute HMAC-SHA256 with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The HMAC key is empty
#[inline]
pub fn hmac_with_config_unverified(
    key: &[u8],
    data: &[u8],
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    hmac_with_config(data, key, config, SecurityMode::Unverified)
}

/// Check HMAC-SHA256 with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The HMAC key is empty or tag is invalid
#[inline]
pub fn hmac_check_with_config_unverified(
    key: &[u8],
    data: &[u8],
    tag: &[u8],
    config: &CoreConfig,
) -> Result<bool> {
    hmac_check_with_config(data, key, tag, config, SecurityMode::Unverified)
}

#[cfg(test)]
#[expect(
    clippy::panic,
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    reason = "test/bench scaffolding: lints suppressed for this module"
)]
mod tests {
    use super::*;
    use crate::{SecurityMode, VerifiedSession, generate_keypair};

    // hash_data tests
    #[test]
    fn test_hash_data_deterministic_returns_same_hash_is_deterministic() {
        let data = b"Test data for hashing";
        let hash1 = hash_data(data);
        let hash2 = hash_data(data);
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_eq!(hash1.len(), 32, "SHA-256 hash should be 32 bytes");
    }

    #[test]
    fn test_hash_data_different_inputs_produce_distinct_hashes_are_unique() {
        let data1 = b"First message";
        let data2 = b"Second message";
        let hash1 = hash_data(data1);
        let hash2 = hash_data(data2);
        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_hash_data_empty_input_returns_32_byte_hash_fails() {
        let data = b"";
        let hash = hash_data(data);
        assert_eq!(hash.len(), 32, "Empty input should still produce 32-byte hash");
    }

    #[test]
    fn test_hash_data_large_input_returns_32_byte_hash_succeeds() {
        let data = vec![0xAB; 100000];
        let hash = hash_data(&data);
        assert_eq!(hash.len(), 32, "Large input should produce 32-byte hash");
    }

    // derive_key tests (unverified API)
    #[test]
    fn test_derive_key_unverified_basic_returns_correct_length_has_correct_size() -> Result<()> {
        let password = b"strong_password";
        let salt = b"random_salt_1234";
        let key = derive_key_unverified(password, salt, 32)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_deterministic_returns_same_key_is_deterministic() -> Result<()> {
        let password = b"test_password";
        let salt = b"test_salt";
        let key1 = derive_key_unverified(password, salt, 32)?;
        let key2 = derive_key_unverified(password, salt, 32)?;
        assert_eq!(key1, key2, "Key derivation should be deterministic");
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_different_passwords_produce_distinct_keys_are_unique()
    -> Result<()> {
        let salt = b"same_salt";
        let key1 = derive_key_unverified(b"password1", salt, 32)?;
        let key2 = derive_key_unverified(b"password2", salt, 32)?;
        assert_ne!(key1, key2, "Different passwords should produce different keys");
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_different_salts_produce_distinct_keys_are_unique() -> Result<()> {
        let password = b"same_password";
        let key1 = derive_key_unverified(password, b"salt1", 32)?;
        let key2 = derive_key_unverified(password, b"salt2", 32)?;
        assert_ne!(key1, key2, "Different salts should produce different keys");
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_different_lengths_return_correct_sizes_has_correct_size()
    -> Result<()> {
        let password = b"password";
        let salt = b"salt";
        let key16 = derive_key_unverified(password, salt, 16)?;
        let key32 = derive_key_unverified(password, salt, 32)?;
        let key64 = derive_key_unverified(password, salt, 64)?;
        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);
        Ok(())
    }

    // derive_key with config tests
    #[test]
    fn test_derive_key_with_config_unverified_succeeds() -> Result<()> {
        let password = b"password";
        let salt = b"salt";
        let config = CoreConfig::default();
        let key = derive_key_with_config_unverified(password, salt, 32, &config)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    // derive_key verified API tests
    #[test]
    fn test_derive_key_verified_mode_succeeds() -> Result<()> {
        let password = b"secure_password";
        let salt = b"secure_salt";
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let key = derive_key(password, salt, 32, SecurityMode::Verified(&session))?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_mode_succeeds() -> Result<()> {
        let password = b"password";
        let salt = b"salt";
        let key = derive_key(password, salt, 32, SecurityMode::Unverified)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    // HMAC tests (unverified API)
    #[test]
    fn test_hmac_unverified_basic_returns_32_byte_tag_succeeds() -> Result<()> {
        let key = b"secret_key_1234567890";
        let data = b"Message to authenticate";
        let tag = hmac_unverified(data, key)?;
        assert!(!tag.is_empty());
        assert_eq!(tag.len(), 32, "HMAC-SHA256 should produce 32-byte tag");
        Ok(())
    }

    #[test]
    fn test_hmac_unverified_deterministic_returns_same_tag_is_deterministic() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let tag1 = hmac_unverified(data, key)?;
        let tag2 = hmac_unverified(data, key)?;
        assert_eq!(tag1, tag2, "HMAC should be deterministic");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_valid_succeeds() -> Result<()> {
        let key = b"authentication_key";
        let data = b"Important message";
        let tag = hmac_unverified(data, key)?;
        let is_valid = hmac_check_unverified(data, key, &tag)?;
        assert!(is_valid, "Valid HMAC should verify successfully");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_wrong_key_returns_false_fails() -> Result<()> {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"data";
        let tag = hmac_unverified(data, key1)?;
        let is_valid = hmac_check_unverified(data, key2, &tag)?;
        assert!(!is_valid, "Wrong key should fail verification");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_wrong_data_returns_false_fails() -> Result<()> {
        let key = b"key";
        let data1 = b"original data";
        let data2 = b"modified data";
        let tag = hmac_unverified(data1, key)?;
        let is_valid = hmac_check_unverified(data2, key, &tag)?;
        assert!(!is_valid, "Wrong data should fail verification");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_invalid_tag_returns_false_fails() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let invalid_tag = vec![0u8; 32];
        let is_valid = hmac_check_unverified(data, key, &invalid_tag)?;
        assert!(!is_valid, "Invalid tag should fail verification");
        Ok(())
    }

    // HMAC with config tests
    #[test]
    fn test_hmac_with_config_unverified_succeeds() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let config = CoreConfig::default();
        let tag = hmac_with_config_unverified(data, key, &config)?;
        let is_valid = hmac_check_with_config_unverified(data, key, &tag, &config)?;
        assert!(is_valid);
        Ok(())
    }

    // HMAC verified API tests
    #[test]
    fn test_hmac_verified_mode_succeeds() -> Result<()> {
        let key = b"secret_key";
        let data = b"authenticated message";
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let tag = hmac(data, key, SecurityMode::Verified(&session))?;
        let is_valid = hmac_check(data, key, &tag, SecurityMode::Verified(&session))?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_unverified_mode_succeeds() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let tag = hmac(data, key, SecurityMode::Unverified)?;
        let is_valid = hmac_check(data, key, &tag, SecurityMode::Unverified)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_with_config_verified_succeeds() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let config = CoreConfig::default();
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let tag = hmac_with_config(data, key, &config, SecurityMode::Verified(&session))?;
        let is_valid =
            hmac_check_with_config(data, key, &tag, &config, SecurityMode::Verified(&session))?;
        assert!(is_valid);
        Ok(())
    }

    // Error path tests
    #[test]
    fn test_derive_key_empty_salt_fails() {
        let result = derive_key_unverified(b"password", b"", 32);
        assert!(result.is_err(), "Empty salt should fail");
        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => assert!(msg.contains("Salt")),
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_derive_key_zero_length_fails() {
        let result = derive_key_unverified(b"password", b"salt", 0);
        assert!(result.is_err(), "Zero length should fail");
        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => assert!(msg.contains("Length")),
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_hmac_empty_key_fails() {
        let result = hmac_unverified(b"data", &[]);
        assert!(result.is_err(), "Empty HMAC key should fail");
        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => assert!(msg.contains("key")),
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_hmac_check_wrong_tag_length_fails() {
        let result = hmac_check_unverified(b"data", b"key", &[0u8; 16]);
        assert!(result.is_err(), "Wrong tag length should fail");
        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => assert!(msg.contains("32 bytes")),
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_hmac_check_empty_key_fails() {
        let result = hmac_check_unverified(b"data", &[], &[0u8; 32]);
        assert!(result.is_err(), "Empty key for HMAC check should fail");
    }

    // Derive key with config + verified session
    #[test]
    fn test_derive_key_with_config_verified_succeeds() -> Result<()> {
        let password = b"password";
        let salt = b"salt";
        let config = CoreConfig::default();
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let key =
            derive_key_with_config(password, salt, 32, &config, SecurityMode::Verified(&session))?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    // HMAC check with config + unverified (covers _with_config_unverified for hmac_check)
    #[test]
    fn test_hmac_check_with_config_unverified_roundtrip() -> Result<()> {
        let key = b"test_key";
        let data = b"important data";
        let config = CoreConfig::default();

        let tag = hmac_with_config_unverified(data, key, &config)?;
        let valid = hmac_check_with_config_unverified(data, key, &tag, &config)?;
        assert!(valid);

        // Wrong data should fail
        let valid = hmac_check_with_config_unverified(b"wrong data", key, &tag, &config)?;
        assert!(!valid);
        Ok(())
    }

    // ================================================================
    // derive_key_with_info tests
    // ================================================================

    #[test]
    fn test_derive_key_with_info_basic_succeeds() -> Result<()> {
        let password = b"ikm-material";
        let salt = b"random-salt";
        let info = b"my-application-context";
        let key = derive_key_with_info_unverified(password, salt, 32, info)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_derive_key_with_info_deterministic() -> Result<()> {
        let password = b"test-ikm";
        let salt = b"test-salt";
        let info = b"test-info";
        let key1 = derive_key_with_info_unverified(password, salt, 32, info)?;
        let key2 = derive_key_with_info_unverified(password, salt, 32, info)?;
        assert_eq!(key1, key2, "Same inputs must produce same key");
        Ok(())
    }

    #[test]
    fn test_derive_key_with_info_different_info_succeeds() -> Result<()> {
        let password = b"same-ikm";
        let salt = b"same-salt";
        let key_a = derive_key_with_info_unverified(password, salt, 32, b"context-a")?;
        let key_b = derive_key_with_info_unverified(password, salt, 32, b"context-b")?;
        assert_ne!(key_a, key_b, "Different info strings must produce different keys");
        Ok(())
    }

    #[test]
    fn test_derive_key_with_info_vs_standard_succeeds() -> Result<()> {
        let password = b"shared-ikm";
        let salt = b"shared-salt";
        // Using the library's default info string should match derive_key
        let via_info = derive_key_with_info_unverified(
            password,
            salt,
            32,
            crate::types::domains::DERIVE_KEY_INFO,
        )?;
        let via_standard = derive_key_unverified(password, salt, 32)?;
        assert_eq!(via_info, via_standard, "DERIVE_KEY_INFO must match derive_key output");
        Ok(())
    }

    #[test]
    fn test_derive_key_with_info_empty_info_fails() {
        let result = derive_key_with_info_unverified(b"ikm", b"salt", 32, b"");
        assert!(result.is_err(), "Empty info string should fail");
        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => assert!(msg.contains("Info")),
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    #[test]
    fn test_derive_key_with_info_verified_session_succeeds() -> Result<()> {
        let password = b"ikm";
        let salt = b"salt";
        let info = b"verified-context";
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let key = derive_key_with_info(password, salt, 32, info, SecurityMode::Verified(&session))?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    // Hash parallel path (data > 65536 bytes)
    #[test]
    fn test_hash_data_parallel_path_is_deterministic() {
        let data = vec![0xAB; 70000]; // > 65536 to trigger parallel path
        let hash1 = hash_data(&data);
        let hash2 = hash_data(&data);
        assert_eq!(hash1, hash2, "Parallel hash should be deterministic");
        assert_eq!(hash1.len(), 32);
    }

    // Edge cases
    #[test]
    fn test_hmac_empty_data_succeeds() -> Result<()> {
        let key = b"key";
        let data = b"";
        let tag = hmac_unverified(data, key)?;
        let is_valid = hmac_check_unverified(data, key, &tag)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_large_data_succeeds() -> Result<()> {
        let key = b"key";
        let data = vec![0x42; 100000];
        let tag = hmac_unverified(&data, key)?;
        let is_valid = hmac_check_unverified(&data, key, &tag)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_different_key_lengths_produce_distinct_tags_has_correct_size() -> Result<()> {
        let data = b"test data";
        let key16 = b"1234567890123456"; // 16 bytes
        let key32 = b"12345678901234567890123456789012"; // 32 bytes

        let tag16 = hmac_unverified(data, key16)?;
        let tag32 = hmac_unverified(data, key32)?;

        assert!(hmac_check_unverified(data, key16, &tag16)?);
        assert!(hmac_check_unverified(data, key32, &tag32)?);
        assert_ne!(tag16, tag32, "Different keys should produce different tags");
        Ok(())
    }
}
