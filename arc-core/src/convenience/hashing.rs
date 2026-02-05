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

use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

use arc_validation::resource_limits::validate_key_derivation_count;

/// Custom output length type for aws-lc-rs HKDF
struct HkdfOutputLen(usize);

impl KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hash_parallel(data: &[u8], chunk_size: usize) -> Vec<[u8; 32]> {
    data.par_chunks(chunk_size)
        .map(|chunk| {
            let mut hasher = Sha3_256::new();
            hasher.update(chunk);
            hasher.finalize().into()
        })
        .collect()
}

#[inline]
fn hash_sha3_256(data: &[u8]) -> [u8; 32] {
    // Use parallel hashing for large data
    if data.len() > 65536 {
        let results = hash_parallel(data, 4096);
        let mut final_hasher = Sha3_256::new();
        for hash in &results {
            final_hasher.update(hash);
        }
        return final_hasher.finalize().into();
    }

    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of HKDF key derivation.
fn derive_key_hkdf(password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
    let hkdf_salt = Salt::new(HKDF_SHA256, salt);
    let prk = hkdf_salt.extract(password);

    let okm = prk
        .expand(&[b"latticearc"], HkdfOutputLen(length))
        .map_err(|_e| CoreError::KeyDerivationFailed("HKDF expansion failed".to_string()))?;

    let mut output = vec![0u8; length];
    okm.fill(&mut output)
        .map_err(|_e| CoreError::KeyDerivationFailed("HKDF fill failed".to_string()))?;

    Ok(output)
}

/// Internal implementation of key derivation.
fn derive_key_internal(password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
    crate::log_crypto_operation_start!(
        "key_derivation",
        algorithm = "HKDF-SHA256",
        output_len = length
    );

    validate_key_derivation_count(1).map_err(|e| {
        crate::log_crypto_operation_error!("key_derivation", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    if salt.is_empty() {
        let err = CoreError::InvalidInput("Salt cannot be empty".to_string());
        crate::log_crypto_operation_error!("key_derivation", err);
        return Err(err);
    }

    if length == 0 {
        let err = CoreError::InvalidInput("Length cannot be zero".to_string());
        crate::log_crypto_operation_error!("key_derivation", err);
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
            crate::log_crypto_operation_error!("key_derivation", e);
        }
    }

    result
}

/// Internal implementation of HMAC.
fn hmac_internal(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    crate::log_crypto_operation_start!("hmac", algorithm = "HMAC-SHA256", data_len = data.len());

    if key.is_empty() {
        let err = CoreError::InvalidInput("HMAC key must not be empty".to_string());
        crate::log_crypto_operation_error!("hmac", err);
        return Err(err);
    }

    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key).map_err(|e| {
        let err = CoreError::InvalidInput(format!("Invalid HMAC key: {}", e));
        crate::log_crypto_operation_error!("hmac", err);
        err
    })?;

    mac.update(data);

    let result = mac.finalize().into_bytes().to_vec();
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
        crate::log_crypto_operation_error!("hmac_verify", err);
        return Err(err);
    }

    if tag.len() != 32 {
        let err = CoreError::InvalidInput(format!("HMAC tag must be 32 bytes, got {}", tag.len()));
        crate::log_crypto_operation_error!("hmac_verify", err);
        return Err(err);
    }

    let expected = hmac_internal(key, data)?;

    let mut tag_bytes = [0u8; 32];
    tag_bytes.copy_from_slice(tag);
    let mut expected_bytes = [0u8; 32];
    expected_bytes.copy_from_slice(&expected);

    let valid: bool = tag_bytes.ct_eq(&expected_bytes).into();

    crate::log_crypto_operation_complete!("hmac_verify", algorithm = "HMAC-SHA256", valid = valid);
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

/// Derive a key from a password and salt using HKDF.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before derivation
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{derive_key, SecurityMode, VerifiedSession};
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let key = derive_key(password, salt, 32, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let key = derive_key(password, salt, 32, SecurityMode::Unverified)?;
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
    password: &[u8],
    salt: &[u8],
    length: usize,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    derive_key_internal(password, salt, length)
}

/// Compute HMAC-SHA256 of data.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before HMAC computation
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{hmac, SecurityMode, VerifiedSession};
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let tag = hmac(data, key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let tag = hmac(data, key, SecurityMode::Unverified)?;
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
/// ```rust,ignore
/// use arc_core::{hmac_check, SecurityMode, VerifiedSession};
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let is_valid = hmac_check(data, key, tag, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let is_valid = hmac_check(data, key, tag, SecurityMode::Unverified)?;
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
) -> Result<Vec<u8>> {
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
pub fn derive_key_unverified(password: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
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
pub fn hmac_unverified(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
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
pub fn hmac_check_unverified(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool> {
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
) -> Result<Vec<u8>> {
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
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]
mod tests {
    use super::*;
    use crate::{SecurityMode, VerifiedSession, generate_keypair};

    // hash_data tests
    #[test]
    fn test_hash_data_deterministic() {
        let data = b"Test data for hashing";
        let hash1 = hash_data(data);
        let hash2 = hash_data(data);
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_eq!(hash1.len(), 32, "SHA-256 hash should be 32 bytes");
    }

    #[test]
    fn test_hash_data_different_inputs() {
        let data1 = b"First message";
        let data2 = b"Second message";
        let hash1 = hash_data(data1);
        let hash2 = hash_data(data2);
        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_hash_data_empty_input() {
        let data = b"";
        let hash = hash_data(data);
        assert_eq!(hash.len(), 32, "Empty input should still produce 32-byte hash");
    }

    #[test]
    fn test_hash_data_large_input() {
        let data = vec![0xAB; 100000];
        let hash = hash_data(&data);
        assert_eq!(hash.len(), 32, "Large input should produce 32-byte hash");
    }

    // derive_key tests (unverified API)
    #[test]
    fn test_derive_key_unverified_basic() -> Result<()> {
        let password = b"strong_password";
        let salt = b"random_salt_1234";
        let key = derive_key_unverified(password, salt, 32)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_deterministic() -> Result<()> {
        let password = b"test_password";
        let salt = b"test_salt";
        let key1 = derive_key_unverified(password, salt, 32)?;
        let key2 = derive_key_unverified(password, salt, 32)?;
        assert_eq!(key1, key2, "Key derivation should be deterministic");
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_different_passwords() -> Result<()> {
        let salt = b"same_salt";
        let key1 = derive_key_unverified(b"password1", salt, 32)?;
        let key2 = derive_key_unverified(b"password2", salt, 32)?;
        assert_ne!(key1, key2, "Different passwords should produce different keys");
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_different_salts() -> Result<()> {
        let password = b"same_password";
        let key1 = derive_key_unverified(password, b"salt1", 32)?;
        let key2 = derive_key_unverified(password, b"salt2", 32)?;
        assert_ne!(key1, key2, "Different salts should produce different keys");
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_different_lengths() -> Result<()> {
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
    fn test_derive_key_with_config_unverified() -> Result<()> {
        let password = b"password";
        let salt = b"salt";
        let config = CoreConfig::default();
        let key = derive_key_with_config_unverified(password, salt, 32, &config)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    // derive_key verified API tests
    #[test]
    fn test_derive_key_verified_mode() -> Result<()> {
        let password = b"secure_password";
        let salt = b"secure_salt";
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let key = derive_key(password, salt, 32, SecurityMode::Verified(&session))?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    #[test]
    fn test_derive_key_unverified_mode() -> Result<()> {
        let password = b"password";
        let salt = b"salt";
        let key = derive_key(password, salt, 32, SecurityMode::Unverified)?;
        assert_eq!(key.len(), 32);
        Ok(())
    }

    // HMAC tests (unverified API)
    #[test]
    fn test_hmac_unverified_basic() -> Result<()> {
        let key = b"secret_key_1234567890";
        let data = b"Message to authenticate";
        let tag = hmac_unverified(key, data)?;
        assert!(!tag.is_empty());
        assert_eq!(tag.len(), 32, "HMAC-SHA256 should produce 32-byte tag");
        Ok(())
    }

    #[test]
    fn test_hmac_unverified_deterministic() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let tag1 = hmac_unverified(key, data)?;
        let tag2 = hmac_unverified(key, data)?;
        assert_eq!(tag1, tag2, "HMAC should be deterministic");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_valid() -> Result<()> {
        let key = b"authentication_key";
        let data = b"Important message";
        let tag = hmac_unverified(key, data)?;
        let is_valid = hmac_check_unverified(key, data, &tag)?;
        assert!(is_valid, "Valid HMAC should verify successfully");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_wrong_key() -> Result<()> {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"data";
        let tag = hmac_unverified(key1, data)?;
        let is_valid = hmac_check_unverified(key2, data, &tag)?;
        assert!(!is_valid, "Wrong key should fail verification");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_wrong_data() -> Result<()> {
        let key = b"key";
        let data1 = b"original data";
        let data2 = b"modified data";
        let tag = hmac_unverified(key, data1)?;
        let is_valid = hmac_check_unverified(key, data2, &tag)?;
        assert!(!is_valid, "Wrong data should fail verification");
        Ok(())
    }

    #[test]
    fn test_hmac_check_unverified_invalid_tag() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let invalid_tag = vec![0u8; 32];
        let is_valid = hmac_check_unverified(key, data, &invalid_tag)?;
        assert!(!is_valid, "Invalid tag should fail verification");
        Ok(())
    }

    // HMAC with config tests
    #[test]
    fn test_hmac_with_config_unverified() -> Result<()> {
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
    fn test_hmac_verified_mode() -> Result<()> {
        let key = b"secret_key";
        let data = b"authenticated message";
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let tag = hmac(data, key, SecurityMode::Verified(&session))?;
        let is_valid = hmac_check(data, key, &tag, SecurityMode::Verified(&session))?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_unverified_mode() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let tag = hmac(data, key, SecurityMode::Unverified)?;
        let is_valid = hmac_check(data, key, &tag, SecurityMode::Unverified)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_with_config_verified() -> Result<()> {
        let key = b"key";
        let data = b"data";
        let config = CoreConfig::default();
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let tag = hmac_with_config(data, key, &config, SecurityMode::Verified(&session))?;
        let is_valid =
            hmac_check_with_config(data, key, &tag, &config, SecurityMode::Verified(&session))?;
        assert!(is_valid);
        Ok(())
    }

    // Edge cases
    #[test]
    fn test_hmac_empty_data() -> Result<()> {
        let key = b"key";
        let data = b"";
        let tag = hmac_unverified(key, data)?;
        let is_valid = hmac_check_unverified(key, data, &tag)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_large_data() -> Result<()> {
        let key = b"key";
        let data = vec![0x42; 100000];
        let tag = hmac_unverified(key, &data)?;
        let is_valid = hmac_check_unverified(key, &data, &tag)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_hmac_different_key_lengths() -> Result<()> {
        let data = b"test data";
        let key16 = b"1234567890123456"; // 16 bytes
        let key32 = b"12345678901234567890123456789012"; // 32 bytes

        let tag16 = hmac_unverified(key16, data)?;
        let tag32 = hmac_unverified(key32, data)?;

        assert!(hmac_check_unverified(key16, data, &tag16)?);
        assert!(hmac_check_unverified(key32, data, &tag32)?);
        assert_ne!(tag16, tag32, "Different keys should produce different tags");
        Ok(())
    }
}
