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
