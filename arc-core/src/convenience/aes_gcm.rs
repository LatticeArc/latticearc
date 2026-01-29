//! AES-GCM symmetric encryption operations
//!
//! This module provides AES-256-GCM authenticated encryption.
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! ```rust,ignore
//! use arc_core::{encrypt_aes_gcm, SecurityMode, VerifiedSession};
//!
//! // With Zero Trust verification (recommended)
//! let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Verified(&session))?;
//!
//! // Without verification (opt-out)
//! let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Unverified)?;
//! ```

use crate::{
    log_crypto_operation_complete, log_crypto_operation_error, log_crypto_operation_start,
};
use tracing::debug;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use rand_core::RngCore;

use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of AES-GCM encryption.
pub(crate) fn encrypt_aes_gcm_internal(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    log_crypto_operation_start!(
        "aes_gcm_encrypt",
        algorithm = "AES-256-GCM",
        data_len = data.len()
    );

    if key.len() < 32 {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: key.len() };
        log_crypto_operation_error!("aes_gcm_encrypt", err);
        return Err(err);
    }

    let key_bytes: [u8; 32] = key
        .get(..32)
        .ok_or_else(|| {
            let err = CoreError::InvalidInput("Key must be at least 32 bytes".to_string());
            log_crypto_operation_error!("aes_gcm_encrypt", err);
            err
        })?
        .try_into()
        .map_err(|_e| {
            let err = CoreError::InvalidInput("Key must be exactly 32 bytes".to_string());
            log_crypto_operation_error!("aes_gcm_encrypt", err);
            err
        })?;

    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_e| {
        let err = CoreError::EncryptionFailed("Failed to create AES key".to_string());
        log_crypto_operation_error!("aes_gcm_encrypt", err);
        err
    })?;
    let aes_key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().try_fill_bytes(&mut nonce_bytes).map_err(|_e| {
        let err = CoreError::EncryptionFailed("Failed to generate random nonce".to_string());
        log_crypto_operation_error!("aes_gcm_encrypt", err);
        err
    })?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = data.to_vec();
    aes_key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext).map_err(|e| {
        let err = CoreError::EncryptionFailed(e.to_string());
        log_crypto_operation_error!("aes_gcm_encrypt", err);
        err
    })?;

    let mut result = nonce_bytes.to_vec();
    result.append(&mut ciphertext);

    log_crypto_operation_complete!(
        "aes_gcm_encrypt",
        algorithm = "AES-256-GCM",
        ciphertext_len = result.len()
    );
    debug!(
        data_len = data.len(),
        ciphertext_len = result.len(),
        "AES-256-GCM encryption completed"
    );

    Ok(result)
}

/// Internal implementation of AES-GCM decryption.
pub(crate) fn decrypt_aes_gcm_internal(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    log_crypto_operation_start!(
        "aes_gcm_decrypt",
        algorithm = "AES-256-GCM",
        encrypted_len = encrypted_data.len()
    );

    if encrypted_data.len() < 12 {
        let err = CoreError::InvalidInput("Data too short".to_string());
        log_crypto_operation_error!("aes_gcm_decrypt", err);
        return Err(err);
    }

    if key.len() < 32 {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: key.len() };
        log_crypto_operation_error!("aes_gcm_decrypt", err);
        return Err(err);
    }

    let key_bytes: [u8; 32] = key
        .get(..32)
        .ok_or_else(|| {
            let err = CoreError::InvalidInput("Key must be at least 32 bytes".to_string());
            log_crypto_operation_error!("aes_gcm_decrypt", err);
            err
        })?
        .try_into()
        .map_err(|_e| {
            let err = CoreError::InvalidInput("Key must be exactly 32 bytes".to_string());
            log_crypto_operation_error!("aes_gcm_decrypt", err);
            err
        })?;

    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_e| {
        let err = CoreError::DecryptionFailed("Failed to create AES key".to_string());
        log_crypto_operation_error!("aes_gcm_decrypt", err);
        err
    })?;
    let aes_key = LessSafeKey::new(unbound);

    let (nonce_slice, ciphertext) = encrypted_data.split_at(12);
    let nonce_bytes: [u8; 12] = nonce_slice.try_into().map_err(|_e| {
        let err = CoreError::InvalidNonce("Nonce must be 12 bytes".to_string());
        log_crypto_operation_error!("aes_gcm_decrypt", err);
        err
    })?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = ciphertext.to_vec();
    let plaintext = aes_key.open_in_place(nonce, Aad::empty(), &mut in_out).map_err(|e| {
        let err = CoreError::DecryptionFailed(e.to_string());
        log_crypto_operation_error!("aes_gcm_decrypt", err);
        err
    })?;

    let result = plaintext.to_vec();
    log_crypto_operation_complete!(
        "aes_gcm_decrypt",
        algorithm = "AES-256-GCM",
        plaintext_len = result.len()
    );
    debug!(
        encrypted_len = encrypted_data.len(),
        plaintext_len = result.len(),
        "AES-256-GCM decryption completed"
    );

    Ok(result)
}

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

/// Encrypt data using AES-256-GCM with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before encryption
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{encrypt_aes_gcm, SecurityMode, VerifiedSession};
///
/// // With Zero Trust verification (recommended)
/// let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Unverified)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The key length is less than 32 bytes
/// - Random nonce generation fails
/// - The encryption operation fails
#[inline]
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8], mode: SecurityMode) -> Result<Vec<u8>> {
    mode.validate()?;
    encrypt_aes_gcm_internal(data, key)
}

/// Decrypt data using AES-256-GCM with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before decryption
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{decrypt_aes_gcm, SecurityMode, VerifiedSession};
///
/// // With Zero Trust verification (recommended)
/// let decrypted = decrypt_aes_gcm(&encrypted, &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let decrypted = decrypt_aes_gcm(&encrypted, &key, SecurityMode::Unverified)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The encrypted data is shorter than 12 bytes (nonce size)
/// - The key length is less than 32 bytes
/// - The decryption operation fails (e.g., authentication tag mismatch)
#[inline]
pub fn decrypt_aes_gcm(encrypted_data: &[u8], key: &[u8], mode: SecurityMode) -> Result<Vec<u8>> {
    mode.validate()?;
    decrypt_aes_gcm_internal(encrypted_data, key)
}

/// Encrypt data using AES-256-GCM with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `Verified` mode
/// - The configuration validation fails
/// - The key length is less than 32 bytes
/// - The encryption operation fails
#[inline]
pub fn encrypt_aes_gcm_with_config(
    data: &[u8],
    key: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    encrypt_aes_gcm_internal(data, key)
}

/// Decrypt data using AES-256-GCM with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `Verified` mode
/// - The configuration validation fails
/// - The encrypted data or key is invalid
/// - The decryption operation fails
#[inline]
pub fn decrypt_aes_gcm_with_config(
    encrypted_data: &[u8],
    key: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    decrypt_aes_gcm_internal(encrypted_data, key)
}

// ============================================================================
// Unverified API (Opt-Out)
// ============================================================================

/// Encrypt data using AES-256-GCM without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible. For verified operations, use
/// `encrypt_aes_gcm(data, key, SecurityMode::Verified(&session))`.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is less than 32 bytes
/// - Random nonce generation fails
/// - The encryption operation fails
#[inline]
pub fn encrypt_aes_gcm_unverified(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    encrypt_aes_gcm(data, key, SecurityMode::Unverified)
}

/// Decrypt data using AES-256-GCM without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible. For verified operations, use
/// `decrypt_aes_gcm(encrypted_data, key, SecurityMode::Verified(&session))`.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted data is shorter than 12 bytes (nonce size)
/// - The key length is less than 32 bytes
/// - The decryption operation fails (e.g., authentication tag mismatch)
#[inline]
pub fn decrypt_aes_gcm_unverified(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    decrypt_aes_gcm(encrypted_data, key, SecurityMode::Unverified)
}

/// Encrypt data using AES-256-GCM with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The key length is less than 32 bytes
/// - Random nonce generation fails
/// - The encryption operation fails
#[inline]
pub fn encrypt_aes_gcm_with_config_unverified(
    data: &[u8],
    key: &[u8],
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    encrypt_aes_gcm_with_config(data, key, config, SecurityMode::Unverified)
}

/// Decrypt data using AES-256-GCM with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The encrypted data is shorter than 12 bytes (nonce size)
/// - The key length is less than 32 bytes
/// - The decryption operation fails (e.g., authentication tag mismatch)
#[inline]
pub fn decrypt_aes_gcm_with_config_unverified(
    encrypted_data: &[u8],
    key: &[u8],
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    decrypt_aes_gcm_with_config(encrypted_data, key, config, SecurityMode::Unverified)
}
