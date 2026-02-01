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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CoreConfig;

    // Helper to generate a valid AES-256 key (32 bytes)
    fn generate_test_key() -> Vec<u8> {
        vec![0x42; 32]
    }

    // Basic encryption/decryption roundtrip tests
    #[test]
    fn test_aes_gcm_roundtrip_basic() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test message for AES-256-GCM encryption";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext, "Decrypted text should match original plaintext");
        assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_empty_data() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext, "Empty data should roundtrip correctly");
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_large_data() -> Result<()> {
        let key = generate_test_key();
        let plaintext = vec![0xAB; 10000]; // 10KB of data

        let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext, "Large data should roundtrip correctly");
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_binary_data() -> Result<()> {
        let key = generate_test_key();
        let plaintext = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE]; // Various byte values

        let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext, "Binary data should roundtrip correctly");
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_with_config() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test with config";
        let config = CoreConfig::default();

        let ciphertext = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
        let decrypted = decrypt_aes_gcm_with_config_unverified(&ciphertext, &key, &config)?;

        assert_eq!(decrypted, plaintext, "Roundtrip with config should work");
        Ok(())
    }

    // Ciphertext format and properties tests
    #[test]
    fn test_aes_gcm_ciphertext_includes_nonce_and_tag() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test message";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

        // Ciphertext = 12 bytes nonce + encrypted data + 16 bytes auth tag
        // Minimum size = 12 (nonce) + 0 (empty plaintext) + 16 (tag) = 28 for empty
        // For our plaintext: 12 + plaintext.len() + 16
        let expected_min_size = 12 + plaintext.len() + 16;
        assert!(
            ciphertext.len() >= expected_min_size,
            "Ciphertext should include nonce and auth tag"
        );
        Ok(())
    }

    #[test]
    fn test_aes_gcm_different_encryptions_produce_different_ciphertexts() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Same plaintext for both encryptions";

        let ciphertext1 = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let ciphertext2 = encrypt_aes_gcm_unverified(plaintext, &key)?;

        // Due to random nonce, ciphertexts should differ even with same plaintext
        assert_ne!(
            ciphertext1, ciphertext2,
            "Different encryptions should produce different ciphertexts due to random nonce"
        );

        // Both should still decrypt to same plaintext
        let decrypted1 = decrypt_aes_gcm_unverified(&ciphertext1, &key)?;
        let decrypted2 = decrypt_aes_gcm_unverified(&ciphertext2, &key)?;
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
        Ok(())
    }

    // Key validation tests
    #[test]
    fn test_aes_gcm_encrypt_with_short_key_fails() {
        let short_key = vec![0x42; 16]; // Only 16 bytes, need 32
        let plaintext = b"Test";

        let result = encrypt_aes_gcm_unverified(plaintext, &short_key);
        assert!(result.is_err(), "Encryption with short key should fail");
        match result.unwrap_err() {
            CoreError::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 16);
            }
            other => panic!("Expected InvalidKeyLength error, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_gcm_decrypt_with_short_key_fails() {
        let key = generate_test_key();
        let plaintext = b"Test";
        let ciphertext =
            encrypt_aes_gcm_unverified(plaintext, &key).expect("encryption should succeed");

        let short_key = vec![0x42; 16];
        let result = decrypt_aes_gcm_unverified(&ciphertext, &short_key);
        assert!(result.is_err(), "Decryption with short key should fail");
    }

    #[test]
    fn test_aes_gcm_encrypt_with_exact_32_byte_key() -> Result<()> {
        let key = generate_test_key(); // Exactly 32 bytes
        let plaintext = b"Test";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_aes_gcm_encrypt_with_longer_key_uses_first_32_bytes() -> Result<()> {
        let long_key = vec![0x42; 64]; // 64 bytes, only first 32 will be used
        let plaintext = b"Test";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &long_key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &long_key)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    // Ciphertext validation tests
    #[test]
    fn test_aes_gcm_decrypt_with_too_short_ciphertext_fails() {
        let key = generate_test_key();
        let too_short = vec![0x42; 10]; // Less than 12 bytes (nonce size)

        let result = decrypt_aes_gcm_unverified(&too_short, &key);
        assert!(result.is_err(), "Decryption with too-short ciphertext should fail");
        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => {
                assert!(msg.contains("too short"), "Error should mention data is too short");
            }
            other => panic!("Expected InvalidInput error, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_gcm_decrypt_with_tampered_ciphertext_fails() {
        let key = generate_test_key();
        let plaintext = b"Test message";
        let mut ciphertext =
            encrypt_aes_gcm_unverified(plaintext, &key).expect("encryption should succeed");

        // Tamper with the ciphertext (flip a bit in the encrypted portion, not the nonce)
        if ciphertext.len() > 12 {
            ciphertext[13] ^= 0x01;
        }

        let result = decrypt_aes_gcm_unverified(&ciphertext, &key);
        assert!(result.is_err(), "Decryption with tampered ciphertext should fail");
        match result.unwrap_err() {
            CoreError::DecryptionFailed(_) => {} // Expected
            other => panic!("Expected DecryptionFailed error, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_gcm_decrypt_with_tampered_nonce_fails() {
        let key = generate_test_key();
        let plaintext = b"Test message";
        let mut ciphertext =
            encrypt_aes_gcm_unverified(plaintext, &key).expect("encryption should succeed");

        // Tamper with the nonce (first 12 bytes)
        ciphertext[5] ^= 0x01;

        let result = decrypt_aes_gcm_unverified(&ciphertext, &key);
        assert!(result.is_err(), "Decryption with tampered nonce should fail");
    }

    // Cross-key decryption test
    #[test]
    fn test_aes_gcm_decrypt_with_wrong_key_fails() {
        let key1 = vec![0x42; 32];
        let key2 = vec![0x43; 32]; // Different key
        let plaintext = b"Test message";

        let ciphertext =
            encrypt_aes_gcm_unverified(plaintext, &key1).expect("encryption should succeed");
        let result = decrypt_aes_gcm_unverified(&ciphertext, &key2);

        assert!(result.is_err(), "Decryption with wrong key should fail");
        match result.unwrap_err() {
            CoreError::DecryptionFailed(_) => {} // Expected
            other => panic!("Expected DecryptionFailed error, got: {:?}", other),
        }
    }

    // SecurityMode tests
    #[test]
    fn test_aes_gcm_encrypt_with_unverified_mode() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)?;
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_aes_gcm_encrypt_with_config_and_unverified_mode() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test";
        let config = CoreConfig::default();

        let ciphertext =
            encrypt_aes_gcm_with_config(plaintext, &key, &config, SecurityMode::Unverified)?;
        let decrypted =
            decrypt_aes_gcm_with_config(&ciphertext, &key, &config, SecurityMode::Unverified)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    // Edge case: multiple roundtrips with same key
    #[test]
    fn test_aes_gcm_multiple_roundtrips_with_same_key() -> Result<()> {
        let key = generate_test_key();
        let messages = vec![
            b"First message".as_ref(),
            b"Second message".as_ref(),
            b"Third message with different length".as_ref(),
        ];

        for message in messages {
            let ciphertext = encrypt_aes_gcm_unverified(message, &key)?;
            let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;
            assert_eq!(decrypted, message, "Each message should roundtrip correctly");
        }
        Ok(())
    }

    // Performance/size validation
    #[test]
    fn test_aes_gcm_ciphertext_size_overhead() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test message";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

        // AES-GCM overhead = 12 bytes (nonce) + 16 bytes (auth tag) = 28 bytes
        let expected_size = plaintext.len() + 28;
        assert_eq!(
            ciphertext.len(),
            expected_size,
            "Ciphertext should have exact overhead of 28 bytes (12 nonce + 16 tag)"
        );
        Ok(())
    }
}
