//! AES-GCM symmetric encryption operations
//!
//! This module provides AES-256-GCM authenticated encryption.
//!
//! ## Security Considerations
//!
//! **Nonce Management:** This implementation uses random 96-bit nonces. Due to birthday
//! paradox, random nonces have a collision probability of approximately 2^-32 after 2^32
//! encryptions (4 billion operations). For high-volume applications, consider using
//! counter-based nonces or rotating keys.
//!
//! **Key Length:** Keys must be exactly 32 bytes for AES-256. Any other key length is
//! rejected with an error.
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::unified_api::{encrypt_aes_gcm, SecurityMode, VerifiedSession};
//! # let data = b"example data";
//! # let key = [0u8; 32];
//! # let pk = [0u8; 32];
//! # let sk = [0u8; 32];
//! # let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // With Zero Trust verification (recommended)
//! let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Verified(&session))?;
//!
//! // Without verification (opt-out)
//! let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Unverified)?;
//! # Ok(())
//! # }
//! ```

use crate::{
    log_crypto_operation_complete, log_crypto_operation_error, log_crypto_operation_start,
};
use tracing::debug;
use zeroize::Zeroizing;

use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{AeadCipher, TAG_LEN};

use crate::unified_api::CoreConfig;
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::zero_trust::SecurityMode;

// ============================================================================
// Internal Implementation — delegates to primitives::aead::AesGcm256
// ============================================================================

/// Internal implementation of AES-GCM encryption.
///
/// Delegates to [`encrypt_aes_gcm_with_aad_internal`] with empty AAD.
pub(crate) fn encrypt_aes_gcm_internal(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    encrypt_aes_gcm_with_aad_internal(data, key, b"")
}

/// Internal implementation of AES-GCM encryption with Additional Authenticated Data (AAD).
///
/// Delegates to `primitives::aead::AesGcm256` so all callers benefit from the
/// same hardening (zero-key warning, `ZeroizeOnDrop`).
///
/// Wire format: `nonce(12) || ciphertext || tag(16)`.
pub(crate) fn encrypt_aes_gcm_with_aad_internal(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    log_crypto_operation_start!(
        "aes_gcm_encrypt_aad",
        algorithm = "AES-256-GCM",
        data_len = data.len(),
        aad_len = aad.len()
    );

    if key.len() != 32 {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: key.len() };
        log_crypto_operation_error!("aes_gcm_encrypt_aad", err);
        return Err(err);
    }

    // Delegate to the primitives AesGcm256 (includes zero-key warning, ZeroizeOnDrop)
    let cipher = AesGcm256::new(key).map_err(|e| {
        let err = CoreError::EncryptionFailed(format!("Failed to create AES key: {e}"));
        log_crypto_operation_error!("aes_gcm_encrypt_aad", err);
        err
    })?;

    let nonce = AesGcm256::generate_nonce();
    let aad_opt = if aad.is_empty() { None } else { Some(aad) };

    let (ciphertext, tag) = cipher.encrypt(&nonce, data, aad_opt).map_err(|e| {
        let err = CoreError::EncryptionFailed(e.to_string());
        log_crypto_operation_error!("aes_gcm_encrypt_aad", err);
        err
    })?;

    // Wire format: nonce(12) || ciphertext || tag(16)
    let mut result =
        Vec::with_capacity(nonce.len().saturating_add(ciphertext.len()).saturating_add(TAG_LEN));
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);

    log_crypto_operation_complete!(
        "aes_gcm_encrypt_aad",
        algorithm = "AES-256-GCM",
        ciphertext_len = result.len()
    );
    debug!(
        data_len = data.len(),
        aad_len = aad.len(),
        ciphertext_len = result.len(),
        "AES-256-GCM encryption with AAD completed"
    );

    Ok(result)
}

/// Internal implementation of AES-GCM decryption with Additional Authenticated Data (AAD).
///
/// Delegates to `primitives::aead::AesGcm256` so all callers benefit from the
/// same hardening (zero-key warning, `ZeroizeOnDrop`).
pub(crate) fn decrypt_aes_gcm_with_aad_internal(
    encrypted_data: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    log_crypto_operation_start!(
        "aes_gcm_decrypt_aad",
        algorithm = "AES-256-GCM",
        encrypted_len = encrypted_data.len(),
        aad_len = aad.len()
    );

    // Minimum: 12 (nonce) + 16 (tag) = 28 bytes
    if encrypted_data.len() < 12 + TAG_LEN {
        let err =
            CoreError::InvalidInput("Data too short for AES-GCM (need nonce + tag)".to_string());
        log_crypto_operation_error!("aes_gcm_decrypt_aad", err);
        return Err(err);
    }

    if key.len() != 32 {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: key.len() };
        log_crypto_operation_error!("aes_gcm_decrypt_aad", err);
        return Err(err);
    }

    // Delegate to the primitives AesGcm256 (includes zero-key warning, ZeroizeOnDrop)
    let cipher = AesGcm256::new(key).map_err(|e| {
        let err = CoreError::DecryptionFailed(format!("Failed to create AES key: {e}"));
        log_crypto_operation_error!("aes_gcm_decrypt_aad", err);
        err
    })?;

    // Parse wire format: nonce(12) || ciphertext || tag(16)
    let (nonce_slice, ct_and_tag) = encrypted_data.split_at(12);
    let nonce: [u8; 12] = nonce_slice.try_into().map_err(|e| {
        let err = CoreError::InvalidNonce(format!("Nonce must be 12 bytes: {e}"));
        log_crypto_operation_error!("aes_gcm_decrypt_aad", err);
        err
    })?;

    let ct_len = ct_and_tag.len().saturating_sub(TAG_LEN);
    let ciphertext = ct_and_tag
        .get(..ct_len)
        .ok_or_else(|| CoreError::DecryptionFailed("Invalid ciphertext length".to_string()))?;
    let tag_slice = ct_and_tag
        .get(ct_len..)
        .ok_or_else(|| CoreError::DecryptionFailed("Invalid tag offset".to_string()))?;
    let tag: [u8; TAG_LEN] = tag_slice
        .try_into()
        .map_err(|_e| CoreError::DecryptionFailed("Tag must be 16 bytes".to_string()))?;

    let aad_opt = if aad.is_empty() { None } else { Some(aad) };

    let result = cipher.decrypt(&nonce, ciphertext, &tag, aad_opt).map_err(|_aead_err| {
        // SECURITY: Opaque error per SP 800-38D §5.2.2
        let err = CoreError::DecryptionFailed("decryption failed".to_string());
        log_crypto_operation_error!("aes_gcm_decrypt_aad", err);
        err
    })?;

    log_crypto_operation_complete!(
        "aes_gcm_decrypt_aad",
        algorithm = "AES-256-GCM",
        plaintext_len = result.len()
    );
    debug!(
        encrypted_len = encrypted_data.len(),
        aad_len = aad.len(),
        plaintext_len = result.len(),
        "AES-256-GCM decryption with AAD completed"
    );

    Ok(result)
}

/// Delegates to [`decrypt_aes_gcm_with_aad_internal`] with empty AAD.
pub(crate) fn decrypt_aes_gcm_internal(
    encrypted_data: &[u8],
    key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_aes_gcm_with_aad_internal(encrypted_data, key, b"")
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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{encrypt_aes_gcm, SecurityMode, VerifiedSession};
/// # let data = b"example data";
/// # let key = [0u8; 32];
/// # let pk = [0u8; 32];
/// # let sk = [0u8; 32];
/// # let session = VerifiedSession::establish(&pk, &sk)?;
///
/// // With Zero Trust verification (recommended)
/// let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
/// ```
///
/// # Key Requirements
///
/// The `key` parameter must be exactly 32 bytes for AES-256-GCM.
/// Any other key length returns an error.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The key length is not exactly 32 bytes
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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{decrypt_aes_gcm, SecurityMode, VerifiedSession};
/// # let encrypted = vec![0u8; 44]; // nonce (12) + ciphertext (16) + tag (16)
/// # let key = [0u8; 32];
/// # let pk = [0u8; 32];
/// # let sk = [0u8; 32];
/// # let session = VerifiedSession::establish(&pk, &sk)?;
///
/// // With Zero Trust verification (recommended)
/// let decrypted = decrypt_aes_gcm(&encrypted, &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let decrypted = decrypt_aes_gcm(&encrypted, &key, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
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
pub fn decrypt_aes_gcm(
    encrypted_data: &[u8],
    key: &[u8],
    mode: SecurityMode,
) -> Result<Zeroizing<Vec<u8>>> {
    mode.validate()?;
    decrypt_aes_gcm_internal(encrypted_data, key)
}

/// Encrypt data using AES-256-GCM with configuration and configurable security mode.
///
/// # Key Requirements
///
/// The `key` parameter must be exactly 32 bytes for AES-256-GCM.
/// Any other key length returns an error.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `Verified` mode
/// - The configuration validation fails
/// - The key length is not exactly 32 bytes
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
) -> Result<Zeroizing<Vec<u8>>> {
    mode.validate()?;
    config.validate()?;
    decrypt_aes_gcm_internal(encrypted_data, key)
}

// ============================================================================
// Unverified API (Opt-Out) — see `convenience::mod` docs for the shared
// security guidance on when to use `_unverified` variants.
// ============================================================================

/// Encrypt data using AES-256-GCM without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible. For verified operations, use
/// `encrypt_aes_gcm(data, key, SecurityMode::Verified(&session))`.
///
/// # Key Requirements
///
/// The `key` must be exactly 32 bytes (AES-256). Any other key length
/// returns an error.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not exactly 32 bytes
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
pub fn decrypt_aes_gcm_unverified(encrypted_data: &[u8], key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_aes_gcm(encrypted_data, key, SecurityMode::Unverified)
}

/// Encrypt data using AES-256-GCM with Additional Authenticated Data (AAD).
///
/// AAD is authenticated but not encrypted — it binds context (e.g., a header,
/// key ID, or metadata) to the ciphertext so that decryption fails unless the
/// identical AAD is supplied.
///
/// # Wire Format
///
/// Output: `nonce(12) || ciphertext || tag(16)` (same as without AAD).
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `Verified` mode
/// - The key length is not exactly 32 bytes
/// - Random nonce generation fails
/// - The encryption operation fails
#[inline]
pub fn encrypt_aes_gcm_with_aad(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    encrypt_aes_gcm_with_aad_internal(data, key, aad)
}

/// Decrypt data using AES-256-GCM with Additional Authenticated Data (AAD).
///
/// The same AAD that was used during encryption must be provided; otherwise
/// decryption will fail with `DecryptionFailed`.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `Verified` mode
/// - The encrypted data is shorter than 12 bytes (nonce size)
/// - The key length is not exactly 32 bytes
/// - The AAD does not match the value used during encryption
/// - The decryption operation fails
#[inline]
pub fn decrypt_aes_gcm_with_aad(
    encrypted_data: &[u8],
    key: &[u8],
    aad: &[u8],
    mode: SecurityMode,
) -> Result<Zeroizing<Vec<u8>>> {
    mode.validate()?;
    decrypt_aes_gcm_with_aad_internal(encrypted_data, key, aad)
}

/// Encrypt data using AES-256-GCM with AAD without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not exactly 32 bytes
/// - Random nonce generation fails
/// - The encryption operation fails
#[inline]
pub fn encrypt_aes_gcm_with_aad_unverified(data: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    encrypt_aes_gcm_with_aad(data, key, aad, SecurityMode::Unverified)
}

/// Decrypt data using AES-256-GCM with AAD without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted data is shorter than 12 bytes (nonce size)
/// - The key length is not exactly 32 bytes
/// - The AAD does not match the value used during encryption
/// - The decryption operation fails
#[inline]
pub fn decrypt_aes_gcm_with_aad_unverified(
    encrypted_data: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_aes_gcm_with_aad(encrypted_data, key, aad, SecurityMode::Unverified)
}

/// Encrypt data using AES-256-GCM with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Key Requirements
///
/// The `key` must be exactly 32 bytes (AES-256). Any other key length
/// returns an error.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The key length is not exactly 32 bytes
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
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_aes_gcm_with_config(encrypted_data, key, config, SecurityMode::Unverified)
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
    use crate::unified_api::CoreConfig;

    // Helper to generate a valid AES-256 key (32 bytes)
    fn generate_test_key() -> Vec<u8> {
        vec![0x42; 32]
    }

    // Basic encryption/decryption roundtrip tests
    #[test]
    fn test_aes_gcm_roundtrip_basic_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test message for AES-256-GCM encryption";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Decrypted text should match original plaintext"
        );
        assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_empty_data_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Empty data should roundtrip correctly"
        );
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_large_data_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = vec![0xAB; 10000]; // 10KB of data

        let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Large data should roundtrip correctly"
        );
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_binary_data_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE]; // Various byte values

        let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Binary data should roundtrip correctly"
        );
        Ok(())
    }

    #[test]
    fn test_aes_gcm_roundtrip_with_config_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test with config";
        let config = CoreConfig::default();

        let ciphertext = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
        let decrypted = decrypt_aes_gcm_with_config_unverified(&ciphertext, &key, &config)?;

        assert_eq!(decrypted.as_slice(), plaintext.as_slice(), "Roundtrip with config should work");
        Ok(())
    }

    // Ciphertext format and properties tests
    #[test]
    fn test_aes_gcm_ciphertext_includes_nonce_and_tag_at_minimum_size_has_correct_size()
    -> Result<()> {
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
    fn test_aes_gcm_different_encryptions_produce_different_ciphertexts_succeeds() -> Result<()> {
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
        assert_eq!(decrypted1.as_slice(), plaintext.as_slice());
        assert_eq!(decrypted2.as_slice(), plaintext.as_slice());
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
    fn test_aes_gcm_encrypt_with_exact_32_byte_key_succeeds() -> Result<()> {
        let key = generate_test_key(); // Exactly 32 bytes
        let plaintext = b"Test";

        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_aes_gcm_encrypt_with_longer_key_rejects_fails() {
        let long_key = vec![0x42; 64]; // 64 bytes - should be rejected (not truncated)
        let plaintext = b"Test";

        let result = encrypt_aes_gcm_unverified(plaintext, &long_key);
        assert!(result.is_err(), "Should reject keys longer than 32 bytes");

        if let Err(CoreError::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 32);
            assert_eq!(actual, 64);
        } else {
            panic!("Expected InvalidKeyLength error");
        }
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
    fn test_aes_gcm_encrypt_with_unverified_mode_succeeds() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test";

        let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)?;
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)?;
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_aes_gcm_encrypt_with_config_and_unverified_mode_succeeds() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Test";
        let config = CoreConfig::default();

        let ciphertext =
            encrypt_aes_gcm_with_config(plaintext, &key, &config, SecurityMode::Unverified)?;
        let decrypted =
            decrypt_aes_gcm_with_config(&ciphertext, &key, &config, SecurityMode::Unverified)?;
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        Ok(())
    }

    // Edge case: multiple roundtrips with same key
    #[test]
    fn test_aes_gcm_multiple_roundtrips_with_same_key_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let messages = vec![
            b"First message".as_ref(),
            b"Second message".as_ref(),
            b"Third message with different length".as_ref(),
        ];

        for message in messages {
            let ciphertext = encrypt_aes_gcm_unverified(message, &key)?;
            let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;
            assert_eq!(decrypted.as_slice(), message, "Each message should roundtrip correctly");
        }
        Ok(())
    }

    // Verified session tests
    #[test]
    fn test_aes_gcm_roundtrip_verified_session_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Verified session roundtrip test";
        let (auth_pk, auth_sk) = crate::unified_api::generate_keypair()?;
        let session = crate::VerifiedSession::establish(auth_pk.as_slice(), auth_sk.as_ref())?;

        let ct = encrypt_aes_gcm(plaintext, &key, SecurityMode::Verified(&session))?;
        let pt = decrypt_aes_gcm(&ct, &key, SecurityMode::Verified(&session))?;
        assert_eq!(pt.as_slice(), plaintext.as_ref());
        Ok(())
    }

    #[test]
    fn test_aes_gcm_with_config_verified_session_succeeds() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Config + verified session test";
        let config = CoreConfig::default();
        let (auth_pk, auth_sk) = crate::unified_api::generate_keypair()?;
        let session = crate::VerifiedSession::establish(auth_pk.as_slice(), auth_sk.as_ref())?;

        let ct = encrypt_aes_gcm_with_config(
            plaintext,
            &key,
            &config,
            SecurityMode::Verified(&session),
        )?;
        let pt = decrypt_aes_gcm_with_config(&ct, &key, &config, SecurityMode::Verified(&session))?;
        assert_eq!(pt.as_slice(), plaintext.as_ref());
        Ok(())
    }

    #[test]
    fn test_aes_gcm_encrypt_with_empty_key_fails() {
        let result = encrypt_aes_gcm_unverified(b"test", &[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            CoreError::InvalidKeyLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 0);
            }
            other => panic!("Expected InvalidKeyLength, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_gcm_decrypt_with_empty_key_fails() {
        let key = generate_test_key();
        let ct = encrypt_aes_gcm_unverified(b"test", &key).unwrap();
        let result = decrypt_aes_gcm_unverified(&ct, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_decrypt_exactly_12_bytes_succeeds() {
        let key = generate_test_key();
        // Exactly 12 bytes = just a nonce, no ciphertext or tag
        let result = decrypt_aes_gcm_unverified(&[0u8; 12], &key);
        assert!(result.is_err(), "12-byte input has no ciphertext body");
    }

    #[test]
    fn test_aes_gcm_internal_encrypt_wrong_key_length_fails() {
        let result = encrypt_aes_gcm_internal(b"test", &[0u8; 31]);
        assert!(result.is_err());
        let result = encrypt_aes_gcm_internal(b"test", &[0u8; 33]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_internal_decrypt_wrong_key_length_fails() {
        let key = generate_test_key();
        let ct = encrypt_aes_gcm_internal(b"test", &key).unwrap();
        let result = decrypt_aes_gcm_internal(&ct, &[0u8; 31]);
        assert!(result.is_err());
        let result = decrypt_aes_gcm_internal(&ct, &[0u8; 33]);
        assert!(result.is_err());
    }

    // ================================================================
    // AES-GCM with AAD tests
    // ================================================================

    #[test]
    fn test_aes_gcm_with_aad_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Encrypt me with context binding";
        let aad = b"authenticated-context-v1";

        let ct = encrypt_aes_gcm_with_aad_unverified(plaintext, &key, aad)?;
        let pt = decrypt_aes_gcm_with_aad_unverified(&ct, &key, aad)?;

        assert_eq!(pt.as_slice(), plaintext.as_slice(), "AAD roundtrip should recover plaintext");
        Ok(())
    }

    #[test]
    fn test_aes_gcm_with_aad_wrong_aad_fails() {
        let key = generate_test_key();
        let plaintext = b"Tamper-evident data";
        let aad = b"correct-aad";
        let wrong_aad = b"wrong-aad";

        let ct = encrypt_aes_gcm_with_aad_unverified(plaintext, &key, aad)
            .expect("encryption should succeed");
        let result = decrypt_aes_gcm_with_aad_unverified(&ct, &key, wrong_aad);

        assert!(result.is_err(), "Mismatched AAD must fail decryption");
        match result.unwrap_err() {
            CoreError::DecryptionFailed(_) => {}
            other => panic!("Expected DecryptionFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_gcm_with_empty_aad_succeeds() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Empty AAD test";

        let ct = encrypt_aes_gcm_with_aad_unverified(plaintext, &key, b"")?;
        let pt = decrypt_aes_gcm_with_aad_unverified(&ct, &key, b"")?;

        assert_eq!(pt.as_slice(), plaintext.as_slice(), "Empty AAD should roundtrip correctly");
        Ok(())
    }

    #[test]
    fn test_aes_gcm_with_aad_verified_session_succeeds() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Verified AAD test";
        let aad = b"session-bound-context";
        let (auth_pk, auth_sk) = crate::unified_api::generate_keypair()?;
        let session = crate::VerifiedSession::establish(auth_pk.as_slice(), auth_sk.as_ref())?;

        let ct = encrypt_aes_gcm_with_aad(plaintext, &key, aad, SecurityMode::Verified(&session))?;
        let pt = decrypt_aes_gcm_with_aad(&ct, &key, aad, SecurityMode::Verified(&session))?;

        assert_eq!(pt.as_slice(), plaintext.as_ref());
        Ok(())
    }

    #[test]
    fn test_aes_gcm_with_aad_large_aad_succeeds() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Large AAD test";
        let aad = vec![0xBB; 1024]; // 1KB of AAD

        let ct = encrypt_aes_gcm_with_aad_unverified(plaintext, &key, &aad)?;
        let pt = decrypt_aes_gcm_with_aad_unverified(&ct, &key, &aad)?;

        assert_eq!(pt.as_slice(), plaintext.as_slice(), "Large AAD should roundtrip correctly");
        Ok(())
    }

    // Performance/size validation
    #[test]
    fn test_aes_gcm_ciphertext_size_overhead_has_correct_size() -> Result<()> {
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

    // ---- Coverage: config unverified roundtrip ----

    #[test]
    fn test_encrypt_decrypt_with_config_unverified_roundtrip() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"Config unverified roundtrip test";
        let config = CoreConfig::default();

        let ct = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
        let pt = decrypt_aes_gcm_with_config_unverified(&ct, &key, &config)?;

        assert_eq!(pt.as_slice(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_config_unverified_wrong_key_length_fails() {
        let short_key = vec![0x42; 16]; // 16 bytes instead of 32
        let plaintext = b"Should fail";
        let config = CoreConfig::default();

        let result = encrypt_aes_gcm_with_config_unverified(plaintext, &short_key, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_unverified_decrypt_wrong_key_fails() -> Result<()> {
        let key = generate_test_key();
        let wrong_key = vec![0xFF; 32];
        let plaintext = b"Decrypt with wrong key";
        let config = CoreConfig::default();

        let ct = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
        let result = decrypt_aes_gcm_with_config_unverified(&ct, &wrong_key, &config);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_config_unverified_decrypt_short_ciphertext_succeeds() {
        let key = generate_test_key();
        let config = CoreConfig::default();
        let short_data = vec![0u8; 5]; // Less than 12 bytes (nonce)

        let result = decrypt_aes_gcm_with_config_unverified(&short_data, &key, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_unverified_empty_plaintext_succeeds() -> Result<()> {
        let key = generate_test_key();
        let config = CoreConfig::default();
        let plaintext = b"";

        let ct = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
        let pt = decrypt_aes_gcm_with_config_unverified(&ct, &key, &config)?;
        assert_eq!(pt.as_slice(), plaintext.as_slice());
        Ok(())
    }

    // ---- Coverage: AAD with SecurityMode ----

    #[test]
    fn test_aad_with_security_mode_unverified_succeeds() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"AAD SecurityMode test";
        let aad = b"authenticated-context";

        let ct = encrypt_aes_gcm_with_aad(plaintext, &key, aad, SecurityMode::Unverified)?;
        let pt = decrypt_aes_gcm_with_aad(&ct, &key, aad, SecurityMode::Unverified)?;
        assert_eq!(pt.as_slice(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_aad_wrong_aad_decrypt_fails() -> Result<()> {
        let key = generate_test_key();
        let plaintext = b"AAD mismatch test";
        let aad = b"correct-aad";
        let wrong_aad = b"wrong-aad";

        let ct = encrypt_aes_gcm_with_aad_unverified(plaintext, &key, aad)?;
        let result = decrypt_aes_gcm_with_aad_unverified(&ct, &key, wrong_aad);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_aad_internal_wrong_key_length_fails() {
        let short_key = vec![0x42; 16];
        let plaintext = b"AAD key length test";
        let aad = b"some-aad";

        let result = encrypt_aes_gcm_with_aad_internal(plaintext, &short_key, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_internal_decrypt_short_data_succeeds() {
        let key = generate_test_key();
        let aad = b"some-aad";
        let short_data = vec![0u8; 5];

        let result = decrypt_aes_gcm_with_aad_internal(&short_data, &key, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_aad_internal_decrypt_wrong_key_length_fails() -> Result<()> {
        let key = generate_test_key();
        let short_key = vec![0x42; 16];
        let plaintext = b"test";
        let aad = b"some-aad";

        let ct = encrypt_aes_gcm_with_aad_internal(plaintext, &key, aad)?;
        let result = decrypt_aes_gcm_with_aad_internal(&ct, &short_key, aad);
        assert!(result.is_err());
        Ok(())
    }
}
