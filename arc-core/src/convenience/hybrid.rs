//! Hybrid KEM encryption operations
//!
//! This module provides hybrid encryption combining post-quantum KEM (ML-KEM)
//! with symmetric encryption (AES-GCM) for defense in depth.
//!
//! ## Zero Trust Enforcement
//!
//! All primary functions use `SecurityMode` to specify verification behavior:
//! - `SecurityMode::Verified(&session)`: Validates session before operation
//! - `SecurityMode::Unverified`: Skips session validation
//!
//! For opt-out scenarios, use the `_unverified` variants which skip
//! session validation. Usage is logged for audit in enterprise deployments.
//!
//! ## Example
//!
//! ```rust,ignore
//! use arc_core::{SecurityMode, VerifiedSession, encrypt_hybrid};
//!
//! // With Zero Trust verification (recommended)
//! let session = VerifiedSession::establish(&public_key, &private_key)?;
//! let result = encrypt_hybrid(data, None, &key, SecurityMode::Verified(&session))?;
//!
//! // Without verification (opt-out)
//! let result = encrypt_hybrid(data, None, &key, SecurityMode::Unverified)?;
//! ```

use crate::{
    log_crypto_operation_complete, log_crypto_operation_error, log_crypto_operation_start,
};
use tracing::debug;

use arc_primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel,
};

use super::aes_gcm::{decrypt_aes_gcm_internal, encrypt_aes_gcm_internal};
use super::keygen::generate_ml_kem_keypair;
use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

use arc_validation::resource_limits::{validate_decryption_size, validate_encryption_size};

/// Result of hybrid encryption containing encapsulated key and ciphertext.
#[derive(Debug)]
pub struct HybridEncryptionResult {
    /// The encapsulated key material for the recipient.
    pub encapsulated_key: Vec<u8>,
    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,
}

pub(crate) fn hybrid_kem_encapsulate(public_key_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let security_level = match public_key_bytes.len() {
        800 => MlKemSecurityLevel::MlKem512,
        1184 => MlKemSecurityLevel::MlKem768,
        1568 => MlKemSecurityLevel::MlKem1024,
        l => {
            return Err(CoreError::InvalidKeyLength {
                expected: 1184, // or others
                actual: l,
            });
        }
    };

    let public_key = MlKemPublicKey::new(security_level, public_key_bytes.to_vec())
        .map_err(|e| CoreError::InvalidInput(format!("Invalid public key: {}", e)))?;

    let mut rng = rand::rngs::OsRng;
    let (shared_secret, encapsulated) = MlKem::encapsulate(&mut rng, &public_key)
        .map_err(|e| CoreError::EncryptionFailed(format!("Encapsulation failed: {}", e)))?;

    Ok((encapsulated.into_bytes(), shared_secret.as_bytes().to_vec()))
}

pub(crate) fn hybrid_kem_decapsulate(
    private_key: &[u8],
    encapsulated_key: &[u8],
) -> Result<Vec<u8>> {
    let security_level = match private_key.len() {
        1632 => MlKemSecurityLevel::MlKem512,
        2400 => MlKemSecurityLevel::MlKem768,
        3168 => MlKemSecurityLevel::MlKem1024,
        l => return Err(CoreError::InvalidKeyLength { expected: 2400, actual: l }),
    };

    let ciphertext_size = security_level.ciphertext_size();
    if encapsulated_key.len() < ciphertext_size {
        return Err(CoreError::InvalidInput(format!(
            "Encapsulated key too short: expected {}, got {}",
            ciphertext_size,
            encapsulated_key.len()
        )));
    }

    let encapsulated_slice = encapsulated_key
        .get(..ciphertext_size)
        .ok_or_else(|| CoreError::InvalidInput("Encapsulated key too short".to_string()))?;

    let encapsulated = MlKemCiphertext::new(security_level, encapsulated_slice.to_vec())
        .map_err(|_e| CoreError::DecryptionFailed("Invalid encapsulated key".to_string()))?;

    let kem_private_key = MlKemSecretKey::new(security_level, private_key.to_vec())
        .map_err(|_e| CoreError::DecryptionFailed("Invalid private key".to_string()))?;

    MlKem::decapsulate(&kem_private_key, &encapsulated)
        .map(|shared_secret| shared_secret.as_bytes().to_vec())
        .map_err(|e| CoreError::DecryptionFailed(format!("KEM decapsulation failed: {}", e)))
}

pub(crate) fn encrypt_hybrid_kem_encapsulate(
    data: &[u8],
    symmetric_key: &[u8],
    kem_security_level: Option<MlKemSecurityLevel>,
) -> Result<Vec<u8>> {
    if symmetric_key.len() < 32 {
        return Err(CoreError::InvalidInput(format!(
            "Symmetric key must be at least 32 bytes, got {}",
            symmetric_key.len()
        )));
    }

    let ciphertext = if let Some(level) = kem_security_level {
        // Generate ephemeral KEM keypair for hybrid encryption
        let (kem_pk, _) = generate_ml_kem_keypair(level)?;
        let encrypted_hybrid =
            encrypt_hybrid_aes_gcm(data, Some(kem_pk.as_slice()), symmetric_key)?;
        // Return encapsulated key + ciphertext
        let mut result = encrypted_hybrid.encapsulated_key;
        result.extend_from_slice(&encrypted_hybrid.ciphertext);
        result
    } else {
        encrypt_aes_gcm_internal(data, symmetric_key)?
    };

    Ok(ciphertext)
}

fn encrypt_hybrid_aes_gcm(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
) -> Result<HybridEncryptionResult> {
    if symmetric_key.len() < 32 {
        return Err(CoreError::InvalidInput(format!(
            "Symmetric key must be at least 32 bytes, got {}",
            symmetric_key.len()
        )));
    }

    let (final_encapsulated_key, final_symmetric_key) = if let Some(pk) = kem_public_key {
        hybrid_kem_encapsulate(pk)?
    } else {
        (vec![], symmetric_key.to_vec())
    };

    let ciphertext = encrypt_aes_gcm_internal(data, &final_symmetric_key)?;

    Ok(HybridEncryptionResult { encapsulated_key: final_encapsulated_key, ciphertext })
}

pub(crate) fn decrypt_hybrid_kem_decapsulate(
    encrypted_data: &[u8],
    symmetric_key: &[u8],
    kem_security_level: MlKemSecurityLevel,
) -> Result<Vec<u8>> {
    // Parse hybrid data: encapsulated_key + ciphertext
    let encapsulated_size = match kem_security_level {
        MlKemSecurityLevel::MlKem512 => 768,
        MlKemSecurityLevel::MlKem768 => 1088,
        MlKemSecurityLevel::MlKem1024 => 1568,
    };

    let encapsulated_key = encrypted_data
        .get(..encapsulated_size)
        .ok_or_else(|| CoreError::InvalidInput("Hybrid encrypted data too short".to_string()))?;

    let ciphertext = encrypted_data
        .get(encapsulated_size..)
        .ok_or_else(|| CoreError::InvalidInput("Hybrid encrypted data too short".to_string()))?;

    decrypt_hybrid_aes_gcm(ciphertext, Some(symmetric_key), encapsulated_key, symmetric_key)
}

fn decrypt_hybrid_aes_gcm(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
) -> Result<Vec<u8>> {
    let final_symmetric_key = if let Some(sk) = kem_private_key {
        hybrid_kem_decapsulate(sk, encapsulated_key)?
    } else {
        symmetric_key.to_vec()
    };

    if final_symmetric_key.len() < 32 {
        return Err(CoreError::InvalidInput(format!(
            "Symmetric key must be at least 32 bytes, got {}",
            final_symmetric_key.len()
        )));
    }

    decrypt_aes_gcm_internal(ciphertext, &final_symmetric_key)
}

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of hybrid encryption.
fn encrypt_hybrid_internal(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
) -> Result<HybridEncryptionResult> {
    let has_kem = kem_public_key.is_some();
    log_crypto_operation_start!("hybrid_encrypt", data_len = data.len(), has_kem = has_kem);

    validate_encryption_size(data.len()).map_err(|e| {
        log_crypto_operation_error!("hybrid_encrypt", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let result = encrypt_hybrid_aes_gcm(data, kem_public_key, symmetric_key);

    match &result {
        Ok(encrypted) => {
            log_crypto_operation_complete!(
                "hybrid_encrypt",
                ciphertext_len = encrypted.ciphertext.len(),
                encapsulated_key_len = encrypted.encapsulated_key.len()
            );
            debug!(
                data_len = data.len(),
                ciphertext_len = encrypted.ciphertext.len(),
                "Hybrid encryption completed"
            );
        }
        Err(e) => {
            log_crypto_operation_error!("hybrid_encrypt", e);
        }
    }

    result
}

/// Internal implementation of hybrid decryption.
fn decrypt_hybrid_internal(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
) -> Result<Vec<u8>> {
    let has_kem = kem_private_key.is_some();
    log_crypto_operation_start!(
        "hybrid_decrypt",
        ciphertext_len = ciphertext.len(),
        has_kem = has_kem
    );

    validate_decryption_size(ciphertext.len()).map_err(|e| {
        log_crypto_operation_error!("hybrid_decrypt", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let result =
        decrypt_hybrid_aes_gcm(ciphertext, kem_private_key, encapsulated_key, symmetric_key);

    match &result {
        Ok(plaintext) => {
            log_crypto_operation_complete!("hybrid_decrypt", plaintext_len = plaintext.len());
            debug!(
                ciphertext_len = ciphertext.len(),
                plaintext_len = plaintext.len(),
                "Hybrid decryption completed"
            );
        }
        Err(e) => {
            log_crypto_operation_error!("hybrid_decrypt", e);
        }
    }

    result
}

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

/// Encrypt data using hybrid encryption (KEM + AES-GCM).
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before encryption
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{encrypt_hybrid, SecurityMode, VerifiedSession, generate_keypair};
///
/// let (pk, sk) = generate_keypair()?;
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let result = encrypt_hybrid(data, None, &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let result = encrypt_hybrid(data, None, &key, SecurityMode::Unverified)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The data size exceeds resource limits
/// - The symmetric key is less than 32 bytes
/// - The KEM public key length does not match a valid ML-KEM security level (800, 1184, or 1568 bytes)
/// - The KEM encapsulation operation fails
/// - The AES-GCM encryption fails
#[inline]
pub fn encrypt_hybrid(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
    mode: SecurityMode,
) -> Result<HybridEncryptionResult> {
    mode.validate()?;
    encrypt_hybrid_internal(data, kem_public_key, symmetric_key)
}

/// Decrypt data using hybrid encryption (KEM + AES-GCM).
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before decryption
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{decrypt_hybrid, SecurityMode, VerifiedSession};
///
/// // With Zero Trust (recommended)
/// let plaintext = decrypt_hybrid(
///     ciphertext,
///     Some(&private_key),
///     &encapsulated_key,
///     &symmetric_key,
///     SecurityMode::Verified(&session),
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The ciphertext size exceeds resource limits
/// - The KEM private key length does not match a valid ML-KEM security level
/// - The encapsulated key is too short for the security level
/// - The KEM decapsulation operation fails
/// - The resulting symmetric key is less than 32 bytes
/// - The AES-GCM decryption fails
#[inline]
pub fn decrypt_hybrid(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    decrypt_hybrid_internal(ciphertext, kem_private_key, encapsulated_key, symmetric_key)
}

/// Encrypt data using hybrid encryption with configuration.
///
/// # Example
///
/// ```rust,ignore
/// let result = encrypt_hybrid_with_config(
///     data,
///     None,
///     &key,
///     &config,
///     SecurityMode::Verified(&session),
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The configuration validation fails
/// - The data size exceeds resource limits
/// - The encryption operation fails
#[inline]
pub fn encrypt_hybrid_with_config(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<HybridEncryptionResult> {
    mode.validate()?;
    config.validate()?;
    encrypt_hybrid_internal(data, kem_public_key, symmetric_key)
}

/// Decrypt data using hybrid encryption with configuration.
///
/// # Example
///
/// ```rust,ignore
/// let plaintext = decrypt_hybrid_with_config(
///     ciphertext,
///     Some(&private_key),
///     &encapsulated_key,
///     &symmetric_key,
///     &config,
///     SecurityMode::Verified(&session),
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The configuration validation fails
/// - The ciphertext size exceeds resource limits
/// - The decryption operation fails
#[inline]
pub fn decrypt_hybrid_with_config(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    decrypt_hybrid_internal(ciphertext, kem_private_key, encapsulated_key, symmetric_key)
}

// ============================================================================
// Unverified API (Opt-Out Functions)
// ============================================================================
// These functions provide opt-out variants for scenarios where Zero Trust
// verification is not required or not possible.

/// Encrypt data using hybrid encryption (KEM + AES-GCM) without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The data size exceeds resource limits
/// - The symmetric key is less than 32 bytes
/// - The KEM public key length does not match a valid ML-KEM security level
/// - The KEM encapsulation operation fails
/// - The AES-GCM encryption fails
#[inline]
pub fn encrypt_hybrid_unverified(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
) -> Result<HybridEncryptionResult> {
    encrypt_hybrid(data, kem_public_key, symmetric_key, SecurityMode::Unverified)
}

/// Decrypt data using hybrid encryption (KEM + AES-GCM) without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The ciphertext size exceeds resource limits
/// - The KEM private key length does not match a valid ML-KEM security level
/// - The encapsulated key is too short for the security level
/// - The KEM decapsulation operation fails
/// - The resulting symmetric key is less than 32 bytes
/// - The AES-GCM decryption fails
#[inline]
pub fn decrypt_hybrid_unverified(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
) -> Result<Vec<u8>> {
    decrypt_hybrid(
        ciphertext,
        kem_private_key,
        encapsulated_key,
        symmetric_key,
        SecurityMode::Unverified,
    )
}

/// Encrypt data using hybrid encryption with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The data size exceeds resource limits
/// - The symmetric key is less than 32 bytes
/// - The KEM public key length does not match a valid ML-KEM security level
/// - The KEM encapsulation operation fails
/// - The AES-GCM encryption fails
#[inline]
pub fn encrypt_hybrid_with_config_unverified(
    data: &[u8],
    kem_public_key: Option<&[u8]>,
    symmetric_key: &[u8],
    config: &CoreConfig,
) -> Result<HybridEncryptionResult> {
    encrypt_hybrid_with_config(
        data,
        kem_public_key,
        symmetric_key,
        config,
        SecurityMode::Unverified,
    )
}

/// Decrypt data using hybrid encryption with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The ciphertext size exceeds resource limits
/// - The KEM private key length does not match a valid ML-KEM security level
/// - The encapsulated key is too short for the security level
/// - The KEM decapsulation operation fails
/// - The resulting symmetric key is less than 32 bytes
/// - The AES-GCM decryption fails
#[inline]
pub fn decrypt_hybrid_with_config_unverified(
    ciphertext: &[u8],
    kem_private_key: Option<&[u8]>,
    encapsulated_key: &[u8],
    symmetric_key: &[u8],
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    decrypt_hybrid_with_config(
        ciphertext,
        kem_private_key,
        encapsulated_key,
        symmetric_key,
        config,
        SecurityMode::Unverified,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CoreConfig;

    // Helper to generate a valid AES-256 key (32 bytes)
    fn generate_test_symmetric_key() -> Vec<u8> {
        vec![0x42; 32]
    }

    // ============================================================================
    // Pure Symmetric Mode Tests (No KEM) - Full Roundtrip
    // ============================================================================

    #[test]
    fn test_hybrid_pure_symmetric_roundtrip() -> Result<()> {
        let message = b"Test message for pure symmetric hybrid encryption";
        let symmetric_key = generate_test_symmetric_key();

        // Encrypt without KEM (pure AES-GCM mode)
        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // Encapsulated key should be empty for pure symmetric
        assert!(
            result.encapsulated_key.is_empty(),
            "Pure symmetric mode should have empty encapsulated key"
        );
        assert!(!result.ciphertext.is_empty(), "Ciphertext should not be empty");

        // Decrypt
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "Decrypted plaintext should match original");
        Ok(())
    }

    #[test]
    fn test_hybrid_pure_symmetric_empty_message() -> Result<()> {
        let message = b"";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "Empty message should roundtrip");
        Ok(())
    }

    #[test]
    fn test_hybrid_pure_symmetric_large_message() -> Result<()> {
        let message = vec![0xAB; 10_000]; // 10KB
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(&message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "Large message should roundtrip");
        Ok(())
    }

    #[test]
    fn test_hybrid_pure_symmetric_binary_data() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(&message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "Binary data should roundtrip");
        Ok(())
    }

    #[test]
    fn test_hybrid_pure_symmetric_non_deterministic() -> Result<()> {
        let message = b"Same message encrypted twice";
        let symmetric_key = generate_test_symmetric_key();

        let result1 = encrypt_hybrid_unverified(message, None, &symmetric_key)?;
        let result2 = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // Due to random nonce in AES-GCM, ciphertexts should differ
        assert_ne!(
            result1.ciphertext, result2.ciphertext,
            "Encryption should be non-deterministic"
        );

        // Both should decrypt to same plaintext
        let plaintext1 = decrypt_hybrid_unverified(&result1.ciphertext, None, &[], &symmetric_key)?;
        let plaintext2 = decrypt_hybrid_unverified(&result2.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext1, message);
        assert_eq!(plaintext2, message);
        Ok(())
    }

    // ============================================================================
    // SecurityMode Tests
    // ============================================================================

    #[test]
    fn test_hybrid_with_unverified_mode() -> Result<()> {
        let message = b"Test with SecurityMode::Unverified";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid(message, None, &symmetric_key, SecurityMode::Unverified)?;
        let plaintext = decrypt_hybrid(
            &result.ciphertext,
            None,
            &[],
            &symmetric_key,
            SecurityMode::Unverified,
        )?;

        assert_eq!(plaintext, message);
        Ok(())
    }

    #[test]
    fn test_hybrid_with_config() -> Result<()> {
        let message = b"Test with CoreConfig";
        let symmetric_key = generate_test_symmetric_key();
        let config = CoreConfig::default();

        let result = encrypt_hybrid_with_config_unverified(message, None, &symmetric_key, &config)?;
        let plaintext = decrypt_hybrid_with_config_unverified(
            &result.ciphertext,
            None,
            &[],
            &symmetric_key,
            &config,
        )?;

        assert_eq!(plaintext, message);
        Ok(())
    }

    #[test]
    fn test_hybrid_with_config_and_mode() -> Result<()> {
        let message = b"Test with both config and SecurityMode";
        let symmetric_key = generate_test_symmetric_key();
        let config = CoreConfig::default();

        let result = encrypt_hybrid_with_config(
            message,
            None,
            &symmetric_key,
            &config,
            SecurityMode::Unverified,
        )?;
        let plaintext = decrypt_hybrid_with_config(
            &result.ciphertext,
            None,
            &[],
            &symmetric_key,
            &config,
            SecurityMode::Unverified,
        )?;

        assert_eq!(plaintext, message);
        Ok(())
    }

    // ============================================================================
    // Error Handling Tests
    // ============================================================================

    #[test]
    fn test_hybrid_encrypt_symmetric_key_too_short() {
        let message = b"Test message";
        let short_key = vec![0x42; 16]; // Only 16 bytes, need at least 32

        let result = encrypt_hybrid_unverified(message, None, &short_key);
        assert!(result.is_err(), "Short symmetric key should fail");

        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => {
                assert!(msg.contains("32 bytes"), "Error should mention required key size");
            }
            other => panic!("Expected InvalidInput error, got: {:?}", other),
        }
    }

    #[test]
    fn test_hybrid_decrypt_symmetric_key_too_short() -> Result<()> {
        let message = b"Test";
        let symmetric_key = generate_test_symmetric_key();

        // Encrypt with valid key
        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // Try to decrypt with short key
        let short_key = vec![0x42; 16];
        let decrypt_result = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &short_key);

        assert!(decrypt_result.is_err(), "Decryption with short key should fail");
        Ok(())
    }

    #[test]
    fn test_hybrid_encrypt_symmetric_key_exactly_32_bytes() -> Result<()> {
        let message = b"Test with minimum key size";
        let symmetric_key = vec![0x42; 32]; // Exactly 32 bytes

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "Exactly 32-byte key should work");
        Ok(())
    }

    #[test]
    fn test_hybrid_encrypt_symmetric_key_larger_than_32_bytes() -> Result<()> {
        let message = b"Test with larger key size";
        let symmetric_key = vec![0x42; 64]; // 64 bytes

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "Larger key should work");
        Ok(())
    }

    #[test]
    fn test_hybrid_decrypt_tampered_ciphertext_fails() -> Result<()> {
        let message = b"Original message";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // Tamper with ciphertext
        let mut tampered = result.ciphertext.clone();
        if !tampered.is_empty() {
            tampered[0] ^= 0xFF;
        }

        let decrypt_result = decrypt_hybrid_unverified(&tampered, None, &[], &symmetric_key);
        assert!(decrypt_result.is_err(), "Tampered ciphertext should fail decryption");

        match decrypt_result.unwrap_err() {
            CoreError::DecryptionFailed(_) => {} // Expected
            other => panic!("Expected DecryptionFailed error, got: {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_hybrid_decrypt_wrong_symmetric_key_fails() -> Result<()> {
        let message = b"Original message";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // Use different key
        let wrong_key = vec![0xFF; 32];
        let decrypt_result = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &wrong_key);

        assert!(decrypt_result.is_err(), "Wrong symmetric key should fail decryption");
        Ok(())
    }

    #[test]
    fn test_hybrid_decrypt_truncated_ciphertext_fails() -> Result<()> {
        let message = b"Original message";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // Truncate ciphertext
        let truncated = if result.ciphertext.len() > 5 {
            &result.ciphertext[..result.ciphertext.len() - 5]
        } else {
            &[]
        };

        let decrypt_result = decrypt_hybrid_unverified(truncated, None, &[], &symmetric_key);
        assert!(decrypt_result.is_err(), "Truncated ciphertext should fail");
        Ok(())
    }

    #[test]
    fn test_hybrid_decrypt_empty_ciphertext_fails() {
        let symmetric_key = generate_test_symmetric_key();

        let result = decrypt_hybrid_unverified(&[], None, &[], &symmetric_key);
        assert!(result.is_err(), "Empty ciphertext should fail decryption");
    }

    #[test]
    fn test_hybrid_invalid_kem_public_key_length() {
        let message = b"Test message";
        let symmetric_key = generate_test_symmetric_key();

        // Invalid public key length (not 800, 1184, or 1568)
        let invalid_pk = vec![0u8; 100];

        let result = encrypt_hybrid_unverified(message, Some(&invalid_pk), &symmetric_key);
        assert!(result.is_err(), "Invalid KEM public key length should fail");

        match result.unwrap_err() {
            CoreError::InvalidKeyLength { .. } => {} // Expected
            other => panic!("Expected InvalidKeyLength error, got: {:?}", other),
        }
    }

    // ============================================================================
    // ML-KEM Encryption Tests (Encryption Only - No Decryption Due to FIPS)
    // ============================================================================

    #[test]
    fn test_hybrid_mlkem512_encryption_only() -> Result<()> {
        let message = b"Test ML-KEM-512 encryption";
        let symmetric_key = generate_test_symmetric_key();

        // Generate ML-KEM-512 keypair
        let (kem_public_key, _kem_private_key) =
            generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512)?;

        // Encryption should succeed
        let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)?;

        // Verify encapsulated key size for ML-KEM-512
        assert_eq!(
            result.encapsulated_key.len(),
            768,
            "ML-KEM-512 encapsulated key should be 768 bytes"
        );
        assert!(!result.ciphertext.is_empty(), "Ciphertext should not be empty");

        // Note: Cannot test decryption due to FIPS 140-3 limitation
        Ok(())
    }

    #[test]
    fn test_hybrid_mlkem768_encryption_only() -> Result<()> {
        let message = b"Test ML-KEM-768 encryption";
        let symmetric_key = generate_test_symmetric_key();

        let (kem_public_key, _) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)?;

        assert_eq!(
            result.encapsulated_key.len(),
            1088,
            "ML-KEM-768 encapsulated key should be 1088 bytes"
        );
        Ok(())
    }

    #[test]
    fn test_hybrid_mlkem1024_encryption_only() -> Result<()> {
        let message = b"Test ML-KEM-1024 encryption";
        let symmetric_key = generate_test_symmetric_key();

        let (kem_public_key, _) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024)?;
        let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)?;

        assert_eq!(
            result.encapsulated_key.len(),
            1568,
            "ML-KEM-1024 encapsulated key should be 1568 bytes"
        );
        Ok(())
    }

    #[test]
    fn test_hybrid_mlkem_encryption_non_deterministic() -> Result<()> {
        let message = b"Same message";
        let symmetric_key = generate_test_symmetric_key();

        let (kem_public_key, _) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let result1 = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)?;
        let result2 = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)?;

        // Encapsulated keys should differ due to KEM randomness
        assert_ne!(
            result1.encapsulated_key, result2.encapsulated_key,
            "Encapsulated keys should be non-deterministic"
        );
        assert_ne!(
            result1.ciphertext, result2.ciphertext,
            "Ciphertexts should be non-deterministic"
        );
        Ok(())
    }

    // ============================================================================
    // Multiple Message Tests
    // ============================================================================

    #[test]
    fn test_hybrid_multiple_sequential_encryptions() -> Result<()> {
        let symmetric_key = generate_test_symmetric_key();

        for i in 0..10 {
            let message = format!("Message number {}", i);

            let result = encrypt_hybrid_unverified(message.as_bytes(), None, &symmetric_key)?;
            let plaintext =
                decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

            assert_eq!(plaintext, message.as_bytes(), "Message {} should roundtrip correctly", i);
        }
        Ok(())
    }

    #[test]
    fn test_hybrid_multiple_messages_same_key() -> Result<()> {
        let symmetric_key = generate_test_symmetric_key();

        let msg1 = b"First message";
        let msg2 = b"Second message";
        let msg3 = b"Third message";

        let result1 = encrypt_hybrid_unverified(msg1, None, &symmetric_key)?;
        let result2 = encrypt_hybrid_unverified(msg2, None, &symmetric_key)?;
        let result3 = encrypt_hybrid_unverified(msg3, None, &symmetric_key)?;

        let plaintext1 = decrypt_hybrid_unverified(&result1.ciphertext, None, &[], &symmetric_key)?;
        let plaintext2 = decrypt_hybrid_unverified(&result2.ciphertext, None, &[], &symmetric_key)?;
        let plaintext3 = decrypt_hybrid_unverified(&result3.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext1, msg1);
        assert_eq!(plaintext2, msg2);
        assert_eq!(plaintext3, msg3);
        Ok(())
    }

    // ============================================================================
    // Internal Function Tests
    // ============================================================================

    #[test]
    fn test_encrypt_hybrid_internal() -> Result<()> {
        let message = b"Test internal encryption";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_internal(message, None, &symmetric_key)?;

        assert!(result.encapsulated_key.is_empty());
        assert!(!result.ciphertext.is_empty());
        Ok(())
    }

    #[test]
    fn test_decrypt_hybrid_internal() -> Result<()> {
        let message = b"Test internal decryption";
        let symmetric_key = generate_test_symmetric_key();

        let encrypted = encrypt_hybrid_internal(message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_internal(&encrypted.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message);
        Ok(())
    }

    #[test]
    fn test_encrypt_hybrid_aes_gcm() -> Result<()> {
        let message = b"Test encrypt_hybrid_aes_gcm";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_aes_gcm(message, None, &symmetric_key)?;

        assert!(result.encapsulated_key.is_empty());
        assert!(!result.ciphertext.is_empty());
        Ok(())
    }

    #[test]
    fn test_decrypt_hybrid_aes_gcm() -> Result<()> {
        let message = b"Test decrypt_hybrid_aes_gcm";
        let symmetric_key = generate_test_symmetric_key();

        let encrypted = encrypt_hybrid_aes_gcm(message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_aes_gcm(&encrypted.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message);
        Ok(())
    }

    #[test]
    fn test_encrypt_hybrid_kem_encapsulate_pure_symmetric() -> Result<()> {
        let message = b"Test encrypt_hybrid_kem_encapsulate without KEM";
        let symmetric_key = generate_test_symmetric_key();

        // Pure symmetric mode (no KEM security level)
        let ciphertext = encrypt_hybrid_kem_encapsulate(message, &symmetric_key, None)?;

        assert!(!ciphertext.is_empty());
        Ok(())
    }

    #[test]
    fn test_encrypt_hybrid_kem_encapsulate_short_key_fails() {
        let message = b"Test";
        let short_key = vec![0x42; 16]; // Less than 32 bytes

        let result = encrypt_hybrid_kem_encapsulate(message, &short_key, None);
        assert!(result.is_err(), "Short symmetric key should fail");

        match result.unwrap_err() {
            CoreError::InvalidInput(msg) => {
                assert!(msg.contains("32 bytes"));
            }
            other => panic!("Expected InvalidInput, got: {:?}", other),
        }
    }

    // ============================================================================
    // Edge Cases
    // ============================================================================

    #[test]
    fn test_hybrid_ciphertext_overhead() -> Result<()> {
        let message = b"Test message";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // AES-GCM overhead: 12 bytes (nonce) + 16 bytes (tag) = 28 bytes
        let expected_min_size = message.len() + 28;
        assert_eq!(
            result.ciphertext.len(),
            expected_min_size,
            "Ciphertext should have 28-byte overhead for AES-GCM"
        );
        Ok(())
    }

    #[test]
    fn test_hybrid_result_structure() -> Result<()> {
        let message = b"Test HybridEncryptionResult structure";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(message, None, &symmetric_key)?;

        // Verify HybridEncryptionResult fields are accessible
        let _encap_key = &result.encapsulated_key;
        let _ciphertext = &result.ciphertext;

        assert!(result.encapsulated_key.is_empty());
        assert!(!result.ciphertext.is_empty());
        Ok(())
    }

    #[test]
    fn test_hybrid_unicode_message() -> Result<()> {
        let message = "こんにちは世界 🌍 مرحبا بالعالم";
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(message.as_bytes(), None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message.as_bytes(), "Unicode should roundtrip");
        Ok(())
    }

    #[test]
    fn test_hybrid_all_zero_bytes_message() -> Result<()> {
        let message = vec![0u8; 100];
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(&message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "All-zero bytes should roundtrip");
        Ok(())
    }

    #[test]
    fn test_hybrid_all_255_bytes_message() -> Result<()> {
        let message = vec![0xFFu8; 100];
        let symmetric_key = generate_test_symmetric_key();

        let result = encrypt_hybrid_unverified(&message, None, &symmetric_key)?;
        let plaintext = decrypt_hybrid_unverified(&result.ciphertext, None, &[], &symmetric_key)?;

        assert_eq!(plaintext, message, "All-255 bytes should roundtrip");
        Ok(())
    }
}
