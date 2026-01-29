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
