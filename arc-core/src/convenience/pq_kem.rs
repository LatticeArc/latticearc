//! Post-quantum KEM operations (ML-KEM)
//!
//! This module provides post-quantum key encapsulation mechanism operations
//! using ML-KEM (FIPS 203).
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//! - `SecurityMode::Verified(&session)`: Validates session before operation
//! - `SecurityMode::Unverified`: Skips session validation
//!
//! The `_unverified` variants are opt-out functions for scenarios where Zero Trust
//! verification is not required or not possible.

use arc_primitives::kem::ml_kem::{MlKem, MlKemCiphertext, MlKemSecretKey, MlKemSecurityLevel};

use super::aes_gcm::{decrypt_aes_gcm_internal, encrypt_aes_gcm_internal};
use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

use arc_validation::resource_limits::{validate_decryption_size, validate_encryption_size};

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of ML-KEM encryption.
fn encrypt_pq_ml_kem_internal(
    data: &[u8],
    ml_kem_pk: &[u8],
    security_level: MlKemSecurityLevel,
) -> Result<Vec<u8>> {
    crate::log_crypto_operation_start!(
        "encrypt_pq_ml_kem",
        security_level = ?security_level,
        data_len = data.len()
    );

    validate_encryption_size(data.len()).map_err(|e| {
        crate::log_crypto_operation_error!("encrypt_pq_ml_kem", "resource limit exceeded");
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let pk = arc_primitives::kem::ml_kem::MlKemPublicKey::new(security_level, ml_kem_pk.to_vec())
        .map_err(|e| {
        crate::log_crypto_operation_error!("encrypt_pq_ml_kem", "invalid public key");
        CoreError::InvalidInput(format!("Invalid ML-KEM public key: {}", e))
    })?;

    let mut rng = rand::rngs::OsRng;
    let (shared_secret, ciphertext) = MlKem::encapsulate(&mut rng, &pk).map_err(|e| {
        crate::log_crypto_operation_error!("encrypt_pq_ml_kem", "encapsulation failed");
        CoreError::EncryptionFailed(format!("ML-KEM encapsulation failed: {}", e))
    })?;

    // Use shared secret to encrypt data with AES-GCM
    let symmetric_key = shared_secret.as_bytes();
    let encrypted_data = encrypt_aes_gcm_internal(data, symmetric_key)?;

    // Combine ciphertext and encrypted data
    let mut result = ciphertext.into_bytes();
    result.extend_from_slice(&encrypted_data);

    crate::log_crypto_operation_complete!(
        "encrypt_pq_ml_kem",
        security_level = ?security_level,
        result_len = result.len()
    );

    Ok(result)
}

/// Internal implementation of ML-KEM decryption.
fn decrypt_pq_ml_kem_internal(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
) -> Result<Vec<u8>> {
    crate::log_crypto_operation_start!(
        "decrypt_pq_ml_kem",
        security_level = ?security_level,
        encrypted_len = encrypted_data.len()
    );

    validate_decryption_size(encrypted_data.len()).map_err(|e| {
        crate::log_crypto_operation_error!("decrypt_pq_ml_kem", "resource limit exceeded");
        CoreError::ResourceExceeded(e.to_string())
    })?;

    // Parse the combined data: ciphertext + encrypted_payload
    let ciphertext_size = match security_level {
        MlKemSecurityLevel::MlKem512 => 768,
        MlKemSecurityLevel::MlKem768 => 1088,
        MlKemSecurityLevel::MlKem1024 => 1568,
    };

    if encrypted_data.len() < ciphertext_size {
        crate::log_crypto_operation_error!("decrypt_pq_ml_kem", "encrypted data too short");
        return Err(CoreError::InvalidInput("Encrypted data too short".to_string()));
    }

    let (ciphertext_bytes, encrypted_payload) = encrypted_data.split_at(ciphertext_size);

    let ciphertext =
        MlKemCiphertext::new(security_level, ciphertext_bytes.to_vec()).map_err(|e| {
            crate::log_crypto_operation_error!("decrypt_pq_ml_kem", "invalid ciphertext");
            CoreError::InvalidInput(format!("Invalid ML-KEM ciphertext: {}", e))
        })?;

    let sk = MlKemSecretKey::new(security_level, ml_kem_sk.to_vec()).map_err(|e| {
        crate::log_crypto_operation_error!("decrypt_pq_ml_kem", "invalid private key");
        CoreError::InvalidInput(format!("Invalid ML-KEM private key: {}", e))
    })?;

    let shared_secret = MlKem::decapsulate(&sk, &ciphertext).map_err(|e| {
        crate::log_crypto_operation_error!("decrypt_pq_ml_kem", "decapsulation failed");
        CoreError::DecryptionFailed(format!("ML-KEM decapsulation failed: {}", e))
    })?;

    // Decrypt payload with shared secret
    let result = decrypt_aes_gcm_internal(encrypted_payload, shared_secret.as_bytes())?;

    crate::log_crypto_operation_complete!(
        "decrypt_pq_ml_kem",
        security_level = ?security_level,
        result_len = result.len()
    );

    Ok(result)
}

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

/// Encrypt data using ML-KEM.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before encryption
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{encrypt_pq_ml_kem, SecurityMode, VerifiedSession};
/// use arc_primitives::kem::ml_kem::MlKemSecurityLevel;
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let encrypted = encrypt_pq_ml_kem(data, &ml_kem_pk, MlKemSecurityLevel::MlKem768, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let encrypted = encrypt_pq_ml_kem(data, &ml_kem_pk, MlKemSecurityLevel::MlKem768, SecurityMode::Unverified)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The data size exceeds resource limits
/// - The public key is invalid for the specified security level
/// - The ML-KEM encapsulation operation fails
/// - The AES-GCM encryption of the payload fails
pub fn encrypt_pq_ml_kem(
    data: &[u8],
    ml_kem_pk: &[u8],
    security_level: MlKemSecurityLevel,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    encrypt_pq_ml_kem_internal(data, ml_kem_pk, security_level)
}

/// Decrypt data using ML-KEM.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before decryption
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{decrypt_pq_ml_kem, SecurityMode, VerifiedSession};
/// use arc_primitives::kem::ml_kem::MlKemSecurityLevel;
///
/// // With Zero Trust (recommended)
/// let decrypted = decrypt_pq_ml_kem(&encrypted, &ml_kem_sk, MlKemSecurityLevel::MlKem768, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let decrypted = decrypt_pq_ml_kem(&encrypted, &ml_kem_sk, MlKemSecurityLevel::MlKem768, SecurityMode::Unverified)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The encrypted data size exceeds resource limits
/// - The encrypted data is shorter than the expected ciphertext size
/// - The ciphertext is invalid for the specified security level
/// - The private key is invalid
/// - The ML-KEM decapsulation operation fails
/// - The AES-GCM decryption of the payload fails
pub fn decrypt_pq_ml_kem(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    decrypt_pq_ml_kem_internal(encrypted_data, ml_kem_sk, security_level)
}

/// Encrypt data using ML-KEM with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired
/// - The configuration validation fails
/// - The data size exceeds resource limits
/// - The public key is invalid for the specified security level
/// - The ML-KEM encapsulation operation fails
pub fn encrypt_pq_ml_kem_with_config(
    data: &[u8],
    ml_kem_pk: &[u8],
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    encrypt_pq_ml_kem_internal(data, ml_kem_pk, security_level)
}

/// Decrypt data using ML-KEM with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired
/// - The configuration validation fails
/// - The encrypted data size exceeds resource limits
/// - The ML-KEM decapsulation operation fails
pub fn decrypt_pq_ml_kem_with_config(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    decrypt_pq_ml_kem_internal(encrypted_data, ml_kem_sk, security_level)
}

// ============================================================================
// Unverified API (opt-out functions for scenarios where Zero Trust is not required)
// ============================================================================

/// Encrypt data using ML-KEM without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The data size exceeds resource limits
/// - The public key is invalid for the specified security level
/// - The ML-KEM encapsulation operation fails
/// - The AES-GCM encryption of the payload fails
pub fn encrypt_pq_ml_kem_unverified(
    data: &[u8],
    ml_kem_pk: &[u8],
    security_level: MlKemSecurityLevel,
) -> Result<Vec<u8>> {
    encrypt_pq_ml_kem(data, ml_kem_pk, security_level, SecurityMode::Unverified)
}

/// Decrypt data using ML-KEM without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted data size exceeds resource limits
/// - The encrypted data is shorter than the expected ciphertext size
/// - The ciphertext is invalid for the specified security level
/// - The private key is invalid
/// - The ML-KEM decapsulation operation fails
/// - The AES-GCM decryption of the payload fails
pub fn decrypt_pq_ml_kem_unverified(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
) -> Result<Vec<u8>> {
    decrypt_pq_ml_kem(encrypted_data, ml_kem_sk, security_level, SecurityMode::Unverified)
}

/// Encrypt data using ML-KEM with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The data size exceeds resource limits
/// - The public key is invalid for the specified security level
/// - The ML-KEM encapsulation operation fails
/// - The AES-GCM encryption of the payload fails
pub fn encrypt_pq_ml_kem_with_config_unverified(
    data: &[u8],
    ml_kem_pk: &[u8],
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    encrypt_pq_ml_kem_with_config(data, ml_kem_pk, security_level, config, SecurityMode::Unverified)
}

/// Decrypt data using ML-KEM with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not required
/// or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The encrypted data size exceeds resource limits
/// - The encrypted data is shorter than the expected ciphertext size
/// - The ciphertext is invalid for the specified security level
/// - The private key is invalid
/// - The ML-KEM decapsulation operation fails
/// - The AES-GCM decryption of the payload fails
pub fn decrypt_pq_ml_kem_with_config_unverified(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    decrypt_pq_ml_kem_with_config(
        encrypted_data,
        ml_kem_sk,
        security_level,
        config,
        SecurityMode::Unverified,
    )
}
