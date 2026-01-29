//! High-level encryption, decryption, signing, and verification API.
//!
//! Provides convenient functions for common cryptographic operations with
//! automatic scheme selection and configuration.
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! ```rust,ignore
//! use arc_core::{encrypt, decrypt, SecurityMode, VerifiedSession};
//!
//! // With Zero Trust verification (recommended)
//! let session = VerifiedSession::establish(&pk, &sk)?;
//! let encrypted = encrypt(data, &key, SecurityMode::Verified(&session))?;
//!
//! // Without verification (opt-out)
//! let encrypted = encrypt(data, &key, SecurityMode::Unverified)?;
//! ```
//!
//! ## Enterprise Behavior
//!
//! In enterprise deployments:
//! - `Verified`: Enables policy enforcement, continuous verification
//! - `Unverified`: Triggers mandatory audit trail; may be blocked by policy

use chrono::Utc;
use tracing::warn;

use arc_primitives::{
    kem::ml_kem::MlKemSecurityLevel,
    sig::{ml_dsa::MlDsaParameterSet, slh_dsa::SecurityLevel as SlhDsaSecurityLevel},
};

use crate::{
    config::{EncryptionConfig, SignatureConfig},
    error::{CoreError, Result},
    traits::SchemeSelector,
    types::{CryptoContext, EncryptedData, EncryptedMetadata, SignedData, SignedMetadata, UseCase},
    zero_trust::SecurityMode,
};

use super::aes_gcm::{decrypt_aes_gcm_internal, encrypt_aes_gcm_internal};
use super::ed25519::{sign_ed25519_internal, verify_ed25519_internal};
use super::hybrid::{decrypt_hybrid_kem_decapsulate, encrypt_hybrid_kem_encapsulate};
use super::keygen::{
    generate_fn_dsa_keypair, generate_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair,
};
// These deprecated imports are needed to implement the deprecated public API
#[allow(deprecated)]
use super::pq_kem::{decrypt_pq_ml_kem_unverified, encrypt_pq_ml_kem_unverified};
#[allow(deprecated)]
use super::pq_sig::{
    sign_pq_fn_dsa_unverified, sign_pq_ml_dsa_unverified, sign_pq_slh_dsa_unverified,
    verify_pq_fn_dsa_unverified, verify_pq_ml_dsa_unverified, verify_pq_slh_dsa_unverified,
};

use arc_validation::resource_limits::{
    validate_decryption_size, validate_encryption_size, validate_signature_size,
};

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of encryption with config.
#[allow(deprecated)]
fn encrypt_with_config_internal(
    data: &[u8],
    config: &EncryptionConfig,
    key: &[u8],
) -> Result<EncryptedData> {
    validate_encryption_size(data.len()).map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;
    config.validate()?;

    // If a preferred scheme is explicitly set, use it directly
    // This allows callers to explicitly request symmetric encryption
    let scheme = if let Some(ref preferred) = config.preferred_scheme {
        crate::selector::CryptoPolicyEngine::force_scheme(preferred)
    } else {
        // Use automatic selection based on context
        let selector = crate::selector::CryptoPolicyEngine::new();
        let ctx = CryptoContext {
            security_level: config.base.security_level.clone(),
            performance_preference: config.base.performance_preference.clone(),
            use_case: None,
            hardware_acceleration: config.base.hardware_acceleration,
            timestamp: Utc::now(),
        };
        selector.select_encryption_scheme(data, &ctx)?
    };

    crate::log_crypto_operation_start!("encrypt", scheme = %scheme, data_size = data.len());

    // SECURITY: Reject symmetric keys when PQ/hybrid scheme is selected
    // Silent downgrade from PQ to classical would be a critical security issue
    if key.len() == 32 && scheme != "aes-256-gcm" && scheme != "chacha20-poly1305" {
        match scheme.as_str() {
            "ml-kem-512"
            | "ml-kem-768"
            | "ml-kem-1024"
            | "hybrid-ml-kem-512-aes-256-gcm"
            | "hybrid-ml-kem-768-aes-256-gcm"
            | "hybrid-ml-kem-1024-aes-256-gcm" => {
                return Err(CoreError::InvalidKey(format!(
                    "Post-quantum scheme '{}' requires a public key, but a 32-byte symmetric key was provided. \
                     Use 'aes-256-gcm' scheme for symmetric encryption or provide the correct public key.",
                    scheme
                )));
            }
            _ => {
                // Log unknown schemes for debugging
                warn!("Unknown encryption scheme '{}' with 32-byte key", scheme);
            }
        }
    }

    let encrypted = match scheme.as_str() {
        "ml-kem-512" => encrypt_pq_ml_kem_unverified(data, key, MlKemSecurityLevel::MlKem512)?,
        "ml-kem-768" => encrypt_pq_ml_kem_unverified(data, key, MlKemSecurityLevel::MlKem768)?,
        "ml-kem-1024" => encrypt_pq_ml_kem_unverified(data, key, MlKemSecurityLevel::MlKem1024)?,
        "hybrid-ml-kem-512-aes-256-gcm" => {
            encrypt_hybrid_kem_encapsulate(data, key, Some(MlKemSecurityLevel::MlKem512))?
        }
        "hybrid-ml-kem-768-aes-256-gcm" => {
            encrypt_hybrid_kem_encapsulate(data, key, Some(MlKemSecurityLevel::MlKem768))?
        }
        "hybrid-ml-kem-1024-aes-256-gcm" => {
            encrypt_hybrid_kem_encapsulate(data, key, Some(MlKemSecurityLevel::MlKem1024))?
        }
        _ => {
            // Default to AES-GCM for classical schemes
            if key.len() < 32 {
                return Err(CoreError::InvalidKeyLength { expected: 32, actual: key.len() });
            }
            if data.is_empty() { data.to_vec() } else { encrypt_aes_gcm_internal(data, key)? }
        }
    };

    let nonce = encrypted.get(..12).map_or_else(Vec::new, <[u8]>::to_vec);
    let tag = encrypted
        .len()
        .checked_sub(16)
        .and_then(|start| encrypted.get(start..))
        .filter(|_| encrypted.len() >= 28)
        .map_or_else(Vec::new, <[u8]>::to_vec);

    // Convert timestamp safely: timestamps after 1970 are always positive
    let timestamp = u64::try_from(Utc::now().timestamp()).unwrap_or(0);

    crate::log_crypto_operation_complete!("encrypt", result_size = encrypted.len(), scheme = %scheme);

    Ok(EncryptedData {
        data: encrypted,
        metadata: EncryptedMetadata { nonce, tag: Some(tag), key_id: None },
        scheme,
        timestamp,
    })
}

/// Internal implementation of decryption.
fn decrypt_internal(encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>> {
    crate::log_crypto_operation_start!("decrypt", scheme = %encrypted.scheme, data_size = encrypted.data.len());

    if encrypted.data.is_empty() {
        crate::log_crypto_operation_complete!("decrypt", result_size = 0_usize);
        return Ok(encrypted.data.clone());
    }

    validate_decryption_size(encrypted.data.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    if key.len() < 32 {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: key.len() };
        crate::log_crypto_operation_error!("decrypt", err);
        return Err(err);
    }

    match decrypt_aes_gcm_internal(&encrypted.data, key) {
        Ok(plaintext) => {
            crate::log_crypto_operation_complete!("decrypt", result_size = plaintext.len());
            Ok(plaintext)
        }
        Err(e) => {
            crate::log_crypto_operation_error!("decrypt", e);
            Err(e)
        }
    }
}

/// Internal implementation of decryption with config.
#[allow(deprecated)]
fn decrypt_with_config_internal(
    encrypted: &EncryptedData,
    _config: &EncryptionConfig,
    key: &[u8],
) -> Result<Vec<u8>> {
    crate::log_crypto_operation_start!("decrypt", scheme = %encrypted.scheme, data_size = encrypted.data.len());

    validate_decryption_size(encrypted.data.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    let result = match encrypted.scheme.as_str() {
        "ml-kem-512" => {
            decrypt_pq_ml_kem_unverified(&encrypted.data, key, MlKemSecurityLevel::MlKem512)
        }
        "ml-kem-768" => {
            decrypt_pq_ml_kem_unverified(&encrypted.data, key, MlKemSecurityLevel::MlKem768)
        }
        "ml-kem-1024" => {
            decrypt_pq_ml_kem_unverified(&encrypted.data, key, MlKemSecurityLevel::MlKem1024)
        }
        "hybrid-ml-kem-512-aes-256-gcm" => {
            decrypt_hybrid_kem_decapsulate(&encrypted.data, key, MlKemSecurityLevel::MlKem512)
        }
        "hybrid-ml-kem-768-aes-256-gcm" => {
            decrypt_hybrid_kem_decapsulate(&encrypted.data, key, MlKemSecurityLevel::MlKem768)
        }
        "hybrid-ml-kem-1024-aes-256-gcm" => {
            decrypt_hybrid_kem_decapsulate(&encrypted.data, key, MlKemSecurityLevel::MlKem1024)
        }
        _ => decrypt_internal(encrypted, key),
    };

    match result {
        Ok(plaintext) => {
            crate::log_crypto_operation_complete!("decrypt", result_size = plaintext.len(), scheme = %encrypted.scheme);
            Ok(plaintext)
        }
        Err(e) => {
            crate::log_crypto_operation_error!("decrypt", e, scheme = %encrypted.scheme);
            Err(e)
        }
    }
}

/// Internal implementation of signing with config.
#[allow(deprecated)]
fn sign_with_config_internal(message: &[u8], config: &SignatureConfig) -> Result<SignedData> {
    validate_signature_size(message.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;
    config.validate()?;

    let selector = crate::selector::CryptoPolicyEngine::new();
    let ctx = CryptoContext {
        security_level: config.base.security_level.clone(),
        performance_preference: config.base.performance_preference.clone(),
        use_case: None,
        hardware_acceleration: config.base.hardware_acceleration,
        timestamp: Utc::now(),
    };
    let scheme = selector.select_signature_scheme(&ctx)?;

    crate::log_crypto_operation_start!("sign", scheme = %scheme, message_size = message.len());

    let (public_key, _private_key, signature) = match scheme.as_str() {
        "ml-dsa-44" => {
            let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;
            let sig =
                sign_pq_ml_dsa_unverified(message, sk.as_slice(), MlDsaParameterSet::MLDSA44)?;
            (pk, sk, sig)
        }
        "ml-dsa-65" => {
            let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
            let sig =
                sign_pq_ml_dsa_unverified(message, sk.as_slice(), MlDsaParameterSet::MLDSA65)?;
            (pk, sk, sig)
        }
        "ml-dsa-87" => {
            let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;
            let sig =
                sign_pq_ml_dsa_unverified(message, sk.as_slice(), MlDsaParameterSet::MLDSA87)?;
            (pk, sk, sig)
        }
        "slh-dsa-shake-128s" => {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
            let sig =
                sign_pq_slh_dsa_unverified(message, sk.as_slice(), SlhDsaSecurityLevel::Shake128s)?;
            (pk, sk, sig)
        }
        "slh-dsa-shake-192s" => {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;
            let sig =
                sign_pq_slh_dsa_unverified(message, sk.as_slice(), SlhDsaSecurityLevel::Shake192s)?;
            (pk, sk, sig)
        }
        "slh-dsa-shake-256s" => {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;
            let sig =
                sign_pq_slh_dsa_unverified(message, sk.as_slice(), SlhDsaSecurityLevel::Shake256s)?;
            (pk, sk, sig)
        }
        "fn-dsa" => {
            let (pk, sk) = generate_fn_dsa_keypair()?;
            let sig = sign_pq_fn_dsa_unverified(message, sk.as_slice())?;
            (pk, sk, sig)
        }
        "ml-dsa-65-hybrid-ed25519" => {
            // Hybrid: ML-DSA + Ed25519
            let (_pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
            let (pk, sk) = generate_keypair()?; // Ed25519
            let pq_sig =
                sign_pq_ml_dsa_unverified(message, pq_sk.as_slice(), MlDsaParameterSet::MLDSA65)?;
            let ed_sig = sign_ed25519_internal(message, sk.as_slice())?;
            let combined_sig = [pq_sig, ed_sig].concat();
            (pk, sk, combined_sig)
        }
        _ => {
            // Default to Ed25519 for classical schemes
            let (pk, sk) = generate_keypair()?;
            let sig = sign_ed25519_internal(message, sk.as_slice())?;
            (pk, sk, sig)
        }
    };

    // Convert timestamp safely: timestamps after 1970 are always positive
    let timestamp = u64::try_from(Utc::now().timestamp()).unwrap_or(0);

    crate::log_crypto_operation_complete!("sign", signature_size = signature.len(), scheme = %scheme);

    Ok(SignedData {
        data: message.to_vec(),
        metadata: SignedMetadata {
            signature,
            signature_algorithm: scheme.clone(),
            public_key,
            key_id: None,
        },
        scheme,
        timestamp,
    })
}

/// Internal implementation of verification with config.
#[allow(deprecated)]
fn verify_with_config_internal(
    message: &[u8],
    signed: &SignedData,
    _config: &SignatureConfig,
) -> Result<bool> {
    crate::log_crypto_operation_start!("verify", scheme = %signed.scheme, message_size = message.len());

    validate_signature_size(message.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;
    let result = match signed.scheme.as_str() {
        "ml-dsa-44" => verify_pq_ml_dsa_unverified(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA44,
        ),
        "ml-dsa-65" => verify_pq_ml_dsa_unverified(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA65,
        ),
        "ml-dsa-87" => verify_pq_ml_dsa_unverified(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA87,
        ),
        "slh-dsa-shake-128s" => verify_pq_slh_dsa_unverified(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            SlhDsaSecurityLevel::Shake128s,
        ),
        "slh-dsa-shake-192s" => verify_pq_slh_dsa_unverified(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            SlhDsaSecurityLevel::Shake192s,
        ),
        "slh-dsa-shake-256s" => verify_pq_slh_dsa_unverified(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            SlhDsaSecurityLevel::Shake256s,
        ),
        "fn-dsa" => verify_pq_fn_dsa_unverified(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
        ),
        "ml-dsa-65-hybrid-ed25519" => {
            // Verify hybrid signature: ML-DSA + Ed25519
            let sig_len = signed.metadata.signature.len();
            if sig_len < 3293 {
                // Minimum ML-DSA-65 signature size
                return Err(CoreError::InvalidInput("Hybrid signature too short".to_string()));
            }
            // Ed25519 signature is 64 bytes at the end
            // Use checked arithmetic to avoid overflow
            let pq_sig_len = sig_len.checked_sub(64).ok_or_else(|| {
                CoreError::InvalidInput(
                    "Hybrid signature too short for Ed25519 component".to_string(),
                )
            })?;
            let pq_sig = signed.metadata.signature.get(..pq_sig_len).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid signature format".to_string())
            })?;
            let ed_sig = signed.metadata.signature.get(pq_sig_len..).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid signature format".to_string())
            })?;
            let pq_valid = verify_pq_ml_dsa_unverified(
                message,
                pq_sig,
                &signed.metadata.public_key,
                MlDsaParameterSet::MLDSA65,
            )?;
            let ed_valid = verify_ed25519_internal(message, ed_sig, &signed.metadata.public_key)?;
            Ok(pq_valid && ed_valid)
        }
        _ => verify_ed25519_internal(
            message,
            &signed.metadata.signature,
            &signed.metadata.public_key,
        ),
    };

    match &result {
        Ok(valid) => {
            crate::log_crypto_operation_complete!("verify", valid = *valid, scheme = %signed.scheme);
        }
        Err(e) => {
            crate::log_crypto_operation_error!("verify", e, scheme = %signed.scheme);
        }
    }
    result
}

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

/// Encrypt data with default configuration.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before encryption
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{encrypt, SecurityMode, VerifiedSession, generate_keypair};
///
/// let (pk, sk) = generate_keypair()?;
/// let key = [0u8; 32];
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let encrypted = encrypt(b"secret", &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let encrypted = encrypt(b"secret", &key, SecurityMode::Unverified)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The data size exceeds resource limits
/// - Encryption with the selected scheme fails
#[inline]
pub fn encrypt(data: &[u8], key: &[u8], mode: SecurityMode) -> Result<EncryptedData> {
    mode.validate()?;
    encrypt_with_config_internal(data, &EncryptionConfig::default(), key)
}

/// Encrypt data with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The data size exceeds resource limits
/// - The configuration is invalid
/// - A post-quantum scheme is selected but a symmetric key is provided
/// - The key length is less than 32 bytes for symmetric encryption
/// - The encryption operation fails
pub fn encrypt_with_config(
    data: &[u8],
    config: &EncryptionConfig,
    key: &[u8],
    mode: SecurityMode,
) -> Result<EncryptedData> {
    mode.validate()?;
    encrypt_with_config_internal(data, config, key)
}

/// Decrypt data with default configuration.
///
/// # Example
///
/// ```rust,ignore
/// let decrypted = decrypt(&encrypted, &key, SecurityMode::Verified(&session))?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The encrypted data size exceeds resource limits
/// - The key length is less than 32 bytes
/// - The decryption operation fails (e.g., invalid ciphertext or authentication failure)
#[inline]
pub fn decrypt(encrypted: &EncryptedData, key: &[u8], mode: SecurityMode) -> Result<Vec<u8>> {
    mode.validate()?;
    decrypt_internal(encrypted, key)
}

/// Decrypt data with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The encrypted data size exceeds resource limits
/// - The key is invalid for the encryption scheme
/// - The decryption or decapsulation operation fails
pub fn decrypt_with_config(
    encrypted: &EncryptedData,
    config: &EncryptionConfig,
    key: &[u8],
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    decrypt_with_config_internal(encrypted, config, key)
}

/// Sign a message with default configuration.
///
/// # Example
///
/// ```rust,ignore
/// let signed = sign(b"message", SecurityMode::Verified(&session))?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The message size exceeds resource limits
/// - Key generation fails
/// - The signing operation fails
#[inline]
pub fn sign(message: &[u8], mode: SecurityMode) -> Result<SignedData> {
    mode.validate()?;
    sign_with_config_internal(message, &SignatureConfig::default())
}

/// Sign a message with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The message size exceeds resource limits
/// - The configuration is invalid
/// - Key generation for the selected scheme fails
/// - The signing operation fails
pub fn sign_with_config(
    message: &[u8],
    config: &SignatureConfig,
    mode: SecurityMode,
) -> Result<SignedData> {
    mode.validate()?;
    sign_with_config_internal(message, config)
}

/// Verify a signed message with default configuration.
///
/// # Example
///
/// ```rust,ignore
/// let is_valid = verify(&signed, SecurityMode::Verified(&session))?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The message size exceeds resource limits
/// - The signature verification operation fails
#[inline]
pub fn verify(signed: &SignedData, mode: SecurityMode) -> Result<bool> {
    mode.validate()?;
    verify_with_config_internal(&signed.data, signed, &SignatureConfig::default())
}

/// Verify a signed message with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The message size exceeds resource limits
/// - The public key is invalid
/// - The signature is malformed or invalid
/// - For hybrid signatures, the signature is too short
pub fn verify_with_config(
    message: &[u8],
    signed: &SignedData,
    config: &SignatureConfig,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    verify_with_config_internal(message, signed, config)
}

/// Encrypt data for a specific use case.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - Scheme selection fails for the given use case
/// - Encryption with the selected scheme fails
pub fn encrypt_for_use_case(
    data: &[u8],
    use_case: UseCase,
    key: &[u8],
    mode: SecurityMode,
) -> Result<EncryptedData> {
    mode.validate()?;
    let config = EncryptionConfig::default();
    let selector = crate::selector::CryptoPolicyEngine::new();
    let ctx = CryptoContext {
        security_level: config.base.security_level.clone(),
        performance_preference: config.base.performance_preference.clone(),
        use_case: Some(use_case),
        hardware_acceleration: config.base.hardware_acceleration,
        timestamp: Utc::now(),
    };
    let _scheme = selector.select_encryption_scheme(data, &ctx)?;
    encrypt_with_config_internal(data, &config, key)
}

// ============================================================================
// Unverified API (Opt-out Functions)
// ============================================================================
// These functions provide opt-out for scenarios where Zero Trust verification
// is not required or not possible.

/// Encrypt data without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The data size exceeds resource limits
/// - Encryption with the selected scheme fails
#[inline]
pub fn encrypt_unverified(data: &[u8], key: &[u8]) -> Result<EncryptedData> {
    encrypt(data, key, SecurityMode::Unverified)
}

/// Encrypt data with custom configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The data size exceeds resource limits
/// - The configuration is invalid
/// - A post-quantum scheme is selected but a symmetric key is provided
/// - The key length is less than 32 bytes for symmetric encryption
/// - The encryption operation fails
pub fn encrypt_with_config_unverified(
    data: &[u8],
    config: &EncryptionConfig,
    key: &[u8],
) -> Result<EncryptedData> {
    encrypt_with_config(data, config, key, SecurityMode::Unverified)
}

/// Decrypt data without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted data size exceeds resource limits
/// - The key length is less than 32 bytes
/// - The decryption operation fails (e.g., invalid ciphertext or authentication failure)
#[inline]
pub fn decrypt_unverified(encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>> {
    decrypt(encrypted, key, SecurityMode::Unverified)
}

/// Decrypt data with custom configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted data size exceeds resource limits
/// - The key is invalid for the encryption scheme
/// - The decryption or decapsulation operation fails
pub fn decrypt_with_config_unverified(
    encrypted: &EncryptedData,
    config: &EncryptionConfig,
    key: &[u8],
) -> Result<Vec<u8>> {
    decrypt_with_config(encrypted, config, key, SecurityMode::Unverified)
}

/// Sign a message without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - Key generation fails
/// - The signing operation fails
#[inline]
pub fn sign_unverified(message: &[u8]) -> Result<SignedData> {
    sign(message, SecurityMode::Unverified)
}

/// Sign a message with custom configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The configuration is invalid
/// - Key generation for the selected scheme fails
/// - The signing operation fails
pub fn sign_with_config_unverified(message: &[u8], config: &SignatureConfig) -> Result<SignedData> {
    sign_with_config(message, config, SecurityMode::Unverified)
}

/// Verify a signed message without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The signature verification operation fails
#[inline]
pub fn verify_unverified(signed: &SignedData) -> Result<bool> {
    verify(signed, SecurityMode::Unverified)
}

/// Verify a signed message with custom configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The public key is invalid
/// - The signature is malformed or invalid
/// - For hybrid signatures, the signature is too short
pub fn verify_with_config_unverified(
    message: &[u8],
    signed: &SignedData,
    config: &SignatureConfig,
) -> Result<bool> {
    verify_with_config(message, signed, config, SecurityMode::Unverified)
}

/// Encrypt data for a specific use case without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - Scheme selection fails for the given use case
/// - Encryption with the selected scheme fails
pub fn encrypt_for_use_case_unverified(
    data: &[u8],
    use_case: UseCase,
    key: &[u8],
) -> Result<EncryptedData> {
    encrypt_for_use_case(data, use_case, key, SecurityMode::Unverified)
}
