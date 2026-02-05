//! High-level encryption, decryption, signing, and verification API.
//!
//! Provides a unified API for cryptographic operations with automatic algorithm
//! selection based on use case or security level.
//!
//! ## Unified API
//!
//! All operations use `CryptoConfig` for configuration:
//!
//! ```rust,ignore
//! use latticearc::{encrypt, decrypt, CryptoConfig, UseCase, VerifiedSession};
//!
//! // Simple: Use defaults (High security)
//! let encrypted = encrypt(data, &key, CryptoConfig::new())?;
//!
//! // With use case (recommended - library picks optimal algorithm)
//! let encrypted = encrypt(data, &key, CryptoConfig::new()
//!     .use_case(UseCase::FileStorage))?;
//!
//! // With Zero Trust session
//! let session = VerifiedSession::establish(&pk, &sk)?;
//! let encrypted = encrypt(data, &key, CryptoConfig::new()
//!     .session(&session)
//!     .use_case(UseCase::FileStorage))?;
//! ```

use chrono::Utc;
use tracing::warn;

use arc_primitives::{
    kem::ml_kem::MlKemSecurityLevel,
    sig::{ml_dsa::MlDsaParameterSet, slh_dsa::SecurityLevel as SlhDsaSecurityLevel},
};

use crate::{
    config::CoreConfig,
    error::{CoreError, Result},
    selector::CryptoPolicyEngine,
    types::{
        AlgorithmSelection, CryptoConfig, EncryptedData, EncryptedMetadata, SignedData,
        SignedMetadata,
    },
};

use super::aes_gcm::{decrypt_aes_gcm_internal, encrypt_aes_gcm_internal};
use super::ed25519::{sign_ed25519_internal, verify_ed25519_internal};
use super::hybrid::{decrypt_hybrid_kem_decapsulate, encrypt_hybrid_kem_encapsulate};
use super::keygen::{
    generate_fn_dsa_keypair, generate_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair,
};
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
// Internal Helpers
// ============================================================================

/// Select encryption scheme based on CryptoConfig.
fn select_encryption_scheme(data: &[u8], options: &CryptoConfig) -> Result<String> {
    match options.get_selection() {
        AlgorithmSelection::UseCase(use_case) => {
            let config = CoreConfig::default();
            CryptoPolicyEngine::select_encryption_scheme(data, &config, Some(use_case))
        }
        AlgorithmSelection::SecurityLevel(level) => {
            let config = CoreConfig::default().with_security_level(level.clone());
            CryptoPolicyEngine::select_encryption_scheme(data, &config, None)
        }
    }
}

/// Select signature scheme based on CryptoConfig.
fn select_signature_scheme(options: &CryptoConfig) -> Result<String> {
    match options.get_selection() {
        AlgorithmSelection::UseCase(use_case) => {
            // For use cases, recommend based on the use case
            CryptoPolicyEngine::recommend_scheme(use_case, &CoreConfig::default())
        }
        AlgorithmSelection::SecurityLevel(level) => {
            let config = CoreConfig::default().with_security_level(level.clone());
            CryptoPolicyEngine::select_signature_scheme(&config)
        }
    }
}

// ============================================================================
// Unified Public API
// ============================================================================

/// Encrypt data with automatic algorithm selection.
///
/// This is the single entry point for encryption. Configure algorithm selection
/// and optional Zero Trust session via the `CryptoConfig` builder.
///
/// # Examples
///
/// ```rust,ignore
/// use latticearc::{encrypt, CryptoConfig, UseCase, SecurityLevel, VerifiedSession};
///
/// let key = [0u8; 32];
///
/// // Simple: Use defaults (High security)
/// let encrypted = encrypt(data, &key, CryptoConfig::new())?;
///
/// // With use case (recommended - library picks optimal algorithm)
/// let encrypted = encrypt(data, &key, CryptoConfig::new()
///     .use_case(UseCase::FileStorage))?;
///
/// // With security level (manual control)
/// let encrypted = encrypt(data, &key, CryptoConfig::new()
///     .security_level(SecurityLevel::Maximum))?;
///
/// // With Zero Trust session
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let encrypted = encrypt(data, &key, CryptoConfig::new()
///     .session(&session)
///     .use_case(UseCase::FileStorage))?;
/// ```
///
/// # Algorithm Selection
///
/// | Use Case | Algorithm |
/// |----------|-----------|
/// | `FileStorage` | ML-KEM-1024 + AES-256-GCM |
/// | `SecureMessaging` | ML-KEM-768 + AES-256-GCM |
/// | `IoTDevice` | ML-KEM-512 + AES-256-GCM |
///
/// | Security Level | Algorithm |
/// |----------------|-----------|
/// | `Maximum` | ML-KEM-1024 |
/// | `High` | ML-KEM-768 |
/// | `Medium` | ML-KEM-768 |
/// | `Low` | ML-KEM-512 |
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Data size exceeds resource limits
/// - Key length is invalid for the selected scheme
/// - Encryption operation fails
#[allow(deprecated)]
pub fn encrypt(data: &[u8], key: &[u8], config: CryptoConfig) -> Result<EncryptedData> {
    config.validate()?;

    let scheme = select_encryption_scheme(data, &config)?;

    validate_encryption_size(data.len()).map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    crate::log_crypto_operation_start!("encrypt", scheme = %scheme, data_size = data.len());

    // SECURITY: Reject symmetric keys when PQ/hybrid scheme is selected
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

    let timestamp = u64::try_from(Utc::now().timestamp()).unwrap_or(0);

    crate::log_crypto_operation_complete!("encrypt", result_size = encrypted.len(), scheme = %scheme);

    Ok(EncryptedData {
        data: encrypted,
        metadata: EncryptedMetadata { nonce, tag: Some(tag), key_id: None },
        scheme,
        timestamp,
    })
}

/// Decrypt data.
///
/// The decryption algorithm is determined by the `encrypted.scheme` field.
///
/// # Examples
///
/// ```rust,ignore
/// use latticearc::{decrypt, CryptoConfig, VerifiedSession};
///
/// // Simple: No session
/// let plaintext = decrypt(&encrypted, &key, CryptoConfig::new())?;
///
/// // With Zero Trust session
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let plaintext = decrypt(&encrypted, &key, CryptoConfig::new()
///     .session(&session))?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Encrypted data size exceeds resource limits
/// - Key is invalid for the encryption scheme
/// - Decryption fails
#[allow(deprecated)]
pub fn decrypt(encrypted: &EncryptedData, key: &[u8], config: CryptoConfig) -> Result<Vec<u8>> {
    config.validate()?;

    crate::log_crypto_operation_start!("decrypt", scheme = %encrypted.scheme, data_size = encrypted.data.len());

    if encrypted.data.is_empty() {
        crate::log_crypto_operation_complete!("decrypt", result_size = 0_usize);
        return Ok(encrypted.data.clone());
    }

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
        _ => {
            if key.len() < 32 {
                return Err(CoreError::InvalidKeyLength { expected: 32, actual: key.len() });
            }
            decrypt_aes_gcm_internal(&encrypted.data, key)
        }
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

/// Sign a message with automatic algorithm selection.
///
/// # Examples
///
/// ```rust,ignore
/// use latticearc::{sign, CryptoConfig, UseCase, VerifiedSession};
///
/// // Simple: Use defaults
/// let signed = sign(message, CryptoConfig::new())?;
///
/// // With use case
/// let signed = sign(message, CryptoConfig::new()
///     .use_case(UseCase::FinancialTransactions))?;
///
/// // With Zero Trust session
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let signed = sign(message, CryptoConfig::new()
///     .session(&session)
///     .use_case(UseCase::FinancialTransactions))?;
/// ```
///
/// # Algorithm Selection
///
/// | Use Case | Algorithm |
/// |----------|-----------|
/// | `FinancialTransactions` | ML-DSA-87 + Ed25519 |
/// | `Authentication` | ML-DSA-87 + Ed25519 |
/// | `FirmwareSigning` | ML-DSA-65 |
///
/// | Security Level | Algorithm |
/// |----------------|-----------|
/// | `Maximum` | ML-DSA-87 |
/// | `High` | ML-DSA-65 |
/// | `Medium` | ML-DSA-65 |
/// | `Low` | ML-DSA-44 |
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Message size exceeds resource limits
/// - Key generation fails
/// - Signing operation fails
#[allow(deprecated)]
pub fn sign(message: &[u8], config: CryptoConfig) -> Result<SignedData> {
    config.validate()?;

    let scheme = select_signature_scheme(&config)?;

    validate_signature_size(message.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

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
        "hybrid-ml-dsa-65-ed25519" | "ml-dsa-65-hybrid-ed25519" => {
            let (pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
            let (ed_pk, ed_sk) = generate_keypair()?;
            let pq_sig =
                sign_pq_ml_dsa_unverified(message, pq_sk.as_slice(), MlDsaParameterSet::MLDSA65)?;
            let ed_sig = sign_ed25519_internal(message, ed_sk.as_slice())?;
            let combined_sig = [pq_sig, ed_sig].concat();
            // Store both public keys: ML-DSA (1952 bytes) + Ed25519 (32 bytes)
            let combined_pk = [pq_pk, ed_pk].concat();
            (combined_pk, ed_sk, combined_sig)
        }
        "hybrid-ml-dsa-87-ed25519" => {
            let (pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;
            let (ed_pk, ed_sk) = generate_keypair()?;
            let pq_sig =
                sign_pq_ml_dsa_unverified(message, pq_sk.as_slice(), MlDsaParameterSet::MLDSA87)?;
            let ed_sig = sign_ed25519_internal(message, ed_sk.as_slice())?;
            let combined_sig = [pq_sig, ed_sig].concat();
            // Store both public keys: ML-DSA (2592 bytes) + Ed25519 (32 bytes)
            let combined_pk = [pq_pk, ed_pk].concat();
            (combined_pk, ed_sk, combined_sig)
        }
        _ => {
            let (pk, sk) = generate_keypair()?;
            let sig = sign_ed25519_internal(message, sk.as_slice())?;
            (pk, sk, sig)
        }
    };

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

/// Verify a signed message.
///
/// The verification algorithm is determined by the `signed.scheme` field.
///
/// # Examples
///
/// ```rust,ignore
/// use latticearc::{verify, CryptoConfig, VerifiedSession};
///
/// // Simple: No session
/// let is_valid = verify(&signed, CryptoConfig::new())?;
///
/// // With Zero Trust session
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let is_valid = verify(&signed, CryptoConfig::new()
///     .session(&session))?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Message size exceeds resource limits
/// - Public key is invalid
/// - Signature is malformed or invalid
#[allow(deprecated)]
pub fn verify(signed: &SignedData, config: CryptoConfig) -> Result<bool> {
    config.validate()?;

    crate::log_crypto_operation_start!("verify", scheme = %signed.scheme, message_size = signed.data.len());

    validate_signature_size(signed.data.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    let result = match signed.scheme.as_str() {
        "ml-dsa-44" => verify_pq_ml_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA44,
        ),
        "ml-dsa-65" => verify_pq_ml_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA65,
        ),
        "ml-dsa-87" => verify_pq_ml_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA87,
        ),
        "slh-dsa-shake-128s" => verify_pq_slh_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            SlhDsaSecurityLevel::Shake128s,
        ),
        "slh-dsa-shake-192s" => verify_pq_slh_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            SlhDsaSecurityLevel::Shake192s,
        ),
        "slh-dsa-shake-256s" => verify_pq_slh_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            SlhDsaSecurityLevel::Shake256s,
        ),
        "fn-dsa" => verify_pq_fn_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
        ),
        "hybrid-ml-dsa-65-ed25519" | "ml-dsa-65-hybrid-ed25519" => {
            // ML-DSA-65 public key is 1952 bytes, Ed25519 is 32 bytes
            const ML_DSA_65_PK_LEN: usize = 1952;
            const ED25519_PK_LEN: usize = 32;

            let sig_len = signed.metadata.signature.len();
            if sig_len < 3293 {
                return Err(CoreError::InvalidInput("Hybrid signature too short".to_string()));
            }

            // Split combined public key: ML-DSA (1952) + Ed25519 (32)
            let pk_len = signed.metadata.public_key.len();
            if pk_len != ML_DSA_65_PK_LEN + ED25519_PK_LEN {
                return Err(CoreError::InvalidInput(format!(
                    "Invalid hybrid public key length: expected {}, got {}",
                    ML_DSA_65_PK_LEN + ED25519_PK_LEN,
                    pk_len
                )));
            }
            let pq_pk = signed.metadata.public_key.get(..ML_DSA_65_PK_LEN).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid public key format".to_string())
            })?;
            let ed_pk = signed.metadata.public_key.get(ML_DSA_65_PK_LEN..).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid public key format".to_string())
            })?;

            // Split combined signature: ML-DSA sig + Ed25519 sig (64 bytes)
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
                &signed.data,
                pq_sig,
                pq_pk,
                MlDsaParameterSet::MLDSA65,
            )?;
            let ed_valid = verify_ed25519_internal(&signed.data, ed_sig, ed_pk)?;
            Ok(pq_valid && ed_valid)
        }
        "hybrid-ml-dsa-87-ed25519" => {
            // ML-DSA-87 public key is 2592 bytes, Ed25519 is 32 bytes
            const ML_DSA_87_PK_LEN: usize = 2592;
            const ED25519_PK_LEN: usize = 32;

            let sig_len = signed.metadata.signature.len();
            if sig_len < 4627 {
                // ML-DSA-87 sig (4595) + Ed25519 sig (64) - some overlap
                return Err(CoreError::InvalidInput("Hybrid signature too short".to_string()));
            }

            // Split combined public key: ML-DSA (2592) + Ed25519 (32)
            let pk_len = signed.metadata.public_key.len();
            if pk_len != ML_DSA_87_PK_LEN + ED25519_PK_LEN {
                return Err(CoreError::InvalidInput(format!(
                    "Invalid hybrid public key length: expected {}, got {}",
                    ML_DSA_87_PK_LEN + ED25519_PK_LEN,
                    pk_len
                )));
            }
            let pq_pk = signed.metadata.public_key.get(..ML_DSA_87_PK_LEN).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid public key format".to_string())
            })?;
            let ed_pk = signed.metadata.public_key.get(ML_DSA_87_PK_LEN..).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid public key format".to_string())
            })?;

            // Split combined signature: ML-DSA sig + Ed25519 sig (64 bytes)
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
                &signed.data,
                pq_sig,
                pq_pk,
                MlDsaParameterSet::MLDSA87,
            )?;
            let ed_valid = verify_ed25519_internal(&signed.data, ed_sig, ed_pk)?;
            Ok(pq_valid && ed_valid)
        }
        _ => verify_ed25519_internal(
            &signed.data,
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
    use crate::{CryptoConfig, SecurityLevel, UseCase};

    // Sign/Verify tests with different security levels
    #[test]
    fn test_sign_verify_with_standard_security() -> Result<()> {
        let message = b"Test message with standard security";
        let config = CryptoConfig::new().security_level(SecurityLevel::Standard);

        let signed = sign(message, config)?;

        assert!(!signed.metadata.signature.is_empty());
        assert!(!signed.metadata.public_key.is_empty());

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_with_high_security() -> Result<()> {
        let message = b"Test message with high security";
        let config = CryptoConfig::new().security_level(SecurityLevel::High);

        let signed = sign(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_with_maximum_security() -> Result<()> {
        let message = b"Test message with maximum security";
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);

        let signed = sign(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_wrong_message() -> Result<()> {
        let message = b"Original message";
        let config = CryptoConfig::new();

        let signed = sign(message, config)?;

        // Modify the message
        let mut modified_signed = signed.clone();
        modified_signed.data = b"Modified message".to_vec();

        // verify() may return Ok(false) or Err depending on implementation
        match verify(&modified_signed, CryptoConfig::new()) {
            Ok(valid) => assert!(!valid, "Modified message should fail verification"),
            Err(_) => {} // Error is also acceptable
        }

        Ok(())
    }

    #[test]
    fn test_sign_verify_corrupted_signature() -> Result<()> {
        let message = b"Test message";
        let config = CryptoConfig::new();

        let signed = sign(message, config)?;

        // Corrupt the signature
        let mut corrupted_signed = signed.clone();
        if let Some(byte) = corrupted_signed.metadata.signature.first_mut() {
            *byte ^= 0xFF;
        }

        // verify() may return Ok(false) or Err depending on implementation
        match verify(&corrupted_signed, CryptoConfig::new()) {
            Ok(valid) => assert!(!valid, "Corrupted signature should fail verification"),
            Err(_) => {} // Error is also acceptable
        }

        Ok(())
    }

    #[test]
    fn test_sign_empty_message() -> Result<()> {
        let message = b"";
        let config = CryptoConfig::new();

        let signed = sign(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Empty message signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_large_message() -> Result<()> {
        let message = vec![0xABu8; 10_000]; // 10KB message
        let config = CryptoConfig::new();

        let signed = sign(&message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Large message signature should be valid");

        Ok(())
    }

    // Use case selection tests
    #[test]
    fn test_sign_with_financial_transactions_use_case() -> Result<()> {
        let message = b"Financial transaction data";
        let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);

        let signed = sign(message, config)?;

        // Financial transactions should use strong signature
        assert!(
            signed.scheme.contains("ml-dsa") || signed.scheme.contains("ed25519"),
            "Financial transactions should use strong signatures"
        );

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_sign_with_authentication_use_case() -> Result<()> {
        let message = b"Authentication data";
        let config = CryptoConfig::new().use_case(UseCase::Authentication);

        let signed = sign(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_sign_with_firmware_signing_use_case() -> Result<()> {
        let message = b"Firmware binary data";
        let config = CryptoConfig::new().use_case(UseCase::FirmwareSigning);

        let signed = sign(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    // Invalid key tests
    #[test]
    fn test_encrypt_with_invalid_key_length() {
        let message = b"Test message";
        let short_key = vec![0x42u8; 16]; // Too short for AES-256
        let config = CryptoConfig::new();

        let result = encrypt(message, &short_key, config);
        assert!(result.is_err(), "Encryption with short key should fail");
    }

    #[test]
    fn test_decrypt_empty_ciphertext() -> Result<()> {
        let key = vec![0x42u8; 32];
        let empty_encrypted = EncryptedData {
            data: vec![],
            metadata: EncryptedMetadata { nonce: vec![], tag: None, key_id: None },
            scheme: "aes-256-gcm".to_string(),
            timestamp: 0,
        };

        let decrypted = decrypt(&empty_encrypted, &key, CryptoConfig::new())?;
        assert!(decrypted.is_empty());

        Ok(())
    }

    // Cross-algorithm tests for signing
    #[test]
    fn test_sign_verify_multiple_security_levels() -> Result<()> {
        let message = b"Test cross-level signatures";

        let levels = [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];
        for level in &levels {
            let config = CryptoConfig::new().security_level(level.clone());
            let signed = sign(message, config)?;
            let is_valid = verify(&signed, CryptoConfig::new())?;
            assert!(is_valid, "Failed for security level: {:?}", level);
        }

        Ok(())
    }

    // ========================================================================
    // Additional Signing Algorithm Coverage
    // ========================================================================

    // Test specific algorithm branches in sign/verify
    #[test]
    fn test_sign_verify_metadata_populated() -> Result<()> {
        let message = b"Test metadata";
        let config = CryptoConfig::new();

        let signed = sign(message, config)?;

        assert!(!signed.metadata.signature.is_empty(), "Signature should not be empty");
        assert!(!signed.metadata.public_key.is_empty(), "Public key should not be empty");
        assert!(!signed.metadata.signature_algorithm.is_empty(), "Algorithm should be set");
        assert!(!signed.scheme.is_empty(), "Scheme should be set");
        assert!(signed.timestamp > 0, "Timestamp should be set");

        Ok(())
    }

    #[test]
    fn test_verify_with_corrupted_public_key() -> Result<()> {
        let message = b"Test message";
        let config = CryptoConfig::new();

        let signed = sign(message, config)?;

        // Corrupt the public key
        let mut corrupted_signed = signed.clone();
        if let Some(byte) = corrupted_signed.metadata.public_key.first_mut() {
            *byte ^= 0xFF;
        }

        // Verification should fail
        match verify(&corrupted_signed, CryptoConfig::new()) {
            Ok(valid) => assert!(!valid, "Corrupted public key should fail verification"),
            Err(_) => {} // Error is also acceptable
        }

        Ok(())
    }

    #[test]
    fn test_sign_verify_binary_message() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let config = CryptoConfig::new();

        let signed = sign(&message, config)?;
        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Binary message signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_unicode_message() -> Result<()> {
        let message = "Test with Unicode: 你好世界 🔐".as_bytes();
        let config = CryptoConfig::new();

        let signed = sign(message, config)?;
        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Unicode message signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_with_blockchain_transaction_use_case() -> Result<()> {
        let message = b"Blockchain transaction data";
        let config = CryptoConfig::new().use_case(UseCase::BlockchainTransaction);

        let signed = sign(message, config)?;
        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_sign_verify_with_legal_documents_use_case() -> Result<()> {
        let message = b"Legal document hash";
        let config = CryptoConfig::new().use_case(UseCase::LegalDocuments);

        let signed = sign(message, config)?;
        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_sign_multiple_messages() -> Result<()> {
        let config = CryptoConfig::new();
        let messages =
            vec![b"First message".as_ref(), b"Second message".as_ref(), b"Third message".as_ref()];

        for message in messages {
            let signed = sign(message, config.clone())?;
            let is_valid = verify(&signed, CryptoConfig::new())?;
            assert!(is_valid, "Message: {:?}", String::from_utf8_lossy(message));
        }

        Ok(())
    }

    #[test]
    fn test_sign_produces_unique_signatures() -> Result<()> {
        let message = b"Same message";
        let config = CryptoConfig::new();

        let signed1 = sign(message, config.clone())?;
        let signed2 = sign(message, config)?;

        // Different key pairs should produce different signatures
        assert_ne!(signed1.metadata.signature, signed2.metadata.signature);
        assert_ne!(signed1.metadata.public_key, signed2.metadata.public_key);

        // Both should verify successfully
        let is_valid1 = verify(&signed1, CryptoConfig::new())?;
        let is_valid2 = verify(&signed2, CryptoConfig::new())?;
        assert!(is_valid1);
        assert!(is_valid2);

        Ok(())
    }

    #[test]
    fn test_verify_rejects_empty_signature() {
        let signed = SignedData {
            data: b"Test message".to_vec(),
            metadata: SignedMetadata {
                signature: vec![], // Empty signature
                signature_algorithm: "ed25519".to_string(),
                public_key: vec![0u8; 32],
                key_id: None,
            },
            scheme: "ed25519".to_string(),
            timestamp: 0,
        };

        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err() || (result.is_ok() && !result.unwrap()));
    }

    #[test]
    fn test_verify_rejects_empty_public_key() {
        let signed = SignedData {
            data: b"Test message".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 64],
                signature_algorithm: "ed25519".to_string(),
                public_key: vec![], // Empty public key
                key_id: None,
            },
            scheme: "ed25519".to_string(),
            timestamp: 0,
        };

        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err() || (result.is_ok() && !result.unwrap()));
    }

    // Decrypt error handling (doesn't require encrypt roundtrip)
    #[test]
    fn test_decrypt_with_short_key() {
        let encrypted = EncryptedData {
            data: vec![1, 2, 3, 4],
            metadata: EncryptedMetadata { nonce: vec![], tag: None, key_id: None },
            scheme: "aes-256-gcm".to_string(),
            timestamp: 0,
        };
        let short_key = vec![0x42u8; 16]; // Too short

        let result = decrypt(&encrypted, &short_key, CryptoConfig::new());
        assert!(result.is_err(), "Decryption with short key should fail");
    }

    #[test]
    fn test_decrypt_unknown_scheme() -> Result<()> {
        let encrypted = EncryptedData {
            data: vec![0x12u8; 40], // 40 bytes of dummy data
            metadata: EncryptedMetadata {
                nonce: vec![0u8; 12],
                tag: Some(vec![0u8; 16]),
                key_id: None,
            },
            scheme: "unknown-scheme".to_string(),
            timestamp: 0,
        };
        let key = vec![0x42u8; 32];

        // Unknown schemes fall back to AES-256-GCM decryption, which should fail for invalid data
        let result = decrypt(&encrypted, &key, CryptoConfig::new());
        assert!(result.is_err(), "Decryption of invalid data should fail");

        Ok(())
    }
}
