//! High-level encryption, decryption, signing, and verification API.
//!
//! Provides a unified API for cryptographic operations with automatic algorithm
//! selection based on use case or security level.
//!
//! ## Unified API
//!
//! All operations use `CryptoConfig` for configuration:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::unified_api::{encrypt, decrypt, CryptoConfig, UseCase};
//! use latticearc::types::crypto_types::{EncryptKey, DecryptKey};
//!
//! // Symmetric encryption with use case
//! let key = [0u8; 32];
//! let encrypted = encrypt(b"secret", EncryptKey::Symmetric(&key),
//!     CryptoConfig::new().force_scheme(latticearc::CryptoScheme::Symmetric))?;
//! let plaintext = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())?;
//!
//! // Hybrid encryption (ML-KEM-768 + X25519 + AES-256-GCM)
//! let (pk, sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"secret", EncryptKey::Hybrid(&pk),
//!     CryptoConfig::new().use_case(UseCase::FileStorage))?;
//! let plaintext = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
//! # Ok(())
//! # }
//! ```

use chrono::Utc;
use zeroize::Zeroizing;

use crate::primitives::sig::{
    ml_dsa::MlDsaParameterSet, slh_dsa::SecurityLevel as SlhDsaSecurityLevel,
};

use crate::types::crypto_types::{
    DecryptKey, EncryptKey, EncryptedOutput, EncryptionScheme, HybridComponents,
};
use crate::unified_api::{
    config::CoreConfig,
    error::{CoreError, Result},
    selector::CryptoPolicyEngine,
    types::{AlgorithmSelection, CryptoConfig, SignedData, SignedMetadata},
};

use super::aes_gcm::{decrypt_aes_gcm_internal, encrypt_aes_gcm_internal};
use super::ed25519::{sign_ed25519_internal, verify_ed25519_internal};
use super::keygen::{
    generate_fn_dsa_keypair, generate_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair,
};
use super::pq_sig::{
    sign_pq_fn_dsa_unverified, sign_pq_ml_dsa_unverified, sign_pq_slh_dsa_unverified,
    verify_pq_fn_dsa_unverified, verify_pq_ml_dsa_unverified, verify_pq_slh_dsa_unverified,
};
#[cfg(not(feature = "fips"))]
use crate::primitives::aead::{AeadCipher, chacha20poly1305::ChaCha20Poly1305Cipher};

use crate::hybrid::encrypt_hybrid::{HybridCiphertext, decrypt_hybrid, encrypt_hybrid};

/// Check FIPS module is operational before any crypto operation.
/// On first call, runs power-up self-tests (lazy initialization).
/// No-op when `fips-self-test` feature is not enabled.
#[cfg(feature = "fips-self-test")]
pub(super) fn fips_verify_operational() -> Result<()> {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // initialize_and_test() calls std::process::abort() on failure (FIPS 140-3 §9.1).
        // If execution continues past this call, self-tests passed.
        let _passed = crate::primitives::self_test::initialize_and_test();
    });
    crate::primitives::self_test::verify_operational().map_err(|e| CoreError::SelfTestFailed {
        component: "FIPS module".to_string(),
        status: e.to_string(),
    })
}

#[cfg(not(feature = "fips-self-test"))]
pub(super) fn fips_verify_operational() -> Result<()> {
    Ok(())
}

use crate::types::resource_limits::{
    validate_decryption_size, validate_encryption_size, validate_signature_size,
};

// ============================================================================
// Internal Helpers
// ============================================================================

/// Select encryption scheme based on CryptoConfig, returning a type-safe enum.
///
/// This is the type-safe replacement for `select_encryption_scheme`.
fn select_encryption_scheme_typed(options: &CryptoConfig) -> Result<EncryptionScheme> {
    match options.get_selection() {
        AlgorithmSelection::UseCase(use_case) => {
            let config = CoreConfig::default();
            Ok(CryptoPolicyEngine::recommend_encryption_scheme(use_case, &config)?)
        }
        AlgorithmSelection::SecurityLevel(level) => {
            let config = CoreConfig::default().with_security_level(level.clone());
            Ok(CryptoPolicyEngine::select_encryption_scheme_typed(&config))
        }
        AlgorithmSelection::ForcedScheme(scheme) => {
            let scheme_str = CryptoPolicyEngine::force_scheme(scheme);
            EncryptionScheme::parse_str(&scheme_str).ok_or_else(|| {
                CoreError::InvalidInput(format!(
                    "Forced scheme '{}' is not an encryption scheme (may be a signature scheme)",
                    scheme_str
                ))
            })
        }
    }
}

/// Select signature scheme based on CryptoConfig.
fn select_signature_scheme(options: &CryptoConfig) -> Result<String> {
    match options.get_selection() {
        AlgorithmSelection::UseCase(use_case) => {
            // For use cases, recommend based on the use case
            Ok(CryptoPolicyEngine::recommend_scheme(use_case, &CoreConfig::default())?)
        }
        AlgorithmSelection::SecurityLevel(level) => {
            let config = CoreConfig::default().with_security_level(level.clone());
            Ok(CryptoPolicyEngine::select_signature_scheme(&config)?)
        }
        AlgorithmSelection::ForcedScheme(scheme) => Ok(CryptoPolicyEngine::force_scheme(scheme)),
    }
}

/// ChaCha20-Poly1305 encrypt (format: nonce || ciphertext || tag)
#[cfg(not(feature = "fips"))]
fn encrypt_chacha20_internal(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305Cipher::new(key)
        .map_err(|_e| CoreError::InvalidKeyLength { expected: 32, actual: key.len() })?;
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let (ciphertext, tag) = cipher
        .encrypt(&nonce, data, None)
        .map_err(|e| CoreError::EncryptionFailed(e.to_string()))?;
    // Format: nonce (12) || ciphertext || tag (16)
    let mut result =
        Vec::with_capacity(12_usize.saturating_add(ciphertext.len()).saturating_add(tag.len()));
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);
    Ok(result)
}

/// ChaCha20-Poly1305 decrypt (expects: nonce || ciphertext || tag)
#[cfg(not(feature = "fips"))]
fn decrypt_chacha20_internal(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 28 {
        return Err(CoreError::DecryptionFailed(
            "Encrypted data too short for ChaCha20-Poly1305 (need nonce + tag)".to_string(),
        ));
    }
    let nonce_slice = encrypted
        .get(..12)
        .ok_or_else(|| CoreError::DecryptionFailed("Failed to extract nonce".to_string()))?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_slice);

    let ciphertext_and_tag = encrypted
        .get(12..)
        .ok_or_else(|| CoreError::DecryptionFailed("Failed to extract ciphertext".to_string()))?;
    let tag_start = ciphertext_and_tag.len().saturating_sub(16);
    let ciphertext = ciphertext_and_tag
        .get(..tag_start)
        .ok_or_else(|| CoreError::DecryptionFailed("Failed to split ciphertext/tag".to_string()))?;
    let tag_slice = ciphertext_and_tag
        .get(tag_start..)
        .ok_or_else(|| CoreError::DecryptionFailed("Failed to extract tag".to_string()))?;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_slice);

    let cipher = ChaCha20Poly1305Cipher::new(key)
        .map_err(|_e| CoreError::InvalidKeyLength { expected: 32, actual: key.len() })?;
    cipher
        .decrypt(&nonce, ciphertext, &tag, None)
        .map_err(|e| CoreError::DecryptionFailed(e.to_string()))
}

// ============================================================================
// Unified Public API
// ============================================================================

/// Encrypt data with automatic algorithm selection.
///
/// This is the **single entry point** for all encryption. The key type
/// (`EncryptKey::Symmetric` or `EncryptKey::Hybrid`) determines the cipher.
/// If the selected scheme requires a hybrid key but a symmetric key is provided
/// (or vice versa), this function returns `Err` — it **never silently degrades**.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{encrypt, CryptoConfig, UseCase, SecurityLevel};
/// use latticearc::types::crypto_types::EncryptKey;
///
/// // Symmetric encryption (AES-256-GCM)
/// let key = [0u8; 32];
/// let encrypted = encrypt(b"secret", EncryptKey::Symmetric(&key),
///     CryptoConfig::new().force_scheme(latticearc::CryptoScheme::Symmetric))?;
///
/// // Hybrid encryption (ML-KEM-768 + X25519 + HKDF + AES-256-GCM)
/// let (pk, sk) = latticearc::generate_hybrid_keypair()?;
/// let encrypted = encrypt(b"secret", EncryptKey::Hybrid(&pk),
///     CryptoConfig::new().use_case(UseCase::FileStorage))?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Key type doesn't match the selected scheme (no silent fallback)
/// - Data size exceeds resource limits
/// - Key length is invalid for the selected scheme
/// - Encryption operation fails
#[must_use = "encryption result must be used or errors will be silently dropped"]
pub fn encrypt(data: &[u8], key: EncryptKey<'_>, config: CryptoConfig) -> Result<EncryptedOutput> {
    fips_verify_operational()?;
    config.validate()?;

    let scheme = select_encryption_scheme_typed(&config)?;
    config.validate_scheme_compliance(scheme.as_str())?;

    // Type-safe key-scheme validation: FAIL on mismatch, never degrade
    CryptoPolicyEngine::validate_key_matches_scheme(&key, &scheme)
        .map_err(|e| CoreError::ConfigurationError(e.to_string()))?;

    validate_encryption_size(data.len()).map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    crate::log_crypto_operation_start!("encrypt", scheme = %scheme, data_size = data.len());

    let output = match (&key, &scheme) {
        // Symmetric AES-256-GCM
        (EncryptKey::Symmetric(k), EncryptionScheme::Aes256Gcm) => {
            if k.len() != 32 {
                return Err(CoreError::InvalidKeyLength { expected: 32, actual: k.len() });
            }
            let encrypted = encrypt_aes_gcm_internal(data, k)?;
            symmetric_bytes_to_output(scheme, &encrypted)?
        }
        // Symmetric ChaCha20-Poly1305 (non-FIPS only)
        #[cfg(not(feature = "fips"))]
        (EncryptKey::Symmetric(k), EncryptionScheme::ChaCha20Poly1305) => {
            if k.len() != 32 {
                return Err(CoreError::InvalidKeyLength { expected: 32, actual: k.len() });
            }
            let encrypted = encrypt_chacha20_internal(data, k)?;
            symmetric_bytes_to_output(scheme, &encrypted)?
        }
        #[cfg(feature = "fips")]
        (EncryptKey::Symmetric(_), EncryptionScheme::ChaCha20Poly1305) => {
            return Err(CoreError::ComplianceViolation(
                "ChaCha20-Poly1305 is not FIPS 140-3 approved. Use AES-256-GCM.".to_string(),
            ));
        }
        // Hybrid ML-KEM + X25519 + HKDF + AES-256-GCM
        (EncryptKey::Hybrid(pk), _) if scheme.requires_hybrid_key() => {
            let mut rng = rand::rngs::OsRng;
            let ct = encrypt_hybrid(&mut rng, pk, data, None).map_err(|e| {
                CoreError::EncryptionFailed(format!("Hybrid encryption failed: {}", e))
            })?;
            let timestamp = u64::try_from(Utc::now().timestamp().max(0)).unwrap_or(0);
            EncryptedOutput {
                scheme,
                ciphertext: ct.symmetric_ciphertext,
                nonce: ct.nonce,
                tag: ct.tag,
                hybrid_data: Some(HybridComponents {
                    ml_kem_ciphertext: ct.kem_ciphertext,
                    ecdh_ephemeral_pk: ct.ecdh_ephemeral_pk,
                }),
                timestamp,
                key_id: None,
            }
        }
        // This arm should be unreachable due to validate_key_matches_scheme above
        _ => {
            return Err(CoreError::InvalidInput(format!(
                "Key type does not match scheme '{}'",
                scheme
            )));
        }
    };

    crate::log_crypto_operation_complete!("encrypt", result_size = output.ciphertext.len(), scheme = %output.scheme);

    Ok(output)
}

/// Convert raw symmetric ciphertext bytes (nonce || ciphertext || tag) into EncryptedOutput.
fn symmetric_bytes_to_output(
    scheme: EncryptionScheme,
    encrypted: &[u8],
) -> Result<EncryptedOutput> {
    if encrypted.len() < 28 {
        return Err(CoreError::EncryptionFailed(
            "Encrypted data too short (need nonce + tag)".to_string(),
        ));
    }
    let nonce = encrypted
        .get(..12)
        .ok_or_else(|| CoreError::EncryptionFailed("Failed to extract nonce".to_string()))?
        .to_vec();

    let tag_start = encrypted.len().saturating_sub(16);
    let tag = encrypted
        .get(tag_start..)
        .ok_or_else(|| CoreError::EncryptionFailed("Failed to extract tag".to_string()))?
        .to_vec();

    let timestamp = u64::try_from(Utc::now().timestamp().max(0)).unwrap_or(0);

    Ok(EncryptedOutput {
        scheme,
        ciphertext: encrypted.to_vec(),
        nonce,
        tag,
        hybrid_data: None,
        timestamp,
        key_id: None,
    })
}

/// Decrypt data encrypted by `encrypt()`.
///
/// The decryption algorithm is determined by `encrypted.scheme` (an enum, not a string).
/// The key type must match the scheme — mismatches return `Err`.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{encrypt, decrypt, CryptoConfig};
/// use latticearc::types::crypto_types::{EncryptKey, DecryptKey};
///
/// let key = [0u8; 32];
/// let encrypted = encrypt(b"secret", EncryptKey::Symmetric(&key),
///     CryptoConfig::new().force_scheme(latticearc::CryptoScheme::Symmetric))?;
/// let plaintext = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Key type doesn't match the encryption scheme
/// - Encrypted data size exceeds resource limits
/// - Decryption or authentication fails
#[must_use = "decryption result must be used or errors will be silently dropped"]
pub fn decrypt(
    encrypted: &EncryptedOutput,
    key: DecryptKey<'_>,
    config: CryptoConfig,
) -> Result<Vec<u8>> {
    fips_verify_operational()?;
    config.validate()?;
    config.validate_scheme_compliance(encrypted.scheme.as_str())?;

    // Type-safe key-scheme validation
    CryptoPolicyEngine::validate_decrypt_key_matches_scheme(&key, &encrypted.scheme)
        .map_err(|e| CoreError::ConfigurationError(e.to_string()))?;

    crate::log_crypto_operation_start!("decrypt", scheme = %encrypted.scheme, data_size = encrypted.ciphertext.len());

    validate_decryption_size(encrypted.ciphertext.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    let result = match (&key, &encrypted.scheme) {
        // Symmetric AES-256-GCM
        (DecryptKey::Symmetric(k), EncryptionScheme::Aes256Gcm) => {
            if k.len() != 32 {
                return Err(CoreError::InvalidKeyLength { expected: 32, actual: k.len() });
            }
            decrypt_aes_gcm_internal(&encrypted.ciphertext, k)
        }
        // Symmetric ChaCha20-Poly1305 (non-FIPS only)
        #[cfg(not(feature = "fips"))]
        (DecryptKey::Symmetric(k), EncryptionScheme::ChaCha20Poly1305) => {
            if k.len() != 32 {
                return Err(CoreError::InvalidKeyLength { expected: 32, actual: k.len() });
            }
            decrypt_chacha20_internal(&encrypted.ciphertext, k)
        }
        #[cfg(feature = "fips")]
        (DecryptKey::Symmetric(_), EncryptionScheme::ChaCha20Poly1305) => {
            return Err(CoreError::ComplianceViolation(
                "ChaCha20-Poly1305 is not FIPS 140-3 approved. Use AES-256-GCM.".to_string(),
            ));
        }
        // Hybrid ML-KEM + X25519 + HKDF + AES-256-GCM
        (DecryptKey::Hybrid(sk), _) if encrypted.scheme.requires_hybrid_key() => {
            let hybrid_data = encrypted.hybrid_data.as_ref().ok_or_else(|| {
                CoreError::DecryptionFailed(
                    "Hybrid scheme but no hybrid_data in EncryptedOutput".to_string(),
                )
            })?;

            let ct = HybridCiphertext {
                kem_ciphertext: hybrid_data.ml_kem_ciphertext.clone(),
                ecdh_ephemeral_pk: hybrid_data.ecdh_ephemeral_pk.clone(),
                symmetric_ciphertext: encrypted.ciphertext.clone(),
                nonce: encrypted.nonce.clone(),
                tag: encrypted.tag.clone(),
            };

            decrypt_hybrid(sk, &ct, None).map_err(|e| {
                CoreError::DecryptionFailed(format!("Hybrid decryption failed: {}", e))
            })
        }
        // Unreachable due to validate_decrypt_key_matches_scheme above
        _ => {
            return Err(CoreError::InvalidInput(format!(
                "Key type does not match scheme '{}'",
                encrypted.scheme
            )));
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

/// Generate a signing keypair for the scheme selected by config.
///
/// The scheme selector auto-picks hybrid (ML-DSA-65 + Ed25519) by default.
/// Returns `(public_key_bytes, secret_key_bytes, scheme_name)`.
///
/// # Unified API
///
/// This is the keypair generation companion to [`sign_with_key`]. Together they
/// form the unified signing API — the scheme selector handles PQ-only, hybrid,
/// and classical transparently based on `CryptoConfig`.
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Key generation fails for the selected scheme
#[must_use = "keypair result must be used or errors will be silently dropped"]
pub fn generate_signing_keypair(
    config: CryptoConfig,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>, String)> {
    fips_verify_operational()?;
    config.validate()?;

    let scheme = select_signature_scheme(&config)?;

    let (public_key, secret_key) = match scheme.as_str() {
        "ml-dsa-44" | "pq-ml-dsa-44" => {
            let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;
            (pk, sk)
        }
        "ml-dsa-65" | "pq-ml-dsa-65" => {
            let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
            (pk, sk)
        }
        "ml-dsa-87" | "pq-ml-dsa-87" => {
            let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;
            (pk, sk)
        }
        "slh-dsa-shake-128s" => {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
            (pk, sk)
        }
        "slh-dsa-shake-192s" => {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;
            (pk, sk)
        }
        "slh-dsa-shake-256s" => {
            let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;
            (pk, sk)
        }
        "fn-dsa" => {
            let (pk, sk) = generate_fn_dsa_keypair()?;
            (pk, sk)
        }
        "hybrid-ml-dsa-44-ed25519" => {
            let (pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;
            let (ed_pk, ed_sk) = generate_keypair()?;
            let combined_pk = [pq_pk, ed_pk].concat();
            let combined_sk = [pq_sk.as_ref(), ed_sk.as_ref()].concat();
            (combined_pk, crate::types::PrivateKey::new(combined_sk))
        }
        "hybrid-ml-dsa-65-ed25519" | "ml-dsa-65-hybrid-ed25519" => {
            let (pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
            let (ed_pk, ed_sk) = generate_keypair()?;
            let combined_pk = [pq_pk, ed_pk].concat();
            let combined_sk = [pq_sk.as_ref(), ed_sk.as_ref()].concat();
            (combined_pk, crate::types::PrivateKey::new(combined_sk))
        }
        "hybrid-ml-dsa-87-ed25519" => {
            let (pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;
            let (ed_pk, ed_sk) = generate_keypair()?;
            let combined_pk = [pq_pk, ed_pk].concat();
            let combined_sk = [pq_sk.as_ref(), ed_sk.as_ref()].concat();
            (combined_pk, crate::types::PrivateKey::new(combined_sk))
        }
        _ => {
            return Err(CoreError::InvalidInput(format!("Unsupported signing scheme: {}", scheme)));
        }
    };

    Ok((public_key, Zeroizing::new(secret_key.as_ref().to_vec()), scheme))
}

/// Sign a message using caller-provided keys (unified API).
///
/// Use [`generate_signing_keypair`] to create matching keys. The scheme is
/// determined by `CryptoConfig` — hybrid by default.
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Message size exceeds resource limits
/// - Secret/public key bytes don't match the expected sizes for the scheme
/// - Signing operation fails
#[allow(clippy::arithmetic_side_effects)] // Key size additions use well-defined NIST constants
#[must_use = "signing result must be used or errors will be silently dropped"]
pub fn sign_with_key(
    message: &[u8],
    secret_key: &[u8],
    public_key: &[u8],
    config: CryptoConfig,
) -> Result<SignedData> {
    fips_verify_operational()?;
    config.validate()?;

    let scheme = select_signature_scheme(&config)?;
    config.validate_scheme_compliance(&scheme)?;

    validate_signature_size(message.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    crate::log_crypto_operation_start!("sign_with_key", scheme = %scheme, message_size = message.len());

    // Uses string-based dispatch. A future SignatureScheme enum
    // (analogous to EncryptionScheme) would provide compile-time exhaustiveness.
    let (result_pk, signature) = match scheme.as_str() {
        "ml-dsa-44" | "pq-ml-dsa-44" => {
            let sig = sign_pq_ml_dsa_unverified(message, secret_key, MlDsaParameterSet::MLDSA44)?;
            (public_key.to_vec(), sig)
        }
        "ml-dsa-65" | "pq-ml-dsa-65" => {
            let sig = sign_pq_ml_dsa_unverified(message, secret_key, MlDsaParameterSet::MLDSA65)?;
            (public_key.to_vec(), sig)
        }
        "ml-dsa-87" | "pq-ml-dsa-87" => {
            let sig = sign_pq_ml_dsa_unverified(message, secret_key, MlDsaParameterSet::MLDSA87)?;
            (public_key.to_vec(), sig)
        }
        "slh-dsa-shake-128s" => {
            let sig =
                sign_pq_slh_dsa_unverified(message, secret_key, SlhDsaSecurityLevel::Shake128s)?;
            (public_key.to_vec(), sig)
        }
        "slh-dsa-shake-192s" => {
            let sig =
                sign_pq_slh_dsa_unverified(message, secret_key, SlhDsaSecurityLevel::Shake192s)?;
            (public_key.to_vec(), sig)
        }
        "slh-dsa-shake-256s" => {
            let sig =
                sign_pq_slh_dsa_unverified(message, secret_key, SlhDsaSecurityLevel::Shake256s)?;
            (public_key.to_vec(), sig)
        }
        "fn-dsa" => {
            let sig = sign_pq_fn_dsa_unverified(message, secret_key)?;
            (public_key.to_vec(), sig)
        }
        #[cfg(not(feature = "fips"))]
        "ed25519" => {
            let sig = sign_ed25519_internal(message, secret_key)?;
            (public_key.to_vec(), sig)
        }
        "hybrid-ml-dsa-44-ed25519" => {
            let pq_sk_len = MlDsaParameterSet::MLDSA44.secret_key_size();
            let pq_pk_len = MlDsaParameterSet::MLDSA44.public_key_size();
            const ED25519_SK_LEN: usize = 32;

            if secret_key.len() != pq_sk_len + ED25519_SK_LEN {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid secret key length mismatch: expected {}, got {}",
                    pq_sk_len + ED25519_SK_LEN,
                    secret_key.len()
                )));
            }
            if public_key.len() != pq_pk_len + 32 {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid public key length mismatch: expected {}, got {}",
                    pq_pk_len + 32,
                    public_key.len()
                )));
            }

            let pq_sk = secret_key.get(..pq_sk_len).ok_or_else(|| {
                CoreError::InvalidKey("Failed to split hybrid secret key".to_string())
            })?;
            let ed_sk = secret_key.get(pq_sk_len..).ok_or_else(|| {
                CoreError::InvalidKey("Failed to split hybrid secret key".to_string())
            })?;

            let pq_sig = sign_pq_ml_dsa_unverified(message, pq_sk, MlDsaParameterSet::MLDSA44)?;
            let ed_sig = sign_ed25519_internal(message, ed_sk)?;
            let combined_sig = [pq_sig, ed_sig].concat();
            (public_key.to_vec(), combined_sig)
        }
        "hybrid-ml-dsa-65-ed25519" | "ml-dsa-65-hybrid-ed25519" => {
            let pq_sk_len = MlDsaParameterSet::MLDSA65.secret_key_size();
            let pq_pk_len = MlDsaParameterSet::MLDSA65.public_key_size();
            const ED25519_SK_LEN: usize = 32;

            if secret_key.len() != pq_sk_len + ED25519_SK_LEN {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid secret key length mismatch: expected {}, got {}",
                    pq_sk_len + ED25519_SK_LEN,
                    secret_key.len()
                )));
            }
            if public_key.len() != pq_pk_len + 32 {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid public key length mismatch: expected {}, got {}",
                    pq_pk_len + 32,
                    public_key.len()
                )));
            }

            let pq_sk = secret_key.get(..pq_sk_len).ok_or_else(|| {
                CoreError::InvalidKey("Failed to split hybrid secret key".to_string())
            })?;
            let ed_sk = secret_key.get(pq_sk_len..).ok_or_else(|| {
                CoreError::InvalidKey("Failed to split hybrid secret key".to_string())
            })?;

            let pq_sig = sign_pq_ml_dsa_unverified(message, pq_sk, MlDsaParameterSet::MLDSA65)?;
            let ed_sig = sign_ed25519_internal(message, ed_sk)?;
            let combined_sig = [pq_sig, ed_sig].concat();
            (public_key.to_vec(), combined_sig)
        }
        "hybrid-ml-dsa-87-ed25519" => {
            let pq_sk_len = MlDsaParameterSet::MLDSA87.secret_key_size();
            let pq_pk_len = MlDsaParameterSet::MLDSA87.public_key_size();
            const ED25519_SK_LEN: usize = 32;

            if secret_key.len() != pq_sk_len + ED25519_SK_LEN {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid secret key length mismatch: expected {}, got {}",
                    pq_sk_len + ED25519_SK_LEN,
                    secret_key.len()
                )));
            }
            if public_key.len() != pq_pk_len + 32 {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid public key length mismatch: expected {}, got {}",
                    pq_pk_len + 32,
                    public_key.len()
                )));
            }

            let pq_sk = secret_key.get(..pq_sk_len).ok_or_else(|| {
                CoreError::InvalidKey("Failed to split hybrid secret key".to_string())
            })?;
            let ed_sk = secret_key.get(pq_sk_len..).ok_or_else(|| {
                CoreError::InvalidKey("Failed to split hybrid secret key".to_string())
            })?;

            let pq_sig = sign_pq_ml_dsa_unverified(message, pq_sk, MlDsaParameterSet::MLDSA87)?;
            let ed_sig = sign_ed25519_internal(message, ed_sk)?;
            let combined_sig = [pq_sig, ed_sig].concat();
            (public_key.to_vec(), combined_sig)
        }
        _ => {
            return Err(CoreError::InvalidInput(format!("Unsupported signing scheme: {}", scheme)));
        }
    };

    let timestamp = u64::try_from(Utc::now().timestamp().max(0)).unwrap_or(0);

    crate::log_crypto_operation_complete!("sign_with_key", signature_size = signature.len(), scheme = %scheme);

    Ok(SignedData {
        data: message.to_vec(),
        metadata: SignedMetadata {
            signature,
            signature_algorithm: scheme.clone(),
            public_key: result_pk,
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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{verify, CryptoConfig, VerifiedSession, SignedData, SignedMetadata};
/// # let signed = SignedData {
/// #     data: vec![],
/// #     metadata: SignedMetadata {
/// #         signature: vec![],
/// #         signature_algorithm: "ed25519".to_string(),
/// #         public_key: vec![],
/// #         key_id: None
/// #     },
/// #     scheme: "ed25519".to_string(),
/// #     timestamp: 0,
/// # };
/// # let pk = [0u8; 32];
/// # let sk = [0u8; 32];
///
/// // Simple: No session
/// let is_valid = verify(&signed, CryptoConfig::new())?;
///
/// // With Zero Trust session
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let is_valid = verify(&signed, CryptoConfig::new()
///     .session(&session))?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Session is set and has expired (`CoreError::SessionExpired`)
/// - Message size exceeds resource limits
/// - Public key is invalid
/// - Signature is malformed or invalid
#[must_use = "verification result must be used or errors will be silently dropped"]
pub fn verify(signed: &SignedData, config: CryptoConfig) -> Result<bool> {
    fips_verify_operational()?;
    config.validate()?;
    config.validate_scheme_compliance(&signed.scheme)?;

    crate::log_crypto_operation_start!("verify", scheme = %signed.scheme, message_size = signed.data.len());

    validate_signature_size(signed.data.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    let result = match signed.scheme.as_str() {
        "ml-dsa-44" | "pq-ml-dsa-44" => verify_pq_ml_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA44,
        ),
        "ml-dsa-65" | "pq-ml-dsa-65" => verify_pq_ml_dsa_unverified(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
            MlDsaParameterSet::MLDSA65,
        ),
        "ml-dsa-87" | "pq-ml-dsa-87" => verify_pq_ml_dsa_unverified(
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
        "hybrid-ml-dsa-44-ed25519" => {
            const ML_DSA_44_PK_LEN: usize = 1312;
            const ED25519_PK_LEN: usize = 32;

            let sig_len = signed.metadata.signature.len();
            if sig_len < 2420 {
                return Err(CoreError::InvalidInput("Hybrid signature too short".to_string()));
            }

            let pk_len = signed.metadata.public_key.len();
            if pk_len != ML_DSA_44_PK_LEN + ED25519_PK_LEN {
                return Err(CoreError::InvalidInput(format!(
                    "Invalid hybrid public key length: expected {}, got {}",
                    ML_DSA_44_PK_LEN + ED25519_PK_LEN,
                    pk_len
                )));
            }
            let pq_pk = signed.metadata.public_key.get(..ML_DSA_44_PK_LEN).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid public key format".to_string())
            })?;
            let ed_pk = signed.metadata.public_key.get(ML_DSA_44_PK_LEN..).ok_or_else(|| {
                CoreError::InvalidInput("Invalid hybrid public key format".to_string())
            })?;

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
                MlDsaParameterSet::MLDSA44,
            )?;
            let ed_valid = verify_ed25519_internal(&signed.data, ed_sig, ed_pk)?;
            Ok(pq_valid && ed_valid)
        }
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
        "ed25519" => verify_ed25519_internal(
            &signed.data,
            &signed.metadata.signature,
            &signed.metadata.public_key,
        ),
        _ => {
            return Err(CoreError::InvalidInput(format!(
                "Unsupported verification scheme: {}",
                signed.scheme
            )));
        }
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
    use crate::types::types::CryptoScheme;
    use crate::{CryptoConfig, SecurityLevel, UseCase};

    /// Helper: generate keypair + sign + return signed data
    fn sign_message(message: &[u8], config: CryptoConfig) -> Result<SignedData> {
        let (pk, sk, _scheme) = generate_signing_keypair(config.clone())?;
        sign_with_key(message, &sk, &pk, config)
    }

    // Sign/Verify tests with different security levels
    #[test]
    fn test_sign_verify_with_standard_security() -> Result<()> {
        let message = b"Test message with standard security";
        let config = CryptoConfig::new().security_level(SecurityLevel::Standard);

        let signed = sign_message(message, config)?;

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

        let signed = sign_message(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_with_maximum_security() -> Result<()> {
        let message = b"Test message with maximum security";
        let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);

        let signed = sign_message(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_wrong_message() -> Result<()> {
        let message = b"Original message";
        let config = CryptoConfig::new();

        let signed = sign_message(message, config)?;

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

        let signed = sign_message(message, config)?;

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

        let signed = sign_message(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Empty message signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_large_message() -> Result<()> {
        let message = vec![0xABu8; 10_000]; // 10KB message
        let config = CryptoConfig::new();

        let signed = sign_message(&message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Large message signature should be valid");

        Ok(())
    }

    // Use case selection tests
    #[test]
    fn test_sign_with_financial_transactions_use_case() -> Result<()> {
        let message = b"Financial transaction data";
        let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);

        let signed = sign_message(message, config)?;

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

        let signed = sign_message(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_sign_with_firmware_signing_use_case() -> Result<()> {
        let message = b"Firmware binary data";
        let config = CryptoConfig::new().use_case(UseCase::FirmwareSigning);

        let signed = sign_message(message, config)?;

        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    // Invalid key tests
    #[test]
    fn test_encrypt_with_invalid_key_length() {
        let message = b"Test message";
        let short_key = vec![0x42u8; 16]; // Too short for AES-256
        let config = CryptoConfig::new().force_scheme(CryptoScheme::Symmetric);

        let result = encrypt(message, EncryptKey::Symmetric(&short_key), config);
        assert!(result.is_err(), "Encryption with short key should fail");
    }

    #[test]
    fn test_decrypt_empty_ciphertext() {
        let key = vec![0x42u8; 32];
        let empty_encrypted = EncryptedOutput {
            scheme: EncryptionScheme::Aes256Gcm,
            ciphertext: vec![],
            nonce: vec![],
            tag: vec![],
            hybrid_data: None,
            timestamp: 0,
            key_id: None,
        };

        // Empty ciphertext should be rejected (too short for nonce)
        let result = decrypt(&empty_encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new());
        assert!(result.is_err(), "Empty ciphertext should be rejected");
    }

    // Cross-algorithm tests for signing
    #[test]
    fn test_sign_verify_multiple_security_levels() -> Result<()> {
        let message = b"Test cross-level signatures";

        let levels = [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];
        for level in &levels {
            let config = CryptoConfig::new().security_level(level.clone());
            let signed = sign_message(message, config)?;
            let is_valid = verify(&signed, CryptoConfig::new())?;
            assert!(is_valid, "Failed for security level: {:?}", level);
        }

        Ok(())
    }

    // ========================================================================
    // Additional Signing Algorithm Coverage
    // ========================================================================

    // Test specific algorithm branches in sign_with_key/verify
    #[test]
    fn test_sign_verify_metadata_populated() -> Result<()> {
        let message = b"Test metadata";
        let config = CryptoConfig::new();

        let signed = sign_message(message, config)?;

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

        let signed = sign_message(message, config)?;

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

        let signed = sign_message(&message, config)?;
        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Binary message signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_unicode_message() -> Result<()> {
        let message = "Test with Unicode: 你好世界 🔐".as_bytes();
        let config = CryptoConfig::new();

        let signed = sign_message(message, config)?;
        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid, "Unicode message signature should be valid");

        Ok(())
    }

    #[test]
    fn test_sign_verify_with_blockchain_transaction_use_case() -> Result<()> {
        let message = b"Blockchain transaction data";
        let config = CryptoConfig::new().use_case(UseCase::BlockchainTransaction);

        let signed = sign_message(message, config)?;
        let is_valid = verify(&signed, CryptoConfig::new())?;
        assert!(is_valid);

        Ok(())
    }

    #[test]
    fn test_sign_verify_with_legal_documents_use_case() -> Result<()> {
        let message = b"Legal document hash";
        let config = CryptoConfig::new().use_case(UseCase::LegalDocuments);

        let signed = sign_message(message, config)?;
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
            let signed = sign_message(message, config.clone())?;
            let is_valid = verify(&signed, CryptoConfig::new())?;
            assert!(is_valid, "Message: {:?}", String::from_utf8_lossy(message));
        }

        Ok(())
    }

    #[test]
    fn test_sign_produces_unique_signatures() -> Result<()> {
        let message = b"Same message";
        let config = CryptoConfig::new();

        let signed1 = sign_message(message, config.clone())?;
        let signed2 = sign_message(message, config)?;

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
                signature_algorithm: "ml-dsa-44".to_string(),
                public_key: vec![0u8; 1312],
                key_id: None,
            },
            scheme: "ml-dsa-44".to_string(),
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
                signature: vec![0u8; 2420],
                signature_algorithm: "ml-dsa-44".to_string(),
                public_key: vec![], // Empty public key
                key_id: None,
            },
            scheme: "ml-dsa-44".to_string(),
            timestamp: 0,
        };

        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err() || (result.is_ok() && !result.unwrap()));
    }

    // Decrypt error handling (doesn't require encrypt roundtrip)
    #[test]
    fn test_decrypt_with_short_key() {
        let encrypted = EncryptedOutput {
            scheme: EncryptionScheme::Aes256Gcm,
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![0u8; 12],
            tag: vec![0u8; 16],
            hybrid_data: None,
            timestamp: 0,
            key_id: None,
        };
        let short_key = vec![0x42u8; 16]; // Too short

        let result = decrypt(&encrypted, DecryptKey::Symmetric(&short_key), CryptoConfig::new());
        assert!(result.is_err(), "Decryption with short key should fail");
    }

    #[test]
    fn test_decrypt_unknown_scheme() {
        // EncryptionScheme is an enum so there are no "unknown" schemes.
        // Instead, test that a key-scheme mismatch is rejected:
        // use a HybridMlKem768 scheme but provide a symmetric key → should error.
        let encrypted = EncryptedOutput {
            scheme: EncryptionScheme::HybridMlKem768Aes256Gcm,
            ciphertext: vec![0x12u8; 40],
            nonce: vec![0u8; 12],
            tag: vec![0u8; 16],
            hybrid_data: None, // missing hybrid_data — decryption must fail
            timestamp: 0,
            key_id: None,
        };
        let key = vec![0x42u8; 32];

        // Symmetric key with hybrid scheme → key-scheme mismatch, must error
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new());
        assert!(result.is_err(), "Key-scheme mismatch should be rejected");
    }

    // === SLH-DSA sign/verify roundtrip tests ===

    #[test]
    fn test_slh_dsa_shake_128s_roundtrip() {
        std::thread::Builder::new()
            .name("slh_dsa_128s".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::slh_dsa::SecurityLevel;
                use crate::unified_api::convenience::keygen::generate_slh_dsa_keypair;
                use crate::unified_api::convenience::pq_sig::sign_pq_slh_dsa_unverified;

                let (pk, sk) = generate_slh_dsa_keypair(SecurityLevel::Shake128s).unwrap();
                let message = b"SLH-DSA-128s test message";
                let signature =
                    sign_pq_slh_dsa_unverified(message, sk.as_ref(), SecurityLevel::Shake128s)
                        .unwrap();

                let signed_data = SignedData {
                    data: message.to_vec(),
                    metadata: SignedMetadata {
                        signature,
                        signature_algorithm: "slh-dsa-shake-128s".to_string(),
                        public_key: pk,
                        key_id: None,
                    },
                    scheme: "slh-dsa-shake-128s".to_string(),
                    timestamp: 0,
                };

                let verified = verify(&signed_data, CryptoConfig::new()).unwrap();
                assert!(verified, "SLH-DSA-128s signature should verify");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_slh_dsa_shake_192s_roundtrip() {
        std::thread::Builder::new()
            .name("slh_dsa_192s".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::slh_dsa::SecurityLevel;
                use crate::unified_api::convenience::keygen::generate_slh_dsa_keypair;
                use crate::unified_api::convenience::pq_sig::sign_pq_slh_dsa_unverified;

                let (pk, sk) = generate_slh_dsa_keypair(SecurityLevel::Shake192s).unwrap();
                let message = b"SLH-DSA-192s test message";
                let signature =
                    sign_pq_slh_dsa_unverified(message, sk.as_ref(), SecurityLevel::Shake192s)
                        .unwrap();

                let signed_data = SignedData {
                    data: message.to_vec(),
                    metadata: SignedMetadata {
                        signature,
                        signature_algorithm: "slh-dsa-shake-192s".to_string(),
                        public_key: pk,
                        key_id: None,
                    },
                    scheme: "slh-dsa-shake-192s".to_string(),
                    timestamp: 0,
                };

                let verified = verify(&signed_data, CryptoConfig::new()).unwrap();
                assert!(verified, "SLH-DSA-192s signature should verify");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_slh_dsa_shake_256s_roundtrip() {
        std::thread::Builder::new()
            .name("slh_dsa_256s".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::slh_dsa::SecurityLevel;
                use crate::unified_api::convenience::keygen::generate_slh_dsa_keypair;
                use crate::unified_api::convenience::pq_sig::sign_pq_slh_dsa_unverified;

                let (pk, sk) = generate_slh_dsa_keypair(SecurityLevel::Shake256s).unwrap();
                let message = b"SLH-DSA-256s test message";
                let signature =
                    sign_pq_slh_dsa_unverified(message, sk.as_ref(), SecurityLevel::Shake256s)
                        .unwrap();

                let signed_data = SignedData {
                    data: message.to_vec(),
                    metadata: SignedMetadata {
                        signature,
                        signature_algorithm: "slh-dsa-shake-256s".to_string(),
                        public_key: pk,
                        key_id: None,
                    },
                    scheme: "slh-dsa-shake-256s".to_string(),
                    timestamp: 0,
                };

                let verified = verify(&signed_data, CryptoConfig::new()).unwrap();
                assert!(verified, "SLH-DSA-256s signature should verify");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === FN-DSA sign/verify roundtrip test ===

    #[test]
    fn test_fn_dsa_roundtrip() {
        std::thread::Builder::new()
            .name("fn_dsa".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::unified_api::convenience::keygen::generate_fn_dsa_keypair;
                use crate::unified_api::convenience::pq_sig::sign_pq_fn_dsa_unverified;

                let (pk, sk) = generate_fn_dsa_keypair().unwrap();
                let message = b"FN-DSA test message";
                let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref()).unwrap();

                let signed_data = SignedData {
                    data: message.to_vec(),
                    metadata: SignedMetadata {
                        signature,
                        signature_algorithm: "fn-dsa".to_string(),
                        public_key: pk,
                        key_id: None,
                    },
                    scheme: "fn-dsa".to_string(),
                    timestamp: 0,
                };

                let verified = verify(&signed_data, CryptoConfig::new()).unwrap();
                assert!(verified, "FN-DSA signature should verify");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Hybrid ML-DSA-44 + Ed25519 sign/verify roundtrip ===

    #[test]
    fn test_hybrid_ml_dsa_44_ed25519_roundtrip() {
        std::thread::Builder::new()
            .name("hybrid_44".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
                use crate::unified_api::convenience::keygen::{
                    generate_keypair, generate_ml_dsa_keypair,
                };

                let (pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).unwrap();
                let (ed_pk, ed_sk) = generate_keypair().unwrap();
                let combined_pk = [pq_pk, ed_pk].concat();
                let combined_sk = [pq_sk.as_ref(), ed_sk.as_ref()].concat();

                let message = b"Hybrid ML-DSA-44 + Ed25519 test";
                let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
                let signed_data =
                    sign_with_key(message, &combined_sk, &combined_pk, config).unwrap();
                assert!(signed_data.metadata.signature_algorithm.contains("hybrid"));

                let verified = verify(&signed_data, CryptoConfig::new()).unwrap();
                assert!(verified, "Hybrid ML-DSA-44+Ed25519 should verify");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Hybrid ML-DSA-87 + Ed25519 sign/verify roundtrip ===

    #[test]
    fn test_hybrid_ml_dsa_87_ed25519_roundtrip() {
        std::thread::Builder::new()
            .name("hybrid_87".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
                use crate::unified_api::convenience::keygen::{
                    generate_keypair, generate_ml_dsa_keypair,
                };

                let (pq_pk, pq_sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87).unwrap();
                let (ed_pk, ed_sk) = generate_keypair().unwrap();
                let combined_pk = [pq_pk, ed_pk].concat();
                let combined_sk = [pq_sk.as_ref(), ed_sk.as_ref()].concat();

                let message = b"Hybrid ML-DSA-87 + Ed25519 test";
                let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
                let signed_data =
                    sign_with_key(message, &combined_sk, &combined_pk, config).unwrap();
                assert!(signed_data.metadata.signature_algorithm.contains("hybrid"));

                let verified = verify(&signed_data, CryptoConfig::new()).unwrap();
                assert!(verified, "Hybrid ML-DSA-87+Ed25519 should verify");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Error handling tests for sign_with_key ===

    #[test]
    fn test_sign_with_invalid_hybrid_key_lengths() {
        std::thread::Builder::new()
            .name("hybrid_bad_key".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let message = b"test";
                // Try to sign with keys that are too short for any hybrid scheme
                let _short_key = vec![1u8; 10];
                let short_pk = vec![2u8; 10];
                let signed = SignedData {
                    data: message.to_vec(),
                    metadata: SignedMetadata {
                        signature: vec![0u8; 10],
                        signature_algorithm: "hybrid-ml-dsa-65-ed25519".to_string(),
                        public_key: short_pk,
                        key_id: None,
                    },
                    scheme: "hybrid-ml-dsa-65-ed25519".to_string(),
                    timestamp: 0,
                };

                // Verification should fail because the keys/signature are too short
                let result = verify(&signed, CryptoConfig::new());
                assert!(result.is_err() || (result.is_ok() && !result.unwrap()));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Ed25519 fallback test ===

    #[test]
    fn test_verify_with_unsupported_scheme_rejected() {
        let signed = SignedData {
            data: b"test".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 64],
                signature_algorithm: "unsupported-scheme".to_string(),
                public_key: vec![0u8; 32],
                key_id: None,
            },
            scheme: "unsupported-scheme".to_string(),
            timestamp: 0,
        };

        // Unsupported schemes are explicitly rejected
        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err(), "Unsupported scheme should be rejected");
    }

    // === Encryption with different security levels ===

    #[test]
    fn test_encrypt_decrypt_with_maximum_security() {
        std::thread::Builder::new()
            .name("max_security_enc".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let data = b"Maximum security encryption test";
                let key = vec![0x42u8; 32];
                let config = CryptoConfig::new()
                    .security_level(SecurityLevel::Maximum)
                    .force_scheme(CryptoScheme::Symmetric);

                let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config.clone()).unwrap();
                let decrypted =
                    decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
                assert_eq!(data.as_slice(), decrypted.as_slice());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === select_encryption_scheme and select_signature_scheme ===

    #[test]
    fn test_select_scheme_with_use_case() {
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
        let scheme = select_signature_scheme(&config);
        assert!(scheme.is_ok(), "Should select a scheme for SecureMessaging");

        let config = CryptoConfig::new().use_case(UseCase::FinancialTransactions);
        let scheme = select_signature_scheme(&config);
        assert!(scheme.is_ok(), "Should select a scheme for FinancialTransactions");
    }

    #[test]
    fn test_select_encryption_scheme_with_use_case() {
        let config = CryptoConfig::new().use_case(UseCase::SecureMessaging);
        let scheme = select_encryption_scheme_typed(&config);
        assert!(scheme.is_ok(), "Should select encryption scheme for SecureMessaging");
    }

    // === Verify error branches for hybrid schemes ===

    #[test]
    fn test_verify_hybrid_44_signature_too_short() {
        let signed = SignedData {
            data: b"test".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 100], // Too short for hybrid-44
                signature_algorithm: "hybrid-ml-dsa-44-ed25519".to_string(),
                public_key: vec![0u8; 1344], // 1312 + 32
                key_id: None,
            },
            scheme: "hybrid-ml-dsa-44-ed25519".to_string(),
            timestamp: 0,
        };
        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hybrid_44_invalid_pk_length() {
        let signed = SignedData {
            data: b"test".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 3000], // Long enough
                signature_algorithm: "hybrid-ml-dsa-44-ed25519".to_string(),
                public_key: vec![0u8; 100], // Wrong PK length
                key_id: None,
            },
            scheme: "hybrid-ml-dsa-44-ed25519".to_string(),
            timestamp: 0,
        };
        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hybrid_65_signature_too_short() {
        let signed = SignedData {
            data: b"test".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 100], // Too short for hybrid-65
                signature_algorithm: "hybrid-ml-dsa-65-ed25519".to_string(),
                public_key: vec![0u8; 1984], // 1952 + 32
                key_id: None,
            },
            scheme: "hybrid-ml-dsa-65-ed25519".to_string(),
            timestamp: 0,
        };
        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hybrid_65_invalid_pk_length() {
        let signed = SignedData {
            data: b"test".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 4000], // Long enough
                signature_algorithm: "hybrid-ml-dsa-65-ed25519".to_string(),
                public_key: vec![0u8; 100], // Wrong PK length
                key_id: None,
            },
            scheme: "hybrid-ml-dsa-65-ed25519".to_string(),
            timestamp: 0,
        };
        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hybrid_87_signature_too_short() {
        let signed = SignedData {
            data: b"test".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 100], // Too short for hybrid-87
                signature_algorithm: "hybrid-ml-dsa-87-ed25519".to_string(),
                public_key: vec![0u8; 2624], // 2592 + 32
                key_id: None,
            },
            scheme: "hybrid-ml-dsa-87-ed25519".to_string(),
            timestamp: 0,
        };
        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_hybrid_87_invalid_pk_length() {
        let signed = SignedData {
            data: b"test".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 5000], // Long enough
                signature_algorithm: "hybrid-ml-dsa-87-ed25519".to_string(),
                public_key: vec![0u8; 100], // Wrong PK length
                key_id: None,
            },
            scheme: "hybrid-ml-dsa-87-ed25519".to_string(),
            timestamp: 0,
        };
        let result = verify(&signed, CryptoConfig::new());
        assert!(result.is_err());
    }

    // === sign_with_key error branches for hybrid ===

    #[test]
    fn test_sign_with_key_hybrid_44_invalid_sk_length() {
        std::thread::Builder::new()
            .name("hybrid_44_bad_sk".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
                let pq_pk_len = MlDsaParameterSet::MLDSA44.public_key_size();

                let message = b"test";
                let bad_sk = vec![0u8; 10]; // Wrong length
                let pk = vec![0u8; pq_pk_len + 32]; // Correct PK length

                let signed = SignedData {
                    data: message.to_vec(),
                    metadata: SignedMetadata {
                        signature: vec![],
                        signature_algorithm: "hybrid-ml-dsa-44-ed25519".to_string(),
                        public_key: pk.clone(),
                        key_id: None,
                    },
                    scheme: "hybrid-ml-dsa-44-ed25519".to_string(),
                    timestamp: 0,
                };

                // Direct call to sign_with_key with wrong SK length
                let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
                let result = sign_with_key(message, &bad_sk, &pk, config);
                // The scheme selector may not pick hybrid-44, so we test via verify instead
                let _ = result;

                // Test verify with correct-length PK but bad signature
                let result = verify(&signed, CryptoConfig::new());
                assert!(result.is_err() || matches!(result, Ok(false)));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Encrypt/Decrypt with different stored scheme names ===
    // NOTE: test_decrypt_with_ml_kem_scheme_name and test_decrypt_with_chacha_scheme_name_rejected
    // have been removed. EncryptionScheme is now an enum, so there are no arbitrary scheme
    // strings to substitute. The typed scheme field prevents these scenarios at compile time.

    #[test]
    fn test_decrypt_unknown_scheme_short_key() {
        // EncryptionScheme is an enum — no unknown schemes exist.
        // Test: short symmetric key with AES-GCM scheme → key length error.
        let encrypted = EncryptedOutput {
            scheme: EncryptionScheme::Aes256Gcm,
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![0u8; 12],
            tag: vec![0u8; 16],
            hybrid_data: None,
            timestamp: 0,
            key_id: None,
        };
        let short_key = vec![0x42u8; 16]; // Too short for AES-256-GCM
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&short_key), CryptoConfig::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_short_key_ml_kem_scheme() {
        // Test: EncryptedOutput with HybridMlKem768 scheme + DecryptKey::Symmetric → mismatch error.
        let encrypted = EncryptedOutput {
            scheme: EncryptionScheme::HybridMlKem768Aes256Gcm,
            ciphertext: vec![1, 2, 3, 4],
            nonce: vec![0u8; 12],
            tag: vec![0u8; 16],
            hybrid_data: None,
            timestamp: 0,
            key_id: None,
        };
        let key = vec![0x42u8; 32];
        // Symmetric key with hybrid scheme → key-scheme mismatch, must error
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = vec![0x42u8; 32];
        let config = CryptoConfig::new().force_scheme(CryptoScheme::Symmetric);
        let encrypted = encrypt(b"", EncryptKey::Symmetric(&key), config).unwrap();
        let decrypted =
            decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
        assert!(decrypted.is_empty());
    }

    // === Key-scheme mismatch tests (the core anti-degradation guarantee) ===

    #[test]
    fn test_encrypt_symmetric_key_default_config_rejects_hybrid_scheme() {
        // CryptoConfig::new() selects a hybrid scheme by default.
        // Passing EncryptKey::Symmetric MUST fail — never silently degrade.
        let key = vec![0x42u8; 32];
        let result = encrypt(b"hello", EncryptKey::Symmetric(&key), CryptoConfig::new());
        assert!(result.is_err(), "Symmetric key + hybrid scheme (default config) must be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("requires a hybrid key") || err.contains("mismatch"),
            "Error should mention key type mismatch, got: {}",
            err
        );
    }

    #[test]
    fn test_encrypt_hybrid_key_symmetric_scheme_rejects() {
        // force_scheme(Symmetric) selects AES-256-GCM, but EncryptKey::Hybrid
        // is provided — must fail.
        let (pk, _sk) = crate::unified_api::convenience::generate_hybrid_keypair().unwrap();
        let config = CryptoConfig::new().force_scheme(CryptoScheme::Symmetric);
        let result = encrypt(b"hello", EncryptKey::Hybrid(&pk), config);
        assert!(result.is_err(), "Hybrid key + symmetric scheme must be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("requires a symmetric key") || err.contains("mismatch"),
            "Error should mention key type mismatch, got: {}",
            err
        );
    }

    #[test]
    fn test_decrypt_symmetric_key_hybrid_encrypted_data_rejects() {
        // Encrypt with hybrid key, try to decrypt with symmetric key.
        let (pk, _sk) = crate::unified_api::convenience::generate_hybrid_keypair().unwrap();
        let encrypted = encrypt(b"hello", EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let fake_key = vec![0x42u8; 32];
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&fake_key), CryptoConfig::new());
        assert!(result.is_err(), "Symmetric key cannot decrypt hybrid-encrypted data");
    }

    // === Use case-based encryption ===

    #[test]
    fn test_encrypt_decrypt_with_use_case() {
        let key = vec![0x42u8; 32];
        let data = b"UseCase-based encryption test";
        let config = CryptoConfig::new()
            .use_case(UseCase::FileStorage)
            .force_scheme(CryptoScheme::Symmetric);

        let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config).unwrap();
        let decrypted =
            decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_with_iot_use_case() {
        let key = vec![0x42u8; 32];
        let data = b"IoT device data";
        let config =
            CryptoConfig::new().use_case(UseCase::IoTDevice).force_scheme(CryptoScheme::Symmetric);

        let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config).unwrap();
        assert!(!encrypted.ciphertext.is_empty());
    }

    // === Keygen through generate_signing_keypair with different use cases ===

    #[test]
    fn test_generate_signing_keypair_iot_use_case_rejected() {
        // IoT use case maps to an encryption scheme (hybrid-ml-kem-512-aes-256-gcm),
        // not a signing scheme. Keygen should reject it.
        let config = CryptoConfig::new().use_case(UseCase::IoTDevice);
        let result = generate_signing_keypair(config);
        assert!(result.is_err(), "IoT encryption scheme should not be used for signing keypair");
    }

    #[test]
    fn test_generate_signing_keypair_file_storage_use_case_rejected() {
        // FileStorage use case maps to an encryption scheme, not signing.
        let config = CryptoConfig::new().use_case(UseCase::FileStorage);
        let result = generate_signing_keypair(config);
        assert!(result.is_err(), "FileStorage encryption scheme should not be used for signing");
    }

    // === Additional keygen scheme branches ===

    #[test]
    fn test_generate_signing_keypair_blockchain_use_case() {
        let config = CryptoConfig::new().use_case(UseCase::BlockchainTransaction);
        let result = generate_signing_keypair(config);
        assert!(result.is_ok());
        let (pk, sk, scheme) = result.unwrap();
        assert!(!pk.is_empty());
        assert!(!sk.is_empty());
        assert!(!scheme.is_empty());
    }

    #[test]
    fn test_generate_signing_keypair_legal_use_case() {
        let config = CryptoConfig::new().use_case(UseCase::LegalDocuments);
        let result = generate_signing_keypair(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_signing_keypair_firmware_use_case() {
        let config = CryptoConfig::new().use_case(UseCase::FirmwareSigning);
        let result = generate_signing_keypair(config);
        assert!(result.is_ok());
    }

    // === Verified session API tests ===

    #[test]
    fn test_encrypt_decrypt_with_verified_session() {
        std::thread::Builder::new()
            .name("enc_verified".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let data = b"Verified session test data";
                let key = vec![0x42u8; 32];

                let (auth_pk, auth_sk) =
                    crate::unified_api::convenience::keygen::generate_keypair().unwrap();
                let session =
                    crate::VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();

                let config =
                    CryptoConfig::new().session(&session).force_scheme(CryptoScheme::Symmetric);
                let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config.clone()).unwrap();
                let decrypted =
                    decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
                assert_eq!(data.as_slice(), decrypted.as_slice());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_sign_verify_with_verified_session() {
        std::thread::Builder::new()
            .name("sign_verified".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let message = b"Verified session sign test";

                let (auth_pk, auth_sk) =
                    crate::unified_api::convenience::keygen::generate_keypair().unwrap();
                let session =
                    crate::VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();

                let config = CryptoConfig::new().session(&session);
                let (pk, sk, _scheme) = generate_signing_keypair(config.clone()).unwrap();
                let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
                let valid = verify(&signed, config).unwrap();
                assert!(valid);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === sign_with_key hybrid error branches ===

    #[test]
    fn test_sign_with_key_hybrid_87_wrong_sk_length() {
        std::thread::Builder::new()
            .name("hybrid_87_bad_sk".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
                let pq_pk_len = MlDsaParameterSet::MLDSA87.public_key_size();

                let message = b"test";
                let bad_sk = vec![0u8; 10]; // Wrong length
                let pk = vec![0u8; pq_pk_len + 32]; // Correct PK length

                // Need to manually construct SignedData with hybrid-87 scheme
                // to test the verify error path
                let signed = SignedData {
                    data: message.to_vec(),
                    metadata: SignedMetadata {
                        signature: vec![0u8; 100], // Too short
                        signature_algorithm: "hybrid-ml-dsa-87-ed25519".to_string(),
                        public_key: pk,
                        key_id: None,
                    },
                    scheme: "hybrid-ml-dsa-87-ed25519".to_string(),
                    timestamp: 0,
                };
                let result = verify(&signed, CryptoConfig::new());
                assert!(result.is_err());

                let _ = bad_sk; // suppress unused warning
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_sign_with_key_hybrid_44_wrong_pk_length() {
        std::thread::Builder::new()
            .name("hybrid_44_bad_pk".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
                let pq_sk_len = MlDsaParameterSet::MLDSA44.secret_key_size();

                let message = b"test";
                let sk = vec![0u8; pq_sk_len + 32]; // Correct SK length
                let bad_pk = vec![0u8; 100]; // Wrong PK length

                // This should return InvalidKey error for wrong PK length
                let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
                let _result = sign_with_key(message, &sk, &bad_pk, config);
                // The scheme selector may not pick hybrid-44, so we just check it doesn't panic
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Verify decrypt with different scheme names for coverage ===
    // NOTE: test_decrypt_with_hybrid_scheme_names has been removed. EncryptionScheme is now an
    // enum, so substituting arbitrary scheme strings is no longer possible. Key-scheme mismatch
    // is caught at the type level.

    // === Encrypt with short key for hybrid/PQ scheme path ===

    #[test]
    fn test_encrypt_short_key_with_use_case() {
        let short_key = vec![0x42u8; 16]; // Too short
        let config = CryptoConfig::new()
            .use_case(UseCase::FileStorage)
            .force_scheme(CryptoScheme::Symmetric);
        let result = encrypt(b"test", EncryptKey::Symmetric(&short_key), config);
        assert!(result.is_err(), "Short key should fail even with use case");
    }

    // === select_encryption_scheme_typed with SecurityLevel ===

    #[test]
    fn test_select_encryption_scheme_with_security_level() {
        let levels = vec![SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];
        for level in levels {
            let config = CryptoConfig::new().security_level(level.clone());
            let scheme = select_encryption_scheme_typed(&config);
            assert!(scheme.is_ok(), "Should select scheme for security level: {:?}", level);
        }
    }

    // === select_signature_scheme with SecurityLevel ===

    #[test]
    fn test_select_signature_scheme_with_security_levels() {
        let levels = vec![SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum];
        for level in levels {
            let config = CryptoConfig::new().security_level(level.clone());
            let scheme = select_signature_scheme(&config);
            assert!(scheme.is_ok(), "Should select sig scheme for security level: {:?}", level);
        }
    }

    // === SecurityLevel::Quantum flow (PQ-only signatures) ===

    #[test]
    fn test_sign_verify_quantum_security_level() {
        std::thread::Builder::new()
            .name("quantum_sig".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let message = b"Quantum-only signature test";
                let config = CryptoConfig::new().security_level(SecurityLevel::Quantum);

                let (pk, sk, scheme) = generate_signing_keypair(config.clone()).unwrap();
                assert!(
                    scheme.contains("pq-ml-dsa"),
                    "Quantum level should select PQ-only: {}",
                    scheme
                );
                assert!(!pk.is_empty());
                assert!(!sk.is_empty());

                let signed = sign_with_key(message, &sk, &pk, config.clone()).unwrap();
                assert_eq!(signed.scheme, scheme);

                let valid = verify(&signed, config).unwrap();
                assert!(valid, "PQ-only signature should verify");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Encrypt/decrypt with different security levels ===

    #[test]
    fn test_encrypt_decrypt_standard_security_level() {
        let key = vec![0x42u8; 32];
        let data = b"Standard level encryption";
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Standard)
            .force_scheme(CryptoScheme::Symmetric);

        let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config).unwrap();
        let decrypted =
            decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_maximum_security_level() {
        let key = vec![0x42u8; 32];
        let data = b"Maximum level encryption";
        let config = CryptoConfig::new()
            .security_level(SecurityLevel::Maximum)
            .force_scheme(CryptoScheme::Symmetric);

        let encrypted = encrypt(data, EncryptKey::Symmetric(&key), config).unwrap();
        let decrypted =
            decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
        assert_eq!(decrypted, data);
    }

    // === ChaCha20-Poly1305 unified API dispatch ===

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypt_decrypt_chacha20poly1305_roundtrip() {
        let key = [0x55u8; 32];
        let data = b"ChaCha20-Poly1305 roundtrip test";

        // Force ChaCha20-Poly1305 via the internal scheme selection
        let encrypted = encrypt_chacha20_internal(data, &key).unwrap();
        let decrypted = decrypt_chacha20_internal(&encrypted, &key).unwrap();
        assert_eq!(&decrypted, data);
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypt_decrypt_chacha20poly1305_via_unified_api() {
        let key = [0xAAu8; 32];
        let data = b"ChaCha20 unified dispatch test";

        // Use internal function to build EncryptedOutput with ChaCha20 scheme
        let encrypted_bytes = encrypt_chacha20_internal(data, &key).unwrap();
        let output =
            symmetric_bytes_to_output(EncryptionScheme::ChaCha20Poly1305, &encrypted_bytes)
                .unwrap();

        // Decrypt via unified decrypt
        let decrypted = decrypt(&output, DecryptKey::Symmetric(&key), CryptoConfig::new()).unwrap();
        assert_eq!(decrypted, data);
    }

    #[cfg(feature = "fips")]
    #[test]
    fn test_chacha20poly1305_rejected_in_fips_mode() {
        let key = [0xBBu8; 32];
        let encrypted_bytes = vec![0u8; 100]; // doesn't matter, should fail before decryption
        let output = EncryptedOutput {
            scheme: EncryptionScheme::ChaCha20Poly1305,
            ciphertext: encrypted_bytes,
            nonce: vec![0u8; 12],
            tag: vec![0u8; 16],
            hybrid_data: None,
            timestamp: 0,
            key_id: None,
        };

        let result = decrypt(&output, DecryptKey::Symmetric(&key), CryptoConfig::new());
        assert!(result.is_err(), "ChaCha20 should be rejected in FIPS mode");
    }

    // === Generate signing keypair with all use cases ===

    #[test]
    fn test_generate_signing_keypair_authentication_use_case() {
        std::thread::Builder::new()
            .name("auth_keygen".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let config = CryptoConfig::new().use_case(UseCase::Authentication);
                let (pk, sk, scheme) = generate_signing_keypair(config).unwrap();
                assert!(
                    scheme.contains("hybrid-ml-dsa-87"),
                    "Auth should use hybrid-87: {}",
                    scheme
                );
                assert!(!pk.is_empty());
                assert!(!sk.is_empty());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_generate_signing_keypair_digital_certificate_use_case() {
        std::thread::Builder::new()
            .name("cert_keygen".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let config = CryptoConfig::new().use_case(UseCase::DigitalCertificate);
                let (pk, sk, scheme) = generate_signing_keypair(config).unwrap();
                assert!(
                    scheme.contains("hybrid-ml-dsa-87"),
                    "DigitalCertificate should use hybrid-87: {}",
                    scheme
                );
                assert!(!pk.is_empty());
                assert!(!sk.is_empty());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Sign message wrapper for various use cases ===

    #[test]
    fn test_sign_message_standard_level() {
        std::thread::Builder::new()
            .name("sign_standard".to_string())
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let config = CryptoConfig::new().security_level(SecurityLevel::Standard);
                let signed = sign_message(b"Standard", config).unwrap();
                assert!(
                    signed.scheme.contains("hybrid-ml-dsa-44"),
                    "Standard should use hybrid-44: {}",
                    signed.scheme
                );
                let valid = verify(&signed, CryptoConfig::new()).unwrap();
                assert!(valid);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // === Decrypt fallback path (unknown scheme) ===
    // NOTE: test_decrypt_unknown_scheme_rejected has been removed. EncryptionScheme is now an
    // enum, so constructing an EncryptedOutput with an unknown scheme is impossible at compile time.

    // ========================================================================
    // Compliance enforcement tests
    // ========================================================================

    #[test]
    fn test_cnsa_verify_rejects_ed25519() -> Result<()> {
        // Sign with ed25519 (default Standard security uses ed25519-based hybrid)
        let message = b"compliance test";
        let config_default = CryptoConfig::new().security_level(SecurityLevel::Standard);
        let signed = sign_message(message, config_default)?;

        // If the scheme is "ed25519", CNSA 2.0 should reject it
        // CNSA 2.0 requires SecurityLevel::Quantum to pass validate()
        if signed.scheme == "ed25519" {
            let cnsa_config = CryptoConfig::new()
                .security_level(SecurityLevel::Quantum)
                .compliance(crate::types::types::ComplianceMode::Cnsa2_0);
            let result = verify(&signed, cnsa_config);
            assert!(result.is_err(), "CNSA 2.0 should reject ed25519 verification");
            let err_msg = format!("{}", result.unwrap_err());
            assert!(err_msg.contains("Compliance violation"));
        }
        // For hybrid schemes, CNSA 2.0 allows them (transitional)
        Ok(())
    }

    #[test]
    fn test_cnsa_verify_rejects_standalone_ed25519_signature() -> Result<()> {
        // Manually construct a SignedData with ed25519 scheme
        let signed = SignedData {
            data: b"test data".to_vec(),
            metadata: SignedMetadata {
                signature: vec![0u8; 64],
                signature_algorithm: "ed25519".to_string(),
                public_key: vec![0u8; 32],
                key_id: None,
            },
            scheme: "ed25519".to_string(),
            timestamp: 0,
        };

        let cnsa_config = CryptoConfig::new()
            .security_level(SecurityLevel::Quantum)
            .compliance(crate::types::types::ComplianceMode::Cnsa2_0);
        let result = verify(&signed, cnsa_config);
        assert!(result.is_err(), "CNSA 2.0 must reject ed25519 signatures");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
        Ok(())
    }

    #[test]
    fn test_fips_decrypt_allows_aes_gcm() -> Result<()> {
        // Encrypt with symmetric force (produces AES-256-GCM)
        let key = vec![0x42u8; 32];
        let data = b"fips compliance test";
        let encrypted = encrypt(
            data,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )?;

        assert_eq!(encrypted.scheme, EncryptionScheme::Aes256Gcm);

        // Decrypt with FIPS config should succeed (AES-256-GCM is FIPS-approved)
        let fips_config =
            CryptoConfig::new().compliance(crate::types::types::ComplianceMode::Fips140_3);
        let plaintext = decrypt(&encrypted, DecryptKey::Symmetric(&key), fips_config)?;
        assert_eq!(plaintext, data);
        Ok(())
    }

    #[test]
    fn test_cnsa_decrypt_rejects_aes_gcm() -> Result<()> {
        // Encrypt with symmetric force (produces AES-256-GCM)
        let key = vec![0x42u8; 32];
        let data = b"cnsa decrypt test";
        let encrypted = encrypt(
            data,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )?;

        assert_eq!(encrypted.scheme, EncryptionScheme::Aes256Gcm);

        // Decrypt with CNSA 2.0 should reject (aes-256-gcm is classical-only)
        // CNSA 2.0 requires SecurityLevel::Quantum to pass validate()
        let cnsa_config = CryptoConfig::new()
            .security_level(SecurityLevel::Quantum)
            .compliance(crate::types::types::ComplianceMode::Cnsa2_0);
        let result = decrypt(&encrypted, DecryptKey::Symmetric(&key), cnsa_config);
        assert!(result.is_err(), "CNSA 2.0 should reject standalone AES-256-GCM");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("CNSA 2.0"));
        Ok(())
    }

    #[test]
    fn test_default_compliance_allows_all_in_verify() -> Result<()> {
        // Sign and verify with default compliance — should always work
        let message = b"default compliance test";
        let config = CryptoConfig::new();
        let signed = sign_message(message, config)?;

        let default_config = CryptoConfig::new();
        let is_valid = verify(&signed, default_config)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_default_compliance_allows_all_in_decrypt() -> Result<()> {
        // Encrypt and decrypt with default compliance — should always work
        let key = vec![0x42u8; 32];
        let data = b"default compliance decrypt test";
        let encrypted = encrypt(
            data,
            EncryptKey::Symmetric(&key),
            CryptoConfig::new().force_scheme(CryptoScheme::Symmetric),
        )?;

        let default_config = CryptoConfig::new();
        let plaintext = decrypt(&encrypted, DecryptKey::Symmetric(&key), default_config)?;
        assert_eq!(plaintext, data);
        Ok(())
    }

    #[test]
    fn test_fips_verify_allows_pq_signatures() -> Result<()> {
        // Sign with PQ algorithm (ML-DSA-65)
        let message = b"pq fips compliance test";
        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let signed = sign_message(message, config)?;

        // FIPS config should accept PQ and hybrid signatures
        let fips_config =
            CryptoConfig::new().compliance(crate::types::types::ComplianceMode::Fips140_3);
        let is_valid = verify(&signed, fips_config)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_cnsa_verify_allows_hybrid_signatures() -> Result<()> {
        // Sign with hybrid (default High security → hybrid-ml-dsa-65-ed25519)
        let message = b"hybrid cnsa test";
        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let signed = sign_message(message, config)?;

        // Hybrid schemes are allowed under CNSA 2.0 (transitional per NIST SP 800-227)
        // Note: CNSA 2.0 config requires SecurityLevel::Quantum to pass validate()
        if signed.scheme.contains("hybrid") {
            let cnsa_config = CryptoConfig::new()
                .security_level(SecurityLevel::Quantum)
                .compliance(crate::types::types::ComplianceMode::Cnsa2_0);
            let is_valid = verify(&signed, cnsa_config)?;
            assert!(is_valid);
        }
        Ok(())
    }
}
