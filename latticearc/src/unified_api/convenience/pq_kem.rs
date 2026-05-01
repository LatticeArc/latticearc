//! Post-quantum KEM operations (ML-KEM)
//!
//! This module provides post-quantum key encapsulation mechanism operations
//! using ML-KEM (FIPS 203) with **FIPS 140-3 validated** aws-lc-rs.
//!
//! Encryption uses ML-KEM encapsulation to derive a shared secret, then encrypts
//! the payload with AES-GCM using that shared secret as the key. The wire format
//! is: `ML-KEM ciphertext || AES-GCM encrypted data`.
//!
//! # Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//! - `SecurityMode::Verified(&session)`: Validates session before operation
//! - `SecurityMode::Unverified`: Skips session validation
//!
//! The `_unverified` variants are opt-out functions for scenarios where Zero Trust
//! verification is not required or not possible.

use tracing::warn;
use zeroize::Zeroizing;

use crate::log_crypto_operation_error;
use crate::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use crate::types::types::SecurityLevel;
use crate::unified_api::logging::op;

use super::aes_gcm::encrypt_aes_gcm_internal;
use crate::unified_api::CoreConfig;
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::zero_trust::SecurityMode;

/// Build the HKDF `info` string for `encrypt_pq_ml_kem` /
/// `decrypt_pq_ml_kem`.
///
/// Thin wrapper over [`crate::types::domains::hkdf_kem_info`] that
/// pins the domain-separation label to [`PQ_KEM_AEAD_KEY_INFO`]. The
/// shared helper is also used by
/// [`crate::hybrid::pq_only::encrypt_pq_only`] (round-12 audit fix
/// L-2) so encrypt/decrypt drift across the two parallel APIs is
/// structurally impossible.
fn pq_kem_aead_key_info(kem_ciphertext: &[u8]) -> Vec<u8> {
    crate::types::domains::hkdf_kem_info(
        crate::types::domains::PQ_KEM_AEAD_KEY_INFO,
        kem_ciphertext,
    )
}

use crate::primitives::resource_limits::validate_encryption_size;

/// Maps `CoreConfig.security_level` to the expected `MlKemSecurityLevel`.
///
/// This enables consistency validation between the explicit algorithm parameter
/// and the config's security level.
fn expected_ml_kem_level(security_level: SecurityLevel) -> MlKemSecurityLevel {
    match security_level {
        SecurityLevel::Standard => MlKemSecurityLevel::MlKem512,
        SecurityLevel::High => MlKemSecurityLevel::MlKem768,
        SecurityLevel::Maximum => MlKemSecurityLevel::MlKem1024,
    }
}

/// Warn if the explicit ML-KEM security level differs from the CoreConfig's security_level.
fn check_ml_kem_config_consistency(explicit: MlKemSecurityLevel, config: &CoreConfig) {
    let expected = expected_ml_kem_level(config.security_level);
    if expected != explicit {
        warn!(
            "Explicit MlKemSecurityLevel ({:?}) differs from CoreConfig security_level ({:?} \
             → {:?}). Using explicit parameter.",
            explicit, config.security_level, expected
        );
    }
}

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
        log_crypto_operation_error!(op::ENCRYPT_PQ_ML_KEM, "resource limit exceeded");
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let pk =
        crate::primitives::kem::ml_kem::MlKemPublicKey::new(security_level, ml_kem_pk.to_vec())
            .map_err(|e| {
                log_crypto_operation_error!(op::ENCRYPT_PQ_ML_KEM, e);
                CoreError::InvalidInput("Invalid ML-KEM public key format".to_string())
            })?;

    let (shared_secret, ciphertext) = MlKem::encapsulate(&pk).map_err(|e| {
        log_crypto_operation_error!(op::ENCRYPT_PQ_ML_KEM, "encapsulation failed");
        CoreError::EncryptionFailed(format!("ML-KEM encapsulation failed: {}", e))
    })?;

    // Derive AES-256 key from ML-KEM shared secret via HKDF, binding the
    // KEM ciphertext into the info string per RFC 9180 §5.1 (HPKE
    // channel binding). The label-only variant of this call could not
    // detect an adversary swapping ciphertext halves if ML-KEM IND-CCA2
    // ever degraded.
    let kem_ct_bytes = ciphertext.into_bytes();
    let info = pq_kem_aead_key_info(&kem_ct_bytes);
    let hkdf_result =
        crate::primitives::kdf::hkdf::hkdf(shared_secret.expose_secret(), None, Some(&info), 32)
            .map_err(|e| {
                log_crypto_operation_error!(op::ENCRYPT_PQ_ML_KEM, "HKDF failed");
                CoreError::EncryptionFailed(format!("Key derivation failed: {e}"))
            })?;
    let encrypted_data = encrypt_aes_gcm_internal(data, hkdf_result.expose_secret())?;

    // Combine ciphertext and encrypted data
    let mut result = kem_ct_bytes;
    result.extend_from_slice(&encrypted_data);

    crate::log_crypto_operation_complete!(
        "encrypt_pq_ml_kem",
        security_level = ?security_level,
        result_len = result.len()
    );

    Ok(result)
}

/// Internal implementation of ML-KEM decryption.
///
/// Decrypts data that was encrypted with [`encrypt_pq_ml_kem_internal`]. The wire
/// format is: `ML-KEM ciphertext || AES-GCM encrypted payload`.
///
/// # Errors
///
/// Returns an error if:
/// - The encrypted data is shorter than the expected ciphertext size
/// - The ML-KEM decapsulation fails (invalid key or ciphertext)
/// - The AES-GCM decryption of the payload fails
fn decrypt_pq_ml_kem_internal(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
) -> Result<Zeroizing<Vec<u8>>> {
    use super::aes_gcm::decrypt_aes_gcm_internal;
    use crate::primitives::kem::ml_kem::{MlKemCiphertext, MlKemSecretKey};

    crate::log_crypto_operation_start!(
        "decrypt_pq_ml_kem",
        security_level = ?security_level,
        data_len = encrypted_data.len()
    );

    // All adversary-reachable failure paths collapse to one opaque error.
    // Attacker controls `encrypted_data` (both KEM ciphertext prefix and AEAD
    // tail); distinguishing "too short" vs "bad KEM ct" vs "decap failed" vs
    // "AEAD tag failed" is a per-stage oracle. Matches HPKE RFC 9180 §5.2
    // and the same pattern used in pq_only::decrypt_pq_only.
    let opaque = || CoreError::DecryptionFailed("decryption failed".to_string());

    let ct_size = security_level.ciphertext_size();
    if encrypted_data.len() < ct_size {
        log_crypto_operation_error!(op::DECRYPT_PQ_ML_KEM, "encrypted data too short");
        return Err(opaque());
    }

    let (ct_bytes, aes_encrypted) = encrypted_data.split_at(ct_size);

    let sk = MlKemSecretKey::new(security_level, ml_kem_sk.to_vec()).map_err(|_e| {
        log_crypto_operation_error!(op::DECRYPT_PQ_ML_KEM, "invalid secret key");
        opaque()
    })?;

    let ct = MlKemCiphertext::new(security_level, ct_bytes.to_vec()).map_err(|_e| {
        log_crypto_operation_error!(op::DECRYPT_PQ_ML_KEM, "invalid ciphertext");
        opaque()
    })?;

    let shared_secret = MlKem::decapsulate(&sk, &ct).map_err(|_e| {
        log_crypto_operation_error!(op::DECRYPT_PQ_ML_KEM, "decapsulation failed");
        opaque()
    })?;

    // Derive AES-256 key from ML-KEM shared secret via HKDF, binding
    // the KEM ciphertext into the info string. Must match the encrypt
    // path byte-for-byte; `pq_kem_aead_key_info(ct_bytes)` is the
    // single canonical helper to prevent encrypt / decrypt drift.
    let info = pq_kem_aead_key_info(ct_bytes);
    let hkdf_result =
        crate::primitives::kdf::hkdf::hkdf(shared_secret.expose_secret(), None, Some(&info), 32)
            .map_err(|_e| {
                log_crypto_operation_error!(op::DECRYPT_PQ_ML_KEM, "HKDF failed");
                opaque()
            })?;
    let plaintext = decrypt_aes_gcm_internal(aes_encrypted, hkdf_result.expose_secret())?;

    crate::log_crypto_operation_complete!(
        "decrypt_pq_ml_kem",
        security_level = ?security_level,
        result_len = plaintext.len()
    );

    Ok(plaintext)
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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{encrypt_pq_ml_kem, SecurityMode, VerifiedSession};
/// use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
/// # let data = b"example data";
/// # let ml_kem_pk = vec![0u8; 1184]; // ML-KEM-768 public key size
/// # let pk = [0u8; 32];
/// # let sk = [0u8; 32];
///
/// // With Zero Trust (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let encrypted = encrypt_pq_ml_kem(data, &ml_kem_pk, MlKemSecurityLevel::MlKem768, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let encrypted = encrypt_pq_ml_kem(data, &ml_kem_pk, MlKemSecurityLevel::MlKem768, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
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
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired (`CoreError::SessionExpired`)
/// - The encrypted data is shorter than the expected ciphertext size
/// - The secret key is invalid for the specified security level
/// - The ML-KEM decapsulation operation fails
/// - The AES-GCM decryption of the payload fails
pub fn decrypt_pq_ml_kem(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
    mode: SecurityMode,
) -> Result<Zeroizing<Vec<u8>>> {
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
    check_ml_kem_config_consistency(security_level, config);
    encrypt_pq_ml_kem_internal(data, ml_kem_pk, security_level)
}

/// Decrypt data using ML-KEM with custom configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The mode is `Verified` and the session has expired
/// - The configuration validation fails
/// - The ML-KEM decapsulation or AES-GCM decryption fails
pub fn decrypt_pq_ml_kem_with_config(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Zeroizing<Vec<u8>>> {
    mode.validate()?;
    config.validate()?;
    check_ml_kem_config_consistency(security_level, config);
    decrypt_pq_ml_kem_internal(encrypted_data, ml_kem_sk, security_level)
}

// ============================================================================
// Unverified API (Opt-Out) — see `convenience::mod` docs for the shared
// security guidance on when to use `_unverified` variants.
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
/// - The encrypted data is shorter than the expected ciphertext size
/// - The secret key is invalid for the specified security level
/// - The ML-KEM decapsulation operation fails
/// - The AES-GCM decryption of the payload fails
pub fn decrypt_pq_ml_kem_unverified(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
) -> Result<Zeroizing<Vec<u8>>> {
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
/// - The ML-KEM decapsulation or AES-GCM decryption fails
pub fn decrypt_pq_ml_kem_with_config_unverified(
    encrypted_data: &[u8],
    ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,
) -> Result<Zeroizing<Vec<u8>>> {
    decrypt_pq_ml_kem_with_config(
        encrypted_data,
        ml_kem_sk,
        security_level,
        config,
        SecurityMode::Unverified,
    )
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
    use crate::primitives::kem::ml_kem::MlKemSecurityLevel;
    use crate::unified_api::convenience::keygen::generate_ml_kem_keypair;
    use crate::{SecurityMode, VerifiedSession, generate_keypair};

    // Encryption tests - testing that encryption produces output
    #[test]
    fn test_encrypt_pq_ml_kem_unverified_512_succeeds() -> Result<()> {
        let data = b"Test data for ML-KEM-512";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512)?;

        let encrypted =
            encrypt_pq_ml_kem_unverified(data, pk.as_slice(), MlKemSecurityLevel::MlKem512)?;
        assert!(encrypted.len() > data.len(), "Ciphertext should be larger than plaintext");
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_768_succeeds() -> Result<()> {
        let data = b"Test data for ML-KEM-768";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted =
            encrypt_pq_ml_kem_unverified(data, pk.as_slice(), MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_1024_succeeds() -> Result<()> {
        let data = b"Test data for ML-KEM-1024";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024)?;

        let encrypted =
            encrypt_pq_ml_kem_unverified(data, pk.as_slice(), MlKemSecurityLevel::MlKem1024)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_empty_data_succeeds() -> Result<()> {
        let data = b"";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted =
            encrypt_pq_ml_kem_unverified(data, pk.as_slice(), MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > 0);
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_large_data_succeeds() -> Result<()> {
        let data = vec![0u8; 10000];
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted =
            encrypt_pq_ml_kem_unverified(&data, pk.as_slice(), MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_pq_ml_kem_roundtrip() {
        let (pk, sk) =
            generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");
        let plaintext = b"ML-KEM encrypt/decrypt roundtrip test";

        let encrypted =
            encrypt_pq_ml_kem_unverified(plaintext, pk.as_slice(), MlKemSecurityLevel::MlKem768)
                .expect("encryption should succeed");

        let decrypted = decrypt_pq_ml_kem_unverified(
            &encrypted,
            sk.expose_secret(),
            MlKemSecurityLevel::MlKem768,
        )
        .expect("decryption should succeed");

        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Decrypted data must match original plaintext"
        );
    }

    // With config tests
    #[test]
    fn test_encrypt_pq_ml_kem_with_config_unverified_succeeds() -> Result<()> {
        let data = b"Test data with config";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let config = CoreConfig::default();

        let encrypted = encrypt_pq_ml_kem_with_config_unverified(
            data,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            &config,
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_with_config_different_levels_succeeds() -> Result<()> {
        let data = b"Test security levels";
        let levels = vec![
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        for level in levels {
            let (pk, _sk) = generate_ml_kem_keypair(level)?;
            let config = CoreConfig::default();

            let encrypted =
                encrypt_pq_ml_kem_with_config_unverified(data, pk.as_slice(), level, &config)?;
            assert!(encrypted.len() > 0);
        }
        Ok(())
    }

    // Verified API tests (with SecurityMode)
    #[test]
    fn test_encrypt_pq_ml_kem_verified_succeeds() -> Result<()> {
        let data = b"Test data with verified session";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        // Create verified session
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let encrypted = encrypt_pq_ml_kem(
            data,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            SecurityMode::Verified(&session),
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_mode_succeeds() -> Result<()> {
        let data = b"Test data with unverified mode";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted = encrypt_pq_ml_kem(
            data,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            SecurityMode::Unverified,
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_with_config_verified_succeeds() -> Result<()> {
        let data = b"Test with config and session";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let config = CoreConfig::default();

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let encrypted = encrypt_pq_ml_kem_with_config(
            data,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_with_config_unverified_mode_succeeds() -> Result<()> {
        let data = b"Test with config unverified mode";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let config = CoreConfig::default();

        let encrypted = encrypt_pq_ml_kem_with_config(
            data,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            &config,
            SecurityMode::Unverified,
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    // Edge case tests
    #[test]
    fn test_ml_kem_binary_data_encryption_succeeds() -> Result<()> {
        let data = vec![0xFF, 0x00, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78];
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted =
            encrypt_pq_ml_kem_unverified(&data, pk.as_slice(), MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_pq_ml_kem_all_levels_roundtrip() {
        let data = b"Test data for all security levels";
        let levels = vec![
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        for level in levels {
            let (pk, sk) = generate_ml_kem_keypair(level).expect("keygen should succeed");

            let encrypted = encrypt_pq_ml_kem_unverified(data, pk.as_slice(), level)
                .expect("encryption should succeed");

            let decrypted = decrypt_pq_ml_kem_unverified(&encrypted, sk.expose_secret(), level)
                .expect("decryption should succeed");

            assert_eq!(
                decrypted.as_slice(),
                data.as_slice(),
                "Roundtrip for {:?} must match",
                level
            );
        }
    }

    #[test]
    fn test_ml_kem_ciphertext_size_increases_has_correct_size() -> Result<()> {
        let data = b"Small data";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted =
            encrypt_pq_ml_kem_unverified(data, pk.as_slice(), MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len(), "Ciphertext should be larger than plaintext");
        Ok(())
    }

    // Decrypt with config roundtrip tests
    #[test]
    fn test_decrypt_pq_ml_kem_with_config_unverified_roundtrip() {
        let plaintext = b"Config decrypt roundtrip";
        let config = CoreConfig::default();
        let (pk, sk) =
            generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");

        let encrypted = encrypt_pq_ml_kem_with_config_unverified(
            plaintext,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            &config,
        )
        .expect("encryption should succeed");

        let decrypted = decrypt_pq_ml_kem_with_config_unverified(
            &encrypted,
            sk.expose_secret(),
            MlKemSecurityLevel::MlKem768,
            &config,
        )
        .expect("decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_pq_ml_kem_with_config_verified_roundtrip() -> Result<()> {
        let plaintext = b"Verified config roundtrip";
        let config = CoreConfig::default();
        let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let encrypted = encrypt_pq_ml_kem_with_config(
            plaintext,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            &config,
            SecurityMode::Verified(&session),
        )?;

        let decrypted = decrypt_pq_ml_kem_with_config(
            &encrypted,
            sk.expose_secret(),
            MlKemSecurityLevel::MlKem768,
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        Ok(())
    }

    #[test]
    fn test_decrypt_pq_ml_kem_verified_roundtrip() -> Result<()> {
        let plaintext = b"Verified roundtrip";
        let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let encrypted = encrypt_pq_ml_kem(
            plaintext,
            pk.as_slice(),
            MlKemSecurityLevel::MlKem768,
            SecurityMode::Verified(&session),
        )?;

        let decrypted = decrypt_pq_ml_kem(
            &encrypted,
            sk.expose_secret(),
            MlKemSecurityLevel::MlKem768,
            SecurityMode::Verified(&session),
        )?;
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        Ok(())
    }

    // ML-KEM encrypt with invalid public key
    #[test]
    fn test_encrypt_pq_ml_kem_invalid_pk_fails() {
        let data = b"test";
        let bad_pk = vec![0u8; 10]; // Too short for any ML-KEM level
        let result =
            encrypt_pq_ml_kem_unverified(data, bad_pk.as_slice(), MlKemSecurityLevel::MlKem768);
        assert!(result.is_err(), "Invalid public key should fail");
    }

    // Decrypt with invalid key should fail
    #[test]
    fn test_decrypt_pq_ml_kem_invalid_key_fails() {
        let (pk, _sk) =
            generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");
        let plaintext = b"test";
        let encrypted =
            encrypt_pq_ml_kem_unverified(plaintext, pk.as_slice(), MlKemSecurityLevel::MlKem768)
                .expect("encryption should succeed");

        // Decrypt with wrong-sized key should fail
        let result =
            decrypt_pq_ml_kem_unverified(&encrypted, &[0u8; 32], MlKemSecurityLevel::MlKem768);
        assert!(result.is_err(), "Decryption with invalid key should fail");
    }

    #[test]
    fn test_decrypt_pq_ml_kem_truncated_data_fails() {
        let result =
            decrypt_pq_ml_kem_unverified(&[0u8; 10], &[0u8; 32], MlKemSecurityLevel::MlKem768);
        assert!(result.is_err(), "Truncated data should fail");
    }

    // Integration test
    #[test]
    fn test_ml_kem_multiple_encryptions_produce_different_ciphertexts_succeeds() -> Result<()> {
        let data = b"Same plaintext";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted1 =
            encrypt_pq_ml_kem_unverified(data, pk.as_slice(), MlKemSecurityLevel::MlKem768)?;
        let encrypted2 =
            encrypt_pq_ml_kem_unverified(data, pk.as_slice(), MlKemSecurityLevel::MlKem768)?;

        // Due to randomness in KEM, ciphertexts should differ
        assert_ne!(
            encrypted1, encrypted2,
            "Multiple encryptions should produce different ciphertexts"
        );
        Ok(())
    }
}
