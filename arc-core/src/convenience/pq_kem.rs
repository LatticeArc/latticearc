//! Post-quantum KEM operations (ML-KEM)
//!
//! This module provides post-quantum key encapsulation mechanism operations
//! using ML-KEM (FIPS 203) with **FIPS 140-3 validated** aws-lc-rs.
//!
//! # ⚠️ IMPORTANT: FIPS 140-3 LIMITATION
//!
//! **ML-KEM DECRYPTION IS NOT SUPPORTED** with the current implementation.
//!
//! ## Why Decryption Doesn't Work
//!
//! FIPS 140-3 validated aws-lc-rs **intentionally prohibits** ML-KEM secret key
//! serialization for security reasons. This means:
//!
//! - ✅ **Encryption works**: You can encrypt data using ML-KEM public keys
//! - ❌ **Decryption fails**: Secret keys from `generate_ml_kem_keypair()` are placeholders
//! - ❌ **No persistence**: Cannot save/load ML-KEM secret keys to/from bytes
//! - ✅ **FIPS compliant**: Maintains FIPS 140-3 certification
//!
//! ## Recommended Alternatives
//!
//! 1. **Ephemeral Session Keys** (Recommended for sessions):
//!    - Keep `DecapsulationKey` object in memory for session lifetime
//!    - Use ML-KEM for key agreement, derive session keys
//!    - Never serialize the secret key to bytes
//!
//! 2. **Hybrid Mode** (Recommended for persistence):
//!    - Use X25519 for long-term keys (supports serialization)
//!    - Combine with ML-KEM for post-quantum protection
//!    - See `arc-hybrid` crate
//!
//! 3. **HSM/KMS Integration**:
//!    - Use hardware security modules with native ML-KEM support
//!    - Keys never leave the secure hardware boundary
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//! - `SecurityMode::Verified(&session)`: Validates session before operation
//! - `SecurityMode::Unverified`: Skips session validation
//!
//! The `_unverified` variants are opt-out functions for scenarios where Zero Trust
//! verification is not required or not possible.

use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

use super::aes_gcm::encrypt_aes_gcm_internal;
use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

use arc_validation::resource_limits::validate_encryption_size;

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
///
/// # FIPS 140-3 Limitation
///
/// **ML-KEM decryption is not supported** with the current FIPS 140-3 validated
/// aws-lc-rs implementation. This is an intentional security design by AWS-LC that
/// prohibits secret key serialization.
///
/// ## Why This Doesn't Work
///
/// - aws-lc-rs `DecapsulationKey` cannot be serialized to bytes
/// - Secret keys from `generate_ml_kem_keypair()` are placeholder values
/// - Decapsulation requires the original `DecapsulationKey` object from key generation
///
/// ## Recommended Alternatives
///
/// 1. **Ephemeral Session Keys**: Keep `DecapsulationKey` in memory for session duration
/// 2. **Hybrid Mode**: Use X25519 for persistent keys + ML-KEM for PQ protection
/// 3. **HSM/KMS**: Use hardware security modules with native ML-KEM support
///
/// # Errors
///
/// Always returns `CoreError::NotImplemented` explaining the FIPS limitation.
fn decrypt_pq_ml_kem_internal(
    _encrypted_data: &[u8],
    _ml_kem_sk: &[u8],
    security_level: MlKemSecurityLevel,
) -> Result<Vec<u8>> {
    crate::log_crypto_operation_error!(
        "decrypt_pq_ml_kem",
        "FIPS limitation: decapsulation not supported"
    );

    Err(CoreError::NotImplemented(format!(
        "ML-KEM {:?} decryption with serialized keys. FIPS 140-3 validated aws-lc-rs \
             does not support DecapsulationKey deserialization for security reasons. \
             ML-KEM secret keys cannot be persisted to bytes. Use ephemeral keys (keep \
             DecapsulationKey in memory), hybrid mode with X25519, or HSM/KMS integration.",
        security_level
    )))
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
/// # ⚠️ FIPS 140-3 LIMITATION - NOT IMPLEMENTED
///
/// **This function always returns an error** due to FIPS 140-3 aws-lc-rs design limitations.
/// ML-KEM secret keys cannot be deserialized from bytes for security reasons.
///
/// See module documentation for alternatives (ephemeral keys, hybrid mode, HSM/KMS).
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
/// # ⚠️ FIPS 140-3 LIMITATION - NOT IMPLEMENTED
///
/// **This function always returns an error** due to FIPS 140-3 aws-lc-rs design limitations.
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
/// # ⚠️ FIPS 140-3 LIMITATION - NOT IMPLEMENTED
///
/// **This function always returns an error** due to FIPS 140-3 aws-lc-rs design limitations.
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
/// # ⚠️ FIPS 140-3 LIMITATION - NOT IMPLEMENTED
///
/// **This function always returns an error** due to FIPS 140-3 aws-lc-rs design limitations.
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
    use crate::convenience::keygen::generate_ml_kem_keypair;
    use crate::{SecurityMode, VerifiedSession, generate_keypair};
    use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

    // Encryption tests - testing that encryption produces output
    #[test]
    fn test_encrypt_pq_ml_kem_unverified_512() -> Result<()> {
        let data = b"Test data for ML-KEM-512";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512)?;

        let encrypted = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem512)?;
        assert!(encrypted.len() > data.len(), "Ciphertext should be larger than plaintext");
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_768() -> Result<()> {
        let data = b"Test data for ML-KEM-768";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_1024() -> Result<()> {
        let data = b"Test data for ML-KEM-1024";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024)?;

        let encrypted = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem1024)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_empty_data() -> Result<()> {
        let data = b"";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > 0);
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_large_data() -> Result<()> {
        let data = vec![0u8; 10000];
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted = encrypt_pq_ml_kem_unverified(&data, &pk, MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_decrypt_pq_ml_kem_always_fails_fips_limitation() {
        let (_, sk) =
            generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");
        let data = vec![0u8; 2000]; // Valid-looking ciphertext size

        let result = decrypt_pq_ml_kem_unverified(&data, sk.as_ref(), MlKemSecurityLevel::MlKem768);

        // Should always return NotImplemented error due to FIPS limitation
        assert!(result.is_err(), "ML-KEM decryption should always fail with FIPS aws-lc-rs");
        match result.unwrap_err() {
            CoreError::NotImplemented(msg) => {
                assert!(msg.contains("aws-lc-rs"), "Error should mention aws-lc-rs limitation");
            }
            other => panic!("Expected NotImplemented error, got: {:?}", other),
        }
    }

    // With config tests
    #[test]
    fn test_encrypt_pq_ml_kem_with_config_unverified() -> Result<()> {
        let data = b"Test data with config";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let config = CoreConfig::default();

        let encrypted = encrypt_pq_ml_kem_with_config_unverified(
            data,
            &pk,
            MlKemSecurityLevel::MlKem768,
            &config,
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_with_config_different_levels() -> Result<()> {
        let data = b"Test security levels";
        let levels = vec![
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ];

        for level in levels {
            let (pk, _sk) = generate_ml_kem_keypair(level)?;
            let config = CoreConfig::default();

            let encrypted = encrypt_pq_ml_kem_with_config_unverified(data, &pk, level, &config)?;
            assert!(encrypted.len() > 0);
        }
        Ok(())
    }

    // Verified API tests (with SecurityMode)
    #[test]
    fn test_encrypt_pq_ml_kem_verified() -> Result<()> {
        let data = b"Test data with verified session";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        // Create verified session
        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let encrypted = encrypt_pq_ml_kem(
            data,
            &pk,
            MlKemSecurityLevel::MlKem768,
            SecurityMode::Verified(&session),
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_unverified_mode() -> Result<()> {
        let data = b"Test data with unverified mode";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted =
            encrypt_pq_ml_kem(data, &pk, MlKemSecurityLevel::MlKem768, SecurityMode::Unverified)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_with_config_verified() -> Result<()> {
        let data = b"Test with config and session";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let config = CoreConfig::default();

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let encrypted = encrypt_pq_ml_kem_with_config(
            data,
            &pk,
            MlKemSecurityLevel::MlKem768,
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_encrypt_pq_ml_kem_with_config_unverified_mode() -> Result<()> {
        let data = b"Test with config unverified mode";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let config = CoreConfig::default();

        let encrypted = encrypt_pq_ml_kem_with_config(
            data,
            &pk,
            MlKemSecurityLevel::MlKem768,
            &config,
            SecurityMode::Unverified,
        )?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    // Edge case tests
    #[test]
    fn test_ml_kem_binary_data_encryption() -> Result<()> {
        let data = vec![0xFF, 0x00, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78];
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted = encrypt_pq_ml_kem_unverified(&data, &pk, MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len());
        Ok(())
    }

    #[test]
    fn test_decrypt_always_returns_not_implemented() {
        let data = b"Test data";
        let (pk, sk) =
            generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keygen should succeed");

        let encrypted = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem768)
            .expect("encryption should succeed");

        // Even with valid key and ciphertext, decryption should fail due to FIPS limitation
        let result =
            decrypt_pq_ml_kem_unverified(&encrypted, sk.as_ref(), MlKemSecurityLevel::MlKem768);

        assert!(result.is_err(), "ML-KEM decryption should always fail with FIPS aws-lc-rs");
        match result.unwrap_err() {
            CoreError::NotImplemented(msg) => {
                assert!(
                    msg.contains("FIPS 140-3") || msg.contains("aws-lc-rs"),
                    "Error should mention FIPS/aws-lc-rs limitation"
                );
            }
            other => panic!("Expected NotImplemented error, got: {:?}", other),
        }
    }

    #[test]
    fn test_ml_kem_ciphertext_size_increases() -> Result<()> {
        let data = b"Small data";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem768)?;
        assert!(encrypted.len() > data.len(), "Ciphertext should be larger than plaintext");
        Ok(())
    }

    // Integration test
    #[test]
    fn test_ml_kem_multiple_encryptions_produce_different_ciphertexts() -> Result<()> {
        let data = b"Same plaintext";
        let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        let encrypted1 = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem768)?;
        let encrypted2 = encrypt_pq_ml_kem_unverified(data, &pk, MlKemSecurityLevel::MlKem768)?;

        // Due to randomness in KEM, ciphertexts should differ
        assert_ne!(
            encrypted1, encrypted2,
            "Multiple encryptions should produce different ciphertexts"
        );
        Ok(())
    }
}
