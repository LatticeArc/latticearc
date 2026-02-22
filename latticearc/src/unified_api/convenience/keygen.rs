//! Key generation for all cryptographic schemes

use crate::unified_api::logging::{KeyPurpose, KeyType};
use tracing::debug;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::primitives::{
    kem::ml_kem::{MlKem, MlKemSecurityLevel},
    sig::{
        fndsa::FNDsaSecurityLevel,
        ml_dsa::{MlDsaParameterSet, generate_keypair as ml_dsa_generate_keypair},
        slh_dsa::{SecurityLevel as SlhDsaSecurityLevel, SigningKey as SlhDsaSigningKey},
    },
};

use crate::types::{PrivateKey, PublicKey};
use crate::unified_api::config::CoreConfig;
use crate::unified_api::error::{CoreError, Result};

/// Generate an Ed25519 keypair
///
/// # Errors
///
/// Returns an error if:
/// - The generated keypair fails FIPS 186-5 validation
/// - The public key is the identity element (all zeros)
/// - The keypair consistency test signature verification fails
pub fn generate_keypair() -> Result<(PublicKey, PrivateKey)> {
    super::api::fips_verify_operational()?;
    debug!("Generating Ed25519 keypair");

    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Validate keys per FIPS 186-5 requirements
    validate_ed25519_keypair(&signing_key, &verifying_key)?;

    let public_key = verifying_key.to_bytes().to_vec();
    let private_key = PrivateKey::new(signing_key.to_bytes().to_vec());

    crate::log_key_generated!("ed25519-keypair", "Ed25519", KeyType::KeyPair, KeyPurpose::Signing);

    Ok((public_key, private_key))
}

/// Generate an Ed25519 keypair with configuration
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The generated keypair fails FIPS 186-5 validation
pub fn generate_keypair_with_config(config: &CoreConfig) -> Result<(PublicKey, PrivateKey)> {
    config.validate()?;
    generate_keypair()
}

/// Validate Ed25519 keypair per FIPS 186-5 requirements
fn validate_ed25519_keypair(signing_key: &SigningKey, verifying_key: &VerifyingKey) -> Result<()> {
    // Validate public key format (32 bytes)
    let public_bytes = verifying_key.to_bytes();
    if public_bytes.len() != 32 {
        return Err(CoreError::KeyGenerationFailed {
            reason: "Invalid public key length".to_string(),
            recovery: "Ensure public key is exactly 32 bytes".to_string(),
        });
    }

    // Validate that public key is not the identity element (all zeros)
    if public_bytes.iter().all(|&b| b == 0) {
        return Err(CoreError::KeyGenerationFailed {
            reason: "Public key is identity element".to_string(),
            recovery: "Generate a new keypair, identity element is invalid".to_string(),
        });
    }

    // Validate private key format (32 bytes)
    let private_bytes = signing_key.to_bytes();
    if private_bytes.len() != 32 {
        return Err(CoreError::KeyGenerationFailed {
            reason: "Invalid private key length".to_string(),
            recovery: "Ensure private key is exactly 32 bytes".to_string(),
        });
    }

    // Validate private key is not zero
    if private_bytes.iter().all(|&b| b == 0) {
        return Err(CoreError::KeyGenerationFailed {
            reason: "Private key is zero".to_string(),
            recovery: "Generate a new keypair, zero private key is invalid".to_string(),
        });
    }

    // Perform a test signature to ensure keypair consistency
    let test_message = b"key_validation_test";
    let signature = signing_key.sign(test_message);
    verifying_key.verify(test_message, &signature).map_err(|e| CoreError::KeyGenerationFailed {
        reason: format!("Keypair validation failed: {e}"),
        recovery: "Regenerate keypair and retry validation".to_string(),
    })?;

    Ok(())
}

/// Generate an ML-KEM keypair
///
/// Returns `(public_key_bytes, private_key_bytes)` suitable for encryption and decryption.
/// The secret key contains real key material serialized from aws-lc-rs `DecapsulationKey`.
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM key generation operation fails
/// - The RNG fails to provide sufficient randomness
pub fn generate_ml_kem_keypair(
    security_level: MlKemSecurityLevel,
) -> Result<(PublicKey, PrivateKey)> {
    super::api::fips_verify_operational()?;
    debug!(security_level = ?security_level, "Generating ML-KEM keypair");

    let mut rng = rand::rngs::OsRng;
    let (pk, sk) = MlKem::generate_keypair(&mut rng, security_level).map_err(|e| {
        CoreError::KeyGenerationFailed {
            reason: format!("ML-KEM key generation failed: {}", e),
            recovery: "Check security level and RNG".to_string(),
        }
    })?;

    let algorithm = format!("{:?}", security_level);
    crate::log_key_generated!(
        "ml-kem-keypair",
        algorithm,
        KeyType::KeyPair,
        KeyPurpose::KeyExchange
    );

    // into_bytes() returns Zeroizing<Vec<u8>> for auto-zeroization.
    // Extract the inner vec for PrivateKey construction; the empty vec left
    // in the Zeroizing wrapper is harmlessly zeroized on drop.
    let mut sk_bytes = sk.into_bytes();
    let sk_data = std::mem::take(&mut *sk_bytes);
    Ok((pk.into_bytes(), PrivateKey::new(sk_data)))
}

/// Generate an ML-KEM keypair with configuration
///
/// See [`generate_ml_kem_keypair`] for details.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The ML-KEM key generation operation fails
pub fn generate_ml_kem_keypair_with_config(
    security_level: MlKemSecurityLevel,
    config: &CoreConfig,
) -> Result<(PublicKey, PrivateKey)> {
    config.validate()?;
    generate_ml_kem_keypair(security_level)
}

/// Generate an ML-DSA keypair
///
/// # Errors
///
/// Returns an error if the ML-DSA key generation operation fails for the given parameter set.
pub fn generate_ml_dsa_keypair(
    parameter_set: MlDsaParameterSet,
) -> Result<(PublicKey, PrivateKey)> {
    debug!(parameter_set = ?parameter_set, "Generating ML-DSA keypair");

    let (pk, sk) =
        ml_dsa_generate_keypair(parameter_set).map_err(|e| CoreError::KeyGenerationFailed {
            reason: format!("ML-DSA key generation failed: {}", e),
            recovery: "Check parameter set".to_string(),
        })?;

    let algorithm = format!("{:?}", parameter_set);
    crate::log_key_generated!("ml-dsa-keypair", algorithm, KeyType::KeyPair, KeyPurpose::Signing);

    Ok((pk.as_bytes().to_vec(), PrivateKey::new(sk.as_bytes().to_vec())))
}

/// Generate an ML-DSA keypair with configuration
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The ML-DSA key generation operation fails
pub fn generate_ml_dsa_keypair_with_config(
    parameter_set: MlDsaParameterSet,
    config: &CoreConfig,
) -> Result<(PublicKey, PrivateKey)> {
    config.validate()?;
    generate_ml_dsa_keypair(parameter_set)
}

/// Generate an SLH-DSA keypair
///
/// # Errors
///
/// Returns an error if the SLH-DSA key generation operation fails for the given security level.
pub fn generate_slh_dsa_keypair(
    security_level: SlhDsaSecurityLevel,
) -> Result<(PublicKey, PrivateKey)> {
    debug!(security_level = ?security_level, "Generating SLH-DSA keypair");

    let (sk, pk) =
        SlhDsaSigningKey::generate(security_level).map_err(|e| CoreError::KeyGenerationFailed {
            reason: format!("SLH-DSA key generation failed: {}", e),
            recovery: "Check security level".to_string(),
        })?;

    let algorithm = format!("{:?}", security_level);
    crate::log_key_generated!("slh-dsa-keypair", algorithm, KeyType::KeyPair, KeyPurpose::Signing);

    Ok((pk.as_bytes().to_vec(), PrivateKey::new(sk.as_bytes().to_vec())))
}

/// Generate an SLH-DSA keypair with configuration
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The SLH-DSA key generation operation fails
pub fn generate_slh_dsa_keypair_with_config(
    security_level: SlhDsaSecurityLevel,
    config: &CoreConfig,
) -> Result<(PublicKey, PrivateKey)> {
    config.validate()?;
    generate_slh_dsa_keypair(security_level)
}

/// Generate an FN-DSA keypair (Level512).
///
/// For Level1024, use [`generate_fn_dsa_keypair_with_level`].
///
/// # Errors
///
/// Returns an error if:
/// - The FN-DSA key generation operation fails
/// - The RNG is unavailable or fails to provide sufficient randomness
pub fn generate_fn_dsa_keypair() -> Result<(PublicKey, PrivateKey)> {
    generate_fn_dsa_keypair_with_level(FNDsaSecurityLevel::Level512)
}

/// Generate an FN-DSA keypair at the specified security level.
///
/// # Arguments
/// * `level` - Security level: `Level512` (NIST Level I) or `Level1024` (NIST Level V)
///
/// # Errors
///
/// Returns an error if:
/// - The FN-DSA key generation operation fails
/// - The RNG is unavailable or fails to provide sufficient randomness
///
/// # Stack Usage
/// FN-DSA Level1024 requires ~32MB stack in debug builds. Use `--release`
/// or spawn a thread with `stack_size(32 * 1024 * 1024)` if needed.
pub fn generate_fn_dsa_keypair_with_level(
    level: FNDsaSecurityLevel,
) -> Result<(PublicKey, PrivateKey)> {
    debug!("Generating FN-DSA keypair ({:?})", level);

    let mut rng = rand::rngs::OsRng;
    let keypair =
        crate::primitives::sig::fndsa::KeyPair::generate(&mut rng, level).map_err(|e| {
            CoreError::KeyGenerationFailed {
                reason: format!("FN-DSA key generation failed: {}", e),
                recovery: "Check RNG availability".to_string(),
            }
        })?;

    let level_name = match level {
        FNDsaSecurityLevel::Level512 => "FN-DSA-512",
        FNDsaSecurityLevel::Level1024 => "FN-DSA-1024",
    };
    crate::log_key_generated!("fn-dsa-keypair", level_name, KeyType::KeyPair, KeyPurpose::Signing);

    Ok((keypair.verifying_key().to_bytes(), PrivateKey::new(keypair.signing_key().to_bytes())))
}

/// Generate an FN-DSA keypair with configuration
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The FN-DSA key generation operation fails
pub fn generate_fn_dsa_keypair_with_config(config: &CoreConfig) -> Result<(PublicKey, PrivateKey)> {
    config.validate()?;
    generate_fn_dsa_keypair()
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
    use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
    use crate::primitives::sig::slh_dsa::SecurityLevel as SlhDsaSecurityLevel;
    use crate::unified_api::convenience::ed25519::{
        sign_ed25519_unverified, verify_ed25519_unverified,
    };
    use crate::unified_api::convenience::pq_kem::encrypt_pq_ml_kem_unverified;
    use crate::unified_api::convenience::pq_sig::{
        sign_pq_ml_dsa_unverified, verify_pq_ml_dsa_unverified,
    };
    use crate::unified_api::convenience::pq_sig::{
        sign_pq_slh_dsa_unverified, verify_pq_slh_dsa_unverified,
    };

    // Ed25519 comprehensive tests
    #[test]
    fn test_ed25519_keypair_format() -> Result<()> {
        let (pk, sk) = generate_keypair()?;
        assert_eq!(pk.len(), 32, "Ed25519 public key must be exactly 32 bytes");
        assert_eq!(sk.as_ref().len(), 32, "Ed25519 secret key must be exactly 32 bytes");
        Ok(())
    }

    #[test]
    fn test_ed25519_keypair_functionality() -> Result<()> {
        let (pk, sk) = generate_keypair()?;
        let message = b"Test message to verify key functionality";

        // Keys should actually work for signing and verification
        let signature = sign_ed25519_unverified(message, sk.as_ref())?;
        let is_valid = verify_ed25519_unverified(message, &signature, &pk)?;
        assert!(is_valid, "Generated keypair should produce valid signatures");
        Ok(())
    }

    #[test]
    fn test_ed25519_keypair_uniqueness() -> Result<()> {
        let (pk1, sk1) = generate_keypair()?;
        let (pk2, sk2) = generate_keypair()?;
        let (pk3, sk3) = generate_keypair()?;

        // All keys should be different
        assert_ne!(pk1, pk2, "Public keys must be unique");
        assert_ne!(pk1, pk3, "Public keys must be unique");
        assert_ne!(pk2, pk3, "Public keys must be unique");
        assert_ne!(sk1.as_ref(), sk2.as_ref(), "Secret keys must be unique");
        assert_ne!(sk1.as_ref(), sk3.as_ref(), "Secret keys must be unique");
        assert_ne!(sk2.as_ref(), sk3.as_ref(), "Secret keys must be unique");
        Ok(())
    }

    #[test]
    fn test_ed25519_keypair_with_config() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) = generate_keypair_with_config(&config)?;

        // Validate format
        assert_eq!(pk.len(), 32);
        assert_eq!(sk.as_ref().len(), 32);

        // Validate functionality
        let message = b"Config test";
        let signature = sign_ed25519_unverified(message, sk.as_ref())?;
        let is_valid = verify_ed25519_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ed25519_cross_keypair_verification_fails() -> Result<()> {
        let (_pk1, sk1) = generate_keypair()?;
        let (pk2, _sk2) = generate_keypair()?;
        let message = b"Cross validation test";

        let signature = sign_ed25519_unverified(message, sk1.as_ref())?;
        let result = verify_ed25519_unverified(message, &signature, &pk2);
        assert!(
            result.is_err(),
            "Signature from one key should not verify with different public key"
        );
        Ok(())
    }

    // ML-KEM comprehensive tests
    // Note: Full encryption/decryption roundtrip tested in integration tests
    #[test]
    fn test_ml_kem_512_keypair_generation() -> Result<()> {
        let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512)?;

        // Validate keys are generated with expected properties
        assert!(!pk.is_empty(), "Public key should not be empty");
        assert!(!sk.as_ref().is_empty(), "Secret key should not be empty");

        // Public key can be used for encryption
        let plaintext = b"Test data for ML-KEM-512";
        let ciphertext =
            encrypt_pq_ml_kem_unverified(plaintext, &pk, MlKemSecurityLevel::MlKem512)?;
        assert!(ciphertext.len() > plaintext.len(), "Ciphertext should be larger than plaintext");
        Ok(())
    }

    #[test]
    fn test_ml_kem_768_keypair_generation() -> Result<()> {
        let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());

        let plaintext = b"Test data";
        let ciphertext =
            encrypt_pq_ml_kem_unverified(plaintext, &pk, MlKemSecurityLevel::MlKem768)?;
        assert!(ciphertext.len() > plaintext.len());
        Ok(())
    }

    #[test]
    fn test_ml_kem_1024_keypair_generation() -> Result<()> {
        let (pk, sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024)?;
        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());

        let plaintext = b"Test data";
        let ciphertext =
            encrypt_pq_ml_kem_unverified(plaintext, &pk, MlKemSecurityLevel::MlKem1024)?;
        assert!(ciphertext.len() > plaintext.len());
        Ok(())
    }

    #[test]
    fn test_ml_kem_keypair_uniqueness() -> Result<()> {
        let (pk1, sk1) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let (pk2, sk2) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        // Public keys must be unique
        assert_ne!(pk1, pk2, "ML-KEM public keys must be unique");

        // Secret keys must also be unique
        assert_ne!(sk1.as_ref(), sk2.as_ref(), "ML-KEM secret keys must be unique");
        Ok(())
    }

    #[test]
    fn test_ml_kem_with_config() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) = generate_ml_kem_keypair_with_config(MlKemSecurityLevel::MlKem768, &config)?;

        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());

        // Validate public key works for encryption
        let plaintext = b"Config test";
        let ciphertext =
            encrypt_pq_ml_kem_unverified(plaintext, &pk, MlKemSecurityLevel::MlKem768)?;
        assert!(ciphertext.len() > plaintext.len());
        Ok(())
    }

    // ML-DSA comprehensive tests
    #[test]
    fn test_ml_dsa_44_keypair_functionality() -> Result<()> {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;
        let message = b"Test ML-DSA-44 signature";

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA44)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA44)?;
        assert!(is_valid, "Generated ML-DSA-44 keys should produce valid signatures");
        Ok(())
    }

    #[test]
    fn test_ml_dsa_65_keypair_functionality() -> Result<()> {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
        let message = b"Test ML-DSA-65 signature";

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_87_keypair_functionality() -> Result<()> {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;
        let message = b"Test ML-DSA-87 signature";

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA87)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA87)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_keypair_uniqueness() -> Result<()> {
        let (pk1, sk1) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
        let (pk2, sk2) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

        assert_ne!(pk1, pk2, "ML-DSA public keys must be unique");
        assert_ne!(sk1.as_ref(), sk2.as_ref(), "ML-DSA secret keys must be unique");
        Ok(())
    }

    #[test]
    fn test_ml_dsa_with_config() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) = generate_ml_dsa_keypair_with_config(MlDsaParameterSet::MLDSA65, &config)?;
        let message = b"Config test";

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_cross_keypair_verification_fails() -> Result<()> {
        let (_pk1, sk1) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
        let (pk2, _sk2) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
        let message = b"Cross validation";

        let signature =
            sign_pq_ml_dsa_unverified(message, sk1.as_ref(), MlDsaParameterSet::MLDSA65)?;
        let result =
            verify_pq_ml_dsa_unverified(message, &signature, &pk2, MlDsaParameterSet::MLDSA65);
        assert!(result.is_err(), "ML-DSA signature should not verify with different key");
        Ok(())
    }

    // SLH-DSA comprehensive tests
    #[test]
    fn test_slh_dsa_128s_keypair_functionality() -> Result<()> {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let message = b"Test SLH-DSA-128s";

        let signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake128s)?;
        let is_valid =
            verify_pq_slh_dsa_unverified(message, &signature, &pk, SlhDsaSecurityLevel::Shake128s)?;
        assert!(is_valid, "Generated SLH-DSA keys should produce valid signatures");
        Ok(())
    }

    #[test]
    fn test_slh_dsa_keypair_uniqueness() -> Result<()> {
        let (pk1, sk1) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let (pk2, sk2) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

        assert_ne!(pk1, pk2, "SLH-DSA public keys must be unique");
        assert_ne!(sk1.as_ref(), sk2.as_ref(), "SLH-DSA secret keys must be unique");
        Ok(())
    }

    #[test]
    fn test_slh_dsa_with_config() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) =
            generate_slh_dsa_keypair_with_config(SlhDsaSecurityLevel::Shake128s, &config)?;
        let message = b"Config test";

        let signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake128s)?;
        let is_valid =
            verify_pq_slh_dsa_unverified(message, &signature, &pk, SlhDsaSecurityLevel::Shake128s)?;
        assert!(is_valid);
        Ok(())
    }

    // FN-DSA tests — must run in release mode (stack overflow in debug)
    #[test]
    fn test_fn_dsa_keypair_functionality() -> Result<()> {
        use crate::unified_api::convenience::pq_sig::{
            sign_pq_fn_dsa_unverified, verify_pq_fn_dsa_unverified,
        };

        let (pk, sk) = generate_fn_dsa_keypair()?;
        let message = b"Test FN-DSA";

        let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_fn_dsa_with_config() -> Result<()> {
        use crate::unified_api::convenience::pq_sig::{
            sign_pq_fn_dsa_unverified, verify_pq_fn_dsa_unverified,
        };

        let config = CoreConfig::default();
        let (pk, sk) = generate_fn_dsa_keypair_with_config(&config)?;
        let message = b"Config test";

        let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    // === Ed25519 validation tests ===

    #[test]
    fn test_validate_ed25519_keypair_success() -> Result<()> {
        // A normal keypair should pass validation
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        assert!(validate_ed25519_keypair(&signing_key, &verifying_key).is_ok());
        Ok(())
    }

    // Note: Ed25519 SigningKey/VerifyingKey are always 32 bytes, so
    // the length checks (lines 63, 80) can't be triggered directly.
    // The identity check (all zeros) and keypair consistency check are the
    // meaningful error branches.

    #[test]
    fn test_generate_keypair_produces_valid_ed25519() -> Result<()> {
        // Verify our keygen goes through the full validation path
        let (pk, sk) = generate_keypair()?;
        assert_eq!(pk.len(), 32, "Ed25519 public key should be 32 bytes");
        assert_eq!(sk.as_ref().len(), 32, "Ed25519 secret key should be 32 bytes");

        // Verify keys are not zero (validation check)
        assert!(!pk.iter().all(|&b| b == 0), "Public key should not be all zeros");
        assert!(!sk.as_ref().iter().all(|&b| b == 0), "Secret key should not be all zeros");
        Ok(())
    }

    #[test]
    fn test_generate_keypair_with_config_validates() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) = generate_keypair_with_config(&config)?;
        assert_eq!(pk.len(), 32);
        assert_eq!(sk.as_ref().len(), 32);
        Ok(())
    }

    // === ML-KEM keygen with all security levels ===

    #[test]
    fn test_ml_kem_keypair_768_with_config() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) = generate_ml_kem_keypair_with_config(MlKemSecurityLevel::MlKem768, &config)?;
        assert!(!pk.is_empty(), "ML-KEM-768 public key should not be empty");
        assert!(!sk.as_ref().is_empty(), "ML-KEM-768 secret key should not be empty");
        Ok(())
    }

    // === ML-DSA keygen with all parameter sets ===

    #[test]
    fn test_ml_dsa_keypair_44() -> Result<()> {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;
        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());
        Ok(())
    }

    #[test]
    fn test_ml_dsa_keypair_87() -> Result<()> {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;
        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());
        Ok(())
    }

    #[test]
    fn test_ml_dsa_keypair_with_config_44() -> Result<()> {
        let config = CoreConfig::default();
        let (pk, sk) = generate_ml_dsa_keypair_with_config(MlDsaParameterSet::MLDSA44, &config)?;
        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());
        Ok(())
    }

    // === SLH-DSA keygen with higher security levels ===

    #[test]
    fn test_slh_dsa_keypair_192s() -> Result<()> {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;
        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());
        Ok(())
    }

    #[test]
    fn test_slh_dsa_keypair_256s() -> Result<()> {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;
        assert!(!pk.is_empty());
        assert!(!sk.as_ref().is_empty());
        Ok(())
    }
}
