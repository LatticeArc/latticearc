//! Key generation for all cryptographic schemes

use crate::logging::{KeyPurpose, KeyType};
use tracing::debug;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use arc_primitives::{
    kem::ml_kem::{MlKem, MlKemSecurityLevel},
    sig::{
        fndsa::FNDsaSecurityLevel,
        ml_dsa::{MlDsaParameterSet, generate_keypair as ml_dsa_generate_keypair},
        slh_dsa::{SecurityLevel as SlhDsaSecurityLevel, SigningKey as SlhDsaSigningKey},
    },
};

use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::types::{PrivateKey, PublicKey};

/// Generate an Ed25519 keypair
///
/// # Errors
///
/// Returns an error if:
/// - The generated keypair fails FIPS 186-5 validation
/// - The public key is the identity element (all zeros)
/// - The keypair consistency test signature verification fails
pub fn generate_keypair() -> Result<(PublicKey, PrivateKey)> {
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
    verifying_key.verify(test_message, &signature).map_err(|_e| {
        CoreError::KeyGenerationFailed {
            reason: "Keypair validation failed".to_string(),
            recovery: "Regenerate keypair and retry validation".to_string(),
        }
    })?;

    Ok(())
}

/// Generate an ML-KEM keypair
///
/// # ⚠️ CRITICAL LIMITATION: Secret Key Cannot Be Used for Decryption
///
/// Due to FIPS 140-3 aws-lc-rs design, the returned `PrivateKey` is a **placeholder**
/// and **cannot be used for ML-KEM decryption**. The secret key bytes are not actual
/// cryptographic material.
///
/// ## Why This Limitation Exists
///
/// - FIPS 140-3 validated aws-lc-rs prohibits secret key serialization for security
/// - ML-KEM decapsulation requires the original `DecapsulationKey` object from aws-lc-rs
/// - Secret keys cannot be persisted to or restored from bytes
///
/// ## Recommended Usage
///
/// 1. **Ephemeral Keys**: Keep `DecapsulationKey` in memory for session duration
/// 2. **Hybrid Mode**: Use X25519 for persistent keys + ML-KEM for PQ protection
/// 3. **Encryption Only**: Use returned public key for encryption (works correctly)
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM key generation operation fails
/// - The RNG fails to provide sufficient randomness
pub fn generate_ml_kem_keypair(
    security_level: MlKemSecurityLevel,
) -> Result<(PublicKey, PrivateKey)> {
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

    Ok((pk.into_bytes(), PrivateKey::new(sk.into_bytes())))
}

/// Generate an ML-KEM keypair with configuration
///
/// # ⚠️ CRITICAL LIMITATION: Secret Key Cannot Be Used for Decryption
///
/// See [`generate_ml_kem_keypair`] for details on FIPS 140-3 limitations.
/// The returned secret key is a placeholder and cannot be used for decryption.
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

/// Generate an FN-DSA keypair
///
/// # Errors
///
/// Returns an error if:
/// - The FN-DSA key generation operation fails
/// - The RNG is unavailable or fails to provide sufficient randomness
pub fn generate_fn_dsa_keypair() -> Result<(PublicKey, PrivateKey)> {
    debug!("Generating FN-DSA keypair (Level512)");

    let mut rng = rand::rngs::OsRng;
    let keypair =
        arc_primitives::sig::fndsa::KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .map_err(|e| CoreError::KeyGenerationFailed {
                reason: format!("FN-DSA key generation failed: {}", e),
                recovery: "Check RNG availability".to_string(),
            })?;

    crate::log_key_generated!(
        "fn-dsa-keypair",
        "FN-DSA-512",
        KeyType::KeyPair,
        KeyPurpose::Signing
    );

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
mod tests {
    use super::*;
    use crate::convenience::ed25519::{sign_ed25519_unverified, verify_ed25519_unverified};
    use crate::convenience::pq_kem::encrypt_pq_ml_kem_unverified;
    use crate::convenience::pq_sig::{sign_pq_ml_dsa_unverified, verify_pq_ml_dsa_unverified};
    use crate::convenience::pq_sig::{sign_pq_slh_dsa_unverified, verify_pq_slh_dsa_unverified};
    use arc_primitives::kem::ml_kem::MlKemSecurityLevel;
    use arc_primitives::sig::ml_dsa::MlDsaParameterSet;
    use arc_primitives::sig::slh_dsa::SecurityLevel as SlhDsaSecurityLevel;

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
    // Note: Full encryption/decryption roundtrip not tested due to aws-lc-rs limitation
    // (cannot deserialize ML-KEM secret keys from bytes)
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
        let (pk1, _sk1) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
        let (pk2, _sk2) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;

        // Public keys must be unique
        assert_ne!(pk1, pk2, "ML-KEM public keys must be unique");

        // Note: Cannot test secret key uniqueness due to FIPS 140-3 limitation.
        // aws-lc-rs doesn't allow ML-KEM secret key serialization, so the returned
        // secret keys are placeholder bytes (all zeros) and will always be identical.
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

    // FN-DSA tests (ignored due to stack overflow)
    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_fn_dsa_keypair_functionality() -> Result<()> {
        use crate::convenience::pq_sig::{sign_pq_fn_dsa_unverified, verify_pq_fn_dsa_unverified};

        let (pk, sk) = generate_fn_dsa_keypair()?;
        let message = b"Test FN-DSA";

        let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_fn_dsa_with_config() -> Result<()> {
        use crate::convenience::pq_sig::{sign_pq_fn_dsa_unverified, verify_pq_fn_dsa_unverified};

        let config = CoreConfig::default();
        let (pk, sk) = generate_fn_dsa_keypair_with_config(&config)?;
        let message = b"Config test";

        let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }
}
