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
