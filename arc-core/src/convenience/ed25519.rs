//! Ed25519 signature operations
//!
//! This module provides Ed25519 digital signature operations.
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! ```rust,ignore
//! use arc_core::{sign_ed25519, verify_ed25519, SecurityMode, VerifiedSession};
//!
//! // With Zero Trust verification (recommended)
//! let signature = sign_ed25519(data, &private_key, SecurityMode::Verified(&session))?;
//!
//! // Without verification (opt-out)
//! let signature = sign_ed25519(data, &private_key, SecurityMode::Unverified)?;
//! ```

use crate::{
    log_crypto_operation_complete, log_crypto_operation_error, log_crypto_operation_start,
};
use tracing::debug;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of Ed25519 signing.
pub(crate) fn sign_ed25519_internal(data: &[u8], ed25519_sk: &[u8]) -> Result<Vec<u8>> {
    log_crypto_operation_start!("ed25519_sign", algorithm = "Ed25519", data_len = data.len());

    if ed25519_sk.len() < 32 {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: ed25519_sk.len() };
        log_crypto_operation_error!("ed25519_sign", err);
        return Err(err);
    }

    let signing_key_bytes: [u8; 32] = ed25519_sk
        .get(..32)
        .ok_or_else(|| {
            let err = CoreError::InvalidInput("Private key must be at least 32 bytes".to_string());
            log_crypto_operation_error!("ed25519_sign", err);
            err
        })?
        .try_into()
        .map_err(|_e| {
            let err = CoreError::InvalidInput("Private key must be 32 bytes".to_string());
            log_crypto_operation_error!("ed25519_sign", err);
            err
        })?;

    let signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let signature: Signature = signing_key.sign(data);
    let sig_bytes = signature.to_bytes().to_vec();

    log_crypto_operation_complete!(
        "ed25519_sign",
        algorithm = "Ed25519",
        signature_len = sig_bytes.len()
    );
    debug!(algorithm = "Ed25519", "Created Ed25519 signature");

    Ok(sig_bytes)
}

/// Internal implementation of Ed25519 verification.
pub(crate) fn verify_ed25519_internal(
    data: &[u8],
    signature_bytes: &[u8],
    ed25519_pk: &[u8],
) -> Result<bool> {
    log_crypto_operation_start!("ed25519_verify", algorithm = "Ed25519", data_len = data.len());

    if signature_bytes.len() < 64 {
        let err = CoreError::InvalidInput(format!(
            "Signature must be at least 64 bytes, got {}",
            signature_bytes.len()
        ));
        log_crypto_operation_error!("ed25519_verify", err);
        return Err(err);
    }
    if ed25519_pk.len() < 32 {
        let err = CoreError::InvalidKeyLength { expected: 32, actual: ed25519_pk.len() };
        log_crypto_operation_error!("ed25519_verify", err);
        return Err(err);
    }

    let signature_bytes_fixed: [u8; 64] = signature_bytes
        .get(..64)
        .ok_or_else(|| {
            let err = CoreError::InvalidInput("Signature must be at least 64 bytes".to_string());
            log_crypto_operation_error!("ed25519_verify", err);
            err
        })?
        .try_into()
        .map_err(|_e| {
            let err = CoreError::InvalidInput("Signature must be 64 bytes".to_string());
            log_crypto_operation_error!("ed25519_verify", err);
            err
        })?;

    let signature = Signature::from_bytes(&signature_bytes_fixed);

    let public_key_bytes: [u8; 32] = ed25519_pk
        .get(..32)
        .ok_or_else(|| {
            let err = CoreError::InvalidInput("Public key must be at least 32 bytes".to_string());
            log_crypto_operation_error!("ed25519_verify", err);
            err
        })?
        .try_into()
        .map_err(|_e| {
            let err = CoreError::InvalidInput("Public key must be 32 bytes".to_string());
            log_crypto_operation_error!("ed25519_verify", err);
            err
        })?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).map_err(|_e| {
        let err = CoreError::InvalidInput("Invalid public key".to_string());
        log_crypto_operation_error!("ed25519_verify", err);
        err
    })?;

    let result = match verifying_key.verify(data, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Err(CoreError::VerificationFailed),
    };

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!("ed25519_verify", algorithm = "Ed25519", valid = valid);
            debug!(algorithm = "Ed25519", valid = valid, "Ed25519 verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!("ed25519_verify", e);
        }
    }

    result
}

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

/// Sign data using Ed25519.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before signing
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{sign_ed25519, SecurityMode, VerifiedSession, generate_keypair};
///
/// let (pk, sk) = generate_keypair()?;
/// let session = VerifiedSession::establish(&pk, &sk)?;
///
/// // With Zero Trust verification (recommended)
/// let signature = sign_ed25519(b"message", &private_key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let signature = sign_ed25519(b"message", &private_key, SecurityMode::Unverified)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `SecurityMode::Verified`
/// - The private key is less than 32 bytes
#[inline]
pub fn sign_ed25519(data: &[u8], ed25519_sk: &[u8], mode: SecurityMode) -> Result<Vec<u8>> {
    mode.validate()?;
    sign_ed25519_internal(data, ed25519_sk)
}

/// Verify an Ed25519 signature.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before verification
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `SecurityMode::Verified`
/// - The signature is less than 64 bytes
/// - The public key is less than 32 bytes
/// - The public key is invalid (not a valid curve point)
#[inline]
pub fn verify_ed25519(
    data: &[u8],
    signature_bytes: &[u8],
    ed25519_pk: &[u8],
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    verify_ed25519_internal(data, signature_bytes, ed25519_pk)
}

/// Sign data using Ed25519 with configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `SecurityMode::Verified`
/// - The configuration validation fails
/// - The private key is less than 32 bytes
#[inline]
pub fn sign_ed25519_with_config(
    data: &[u8],
    ed25519_sk: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    sign_ed25519_internal(data, ed25519_sk)
}

/// Verify an Ed25519 signature with configuration.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `SecurityMode::Verified`
/// - The configuration validation fails
/// - The signature or public key is invalid
#[inline]
pub fn verify_ed25519_with_config(
    data: &[u8],
    signature_bytes: &[u8],
    ed25519_pk: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    config.validate()?;
    verify_ed25519_internal(data, signature_bytes, ed25519_pk)
}

// ============================================================================
// Unverified API (Opt-Out)
// ============================================================================
//
// These functions skip Zero Trust session validation. They are a valid choice
// for scenarios where session management is not needed or not possible.

/// Sign data using Ed25519 without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The private key is less than 32 bytes
#[inline]
pub fn sign_ed25519_unverified(data: &[u8], ed25519_sk: &[u8]) -> Result<Vec<u8>> {
    sign_ed25519(data, ed25519_sk, SecurityMode::Unverified)
}

/// Verify an Ed25519 signature without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The signature is less than 64 bytes
/// - The public key is less than 32 bytes
/// - The public key is invalid (not a valid curve point)
#[inline]
pub fn verify_ed25519_unverified(
    data: &[u8],
    signature_bytes: &[u8],
    ed25519_pk: &[u8],
) -> Result<bool> {
    verify_ed25519(data, signature_bytes, ed25519_pk, SecurityMode::Unverified)
}

/// Sign data using Ed25519 with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The private key is less than 32 bytes
#[inline]
pub fn sign_ed25519_with_config_unverified(
    data: &[u8],
    ed25519_sk: &[u8],
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    sign_ed25519_with_config(data, ed25519_sk, config, SecurityMode::Unverified)
}

/// Verify an Ed25519 signature with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification
/// is not required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The signature is less than 64 bytes
/// - The public key is less than 32 bytes
/// - The public key is invalid (not a valid curve point)
#[inline]
pub fn verify_ed25519_with_config_unverified(
    data: &[u8],
    signature_bytes: &[u8],
    ed25519_pk: &[u8],
    config: &CoreConfig,
) -> Result<bool> {
    verify_ed25519_with_config(data, signature_bytes, ed25519_pk, config, SecurityMode::Unverified)
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
mod tests {
    use super::*;
    use crate::{SecurityMode, VerifiedSession, generate_keypair};

    // Basic sign/verify tests (unverified API)
    #[test]
    fn test_sign_verify_ed25519_unverified() -> Result<()> {
        let message = b"Test message for Ed25519";
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519_unverified(message, sk.as_ref())?;
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");

        let is_valid = verify_ed25519_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_ed25519_deterministic() -> Result<()> {
        let message = b"Same message";
        let (_, sk) = generate_keypair()?;

        let sig1 = sign_ed25519_unverified(message, sk.as_ref())?;
        let sig2 = sign_ed25519_unverified(message, sk.as_ref())?;

        assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
        Ok(())
    }

    #[test]
    fn test_verify_ed25519_wrong_message() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) = generate_keypair().expect("keygen should succeed");

        let signature =
            sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");
        let result = verify_ed25519_unverified(wrong_message, &signature, &pk);
        assert!(result.is_err(), "Verification should fail for wrong message");
    }

    #[test]
    fn test_verify_ed25519_invalid_signature() {
        let message = b"Test message";
        let (pk, _sk) = generate_keypair().expect("keygen should succeed");
        let invalid_signature = vec![0u8; 64];

        let result = verify_ed25519_unverified(message, &invalid_signature, &pk);
        assert!(result.is_err(), "Verification should fail for invalid signature");
    }

    #[test]
    fn test_verify_ed25519_wrong_public_key() {
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let (wrong_pk, _) = generate_keypair().expect("keygen should succeed");

        let signature =
            sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");
        let result = verify_ed25519_unverified(message, &signature, &wrong_pk);
        assert!(result.is_err(), "Verification should fail with wrong public key");
    }

    // With config tests
    #[test]
    fn test_sign_verify_ed25519_with_config_unverified() -> Result<()> {
        let message = b"Test with config";
        let (pk, sk) = generate_keypair()?;
        let config = CoreConfig::default();

        let signature = sign_ed25519_with_config_unverified(message, sk.as_ref(), &config)?;
        let is_valid = verify_ed25519_with_config_unverified(message, &signature, &pk, &config)?;
        assert!(is_valid);
        Ok(())
    }

    // Verified API tests (with SecurityMode)
    #[test]
    fn test_sign_verify_ed25519_verified() -> Result<()> {
        let message = b"Test with verified session";
        let (pk, sk) = generate_keypair()?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let signature = sign_ed25519(message, sk.as_ref(), SecurityMode::Verified(&session))?;
        let is_valid = verify_ed25519(message, &signature, &pk, SecurityMode::Verified(&session))?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_ed25519_unverified_mode() -> Result<()> {
        let message = b"Test unverified mode";
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519(message, sk.as_ref(), SecurityMode::Unverified)?;
        let is_valid = verify_ed25519(message, &signature, &pk, SecurityMode::Unverified)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_ed25519_with_config_verified() -> Result<()> {
        let message = b"Test with config and session";
        let (pk, sk) = generate_keypair()?;
        let config = CoreConfig::default();

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let signature = sign_ed25519_with_config(
            message,
            sk.as_ref(),
            &config,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_ed25519_with_config(
            message,
            &signature,
            &pk,
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_ed25519_with_config_unverified_mode() -> Result<()> {
        let message = b"Test with config unverified mode";
        let (pk, sk) = generate_keypair()?;
        let config = CoreConfig::default();

        let signature =
            sign_ed25519_with_config(message, sk.as_ref(), &config, SecurityMode::Unverified)?;
        let is_valid = verify_ed25519_with_config(
            message,
            &signature,
            &pk,
            &config,
            SecurityMode::Unverified,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // Edge cases
    #[test]
    fn test_ed25519_empty_message() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519_unverified(message, sk.as_ref())?;
        let is_valid = verify_ed25519_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ed25519_large_message() -> Result<()> {
        let message = vec![0xAB; 100000];
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
        let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ed25519_signature_length_constant() -> Result<()> {
        let (_, sk) = generate_keypair()?;
        let short_msg = b"short";
        let long_msg = vec![0xFF; 10000];

        let sig1 = sign_ed25519_unverified(short_msg, sk.as_ref())?;
        let sig2 = sign_ed25519_unverified(&long_msg, sk.as_ref())?;

        assert_eq!(sig1.len(), 64, "Signature length should be constant");
        assert_eq!(sig2.len(), 64, "Signature length should be constant");
        Ok(())
    }

    #[test]
    fn test_ed25519_different_messages_different_signatures() -> Result<()> {
        let (_, sk) = generate_keypair()?;
        let msg1 = b"First message";
        let msg2 = b"Second message";

        let sig1 = sign_ed25519_unverified(msg1, sk.as_ref())?;
        let sig2 = sign_ed25519_unverified(msg2, sk.as_ref())?;

        assert_ne!(sig1, sig2, "Different messages should produce different signatures");
        Ok(())
    }

    #[test]
    fn test_ed25519_different_keys_different_signatures() -> Result<()> {
        let message = b"Same message";
        let (_, sk1) = generate_keypair()?;
        let (_, sk2) = generate_keypair()?;

        let sig1 = sign_ed25519_unverified(message, sk1.as_ref())?;
        let sig2 = sign_ed25519_unverified(message, sk2.as_ref())?;

        assert_ne!(sig1, sig2, "Different keys should produce different signatures");
        Ok(())
    }

    // Invalid input tests
    #[test]
    fn test_ed25519_invalid_signature_length() {
        let message = b"Test message";
        let (pk, _sk) = generate_keypair().expect("keygen should succeed");
        let invalid_sig = vec![0u8; 32]; // Wrong length

        let result = verify_ed25519_unverified(message, &invalid_sig, &pk);
        assert!(result.is_err(), "Should reject signature with wrong length");
    }

    #[test]
    fn test_ed25519_invalid_public_key_length() {
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let invalid_pk = vec![0u8; 16]; // Wrong length

        let signature =
            sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");
        let result = verify_ed25519_unverified(message, &signature, &invalid_pk);
        assert!(result.is_err(), "Should reject public key with wrong length");
    }

    #[test]
    fn test_ed25519_invalid_secret_key_length() {
        let message = b"Test message";
        let invalid_sk = vec![0u8; 16]; // Wrong length

        let result = sign_ed25519_unverified(message, &invalid_sk);
        assert!(result.is_err(), "Should reject secret key with wrong length");
    }
}
