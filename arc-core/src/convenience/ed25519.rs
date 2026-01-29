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

    let valid = verifying_key.verify(data, &signature).is_ok();

    log_crypto_operation_complete!("ed25519_verify", algorithm = "Ed25519", valid = valid);
    debug!(algorithm = "Ed25519", valid = valid, "Ed25519 verification completed");

    Ok(valid)
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
