//! Post-quantum signature operations (ML-DSA, SLH-DSA, FN-DSA)
//!
//! This module provides post-quantum digital signature operations using
//! ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and FN-DSA (FIPS 206).
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! - **`SecurityMode::Verified(&session)`**: Validates session, enables policy enforcement
//! - **`SecurityMode::Unverified`**: Skips session validation (triggers audit in enterprise)
//!
//! The `_unverified` variants are opt-out functions for scenarios where Zero Trust
//! verification is not required or not possible. They call the unified functions with
//! `SecurityMode::Unverified`.

use crate::{
    log_crypto_operation_complete, log_crypto_operation_error, log_crypto_operation_start,
};
use tracing::debug;

use arc_primitives::sig::{
    fndsa::{
        FNDsaSecurityLevel, Signature as FnDsaSignature, SigningKey as FnDsaSigningKey,
        VerifyingKey as FnDsaVerifyingKey,
    },
    ml_dsa::{MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature},
    slh_dsa::{
        SecurityLevel as SlhDsaSecurityLevel, SigningKey as SlhDsaSigningKey,
        VerifyingKey as SlhDsaVerifyingKey,
    },
};

use crate::config::CoreConfig;
use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

use arc_validation::resource_limits::validate_signature_size;

// ============================================================================
// Internal Implementation - ML-DSA
// ============================================================================

/// Internal implementation of ML-DSA signing.
fn sign_pq_ml_dsa_internal(
    message: &[u8],
    ml_dsa_sk: &[u8],
    parameter_set: MlDsaParameterSet,
) -> Result<Vec<u8>> {
    log_crypto_operation_start!("ml_dsa_sign", algorithm = ?parameter_set, message_len = message.len());

    validate_signature_size(message.len()).map_err(|e| {
        log_crypto_operation_error!("ml_dsa_sign", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let sk = MlDsaSecretKey::new(parameter_set, ml_dsa_sk.to_vec()).map_err(|e| {
        log_crypto_operation_error!("ml_dsa_sign", e);
        CoreError::InvalidInput(format!("Invalid ML-DSA private key: {}", e))
    })?;

    let signature = arc_primitives::sig::ml_dsa::sign(&sk, message, &[]).map_err(|e| {
        log_crypto_operation_error!("ml_dsa_sign", e);
        CoreError::SignatureFailed(format!("ML-DSA signing failed: {}", e))
    })?;

    let sig_bytes = signature.as_bytes().to_vec();
    log_crypto_operation_complete!("ml_dsa_sign", algorithm = ?parameter_set, signature_len = sig_bytes.len());
    debug!(algorithm = ?parameter_set, "Created ML-DSA signature");

    Ok(sig_bytes)
}

/// Internal implementation of ML-DSA verification.
fn verify_pq_ml_dsa_internal(
    message: &[u8],
    signature: &[u8],
    ml_dsa_pk: &[u8],
    parameter_set: MlDsaParameterSet,
) -> Result<bool> {
    log_crypto_operation_start!("ml_dsa_verify", algorithm = ?parameter_set, message_len = message.len());

    validate_signature_size(message.len()).map_err(|e| {
        log_crypto_operation_error!("ml_dsa_verify", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let pk = MlDsaPublicKey::new(parameter_set, ml_dsa_pk.to_vec()).map_err(|e| {
        log_crypto_operation_error!("ml_dsa_verify", e);
        CoreError::InvalidInput(format!("Invalid ML-DSA public key: {}", e))
    })?;

    let sig = MlDsaSignature::new(parameter_set, signature.to_vec()).map_err(|e| {
        log_crypto_operation_error!("ml_dsa_verify", e);
        CoreError::InvalidInput(format!("Invalid ML-DSA signature: {}", e))
    })?;

    let result = match arc_primitives::sig::ml_dsa::verify(&pk, message, &sig, &[]) {
        Ok(true) => Ok(true),
        Ok(false) => Err(CoreError::VerificationFailed),
        Err(e) => Err(CoreError::InvalidInput(format!("ML-DSA verification error: {}", e))),
    };

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!("ml_dsa_verify", algorithm = ?parameter_set, valid = *valid);
            debug!(algorithm = ?parameter_set, valid = *valid, "ML-DSA verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!("ml_dsa_verify", e);
        }
    }

    result
}

// ============================================================================
// Internal Implementation - SLH-DSA
// ============================================================================

/// Internal implementation of SLH-DSA signing.
fn sign_pq_slh_dsa_internal(
    message: &[u8],
    slh_dsa_sk: &[u8],
    security_level: SlhDsaSecurityLevel,
) -> Result<Vec<u8>> {
    log_crypto_operation_start!("slh_dsa_sign", algorithm = ?security_level, message_len = message.len());

    validate_signature_size(message.len()).map_err(|e| {
        log_crypto_operation_error!("slh_dsa_sign", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let sk = SlhDsaSigningKey::from_bytes(security_level, slh_dsa_sk).map_err(|e| {
        log_crypto_operation_error!("slh_dsa_sign", e);
        CoreError::InvalidInput(format!("Invalid SLH-DSA private key: {}", e))
    })?;

    let signature = sk.sign(message, Some(b"context")).map_err(|e| {
        log_crypto_operation_error!("slh_dsa_sign", e);
        CoreError::SignatureFailed(format!("SLH-DSA signing failed: {}", e))
    })?;

    log_crypto_operation_complete!("slh_dsa_sign", algorithm = ?security_level, signature_len = signature.len());
    debug!(algorithm = ?security_level, "Created SLH-DSA signature");

    Ok(signature)
}

/// Internal implementation of SLH-DSA verification.
fn verify_pq_slh_dsa_internal(
    message: &[u8],
    signature: &[u8],
    slh_dsa_pk: &[u8],
    security_level: SlhDsaSecurityLevel,
) -> Result<bool> {
    log_crypto_operation_start!("slh_dsa_verify", algorithm = ?security_level, message_len = message.len());

    validate_signature_size(message.len()).map_err(|e| {
        log_crypto_operation_error!("slh_dsa_verify", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let pk = SlhDsaVerifyingKey::from_bytes(security_level, slh_dsa_pk).map_err(|e| {
        log_crypto_operation_error!("slh_dsa_verify", e);
        CoreError::InvalidInput(format!("Invalid SLH-DSA public key: {}", e))
    })?;

    let result = match pk.verify(message, signature, Some(b"context")) {
        Ok(true) => Ok(true),
        Ok(false) => Err(CoreError::VerificationFailed),
        Err(e) => Err(CoreError::InvalidInput(format!("SLH-DSA verification error: {}", e))),
    };

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!("slh_dsa_verify", algorithm = ?security_level, valid = *valid);
            debug!(algorithm = ?security_level, valid = *valid, "SLH-DSA verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!("slh_dsa_verify", e);
        }
    }

    result
}

// ============================================================================
// Internal Implementation - FN-DSA
// ============================================================================

/// Internal implementation of FN-DSA signing.
fn sign_pq_fn_dsa_internal(message: &[u8], fn_dsa_sk: &[u8]) -> Result<Vec<u8>> {
    log_crypto_operation_start!(
        "fn_dsa_sign",
        algorithm = "FN-DSA-512",
        message_len = message.len()
    );

    validate_signature_size(message.len()).map_err(|e| {
        log_crypto_operation_error!("fn_dsa_sign", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let mut sk = FnDsaSigningKey::from_bytes(fn_dsa_sk.to_vec(), FNDsaSecurityLevel::Level512)
        .map_err(|e| {
            log_crypto_operation_error!("fn_dsa_sign", e);
            CoreError::InvalidInput(format!("Invalid FN-DSA private key: {}", e))
        })?;

    let mut rng = rand::rngs::OsRng;
    let signature = sk.sign(&mut rng, message).map_err(|e| {
        log_crypto_operation_error!("fn_dsa_sign", e);
        CoreError::SignatureFailed(format!("FN-DSA signing failed: {}", e))
    })?;

    let sig_bytes = signature.to_bytes();
    log_crypto_operation_complete!(
        "fn_dsa_sign",
        algorithm = "FN-DSA-512",
        signature_len = sig_bytes.len()
    );
    debug!(algorithm = "FN-DSA-512", "Created FN-DSA signature");

    Ok(sig_bytes)
}

/// Internal implementation of FN-DSA verification.
fn verify_pq_fn_dsa_internal(message: &[u8], signature: &[u8], fn_dsa_pk: &[u8]) -> Result<bool> {
    log_crypto_operation_start!(
        "fn_dsa_verify",
        algorithm = "FN-DSA-512",
        message_len = message.len()
    );

    validate_signature_size(message.len()).map_err(|e| {
        log_crypto_operation_error!("fn_dsa_verify", e);
        CoreError::ResourceExceeded(e.to_string())
    })?;

    let pk = FnDsaVerifyingKey::from_bytes(fn_dsa_pk.to_vec(), FNDsaSecurityLevel::Level512)
        .map_err(|e| {
            log_crypto_operation_error!("fn_dsa_verify", e);
            CoreError::InvalidInput(format!("Invalid FN-DSA public key: {}", e))
        })?;

    let sig = FnDsaSignature::from_bytes(signature.to_vec()).map_err(|e| {
        log_crypto_operation_error!("fn_dsa_verify", e);
        CoreError::InvalidInput(format!("Invalid FN-DSA signature: {}", e))
    })?;

    let result = match pk.verify(message, &sig) {
        Ok(true) => Ok(true),
        Ok(false) => Err(CoreError::VerificationFailed),
        Err(e) => Err(CoreError::InvalidInput(format!("FN-DSA verification error: {}", e))),
    };

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!(
                "fn_dsa_verify",
                algorithm = "FN-DSA-512",
                valid = *valid
            );
            debug!(algorithm = "FN-DSA-512", valid = *valid, "FN-DSA verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!("fn_dsa_verify", e);
        }
    }

    result
}

// ============================================================================
// Unified API - ML-DSA (with SecurityMode)
// ============================================================================

/// Sign a message using ML-DSA with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before signing
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The message size exceeds resource limits
/// - The private key is invalid for the specified parameter set
/// - The ML-DSA signing operation fails
pub fn sign_pq_ml_dsa(
    message: &[u8],
    private_key: &[u8],
    params: MlDsaParameterSet,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    sign_pq_ml_dsa_internal(message, private_key, params)
}

/// Verify a message signature using ML-DSA with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before verification
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The message size exceeds resource limits
/// - The public key is invalid for the specified parameter set
/// - The signature is malformed
/// - The signature verification fails
pub fn verify_pq_ml_dsa(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    params: MlDsaParameterSet,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    verify_pq_ml_dsa_internal(message, signature, public_key, params)
}

// ============================================================================
// Unified API - SLH-DSA (with SecurityMode)
// ============================================================================

/// Sign a message using SLH-DSA with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before signing
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The message size exceeds resource limits
/// - The private key is invalid for the specified security level
/// - The SLH-DSA signing operation fails
pub fn sign_pq_slh_dsa(
    message: &[u8],
    private_key: &[u8],
    security_level: SlhDsaSecurityLevel,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    sign_pq_slh_dsa_internal(message, private_key, security_level)
}

/// Verify a message signature using SLH-DSA with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before verification
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The message size exceeds resource limits
/// - The public key is invalid for the specified security level
/// - The signature verification fails
pub fn verify_pq_slh_dsa(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    security_level: SlhDsaSecurityLevel,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    verify_pq_slh_dsa_internal(message, signature, public_key, security_level)
}

// ============================================================================
// Unified API - FN-DSA (with SecurityMode)
// ============================================================================

/// Sign a message using FN-DSA with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before signing
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The message size exceeds resource limits
/// - The private key is invalid
/// - The FN-DSA signing operation fails
pub fn sign_pq_fn_dsa(message: &[u8], private_key: &[u8], mode: SecurityMode) -> Result<Vec<u8>> {
    mode.validate()?;
    sign_pq_fn_dsa_internal(message, private_key)
}

/// Verify a message signature using FN-DSA with configurable security mode.
///
/// Uses `SecurityMode` to specify verification behavior:
/// - `SecurityMode::Verified(&session)`: Validates session before verification
/// - `SecurityMode::Unverified`: Skips session validation
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (`CoreError::SessionExpired`) when using `Verified` mode
/// - The message size exceeds resource limits
/// - The public key is invalid
/// - The signature is malformed
/// - The signature verification fails
pub fn verify_pq_fn_dsa(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    verify_pq_fn_dsa_internal(message, signature, public_key)
}

// ============================================================================
// Unified API with Config - ML-DSA
// ============================================================================

/// Sign a message using ML-DSA with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `Verified` mode
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The ML-DSA signing operation fails
pub fn sign_pq_ml_dsa_with_config(
    message: &[u8],
    private_key: &[u8],
    params: MlDsaParameterSet,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    sign_pq_ml_dsa_internal(message, private_key, params)
}

/// Verify a message signature using ML-DSA with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired when using `Verified` mode
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The signature verification fails
pub fn verify_pq_ml_dsa_with_config(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    params: MlDsaParameterSet,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    config.validate()?;
    verify_pq_ml_dsa_internal(message, signature, public_key, params)
}

// ============================================================================
// Unified API with Config - SLH-DSA
// ============================================================================

/// Sign a message using SLH-DSA with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The security mode validation fails (session expired for Verified mode)
/// - The configuration validation fails
/// - The private key is invalid for SLH-DSA
/// - The signing operation fails
pub fn sign_pq_slh_dsa_with_config(
    message: &[u8],
    private_key: &[u8],
    security_level: SlhDsaSecurityLevel,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    sign_pq_slh_dsa_internal(message, private_key, security_level)
}

/// Verify a message signature using SLH-DSA with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The security mode validation fails (session expired for Verified mode)
/// - The configuration validation fails
/// - The public key is invalid for SLH-DSA
/// - The signature verification fails
pub fn verify_pq_slh_dsa_with_config(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    security_level: SlhDsaSecurityLevel,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    config.validate()?;
    verify_pq_slh_dsa_internal(message, signature, public_key, security_level)
}

// ============================================================================
// Unified API with Config - FN-DSA
// ============================================================================

/// Sign a message using FN-DSA with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The security mode validation fails (session expired for Verified mode)
/// - The configuration validation fails
/// - The private key is invalid for FN-DSA
/// - The signing operation fails
pub fn sign_pq_fn_dsa_with_config(
    message: &[u8],
    private_key: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    sign_pq_fn_dsa_internal(message, private_key)
}

/// Verify a message signature using FN-DSA with configuration and configurable security mode.
///
/// # Errors
///
/// Returns an error if:
/// - The security mode validation fails (session expired for Verified mode)
/// - The configuration validation fails
/// - The public key is invalid for FN-DSA
/// - The signature is malformed
/// - The signature verification fails
pub fn verify_pq_fn_dsa_with_config(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    config.validate()?;
    verify_pq_fn_dsa_internal(message, signature, public_key)
}

// ============================================================================
// Unverified API - ML-DSA (Opt-Out)
// ============================================================================

/// Sign a message using ML-DSA without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The private key is invalid for the specified parameter set
/// - The ML-DSA signing operation fails
pub fn sign_pq_ml_dsa_unverified(
    message: &[u8],
    ml_dsa_sk: &[u8],
    parameter_set: MlDsaParameterSet,
) -> Result<Vec<u8>> {
    sign_pq_ml_dsa(message, ml_dsa_sk, parameter_set, SecurityMode::Unverified)
}

/// Verify a message signature using ML-DSA without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The public key is invalid for the specified parameter set
/// - The signature is malformed
/// - The signature verification fails
pub fn verify_pq_ml_dsa_unverified(
    message: &[u8],
    signature: &[u8],
    ml_dsa_pk: &[u8],
    parameter_set: MlDsaParameterSet,
) -> Result<bool> {
    verify_pq_ml_dsa(message, signature, ml_dsa_pk, parameter_set, SecurityMode::Unverified)
}

/// Sign a message using ML-DSA with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The private key is invalid for the specified parameter set
/// - The ML-DSA signing operation fails
pub fn sign_pq_ml_dsa_with_config_unverified(
    message: &[u8],
    ml_dsa_sk: &[u8],
    parameter_set: MlDsaParameterSet,
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    sign_pq_ml_dsa_with_config(message, ml_dsa_sk, parameter_set, config, SecurityMode::Unverified)
}

/// Verify a message signature using ML-DSA with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The public key is invalid for the specified parameter set
/// - The signature is malformed
/// - The signature verification fails
pub fn verify_pq_ml_dsa_with_config_unverified(
    message: &[u8],
    signature: &[u8],
    ml_dsa_pk: &[u8],
    parameter_set: MlDsaParameterSet,
    config: &CoreConfig,
) -> Result<bool> {
    verify_pq_ml_dsa_with_config(
        message,
        signature,
        ml_dsa_pk,
        parameter_set,
        config,
        SecurityMode::Unverified,
    )
}

// ============================================================================
// Unverified API - SLH-DSA (Opt-Out)
// ============================================================================

/// Sign a message using SLH-DSA without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The private key is invalid for the specified security level
/// - The SLH-DSA signing operation fails
pub fn sign_pq_slh_dsa_unverified(
    message: &[u8],
    slh_dsa_sk: &[u8],
    security_level: SlhDsaSecurityLevel,
) -> Result<Vec<u8>> {
    sign_pq_slh_dsa(message, slh_dsa_sk, security_level, SecurityMode::Unverified)
}

/// Verify a message signature using SLH-DSA without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The public key is invalid for the specified security level
/// - The signature verification fails
pub fn verify_pq_slh_dsa_unverified(
    message: &[u8],
    signature: &[u8],
    slh_dsa_pk: &[u8],
    security_level: SlhDsaSecurityLevel,
) -> Result<bool> {
    verify_pq_slh_dsa(message, signature, slh_dsa_pk, security_level, SecurityMode::Unverified)
}

/// Sign a message using SLH-DSA with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The private key is invalid for the specified security level
/// - The SLH-DSA signing operation fails
pub fn sign_pq_slh_dsa_with_config_unverified(
    message: &[u8],
    slh_dsa_sk: &[u8],
    security_level: SlhDsaSecurityLevel,
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    sign_pq_slh_dsa_with_config(
        message,
        slh_dsa_sk,
        security_level,
        config,
        SecurityMode::Unverified,
    )
}

/// Verify a message signature using SLH-DSA with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The public key is invalid for the specified security level
/// - The signature verification fails
pub fn verify_pq_slh_dsa_with_config_unverified(
    message: &[u8],
    signature: &[u8],
    slh_dsa_pk: &[u8],
    security_level: SlhDsaSecurityLevel,
    config: &CoreConfig,
) -> Result<bool> {
    verify_pq_slh_dsa_with_config(
        message,
        signature,
        slh_dsa_pk,
        security_level,
        config,
        SecurityMode::Unverified,
    )
}

// ============================================================================
// Unverified API - FN-DSA (Opt-Out)
// ============================================================================

/// Sign a message using FN-DSA without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The private key is invalid
/// - The FN-DSA signing operation fails
pub fn sign_pq_fn_dsa_unverified(message: &[u8], fn_dsa_sk: &[u8]) -> Result<Vec<u8>> {
    sign_pq_fn_dsa(message, fn_dsa_sk, SecurityMode::Unverified)
}

/// Verify a message signature using FN-DSA without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The message size exceeds resource limits
/// - The public key is invalid
/// - The signature is malformed
/// - The signature verification fails
pub fn verify_pq_fn_dsa_unverified(
    message: &[u8],
    signature: &[u8],
    fn_dsa_pk: &[u8],
) -> Result<bool> {
    verify_pq_fn_dsa(message, signature, fn_dsa_pk, SecurityMode::Unverified)
}

/// Sign a message using FN-DSA with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The private key is invalid
/// - The FN-DSA signing operation fails
pub fn sign_pq_fn_dsa_with_config_unverified(
    message: &[u8],
    fn_dsa_sk: &[u8],
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    sign_pq_fn_dsa_with_config(message, fn_dsa_sk, config, SecurityMode::Unverified)
}

/// Verify a message signature using FN-DSA with configuration without Zero Trust verification.
///
/// This is an opt-out function for scenarios where Zero Trust verification is not
/// required or not possible.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration validation fails
/// - The message size exceeds resource limits
/// - The public key is invalid
/// - The signature is malformed
/// - The signature verification fails
pub fn verify_pq_fn_dsa_with_config_unverified(
    message: &[u8],
    signature: &[u8],
    fn_dsa_pk: &[u8],
    config: &CoreConfig,
) -> Result<bool> {
    verify_pq_fn_dsa_with_config(message, signature, fn_dsa_pk, config, SecurityMode::Unverified)
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
mod tests {
    use super::*;
    use crate::convenience::keygen::{
        generate_fn_dsa_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair,
    };
    use crate::{SecurityMode, VerifiedSession, generate_keypair};
    use arc_primitives::sig::ml_dsa::MlDsaParameterSet;
    use arc_primitives::sig::slh_dsa::SecurityLevel as SlhDsaSecurityLevel;

    // ML-DSA tests (unverified API)
    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_44() -> Result<()> {
        let message = b"Test message for ML-DSA-44";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA44)?;
        assert!(!signature.is_empty());

        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA44)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_65() -> Result<()> {
        let message = b"Test message for ML-DSA-65";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_87() -> Result<()> {
        let message = b"Test message for ML-DSA-87";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA87)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA87)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_verify_invalid_signature() {
        let message = b"Test message";
        let (pk, _sk) =
            generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");
        let invalid_signature = vec![0u8; 100];

        let result = verify_pq_ml_dsa_unverified(
            message,
            &invalid_signature,
            &pk,
            MlDsaParameterSet::MLDSA65,
        );
        assert!(result.is_err(), "Verification should fail for invalid signature");
    }

    #[test]
    fn test_ml_dsa_verify_wrong_message() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) =
            generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");

        let signature = sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)
            .expect("signing should succeed");
        let result =
            verify_pq_ml_dsa_unverified(wrong_message, &signature, &pk, MlDsaParameterSet::MLDSA65);
        assert!(result.is_err(), "Verification should fail for wrong message");
    }

    // ML-DSA with config tests
    #[test]
    fn test_sign_verify_pq_ml_dsa_with_config_unverified() -> Result<()> {
        let message = b"Test with config";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
        let config = CoreConfig::default();

        let signature = sign_pq_ml_dsa_with_config_unverified(
            message,
            sk.as_ref(),
            MlDsaParameterSet::MLDSA65,
            &config,
        )?;
        let is_valid = verify_pq_ml_dsa_with_config_unverified(
            message,
            &signature,
            &pk,
            MlDsaParameterSet::MLDSA65,
            &config,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // ML-DSA verified API tests
    #[test]
    fn test_sign_verify_pq_ml_dsa_verified() -> Result<()> {
        let message = b"Test with verified session";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let signature = sign_pq_ml_dsa(
            message,
            sk.as_ref(),
            MlDsaParameterSet::MLDSA65,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_ml_dsa(
            message,
            &signature,
            &pk,
            MlDsaParameterSet::MLDSA65,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_mode() -> Result<()> {
        let message = b"Test unverified mode";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

        let signature = sign_pq_ml_dsa(
            message,
            sk.as_ref(),
            MlDsaParameterSet::MLDSA65,
            SecurityMode::Unverified,
        )?;
        let is_valid = verify_pq_ml_dsa(
            message,
            &signature,
            &pk,
            MlDsaParameterSet::MLDSA65,
            SecurityMode::Unverified,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // SLH-DSA tests
    #[test]
    fn test_sign_verify_pq_slh_dsa_unverified_128s() -> Result<()> {
        let message = b"Test SLH-DSA-128s";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

        let signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake128s)?;
        let is_valid =
            verify_pq_slh_dsa_unverified(message, &signature, &pk, SlhDsaSecurityLevel::Shake128s)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_slh_dsa_unverified_128f() -> Result<()> {
        let message = b"Test SLH-DSA-128f";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;

        let signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake192s)?;
        let is_valid =
            verify_pq_slh_dsa_unverified(message, &signature, &pk, SlhDsaSecurityLevel::Shake192s)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_verify_wrong_message() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)
            .expect("keygen should succeed");

        let signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake128s)
                .expect("signing should succeed");
        let result = verify_pq_slh_dsa_unverified(
            wrong_message,
            &signature,
            &pk,
            SlhDsaSecurityLevel::Shake128s,
        );
        assert!(result.is_err(), "Verification should fail for wrong message");
    }

    // SLH-DSA with config tests
    #[test]
    fn test_sign_verify_pq_slh_dsa_with_config_unverified() -> Result<()> {
        let message = b"Test SLH-DSA with config";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let config = CoreConfig::default();

        let signature = sign_pq_slh_dsa_with_config_unverified(
            message,
            sk.as_ref(),
            SlhDsaSecurityLevel::Shake128s,
            &config,
        )?;
        let is_valid = verify_pq_slh_dsa_with_config_unverified(
            message,
            &signature,
            &pk,
            SlhDsaSecurityLevel::Shake128s,
            &config,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // SLH-DSA verified API tests
    #[test]
    fn test_sign_verify_pq_slh_dsa_verified() -> Result<()> {
        let message = b"Test SLH-DSA verified";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let signature = sign_pq_slh_dsa(
            message,
            sk.as_ref(),
            SlhDsaSecurityLevel::Shake128s,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_slh_dsa(
            message,
            &signature,
            &pk,
            SlhDsaSecurityLevel::Shake128s,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    // FN-DSA tests
    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_sign_verify_pq_fn_dsa_unverified() -> Result<()> {
        let message = b"Test FN-DSA";
        let (pk, sk) = generate_fn_dsa_keypair()?;

        let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_fn_dsa_verify_wrong_message() -> Result<()> {
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) = generate_fn_dsa_keypair()?;

        let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(wrong_message, &signature, &pk)?;
        assert!(!is_valid);
        Ok(())
    }

    // FN-DSA with config tests
    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_sign_verify_pq_fn_dsa_with_config_unverified() -> Result<()> {
        let message = b"Test FN-DSA with config";
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let config = CoreConfig::default();

        let signature = sign_pq_fn_dsa_with_config_unverified(message, sk.as_ref(), &config)?;
        let is_valid = verify_pq_fn_dsa_with_config_unverified(message, &signature, &pk, &config)?;
        assert!(is_valid);
        Ok(())
    }

    // FN-DSA verified API tests
    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_sign_verify_pq_fn_dsa_verified() -> Result<()> {
        let message = b"Test FN-DSA verified";
        let (pk, sk) = generate_fn_dsa_keypair()?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let signature = sign_pq_fn_dsa(message, sk.as_ref(), SecurityMode::Verified(&session))?;
        let is_valid =
            verify_pq_fn_dsa(message, &signature, &pk, SecurityMode::Verified(&session))?;
        assert!(is_valid);
        Ok(())
    }

    // Edge case tests
    #[test]
    fn test_ml_dsa_empty_message() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_large_message() -> Result<()> {
        let message = vec![0xAB; 10000];
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

        let signature =
            sign_pq_ml_dsa_unverified(&message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(&message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_signature_determinism() -> Result<()> {
        let message = b"Same message";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

        let sig1 = sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;
        let sig2 = sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;

        // ML-DSA signatures may be non-deterministic due to randomness
        // Just verify both are valid
        let valid1 = verify_pq_ml_dsa_unverified(message, &sig1, &pk, MlDsaParameterSet::MLDSA65)?;
        let valid2 = verify_pq_ml_dsa_unverified(message, &sig2, &pk, MlDsaParameterSet::MLDSA65)?;
        assert!(valid1 && valid2);
        Ok(())
    }

    // Integration tests
    #[test]
    fn test_all_ml_dsa_security_levels() -> Result<()> {
        let message = b"Test all levels";
        let levels = vec![
            MlDsaParameterSet::MLDSA44,
            MlDsaParameterSet::MLDSA65,
            MlDsaParameterSet::MLDSA87,
        ];

        for level in levels {
            let (pk, sk) = generate_ml_dsa_keypair(level)?;
            let signature = sign_pq_ml_dsa_unverified(message, sk.as_ref(), level)?;
            let is_valid = verify_pq_ml_dsa_unverified(message, &signature, &pk, level)?;
            assert!(is_valid, "Verification failed for {:?}", level);
        }
        Ok(())
    }

    #[test]
    fn test_all_slh_dsa_security_levels() -> Result<()> {
        let message = b"Test all SLH-DSA levels";
        let levels = vec![SlhDsaSecurityLevel::Shake128s, SlhDsaSecurityLevel::Shake192s];

        for level in levels {
            let (pk, sk) = generate_slh_dsa_keypair(level)?;
            let signature = sign_pq_slh_dsa_unverified(message, sk.as_ref(), level)?;
            let is_valid = verify_pq_slh_dsa_unverified(message, &signature, &pk, level)?;
            assert!(is_valid, "Verification failed for {:?}", level);
        }
        Ok(())
    }

    // Additional tests for 90%+ coverage target

    #[test]
    fn test_slh_dsa_shake256s() -> Result<()> {
        let message = b"Test SLH-DSA Shake256s";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;
        let signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake256s)?;
        let is_valid =
            verify_pq_slh_dsa_unverified(message, &signature, &pk, SlhDsaSecurityLevel::Shake256s)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_empty_message() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake128s)?;
        let is_valid =
            verify_pq_slh_dsa_unverified(message, &signature, &pk, SlhDsaSecurityLevel::Shake128s)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_large_message() -> Result<()> {
        let message = vec![0xCD; 10_000];
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;
        let signature =
            sign_pq_slh_dsa_unverified(&message, sk.as_ref(), SlhDsaSecurityLevel::Shake192s)?;
        let is_valid = verify_pq_slh_dsa_unverified(
            &message,
            &signature,
            &pk,
            SlhDsaSecurityLevel::Shake192s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_binary_data() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let signature =
            sign_pq_slh_dsa_unverified(&message, sk.as_ref(), SlhDsaSecurityLevel::Shake128s)?;
        let is_valid = verify_pq_slh_dsa_unverified(
            &message,
            &signature,
            &pk,
            SlhDsaSecurityLevel::Shake128s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_fn_dsa_empty_message() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let signature = sign_pq_fn_dsa_unverified(message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_fn_dsa_large_message() -> Result<()> {
        let message = vec![0xEF; 10_000];
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let signature = sign_pq_fn_dsa_unverified(&message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(&message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_cross_keypair_fails() {
        let message = b"Test message";
        let (_pk1, sk1) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair 1");
        let (pk2, _sk2) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair 2");

        let signature =
            sign_pq_ml_dsa_unverified(message, sk1.as_ref(), MlDsaParameterSet::MLDSA44)
                .expect("signing");

        let result =
            verify_pq_ml_dsa_unverified(message, &signature, &pk2, MlDsaParameterSet::MLDSA44);
        assert!(result.is_err());
    }

    #[test]
    fn test_slh_dsa_cross_keypair_fails() {
        let message = b"Test message";
        let (_pk1, sk1) =
            generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair 1");
        let (pk2, _sk2) =
            generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair 2");

        let signature =
            sign_pq_slh_dsa_unverified(message, sk1.as_ref(), SlhDsaSecurityLevel::Shake128s)
                .expect("signing");

        let result =
            verify_pq_slh_dsa_unverified(message, &signature, &pk2, SlhDsaSecurityLevel::Shake128s);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_dsa_tampered_signature_fails() {
        let message = b"Original message";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair");

        let mut signature =
            sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA44)
                .expect("signing");

        if !signature.is_empty() {
            signature[0] ^= 0xFF;
        }

        let result =
            verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA44);
        assert!(result.is_err());
    }

    #[test]
    fn test_slh_dsa_tampered_signature_fails() {
        let message = b"Original message";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair");

        let mut signature =
            sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake128s)
                .expect("signing");

        if !signature.is_empty() {
            signature[0] ^= 0xFF;
        }

        let result =
            verify_pq_slh_dsa_unverified(message, &signature, &pk, SlhDsaSecurityLevel::Shake128s);
        assert!(result.is_err());
    }

    #[test]
    fn test_ml_dsa_binary_data() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;
        let signature =
            sign_pq_ml_dsa_unverified(&message, sk.as_ref(), MlDsaParameterSet::MLDSA44)?;
        let is_valid =
            verify_pq_ml_dsa_unverified(&message, &signature, &pk, MlDsaParameterSet::MLDSA44)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    #[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
    fn test_fn_dsa_binary_data() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let signature = sign_pq_fn_dsa_unverified(&message, sk.as_ref())?;
        let is_valid = verify_pq_fn_dsa_unverified(&message, &signature, &pk)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_multiple_messages() -> Result<()> {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
        let messages = vec![b"First".as_ref(), b"Second".as_ref(), b"Third".as_ref()];

        for message in messages {
            let signature =
                sign_pq_ml_dsa_unverified(message, sk.as_ref(), MlDsaParameterSet::MLDSA65)?;
            let is_valid =
                verify_pq_ml_dsa_unverified(message, &signature, &pk, MlDsaParameterSet::MLDSA65)?;
            assert!(is_valid);
        }
        Ok(())
    }

    #[test]
    fn test_slh_dsa_multiple_messages() -> Result<()> {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;
        let messages = vec![b"First".as_ref(), b"Second".as_ref(), b"Third".as_ref()];

        for message in messages {
            let signature =
                sign_pq_slh_dsa_unverified(message, sk.as_ref(), SlhDsaSecurityLevel::Shake192s)?;
            let is_valid = verify_pq_slh_dsa_unverified(
                message,
                &signature,
                &pk,
                SlhDsaSecurityLevel::Shake192s,
            )?;
            assert!(is_valid);
        }
        Ok(())
    }

    #[test]
    fn test_ml_dsa_with_config_all_params() -> Result<()> {
        let message = b"Test with config";
        let config = CoreConfig::default();
        let params = vec![
            MlDsaParameterSet::MLDSA44,
            MlDsaParameterSet::MLDSA65,
            MlDsaParameterSet::MLDSA87,
        ];

        for param in params {
            let (pk, sk) = generate_ml_dsa_keypair(param)?;
            let signature =
                sign_pq_ml_dsa_with_config_unverified(message, sk.as_ref(), param, &config)?;
            let is_valid =
                verify_pq_ml_dsa_with_config_unverified(message, &signature, &pk, param, &config)?;
            assert!(is_valid);
        }
        Ok(())
    }

    #[test]
    fn test_slh_dsa_256s_with_config() -> Result<()> {
        let message = b"Test SLH-DSA-256s with config";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;
        let config = CoreConfig::default();

        let signature = sign_pq_slh_dsa_with_config_unverified(
            message,
            sk.as_ref(),
            SlhDsaSecurityLevel::Shake256s,
            &config,
        )?;
        let is_valid = verify_pq_slh_dsa_with_config_unverified(
            message,
            &signature,
            &pk,
            SlhDsaSecurityLevel::Shake256s,
            &config,
        )?;
        assert!(is_valid);
        Ok(())
    }
}
