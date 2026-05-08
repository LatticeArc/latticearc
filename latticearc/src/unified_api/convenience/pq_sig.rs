//! Post-quantum signature operations (ML-DSA, SLH-DSA, FN-DSA)
//!
//! This module provides post-quantum digital signature operations using
//! ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and FN-DSA (draft FIPS 206).
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! - **`SecurityMode::Verified(&session)`**: Validates session, enables policy enforcement
//! - **`SecurityMode::Unverified`**: Skips session validation
//!
//! The `_unverified` variants are opt-out functions for scenarios where Zero Trust
//! verification is not required or not possible. They call the unified functions with
//! `SecurityMode::Unverified`.

use crate::{
    log_crypto_operation_complete, log_crypto_operation_error, log_crypto_operation_start,
};
use tracing::{debug, warn};

use crate::primitives::sig::{
    fndsa::{
        FnDsaSecurityLevel, Signature as FnDsaSignature, SigningKey as FnDsaSigningKey,
        VerifyingKey as FnDsaVerifyingKey,
    },
    ml_dsa::{MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature},
    slh_dsa::{
        SigningKey as SlhDsaSigningKey, SlhDsaSecurityLevel, VerifyingKey as SlhDsaVerifyingKey,
    },
};

use crate::types::types::SecurityLevel;
use crate::unified_api::CoreConfig;
use crate::unified_api::error::{CoreError, Result};

/// Map a primitive verify result `Result<bool, E>` to the convenience-API
/// shape `Result<bool, CoreError>`. Used by all three PQ verify paths
/// (ML-DSA, SLH-DSA, FN-DSA) to collapse:
///
/// ```text
/// Ok(true)  → Ok(true)
/// Ok(false) → Ok(false)
/// Err(e)    → Ok(false), with `tracing::debug!` capturing the cause
/// ```
///
/// the previous mapping returned distinguishable
/// `Err(VerificationFailed)` and `Err(InvalidInput("{alg} ... {e}"))`
/// variants on adversary-reachable input, leaking both the algorithm
/// name and upstream parse failure detail. H7 closed the same
/// re-opening at convenience-layer string sites but missed this central
/// mapper. Now the only observable boolean to a verifier is `Ok(false)`
/// for any rejection (correct shape *or* malformed bytes); diagnosis
/// goes through `tracing::debug!` at developer log level.
// the post-collapse signature always returns `Ok(...)`, but
// the wrapping `Result<bool>` is required to match the call sites that
// previously could fail and to keep the public-API shape stable across
// the Pattern 6 sweep. `unnecessary_wraps` is silenced for that reason.
#[expect(
    clippy::unnecessary_wraps,
    reason = "Result<bool> shape preserved for API parity with the pre-Pattern-6 callers; if a future change re-introduces a fallible path the suppress will resolve naturally"
)]
fn map_verify_result<E: std::fmt::Display>(
    r: std::result::Result<bool, E>,
    alg: &str,
) -> Result<bool> {
    Ok(match r {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(alg = %alg, error = %e, "PQ-sig verify rejected (Err mapped to Ok(false))");
            false
        }
    })
}
use crate::unified_api::logging::op;
use crate::unified_api::zero_trust::SecurityMode;

use crate::primitives::resource_limits::validate_signature_size;

/// Maps `CoreConfig.security_level` to the expected `MlDsaParameterSet`.
fn expected_ml_dsa_params(security_level: SecurityLevel) -> MlDsaParameterSet {
    match security_level {
        SecurityLevel::Standard => MlDsaParameterSet::MlDsa44,
        SecurityLevel::High => MlDsaParameterSet::MlDsa65,
        SecurityLevel::Maximum => MlDsaParameterSet::MlDsa87,
    }
}

/// Warn if the explicit ML-DSA parameter set differs from the CoreConfig's security_level.
fn check_ml_dsa_config_consistency(explicit: MlDsaParameterSet, config: &CoreConfig) {
    let expected = expected_ml_dsa_params(config.security_level);
    if expected != explicit {
        warn!(
            "Explicit MlDsaParameterSet ({:?}) differs from CoreConfig security_level ({:?} \
             → {:?}). Using explicit parameter.",
            explicit, config.security_level, expected
        );
    }
}

/// Maps `CoreConfig.security_level` to the expected `SlhDsaSecurityLevel`.
fn expected_slh_dsa_level(security_level: SecurityLevel) -> SlhDsaSecurityLevel {
    match security_level {
        SecurityLevel::Standard => SlhDsaSecurityLevel::Shake128s,
        SecurityLevel::High => SlhDsaSecurityLevel::Shake192s,
        SecurityLevel::Maximum => SlhDsaSecurityLevel::Shake256s,
    }
}

/// Warn if the explicit SLH-DSA security level differs from the CoreConfig's security_level.
fn check_slh_dsa_config_consistency(explicit: SlhDsaSecurityLevel, config: &CoreConfig) {
    let expected = expected_slh_dsa_level(config.security_level);
    if expected != explicit {
        warn!(
            "Explicit SlhDsaSecurityLevel ({:?}) differs from CoreConfig security_level ({:?} \
             → {:?}). Using explicit parameter.",
            explicit, config.security_level, expected
        );
    }
}

// ============================================================================
// Internal Implementation - ML-DSA
// ============================================================================

/// Internal implementation of ML-DSA signing.
fn sign_pq_ml_dsa_internal(
    message: &[u8],
    ml_dsa_sk: &[u8],
    parameter_set: MlDsaParameterSet,
) -> Result<Vec<u8>> {
    log_crypto_operation_start!(op::ML_DSA_SIGN, algorithm = ?parameter_set, message_len = message.len());

    // opaque ResourceExceeded — never expose
    // the configured `max_signature_size_bytes` cap via Display.
    if let Err(e) = validate_signature_size(message.len()) {
        log_crypto_operation_error!(op::ML_DSA_SIGN, e);
        return Err(CoreError::ResourceExceeded("message exceeds resource limit".to_string()));
    }

    let sk = MlDsaSecretKey::new(parameter_set, ml_dsa_sk.to_vec()).map_err(|e| {
        log_crypto_operation_error!(op::ML_DSA_SIGN, e);
        CoreError::InvalidInput("Invalid ML-DSA private key format".to_string())
    })?;

    let signature = sk.sign(message, &[]).map_err(|e| {
        log_crypto_operation_error!(op::ML_DSA_SIGN, e);
        CoreError::SignatureFailed(format!("ML-DSA signing failed: {}", e))
    })?;

    let sig_bytes = signature.as_bytes().to_vec();
    log_crypto_operation_complete!(op::ML_DSA_SIGN, algorithm = ?parameter_set, signature_len = sig_bytes.len());
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
    log_crypto_operation_start!(op::ML_DSA_VERIFY, algorithm = ?parameter_set, message_len = message.len());

    // collapse "message exceeds
    // resource limit" to `Ok(false)` on the verify path so an adversary
    // cannot binary-search the configured cap from the Result variant.
    // The earlier H7 fix made this `CoreError::ResourceExceeded`, which
    // was still distinguishable from `Ok(false)` / `VerificationFailed`
    // — re-opening the M1 oracle at the convenience layer. Sign-side
    // resource-limit errors stay loud (caller controls input).
    if let Err(e) = validate_signature_size(message.len()) {
        log_crypto_operation_error!(op::ML_DSA_VERIFY, e);
        return Ok(false);
    }

    let pk = MlDsaPublicKey::new(parameter_set, ml_dsa_pk.to_vec()).map_err(|e| {
        log_crypto_operation_error!(op::ML_DSA_VERIFY, e);
        CoreError::InvalidInput("Invalid ML-DSA public key format".to_string())
    })?;

    let sig = MlDsaSignature::new(parameter_set, signature.to_vec()).map_err(|e| {
        log_crypto_operation_error!(op::ML_DSA_VERIFY, e);
        CoreError::InvalidInput(format!("Invalid ML-DSA signature: {}", e))
    })?;

    let result = map_verify_result(pk.verify(message, &sig, &[]), "ML-DSA");

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!(op::ML_DSA_VERIFY, algorithm = ?parameter_set, valid = *valid);
            debug!(algorithm = ?parameter_set, valid = *valid, "ML-DSA verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!(op::ML_DSA_VERIFY, e);
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
    log_crypto_operation_start!(op::SLH_DSA_SIGN, algorithm = ?security_level, message_len = message.len());

    if let Err(e) = validate_signature_size(message.len()) {
        log_crypto_operation_error!(op::SLH_DSA_SIGN, e);
        return Err(CoreError::ResourceExceeded("message exceeds resource limit".to_string()));
    }

    let sk = SlhDsaSigningKey::from_bytes(slh_dsa_sk, security_level).map_err(|e| {
        log_crypto_operation_error!(op::SLH_DSA_SIGN, e);
        CoreError::InvalidInput("Invalid SLH-DSA private key format".to_string())
    })?;

    // use empty context to match every other
    // signature path in this crate (ML-DSA convenience and dispatcher,
    // hybrid SLH-DSA) and the FIPS 205 §10.2 default. The previous
    // `b"context"` magic string produced signatures that were not
    // verifiable by any third party following FIPS 205 default
    // semantics, and not interoperable with this crate's other paths.
    // BREAKING CHANGE: signatures produced by 0.7.x convenience
    // SLH-DSA sign cannot be verified by 0.8.x convenience verify and
    // vice versa. See CHANGELOG.
    let signature = sk.sign(message, &[]).map_err(|e| {
        log_crypto_operation_error!(op::SLH_DSA_SIGN, e);
        CoreError::SignatureFailed(format!("SLH-DSA signing failed: {}", e))
    })?;

    log_crypto_operation_complete!(op::SLH_DSA_SIGN, algorithm = ?security_level, signature_len = signature.len());
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
    log_crypto_operation_start!(op::SLH_DSA_VERIFY, algorithm = ?security_level, message_len = message.len());

    // see ML-DSA verify above for rationale.
    if let Err(e) = validate_signature_size(message.len()) {
        log_crypto_operation_error!(op::SLH_DSA_VERIFY, e);
        return Ok(false);
    }

    let pk = SlhDsaVerifyingKey::from_bytes(slh_dsa_pk, security_level).map_err(|e| {
        log_crypto_operation_error!(op::SLH_DSA_VERIFY, e);
        CoreError::InvalidInput("Invalid SLH-DSA public key format".to_string())
    })?;

    // empty context matches FIPS 205 §10.2
    // default, hybrid SLH-DSA, and ML-DSA convenience path.
    let result = map_verify_result(pk.verify(message, signature, &[]), "SLH-DSA");

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!(op::SLH_DSA_VERIFY, algorithm = ?security_level, valid = *valid);
            debug!(algorithm = ?security_level, valid = *valid, "SLH-DSA verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!(op::SLH_DSA_VERIFY, e);
        }
    }

    result
}

// ============================================================================
// Internal Implementation - FN-DSA
// ============================================================================

/// Internal implementation of FN-DSA signing.
fn sign_pq_fn_dsa_internal(
    message: &[u8],
    fn_dsa_sk: &[u8],
    security_level: FnDsaSecurityLevel,
) -> Result<Vec<u8>> {
    log_crypto_operation_start!(
        op::FN_DSA_SIGN,
        algorithm = "FN-DSA",
        security_level = ?security_level,
        message_len = message.len()
    );

    if let Err(e) = validate_signature_size(message.len()) {
        log_crypto_operation_error!(op::FN_DSA_SIGN, e);
        return Err(CoreError::ResourceExceeded("message exceeds resource limit".to_string()));
    }

    let mut sk = FnDsaSigningKey::from_bytes(fn_dsa_sk, security_level).map_err(|e| {
        log_crypto_operation_error!(op::FN_DSA_SIGN, e);
        CoreError::InvalidInput("Invalid FN-DSA private key format".to_string())
    })?;

    let signature = sk.sign(message).map_err(|e| {
        log_crypto_operation_error!(op::FN_DSA_SIGN, e);
        CoreError::SignatureFailed(format!("FN-DSA signing failed: {}", e))
    })?;

    let sig_bytes = signature.to_bytes();
    log_crypto_operation_complete!(
        op::FN_DSA_SIGN,
        algorithm = "FN-DSA",
        signature_len = sig_bytes.len()
    );
    debug!(algorithm = "FN-DSA", "Created FN-DSA signature");

    Ok(sig_bytes)
}

/// Internal implementation of FN-DSA verification.
fn verify_pq_fn_dsa_internal(
    message: &[u8],
    signature: &[u8],
    fn_dsa_pk: &[u8],
    security_level: FnDsaSecurityLevel,
) -> Result<bool> {
    log_crypto_operation_start!(
        op::FN_DSA_VERIFY,
        algorithm = "FN-DSA",
        security_level = ?security_level,
        message_len = message.len()
    );

    // see ML-DSA verify above for rationale.
    if let Err(e) = validate_signature_size(message.len()) {
        log_crypto_operation_error!(op::FN_DSA_VERIFY, e);
        return Ok(false);
    }

    let pk = FnDsaVerifyingKey::from_bytes(fn_dsa_pk, security_level).map_err(|e| {
        log_crypto_operation_error!(op::FN_DSA_VERIFY, e);
        CoreError::InvalidInput("Invalid FN-DSA public key format".to_string())
    })?;

    let sig = FnDsaSignature::from_bytes(signature).map_err(|e| {
        log_crypto_operation_error!(op::FN_DSA_VERIFY, e);
        CoreError::InvalidInput(format!("Invalid FN-DSA signature: {}", e))
    })?;

    let result = map_verify_result(pk.verify(message, &sig), "FN-DSA");

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!(op::FN_DSA_VERIFY, algorithm = "FN-DSA", valid = *valid);
            debug!(algorithm = "FN-DSA", valid = *valid, "FN-DSA verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!(op::FN_DSA_VERIFY, e);
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
pub fn sign_pq_fn_dsa(
    message: &[u8],
    private_key: &[u8],
    security_level: FnDsaSecurityLevel,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    sign_pq_fn_dsa_internal(message, private_key, security_level)
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
    security_level: FnDsaSecurityLevel,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    verify_pq_fn_dsa_internal(message, signature, public_key, security_level)
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
    check_ml_dsa_config_consistency(params, config);
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
    check_ml_dsa_config_consistency(params, config);
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
    check_slh_dsa_config_consistency(security_level, config);
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
    check_slh_dsa_config_consistency(security_level, config);
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
    security_level: FnDsaSecurityLevel,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<Vec<u8>> {
    mode.validate()?;
    config.validate()?;
    sign_pq_fn_dsa_internal(message, private_key, security_level)
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
    security_level: FnDsaSecurityLevel,
    config: &CoreConfig,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;
    config.validate()?;
    verify_pq_fn_dsa_internal(message, signature, public_key, security_level)
}

// ============================================================================
// Unverified API — ML-DSA / SLH-DSA / FN-DSA (Opt-Out)
// ============================================================================
// See `convenience::mod` docs for the shared security guidance on when to use
// `_unverified` variants.

// ----------------------------------------------------------------------------
// ML-DSA
// ----------------------------------------------------------------------------

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
pub fn sign_pq_fn_dsa_unverified(
    message: &[u8],
    fn_dsa_sk: &[u8],
    security_level: FnDsaSecurityLevel,
) -> Result<Vec<u8>> {
    sign_pq_fn_dsa(message, fn_dsa_sk, security_level, SecurityMode::Unverified)
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
    security_level: FnDsaSecurityLevel,
) -> Result<bool> {
    verify_pq_fn_dsa(message, signature, fn_dsa_pk, security_level, SecurityMode::Unverified)
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
    security_level: FnDsaSecurityLevel,
    config: &CoreConfig,
) -> Result<Vec<u8>> {
    sign_pq_fn_dsa_with_config(message, fn_dsa_sk, security_level, config, SecurityMode::Unverified)
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
    security_level: FnDsaSecurityLevel,
    config: &CoreConfig,
) -> Result<bool> {
    verify_pq_fn_dsa_with_config(
        message,
        signature,
        fn_dsa_pk,
        security_level,
        config,
        SecurityMode::Unverified,
    )
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "Test code uses .expect() for keygen-failed assertions, direct indexing for fixed-size signature/key buffers, and assert! macros (which expand to panic) inside Result-returning test functions. Any lint here that no longer triggers will fail #[expect] and be cleaned automatically."
)]
mod tests {
    use super::*;
    use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
    use crate::primitives::sig::slh_dsa::SlhDsaSecurityLevel;
    use crate::unified_api::convenience::keygen::{
        generate_fn_dsa_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair,
    };
    use crate::{SecurityMode, VerifiedSession, generate_keypair};

    // ML-DSA tests (unverified API)
    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_44_succeeds() -> Result<()> {
        let message = b"Test message for ML-DSA-44";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa44)?;
        assert!(!signature.is_empty());

        let is_valid = verify_pq_ml_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa44,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_65_succeeds() -> Result<()> {
        let message = b"Test message for ML-DSA-65";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa65)?;
        let is_valid = verify_pq_ml_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_87_succeeds() -> Result<()> {
        let message = b"Test message for ML-DSA-87";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa87)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa87)?;
        let is_valid = verify_pq_ml_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa87,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_verify_invalid_signature_fails() {
        let message = b"Test message";
        let (pk, _sk) =
            generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("keygen should succeed");
        let invalid_signature = vec![0u8; 100];

        let result = verify_pq_ml_dsa_unverified(
            message,
            &invalid_signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
        );
        assert!(result.is_err(), "Verification should fail for invalid signature");
    }

    #[test]
    fn test_ml_dsa_verify_wrong_message_fails() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) =
            generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("keygen should succeed");

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa65)
                .expect("signing should succeed");
        let result = verify_pq_ml_dsa_unverified(
            wrong_message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
        );
        // verify path collapses Err to Ok(false) for
        // adversary-reachable input (Pattern 6).
        assert_eq!(result.ok(), Some(false), "verify must return Ok(false) for wrong message");
    }

    // ML-DSA with config tests
    #[test]
    fn test_sign_verify_pq_ml_dsa_with_config_unverified_succeeds() -> Result<()> {
        let message = b"Test with config";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;
        let config = CoreConfig::default();

        let signature = sign_pq_ml_dsa_with_config_unverified(
            message,
            sk.expose_secret(),
            MlDsaParameterSet::MlDsa65,
            &config,
        )?;
        let is_valid = verify_pq_ml_dsa_with_config_unverified(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
            &config,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // ML-DSA verified API tests
    #[test]
    fn test_sign_verify_pq_ml_dsa_verified_succeeds() -> Result<()> {
        let message = b"Test with verified session";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature = sign_pq_ml_dsa(
            message,
            sk.expose_secret(),
            MlDsaParameterSet::MlDsa65,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_ml_dsa(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_ml_dsa_unverified_mode_succeeds() -> Result<()> {
        let message = b"Test unverified mode";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;

        let signature = sign_pq_ml_dsa(
            message,
            sk.expose_secret(),
            MlDsaParameterSet::MlDsa65,
            SecurityMode::Unverified,
        )?;
        let is_valid = verify_pq_ml_dsa(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
            SecurityMode::Unverified,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // SLH-DSA tests
    #[test]
    fn test_sign_verify_pq_slh_dsa_unverified_128s_succeeds() -> Result<()> {
        let message = b"Test SLH-DSA-128s";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

        let signature = sign_pq_slh_dsa_unverified(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake128s,
        )?;
        let is_valid = verify_pq_slh_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_pq_slh_dsa_unverified_128f_succeeds() -> Result<()> {
        let message = b"Test SLH-DSA-128f";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;

        let signature = sign_pq_slh_dsa_unverified(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake192s,
        )?;
        let is_valid = verify_pq_slh_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake192s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_verify_wrong_message_fails() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)
            .expect("keygen should succeed");

        let signature =
            sign_pq_slh_dsa_unverified(message, sk.expose_secret(), SlhDsaSecurityLevel::Shake128s)
                .expect("signing should succeed");
        let result = verify_pq_slh_dsa_unverified(
            wrong_message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
        );
        // verify path collapses Err to Ok(false).
        assert_eq!(result.ok(), Some(false), "verify must return Ok(false) for wrong message");
    }

    // SLH-DSA with config tests
    #[test]
    fn test_sign_verify_pq_slh_dsa_with_config_unverified_succeeds() -> Result<()> {
        let message = b"Test SLH-DSA with config";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let config = CoreConfig::default();

        let signature = sign_pq_slh_dsa_with_config_unverified(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake128s,
            &config,
        )?;
        let is_valid = verify_pq_slh_dsa_with_config_unverified(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
            &config,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // SLH-DSA verified API tests
    #[test]
    fn test_sign_verify_pq_slh_dsa_verified_succeeds() -> Result<()> {
        let message = b"Test SLH-DSA verified";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature = sign_pq_slh_dsa(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake128s,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_slh_dsa(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    // FN-DSA tests
    #[test]
    // FN-DSA: must run in release mode (stack overflow in debug)
    fn test_sign_verify_pq_fn_dsa_unverified_succeeds() -> Result<()> {
        let message = b"Test FN-DSA";
        let (pk, sk) = generate_fn_dsa_keypair()?;

        let signature =
            sign_pq_fn_dsa_unverified(message, sk.expose_secret(), FnDsaSecurityLevel::Level512)?;
        let is_valid = verify_pq_fn_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    // FN-DSA: must run in release mode (stack overflow in debug)
    fn test_fn_dsa_verify_wrong_message_fails() -> Result<()> {
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) = generate_fn_dsa_keypair()?;

        let signature =
            sign_pq_fn_dsa_unverified(message, sk.expose_secret(), FnDsaSecurityLevel::Level512)?;
        // verify path collapses Err to Ok(false) (Pattern 6).
        // The earlier comment said "FN-DSA returns Err" — that
        // was the leaky behaviour the H6 sweep closed.
        let result = verify_pq_fn_dsa_unverified(
            wrong_message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
        );
        assert_eq!(
            result.ok(),
            Some(false),
            "FN-DSA verify must return Ok(false) for wrong message"
        );
        Ok(())
    }

    // FN-DSA with config tests
    #[test]
    // FN-DSA: must run in release mode (stack overflow in debug)
    fn test_sign_verify_pq_fn_dsa_with_config_unverified_succeeds() -> Result<()> {
        let message = b"Test FN-DSA with config";
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let config = CoreConfig::default();

        let signature = sign_pq_fn_dsa_with_config_unverified(
            message,
            sk.expose_secret(),
            FnDsaSecurityLevel::Level512,
            &config,
        )?;
        let is_valid = verify_pq_fn_dsa_with_config_unverified(
            message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
            &config,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // FN-DSA verified API tests
    #[test]
    // FN-DSA: must run in release mode (stack overflow in debug)
    fn test_sign_verify_pq_fn_dsa_verified_succeeds() -> Result<()> {
        let message = b"Test FN-DSA verified";
        let (pk, sk) = generate_fn_dsa_keypair()?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature = sign_pq_fn_dsa(
            message,
            sk.expose_secret(),
            FnDsaSecurityLevel::Level512,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_fn_dsa(
            message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    // Edge case tests
    #[test]
    fn test_ml_dsa_empty_message_roundtrip_succeeds() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;

        let signature =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa65)?;
        let is_valid = verify_pq_ml_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_large_message_roundtrip_succeeds() -> Result<()> {
        let message = vec![0xAB; 10000];
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;

        let signature =
            sign_pq_ml_dsa_unverified(&message, sk.expose_secret(), MlDsaParameterSet::MlDsa65)?;
        let is_valid = verify_pq_ml_dsa_unverified(
            &message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_signature_is_deterministic() -> Result<()> {
        let message = b"Same message";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;

        let sig1 =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa65)?;
        let sig2 =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa65)?;

        // ML-DSA signatures may be non-deterministic due to randomness
        // Just verify both are valid
        let valid1 =
            verify_pq_ml_dsa_unverified(message, &sig1, pk.as_slice(), MlDsaParameterSet::MlDsa65)?;
        let valid2 =
            verify_pq_ml_dsa_unverified(message, &sig2, pk.as_slice(), MlDsaParameterSet::MlDsa65)?;
        assert!(valid1 && valid2);
        Ok(())
    }

    // Integration tests
    #[test]
    fn test_all_ml_dsa_security_levels_succeed_succeeds() -> Result<()> {
        let message = b"Test all levels";
        let levels = vec![
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ];

        for level in levels {
            let (pk, sk) = generate_ml_dsa_keypair(level)?;
            let signature = sign_pq_ml_dsa_unverified(message, sk.expose_secret(), level)?;
            let is_valid = verify_pq_ml_dsa_unverified(message, &signature, pk.as_slice(), level)?;
            assert!(is_valid, "Verification failed for {:?}", level);
        }
        Ok(())
    }

    #[test]
    fn test_all_slh_dsa_security_levels_succeed_succeeds() -> Result<()> {
        let message = b"Test all SLH-DSA levels";
        let levels = vec![SlhDsaSecurityLevel::Shake128s, SlhDsaSecurityLevel::Shake192s];

        for level in levels {
            let (pk, sk) = generate_slh_dsa_keypair(level)?;
            let signature = sign_pq_slh_dsa_unverified(message, sk.expose_secret(), level)?;
            let is_valid = verify_pq_slh_dsa_unverified(message, &signature, pk.as_slice(), level)?;
            assert!(is_valid, "Verification failed for {:?}", level);
        }
        Ok(())
    }

    // Additional tests for 90%+ coverage target

    #[test]
    fn test_slh_dsa_shake256s_succeeds() -> Result<()> {
        let message = b"Test SLH-DSA Shake256s";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;
        let signature = sign_pq_slh_dsa_unverified(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake256s,
        )?;
        let is_valid = verify_pq_slh_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake256s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_empty_message_roundtrip_succeeds() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let signature = sign_pq_slh_dsa_unverified(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake128s,
        )?;
        let is_valid = verify_pq_slh_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_large_message_roundtrip_succeeds() -> Result<()> {
        let message = vec![0xCD; 10_000];
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;
        let signature = sign_pq_slh_dsa_unverified(
            &message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake192s,
        )?;
        let is_valid = verify_pq_slh_dsa_unverified(
            &message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake192s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_slh_dsa_binary_data_roundtrip_succeeds() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let signature = sign_pq_slh_dsa_unverified(
            &message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake128s,
        )?;
        let is_valid = verify_pq_slh_dsa_unverified(
            &message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    // FN-DSA: must run in release mode (stack overflow in debug)
    fn test_fn_dsa_empty_message_roundtrip_succeeds() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let signature =
            sign_pq_fn_dsa_unverified(message, sk.expose_secret(), FnDsaSecurityLevel::Level512)?;
        let is_valid = verify_pq_fn_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    // FN-DSA: must run in release mode (stack overflow in debug)
    fn test_fn_dsa_large_message_roundtrip_succeeds() -> Result<()> {
        let message = vec![0xEF; 10_000];
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let signature =
            sign_pq_fn_dsa_unverified(&message, sk.expose_secret(), FnDsaSecurityLevel::Level512)?;
        let is_valid = verify_pq_fn_dsa_unverified(
            &message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_cross_keypair_fails() {
        let message = b"Test message";
        let (_pk1, sk1) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair 1");
        let (pk2, _sk2) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair 2");

        let signature =
            sign_pq_ml_dsa_unverified(message, sk1.expose_secret(), MlDsaParameterSet::MlDsa44)
                .expect("signing");

        let result = verify_pq_ml_dsa_unverified(
            message,
            &signature,
            pk2.as_slice(),
            MlDsaParameterSet::MlDsa44,
        );
        // verify path collapses Err to Ok(false) (Pattern 6).
        assert_eq!(result.ok(), Some(false), "verify must return Ok(false)");
    }

    #[test]
    fn test_slh_dsa_cross_keypair_fails() {
        let message = b"Test message";
        let (_pk1, sk1) =
            generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair 1");
        let (pk2, _sk2) =
            generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair 2");

        let signature = sign_pq_slh_dsa_unverified(
            message,
            sk1.expose_secret(),
            SlhDsaSecurityLevel::Shake128s,
        )
        .expect("signing");

        let result = verify_pq_slh_dsa_unverified(
            message,
            &signature,
            pk2.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
        );
        // verify path collapses Err to Ok(false) (Pattern 6).
        assert_eq!(result.ok(), Some(false), "verify must return Ok(false)");
    }

    #[test]
    fn test_ml_dsa_tampered_signature_fails() {
        let message = b"Original message";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair");

        let mut signature =
            sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa44)
                .expect("signing");

        if !signature.is_empty() {
            signature[0] ^= 0xFF;
        }

        let result = verify_pq_ml_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa44,
        );
        // verify path collapses Err to Ok(false) (Pattern 6).
        assert_eq!(result.ok(), Some(false), "verify must return Ok(false)");
    }

    #[test]
    fn test_slh_dsa_tampered_signature_fails() {
        let message = b"Original message";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair");

        let mut signature =
            sign_pq_slh_dsa_unverified(message, sk.expose_secret(), SlhDsaSecurityLevel::Shake128s)
                .expect("signing");

        if !signature.is_empty() {
            signature[0] ^= 0xFF;
        }

        let result = verify_pq_slh_dsa_unverified(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
        );
        // verify path collapses Err to Ok(false) (Pattern 6).
        assert_eq!(result.ok(), Some(false), "verify must return Ok(false)");
    }

    #[test]
    fn test_ml_dsa_binary_data_roundtrip_succeeds() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44)?;
        let signature =
            sign_pq_ml_dsa_unverified(&message, sk.expose_secret(), MlDsaParameterSet::MlDsa44)?;
        let is_valid = verify_pq_ml_dsa_unverified(
            &message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa44,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    // FN-DSA: must run in release mode (stack overflow in debug)
    fn test_fn_dsa_binary_data_roundtrip_succeeds() -> Result<()> {
        let message = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let signature =
            sign_pq_fn_dsa_unverified(&message, sk.expose_secret(), FnDsaSecurityLevel::Level512)?;
        let is_valid = verify_pq_fn_dsa_unverified(
            &message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ml_dsa_multiple_messages_succeed_succeeds() -> Result<()> {
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;
        let messages = vec![b"First".as_ref(), b"Second".as_ref(), b"Third".as_ref()];

        for message in messages {
            let signature =
                sign_pq_ml_dsa_unverified(message, sk.expose_secret(), MlDsaParameterSet::MlDsa65)?;
            let is_valid = verify_pq_ml_dsa_unverified(
                message,
                &signature,
                pk.as_slice(),
                MlDsaParameterSet::MlDsa65,
            )?;
            assert!(is_valid);
        }
        Ok(())
    }

    #[test]
    fn test_slh_dsa_multiple_messages_succeed_succeeds() -> Result<()> {
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;
        let messages = vec![b"First".as_ref(), b"Second".as_ref(), b"Third".as_ref()];

        for message in messages {
            let signature = sign_pq_slh_dsa_unverified(
                message,
                sk.expose_secret(),
                SlhDsaSecurityLevel::Shake192s,
            )?;
            let is_valid = verify_pq_slh_dsa_unverified(
                message,
                &signature,
                pk.as_slice(),
                SlhDsaSecurityLevel::Shake192s,
            )?;
            assert!(is_valid);
        }
        Ok(())
    }

    #[test]
    fn test_ml_dsa_with_config_all_params_succeeds() -> Result<()> {
        let message = b"Test with config";
        let config = CoreConfig::default();
        let params = vec![
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ];

        for param in params {
            let (pk, sk) = generate_ml_dsa_keypair(param)?;
            let signature =
                sign_pq_ml_dsa_with_config_unverified(message, sk.expose_secret(), param, &config)?;
            let is_valid = verify_pq_ml_dsa_with_config_unverified(
                message,
                &signature,
                pk.as_slice(),
                param,
                &config,
            )?;
            assert!(is_valid);
        }
        Ok(())
    }

    #[test]
    fn test_slh_dsa_256s_with_config_succeeds() -> Result<()> {
        let message = b"Test SLH-DSA-256s with config";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;
        let config = CoreConfig::default();

        let signature = sign_pq_slh_dsa_with_config_unverified(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake256s,
            &config,
        )?;
        let is_valid = verify_pq_slh_dsa_with_config_unverified(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake256s,
            &config,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // ========================================================================
    // SLH-DSA with_config + verified session tests
    // ========================================================================

    #[test]
    fn test_sign_verify_pq_slh_dsa_with_config_verified_succeeds() -> Result<()> {
        let message = b"SLH-DSA with config verified";
        let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
        let config = CoreConfig::default();

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature = sign_pq_slh_dsa_with_config(
            message,
            sk.expose_secret(),
            SlhDsaSecurityLevel::Shake128s,
            &config,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_slh_dsa_with_config(
            message,
            &signature,
            pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    // ========================================================================
    // FN-DSA with_config + verified session test
    // ========================================================================

    #[test]
    fn test_sign_verify_pq_fn_dsa_with_config_verified_succeeds() -> Result<()> {
        let message = b"FN-DSA with config verified";
        let (pk, sk) = generate_fn_dsa_keypair()?;
        let config = CoreConfig::default();

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature = sign_pq_fn_dsa_with_config(
            message,
            sk.expose_secret(),
            FnDsaSecurityLevel::Level512,
            &config,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_fn_dsa_with_config(
            message,
            &signature,
            pk.as_slice(),
            FnDsaSecurityLevel::Level512,
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    // ========================================================================
    // ML-DSA with_config + verified session
    // ========================================================================

    #[test]
    fn test_sign_verify_pq_ml_dsa_with_config_verified_succeeds() -> Result<()> {
        let message = b"ML-DSA with config verified";
        let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65)?;
        let config = CoreConfig::default();

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature = sign_pq_ml_dsa_with_config(
            message,
            sk.expose_secret(),
            MlDsaParameterSet::MlDsa65,
            &config,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_pq_ml_dsa_with_config(
            message,
            &signature,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa65,
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    // ========================================================================
    // Invalid key error paths
    // ========================================================================

    #[test]
    fn test_sign_pq_ml_dsa_invalid_sk_returns_error() {
        let bad_sk = vec![0u8; 10]; // Way too short
        let result = sign_pq_ml_dsa_unverified(b"msg", &bad_sk, MlDsaParameterSet::MlDsa44);
        assert!(result.is_err(), "Invalid ML-DSA secret key should fail");
    }

    #[test]
    fn test_verify_pq_ml_dsa_invalid_pk_returns_error() {
        let bad_pk = vec![0u8; 10];
        let bad_sig = vec![0u8; 100];
        let result = verify_pq_ml_dsa_unverified(
            b"msg",
            &bad_sig,
            bad_pk.as_slice(),
            MlDsaParameterSet::MlDsa44,
        );
        assert!(result.is_err(), "Invalid ML-DSA public key should fail");
    }

    #[test]
    fn test_verify_pq_ml_dsa_invalid_signature_returns_error() {
        let (pk, _sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keygen");
        let bad_sig = vec![0u8; 10]; // Way too short
        let result = verify_pq_ml_dsa_unverified(
            b"msg",
            &bad_sig,
            pk.as_slice(),
            MlDsaParameterSet::MlDsa44,
        );
        assert!(result.is_err(), "Invalid ML-DSA signature should fail");
    }

    #[test]
    fn test_sign_pq_slh_dsa_invalid_sk_returns_error() {
        let bad_sk = vec![0u8; 10];
        let result = sign_pq_slh_dsa_unverified(b"msg", &bad_sk, SlhDsaSecurityLevel::Shake128s);
        assert!(result.is_err(), "Invalid SLH-DSA secret key should fail");
    }

    #[test]
    fn test_verify_pq_slh_dsa_invalid_pk_returns_error() {
        let bad_pk = vec![0u8; 10];
        let bad_sig = vec![0u8; 100];
        let result = verify_pq_slh_dsa_unverified(
            b"msg",
            &bad_sig,
            bad_pk.as_slice(),
            SlhDsaSecurityLevel::Shake128s,
        );
        assert!(result.is_err(), "Invalid SLH-DSA public key should fail");
    }

    #[test]
    fn test_sign_pq_fn_dsa_invalid_sk_returns_error() {
        let bad_sk = vec![0u8; 10];
        let result = sign_pq_fn_dsa_unverified(b"msg", &bad_sk, FnDsaSecurityLevel::Level512);
        assert!(result.is_err(), "Invalid FN-DSA secret key should fail");
    }

    #[test]
    fn test_verify_pq_fn_dsa_invalid_pk_returns_error() {
        let bad_pk = vec![0u8; 10];
        let bad_sig = vec![0u8; 100];
        let result = verify_pq_fn_dsa_unverified(
            b"msg",
            &bad_sig,
            bad_pk.as_slice(),
            FnDsaSecurityLevel::Level512,
        );
        assert!(result.is_err(), "Invalid FN-DSA public key should fail");
    }
}
