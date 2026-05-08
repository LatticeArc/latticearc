//! Ed25519 signature operations
//!
//! This module provides Ed25519 digital signature operations.
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::unified_api::{sign_ed25519, verify_ed25519, SecurityMode, VerifiedSession};
//! # let data = b"example data";
//! # let private_key = [0u8; 32];
//! # let pk = [0u8; 32];
//! # let sk = [0u8; 32];
//! # let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // With Zero Trust verification (recommended)
//! let signature = sign_ed25519(data, &private_key, SecurityMode::Verified(&session))?;
//!
//! // Without verification (opt-out)
//! let signature = sign_ed25519(data, &private_key, SecurityMode::Unverified)?;
//! # Ok(())
//! # }
//! ```

use crate::{
    log_crypto_operation_complete, log_crypto_operation_error, log_crypto_operation_start,
};
use tracing::debug;

use crate::primitives::ec::ed25519::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SECRET_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519KeyPair,
    Ed25519Signature as Ed25519SignatureOps,
};
use crate::primitives::ec::traits::{EcKeyPair, EcSignature};
use crate::primitives::resource_limits::validate_signature_size;

use crate::unified_api::CoreConfig;
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::logging::op;
use crate::unified_api::zero_trust::SecurityMode;

// ============================================================================
// Internal Implementation
// ============================================================================

/// Internal implementation of Ed25519 signing.
pub(crate) fn sign_ed25519_internal(data: &[u8], ed25519_sk: &[u8]) -> Result<Vec<u8>> {
    log_crypto_operation_start!(op::ED25519_SIGN, algorithm = "Ed25519", data_len = data.len());

    // bound message length before
    // SHA-512 hashes the entire payload, opaquely.
    if let Err(e) = validate_signature_size(data.len()) {
        log_crypto_operation_error!(op::ED25519_SIGN, e);
        return Err(CoreError::ResourceExceeded("message exceeds resource limit".to_string()));
    }

    // reject non-canonical SK lengths at the
    // boundary. Previously we accepted any `len >= 32` and silently
    // truncated to the leading 32 bytes via `sk.get(..32)`. libsodium-
    // style 64-byte expanded SKs (seed || derived PK) were misinterpreted
    // — the trailing 32 bytes were silently discarded. The correct
    // contract is "Ed25519 SK is exactly 32 bytes (the RFC 8032 seed)".
    if ed25519_sk.len() != ED25519_SECRET_KEY_LEN {
        let err = CoreError::InvalidKeyLength {
            expected: ED25519_SECRET_KEY_LEN,
            actual: ed25519_sk.len(),
        };
        log_crypto_operation_error!(op::ED25519_SIGN, err);
        return Err(err);
    }

    // opaque error mapping — upstream parse
    // wording is version-volatile and would leak which exact validity
    // check failed.
    let keypair = Ed25519KeyPair::from_secret_key(ed25519_sk).map_err(|e| {
        log_crypto_operation_error!(op::ED25519_SIGN, e);
        CoreError::InvalidKey("invalid Ed25519 secret key".to_string())
    })?;

    let signature = keypair.sign(data).map_err(|e| {
        log_crypto_operation_error!(op::ED25519_SIGN, e);
        CoreError::ResourceExceeded("message exceeds resource limit".to_string())
    })?;
    let sig_bytes = Ed25519SignatureOps::signature_bytes(&signature);

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
    log_crypto_operation_start!(op::ED25519_VERIFY, algorithm = "Ed25519", data_len = data.len());

    // bound message length before SHA-512
    // hashes the payload (RFC 8032 §5.1.7).
    if let Err(e) = validate_signature_size(data.len()) {
        log_crypto_operation_error!(op::ED25519_VERIFY, e);
        return Err(CoreError::ResourceExceeded("message exceeds resource limit".to_string()));
    }

    // reject non-canonical signature/PK
    // lengths at the boundary. Previously we accepted any `len >=
    // expected` and silently truncated to the leading prefix, which let
    // relays append junk and still verify the signature — a
    // wire-format-canonicalization break. Sig length must be exactly 64
    // and PK length must be exactly 32 per RFC 8032.
    if signature_bytes.len() != ED25519_SIGNATURE_LEN {
        let err = CoreError::InvalidInput("invalid Ed25519 signature length".to_string());
        log_crypto_operation_error!(op::ED25519_VERIFY, err);
        return Err(err);
    }
    if ed25519_pk.len() != ED25519_PUBLIC_KEY_LEN {
        let err = CoreError::InvalidKeyLength {
            expected: ED25519_PUBLIC_KEY_LEN,
            actual: ed25519_pk.len(),
        };
        log_crypto_operation_error!(op::ED25519_VERIFY, err);
        return Err(err);
    }

    // Parse the signature via the primitives layer.
    let signature = Ed25519SignatureOps::signature_from_bytes(signature_bytes).map_err(|e| {
        log_crypto_operation_error!(op::ED25519_VERIFY, e);
        // opaque parse-failure mapping —
        // never relay upstream variant wording.
        CoreError::InvalidInput("invalid Ed25519 signature".to_string())
    })?;

    // collapse all adversary-reachable verify
    // errors (off-curve PK, tampered signature, MAC mismatch) to
    // `Ok(false)` so a probing attacker cannot distinguish reject
    // reasons from the Result shape. The underlying cause is logged
    // via tracing::debug for operators.
    let result = match Ed25519SignatureOps::verify(ed25519_pk, data, &signature) {
        Ok(()) => Ok(true),
        Err(e) => {
            tracing::debug!(error = %e, "Ed25519 verification rejected");
            Ok(false)
        }
    };

    match &result {
        Ok(valid) => {
            log_crypto_operation_complete!(
                op::ED25519_VERIFY,
                algorithm = "Ed25519",
                valid = valid
            );
            debug!(algorithm = "Ed25519", valid = valid, "Ed25519 verification completed");
        }
        Err(e) => {
            log_crypto_operation_error!(op::ED25519_VERIFY, e);
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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::unified_api::{sign_ed25519, SecurityMode, VerifiedSession, generate_keypair};
/// # let private_key = [0u8; 32];
///
/// let (pk, sk) = generate_keypair()?;
/// let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret())?;
///
/// // With Zero Trust verification (recommended)
/// let signature = sign_ed25519(b"message", &private_key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let signature = sign_ed25519(b"message", &private_key, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
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
// Unverified API (Opt-Out) — see `convenience::mod` docs for the shared
// security guidance on when to use `_unverified` variants.
// ============================================================================

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
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    reason = "test/bench scaffolding: lints suppressed for this module"
)]
mod tests {
    use super::*;
    use crate::{SecurityMode, VerifiedSession, generate_keypair};

    // Basic sign/verify tests (unverified API)
    #[test]
    fn test_sign_verify_ed25519_unverified_roundtrip_succeeds() -> Result<()> {
        let message = b"Test message for Ed25519";
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519_unverified(message, sk.expose_secret())?;
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");

        let is_valid = verify_ed25519_unverified(message, &signature, pk.as_slice())?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_ed25519_deterministic_produces_same_signature_is_deterministic() -> Result<()> {
        let message = b"Same message";
        let (_, sk) = generate_keypair()?;

        let sig1 = sign_ed25519_unverified(message, sk.expose_secret())?;
        let sig2 = sign_ed25519_unverified(message, sk.expose_secret())?;

        assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
        Ok(())
    }

    #[test]
    fn test_verify_ed25519_wrong_message_returns_false() {
        // adversary-reachable verify failures
        // now collapse to `Ok(false)` instead of `Err(VerificationFailed)`
        // so a probing attacker cannot distinguish reject reasons from
        // the Result shape. Test renamed to reflect the new contract.
        let message = b"Original message";
        let wrong_message = b"Wrong message";
        let (pk, sk) = generate_keypair().expect("keygen should succeed");

        let signature =
            sign_ed25519_unverified(message, sk.expose_secret()).expect("signing should succeed");
        let result = verify_ed25519_unverified(wrong_message, &signature, pk.as_slice());
        assert_eq!(result.ok(), Some(false), "Wrong message should yield Ok(false)");
    }

    #[test]
    fn test_verify_ed25519_invalid_signature_returns_false() {
        // an all-zero 64-byte buffer is a
        // valid Ed25519 signature *encoding* (no parse-time validity
        // check exists in RFC 8032), so it goes through the verify path
        // and is rejected with `Ok(false)`, not `Err`.
        let message = b"Test message";
        let (pk, _sk) = generate_keypair().expect("keygen should succeed");
        let invalid_signature = vec![0u8; 64];

        let result = verify_ed25519_unverified(message, &invalid_signature, pk.as_slice());
        assert_eq!(result.ok(), Some(false), "Invalid signature should yield Ok(false)");
    }

    #[test]
    fn test_verify_ed25519_wrong_public_key_returns_false() {
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let (wrong_pk, _) = generate_keypair().expect("keygen should succeed");

        let signature =
            sign_ed25519_unverified(message, sk.expose_secret()).expect("signing should succeed");
        let result = verify_ed25519_unverified(message, &signature, wrong_pk.as_slice());
        // wrong PK is adversary-reachable, so
        // it collapses to Ok(false).
        assert_eq!(result.ok(), Some(false), "Wrong public key should yield Ok(false)");
    }

    // With config tests
    #[test]
    fn test_sign_verify_ed25519_with_config_unverified_roundtrip() -> Result<()> {
        let message = b"Test with config";
        let (pk, sk) = generate_keypair()?;
        let config = CoreConfig::default();

        let signature = sign_ed25519_with_config_unverified(message, sk.expose_secret(), &config)?;
        let is_valid =
            verify_ed25519_with_config_unverified(message, &signature, pk.as_slice(), &config)?;
        assert!(is_valid);
        Ok(())
    }

    // Verified API tests (with SecurityMode)
    #[test]
    fn test_sign_verify_ed25519_verified_roundtrip_succeeds() -> Result<()> {
        let message = b"Test with verified session";
        let (pk, sk) = generate_keypair()?;

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature =
            sign_ed25519(message, sk.expose_secret(), SecurityMode::Verified(&session))?;
        let is_valid =
            verify_ed25519(message, &signature, pk.as_slice(), SecurityMode::Verified(&session))?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_ed25519_unverified_mode_roundtrip_succeeds() -> Result<()> {
        let message = b"Test unverified mode";
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519(message, sk.expose_secret(), SecurityMode::Unverified)?;
        let is_valid =
            verify_ed25519(message, &signature, pk.as_slice(), SecurityMode::Unverified)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_ed25519_with_config_verified_roundtrip() -> Result<()> {
        let message = b"Test with config and session";
        let (pk, sk) = generate_keypair()?;
        let config = CoreConfig::default();

        let (auth_pk, auth_sk) = generate_keypair()?;
        let session = VerifiedSession::establish(auth_pk.as_slice(), auth_sk.expose_secret())?;

        let signature = sign_ed25519_with_config(
            message,
            sk.expose_secret(),
            &config,
            SecurityMode::Verified(&session),
        )?;
        let is_valid = verify_ed25519_with_config(
            message,
            &signature,
            pk.as_slice(),
            &config,
            SecurityMode::Verified(&session),
        )?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_sign_verify_ed25519_with_config_unverified_mode_roundtrip() -> Result<()> {
        let message = b"Test with config unverified mode";
        let (pk, sk) = generate_keypair()?;
        let config = CoreConfig::default();

        let signature = sign_ed25519_with_config(
            message,
            sk.expose_secret(),
            &config,
            SecurityMode::Unverified,
        )?;
        let is_valid = verify_ed25519_with_config(
            message,
            &signature,
            pk.as_slice(),
            &config,
            SecurityMode::Unverified,
        )?;
        assert!(is_valid);
        Ok(())
    }

    // Edge cases
    #[test]
    fn test_ed25519_empty_message_signs_and_verifies_succeeds() -> Result<()> {
        let message = b"";
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519_unverified(message, sk.expose_secret())?;
        let is_valid = verify_ed25519_unverified(message, &signature, pk.as_slice())?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ed25519_large_message_signs_and_verifies_succeeds() -> Result<()> {
        // Ed25519 sign/verify now bound message
        // length via `validate_signature_size` (default 64 KiB). The
        // previous 100,000-byte fixture exceeded the cap; use 50 KiB so
        // the test still exercises a "large" message under the new
        // contract.
        let message = vec![0xAB; 50 * 1024];
        let (pk, sk) = generate_keypair()?;

        let signature = sign_ed25519_unverified(&message, sk.expose_secret())?;
        let is_valid = verify_ed25519_unverified(&message, &signature, pk.as_slice())?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_ed25519_signature_length_is_constant_64_bytes_has_correct_size() -> Result<()> {
        let (_, sk) = generate_keypair()?;
        let short_msg = b"short";
        let long_msg = vec![0xFF; 10000];

        let sig1 = sign_ed25519_unverified(short_msg, sk.expose_secret())?;
        let sig2 = sign_ed25519_unverified(&long_msg, sk.expose_secret())?;

        assert_eq!(sig1.len(), 64, "Signature length should be constant");
        assert_eq!(sig2.len(), 64, "Signature length should be constant");
        Ok(())
    }

    #[test]
    fn test_ed25519_different_messages_produce_different_signatures_succeeds() -> Result<()> {
        let (_, sk) = generate_keypair()?;
        let msg1 = b"First message";
        let msg2 = b"Second message";

        let sig1 = sign_ed25519_unverified(msg1, sk.expose_secret())?;
        let sig2 = sign_ed25519_unverified(msg2, sk.expose_secret())?;

        assert_ne!(sig1, sig2, "Different messages should produce different signatures");
        Ok(())
    }

    #[test]
    fn test_ed25519_different_keys_produce_different_signatures_succeeds() -> Result<()> {
        let message = b"Same message";
        let (_, sk1) = generate_keypair()?;
        let (_, sk2) = generate_keypair()?;

        let sig1 = sign_ed25519_unverified(message, sk1.expose_secret())?;
        let sig2 = sign_ed25519_unverified(message, sk2.expose_secret())?;

        assert_ne!(sig1, sig2, "Different keys should produce different signatures");
        Ok(())
    }

    // Invalid input tests
    #[test]
    fn test_ed25519_invalid_signature_length_returns_error() {
        let message = b"Test message";
        let (pk, _sk) = generate_keypair().expect("keygen should succeed");
        let invalid_sig = vec![0u8; 32]; // Wrong length

        let result = verify_ed25519_unverified(message, &invalid_sig, pk.as_slice());
        assert!(result.is_err(), "Should reject signature with wrong length");
    }

    #[test]
    fn test_ed25519_invalid_public_key_length_returns_error() {
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let invalid_pk = vec![0u8; 16]; // Wrong length

        let signature =
            sign_ed25519_unverified(message, sk.expose_secret()).expect("signing should succeed");
        let result = verify_ed25519_unverified(message, &signature, &invalid_pk);
        assert!(result.is_err(), "Should reject public key with wrong length");
    }

    #[test]
    fn test_ed25519_invalid_secret_key_length_returns_error() {
        let message = b"Test message";
        let invalid_sk = vec![0u8; 16]; // Wrong length

        let result = sign_ed25519_unverified(message, &invalid_sk);
        assert!(result.is_err(), "Should reject secret key with wrong length");
    }

    // === Additional error branch tests ===

    #[test]
    fn test_ed25519_empty_key_returns_error() {
        let message = b"Test message";
        let result = sign_ed25519_unverified(message, &[]);
        assert!(result.is_err(), "Empty secret key should fail");
    }

    #[test]
    fn test_ed25519_verify_empty_signature_returns_error() {
        let message = b"Test message";
        let (pk, _sk) = generate_keypair().expect("keygen should succeed");

        let result = verify_ed25519_unverified(message, &[], pk.as_slice());
        assert!(result.is_err(), "Empty signature should fail verification");
    }

    #[test]
    fn test_ed25519_verify_empty_public_key_returns_error() {
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let signature = sign_ed25519_unverified(message, sk.expose_secret()).unwrap();

        let result = verify_ed25519_unverified(message, &signature, &[]);
        assert!(result.is_err(), "Empty public key should fail");
    }

    #[test]
    fn test_ed25519_verify_invalid_public_key_format_returns_false() {
        // an off-curve PK (correct length, but
        // not a valid Ed25519 point) is adversary-reachable, so verify
        // collapses it to `Ok(false)` rather than `Err(InvalidKey)` —
        // otherwise the variant shape is itself a side-channel into
        // which check failed (off-curve vs malformed encoding vs MAC
        // mismatch).
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let signature = sign_ed25519_unverified(message, sk.expose_secret()).unwrap();

        // 32 bytes but not a valid Ed25519 point
        let bad_pk = vec![0xFF; 32];
        let result = verify_ed25519_unverified(message, &signature, bad_pk.as_slice());
        assert_eq!(result.ok(), Some(false), "Invalid Ed25519 point should yield Ok(false)");
    }

    #[test]
    fn test_ed25519_sign_with_config_validation_succeeds() {
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let config = CoreConfig::default();

        let result = sign_ed25519_with_config(
            message,
            sk.expose_secret(),
            &config,
            SecurityMode::Unverified,
        );
        assert!(result.is_ok(), "Signing with valid config should succeed");
    }

    #[test]
    fn test_ed25519_verify_with_config_validation_succeeds() {
        let message = b"Test message";
        let (pk, sk) = generate_keypair().expect("keygen should succeed");
        let config = CoreConfig::default();

        let signature = sign_ed25519_unverified(message, sk.expose_secret()).unwrap();
        let result = verify_ed25519_with_config(
            message,
            &signature,
            pk.as_slice(),
            &config,
            SecurityMode::Unverified,
        );
        assert!(result.is_ok());
    }

    // Unverified variant tests for coverage
    #[test]
    fn test_ed25519_sign_with_config_unverified_succeeds() {
        let message = b"Test message";
        let (_, sk) = generate_keypair().expect("keygen should succeed");
        let config = CoreConfig::default();

        let result = sign_ed25519_with_config_unverified(message, sk.expose_secret(), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_verify_with_config_unverified_succeeds() {
        let message = b"Test message";
        let (pk, sk) = generate_keypair().expect("keygen should succeed");
        let config = CoreConfig::default();

        let signature = sign_ed25519_unverified(message, sk.expose_secret()).unwrap();
        let result =
            verify_ed25519_with_config_unverified(message, &signature, pk.as_slice(), &config);
        assert!(result.is_ok());
    }
}
