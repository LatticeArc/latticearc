//! Hybrid signature convenience API (ML-DSA-65 + Ed25519)
//!
//! This module wraps [`arc_hybrid::sig_hybrid`] to provide a high-level hybrid
//! signature API with `SecurityMode` support. The underlying implementation uses
//! AND-composition: both ML-DSA and Ed25519 must verify for the signature to be valid.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use arc_core::{
//!     generate_hybrid_signing_keypair, sign_hybrid, verify_hybrid_signature,
//!     SecurityMode,
//! };
//!
//! let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;
//! let signature = sign_hybrid(b"message", &sk, SecurityMode::Unverified)?;
//! let valid = verify_hybrid_signature(b"message", &signature, &pk, SecurityMode::Unverified)?;
//! assert!(valid);
//! ```

use arc_hybrid::sig_hybrid::{
    self, HybridPublicKey, HybridSecretKey, HybridSignature, HybridSignatureError,
};

use crate::error::{CoreError, Result};
use crate::zero_trust::SecurityMode;

use arc_validation::resource_limits::validate_signature_size;

/// Generate a hybrid signing keypair (ML-DSA-65 + Ed25519).
///
/// Returns a public key (for verification) and a secret key (for signing).
/// The keypair combines post-quantum and classical algorithms so that
/// security holds if *either* algorithm remains secure.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (when `mode` is `Verified`)
/// - Key generation fails
pub fn generate_hybrid_signing_keypair(
    mode: SecurityMode,
) -> Result<(HybridPublicKey, HybridSecretKey)> {
    mode.validate()?;

    let mut rng = rand::rngs::OsRng;
    sig_hybrid::generate_keypair(&mut rng).map_err(|e| {
        CoreError::SignatureFailed(format!("Hybrid signing keypair generation failed: {}", e))
    })
}

/// Sign a message using hybrid signatures (ML-DSA-65 + Ed25519).
///
/// Both ML-DSA and Ed25519 signatures are generated. An attacker would need
/// to break *both* algorithms to forge a signature.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (when `mode` is `Verified`)
/// - Message size exceeds resource limits
/// - Signing fails (invalid key material or crypto error)
pub fn sign_hybrid(
    message: &[u8],
    sk: &HybridSecretKey,
    mode: SecurityMode,
) -> Result<HybridSignature> {
    mode.validate()?;

    validate_signature_size(message.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    sig_hybrid::sign(sk, message).map_err(hybrid_sig_error_to_core)
}

/// Verify a hybrid signature (ML-DSA-65 + Ed25519).
///
/// Both component signatures must verify for the result to be `Ok(true)`.
///
/// # Errors
///
/// Returns an error if:
/// - The session has expired (when `mode` is `Verified`)
/// - Message size exceeds resource limits
/// - Key or signature material is malformed
/// - Either component verification fails
pub fn verify_hybrid_signature(
    message: &[u8],
    signature: &HybridSignature,
    pk: &HybridPublicKey,
    mode: SecurityMode,
) -> Result<bool> {
    mode.validate()?;

    validate_signature_size(message.len())
        .map_err(|e| CoreError::ResourceExceeded(e.to_string()))?;

    sig_hybrid::verify(pk, message, signature).map_err(hybrid_sig_error_to_core)
}

/// Generate a hybrid signing keypair with configuration validation.
///
/// # Errors
///
/// Returns an error if config validation, session validation, or key generation fails.
#[inline]
pub fn generate_hybrid_signing_keypair_with_config(
    config: &crate::config::CoreConfig,
    mode: SecurityMode,
) -> Result<(HybridPublicKey, HybridSecretKey)> {
    config.validate()?;
    generate_hybrid_signing_keypair(mode)
}

/// Sign a message using hybrid signatures with configuration validation.
///
/// # Errors
///
/// Returns an error if config validation, session validation, or signing fails.
#[inline]
pub fn sign_hybrid_with_config(
    message: &[u8],
    sk: &HybridSecretKey,
    config: &crate::config::CoreConfig,
    mode: SecurityMode,
) -> Result<HybridSignature> {
    config.validate()?;
    sign_hybrid(message, sk, mode)
}

/// Verify a hybrid signature with configuration validation.
///
/// # Errors
///
/// Returns an error if config validation, session validation, or verification fails.
#[inline]
pub fn verify_hybrid_signature_with_config(
    message: &[u8],
    signature: &HybridSignature,
    pk: &HybridPublicKey,
    config: &crate::config::CoreConfig,
    mode: SecurityMode,
) -> Result<bool> {
    config.validate()?;
    verify_hybrid_signature(message, signature, pk, mode)
}

// ============================================================================
// Unverified Convenience Variants
// ============================================================================

/// Generate a hybrid signing keypair without Zero Trust verification.
///
/// # Errors
///
/// Returns an error if key generation fails.
#[inline]
pub fn generate_hybrid_signing_keypair_unverified() -> Result<(HybridPublicKey, HybridSecretKey)> {
    generate_hybrid_signing_keypair(SecurityMode::Unverified)
}

/// Sign a message using hybrid signatures without Zero Trust verification.
///
/// # Errors
///
/// Returns an error if signing fails.
#[inline]
pub fn sign_hybrid_unverified(message: &[u8], sk: &HybridSecretKey) -> Result<HybridSignature> {
    sign_hybrid(message, sk, SecurityMode::Unverified)
}

/// Verify a hybrid signature without Zero Trust verification.
///
/// # Errors
///
/// Returns an error if verification fails.
#[inline]
pub fn verify_hybrid_signature_unverified(
    message: &[u8],
    signature: &HybridSignature,
    pk: &HybridPublicKey,
) -> Result<bool> {
    verify_hybrid_signature(message, signature, pk, SecurityMode::Unverified)
}

/// Convert `HybridSignatureError` to `CoreError`.
fn hybrid_sig_error_to_core(e: HybridSignatureError) -> CoreError {
    match e {
        HybridSignatureError::MlDsaError(msg) => {
            CoreError::SignatureFailed(format!("Hybrid ML-DSA error: {}", msg))
        }
        HybridSignatureError::Ed25519Error(msg) => {
            CoreError::SignatureFailed(format!("Hybrid Ed25519 error: {}", msg))
        }
        HybridSignatureError::VerificationFailed(_msg) => CoreError::VerificationFailed,
        HybridSignatureError::InvalidKeyMaterial(msg) => {
            CoreError::InvalidKey(format!("Hybrid key material error: {}", msg))
        }
        HybridSignatureError::CryptoError(msg) => {
            CoreError::SignatureFailed(format!("Hybrid crypto error: {}", msg))
        }
    }
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

    #[test]
    fn test_hybrid_sig_roundtrip_unverified() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

        let message = b"Hello, hybrid signatures!";
        let signature = sign_hybrid_unverified(message, &sk)?;
        let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;

        assert!(valid, "Hybrid signature roundtrip should succeed");
        Ok(())
    }

    #[test]
    fn test_hybrid_sig_roundtrip_with_mode() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;

        let message = b"SecurityMode test";
        let signature = sign_hybrid(message, &sk, SecurityMode::Unverified)?;
        let valid = verify_hybrid_signature(message, &signature, &pk, SecurityMode::Unverified)?;

        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_hybrid_sig_with_config() -> Result<()> {
        let config = crate::config::CoreConfig::default();
        let (pk, sk) =
            generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified)?;

        let message = b"Config test";
        let signature = sign_hybrid_with_config(message, &sk, &config, SecurityMode::Unverified)?;
        let valid = verify_hybrid_signature_with_config(
            message,
            &signature,
            &pk,
            &config,
            SecurityMode::Unverified,
        )?;

        assert!(valid);
        Ok(())
    }

    #[test]
    fn test_hybrid_sig_wrong_message() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

        let signature = sign_hybrid_unverified(b"correct message", &sk)?;
        let result = verify_hybrid_signature_unverified(b"wrong message", &signature, &pk);

        assert!(result.is_err(), "Wrong message should fail verification");
        Ok(())
    }

    #[test]
    fn test_hybrid_sig_wrong_key() -> Result<()> {
        let (_pk1, sk1) = generate_hybrid_signing_keypair_unverified()?;
        let (pk2, _sk2) = generate_hybrid_signing_keypair_unverified()?;

        let message = b"cross-key test";
        let signature = sign_hybrid_unverified(message, &sk1)?;
        let result = verify_hybrid_signature_unverified(message, &signature, &pk2);

        assert!(result.is_err(), "Wrong key should fail verification");
        Ok(())
    }

    #[test]
    fn test_hybrid_sig_empty_message() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

        let message = b"";
        let signature = sign_hybrid_unverified(message, &sk)?;
        let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;

        assert!(valid, "Empty message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_hybrid_sig_large_message() -> Result<()> {
        let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

        let message = vec![0xAB; 10_000];
        let signature = sign_hybrid_unverified(&message, &sk)?;
        let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;

        assert!(valid, "Large message should sign and verify");
        Ok(())
    }

    #[test]
    fn test_hybrid_sig_verified_session() -> Result<()> {
        let (auth_pk, auth_sk) = crate::convenience::keygen::generate_keypair()?;
        let session = crate::zero_trust::VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

        let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Verified(&session))?;

        let message = b"Verified session test";
        let signature = sign_hybrid(message, &sk, SecurityMode::Verified(&session))?;
        let valid =
            verify_hybrid_signature(message, &signature, &pk, SecurityMode::Verified(&session))?;

        assert!(valid);
        Ok(())
    }
}
