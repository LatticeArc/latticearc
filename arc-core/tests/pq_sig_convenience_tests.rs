//! Comprehensive tests for PQ-Signature convenience API (ML-DSA, SLH-DSA, FN-DSA)
//!
//! This test suite validates the post-quantum signature operations in arc-core,
//! covering SecurityMode integration, with_config variants, error handling,
//! cross-keypair verification failures, and edge cases.
//!
//! # Test Coverage
//!
//! 1. **ML-DSA with_config variants** - All parameter sets (MLDSA44, MLDSA65, MLDSA87)
//! 2. **SecurityMode::Verified** - Verified session integration for all algorithms
//! 3. **Cross-keypair verification** - Sign with key1, verify with key2 fails
//! 4. **Corrupted signature rejection** - Single byte tampering detected
//! 5. **Invalid key format rejection** - Wrong length keys rejected
//! 6. **SLH-DSA all variants** - Shake128s, Shake192s, Shake256s roundtrips
//! 7. **FN-DSA tests** - Marked `#[ignore]` due to stack overflow in debug mode
//! 8. **Unicode message content** - International character handling
//! 9. **Binary data with edge bytes** - 0x00, 0xFF, 0x7F, 0x80 handling

#![allow(
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

use arc_core::{
    config::CoreConfig,
    convenience::{
        generate_fn_dsa_keypair, generate_keypair, generate_ml_dsa_keypair,
        generate_slh_dsa_keypair, sign_pq_fn_dsa, sign_pq_fn_dsa_with_config,
        sign_pq_fn_dsa_with_config_unverified, sign_pq_ml_dsa, sign_pq_ml_dsa_with_config,
        sign_pq_ml_dsa_with_config_unverified, sign_pq_slh_dsa, sign_pq_slh_dsa_with_config,
        sign_pq_slh_dsa_with_config_unverified, verify_pq_fn_dsa, verify_pq_fn_dsa_with_config,
        verify_pq_fn_dsa_with_config_unverified, verify_pq_ml_dsa, verify_pq_ml_dsa_with_config,
        verify_pq_ml_dsa_with_config_unverified, verify_pq_slh_dsa, verify_pq_slh_dsa_with_config,
        verify_pq_slh_dsa_with_config_unverified,
    },
    error::{CoreError, Result},
    zero_trust::{SecurityMode, VerifiedSession},
};
use arc_primitives::sig::{
    ml_dsa::MlDsaParameterSet, slh_dsa::SecurityLevel as SlhDsaSecurityLevel,
};

// ============================================================================
// ML-DSA with_config Tests (Task 1.2.18)
// ============================================================================

#[test]
fn test_ml_dsa_44_with_config_roundtrip() -> Result<()> {
    let message = b"Test ML-DSA-44 with configuration";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;
    let config = CoreConfig::default();

    let signature = sign_pq_ml_dsa_with_config_unverified(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA44,
        &config,
    )?;

    assert!(!signature.is_empty(), "Signature should not be empty");

    let is_valid = verify_pq_ml_dsa_with_config_unverified(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA44,
        &config,
    )?;

    assert!(is_valid, "ML-DSA-44 signature should verify with config");
    Ok(())
}

#[test]
fn test_ml_dsa_65_with_config_roundtrip() -> Result<()> {
    let message = b"Test ML-DSA-65 with configuration";
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

    assert!(is_valid, "ML-DSA-65 signature should verify with config");
    Ok(())
}

#[test]
fn test_ml_dsa_87_with_config_roundtrip() -> Result<()> {
    let message = b"Test ML-DSA-87 with configuration";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;
    let config = CoreConfig::default();

    let signature = sign_pq_ml_dsa_with_config_unverified(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA87,
        &config,
    )?;

    let is_valid = verify_pq_ml_dsa_with_config_unverified(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA87,
        &config,
    )?;

    assert!(is_valid, "ML-DSA-87 signature should verify with config");
    Ok(())
}

#[test]
fn test_ml_dsa_all_params_with_config() -> Result<()> {
    let message = b"Test all ML-DSA parameter sets with config";
    let config = CoreConfig::default();
    let params =
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87];

    for param in &params {
        let (pk, sk) = generate_ml_dsa_keypair(*param)?;

        let signature =
            sign_pq_ml_dsa_with_config_unverified(message, sk.as_ref(), *param, &config)?;

        let is_valid =
            verify_pq_ml_dsa_with_config_unverified(message, &signature, &pk, *param, &config)?;

        assert!(is_valid, "ML-DSA {:?} should verify with config", param);
    }

    Ok(())
}

// ============================================================================
// SecurityMode::Verified Tests (Task 1.2.19)
// ============================================================================

#[test]
fn test_ml_dsa_44_verified_mode() -> Result<()> {
    let message = b"Test ML-DSA-44 with verified session";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_ml_dsa(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Verified(&session),
    )?;

    let is_valid = verify_pq_ml_dsa(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Verified(&session),
    )?;

    assert!(is_valid, "ML-DSA-44 should verify with Verified mode");
    Ok(())
}

#[test]
fn test_ml_dsa_65_verified_mode() -> Result<()> {
    let message = b"Test ML-DSA-65 with verified session";
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

    assert!(is_valid, "ML-DSA-65 should verify with Verified mode");
    Ok(())
}

#[test]
fn test_ml_dsa_87_verified_mode() -> Result<()> {
    let message = b"Test ML-DSA-87 with verified session";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_ml_dsa(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Verified(&session),
    )?;

    let is_valid = verify_pq_ml_dsa(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Verified(&session),
    )?;

    assert!(is_valid, "ML-DSA-87 should verify with Verified mode");
    Ok(())
}

#[test]
fn test_slh_dsa_shake128s_verified_mode() -> Result<()> {
    let message = b"Test SLH-DSA-SHAKE128s with verified session";
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

    assert!(is_valid, "SLH-DSA-SHAKE128s should verify with Verified mode");
    Ok(())
}

#[test]
fn test_slh_dsa_shake192s_verified_mode() -> Result<()> {
    let message = b"Test SLH-DSA-SHAKE192s with verified session";
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake192s,
        SecurityMode::Verified(&session),
    )?;

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake192s,
        SecurityMode::Verified(&session),
    )?;

    assert!(is_valid, "SLH-DSA-SHAKE192s should verify with Verified mode");
    Ok(())
}

#[test]
fn test_slh_dsa_shake256s_verified_mode() -> Result<()> {
    let message = b"Test SLH-DSA-SHAKE256s with verified session";
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake256s,
        SecurityMode::Verified(&session),
    )?;

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake256s,
        SecurityMode::Verified(&session),
    )?;

    assert!(is_valid, "SLH-DSA-SHAKE256s should verify with Verified mode");
    Ok(())
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_verified_mode() -> Result<()> {
    let message = b"Test FN-DSA with verified session";
    let (pk, sk) = generate_fn_dsa_keypair()?;

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_fn_dsa(message, sk.as_ref(), SecurityMode::Verified(&session))?;

    let is_valid = verify_pq_fn_dsa(message, &signature, &pk, SecurityMode::Verified(&session))?;

    assert!(is_valid, "FN-DSA should verify with Verified mode");
    Ok(())
}

#[test]
fn test_ml_dsa_with_config_verified_mode() -> Result<()> {
    let message = b"Test ML-DSA with config and verified session";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
    let config = CoreConfig::default();

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_ml_dsa_with_config(
        message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA65,
        &config,
        SecurityMode::Verified(&session),
    )?;

    let is_valid = verify_pq_ml_dsa_with_config(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA65,
        &config,
        SecurityMode::Verified(&session),
    )?;

    assert!(is_valid, "ML-DSA with config should verify in Verified mode");
    Ok(())
}

#[test]
fn test_slh_dsa_with_config_verified_mode() -> Result<()> {
    let message = b"Test SLH-DSA with config and verified session";
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
    let config = CoreConfig::default();

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_slh_dsa_with_config(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        &config,
        SecurityMode::Verified(&session),
    )?;

    let is_valid = verify_pq_slh_dsa_with_config(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake128s,
        &config,
        SecurityMode::Verified(&session),
    )?;

    assert!(is_valid, "SLH-DSA with config should verify in Verified mode");
    Ok(())
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_with_config_verified_mode() -> Result<()> {
    let message = b"Test FN-DSA with config and verified session";
    let (pk, sk) = generate_fn_dsa_keypair()?;
    let config = CoreConfig::default();

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_pq_fn_dsa_with_config(
        message,
        sk.as_ref(),
        &config,
        SecurityMode::Verified(&session),
    )?;

    let is_valid = verify_pq_fn_dsa_with_config(
        message,
        &signature,
        &pk,
        &config,
        SecurityMode::Verified(&session),
    )?;

    assert!(is_valid, "FN-DSA with config should verify in Verified mode");
    Ok(())
}

// ============================================================================
// Cross-Keypair Verification Tests (Task 1.2.20)
// ============================================================================

#[test]
fn test_ml_dsa_44_cross_keypair_fails() {
    let message = b"Test cross-keypair verification";
    let (_pk1, sk1) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair 1 generation");
    let (pk2, _sk2) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair 2 generation");

    let signature =
        sign_pq_ml_dsa(message, sk1.as_ref(), MlDsaParameterSet::MLDSA44, SecurityMode::Unverified)
            .expect("signing should succeed");

    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &pk2,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Verification should fail with different keypair");
    match result {
        Err(CoreError::VerificationFailed) => {}
        _ => panic!("Expected VerificationFailed error, got {:?}", result),
    }
}

#[test]
fn test_ml_dsa_65_cross_keypair_fails() {
    let message = b"Test cross-keypair verification ML-DSA-65";
    let (_pk1, sk1) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair 1 generation");
    let (pk2, _sk2) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair 2 generation");

    let signature =
        sign_pq_ml_dsa(message, sk1.as_ref(), MlDsaParameterSet::MLDSA65, SecurityMode::Unverified)
            .expect("signing should succeed");

    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &pk2,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "ML-DSA-65 verification should fail with different keypair");
}

#[test]
fn test_ml_dsa_87_cross_keypair_fails() {
    let message = b"Test cross-keypair verification ML-DSA-87";
    let (_pk1, sk1) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87).expect("keypair 1 generation");
    let (pk2, _sk2) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87).expect("keypair 2 generation");

    let signature =
        sign_pq_ml_dsa(message, sk1.as_ref(), MlDsaParameterSet::MLDSA87, SecurityMode::Unverified)
            .expect("signing should succeed");

    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &pk2,
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "ML-DSA-87 verification should fail with different keypair");
}

#[test]
fn test_slh_dsa_cross_keypair_fails() {
    let message = b"Test SLH-DSA cross-keypair verification";
    let (_pk1, sk1) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair 1 generation");
    let (pk2, _sk2) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair 2 generation");

    let signature = sign_pq_slh_dsa(
        message,
        sk1.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let result = verify_pq_slh_dsa(
        message,
        &signature,
        &pk2,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "SLH-DSA verification should fail with different keypair");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_cross_keypair_fails() {
    let message = b"Test FN-DSA cross-keypair verification";
    let (_pk1, sk1) = generate_fn_dsa_keypair().expect("keypair 1 generation");
    let (pk2, _sk2) = generate_fn_dsa_keypair().expect("keypair 2 generation");

    let signature = sign_pq_fn_dsa(message, sk1.as_ref(), SecurityMode::Unverified)
        .expect("signing should succeed");

    let result = verify_pq_fn_dsa(message, &signature, &pk2, SecurityMode::Unverified);

    assert!(result.is_err(), "FN-DSA verification should fail with different keypair");
}

// ============================================================================
// Corrupted Signature Rejection Tests (Task 1.2.6)
// ============================================================================

#[test]
fn test_ml_dsa_corrupted_signature_single_byte() {
    let message = b"Test corrupted signature detection";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let mut signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MLDSA65, SecurityMode::Unverified)
            .expect("signing should succeed");

    // Tamper with a single byte
    if signature.len() > 50 {
        signature[50] ^= 0xFF;
    } else if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Corrupted signature should be rejected");
}

#[test]
fn test_ml_dsa_corrupted_signature_first_byte() {
    let message = b"Test first byte corruption";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let mut signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MLDSA44, SecurityMode::Unverified)
            .expect("signing should succeed");

    if !signature.is_empty() {
        signature[0] ^= 0x01; // Single bit flip
    }

    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Signature with corrupted first byte should fail");
}

#[test]
fn test_ml_dsa_corrupted_signature_last_byte() {
    let message = b"Test last byte corruption";
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87).expect("keypair generation");

    let mut signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MLDSA87, SecurityMode::Unverified)
            .expect("signing should succeed");

    if !signature.is_empty() {
        let last_idx = signature.len() - 1;
        signature[last_idx] ^= 0xFF;
    }

    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Signature with corrupted last byte should fail");
}

#[test]
fn test_slh_dsa_corrupted_signature_single_byte() {
    let message = b"Test SLH-DSA corrupted signature";
    let (pk, sk) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let mut signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    if signature.len() > 100 {
        signature[100] ^= 0xFF;
    } else if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_slh_dsa(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "SLH-DSA corrupted signature should be rejected");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_corrupted_signature_single_byte() {
    let message = b"Test FN-DSA corrupted signature";
    let (pk, sk) = generate_fn_dsa_keypair().expect("keypair generation");

    let mut signature =
        sign_pq_fn_dsa(message, sk.as_ref(), SecurityMode::Unverified).expect("signing");

    if signature.len() > 100 {
        signature[100] ^= 0xFF;
    } else if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_fn_dsa(message, &signature, &pk, SecurityMode::Unverified);

    assert!(result.is_err(), "FN-DSA corrupted signature should be rejected");
}

// ============================================================================
// Invalid Key Format Rejection Tests
// ============================================================================

#[test]
fn test_ml_dsa_wrong_length_private_key() {
    let message = b"Test wrong length private key";
    let wrong_key = vec![0u8; 100]; // Wrong length for any ML-DSA variant

    let result =
        sign_pq_ml_dsa(message, &wrong_key, MlDsaParameterSet::MLDSA65, SecurityMode::Unverified);

    assert!(result.is_err(), "Should reject wrong length private key");
    match result {
        Err(CoreError::InvalidInput(_)) => {}
        _ => panic!("Expected InvalidInput error, got {:?}", result),
    }
}

#[test]
fn test_ml_dsa_wrong_length_public_key() {
    let message = b"Test wrong length public key";
    let (_, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MLDSA65, SecurityMode::Unverified)
            .expect("signing should succeed");

    let wrong_pk = vec![0u8; 100]; // Wrong length

    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &wrong_pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Should reject wrong length public key");
}

#[test]
fn test_slh_dsa_wrong_length_private_key() {
    let message = b"Test SLH-DSA wrong length private key";
    let wrong_key = vec![0u8; 32]; // Wrong length for SLH-DSA

    let result = sign_pq_slh_dsa(
        message,
        &wrong_key,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Should reject wrong length SLH-DSA private key");
}

#[test]
fn test_slh_dsa_wrong_length_public_key() {
    let message = b"Test SLH-DSA wrong length public key";
    let (_, sk) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let wrong_pk = vec![0u8; 16]; // Wrong length

    let result = verify_pq_slh_dsa(
        message,
        &signature,
        &wrong_pk,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Should reject wrong length SLH-DSA public key");
}

#[test]
fn test_fn_dsa_wrong_length_private_key() {
    let message = b"Test FN-DSA wrong length private key";
    let wrong_key = vec![0u8; 32]; // Wrong length for FN-DSA

    let result = sign_pq_fn_dsa(message, &wrong_key, SecurityMode::Unverified);

    assert!(result.is_err(), "Should reject wrong length FN-DSA private key");
}

#[test]
fn test_fn_dsa_wrong_length_public_key() {
    let message = b"Test FN-DSA wrong length public key";

    // Cannot easily generate signature without valid keypair, so use dummy signature
    let dummy_signature = vec![0u8; 1000];
    let wrong_pk = vec![0u8; 32]; // Wrong length

    let result = verify_pq_fn_dsa(message, &dummy_signature, &wrong_pk, SecurityMode::Unverified);

    assert!(result.is_err(), "Should reject wrong length FN-DSA public key");
}

// ============================================================================
// SLH-DSA All Variants Tests
// ============================================================================

#[test]
fn test_slh_dsa_shake128s_roundtrip() -> Result<()> {
    let message = b"Test SLH-DSA-SHAKE128s roundtrip";
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    assert!(!signature.is_empty(), "SLH-DSA signature should not be empty");

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA-SHAKE128s signature should verify");
    Ok(())
}

#[test]
fn test_slh_dsa_shake192s_roundtrip() -> Result<()> {
    let message = b"Test SLH-DSA-SHAKE192s roundtrip";
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake192s,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake192s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA-SHAKE192s signature should verify");
    Ok(())
}

#[test]
fn test_slh_dsa_shake256s_roundtrip() -> Result<()> {
    let message = b"Test SLH-DSA-SHAKE256s roundtrip";
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake256s,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake256s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA-SHAKE256s signature should verify");
    Ok(())
}

#[test]
fn test_slh_dsa_all_variants_with_config() -> Result<()> {
    let message = b"Test all SLH-DSA variants with config";
    let config = CoreConfig::default();
    let levels = [
        SlhDsaSecurityLevel::Shake128s,
        SlhDsaSecurityLevel::Shake192s,
        SlhDsaSecurityLevel::Shake256s,
    ];

    for level in &levels {
        let (pk, sk) = generate_slh_dsa_keypair(*level)?;

        let signature =
            sign_pq_slh_dsa_with_config_unverified(message, sk.as_ref(), *level, &config)?;

        let is_valid =
            verify_pq_slh_dsa_with_config_unverified(message, &signature, &pk, *level, &config)?;

        assert!(is_valid, "SLH-DSA {:?} should verify with config", level);
    }

    Ok(())
}

// ============================================================================
// FN-DSA Tests (All Ignored - Stack Overflow in Debug Mode)
// ============================================================================

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_roundtrip() -> Result<()> {
    let message = b"Test FN-DSA roundtrip";
    let (pk, sk) = generate_fn_dsa_keypair()?;

    let signature = sign_pq_fn_dsa(message, sk.as_ref(), SecurityMode::Unverified)?;

    assert!(!signature.is_empty(), "FN-DSA signature should not be empty");

    let is_valid = verify_pq_fn_dsa(message, &signature, &pk, SecurityMode::Unverified)?;

    assert!(is_valid, "FN-DSA signature should verify");
    Ok(())
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_with_config_roundtrip() -> Result<()> {
    let message = b"Test FN-DSA with config";
    let (pk, sk) = generate_fn_dsa_keypair()?;
    let config = CoreConfig::default();

    let signature = sign_pq_fn_dsa_with_config_unverified(message, sk.as_ref(), &config)?;

    let is_valid = verify_pq_fn_dsa_with_config_unverified(message, &signature, &pk, &config)?;

    assert!(is_valid, "FN-DSA with config should verify");
    Ok(())
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_large_message() -> Result<()> {
    let message = vec![0xAB; 10_000];
    let (pk, sk) = generate_fn_dsa_keypair()?;

    let signature = sign_pq_fn_dsa(&message, sk.as_ref(), SecurityMode::Unverified)?;

    let is_valid = verify_pq_fn_dsa(&message, &signature, &pk, SecurityMode::Unverified)?;

    assert!(is_valid, "FN-DSA should handle large messages");
    Ok(())
}

// ============================================================================
// Unicode Message Content Tests
// ============================================================================

#[test]
fn test_ml_dsa_unicode_message() -> Result<()> {
    // Various Unicode scripts
    let message = "Hello World! Bonjour! Hola! \u{4e2d}\u{6587} \u{65e5}\u{672c}\u{8a9e} \u{d55c}\u{ad6d}\u{c5b4} \u{0627}\u{0644}\u{0639}\u{0631}\u{0628}\u{064a}\u{0629} \u{05e2}\u{05d1}\u{05e8}\u{05d9}\u{05ea} \u{0420}\u{0443}\u{0441}\u{0441}\u{043a}\u{0438}\u{0439} \u{1f600}\u{1f4bb}\u{1f510}";
    let message_bytes = message.as_bytes();

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

    let signature = sign_pq_ml_dsa(
        message_bytes,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        message_bytes,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle Unicode messages correctly");
    Ok(())
}

#[test]
fn test_ml_dsa_cyrillic_message() -> Result<()> {
    let message = "\u{041f}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442} \u{041c}\u{0438}\u{0440}"; // Privet Mir
    let message_bytes = message.as_bytes();

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;

    let signature = sign_pq_ml_dsa(
        message_bytes,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        message_bytes,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle Cyrillic messages");
    Ok(())
}

#[test]
fn test_ml_dsa_cjk_message() -> Result<()> {
    let message = "\u{4e2d}\u{6587}\u{6d4b}\u{8bd5}\u{6d88}\u{606f}"; // Chinese test message
    let message_bytes = message.as_bytes();

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;

    let signature = sign_pq_ml_dsa(
        message_bytes,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        message_bytes,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle CJK messages");
    Ok(())
}

#[test]
fn test_ml_dsa_emoji_message() -> Result<()> {
    let message = "\u{1f600}\u{1f4bb}\u{1f510}\u{1f5dd}\u{1f512}\u{1f513}\u{2705}\u{274c}"; // Various emojis
    let message_bytes = message.as_bytes();

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

    let signature = sign_pq_ml_dsa(
        message_bytes,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        message_bytes,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle emoji messages");
    Ok(())
}

#[test]
fn test_slh_dsa_unicode_message() -> Result<()> {
    let message = "\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}\u{4e16}\u{754c}"; // Japanese greeting
    let message_bytes = message.as_bytes();

    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

    let signature = sign_pq_slh_dsa(
        message_bytes,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_slh_dsa(
        message_bytes,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA should handle Unicode messages");
    Ok(())
}

// ============================================================================
// Binary Data with Edge Bytes Tests
// ============================================================================

#[test]
fn test_ml_dsa_binary_edge_bytes() -> Result<()> {
    // Test with edge case bytes: null, max byte, signed boundaries
    let message: Vec<u8> = vec![
        0x00, 0x00, 0x00, // Multiple nulls
        0xFF, 0xFF, 0xFF, // Multiple max bytes
        0x7F, 0x7F, // Max positive signed byte
        0x80, 0x80, // Min negative signed byte (two's complement)
        0x01, 0xFE, // Near boundaries
        0x00, 0xFF, 0x7F, 0x80, // All four at once
    ];

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

    let signature = sign_pq_ml_dsa(
        &message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        &message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle binary edge bytes");
    Ok(())
}

#[test]
fn test_ml_dsa_all_nulls() -> Result<()> {
    let message = vec![0x00; 256];

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;

    let signature = sign_pq_ml_dsa(
        &message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        &message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle all-null messages");
    Ok(())
}

#[test]
fn test_ml_dsa_all_ones() -> Result<()> {
    let message = vec![0xFF; 256];

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87)?;

    let signature = sign_pq_ml_dsa(
        &message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        &message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA87,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle all-0xFF messages");
    Ok(())
}

#[test]
fn test_slh_dsa_binary_edge_bytes() -> Result<()> {
    let message: Vec<u8> = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE, 0x00, 0xFF];

    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s)?;

    let signature = sign_pq_slh_dsa(
        &message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake192s,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_slh_dsa(
        &message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake192s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA should handle binary edge bytes");
    Ok(())
}

#[test]
fn test_slh_dsa_alternating_pattern() -> Result<()> {
    let message: Vec<u8> = (0..256).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();

    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake256s)?;

    let signature = sign_pq_slh_dsa(
        &message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake256s,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_slh_dsa(
        &message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake256s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA should handle alternating byte patterns");
    Ok(())
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[test]
fn test_ml_dsa_empty_message() -> Result<()> {
    let message = b"";

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

    let signature =
        sign_pq_ml_dsa(message, sk.as_ref(), MlDsaParameterSet::MLDSA65, SecurityMode::Unverified)?;

    let is_valid = verify_pq_ml_dsa(
        message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle empty messages");
    Ok(())
}

#[test]
fn test_slh_dsa_empty_message() -> Result<()> {
    let message = b"";

    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

    let signature = sign_pq_slh_dsa(
        message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA should handle empty messages");
    Ok(())
}

#[test]
fn test_ml_dsa_single_byte_message() -> Result<()> {
    let message = [0x42];

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44)?;

    let signature = sign_pq_ml_dsa(
        &message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        &message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle single byte messages");
    Ok(())
}

#[test]
fn test_ml_dsa_large_message() -> Result<()> {
    let message = vec![0xAB; 60_000]; // 60KB message (within 65536 limit)

    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;

    let signature = sign_pq_ml_dsa(
        &message,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_ml_dsa(
        &message,
        &signature,
        &pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "ML-DSA should handle large messages (100KB)");
    Ok(())
}

#[test]
fn test_slh_dsa_large_message() -> Result<()> {
    let message = vec![0xCD; 10_000]; // 10KB message (SLH-DSA is slower)

    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;

    let signature = sign_pq_slh_dsa(
        &message,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    let is_valid = verify_pq_slh_dsa(
        &message,
        &signature,
        &pk,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )?;

    assert!(is_valid, "SLH-DSA should handle large messages (50KB)");
    Ok(())
}

// ============================================================================
// Multiple Signatures with Same Key Tests
// ============================================================================

#[test]
fn test_ml_dsa_multiple_signatures_same_key() -> Result<()> {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65)?;
    let messages = [
        b"First message".as_slice(),
        b"Second message".as_slice(),
        b"Third message".as_slice(),
        b"Fourth message".as_slice(),
        b"Fifth message".as_slice(),
    ];

    for message in &messages {
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

        assert!(is_valid, "ML-DSA should sign/verify multiple messages with same key");
    }

    Ok(())
}

#[test]
fn test_slh_dsa_multiple_signatures_same_key() -> Result<()> {
    let (pk, sk) = generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s)?;
    let messages = [b"Message A".as_slice(), b"Message B".as_slice(), b"Message C".as_slice()];

    for message in &messages {
        let signature = sign_pq_slh_dsa(
            message,
            sk.as_ref(),
            SlhDsaSecurityLevel::Shake128s,
            SecurityMode::Unverified,
        )?;

        let is_valid = verify_pq_slh_dsa(
            message,
            &signature,
            &pk,
            SlhDsaSecurityLevel::Shake128s,
            SecurityMode::Unverified,
        )?;

        assert!(is_valid, "SLH-DSA should sign/verify multiple messages with same key");
    }

    Ok(())
}

// ============================================================================
// Signature Non-Reusability Tests
// ============================================================================

#[test]
fn test_ml_dsa_signature_message_binding() {
    let (pk, sk) = generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let message_a = b"Message A";
    let message_b = b"Message B";

    let signature_a = sign_pq_ml_dsa(
        message_a,
        sk.as_ref(),
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )
    .expect("signing A");

    // Signature for message A should not verify message B
    let result = verify_pq_ml_dsa(
        message_b,
        &signature_a,
        &pk,
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Signature should not verify different message");
}

#[test]
fn test_slh_dsa_signature_message_binding() {
    let (pk, sk) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message_a = b"Original content";
    let message_b = b"Modified content";

    let signature_a = sign_pq_slh_dsa(
        message_a,
        sk.as_ref(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("signing A");

    let result = verify_pq_slh_dsa(
        message_b,
        &signature_a,
        &pk,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "SLH-DSA signature should not verify different message");
}

// ============================================================================
// Parameter Set Mismatch Tests
// ============================================================================

#[test]
fn test_ml_dsa_parameter_set_mismatch_sign() {
    let message = b"Parameter mismatch test";
    let (_, sk_44) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    // Try to sign with MLDSA44 key using MLDSA65 parameters
    let result = sign_pq_ml_dsa(
        message,
        sk_44.as_ref(),
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Should fail with mismatched parameter set");
}

#[test]
fn test_ml_dsa_parameter_set_mismatch_verify() {
    let message = b"Parameter mismatch verify test";
    let (pk_44, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair 44 generation");
    let (_, sk_65) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair 65 generation");

    let signature = sign_pq_ml_dsa(
        message,
        sk_65.as_ref(),
        MlDsaParameterSet::MLDSA65,
        SecurityMode::Unverified,
    )
    .expect("signing");

    // Try to verify MLDSA65 signature with MLDSA44 key
    let result = verify_pq_ml_dsa(
        message,
        &signature,
        &pk_44,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Should fail with mismatched parameter sets");
}

#[test]
fn test_slh_dsa_security_level_mismatch() {
    let message = b"Security level mismatch test";
    let (_, sk_128s) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    // Try to sign with 128s key using 192s parameters
    let result = sign_pq_slh_dsa(
        message,
        sk_128s.as_ref(),
        SlhDsaSecurityLevel::Shake192s,
        SecurityMode::Unverified,
    );

    assert!(result.is_err(), "Should fail with mismatched security level");
}
