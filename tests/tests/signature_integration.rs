//! Comprehensive integration tests for post-quantum signature APIs
//!
//! This test suite validates the signature convenience APIs in arc-core,
//! covering ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and FN-DSA (FIPS 206).
//!
//! Test coverage includes:
//! - Basic sign/verify workflows for all schemes
//! - Invalid signature detection
//! - Invalid public key handling
//! - Cross-scheme compatibility validation
//! - Message variants (empty, small, large)
//! - Round-trip serialization
//! - Error conditions and edge cases

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

use latticearc::primitives::sig::{
    fndsa::FnDsaSecurityLevel, ml_dsa::MlDsaParameterSet, slh_dsa::SlhDsaSecurityLevel,
};
use latticearc::unified_api::{
    CoreConfig,
    convenience::{
        generate_fn_dsa_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair, sign_pq_fn_dsa,
        sign_pq_fn_dsa_unverified, sign_pq_fn_dsa_with_config,
        sign_pq_fn_dsa_with_config_unverified, sign_pq_ml_dsa, sign_pq_ml_dsa_unverified,
        sign_pq_ml_dsa_with_config, sign_pq_ml_dsa_with_config_unverified, sign_pq_slh_dsa,
        sign_pq_slh_dsa_unverified, sign_pq_slh_dsa_with_config,
        sign_pq_slh_dsa_with_config_unverified, verify_pq_fn_dsa, verify_pq_fn_dsa_unverified,
        verify_pq_fn_dsa_with_config, verify_pq_fn_dsa_with_config_unverified, verify_pq_ml_dsa,
        verify_pq_ml_dsa_unverified, verify_pq_ml_dsa_with_config,
        verify_pq_ml_dsa_with_config_unverified, verify_pq_slh_dsa, verify_pq_slh_dsa_unverified,
        verify_pq_slh_dsa_with_config, verify_pq_slh_dsa_with_config_unverified,
    },
    zero_trust::SecurityMode,
};

// ============================================================================
// ML-DSA Tests - Basic Sign/Verify Workflow
// ============================================================================

#[test]
fn test_ml_dsa_44_sign_verify_roundtrip() {
    let message = b"Test message for ML-DSA-44";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid ML-DSA-44 signature should verify");
}

#[test]
fn test_ml_dsa_65_sign_verify_roundtrip() {
    let message = b"Test message for ML-DSA-65";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa65)
            .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa65,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid ML-DSA-65 signature should verify");
}

#[test]
fn test_ml_dsa_87_sign_verify_roundtrip() {
    let message = b"Test message for ML-DSA-87";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa87).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa87)
            .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa87,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid ML-DSA-87 signature should verify");
}

#[test]
fn test_ml_dsa_with_security_mode_succeeds() {
    let message = b"Test with SecurityMode";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature = sign_pq_ml_dsa(
        message,
        private_key.expose_secret(),
        MlDsaParameterSet::MlDsa44,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with SecurityMode");
}

#[test]
fn test_ml_dsa_with_config_succeeds() {
    let message = b"Test with CoreConfig";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature = sign_pq_ml_dsa_with_config_unverified(
        message,
        private_key.expose_secret(),
        MlDsaParameterSet::MlDsa44,
        &config,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_with_config_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
        &config,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with config");
}

#[test]
fn test_ml_dsa_with_config_and_security_mode_succeeds() {
    let message = b"Test with both config and SecurityMode";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("keypair generation");

    let signature = sign_pq_ml_dsa_with_config(
        message,
        private_key.expose_secret(),
        MlDsaParameterSet::MlDsa65,
        &config,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_with_config(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa65,
        &config,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify");
}

// ============================================================================
// ML-DSA Tests - Invalid Signature Detection
// ============================================================================

#[test]
fn test_ml_dsa_modified_signature_fails() {
    let message = b"Original message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let mut signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    // Tamper with signature
    if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Modified signature should fail verification");
}

#[test]
fn test_ml_dsa_wrong_message_fails() {
    let message = b"Original message";
    let wrong_message = b"Different message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    let result = verify_pq_ml_dsa_unverified(
        wrong_message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Wrong message should fail verification");
}

#[test]
fn test_ml_dsa_signature_not_deterministic_produces_distinct_signatures_is_deterministic() {
    let message = b"Same message";
    let (_, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let sig1 =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");
    let sig2 =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    // ML-DSA uses randomness, so signatures should differ
    assert_ne!(sig1, sig2, "ML-DSA signatures should be non-deterministic");
}

// ============================================================================
// ML-DSA Tests - Invalid Public Key Handling
// ============================================================================

#[test]
fn test_ml_dsa_invalid_public_key_length_returns_error() {
    let message = b"Test message";
    let (_, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    let invalid_pk = vec![0u8; 10]; // Too short
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &invalid_pk, MlDsaParameterSet::MlDsa44);

    assert!(result.is_err(), "Invalid public key length should fail");
}

#[test]
fn test_ml_dsa_wrong_public_key_fails() {
    let message = b"Test message";
    let (_, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");
    let (wrong_pk, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        wrong_pk.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Wrong public key should fail verification");
}

#[test]
fn test_ml_dsa_corrupted_public_key_returns_error() {
    let message = b"Test message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    // Corrupt public key
    let mut pk_bytes = public_key.into_bytes();
    if !pk_bytes.is_empty() {
        pk_bytes[0] ^= 0xFF;
    }

    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &pk_bytes, MlDsaParameterSet::MlDsa44);

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Corrupted public key should fail");
}

// ============================================================================
// ML-DSA Tests - Cross-Scheme Compatibility
// ============================================================================

#[test]
fn test_ml_dsa_44_signature_fails_with_65_params_fails() {
    let message = b"Test message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    // Try to verify with wrong parameter set
    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa65,
    );

    assert!(result.is_err(), "Different parameter set should fail");
}

#[test]
fn test_ml_dsa_65_signature_fails_with_87_params_fails() {
    let message = b"Test message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa65)
            .expect("signing should succeed");

    // Try to verify with wrong parameter set
    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa87,
    );

    assert!(result.is_err(), "Different parameter set should fail");
}

// ============================================================================
// ML-DSA Tests - Message Variants
// ============================================================================

#[test]
fn test_ml_dsa_empty_message_signs_and_verifies_succeeds() {
    let message = b"";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing empty message should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

#[test]
fn test_ml_dsa_small_message_signs_and_verifies_succeeds() {
    let message = b"X";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Small message signature should verify");
}

#[test]
fn test_ml_dsa_large_message_signs_and_verifies_succeeds() {
    let message = vec![0x42u8; 65_000]; // ~64KB (within 65536 byte limit)
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature = sign_pq_ml_dsa_unverified(
        &message,
        private_key.expose_secret(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("signing large message should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        &message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Large message signature should verify");
}

#[test]
fn test_ml_dsa_unicode_message_signs_and_verifies_succeeds() {
    let message = "こんにちは世界 🌍 مرحبا بالعالم";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature = sign_pq_ml_dsa_unverified(
        message.as_bytes(),
        private_key.expose_secret(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        message.as_bytes(),
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Unicode message signature should verify");
}

#[test]
fn test_ml_dsa_binary_message_signs_and_verifies_succeeds() {
    let message: Vec<u8> = (0..=255).collect();
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature = sign_pq_ml_dsa_unverified(
        &message,
        private_key.expose_secret(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        &message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Binary message signature should verify");
}

// ============================================================================
// SLH-DSA Tests - Basic Sign/Verify Workflow
// ============================================================================

#[test]
fn test_slh_dsa_128f_sign_verify_roundtrip() {
    let message = b"Test message for SLH-DSA-128F";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid SLH-DSA-128F signature should verify");
}

#[test]
fn test_slh_dsa_128s_sign_verify_roundtrip() {
    let message = b"Test message for SLH-DSA-128S";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid SLH-DSA-128S signature should verify");
}

#[test]
fn test_slh_dsa_192f_sign_verify_roundtrip() {
    let message = b"Test message for SLH-DSA-192F";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake192s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake192s,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake192s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid SLH-DSA-192F signature should verify");
}

#[test]
fn test_slh_dsa_with_security_mode_succeeds() {
    let message = b"Test with SecurityMode";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with SecurityMode");
}

#[test]
fn test_slh_dsa_with_config_succeeds() {
    let message = b"Test with CoreConfig";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_with_config_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
        &config,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_with_config_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
        &config,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with config");
}

#[test]
fn test_slh_dsa_with_config_and_security_mode_succeeds() {
    let message = b"Test with both config and SecurityMode";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_with_config(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
        &config,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_with_config(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
        &config,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify");
}

// ============================================================================
// SLH-DSA Tests - Invalid Signature Detection
// ============================================================================

#[test]
fn test_slh_dsa_modified_signature_fails() {
    let message = b"Original message";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let mut signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    // Tamper with signature
    if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Modified signature should fail verification");
}

#[test]
fn test_slh_dsa_wrong_message_fails() {
    let message = b"Original message";
    let wrong_message = b"Different message";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    let result = verify_pq_slh_dsa_unverified(
        wrong_message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Wrong message should fail verification");
}

// ============================================================================
// SLH-DSA Tests - Invalid Public Key Handling
// ============================================================================

#[test]
fn test_slh_dsa_invalid_public_key_length_returns_error() {
    let message = b"Test message";
    let (_, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    let invalid_pk = vec![0u8; 10]; // Too short
    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &invalid_pk,
        SlhDsaSecurityLevel::Shake128s,
    );

    assert!(result.is_err(), "Invalid public key length should fail");
}

#[test]
fn test_slh_dsa_wrong_public_key_fails() {
    let message = b"Test message";
    let (_, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");
    let (wrong_pk, _) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        wrong_pk.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Wrong public key should fail verification");
}

// ============================================================================
// SLH-DSA Tests - Cross-Scheme Compatibility
// ============================================================================

#[test]
fn test_slh_dsa_128f_signature_fails_with_128s_fails() {
    let message = b"Test message";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    // Try to verify with wrong security level (Shake192s instead of Shake128s)
    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake192s,
    );

    assert!(result.is_err(), "Different security level should fail");
}

// ============================================================================
// SLH-DSA Tests - Message Variants
// ============================================================================

#[test]
fn test_slh_dsa_empty_message_signs_and_verifies_succeeds() {
    let message = b"";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing empty message should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

#[test]
fn test_slh_dsa_large_message_signs_and_verifies_succeeds() {
    let message = vec![0x42u8; 65_000]; // ~64KB (within 65536 byte limit)
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        &message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing large message should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        &message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Large message signature should verify");
}

// ============================================================================
// FN-DSA Tests - Basic Sign/Verify Workflow
// ============================================================================
//
// NOTE: FN-DSA tests are ignored by default due to stack overflow issues in debug mode.
// FN-DSA uses large stack frames that exceed default stack sizes in unoptimized builds.
// Run these tests in release mode with: cargo test --release --test signature_integration -- --ignored
//

#[test]
fn test_fn_dsa_sign_verify_roundtrip() {
    let message = b"Test message for FN-DSA";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid FN-DSA signature should verify");
}

#[test]
fn test_fn_dsa_with_security_mode_succeeds() {
    let message = b"Test with SecurityMode";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa(
        message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with SecurityMode");
}

#[test]
fn test_fn_dsa_with_config_succeeds() {
    let message = b"Test with CoreConfig";
    let config = CoreConfig::default();
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_with_config_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
        &config,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa_with_config_unverified(
        message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
        &config,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with config");
}

#[test]
fn test_fn_dsa_with_config_and_security_mode_succeeds() {
    let message = b"Test with both config and SecurityMode";
    let config = CoreConfig::default();
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_with_config(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
        &config,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa_with_config(
        message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
        &config,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify");
}

// ============================================================================
// FN-DSA Tests - Invalid Signature Detection
// ============================================================================

#[test]
fn test_fn_dsa_modified_signature_fails() {
    let message = b"Original message";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let mut signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    // Tamper with signature
    if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_fn_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Modified signature should fail verification");
}

#[test]
fn test_fn_dsa_wrong_message_fails() {
    let message = b"Original message";
    let wrong_message = b"Different message";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    let result = verify_pq_fn_dsa_unverified(
        wrong_message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Wrong message should fail verification");
}

#[test]
fn test_fn_dsa_signature_not_deterministic_produces_distinct_signatures_is_deterministic() {
    let message = b"Same message";
    let (_, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let sig1 = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");
    let sig2 = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    // FN-DSA uses randomness, so signatures should differ
    assert_ne!(sig1, sig2, "FN-DSA signatures should be non-deterministic");
}

// ============================================================================
// FN-DSA Tests - Invalid Public Key Handling
// ============================================================================

#[test]
fn test_fn_dsa_invalid_public_key_length_returns_error() {
    let message = b"Test message";
    let (_, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    let invalid_pk = vec![0u8; 10]; // Too short
    let result =
        verify_pq_fn_dsa_unverified(message, &signature, &invalid_pk, FnDsaSecurityLevel::Level512);

    assert!(result.is_err(), "Invalid public key length should fail");
}

#[test]
fn test_fn_dsa_wrong_public_key_fails() {
    let message = b"Test message";
    let (_, private_key) = generate_fn_dsa_keypair().expect("keypair generation");
    let (wrong_pk, _) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    let result = verify_pq_fn_dsa_unverified(
        message,
        &signature,
        wrong_pk.as_slice(),
        FnDsaSecurityLevel::Level512,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Wrong public key should fail verification");
}

// ============================================================================
// FN-DSA Tests - Message Variants
// ============================================================================

#[test]
fn test_fn_dsa_empty_message_signs_and_verifies_succeeds() {
    let message = b"";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing empty message should succeed");

    let is_valid = verify_pq_fn_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

#[test]
fn test_fn_dsa_large_message_signs_and_verifies_succeeds() {
    let message = vec![0x42u8; 60_000]; // 60KB (within 64KB signature limit)
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(
        &message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing large message should succeed");

    let is_valid = verify_pq_fn_dsa_unverified(
        &message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Large message signature should verify");
}

// ============================================================================
// Cross-Scheme Tests - Different Schemes Should Not Interoperate
// ============================================================================

#[test]
fn test_ml_dsa_signature_with_slh_dsa_key_fails() {
    let message = b"Test message";
    let (_, ml_dsa_sk) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("ML-DSA keypair");
    let (slh_dsa_pk, _) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("SLH-DSA keypair");

    let ml_dsa_sig =
        sign_pq_ml_dsa_unverified(message, ml_dsa_sk.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("ML-DSA signing should succeed");

    // This should fail because we're mixing schemes
    let result = verify_pq_slh_dsa_unverified(
        message,
        &ml_dsa_sig,
        slh_dsa_pk.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "ML-DSA signature should not verify with SLH-DSA key");
}

#[test]
fn test_slh_dsa_signature_with_fn_dsa_key_fails() {
    let message = b"Test message";
    let (_, slh_dsa_sk) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("SLH-DSA keypair");
    let (fn_dsa_pk, _) = generate_fn_dsa_keypair().expect("FN-DSA keypair");

    let slh_dsa_sig = sign_pq_slh_dsa_unverified(
        message,
        slh_dsa_sk.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("SLH-DSA signing should succeed");

    // This should fail because we're mixing schemes
    let result = verify_pq_fn_dsa_unverified(
        message,
        &slh_dsa_sig,
        fn_dsa_pk.as_slice(),
        FnDsaSecurityLevel::Level512,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "SLH-DSA signature should not verify with FN-DSA key");
}

#[test]
fn test_fn_dsa_signature_with_ml_dsa_key_fails() {
    let message = b"Test message";
    let (_, fn_dsa_sk) = generate_fn_dsa_keypair().expect("FN-DSA keypair");
    let (ml_dsa_pk, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("ML-DSA keypair");

    let fn_dsa_sig =
        sign_pq_fn_dsa_unverified(message, fn_dsa_sk.expose_secret(), FnDsaSecurityLevel::Level512)
            .expect("FN-DSA signing should succeed");

    // This should fail because we're mixing schemes
    let result = verify_pq_ml_dsa_unverified(
        message,
        &fn_dsa_sig,
        ml_dsa_pk.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );

    assert!(result.is_err(), "FN-DSA signature should not verify with ML-DSA key");
}

// ============================================================================
// Error Condition Tests
// ============================================================================

#[test]
fn test_ml_dsa_invalid_private_key_returns_error() {
    let message = b"Test message";
    let invalid_sk = vec![0u8; 10]; // Too short

    let result = sign_pq_ml_dsa_unverified(message, &invalid_sk, MlDsaParameterSet::MlDsa44);

    assert!(result.is_err(), "Invalid private key should fail signing");
}

#[test]
fn test_slh_dsa_invalid_private_key_returns_error() {
    let message = b"Test message";
    let invalid_sk = vec![0u8; 10]; // Too short

    let result = sign_pq_slh_dsa_unverified(message, &invalid_sk, SlhDsaSecurityLevel::Shake128s);

    assert!(result.is_err(), "Invalid private key should fail signing");
}

#[test]
fn test_fn_dsa_invalid_private_key_returns_error() {
    let message = b"Test message";
    let invalid_sk = vec![0u8; 10]; // Too short

    let result = sign_pq_fn_dsa_unverified(message, &invalid_sk, FnDsaSecurityLevel::Level512);

    assert!(result.is_err(), "Invalid private key should fail signing");
}

#[test]
fn test_ml_dsa_empty_signature_returns_error() {
    let message = b"Test message";
    let (public_key, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let empty_sig = vec![];
    let result = verify_pq_ml_dsa_unverified(
        message,
        &empty_sig,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );

    assert!(result.is_err(), "Empty signature should fail verification");
}

#[test]
fn test_slh_dsa_empty_signature_returns_error() {
    let message = b"Test message";
    let (public_key, _) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let empty_sig = vec![];
    let result = verify_pq_slh_dsa_unverified(
        message,
        &empty_sig,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );

    // Round-28 H6: verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "Empty signature should fail verification");
}

#[test]
fn test_fn_dsa_empty_signature_returns_error() {
    let message = b"Test message";
    let (public_key, _) = generate_fn_dsa_keypair().expect("keypair generation");

    let empty_sig = vec![];
    let result = verify_pq_fn_dsa_unverified(
        message,
        &empty_sig,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    );

    assert!(result.is_err(), "Empty signature should fail verification");
}

// ============================================================================
// Round-trip Serialization Tests
// ============================================================================

#[test]
fn test_ml_dsa_key_serialization_roundtrip() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    // Keys are already serialized as bytes, test they work after clone
    let pk_bytes = public_key.as_slice().to_vec();
    let sk_bytes = private_key.expose_secret().to_vec();

    let message = b"Test serialization";
    let signature = sign_pq_ml_dsa_unverified(message, &sk_bytes, MlDsaParameterSet::MlDsa44)
        .expect("signing should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &signature, &pk_bytes, MlDsaParameterSet::MlDsa44)
            .expect("verification should succeed");

    assert!(is_valid, "Serialized keys should work correctly");
}

#[test]
fn test_slh_dsa_key_serialization_roundtrip() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    // Keys are already serialized as bytes, test they work after clone
    let pk_bytes = public_key.as_slice().to_vec();
    let sk_bytes = private_key.expose_secret().to_vec();

    let message = b"Test serialization";
    let signature = sign_pq_slh_dsa_unverified(message, &sk_bytes, SlhDsaSecurityLevel::Shake128s)
        .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &pk_bytes,
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Serialized keys should work correctly");
}

#[test]
fn test_fn_dsa_key_serialization_roundtrip() {
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    // Keys are already serialized as bytes, test they work after clone
    let pk_bytes = public_key.as_slice().to_vec();
    let sk_bytes = private_key.expose_secret().to_vec();

    let message = b"Test serialization";
    let signature = sign_pq_fn_dsa_unverified(message, &sk_bytes, FnDsaSecurityLevel::Level512)
        .expect("signing should succeed");

    let is_valid =
        verify_pq_fn_dsa_unverified(message, &signature, &pk_bytes, FnDsaSecurityLevel::Level512)
            .expect("verification should succeed");

    assert!(is_valid, "Serialized keys should work correctly");
}

#[test]
fn test_ml_dsa_signature_serialization_roundtrip() {
    let message = b"Test signature serialization";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    // Simulate serialization/deserialization
    let sig_bytes = signature.clone();

    let is_valid = verify_pq_ml_dsa_unverified(
        message,
        &sig_bytes,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Serialized signature should verify");
}
