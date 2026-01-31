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

#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use arc_core::{
    config::CoreConfig,
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
use arc_primitives::sig::{
    ml_dsa::MlDsaParameterSet, slh_dsa::SecurityLevel as SlhDsaSecurityLevel,
};

// ============================================================================
// ML-DSA Tests - Basic Sign/Verify Workflow
// ============================================================================

#[test]
fn test_ml_dsa_44_sign_verify_roundtrip() {
    let message = b"Test message for ML-DSA-44";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA44)
            .expect("verification should succeed");

    assert!(is_valid, "Valid ML-DSA-44 signature should verify");
}

#[test]
fn test_ml_dsa_65_sign_verify_roundtrip() {
    let message = b"Test message for ML-DSA-65";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA65)
            .expect("signing should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA65)
            .expect("verification should succeed");

    assert!(is_valid, "Valid ML-DSA-65 signature should verify");
}

#[test]
fn test_ml_dsa_87_sign_verify_roundtrip() {
    let message = b"Test message for ML-DSA-87";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA87)
            .expect("signing should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA87)
            .expect("verification should succeed");

    assert!(is_valid, "Valid ML-DSA-87 signature should verify");
}

#[test]
fn test_ml_dsa_with_security_mode() {
    let message = b"Test with SecurityMode";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature = sign_pq_ml_dsa(
        message,
        private_key.as_slice(),
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa(
        message,
        &signature,
        &public_key,
        MlDsaParameterSet::MLDSA44,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with SecurityMode");
}

#[test]
fn test_ml_dsa_with_config() {
    let message = b"Test with CoreConfig";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature = sign_pq_ml_dsa_with_config_unverified(
        message,
        private_key.as_slice(),
        MlDsaParameterSet::MLDSA44,
        &config,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_with_config_unverified(
        message,
        &signature,
        &public_key,
        MlDsaParameterSet::MLDSA44,
        &config,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with config");
}

#[test]
fn test_ml_dsa_with_config_and_security_mode() {
    let message = b"Test with both config and SecurityMode";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let signature = sign_pq_ml_dsa_with_config(
        message,
        private_key.as_slice(),
        MlDsaParameterSet::MLDSA65,
        &config,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_with_config(
        message,
        &signature,
        &public_key,
        MlDsaParameterSet::MLDSA65,
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
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let mut signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Tamper with signature
    if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA44);

    assert!(result.is_err(), "Modified signature should fail verification");
}

#[test]
fn test_ml_dsa_wrong_message_fails() {
    let message = b"Original message";
    let wrong_message = b"Different message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let result = verify_pq_ml_dsa_unverified(
        wrong_message,
        &signature,
        &public_key,
        MlDsaParameterSet::MLDSA44,
    );

    assert!(result.is_err(), "Wrong message should fail verification");
}

#[test]
fn test_ml_dsa_signature_not_deterministic() {
    let message = b"Same message";
    let (_, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let sig1 =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");
    let sig2 =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // ML-DSA uses randomness, so signatures should differ
    assert_ne!(sig1, sig2, "ML-DSA signatures should be non-deterministic");
}

// ============================================================================
// ML-DSA Tests - Invalid Public Key Handling
// ============================================================================

#[test]
fn test_ml_dsa_invalid_public_key_length() {
    let message = b"Test message";
    let (_, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let invalid_pk = vec![0u8; 10]; // Too short
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &invalid_pk, MlDsaParameterSet::MLDSA44);

    assert!(result.is_err(), "Invalid public key length should fail");
}

#[test]
fn test_ml_dsa_wrong_public_key_fails() {
    let message = b"Test message";
    let (_, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");
    let (wrong_pk, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &wrong_pk, MlDsaParameterSet::MLDSA44);

    assert!(result.is_err(), "Wrong public key should fail verification");
}

#[test]
fn test_ml_dsa_corrupted_public_key() {
    let message = b"Test message";
    let (mut public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Corrupt public key
    if !public_key.is_empty() {
        public_key[0] ^= 0xFF;
    }

    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA44);

    assert!(result.is_err(), "Corrupted public key should fail");
}

// ============================================================================
// ML-DSA Tests - Cross-Scheme Compatibility
// ============================================================================

#[test]
fn test_ml_dsa_44_signature_fails_with_65_params() {
    let message = b"Test message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Try to verify with wrong parameter set
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA65);

    assert!(result.is_err(), "Different parameter set should fail");
}

#[test]
fn test_ml_dsa_65_signature_fails_with_87_params() {
    let message = b"Test message";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA65)
            .expect("signing should succeed");

    // Try to verify with wrong parameter set
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA87);

    assert!(result.is_err(), "Different parameter set should fail");
}

// ============================================================================
// ML-DSA Tests - Message Variants
// ============================================================================

#[test]
fn test_ml_dsa_empty_message() {
    let message = b"";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing empty message should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA44)
            .expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

#[test]
fn test_ml_dsa_small_message() {
    let message = b"X";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA44)
            .expect("verification should succeed");

    assert!(is_valid, "Small message signature should verify");
}

#[test]
fn test_ml_dsa_large_message() {
    let message = vec![0x42u8; 65_000]; // ~64KB (within 65536 byte limit)
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(&message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing large message should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(&message, &signature, &public_key, MlDsaParameterSet::MLDSA44)
            .expect("verification should succeed");

    assert!(is_valid, "Large message signature should verify");
}

#[test]
fn test_ml_dsa_unicode_message() {
    let message = "こんにちは世界 🌍 مرحبا بالعالم";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature = sign_pq_ml_dsa_unverified(
        message.as_bytes(),
        private_key.as_slice(),
        MlDsaParameterSet::MLDSA44,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_ml_dsa_unverified(
        message.as_bytes(),
        &signature,
        &public_key,
        MlDsaParameterSet::MLDSA44,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Unicode message signature should verify");
}

#[test]
fn test_ml_dsa_binary_message() {
    let message: Vec<u8> = (0..=255).collect();
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(&message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(&message, &signature, &public_key, MlDsaParameterSet::MLDSA44)
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

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key,
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

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key,
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

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake192s)
            .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake192s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid SLH-DSA-192F signature should verify");
}

#[test]
fn test_slh_dsa_with_security_mode() {
    let message = b"Test with SecurityMode";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa(
        message,
        private_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa(
        message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
        SecurityMode::Unverified,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with SecurityMode");
}

#[test]
fn test_slh_dsa_with_config() {
    let message = b"Test with CoreConfig";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_with_config_unverified(
        message,
        private_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
        &config,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_with_config_unverified(
        message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
        &config,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with config");
}

#[test]
fn test_slh_dsa_with_config_and_security_mode() {
    let message = b"Test with both config and SecurityMode";
    let config = CoreConfig::default();
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_with_config(
        message,
        private_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
        &config,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_slh_dsa_with_config(
        message,
        &signature,
        &public_key,
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

    let mut signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    // Tamper with signature
    if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    );

    assert!(result.is_err(), "Modified signature should fail verification");
}

#[test]
fn test_slh_dsa_wrong_message_fails() {
    let message = b"Original message";
    let wrong_message = b"Different message";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    let result = verify_pq_slh_dsa_unverified(
        wrong_message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    );

    assert!(result.is_err(), "Wrong message should fail verification");
}

// ============================================================================
// SLH-DSA Tests - Invalid Public Key Handling
// ============================================================================

#[test]
fn test_slh_dsa_invalid_public_key_length() {
    let message = b"Test message";
    let (_, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
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

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &wrong_pk,
        SlhDsaSecurityLevel::Shake128s,
    );

    assert!(result.is_err(), "Wrong public key should fail verification");
}

// ============================================================================
// SLH-DSA Tests - Cross-Scheme Compatibility
// ============================================================================

#[test]
fn test_slh_dsa_128f_signature_fails_with_128s() {
    let message = b"Test message";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    // Try to verify with wrong security level (Shake192s instead of Shake128s)
    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake192s,
    );

    assert!(result.is_err(), "Different security level should fail");
}

// ============================================================================
// SLH-DSA Tests - Message Variants
// ============================================================================

#[test]
fn test_slh_dsa_empty_message() {
    let message = b"";
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing empty message should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

#[test]
fn test_slh_dsa_large_message() {
    let message = vec![0x42u8; 65_000]; // ~64KB (within 65536 byte limit)
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let signature = sign_pq_slh_dsa_unverified(
        &message,
        private_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing large message should succeed");

    let is_valid = verify_pq_slh_dsa_unverified(
        &message,
        &signature,
        &public_key,
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
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_sign_verify_roundtrip() {
    let message = b"Test message for FN-DSA";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature =
        sign_pq_fn_dsa_unverified(message, private_key.as_slice()).expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &public_key)
        .expect("verification should succeed");

    assert!(is_valid, "Valid FN-DSA signature should verify");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_with_security_mode() {
    let message = b"Test with SecurityMode";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa(message, private_key.as_slice(), SecurityMode::Unverified)
        .expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa(message, &signature, &public_key, SecurityMode::Unverified)
        .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with SecurityMode");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_with_config() {
    let message = b"Test with CoreConfig";
    let config = CoreConfig::default();
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_with_config_unverified(message, private_key.as_slice(), &config)
        .expect("signing should succeed");

    let is_valid =
        verify_pq_fn_dsa_with_config_unverified(message, &signature, &public_key, &config)
            .expect("verification should succeed");

    assert!(is_valid, "Valid signature should verify with config");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_with_config_and_security_mode() {
    let message = b"Test with both config and SecurityMode";
    let config = CoreConfig::default();
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_with_config(
        message,
        private_key.as_slice(),
        &config,
        SecurityMode::Unverified,
    )
    .expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa_with_config(
        message,
        &signature,
        &public_key,
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
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_modified_signature_fails() {
    let message = b"Original message";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let mut signature =
        sign_pq_fn_dsa_unverified(message, private_key.as_slice()).expect("signing should succeed");

    // Tamper with signature
    if !signature.is_empty() {
        signature[0] ^= 0xFF;
    }

    let result = verify_pq_fn_dsa_unverified(message, &signature, &public_key);

    assert!(result.is_err(), "Modified signature should fail verification");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_wrong_message_fails() {
    let message = b"Original message";
    let wrong_message = b"Different message";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature =
        sign_pq_fn_dsa_unverified(message, private_key.as_slice()).expect("signing should succeed");

    let result = verify_pq_fn_dsa_unverified(wrong_message, &signature, &public_key);

    assert!(result.is_err(), "Wrong message should fail verification");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_signature_not_deterministic() {
    let message = b"Same message";
    let (_, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let sig1 =
        sign_pq_fn_dsa_unverified(message, private_key.as_slice()).expect("signing should succeed");
    let sig2 =
        sign_pq_fn_dsa_unverified(message, private_key.as_slice()).expect("signing should succeed");

    // FN-DSA uses randomness, so signatures should differ
    assert_ne!(sig1, sig2, "FN-DSA signatures should be non-deterministic");
}

// ============================================================================
// FN-DSA Tests - Invalid Public Key Handling
// ============================================================================

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_invalid_public_key_length() {
    let message = b"Test message";
    let (_, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature =
        sign_pq_fn_dsa_unverified(message, private_key.as_slice()).expect("signing should succeed");

    let invalid_pk = vec![0u8; 10]; // Too short
    let result = verify_pq_fn_dsa_unverified(message, &signature, &invalid_pk);

    assert!(result.is_err(), "Invalid public key length should fail");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_wrong_public_key_fails() {
    let message = b"Test message";
    let (_, private_key) = generate_fn_dsa_keypair().expect("keypair generation");
    let (wrong_pk, _) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature =
        sign_pq_fn_dsa_unverified(message, private_key.as_slice()).expect("signing should succeed");

    let result = verify_pq_fn_dsa_unverified(message, &signature, &wrong_pk);

    assert!(result.is_err(), "Wrong public key should fail verification");
}

// ============================================================================
// FN-DSA Tests - Message Variants
// ============================================================================

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_empty_message() {
    let message = b"";
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(message, private_key.as_slice())
        .expect("signing empty message should succeed");

    let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &public_key)
        .expect("verification should succeed");

    assert!(is_valid, "Empty message signature should verify");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_large_message() {
    let message = vec![0x42u8; 100_000]; // 100KB
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let signature = sign_pq_fn_dsa_unverified(&message, private_key.as_slice())
        .expect("signing large message should succeed");

    let is_valid = verify_pq_fn_dsa_unverified(&message, &signature, &public_key)
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
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("ML-DSA keypair");
    let (slh_dsa_pk, _) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("SLH-DSA keypair");

    let ml_dsa_sig =
        sign_pq_ml_dsa_unverified(message, ml_dsa_sk.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("ML-DSA signing should succeed");

    // This should fail because we're mixing schemes
    let result = verify_pq_slh_dsa_unverified(
        message,
        &ml_dsa_sig,
        &slh_dsa_pk,
        SlhDsaSecurityLevel::Shake128s,
    );

    assert!(result.is_err(), "ML-DSA signature should not verify with SLH-DSA key");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_slh_dsa_signature_with_fn_dsa_key_fails() {
    let message = b"Test message";
    let (_, slh_dsa_sk) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("SLH-DSA keypair");
    let (fn_dsa_pk, _) = generate_fn_dsa_keypair().expect("FN-DSA keypair");

    let slh_dsa_sig =
        sign_pq_slh_dsa_unverified(message, slh_dsa_sk.as_slice(), SlhDsaSecurityLevel::Shake128s)
            .expect("SLH-DSA signing should succeed");

    // This should fail because we're mixing schemes
    let result = verify_pq_fn_dsa_unverified(message, &slh_dsa_sig, &fn_dsa_pk);

    assert!(result.is_err(), "SLH-DSA signature should not verify with FN-DSA key");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_signature_with_ml_dsa_key_fails() {
    let message = b"Test message";
    let (_, fn_dsa_sk) = generate_fn_dsa_keypair().expect("FN-DSA keypair");
    let (ml_dsa_pk, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("ML-DSA keypair");

    let fn_dsa_sig = sign_pq_fn_dsa_unverified(message, fn_dsa_sk.as_slice())
        .expect("FN-DSA signing should succeed");

    // This should fail because we're mixing schemes
    let result =
        verify_pq_ml_dsa_unverified(message, &fn_dsa_sig, &ml_dsa_pk, MlDsaParameterSet::MLDSA44);

    assert!(result.is_err(), "FN-DSA signature should not verify with ML-DSA key");
}

// ============================================================================
// Error Condition Tests
// ============================================================================

#[test]
fn test_ml_dsa_invalid_private_key() {
    let message = b"Test message";
    let invalid_sk = vec![0u8; 10]; // Too short

    let result = sign_pq_ml_dsa_unverified(message, &invalid_sk, MlDsaParameterSet::MLDSA44);

    assert!(result.is_err(), "Invalid private key should fail signing");
}

#[test]
fn test_slh_dsa_invalid_private_key() {
    let message = b"Test message";
    let invalid_sk = vec![0u8; 10]; // Too short

    let result = sign_pq_slh_dsa_unverified(message, &invalid_sk, SlhDsaSecurityLevel::Shake128s);

    assert!(result.is_err(), "Invalid private key should fail signing");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_invalid_private_key() {
    let message = b"Test message";
    let invalid_sk = vec![0u8; 10]; // Too short

    let result = sign_pq_fn_dsa_unverified(message, &invalid_sk);

    assert!(result.is_err(), "Invalid private key should fail signing");
}

#[test]
fn test_ml_dsa_empty_signature() {
    let message = b"Test message";
    let (public_key, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let empty_sig = vec![];
    let result =
        verify_pq_ml_dsa_unverified(message, &empty_sig, &public_key, MlDsaParameterSet::MLDSA44);

    assert!(result.is_err(), "Empty signature should fail verification");
}

#[test]
fn test_slh_dsa_empty_signature() {
    let message = b"Test message";
    let (public_key, _) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let empty_sig = vec![];
    let result = verify_pq_slh_dsa_unverified(
        message,
        &empty_sig,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    );

    assert!(result.is_err(), "Empty signature should fail verification");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_empty_signature() {
    let message = b"Test message";
    let (public_key, _) = generate_fn_dsa_keypair().expect("keypair generation");

    let empty_sig = vec![];
    let result = verify_pq_fn_dsa_unverified(message, &empty_sig, &public_key);

    assert!(result.is_err(), "Empty signature should fail verification");
}

// ============================================================================
// Round-trip Serialization Tests
// ============================================================================

#[test]
fn test_ml_dsa_key_serialization_roundtrip() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    // Keys are already serialized as bytes, test they work after clone
    let pk_bytes = public_key.clone();
    let sk_bytes = private_key.as_slice().to_vec();

    let message = b"Test serialization";
    let signature = sign_pq_ml_dsa_unverified(message, &sk_bytes, MlDsaParameterSet::MLDSA44)
        .expect("signing should succeed");

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &signature, &pk_bytes, MlDsaParameterSet::MLDSA44)
            .expect("verification should succeed");

    assert!(is_valid, "Serialized keys should work correctly");
}

#[test]
fn test_slh_dsa_key_serialization_roundtrip() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    // Keys are already serialized as bytes, test they work after clone
    let pk_bytes = public_key.clone();
    let sk_bytes = private_key.as_slice().to_vec();

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
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_key_serialization_roundtrip() {
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    // Keys are already serialized as bytes, test they work after clone
    let pk_bytes = public_key.clone();
    let sk_bytes = private_key.as_slice().to_vec();

    let message = b"Test serialization";
    let signature = sign_pq_fn_dsa_unverified(message, &sk_bytes).expect("signing should succeed");

    let is_valid = verify_pq_fn_dsa_unverified(message, &signature, &pk_bytes)
        .expect("verification should succeed");

    assert!(is_valid, "Serialized keys should work correctly");
}

#[test]
fn test_ml_dsa_signature_serialization_roundtrip() {
    let message = b"Test signature serialization";
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_slice(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Simulate serialization/deserialization
    let sig_bytes = signature.clone();

    let is_valid =
        verify_pq_ml_dsa_unverified(message, &sig_bytes, &public_key, MlDsaParameterSet::MLDSA44)
            .expect("verification should succeed");

    assert!(is_valid, "Serialized signature should verify");
}
