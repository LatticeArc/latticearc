//! Comprehensive negative tests for post-quantum signatures (arc-core convenience APIs)
//!
//! This test suite validates error handling for ML-DSA, SLH-DSA, and FN-DSA signature schemes.
//!
//! Test coverage:
//! - Empty messages/keys/signatures
//! - Invalid signature lengths
//! - Corrupted signatures
//! - Wrong public keys
//! - Mismatched parameter sets
//! - Cross-scheme contamination

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use latticearc::primitives::sig::{
    fndsa::FnDsaSecurityLevel, ml_dsa::MlDsaParameterSet, slh_dsa::SlhDsaSecurityLevel,
};
use latticearc::unified_api::convenience::{
    generate_fn_dsa_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair,
    sign_pq_fn_dsa_unverified, sign_pq_ml_dsa_unverified, sign_pq_slh_dsa_unverified,
    verify_pq_fn_dsa_unverified, verify_pq_ml_dsa_unverified, verify_pq_slh_dsa_unverified,
};

// ============================================================================
// ML-DSA Negative Tests - Empty Inputs
// ============================================================================

#[test]
fn test_ml_dsa_sign_empty_message_succeeds() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    // Signing empty message should succeed (valid use case)
    let result =
        sign_pq_ml_dsa_unverified(&[], private_key.expose_secret(), MlDsaParameterSet::MlDsa44);
    assert!(result.is_ok(), "Signing empty message should succeed");
}

#[test]
fn test_ml_dsa_sign_empty_private_key_fails() {
    let message = b"Test message";
    let empty_key = [];

    let result = sign_pq_ml_dsa_unverified(message, &empty_key, MlDsaParameterSet::MlDsa44);
    assert!(result.is_err(), "Should fail with empty private key");
}

#[test]
fn test_ml_dsa_verify_empty_signature_fails() {
    let (public_key, _private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Test message";
    let empty_signature = [];

    let result = verify_pq_ml_dsa_unverified(
        message,
        &empty_signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );
    assert!(result.is_err(), "Should fail with empty signature");
}

#[test]
fn test_ml_dsa_verify_empty_public_key_fails() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    let empty_key = [];
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &empty_key, MlDsaParameterSet::MlDsa44);
    assert!(result.is_err(), "Should fail with empty public key");
}

// ============================================================================
// ML-DSA Negative Tests - Invalid Key Lengths
// ============================================================================

#[test]
fn test_ml_dsa_sign_truncated_private_key_fails() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Test message";
    let truncated_key = &private_key.expose_secret()[..100];

    let result = sign_pq_ml_dsa_unverified(message, truncated_key, MlDsaParameterSet::MlDsa44);
    assert!(result.is_err(), "Should fail with truncated private key");
}

#[test]
fn test_ml_dsa_verify_truncated_public_key_fails() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa65)
            .expect("signing should succeed");

    let truncated_key = &public_key.as_slice()[..100];
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, truncated_key, MlDsaParameterSet::MlDsa65);
    assert!(result.is_err(), "Should fail with truncated public key");
}

#[test]
fn test_ml_dsa_verify_oversized_signature_fails() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Test message";
    let mut signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    // Add extra bytes to signature
    signature.extend_from_slice(&[0u8; 100]);

    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );
    assert!(result.is_err(), "Should fail with oversized signature");
}

// ============================================================================
// ML-DSA Negative Tests - Corrupted Signatures
// ============================================================================

#[test]
fn test_ml_dsa_verify_corrupted_signature_fails() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Test message";
    let mut signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    // Corrupt the signature
    if signature.len() > 10 {
        signature[10] ^= 0xFF;
    }

    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "corrupted signature must yield Ok(false)");
}

#[test]
fn test_ml_dsa_verify_modified_message_fails() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Original message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa44)
            .expect("signing should succeed");

    let modified_message = b"Modified message";
    let result = verify_pq_ml_dsa_unverified(
        modified_message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "modified message must yield Ok(false)");
}

// ============================================================================
// ML-DSA Negative Tests - Wrong Parameter Sets
// ============================================================================

#[test]
fn test_ml_dsa_44_key_with_65_params_fails() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Test message";
    // Try to sign with MlDsa44 key using MlDsa65 parameters
    let result =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa65);
    assert!(result.is_err(), "Should fail with mismatched parameter set");
}

#[test]
fn test_ml_dsa_65_signature_with_87_verify_fails() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa65).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.expose_secret(), MlDsaParameterSet::MlDsa65)
            .expect("signing should succeed");

    let (public_key_87, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa87).expect("keypair generation");

    // Try to verify MlDsa65 signature with MlDsa87 key
    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key_87.as_slice(),
        MlDsaParameterSet::MlDsa87,
    );
    assert!(result.is_err(), "Should fail with mismatched parameter set");
}

#[test]
fn test_ml_dsa_verify_with_wrong_public_key_fails() {
    let (_public_key_1, private_key_1) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");
    let (public_key_2, _private_key_2) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = b"Test message";
    let signature = sign_pq_ml_dsa_unverified(
        message,
        private_key_1.expose_secret(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("signing should succeed");

    // verify path collapses Err to Ok(false) (Pattern 6).
    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        public_key_2.as_slice(),
        MlDsaParameterSet::MlDsa44,
    );
    assert_eq!(result.ok(), Some(false), "wrong public key must yield Ok(false)");
}

// ============================================================================
// SLH-DSA Negative Tests
// ============================================================================

#[test]
fn test_slh_dsa_sign_empty_private_key_fails() {
    let message = b"Test message";
    let empty_key = [];

    let result = sign_pq_slh_dsa_unverified(message, &empty_key, SlhDsaSecurityLevel::Shake128s);
    assert!(result.is_err(), "Should fail with empty private key");
}

#[test]
fn test_slh_dsa_verify_empty_signature_fails() {
    let (public_key, _private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let empty_signature = [];

    let result = verify_pq_slh_dsa_unverified(
        message,
        &empty_signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "empty signature must yield Ok(false)");
}

#[test]
fn test_slh_dsa_verify_corrupted_signature_fails() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let mut signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    // Corrupt the signature
    if signature.len() > 50 {
        signature[50] ^= 0xFF;
    }

    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "corrupted signature must yield Ok(false)");
}

#[test]
fn test_slh_dsa_verify_truncated_signature_fails() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    // Truncate signature
    let truncated = &signature[..signature.len() / 2];

    let result = verify_pq_slh_dsa_unverified(
        message,
        truncated,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "truncated signature must yield Ok(false)");
}

#[test]
fn test_slh_dsa_l1_key_with_l3_params_fails() {
    let (_public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    // Try to sign with L1 key using L3 parameters
    let result = sign_pq_slh_dsa_unverified(
        message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake192s,
    );
    assert!(result.is_err(), "Should fail with mismatched security level");
}

#[test]
fn test_slh_dsa_verify_wrong_public_key_fails() {
    let (_public_key_1, private_key_1) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");
    let (public_key_2, _private_key_2) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let signature = sign_pq_slh_dsa_unverified(
        message,
        private_key_1.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    // verify path collapses Err to Ok(false) (Pattern 6).
    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        public_key_2.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );
    assert_eq!(result.ok(), Some(false), "wrong public key must yield Ok(false)");
}

// ============================================================================
// FN-DSA Negative Tests
// ============================================================================

#[test]
fn test_fn_dsa_sign_empty_private_key_fails() {
    let message = b"Test message";
    let empty_key = [];

    let result = sign_pq_fn_dsa_unverified(message, &empty_key, FnDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should fail with empty private key");
}

#[test]
fn test_fn_dsa_verify_empty_signature_fails() {
    let (public_key, _private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let empty_signature = [];

    let result = verify_pq_fn_dsa_unverified(
        message,
        &empty_signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    );
    assert!(result.is_err(), "Should fail with empty signature");
}

#[test]
fn test_fn_dsa_verify_corrupted_signature_fails() {
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let mut signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    // Corrupt the signature
    if signature.len() > 100 {
        signature[100] ^= 0xFF;
    }

    let result = verify_pq_fn_dsa_unverified(
        message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "corrupted signature must yield Ok(false)");
}

#[test]
fn test_fn_dsa_sign_truncated_private_key_fails() {
    let (_public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let truncated_key = &private_key.expose_secret()[..100];

    let result = sign_pq_fn_dsa_unverified(message, truncated_key, FnDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should fail with truncated private key");
}

#[test]
fn test_fn_dsa_verify_wrong_public_key_fails() {
    let (_public_key_1, private_key_1) = generate_fn_dsa_keypair().expect("keypair generation");
    let (public_key_2, _private_key_2) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let signature = sign_pq_fn_dsa_unverified(
        message,
        private_key_1.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    // verify path collapses Err to Ok(false) (Pattern 6).
    let result = verify_pq_fn_dsa_unverified(
        message,
        &signature,
        public_key_2.as_slice(),
        FnDsaSecurityLevel::Level512,
    );
    assert_eq!(result.ok(), Some(false), "wrong public key must yield Ok(false)");
}

#[test]
fn test_fn_dsa_verify_junk_signature_fails() {
    let (public_key, _private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    // Create junk signature with reasonable length
    let junk_signature = vec![0x42u8; 1000];

    let result = verify_pq_fn_dsa_unverified(
        message,
        &junk_signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "junk signature must yield Ok(false)");
}

// ============================================================================
// Cross-Scheme Contamination Tests
// ============================================================================

#[test]
fn test_ml_dsa_signature_with_slh_dsa_verify_fails() {
    let (_ml_public_key, ml_private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");
    let (slh_public_key, _slh_private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let ml_signature = sign_pq_ml_dsa_unverified(
        message,
        ml_private_key.expose_secret(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("signing should succeed");

    // verify path collapses Err to Ok(false) (Pattern 6).
    let result = verify_pq_slh_dsa_unverified(
        message,
        &ml_signature,
        slh_public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    );
    assert_eq!(
        result.ok(),
        Some(false),
        "ML-DSA signature with SLH-DSA verify must yield Ok(false)"
    );
}

// ============================================================================
// Boundary Condition Tests
// ============================================================================

#[test]
fn test_ml_dsa_verify_single_byte_message_succeeds() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    let message = [0x42u8];
    let signature = sign_pq_ml_dsa_unverified(
        &message,
        private_key.expose_secret(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("signing should succeed");

    let valid = verify_pq_ml_dsa_unverified(
        &message,
        &signature,
        public_key.as_slice(),
        MlDsaParameterSet::MlDsa44,
    )
    .expect("verification should succeed");

    assert!(valid, "Single byte message should verify correctly");
}

#[test]
fn test_slh_dsa_verify_large_message_succeeds() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    // Test with 1KB message
    let message = vec![0xAAu8; 1024];
    let signature = sign_pq_slh_dsa_unverified(
        &message,
        private_key.expose_secret(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("signing should succeed");

    let valid = verify_pq_slh_dsa_unverified(
        &message,
        &signature,
        public_key.as_slice(),
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(valid, "Large message should verify correctly");
}

#[test]
fn test_fn_dsa_verify_modified_single_bit_fails() {
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message with single bit flip";
    let signature = sign_pq_fn_dsa_unverified(
        message,
        private_key.expose_secret(),
        FnDsaSecurityLevel::Level512,
    )
    .expect("signing should succeed");

    // Modify a single bit in the message
    let mut modified_message = message.to_vec();
    modified_message[0] ^= 0x01;

    let result = verify_pq_fn_dsa_unverified(
        &modified_message,
        &signature,
        public_key.as_slice(),
        FnDsaSecurityLevel::Level512,
    );
    // verify path collapses Err to Ok(false) (Pattern 6).
    assert_eq!(result.ok(), Some(false), "single-bit modification must yield Ok(false)");
}
