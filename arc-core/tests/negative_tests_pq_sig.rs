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
    convenience::{
        generate_fn_dsa_keypair, generate_ml_dsa_keypair, generate_slh_dsa_keypair,
        sign_pq_fn_dsa_unverified, sign_pq_ml_dsa_unverified, sign_pq_slh_dsa_unverified,
        verify_pq_fn_dsa_unverified, verify_pq_ml_dsa_unverified, verify_pq_slh_dsa_unverified,
    },
    error::CoreError,
};
use arc_primitives::sig::{
    ml_dsa::MlDsaParameterSet, slh_dsa::SecurityLevel as SlhDsaSecurityLevel,
};

// ============================================================================
// ML-DSA Negative Tests - Empty Inputs
// ============================================================================

#[test]
fn test_ml_dsa_sign_empty_message() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    // Signing empty message should succeed (valid use case)
    let result = sign_pq_ml_dsa_unverified(&[], private_key.as_ref(), MlDsaParameterSet::MLDSA44);
    assert!(result.is_ok(), "Signing empty message should succeed");
}

#[test]
fn test_ml_dsa_sign_empty_private_key() {
    let message = b"Test message";
    let empty_key = [];

    let result = sign_pq_ml_dsa_unverified(message, &empty_key, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err(), "Should fail with empty private key");
}

#[test]
fn test_ml_dsa_verify_empty_signature() {
    let (public_key, _private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Test message";
    let empty_signature = [];

    let result = verify_pq_ml_dsa_unverified(
        message,
        &empty_signature,
        &public_key,
        MlDsaParameterSet::MLDSA44,
    );
    assert!(result.is_err(), "Should fail with empty signature");
}

#[test]
fn test_ml_dsa_verify_empty_public_key() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_ref(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let empty_key = [];
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &empty_key, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err(), "Should fail with empty public key");
}

// ============================================================================
// ML-DSA Negative Tests - Invalid Key Lengths
// ============================================================================

#[test]
fn test_ml_dsa_sign_truncated_private_key() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Test message";
    let truncated_key = &private_key.as_ref()[..100];

    let result = sign_pq_ml_dsa_unverified(message, truncated_key, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err(), "Should fail with truncated private key");
}

#[test]
fn test_ml_dsa_verify_truncated_public_key() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_ref(), MlDsaParameterSet::MLDSA65)
            .expect("signing should succeed");

    let truncated_key = &public_key[..100];
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, truncated_key, MlDsaParameterSet::MLDSA65);
    assert!(result.is_err(), "Should fail with truncated public key");
}

#[test]
fn test_ml_dsa_verify_oversized_signature() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Test message";
    let mut signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_ref(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Add extra bytes to signature
    signature.extend_from_slice(&[0u8; 100]);

    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err(), "Should fail with oversized signature");
}

// ============================================================================
// ML-DSA Negative Tests - Corrupted Signatures
// ============================================================================

#[test]
fn test_ml_dsa_verify_corrupted_signature() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Test message";
    let mut signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_ref(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Corrupt the signature
    if signature.len() > 10 {
        signature[10] ^= 0xFF;
    }

    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err(), "Should fail with corrupted signature");

    match result {
        Err(CoreError::VerificationFailed) | Err(CoreError::InvalidInput(_)) => {
            // Expected error types
        }
        _ => panic!("Expected VerificationFailed or InvalidInput, got {:?}", result),
    }
}

#[test]
fn test_ml_dsa_verify_modified_message() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Original message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_ref(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let modified_message = b"Modified message";
    let result = verify_pq_ml_dsa_unverified(
        modified_message,
        &signature,
        &public_key,
        MlDsaParameterSet::MLDSA44,
    );
    assert!(result.is_err(), "Should fail when message is modified");

    match result {
        Err(CoreError::VerificationFailed) => {
            // Expected error
        }
        _ => panic!("Expected VerificationFailed, got {:?}", result),
    }
}

// ============================================================================
// ML-DSA Negative Tests - Wrong Parameter Sets
// ============================================================================

#[test]
fn test_ml_dsa_44_key_with_65_params() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Test message";
    // Try to sign with MLDSA44 key using MLDSA65 parameters
    let result =
        sign_pq_ml_dsa_unverified(message, private_key.as_ref(), MlDsaParameterSet::MLDSA65);
    assert!(result.is_err(), "Should fail with mismatched parameter set");
}

#[test]
fn test_ml_dsa_65_signature_with_87_verify() {
    let (_public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA65).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key.as_ref(), MlDsaParameterSet::MLDSA65)
            .expect("signing should succeed");

    let (public_key_87, _) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA87).expect("keypair generation");

    // Try to verify MLDSA65 signature with MLDSA87 key
    let result = verify_pq_ml_dsa_unverified(
        message,
        &signature,
        &public_key_87,
        MlDsaParameterSet::MLDSA87,
    );
    assert!(result.is_err(), "Should fail with mismatched parameter set");
}

#[test]
fn test_ml_dsa_verify_with_wrong_public_key() {
    let (_public_key_1, private_key_1) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");
    let (public_key_2, _private_key_2) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_ml_dsa_unverified(message, private_key_1.as_ref(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Try to verify with different public key
    let result =
        verify_pq_ml_dsa_unverified(message, &signature, &public_key_2, MlDsaParameterSet::MLDSA44);
    assert!(result.is_err(), "Should fail with wrong public key");

    match result {
        Err(CoreError::VerificationFailed) => {
            // Expected error
        }
        _ => panic!("Expected VerificationFailed, got {:?}", result),
    }
}

// ============================================================================
// SLH-DSA Negative Tests
// ============================================================================

#[test]
fn test_slh_dsa_sign_empty_private_key() {
    let message = b"Test message";
    let empty_key = [];

    let result = sign_pq_slh_dsa_unverified(message, &empty_key, SlhDsaSecurityLevel::Shake128s);
    assert!(result.is_err(), "Should fail with empty private key");
}

#[test]
fn test_slh_dsa_verify_empty_signature() {
    let (public_key, _private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let empty_signature = [];

    let result = verify_pq_slh_dsa_unverified(
        message,
        &empty_signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    );
    assert!(result.is_err(), "Should fail with empty signature");
}

#[test]
fn test_slh_dsa_verify_corrupted_signature() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let mut signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_ref(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    // Corrupt the signature
    if signature.len() > 50 {
        signature[50] ^= 0xFF;
    }

    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    );
    assert!(result.is_err(), "Should fail with corrupted signature");
}

#[test]
fn test_slh_dsa_verify_truncated_signature() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_slh_dsa_unverified(message, private_key.as_ref(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    // Truncate signature
    let truncated = &signature[..signature.len() / 2];

    let result = verify_pq_slh_dsa_unverified(
        message,
        truncated,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    );
    assert!(result.is_err(), "Should fail with truncated signature");
}

#[test]
fn test_slh_dsa_l1_key_with_l3_params() {
    let (_public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    // Try to sign with L1 key using L3 parameters
    let result =
        sign_pq_slh_dsa_unverified(message, private_key.as_ref(), SlhDsaSecurityLevel::Shake192s);
    assert!(result.is_err(), "Should fail with mismatched security level");
}

#[test]
fn test_slh_dsa_verify_wrong_public_key() {
    let (_public_key_1, private_key_1) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");
    let (public_key_2, _private_key_2) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_slh_dsa_unverified(message, private_key_1.as_ref(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    // Verify with different public key
    let result = verify_pq_slh_dsa_unverified(
        message,
        &signature,
        &public_key_2,
        SlhDsaSecurityLevel::Shake128s,
    );
    assert!(result.is_err(), "Should fail with wrong public key");
}

// ============================================================================
// FN-DSA Negative Tests
// ============================================================================

#[test]
fn test_fn_dsa_sign_empty_private_key() {
    let message = b"Test message";
    let empty_key = [];

    let result = sign_pq_fn_dsa_unverified(message, &empty_key);
    assert!(result.is_err(), "Should fail with empty private key");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_verify_empty_signature() {
    let (public_key, _private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let empty_signature = [];

    let result = verify_pq_fn_dsa_unverified(message, &empty_signature, &public_key);
    assert!(result.is_err(), "Should fail with empty signature");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_verify_corrupted_signature() {
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let mut signature =
        sign_pq_fn_dsa_unverified(message, private_key.as_ref()).expect("signing should succeed");

    // Corrupt the signature
    if signature.len() > 100 {
        signature[100] ^= 0xFF;
    }

    let result = verify_pq_fn_dsa_unverified(message, &signature, &public_key);
    assert!(result.is_err(), "Should fail with corrupted signature");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_verify_truncated_private_key() {
    let (_public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let truncated_key = &private_key.as_ref()[..100];

    let result = sign_pq_fn_dsa_unverified(message, truncated_key);
    assert!(result.is_err(), "Should fail with truncated private key");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_verify_wrong_public_key() {
    let (_public_key_1, private_key_1) = generate_fn_dsa_keypair().expect("keypair generation");
    let (public_key_2, _private_key_2) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    let signature =
        sign_pq_fn_dsa_unverified(message, private_key_1.as_ref()).expect("signing should succeed");

    // Verify with different public key
    let result = verify_pq_fn_dsa_unverified(message, &signature, &public_key_2);
    assert!(result.is_err(), "Should fail with wrong public key");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_verify_junk_signature() {
    let (public_key, _private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message";
    // Create junk signature with reasonable length
    let junk_signature = vec![0x42u8; 1000];

    let result = verify_pq_fn_dsa_unverified(message, &junk_signature, &public_key);
    assert!(result.is_err(), "Should fail with junk signature");
}

// ============================================================================
// Cross-Scheme Contamination Tests
// ============================================================================

#[test]
fn test_ml_dsa_signature_with_slh_dsa_verify() {
    let (_ml_public_key, ml_private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");
    let (slh_public_key, _slh_private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    let message = b"Test message";
    let ml_signature =
        sign_pq_ml_dsa_unverified(message, ml_private_key.as_ref(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    // Try to verify ML-DSA signature with SLH-DSA
    // This should fail due to key/signature format mismatch
    let result = verify_pq_slh_dsa_unverified(
        message,
        &ml_signature,
        &slh_public_key,
        SlhDsaSecurityLevel::Shake128s,
    );
    assert!(result.is_err(), "Should fail when mixing ML-DSA and SLH-DSA");
}

// ============================================================================
// Boundary Condition Tests
// ============================================================================

#[test]
fn test_ml_dsa_verify_single_byte_message() {
    let (public_key, private_key) =
        generate_ml_dsa_keypair(MlDsaParameterSet::MLDSA44).expect("keypair generation");

    let message = [0x42u8];
    let signature =
        sign_pq_ml_dsa_unverified(&message, private_key.as_ref(), MlDsaParameterSet::MLDSA44)
            .expect("signing should succeed");

    let valid =
        verify_pq_ml_dsa_unverified(&message, &signature, &public_key, MlDsaParameterSet::MLDSA44)
            .expect("verification should succeed");

    assert!(valid, "Single byte message should verify correctly");
}

#[test]
fn test_slh_dsa_verify_large_message() {
    let (public_key, private_key) =
        generate_slh_dsa_keypair(SlhDsaSecurityLevel::Shake128s).expect("keypair generation");

    // Test with 1KB message
    let message = vec![0xAAu8; 1024];
    let signature =
        sign_pq_slh_dsa_unverified(&message, private_key.as_ref(), SlhDsaSecurityLevel::Shake128s)
            .expect("signing should succeed");

    let valid = verify_pq_slh_dsa_unverified(
        &message,
        &signature,
        &public_key,
        SlhDsaSecurityLevel::Shake128s,
    )
    .expect("verification should succeed");

    assert!(valid, "Large message should verify correctly");
}

#[test]
#[ignore = "FN-DSA causes stack overflow in debug mode - run in release mode"]
fn test_fn_dsa_verify_modified_single_bit() {
    let (public_key, private_key) = generate_fn_dsa_keypair().expect("keypair generation");

    let message = b"Test message with single bit flip";
    let signature =
        sign_pq_fn_dsa_unverified(message, private_key.as_ref()).expect("signing should succeed");

    // Modify a single bit in the message
    let mut modified_message = message.to_vec();
    modified_message[0] ^= 0x01;

    let result = verify_pq_fn_dsa_unverified(&modified_message, &signature, &public_key);
    assert!(result.is_err(), "Should fail with single bit modification");
}
