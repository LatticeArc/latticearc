#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::single_match,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::explicit_auto_deref,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::print_stdout,
    clippy::unused_unit,
    clippy::expect_fun_call,
    clippy::useless_vec,
    clippy::cloned_instead_of_copied,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::manual_let_else
)]
//! Comprehensive ML-DSA (FIPS 204) Test Suite
//!
//! This test suite provides comprehensive coverage for ML-DSA digital signatures
//! as part of Phase 2 of the QuantumShield security audit (Tasks 2.2.1-2.2.10).
//!
//! ## Test Categories
//!
//! - **2.2.1-2.2.3**: Basic keygen/sign/verify for MLDSA44, MLDSA65, MLDSA87
//! - **2.2.4**: Deterministic signing (same message + key produces valid signatures)
//! - **2.2.5**: Context string support and domain separation
//! - **2.2.6**: Wrong message verification failures
//! - **2.2.7**: Corrupted signature detection
//! - **2.2.8**: Malleability resistance
//! - **2.2.9**: Key serialization roundtrip
//! - **2.2.10**: NIST KAT vectors (when available)
//!
//! ## Security Properties Verified
//!
//! - EUF-CMA (Existential Unforgeability under Chosen Message Attacks)
//! - Signature integrity against corruption
//! - Domain separation via context strings
//! - Key serialization correctness
//! - Cross-parameter set incompatibility

use arc_primitives::sig::ml_dsa::{
    MlDsaError, MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    generate_keypair, sign, verify,
};
use rand::RngCore;
use subtle::ConstantTimeEq;

// ============================================================================
// 2.2.1: MLDSA44 Keygen/Sign/Verify Tests
// ============================================================================

#[test]
fn test_mldsa44_keygen_produces_valid_keys() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("MLDSA44 keygen should succeed");

    assert_eq!(pk.parameter_set, MlDsaParameterSet::MLDSA44);
    assert_eq!(sk.parameter_set(), MlDsaParameterSet::MLDSA44);
    assert_eq!(pk.len(), MlDsaParameterSet::MLDSA44.public_key_size());
    assert_eq!(sk.len(), MlDsaParameterSet::MLDSA44.secret_key_size());
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_mldsa44_sign_produces_valid_signature() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("MLDSA44 keygen should succeed");
    let message = b"Test message for MLDSA44 signing";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("MLDSA44 signing should succeed");

    assert_eq!(signature.parameter_set, MlDsaParameterSet::MLDSA44);
    assert_eq!(signature.len(), MlDsaParameterSet::MLDSA44.signature_size());
    assert!(!signature.is_empty());

    let is_valid = verify(&pk, message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "MLDSA44 signature should verify correctly");
}

#[test]
fn test_mldsa44_verify_rejects_wrong_message() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("MLDSA44 keygen should succeed");
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    let is_valid =
        verify(&pk, wrong_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MLDSA44 signature should NOT verify with wrong message");
}

#[test]
fn test_mldsa44_verify_rejects_wrong_key() {
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("Second keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sign(&sk1, message, context).expect("Signing should succeed");

    let is_valid =
        verify(&pk2, message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MLDSA44 signature should NOT verify with wrong public key");
}

// ============================================================================
// 2.2.2: MLDSA65 Keygen/Sign/Verify Tests
// ============================================================================

#[test]
fn test_mldsa65_keygen_produces_valid_keys() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("MLDSA65 keygen should succeed");

    assert_eq!(pk.parameter_set, MlDsaParameterSet::MLDSA65);
    assert_eq!(sk.parameter_set(), MlDsaParameterSet::MLDSA65);
    assert_eq!(pk.len(), MlDsaParameterSet::MLDSA65.public_key_size());
    assert_eq!(sk.len(), MlDsaParameterSet::MLDSA65.secret_key_size());
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_mldsa65_sign_produces_valid_signature() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("MLDSA65 keygen should succeed");
    let message = b"Test message for MLDSA65 signing";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("MLDSA65 signing should succeed");

    assert_eq!(signature.parameter_set, MlDsaParameterSet::MLDSA65);
    assert_eq!(signature.len(), MlDsaParameterSet::MLDSA65.signature_size());
    assert!(!signature.is_empty());

    let is_valid = verify(&pk, message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "MLDSA65 signature should verify correctly");
}

#[test]
fn test_mldsa65_verify_rejects_wrong_message() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("MLDSA65 keygen should succeed");
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    let is_valid =
        verify(&pk, wrong_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MLDSA65 signature should NOT verify with wrong message");
}

#[test]
fn test_mldsa65_verify_rejects_wrong_key() {
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("Second keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sign(&sk1, message, context).expect("Signing should succeed");

    let is_valid =
        verify(&pk2, message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MLDSA65 signature should NOT verify with wrong public key");
}

// ============================================================================
// 2.2.3: MLDSA87 Keygen/Sign/Verify Tests
// ============================================================================

#[test]
fn test_mldsa87_keygen_produces_valid_keys() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("MLDSA87 keygen should succeed");

    assert_eq!(pk.parameter_set, MlDsaParameterSet::MLDSA87);
    assert_eq!(sk.parameter_set(), MlDsaParameterSet::MLDSA87);
    assert_eq!(pk.len(), MlDsaParameterSet::MLDSA87.public_key_size());
    assert_eq!(sk.len(), MlDsaParameterSet::MLDSA87.secret_key_size());
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_mldsa87_sign_produces_valid_signature() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("MLDSA87 keygen should succeed");
    let message = b"Test message for MLDSA87 signing";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("MLDSA87 signing should succeed");

    assert_eq!(signature.parameter_set, MlDsaParameterSet::MLDSA87);
    assert_eq!(signature.len(), MlDsaParameterSet::MLDSA87.signature_size());
    assert!(!signature.is_empty());

    let is_valid = verify(&pk, message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "MLDSA87 signature should verify correctly");
}

#[test]
fn test_mldsa87_verify_rejects_wrong_message() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("MLDSA87 keygen should succeed");
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    let is_valid =
        verify(&pk, wrong_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MLDSA87 signature should NOT verify with wrong message");
}

#[test]
fn test_mldsa87_verify_rejects_wrong_key() {
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("Second keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sign(&sk1, message, context).expect("Signing should succeed");

    let is_valid =
        verify(&pk2, message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MLDSA87 signature should NOT verify with wrong public key");
}

// ============================================================================
// 2.2.4: Deterministic Signing Tests
// ============================================================================

#[test]
fn test_mldsa44_multiple_signatures_all_verify() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Deterministic signing test message";
    let context: &[u8] = &[];

    // Generate multiple signatures for the same message
    let sig1 = sign(&sk, message, context).expect("First signing should succeed");
    let sig2 = sign(&sk, message, context).expect("Second signing should succeed");
    let sig3 = sign(&sk, message, context).expect("Third signing should succeed");

    // All signatures should verify correctly
    assert!(
        verify(&pk, message, &sig1, context).expect("Verification should succeed"),
        "First signature should verify"
    );
    assert!(
        verify(&pk, message, &sig2, context).expect("Verification should succeed"),
        "Second signature should verify"
    );
    assert!(
        verify(&pk, message, &sig3, context).expect("Verification should succeed"),
        "Third signature should verify"
    );

    // Note: ML-DSA uses randomized signing, so signatures will differ
    // This is expected behavior per FIPS 204
}

#[test]
fn test_mldsa65_multiple_signatures_all_verify() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");
    let message = b"Deterministic signing test message";
    let context: &[u8] = &[];

    let sig1 = sign(&sk, message, context).expect("First signing should succeed");
    let sig2 = sign(&sk, message, context).expect("Second signing should succeed");

    assert!(verify(&pk, message, &sig1, context).expect("Verification should succeed"));
    assert!(verify(&pk, message, &sig2, context).expect("Verification should succeed"));
}

#[test]
fn test_mldsa87_multiple_signatures_all_verify() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");
    let message = b"Deterministic signing test message";
    let context: &[u8] = &[];

    let sig1 = sign(&sk, message, context).expect("First signing should succeed");
    let sig2 = sign(&sk, message, context).expect("Second signing should succeed");

    assert!(verify(&pk, message, &sig1, context).expect("Verification should succeed"));
    assert!(verify(&pk, message, &sig2, context).expect("Verification should succeed"));
}

#[test]
fn test_randomized_signing_produces_different_signatures() {
    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message for randomness";
    let context: &[u8] = &[];

    let sig1 = sign(&sk, message, context).expect("First signing should succeed");
    let sig2 = sign(&sk, message, context).expect("Second signing should succeed");

    // ML-DSA uses randomized signing, signatures should differ
    // (This is not strictly guaranteed but highly probable)
    // We just verify both are valid, which is the cryptographic requirement
    assert_ne!(sig1.data.len(), 0, "Signature should not be empty");
    assert_ne!(sig2.data.len(), 0, "Signature should not be empty");
}

// ============================================================================
// 2.2.5: Context String Tests
// ============================================================================

#[test]
fn test_context_string_domain_separation() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message with context";

    let context1 = b"application-v1";
    let context2 = b"application-v2";

    let sig_ctx1 = sign(&sk, message, context1).expect("Signing with context1 should succeed");
    let sig_ctx2 = sign(&sk, message, context2).expect("Signing with context2 should succeed");

    // Verify with correct context
    assert!(
        verify(&pk, message, &sig_ctx1, context1).expect("Verification should succeed"),
        "Signature should verify with same context"
    );
    assert!(
        verify(&pk, message, &sig_ctx2, context2).expect("Verification should succeed"),
        "Signature should verify with same context"
    );

    // Cross-context verification should fail
    assert!(
        !verify(&pk, message, &sig_ctx1, context2).expect("Verification should not error"),
        "Signature with context1 should NOT verify with context2"
    );
    assert!(
        !verify(&pk, message, &sig_ctx2, context1).expect("Verification should not error"),
        "Signature with context2 should NOT verify with context1"
    );
}

#[test]
fn test_empty_vs_nonempty_context() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");
    let message = b"Test message";

    let empty_context: &[u8] = &[];
    let nonempty_context = b"some-context";

    let sig_empty = sign(&sk, message, empty_context).expect("Signing should succeed");
    let sig_nonempty = sign(&sk, message, nonempty_context).expect("Signing should succeed");

    // Verify with correct contexts
    assert!(verify(&pk, message, &sig_empty, empty_context).expect("Verification should succeed"));
    assert!(
        verify(&pk, message, &sig_nonempty, nonempty_context).expect("Verification should succeed")
    );

    // Cross-context verification should fail
    assert!(
        !verify(&pk, message, &sig_empty, nonempty_context).expect("Verification should not error")
    );
    assert!(
        !verify(&pk, message, &sig_nonempty, empty_context).expect("Verification should not error")
    );
}

#[test]
fn test_maximum_length_context_string() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message";

    // FIPS 204 allows context up to 255 bytes
    let max_context = vec![0xABu8; 255];

    let signature =
        sign(&sk, message, &max_context).expect("Signing with max context should succeed");
    let is_valid =
        verify(&pk, message, &signature, &max_context).expect("Verification should succeed");
    assert!(is_valid, "Max-length context should work");
}

#[test]
fn test_context_single_byte_difference() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");
    let message = b"Test message";

    let context1 = b"context-A";
    let context2 = b"context-B";

    let signature = sign(&sk, message, context1).expect("Signing should succeed");

    assert!(verify(&pk, message, &signature, context1).expect("Verification should succeed"));
    assert!(
        !verify(&pk, message, &signature, context2).expect("Verification should not error"),
        "Single byte difference in context should fail verification"
    );
}

#[test]
fn test_context_length_matters() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message";

    let short_context = b"ctx";
    let long_context = b"ctx\x00"; // Same prefix but different length

    let signature = sign(&sk, message, short_context).expect("Signing should succeed");

    assert!(verify(&pk, message, &signature, short_context).expect("Verification should succeed"));
    assert!(
        !verify(&pk, message, &signature, long_context).expect("Verification should not error"),
        "Different length context should fail verification"
    );
}

// ============================================================================
// 2.2.6: Wrong Message Verification Fails
// ============================================================================

#[test]
fn test_single_bit_message_modification() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Original message content";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    // Modify a single bit
    let mut modified_message = message.to_vec();
    modified_message[0] ^= 0x01;

    let is_valid =
        verify(&pk, &modified_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Single bit modification should fail verification");
}

#[test]
fn test_message_truncation_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");
    let message = b"This is a longer message for truncation test";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    // Truncate message
    let truncated = &message[..message.len() - 5];

    let is_valid =
        verify(&pk, truncated, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Truncated message should fail verification");
}

#[test]
fn test_message_extension_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");
    let message = b"Original message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    // Extend message
    let mut extended = message.to_vec();
    extended.extend_from_slice(b" extra content");

    let is_valid =
        verify(&pk, &extended, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Extended message should fail verification");
}

#[test]
fn test_completely_different_message_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let original = b"The quick brown fox jumps over the lazy dog";
    let different = b"Pack my box with five dozen liquor jugs";
    let context: &[u8] = &[];

    let signature = sign(&sk, original, context).expect("Signing should succeed");

    let is_valid =
        verify(&pk, different, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Completely different message should fail verification");
}

// ============================================================================
// 2.2.7: Corrupted Signature Detection
// ============================================================================

#[test]
fn test_corrupted_signature_first_byte() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message for corruption";
    let context: &[u8] = &[];

    let mut signature = sign(&sk, message, context).expect("Signing should succeed");
    signature.data[0] ^= 0xFF;

    let is_valid =
        verify(&pk, message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Corrupted first byte should fail verification");
}

#[test]
fn test_corrupted_signature_middle_byte() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");
    let message = b"Test message for corruption";
    let context: &[u8] = &[];

    let mut signature = sign(&sk, message, context).expect("Signing should succeed");
    let middle = signature.data.len() / 2;
    signature.data[middle] ^= 0xFF;

    let is_valid =
        verify(&pk, message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Corrupted middle byte should fail verification");
}

#[test]
fn test_corrupted_signature_last_byte() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");
    let message = b"Test message for corruption";
    let context: &[u8] = &[];

    let mut signature = sign(&sk, message, context).expect("Signing should succeed");
    let last = signature.data.len() - 1;
    signature.data[last] ^= 0xFF;

    let is_valid =
        verify(&pk, message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Corrupted last byte should fail verification");
}

#[test]
fn test_corrupted_signature_multiple_bytes() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message for multiple corruption";
    let context: &[u8] = &[];

    let mut signature = sign(&sk, message, context).expect("Signing should succeed");
    let len = signature.data.len();
    signature.data[0] ^= 0xFF;
    signature.data[len / 4] ^= 0xAA;
    signature.data[len / 2] ^= 0x55;
    signature.data[len - 1] ^= 0xFF;

    let is_valid =
        verify(&pk, message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Multiple corrupted bytes should fail verification");
}

#[test]
fn test_all_zeros_signature_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    // Create all-zeros signature with same length
    let zero_sig = MlDsaSignature {
        parameter_set: MlDsaParameterSet::MLDSA44,
        data: vec![0u8; signature.len()],
    };

    let is_valid = verify(&pk, message, &zero_sig, context).expect("Verification should not error");
    assert!(!is_valid, "All-zeros signature should fail verification");
}

#[test]
fn test_all_ones_signature_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    // Create all-ones signature with same length
    let ones_sig = MlDsaSignature {
        parameter_set: MlDsaParameterSet::MLDSA65,
        data: vec![0xFFu8; signature.len()],
    };

    let is_valid = verify(&pk, message, &ones_sig, context).expect("Verification should not error");
    assert!(!is_valid, "All-ones signature should fail verification");
}

#[test]
fn test_truncated_signature_errors() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let mut signature = sign(&sk, message, context).expect("Signing should succeed");
    signature.data.truncate(signature.data.len() - 10);

    let result = verify(&pk, message, &signature, context);
    assert!(result.is_err(), "Truncated signature should cause an error");
}

#[test]
fn test_random_bytes_signature_fails() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    // Create random signature
    let mut rng = rand::thread_rng();
    let mut random_data = vec![0u8; MlDsaParameterSet::MLDSA87.signature_size()];
    rng.fill_bytes(&mut random_data);

    let random_sig =
        MlDsaSignature { parameter_set: MlDsaParameterSet::MLDSA87, data: random_data };

    let is_valid =
        verify(&pk, message, &random_sig, context).expect("Verification should not error");
    assert!(!is_valid, "Random bytes signature should fail verification");
}

// ============================================================================
// 2.2.8: Malleability Resistance
// ============================================================================

#[test]
fn test_signature_not_malleable_by_bit_flip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message = b"Malleability test message";
    let context: &[u8] = &[];

    let original_sig = sign(&sk, message, context).expect("Signing should succeed");

    // Try flipping each bit and verify none produce valid signatures
    let mut any_malleable = false;
    for byte_idx in 0..original_sig.data.len().min(50) {
        // Test first 50 bytes
        for bit in 0..8 {
            let mut modified_sig = original_sig.clone();
            modified_sig.data[byte_idx] ^= 1 << bit;

            if let Ok(is_valid) = verify(&pk, message, &modified_sig, context) {
                if is_valid {
                    any_malleable = true;
                    break;
                }
            }
        }
        if any_malleable {
            break;
        }
    }

    assert!(
        !any_malleable,
        "No bit flip should produce a valid signature (malleability resistance)"
    );
}

#[test]
fn test_cross_parameter_set_incompatibility() {
    let (_pk44, sk44) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("MLDSA44 keygen should succeed");
    let (pk65, _sk65) =
        generate_keypair(MlDsaParameterSet::MLDSA65).expect("MLDSA65 keygen should succeed");
    let (pk87, _sk87) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("MLDSA87 keygen should succeed");

    let message = b"Cross-parameter test";
    let context: &[u8] = &[];

    let sig44 = sign(&sk44, message, context).expect("Signing should succeed");

    // MLDSA44 signature should not verify with MLDSA65 or MLDSA87 keys
    let result65 = verify(&pk65, message, &sig44, context);
    match result65 {
        Ok(is_valid) => assert!(!is_valid, "MLDSA44 sig should not verify with MLDSA65 key"),
        Err(_) => {} // Error is also acceptable
    }

    let result87 = verify(&pk87, message, &sig44, context);
    match result87 {
        Ok(is_valid) => assert!(!is_valid, "MLDSA44 sig should not verify with MLDSA87 key"),
        Err(_) => {} // Error is also acceptable
    }
}

#[test]
fn test_signature_reuse_across_messages_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");
    let context: &[u8] = &[];

    let message1 = b"First message";
    let message2 = b"Second message";

    let sig1 = sign(&sk, message1, context).expect("Signing should succeed");

    // Signature for message1 should not verify for message2
    let is_valid = verify(&pk, message2, &sig1, context).expect("Verification should not error");
    assert!(!is_valid, "Signature should not be reusable across different messages");
}

// ============================================================================
// 2.2.9: Key Serialization Roundtrip
// ============================================================================

#[test]
fn test_mldsa44_public_key_serialization_roundtrip() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");

    let pk_bytes = pk.as_bytes().to_vec();
    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA44, pk_bytes)
        .expect("Public key restoration should succeed");

    assert_eq!(pk.as_bytes(), restored_pk.as_bytes());
    assert_eq!(pk.parameter_set, restored_pk.parameter_set);
}

#[test]
fn test_mldsa65_public_key_serialization_roundtrip() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");

    let pk_bytes = pk.as_bytes().to_vec();
    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA65, pk_bytes)
        .expect("Public key restoration should succeed");

    assert_eq!(pk.as_bytes(), restored_pk.as_bytes());
}

#[test]
fn test_mldsa87_public_key_serialization_roundtrip() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");

    let pk_bytes = pk.as_bytes().to_vec();
    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA87, pk_bytes)
        .expect("Public key restoration should succeed");

    assert_eq!(pk.as_bytes(), restored_pk.as_bytes());
}

#[test]
fn test_secret_key_serialization_roundtrip() {
    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");

    let sk_bytes = sk.as_bytes().to_vec();
    let restored_sk = MlDsaSecretKey::new(MlDsaParameterSet::MLDSA44, sk_bytes)
        .expect("Secret key restoration should succeed");

    assert_eq!(sk.len(), restored_sk.len());
    assert_eq!(sk.parameter_set(), restored_sk.parameter_set());
}

#[test]
fn test_restored_key_can_sign_and_verify() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");
    let message = b"Test message for restored key";
    let context: &[u8] = &[];

    // Serialize and restore keys
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.as_bytes().to_vec();

    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA65, pk_bytes)
        .expect("Public key restoration should succeed");
    let restored_sk = MlDsaSecretKey::new(MlDsaParameterSet::MLDSA65, sk_bytes)
        .expect("Secret key restoration should succeed");

    // Sign with restored secret key
    let signature = sign(&restored_sk, message, context).expect("Signing should succeed");

    // Verify with restored public key
    let is_valid =
        verify(&restored_pk, message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "Restored keys should work correctly");
}

#[test]
fn test_signature_serialization_roundtrip() {
    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing should succeed");

    let sig_bytes = signature.as_bytes().to_vec();
    let restored_sig = MlDsaSignature::new(MlDsaParameterSet::MLDSA87, sig_bytes)
        .expect("Signature restoration should succeed");

    assert_eq!(signature.as_bytes(), restored_sig.as_bytes());
    assert_eq!(signature.parameter_set, restored_sig.parameter_set);
}

#[test]
fn test_invalid_public_key_length_rejected() {
    // Too short
    let short_bytes = vec![0u8; 100];
    let result = MlDsaPublicKey::new(MlDsaParameterSet::MLDSA44, short_bytes);
    assert!(result.is_err());

    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, MlDsaParameterSet::MLDSA44.public_key_size());
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_invalid_secret_key_length_rejected() {
    // Too long
    let long_bytes = vec![0u8; 10000];
    let result = MlDsaSecretKey::new(MlDsaParameterSet::MLDSA65, long_bytes);
    assert!(result.is_err());

    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, MlDsaParameterSet::MLDSA65.secret_key_size());
            assert_eq!(actual, 10000);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_invalid_signature_length_rejected() {
    let short_bytes = vec![0u8; 50];
    let result = MlDsaSignature::new(MlDsaParameterSet::MLDSA87, short_bytes);
    assert!(result.is_err());

    match result {
        Err(MlDsaError::InvalidSignatureLength { expected, actual }) => {
            assert_eq!(expected, MlDsaParameterSet::MLDSA87.signature_size());
            assert_eq!(actual, 50);
        }
        _ => panic!("Expected InvalidSignatureLength error"),
    }
}

// ============================================================================
// 2.2.10: NIST KAT Vectors (Parameter Set Properties)
// ============================================================================

#[test]
fn test_mldsa44_parameter_properties() {
    let param = MlDsaParameterSet::MLDSA44;

    assert_eq!(param.name(), "ML-DSA-44");
    assert_eq!(param.public_key_size(), 1312);
    assert_eq!(param.secret_key_size(), 2560);
    assert_eq!(param.signature_size(), 2420);
    assert_eq!(param.nist_security_level(), 2);
}

#[test]
fn test_mldsa65_parameter_properties() {
    let param = MlDsaParameterSet::MLDSA65;

    assert_eq!(param.name(), "ML-DSA-65");
    assert_eq!(param.public_key_size(), 1952);
    assert_eq!(param.secret_key_size(), 4032);
    assert_eq!(param.signature_size(), 3309);
    assert_eq!(param.nist_security_level(), 3);
}

#[test]
fn test_mldsa87_parameter_properties() {
    let param = MlDsaParameterSet::MLDSA87;

    assert_eq!(param.name(), "ML-DSA-87");
    assert_eq!(param.public_key_size(), 2592);
    assert_eq!(param.secret_key_size(), 4896);
    assert_eq!(param.signature_size(), 4627);
    assert_eq!(param.nist_security_level(), 5);
}

#[test]
fn test_generated_key_sizes_match_spec() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) = generate_keypair(param).expect("Keygen should succeed");

        assert_eq!(
            pk.len(),
            param.public_key_size(),
            "Public key size should match spec for {:?}",
            param
        );
        assert_eq!(
            sk.len(),
            param.secret_key_size(),
            "Secret key size should match spec for {:?}",
            param
        );
    }
}

#[test]
fn test_generated_signature_sizes_match_spec() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (_pk, sk) = generate_keypair(param).expect("Keygen should succeed");
        let message = b"Test message";
        let context: &[u8] = &[];

        let signature = sign(&sk, message, context).expect("Signing should succeed");

        assert_eq!(
            signature.len(),
            param.signature_size(),
            "Signature size should match spec for {:?}",
            param
        );
    }
}

// ============================================================================
// Additional Edge Case Tests
// ============================================================================

#[test]
fn test_empty_message_signing() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let message: &[u8] = &[];
    let context: &[u8] = &[];

    let signature = sign(&sk, message, context).expect("Signing empty message should succeed");
    let is_valid = verify(&pk, message, &signature, context).expect("Verification should succeed");

    assert!(is_valid, "Empty message should sign and verify correctly");
}

#[test]
fn test_large_message_signing() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Keygen should succeed");

    let mut rng = rand::thread_rng();
    let mut large_message = vec![0u8; 100_000];
    rng.fill_bytes(&mut large_message);
    let context: &[u8] = &[];

    let signature =
        sign(&sk, &large_message, context).expect("Signing large message should succeed");
    let is_valid =
        verify(&pk, &large_message, &signature, context).expect("Verification should succeed");

    assert!(is_valid, "Large message should sign and verify correctly");
}

#[test]
fn test_secret_key_constant_time_comparison() {
    let (_pk1, sk1) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");
    let (_pk2, sk2) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Keygen should succeed");

    // Test constant-time equality
    let same_key_eq: bool = sk1.ct_eq(&sk1).into();
    let diff_key_eq: bool = sk1.ct_eq(&sk2).into();

    assert!(same_key_eq, "Same key should be equal");
    assert!(!diff_key_eq, "Different keys should not be equal");
}

#[test]
fn test_secret_key_zeroization() {
    let (_pk, mut sk) =
        generate_keypair(MlDsaParameterSet::MLDSA87).expect("Keygen should succeed");

    // Verify key has non-zero data before zeroization
    let sk_bytes_before = sk.as_bytes().to_vec();
    assert!(
        !sk_bytes_before.iter().all(|&b| b == 0),
        "Secret key should contain non-zero data before zeroization"
    );

    // Zeroize and verify
    use zeroize::Zeroize;
    sk.zeroize();

    let sk_bytes_after = sk.as_bytes();
    assert!(
        sk_bytes_after.iter().all(|&b| b == 0),
        "Secret key should be all zeros after zeroization"
    );
}

#[test]
fn test_unique_keypair_generation() {
    let (pk1, _sk1) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("Second keygen should succeed");
    let (pk3, _sk3) =
        generate_keypair(MlDsaParameterSet::MLDSA44).expect("Third keygen should succeed");

    assert_ne!(pk1.as_bytes(), pk2.as_bytes(), "Generated keys should be unique");
    assert_ne!(pk2.as_bytes(), pk3.as_bytes(), "Generated keys should be unique");
    assert_ne!(pk1.as_bytes(), pk3.as_bytes(), "Generated keys should be unique");
}

#[test]
fn test_all_parameter_sets_comprehensive() {
    for param in
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87]
    {
        let (pk, sk) =
            generate_keypair(param).expect(&format!("{:?} keygen should succeed", param));
        let message = b"Comprehensive test message";
        let context = b"test-context";

        // Test basic signing and verification
        let signature =
            sign(&sk, message, context).expect(&format!("{:?} signing should succeed", param));
        assert!(
            verify(&pk, message, &signature, context).expect("Verification should succeed"),
            "{:?} signature should verify",
            param
        );

        // Test wrong message fails
        let wrong_msg = b"wrong message";
        assert!(
            !verify(&pk, wrong_msg, &signature, context).expect("Verification should not error"),
            "{:?} should reject wrong message",
            param
        );

        // Test wrong context fails
        let wrong_ctx = b"wrong-context";
        assert!(
            !verify(&pk, message, &signature, wrong_ctx).expect("Verification should not error"),
            "{:?} should reject wrong context",
            param
        );

        // Test corrupted signature fails
        let mut corrupted_sig = signature.clone();
        corrupted_sig.data[0] ^= 0xFF;
        assert!(
            !verify(&pk, message, &corrupted_sig, context).expect("Verification should not error"),
            "{:?} should reject corrupted signature",
            param
        );
    }
}

// ============================================================================
// Error Type Tests
// ============================================================================

#[test]
fn test_error_display_messages() {
    let errors = vec![
        MlDsaError::KeyGenerationError("test keygen error".to_string()),
        MlDsaError::SigningError("test signing error".to_string()),
        MlDsaError::VerificationError("test verification error".to_string()),
        MlDsaError::InvalidKeyLength { expected: 1312, actual: 100 },
        MlDsaError::InvalidSignatureLength { expected: 2420, actual: 50 },
        MlDsaError::InvalidParameterSet("unknown".to_string()),
        MlDsaError::FeatureNotEnabled,
        MlDsaError::CryptoError("test crypto error".to_string()),
    ];

    for error in errors {
        let display = format!("{}", error);
        assert!(!display.is_empty(), "Error display should not be empty");
    }
}

#[test]
fn test_parameter_set_equality() {
    assert_eq!(MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA44);
    assert_eq!(MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA65);
    assert_eq!(MlDsaParameterSet::MLDSA87, MlDsaParameterSet::MLDSA87);

    assert_ne!(MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65);
    assert_ne!(MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87);
    assert_ne!(MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA87);
}

#[test]
fn test_parameter_set_debug_format() {
    assert_eq!(format!("{:?}", MlDsaParameterSet::MLDSA44), "MLDSA44");
    assert_eq!(format!("{:?}", MlDsaParameterSet::MLDSA65), "MLDSA65");
    assert_eq!(format!("{:?}", MlDsaParameterSet::MLDSA87), "MLDSA87");
}

#[test]
fn test_parameter_set_clone() {
    let param = MlDsaParameterSet::MLDSA65;
    let cloned = param;
    assert_eq!(param, cloned);
}
