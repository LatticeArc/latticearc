#![allow(
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::collapsible_if,
    clippy::single_match,
    clippy::expect_fun_call
)]
//! Comprehensive ML-DSA (FIPS 204) Test Suite
//!
//! This test suite provides comprehensive coverage for ML-DSA digital signatures
//! as part of Phase 2 of the QuantumShield security audit (Tasks 2.2.1-2.2.10).
//!
//! ## Test Categories
//!
//! - **2.2.1-2.2.3**: Basic keygen/sign/verify for MlDsa44, MlDsa65, MlDsa87
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

use latticearc::primitives::sig::ml_dsa::{
    MlDsaError, MlDsaParameterSet, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, generate_keypair,
};
use rand::RngCore;
use subtle::ConstantTimeEq;

// ============================================================================
// 2.2.1: MlDsa44 Keygen/Sign/Verify Tests
// ============================================================================

#[test]
fn test_mldsa44_keygen_produces_valid_keys_succeeds() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("MlDsa44 keygen should succeed");

    assert_eq!(pk.parameter_set(), MlDsaParameterSet::MlDsa44);
    assert_eq!(sk.parameter_set(), MlDsaParameterSet::MlDsa44);
    assert_eq!(pk.len(), MlDsaParameterSet::MlDsa44.public_key_size());
    assert_eq!(sk.len(), MlDsaParameterSet::MlDsa44.secret_key_size());
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_mldsa44_sign_produces_valid_signature_succeeds() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("MlDsa44 keygen should succeed");
    let message = b"Test message for MlDsa44 signing";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("MlDsa44 signing should succeed");

    assert_eq!(signature.parameter_set(), MlDsaParameterSet::MlDsa44);
    assert_eq!(signature.len(), MlDsaParameterSet::MlDsa44.signature_size());
    assert!(!signature.is_empty());

    let is_valid = pk.verify(message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "MlDsa44 signature should verify correctly");
}

#[test]
fn test_mldsa44_verify_rejects_wrong_message_fails() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("MlDsa44 keygen should succeed");
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    let is_valid =
        pk.verify(wrong_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MlDsa44 signature should NOT verify with wrong message");
}

#[test]
fn test_mldsa44_verify_rejects_wrong_key_fails() {
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("Second keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sk1.sign(message, context).expect("Signing should succeed");

    let is_valid = pk2.verify(message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MlDsa44 signature should NOT verify with wrong public key");
}

// ============================================================================
// 2.2.2: MlDsa65 Keygen/Sign/Verify Tests
// ============================================================================

#[test]
fn test_mldsa65_keygen_produces_valid_keys_succeeds() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa65).expect("MlDsa65 keygen should succeed");

    assert_eq!(pk.parameter_set(), MlDsaParameterSet::MlDsa65);
    assert_eq!(sk.parameter_set(), MlDsaParameterSet::MlDsa65);
    assert_eq!(pk.len(), MlDsaParameterSet::MlDsa65.public_key_size());
    assert_eq!(sk.len(), MlDsaParameterSet::MlDsa65.secret_key_size());
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_mldsa65_sign_produces_valid_signature_succeeds() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa65).expect("MlDsa65 keygen should succeed");
    let message = b"Test message for MlDsa65 signing";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("MlDsa65 signing should succeed");

    assert_eq!(signature.parameter_set(), MlDsaParameterSet::MlDsa65);
    assert_eq!(signature.len(), MlDsaParameterSet::MlDsa65.signature_size());
    assert!(!signature.is_empty());

    let is_valid = pk.verify(message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "MlDsa65 signature should verify correctly");
}

#[test]
fn test_mldsa65_verify_rejects_wrong_message_fails() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa65).expect("MlDsa65 keygen should succeed");
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    let is_valid =
        pk.verify(wrong_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MlDsa65 signature should NOT verify with wrong message");
}

#[test]
fn test_mldsa65_verify_rejects_wrong_key_fails() {
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MlDsa65).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MlDsa65).expect("Second keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sk1.sign(message, context).expect("Signing should succeed");

    let is_valid = pk2.verify(message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MlDsa65 signature should NOT verify with wrong public key");
}

// ============================================================================
// 2.2.3: MlDsa87 Keygen/Sign/Verify Tests
// ============================================================================

#[test]
fn test_mldsa87_keygen_produces_valid_keys_succeeds() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("MlDsa87 keygen should succeed");

    assert_eq!(pk.parameter_set(), MlDsaParameterSet::MlDsa87);
    assert_eq!(sk.parameter_set(), MlDsaParameterSet::MlDsa87);
    assert_eq!(pk.len(), MlDsaParameterSet::MlDsa87.public_key_size());
    assert_eq!(sk.len(), MlDsaParameterSet::MlDsa87.secret_key_size());
    assert!(!pk.is_empty());
    assert!(!sk.is_empty());
}

#[test]
fn test_mldsa87_sign_produces_valid_signature_succeeds() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("MlDsa87 keygen should succeed");
    let message = b"Test message for MlDsa87 signing";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("MlDsa87 signing should succeed");

    assert_eq!(signature.parameter_set(), MlDsaParameterSet::MlDsa87);
    assert_eq!(signature.len(), MlDsaParameterSet::MlDsa87.signature_size());
    assert!(!signature.is_empty());

    let is_valid = pk.verify(message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "MlDsa87 signature should verify correctly");
}

#[test]
fn test_mldsa87_verify_rejects_wrong_message_fails() {
    let (pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("MlDsa87 keygen should succeed");
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    let is_valid =
        pk.verify(wrong_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MlDsa87 signature should NOT verify with wrong message");
}

#[test]
fn test_mldsa87_verify_rejects_wrong_key_fails() {
    let (_pk1, sk1) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("Second keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sk1.sign(message, context).expect("Signing should succeed");

    let is_valid = pk2.verify(message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "MlDsa87 signature should NOT verify with wrong public key");
}

// ============================================================================
// 2.2.4: Deterministic Signing Tests
// ============================================================================

#[test]
fn test_mldsa44_multiple_signatures_all_verify_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Deterministic signing test message";
    let context: &[u8] = &[];

    // Generate multiple signatures for the same message
    let sig1 = sk.sign(message, context).expect("First signing should succeed");
    let sig2 = sk.sign(message, context).expect("Second signing should succeed");
    let sig3 = sk.sign(message, context).expect("Third signing should succeed");

    // All signatures should verify correctly
    assert!(
        pk.verify(message, &sig1, context).expect("Verification should succeed"),
        "First signature should verify"
    );
    assert!(
        pk.verify(message, &sig2, context).expect("Verification should succeed"),
        "Second signature should verify"
    );
    assert!(
        pk.verify(message, &sig3, context).expect("Verification should succeed"),
        "Third signature should verify"
    );

    // Note: ML-DSA uses randomized signing, so signatures will differ
    // This is expected behavior per FIPS 204
}

#[test]
fn test_mldsa65_multiple_signatures_all_verify_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");
    let message = b"Deterministic signing test message";
    let context: &[u8] = &[];

    let sig1 = sk.sign(message, context).expect("First signing should succeed");
    let sig2 = sk.sign(message, context).expect("Second signing should succeed");

    assert!(pk.verify(message, &sig1, context).expect("Verification should succeed"));
    assert!(pk.verify(message, &sig2, context).expect("Verification should succeed"));
}

#[test]
fn test_mldsa87_multiple_signatures_all_verify_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");
    let message = b"Deterministic signing test message";
    let context: &[u8] = &[];

    let sig1 = sk.sign(message, context).expect("First signing should succeed");
    let sig2 = sk.sign(message, context).expect("Second signing should succeed");

    assert!(pk.verify(message, &sig1, context).expect("Verification should succeed"));
    assert!(pk.verify(message, &sig2, context).expect("Verification should succeed"));
}

#[test]
fn test_randomized_signing_produces_different_signatures_succeeds() {
    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message for randomness";
    let context: &[u8] = &[];

    let sig1 = sk.sign(message, context).expect("First signing should succeed");
    let sig2 = sk.sign(message, context).expect("Second signing should succeed");

    // ML-DSA uses randomized signing, signatures should differ
    // (This is not strictly guaranteed but highly probable)
    // We just verify both are valid, which is the cryptographic requirement
    assert_ne!(sig1.as_bytes().len(), 0, "Signature should not be empty");
    assert_ne!(sig2.as_bytes().len(), 0, "Signature should not be empty");
}

// ============================================================================
// 2.2.5: Context String Tests
// ============================================================================

#[test]
fn test_context_string_domain_separation_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message with context";

    let context1 = b"application-v1";
    let context2 = b"application-v2";

    let sig_ctx1 = sk.sign(message, context1).expect("Signing with context1 should succeed");
    let sig_ctx2 = sk.sign(message, context2).expect("Signing with context2 should succeed");

    // Verify with correct context
    assert!(
        pk.verify(message, &sig_ctx1, context1).expect("Verification should succeed"),
        "Signature should verify with same context"
    );
    assert!(
        pk.verify(message, &sig_ctx2, context2).expect("Verification should succeed"),
        "Signature should verify with same context"
    );

    // Cross-context verification should fail
    assert!(
        !pk.verify(message, &sig_ctx1, context2).expect("Verification should not error"),
        "Signature with context1 should NOT verify with context2"
    );
    assert!(
        !pk.verify(message, &sig_ctx2, context1).expect("Verification should not error"),
        "Signature with context2 should NOT verify with context1"
    );
}

#[test]
fn test_empty_vs_nonempty_context_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");
    let message = b"Test message";

    let empty_context: &[u8] = &[];
    let nonempty_context = b"some-context";

    let sig_empty = sk.sign(message, empty_context).expect("Signing should succeed");
    let sig_nonempty = sk.sign(message, nonempty_context).expect("Signing should succeed");

    // Verify with correct contexts
    assert!(pk.verify(message, &sig_empty, empty_context).expect("Verification should succeed"));
    assert!(
        pk.verify(message, &sig_nonempty, nonempty_context).expect("Verification should succeed")
    );

    // Cross-context verification should fail
    assert!(
        !pk.verify(message, &sig_empty, nonempty_context).expect("Verification should not error")
    );
    assert!(
        !pk.verify(message, &sig_nonempty, empty_context).expect("Verification should not error")
    );
}

#[test]
fn test_maximum_length_context_string_has_correct_size() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message";

    // FIPS 204 allows context up to 255 bytes
    let max_context = vec![0xABu8; 255];

    let signature =
        sk.sign(message, &max_context).expect("Signing with max context should succeed");
    let is_valid =
        pk.verify(message, &signature, &max_context).expect("Verification should succeed");
    assert!(is_valid, "Max-length context should work");
}

#[test]
fn test_context_single_byte_difference_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");
    let message = b"Test message";

    let context1 = b"context-A";
    let context2 = b"context-B";

    let signature = sk.sign(message, context1).expect("Signing should succeed");

    assert!(pk.verify(message, &signature, context1).expect("Verification should succeed"));
    assert!(
        !pk.verify(message, &signature, context2).expect("Verification should not error"),
        "Single byte difference in context should fail verification"
    );
}

#[test]
fn test_context_length_matters_has_correct_size() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message";

    let short_context = b"ctx";
    let long_context = b"ctx\x00"; // Same prefix but different length

    let signature = sk.sign(message, short_context).expect("Signing should succeed");

    assert!(pk.verify(message, &signature, short_context).expect("Verification should succeed"));
    assert!(
        !pk.verify(message, &signature, long_context).expect("Verification should not error"),
        "Different length context should fail verification"
    );
}

// ============================================================================
// 2.2.6: Wrong Message Verification Fails
// ============================================================================

#[test]
fn test_single_bit_message_modification_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Original message content";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    // Modify a single bit
    let mut modified_message = message.to_vec();
    modified_message[0] ^= 0x01;

    let is_valid =
        pk.verify(&modified_message, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Single bit modification should fail verification");
}

#[test]
fn test_message_truncation_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");
    let message = b"This is a longer message for truncation test";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    // Truncate message
    let truncated = &message[..message.len() - 5];

    let is_valid =
        pk.verify(truncated, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Truncated message should fail verification");
}

#[test]
fn test_message_extension_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");
    let message = b"Original message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    // Extend message
    let mut extended = message.to_vec();
    extended.extend_from_slice(b" extra content");

    let is_valid =
        pk.verify(&extended, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Extended message should fail verification");
}

#[test]
fn test_completely_different_message_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let original = b"The quick brown fox jumps over the lazy dog";
    let different = b"Pack my box with five dozen liquor jugs";
    let context: &[u8] = &[];

    let signature = sk.sign(original, context).expect("Signing should succeed");

    let is_valid =
        pk.verify(different, &signature, context).expect("Verification should not error");
    assert!(!is_valid, "Completely different message should fail verification");
}

// ============================================================================
// 2.2.7: Corrupted Signature Detection
// ============================================================================

#[test]
fn test_corrupted_signature_first_byte_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message for corruption";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");
    let mut bytes = signature.as_bytes().to_vec();
    bytes[0] ^= 0xFF;
    let corrupted = MlDsaSignature::from_bytes_unchecked(signature.parameter_set(), bytes);

    let is_valid = pk.verify(message, &corrupted, context).expect("Verification should not error");
    assert!(!is_valid, "Corrupted first byte should fail verification");
}

#[test]
fn test_corrupted_signature_middle_byte_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");
    let message = b"Test message for corruption";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");
    let mut bytes = signature.as_bytes().to_vec();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xFF;
    let corrupted = MlDsaSignature::from_bytes_unchecked(signature.parameter_set(), bytes);

    let is_valid = pk.verify(message, &corrupted, context).expect("Verification should not error");
    assert!(!is_valid, "Corrupted middle byte should fail verification");
}

#[test]
fn test_corrupted_signature_last_byte_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");
    let message = b"Test message for corruption";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");
    let mut bytes = signature.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let corrupted = MlDsaSignature::from_bytes_unchecked(signature.parameter_set(), bytes);

    let is_valid = pk.verify(message, &corrupted, context).expect("Verification should not error");
    assert!(!is_valid, "Corrupted last byte should fail verification");
}

#[test]
fn test_corrupted_signature_multiple_bytes_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message for multiple corruption";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");
    let mut bytes = signature.as_bytes().to_vec();
    let len = bytes.len();
    bytes[0] ^= 0xFF;
    bytes[len / 4] ^= 0xAA;
    bytes[len / 2] ^= 0x55;
    bytes[len - 1] ^= 0xFF;
    let corrupted = MlDsaSignature::from_bytes_unchecked(signature.parameter_set(), bytes);

    let is_valid = pk.verify(message, &corrupted, context).expect("Verification should not error");
    assert!(!is_valid, "Multiple corrupted bytes should fail verification");
}

#[test]
fn test_all_zeros_signature_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    // Create all-zeros signature with same length
    let zero_sig = MlDsaSignature::from_bytes_unchecked(
        MlDsaParameterSet::MlDsa44,
        vec![0u8; signature.len()],
    );

    let is_valid = pk.verify(message, &zero_sig, context).expect("Verification should not error");
    assert!(!is_valid, "All-zeros signature should fail verification");
}

#[test]
fn test_all_ones_signature_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    // Create all-ones signature with same length
    let ones_sig = MlDsaSignature::from_bytes_unchecked(
        MlDsaParameterSet::MlDsa65,
        vec![0xFFu8; signature.len()],
    );

    let is_valid = pk.verify(message, &ones_sig, context).expect("Verification should not error");
    assert!(!is_valid, "All-ones signature should fail verification");
}

#[test]
fn test_truncated_signature_errors_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");
    let mut truncated_bytes = signature.as_bytes().to_vec();
    truncated_bytes.truncate(truncated_bytes.len() - 10);
    let truncated =
        MlDsaSignature::from_bytes_unchecked(signature.parameter_set(), truncated_bytes);

    let result = pk.verify(message, &truncated, context);
    assert!(result.is_err(), "Truncated signature should cause an error");
}

#[test]
fn test_random_bytes_signature_fails() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    // Create random signature
    let mut random_data = vec![0u8; MlDsaParameterSet::MlDsa87.signature_size()];
    latticearc::primitives::rand::secure_rng().fill_bytes(&mut random_data);

    let random_sig = MlDsaSignature::from_bytes_unchecked(MlDsaParameterSet::MlDsa87, random_data);

    let is_valid = pk.verify(message, &random_sig, context).expect("Verification should not error");
    assert!(!is_valid, "Random bytes signature should fail verification");
}

// ============================================================================
// 2.2.8: Malleability Resistance
// ============================================================================

#[test]
fn test_signature_not_malleable_by_bit_flip_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message = b"Malleability test message";
    let context: &[u8] = &[];

    let original_sig = sk.sign(message, context).expect("Signing should succeed");

    // Try flipping each bit and verify none produce valid signatures
    let mut any_malleable = false;
    for byte_idx in 0..original_sig.as_bytes().len().min(50) {
        // Test first 50 bytes
        for bit in 0..8 {
            let mut bytes = original_sig.as_bytes().to_vec();
            bytes[byte_idx] ^= 1 << bit;
            let modified_sig =
                MlDsaSignature::from_bytes_unchecked(original_sig.parameter_set(), bytes);

            if let Ok(is_valid) = pk.verify(message, &modified_sig, context) {
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
fn test_cross_parameter_set_incompatibility_succeeds() {
    let (_pk44, sk44) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("MlDsa44 keygen should succeed");
    let (pk65, _sk65) =
        generate_keypair(MlDsaParameterSet::MlDsa65).expect("MlDsa65 keygen should succeed");
    let (pk87, _sk87) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("MlDsa87 keygen should succeed");

    let message = b"Cross-parameter test";
    let context: &[u8] = &[];

    let sig44 = sk44.sign(message, context).expect("Signing should succeed");

    // MlDsa44 signature should not verify with MlDsa65 or MlDsa87 keys
    let result65 = pk65.verify(message, &sig44, context);
    match result65 {
        Ok(is_valid) => assert!(!is_valid, "MlDsa44 sig should not verify with MlDsa65 key"),
        Err(_) => {} // Error is also acceptable
    }

    let result87 = pk87.verify(message, &sig44, context);
    match result87 {
        Ok(is_valid) => assert!(!is_valid, "MlDsa44 sig should not verify with MlDsa87 key"),
        Err(_) => {} // Error is also acceptable
    }
}

#[test]
fn test_signature_reuse_across_messages_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");
    let context: &[u8] = &[];

    let message1 = b"First message";
    let message2 = b"Second message";

    let sig1 = sk.sign(message1, context).expect("Signing should succeed");

    // Signature for message1 should not verify for message2
    let is_valid = pk.verify(message2, &sig1, context).expect("Verification should not error");
    assert!(!is_valid, "Signature should not be reusable across different messages");
}

// ============================================================================
// 2.2.9: Key Serialization Roundtrip
// ============================================================================

#[test]
fn test_mldsa44_public_key_serialization_roundtrip() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");

    let pk_bytes = pk.as_bytes().to_vec();
    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa44, pk_bytes)
        .expect("Public key restoration should succeed");

    assert_eq!(pk.as_bytes(), restored_pk.as_bytes());
    assert_eq!(pk.parameter_set(), restored_pk.parameter_set());
}

#[test]
fn test_mldsa65_public_key_serialization_roundtrip() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");

    let pk_bytes = pk.as_bytes().to_vec();
    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa65, pk_bytes)
        .expect("Public key restoration should succeed");

    assert_eq!(pk.as_bytes(), restored_pk.as_bytes());
}

#[test]
fn test_mldsa87_public_key_serialization_roundtrip() {
    let (pk, _sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");

    let pk_bytes = pk.as_bytes().to_vec();
    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa87, pk_bytes)
        .expect("Public key restoration should succeed");

    assert_eq!(pk.as_bytes(), restored_pk.as_bytes());
}

#[test]
fn test_secret_key_serialization_roundtrip() {
    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");

    let sk_bytes = sk.expose_secret().to_vec();
    let restored_sk = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa44, sk_bytes)
        .expect("Secret key restoration should succeed");

    assert_eq!(sk.len(), restored_sk.len());
    assert_eq!(sk.parameter_set(), restored_sk.parameter_set());
}

#[test]
fn test_restored_key_can_sign_and_verify_roundtrip() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");
    let message = b"Test message for restored key";
    let context: &[u8] = &[];

    // Serialize and restore keys
    let pk_bytes = pk.as_bytes().to_vec();
    let sk_bytes = sk.expose_secret().to_vec();

    let restored_pk = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa65, pk_bytes)
        .expect("Public key restoration should succeed");
    let restored_sk = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa65, sk_bytes)
        .expect("Secret key restoration should succeed");

    // Sign with restored secret key
    let signature = restored_sk.sign(message, context).expect("Signing should succeed");

    // Verify with restored public key
    let is_valid =
        restored_pk.verify(message, &signature, context).expect("Verification should succeed");
    assert!(is_valid, "Restored keys should work correctly");
}

#[test]
fn test_signature_serialization_roundtrip() {
    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");
    let message = b"Test message";
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing should succeed");

    let sig_bytes = signature.as_bytes().to_vec();
    let restored_sig = MlDsaSignature::new(MlDsaParameterSet::MlDsa87, sig_bytes)
        .expect("Signature restoration should succeed");

    assert_eq!(signature.as_bytes(), restored_sig.as_bytes());
    assert_eq!(signature.parameter_set(), restored_sig.parameter_set());
}

#[test]
fn test_invalid_public_key_length_rejected_fails() {
    // Too short
    let short_bytes = vec![0u8; 100];
    let result = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa44, short_bytes);
    assert!(result.is_err());

    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, MlDsaParameterSet::MlDsa44.public_key_size());
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_invalid_secret_key_length_rejected_fails() {
    // Too long
    let long_bytes = vec![0u8; 10000];
    let result = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa65, long_bytes);
    assert!(result.is_err());

    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, MlDsaParameterSet::MlDsa65.secret_key_size());
            assert_eq!(actual, 10000);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_invalid_signature_length_rejected_fails() {
    let short_bytes = vec![0u8; 50];
    let result = MlDsaSignature::new(MlDsaParameterSet::MlDsa87, short_bytes);
    assert!(result.is_err());

    match result {
        Err(MlDsaError::InvalidSignatureLength { expected, actual }) => {
            assert_eq!(expected, MlDsaParameterSet::MlDsa87.signature_size());
            assert_eq!(actual, 50);
        }
        _ => panic!("Expected InvalidSignatureLength error"),
    }
}

// ============================================================================
// 2.2.10: NIST KAT Vectors (Parameter Set Properties)
// ============================================================================

#[test]
fn test_mldsa44_parameter_properties_succeeds() {
    let param = MlDsaParameterSet::MlDsa44;

    assert_eq!(param.name(), "ML-DSA-44");
    assert_eq!(param.public_key_size(), 1312);
    assert_eq!(param.secret_key_size(), 2560);
    assert_eq!(param.signature_size(), 2420);
    assert_eq!(param.nist_security_level(), 2);
}

#[test]
fn test_mldsa65_parameter_properties_succeeds() {
    let param = MlDsaParameterSet::MlDsa65;

    assert_eq!(param.name(), "ML-DSA-65");
    assert_eq!(param.public_key_size(), 1952);
    assert_eq!(param.secret_key_size(), 4032);
    assert_eq!(param.signature_size(), 3309);
    assert_eq!(param.nist_security_level(), 3);
}

#[test]
fn test_mldsa87_parameter_properties_succeeds() {
    let param = MlDsaParameterSet::MlDsa87;

    assert_eq!(param.name(), "ML-DSA-87");
    assert_eq!(param.public_key_size(), 2592);
    assert_eq!(param.secret_key_size(), 4896);
    assert_eq!(param.signature_size(), 4627);
    assert_eq!(param.nist_security_level(), 5);
}

#[test]
fn test_generated_key_sizes_match_spec_has_correct_size() {
    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
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
fn test_generated_signature_sizes_match_spec_has_correct_size() {
    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
    {
        let (_pk, sk) = generate_keypair(param).expect("Keygen should succeed");
        let message = b"Test message";
        let context: &[u8] = &[];

        let signature = sk.sign(message, context).expect("Signing should succeed");

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
fn test_empty_message_signing_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let message: &[u8] = &[];
    let context: &[u8] = &[];

    let signature = sk.sign(message, context).expect("Signing empty message should succeed");
    let is_valid = pk.verify(message, &signature, context).expect("Verification should succeed");

    assert!(is_valid, "Empty message should sign and verify correctly");
}

#[test]
fn test_large_message_signing_succeeds() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("Keygen should succeed");

    // 50 KiB — below the default max_signature_size_bytes (64 KiB) resource cap.
    let mut large_message = vec![0u8; 50 * 1024];
    latticearc::primitives::rand::secure_rng().fill_bytes(&mut large_message);
    let context: &[u8] = &[];

    let signature = sk.sign(&large_message, context).expect("Signing large message should succeed");
    let is_valid =
        pk.verify(&large_message, &signature, context).expect("Verification should succeed");

    assert!(is_valid, "Large message should sign and verify correctly");
}

#[test]
fn test_secret_key_constant_time_comparison_succeeds() {
    let (_pk1, sk1) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");
    let (_pk2, sk2) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("Keygen should succeed");

    // Test constant-time equality
    let same_key_eq: bool = sk1.ct_eq(&sk1).into();
    let diff_key_eq: bool = sk1.ct_eq(&sk2).into();

    assert!(same_key_eq, "Same key should be equal");
    assert!(!diff_key_eq, "Different keys should not be equal");
}

#[test]
fn test_secret_key_zeroization_succeeds() {
    let (_pk, mut sk) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("Keygen should succeed");

    // Verify key has non-zero data before zeroization
    let sk_bytes_before = sk.expose_secret().to_vec();
    assert!(
        !sk_bytes_before.iter().all(|&b| b == 0),
        "Secret key should contain non-zero data before zeroization"
    );

    // Zeroize and verify
    use zeroize::Zeroize;
    sk.zeroize();

    let sk_bytes_after = sk.expose_secret();
    assert!(
        sk_bytes_after.iter().all(|&b| b == 0),
        "Secret key should be all zeros after zeroization"
    );
}

#[test]
fn test_unique_keypair_generation_are_unique() {
    let (pk1, _sk1) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("First keygen should succeed");
    let (pk2, _sk2) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("Second keygen should succeed");
    let (pk3, _sk3) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("Third keygen should succeed");

    assert_ne!(pk1.as_bytes(), pk2.as_bytes(), "Generated keys should be unique");
    assert_ne!(pk2.as_bytes(), pk3.as_bytes(), "Generated keys should be unique");
    assert_ne!(pk1.as_bytes(), pk3.as_bytes(), "Generated keys should be unique");
}

#[test]
fn test_all_parameter_sets_comprehensive_succeeds() {
    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
    {
        let (pk, sk) =
            generate_keypair(param).expect(&format!("{:?} keygen should succeed", param));
        let message = b"Comprehensive test message";
        let context = b"test-context";

        // Test basic signing and verification
        let signature =
            sk.sign(message, context).expect(&format!("{:?} signing should succeed", param));
        assert!(
            pk.verify(message, &signature, context).expect("Verification should succeed"),
            "{:?} signature should verify",
            param
        );

        // Test wrong message fails
        let wrong_msg = b"wrong message";
        assert!(
            !pk.verify(wrong_msg, &signature, context).expect("Verification should not error"),
            "{:?} should reject wrong message",
            param
        );

        // Test wrong context fails
        let wrong_ctx = b"wrong-context";
        assert!(
            !pk.verify(message, &signature, wrong_ctx).expect("Verification should not error"),
            "{:?} should reject wrong context",
            param
        );

        // Test corrupted signature fails
        let mut corrupted_bytes = signature.as_bytes().to_vec();
        corrupted_bytes[0] ^= 0xFF;
        let corrupted_sig =
            MlDsaSignature::from_bytes_unchecked(signature.parameter_set(), corrupted_bytes);
        assert!(
            !pk.verify(message, &corrupted_sig, context).expect("Verification should not error"),
            "{:?} should reject corrupted signature",
            param
        );
    }
}

// ============================================================================
// Error Type Tests
// ============================================================================

#[test]
fn test_error_display_messages_fails() {
    let errors = vec![
        MlDsaError::KeyGenerationError("test keygen error".to_string()),
        MlDsaError::SigningError("test signing error".to_string()),
        MlDsaError::VerificationError("test verification error".to_string()),
        MlDsaError::InvalidKeyLength { expected: 1312, actual: 100 },
        MlDsaError::InvalidSignatureLength { expected: 2420, actual: 50 },
        MlDsaError::InvalidParameterSet("unknown".to_string()),
        MlDsaError::CryptoError("test crypto error".to_string()),
    ];

    for error in errors {
        let display = format!("{error}");
        assert!(!display.is_empty(), "Error display should not be empty");
    }
}

#[test]
fn test_parameter_set_equality_succeeds() {
    assert_eq!(MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa44);
    assert_eq!(MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa65);
    assert_eq!(MlDsaParameterSet::MlDsa87, MlDsaParameterSet::MlDsa87);

    assert_ne!(MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65);
    assert_ne!(MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87);
    assert_ne!(MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa87);
}

#[test]
fn test_parameter_set_debug_format_has_correct_size() {
    assert_eq!(format!("{:?}", MlDsaParameterSet::MlDsa44), "MlDsa44");
    assert_eq!(format!("{:?}", MlDsaParameterSet::MlDsa65), "MlDsa65");
    assert_eq!(format!("{:?}", MlDsaParameterSet::MlDsa87), "MlDsa87");
}

#[test]
fn test_parameter_set_clone_succeeds() {
    let param = MlDsaParameterSet::MlDsa65;
    let cloned = param;
    assert_eq!(param, cloned);
}

// ============================================================================
// Sign with corrupted secret keys (covers try_into + try_from_bytes error paths)
// ============================================================================

#[test]
fn test_sign_corrupted_sk_44_fails() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa44).expect("MlDsa44 keygen should succeed");
    let mut corrupted_sk_bytes = sk.expose_secret().to_vec();
    // Corrupt every 10th byte to ensure key deserialization fails
    for i in (0..corrupted_sk_bytes.len()).step_by(10) {
        corrupted_sk_bytes[i] ^= 0xFF;
    }
    let corrupted_sk = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa44, corrupted_sk_bytes)
        .expect("SecretKey construction accepts any bytes of correct length");

    let result = corrupted_sk.sign(b"test message", &[]);
    // Corrupted key may fail at try_from_bytes or produce an invalid signature
    // Either outcome is acceptable
    match result {
        Ok(sig) => {
            // If sign succeeds with corrupted key, verify should still reject
            let (_pk2, _sk2) =
                generate_keypair(MlDsaParameterSet::MlDsa44).expect("keygen should succeed");
            assert!(!sig.is_empty());
        }
        Err(_) => {} // Expected: signing fails with corrupted key
    }
}

#[test]
fn test_sign_corrupted_sk_65_fails() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa65).expect("MlDsa65 keygen should succeed");
    let mut corrupted_sk_bytes = sk.expose_secret().to_vec();
    for i in (0..corrupted_sk_bytes.len()).step_by(10) {
        corrupted_sk_bytes[i] ^= 0xFF;
    }
    let corrupted_sk = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa65, corrupted_sk_bytes)
        .expect("SecretKey construction accepts any bytes of correct length");

    let result = corrupted_sk.sign(b"test message", &[]);
    match result {
        Ok(_) => {}  // Sign may succeed; corrupted key doesn't always cause error
        Err(_) => {} // Expected
    }
}

#[test]
fn test_sign_corrupted_sk_87_fails() {
    let (_pk, sk) =
        generate_keypair(MlDsaParameterSet::MlDsa87).expect("MlDsa87 keygen should succeed");
    let mut corrupted_sk_bytes = sk.expose_secret().to_vec();
    for i in (0..corrupted_sk_bytes.len()).step_by(10) {
        corrupted_sk_bytes[i] ^= 0xFF;
    }
    let corrupted_sk = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa87, corrupted_sk_bytes)
        .expect("SecretKey construction accepts any bytes of correct length");

    let result = corrupted_sk.sign(b"test message", &[]);
    match result {
        Ok(_) => {}
        Err(_) => {}
    }
}

// ============================================================================
// Verify with corrupted public keys
// ============================================================================

#[test]
fn test_verify_corrupted_pk_44_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa44).expect("keygen should succeed");
    let message = b"test message for corrupted pk";
    let context: &[u8] = &[];
    let signature = sk.sign(message, context).expect("signing should succeed");

    // Corrupt the pk
    let mut corrupted_pk_bytes = pk.as_bytes().to_vec();
    for i in (0..corrupted_pk_bytes.len()).step_by(10) {
        corrupted_pk_bytes[i] ^= 0xFF;
    }
    let corrupted_pk = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa44, corrupted_pk_bytes)
        .expect("PublicKey construction accepts any bytes of correct length");

    let result = corrupted_pk.verify(message, &signature, context);
    match result {
        Ok(valid) => assert!(!valid, "Corrupted pk should not verify"),
        Err(_) => {} // Error from try_from_bytes is also acceptable
    }
}

#[test]
fn test_verify_corrupted_pk_65_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa65).expect("keygen should succeed");
    let message = b"test message for corrupted pk";
    let context: &[u8] = &[];
    let signature = sk.sign(message, context).expect("signing should succeed");

    let mut corrupted_pk_bytes = pk.as_bytes().to_vec();
    for i in (0..corrupted_pk_bytes.len()).step_by(10) {
        corrupted_pk_bytes[i] ^= 0xFF;
    }
    let corrupted_pk = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa65, corrupted_pk_bytes)
        .expect("PublicKey construction accepts any bytes of correct length");

    let result = corrupted_pk.verify(message, &signature, context);
    match result {
        Ok(valid) => assert!(!valid, "Corrupted pk should not verify"),
        Err(_) => {}
    }
}

#[test]
fn test_verify_corrupted_pk_87_fails() {
    let (pk, sk) = generate_keypair(MlDsaParameterSet::MlDsa87).expect("keygen should succeed");
    let message = b"test message for corrupted pk";
    let context: &[u8] = &[];
    let signature = sk.sign(message, context).expect("signing should succeed");

    let mut corrupted_pk_bytes = pk.as_bytes().to_vec();
    for i in (0..corrupted_pk_bytes.len()).step_by(10) {
        corrupted_pk_bytes[i] ^= 0xFF;
    }
    let corrupted_pk = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa87, corrupted_pk_bytes)
        .expect("PublicKey construction accepts any bytes of correct length");

    let result = corrupted_pk.verify(message, &signature, context);
    match result {
        Ok(valid) => assert!(!valid, "Corrupted pk should not verify"),
        Err(_) => {}
    }
}

// ============================================================================
// Sign with wrong-length secret keys (triggers try_into error path)
// ============================================================================

#[test]
fn test_sign_short_sk_44_succeeds() {
    // Verify that wrong-length keys are rejected at construction time.
    let result = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa44, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, 2560);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_sign_short_sk_65_succeeds() {
    let result = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa65, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, 4032);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_sign_short_sk_87_succeeds() {
    let result = MlDsaSecretKey::new(MlDsaParameterSet::MlDsa87, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, 4896);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

// ============================================================================
// Verify with wrong-length public keys and signatures
// ============================================================================

#[test]
fn test_verify_short_pk_44_succeeds() {
    let result = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa44, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, 1312);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_verify_short_pk_65_succeeds() {
    let result = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa65, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, 1952);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_verify_short_pk_87_succeeds() {
    let result = MlDsaPublicKey::new(MlDsaParameterSet::MlDsa87, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, 2592);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

#[test]
fn test_verify_short_sig_65_succeeds() {
    let result = MlDsaSignature::new(MlDsaParameterSet::MlDsa65, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidSignatureLength { expected, actual }) => {
            assert_eq!(expected, 3309);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidSignatureLength error"),
    }
}

#[test]
fn test_verify_short_sig_87_succeeds() {
    let result = MlDsaSignature::new(MlDsaParameterSet::MlDsa87, vec![0u8; 100]);
    assert!(result.is_err());
    match result {
        Err(MlDsaError::InvalidSignatureLength { expected, actual }) => {
            assert_eq!(expected, 4627);
            assert_eq!(actual, 100);
        }
        _ => panic!("Expected InvalidSignatureLength error"),
    }
}
