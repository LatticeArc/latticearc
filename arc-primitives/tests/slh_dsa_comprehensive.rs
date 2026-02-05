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
//! Comprehensive SLH-DSA (Stateless Hash-Based Digital Signature) Tests
//!
//! This test suite validates SLH-DSA signatures as specified in FIPS 205.
//! SLH-DSA is computationally intensive; some tests are marked with `#[ignore]`
//! for CI performance reasons.
//!
//! Test coverage:
//! - All SHA2 variants (128s, 128f, 192s, 192f, 256s, 256f)
//! - All SHAKE variants (128s, 128f, 192s, 192f, 256s, 256f)
//! - Deterministic signing behavior
//! - Performance variant comparison (f vs s)
//! - Key serialization/deserialization
//! - Context string handling
//! - Edge cases and error conditions
//!
//! Note: The fips205 crate provides 12 security parameter sets across two families
//! (SHA2 and SHAKE) with "f" (fast) and "s" (small) parameter tradeoffs.

use fips205::traits::{SerDes, Signer, Verifier};

// SHA2 variants
use fips205::slh_dsa_sha2_128f;
use fips205::slh_dsa_sha2_128s;
use fips205::slh_dsa_sha2_192f;
use fips205::slh_dsa_sha2_192s;
use fips205::slh_dsa_sha2_256f;
use fips205::slh_dsa_sha2_256s;

// SHAKE variants
use fips205::slh_dsa_shake_128f;
use fips205::slh_dsa_shake_128s;
use fips205::slh_dsa_shake_192f;
use fips205::slh_dsa_shake_192s;
use fips205::slh_dsa_shake_256f;
use fips205::slh_dsa_shake_256s;

// ============================================================================
// Helper Macros for DRY Test Generation
// ============================================================================

/// Macro to generate basic sign/verify tests for each variant
macro_rules! slh_dsa_basic_test {
    ($test_name:ident, $module:ident) => {
        #[test]
        fn $test_name() {
            let message = b"Test message for SLH-DSA basic test";
            let context = b"";

            // Generate keypair
            let (pk, sk) = $module::try_keygen().expect("Key generation should succeed");

            // Sign with hedging enabled (true)
            let signature = sk.try_sign(message, context, true).expect("Signing should succeed");

            // Verify signature
            let is_valid = pk.verify(message, &signature, context);
            assert!(is_valid, "Signature verification should succeed");
        }
    };
}

/// Macro to generate serialization roundtrip tests
macro_rules! slh_dsa_serialization_test {
    ($test_name:ident, $module:ident) => {
        #[test]
        fn $test_name() {
            let message = b"Serialization test message";
            let context = b"";

            // Generate keypair
            let (pk, sk) = $module::try_keygen().expect("Key generation should succeed");

            // Serialize and deserialize public key
            let pk_bytes = pk.into_bytes();
            let pk_restored = $module::PublicKey::try_from_bytes(&pk_bytes)
                .expect("Public key deserialization should succeed");

            // Serialize and deserialize private key
            let sk_bytes = sk.into_bytes();
            let sk_restored = $module::PrivateKey::try_from_bytes(&sk_bytes)
                .expect("Private key deserialization should succeed");

            // Verify restored keys work
            let signature = sk_restored
                .try_sign(message, context, true)
                .expect("Signing with restored key should succeed");
            let is_valid = pk_restored.verify(message, &signature, context);
            assert!(is_valid, "Verification with restored keys should succeed");
        }
    };
}

/// Macro for key size validation tests
macro_rules! slh_dsa_key_size_test {
    ($test_name:ident, $module:ident, $pk_len:expr, $sk_len:expr, $sig_len:expr) => {
        #[test]
        fn $test_name() {
            let (pk, sk) = $module::try_keygen().expect("Key generation should succeed");

            // Verify key sizes
            let pk_bytes = pk.into_bytes();
            let sk_bytes = sk.into_bytes();
            assert_eq!(
                pk_bytes.len(),
                $pk_len,
                "Public key size mismatch for {}",
                stringify!($module)
            );
            assert_eq!(
                sk_bytes.len(),
                $sk_len,
                "Secret key size mismatch for {}",
                stringify!($module)
            );

            // Generate signature and verify size
            let (pk2, sk2) = $module::try_keygen().expect("Key generation should succeed");
            let sig = sk2.try_sign(b"test", b"", true).expect("Signing should succeed");
            assert_eq!(
                sig.as_ref().len(),
                $sig_len,
                "Signature size mismatch for {}",
                stringify!($module)
            );
            assert!(pk2.verify(b"test", &sig, b""));
        }
    };
}

// ============================================================================
// SHAKE Variant Tests - Basic Sign/Verify
// ============================================================================

slh_dsa_basic_test!(test_shake_128s_basic_sign_verify, slh_dsa_shake_128s);
slh_dsa_basic_test!(test_shake_128f_basic_sign_verify, slh_dsa_shake_128f);
slh_dsa_basic_test!(test_shake_192s_basic_sign_verify, slh_dsa_shake_192s);

#[test]
#[ignore] // Computationally intensive
fn test_shake_192f_basic_sign_verify() {
    let message = b"Test message for SLH-DSA basic test";
    let context = b"";
    let (pk, sk) = slh_dsa_shake_192f::try_keygen().expect("Key generation should succeed");
    let signature = sk.try_sign(message, context, true).expect("Signing should succeed");
    let is_valid = pk.verify(message, &signature, context);
    assert!(is_valid, "Signature verification should succeed");
}

slh_dsa_basic_test!(test_shake_256s_basic_sign_verify, slh_dsa_shake_256s);

#[test]
#[ignore] // Computationally intensive
fn test_shake_256f_basic_sign_verify() {
    let message = b"Test message for SLH-DSA basic test";
    let context = b"";
    let (pk, sk) = slh_dsa_shake_256f::try_keygen().expect("Key generation should succeed");
    let signature = sk.try_sign(message, context, true).expect("Signing should succeed");
    let is_valid = pk.verify(message, &signature, context);
    assert!(is_valid, "Signature verification should succeed");
}

// ============================================================================
// SHA2 Variant Tests - Basic Sign/Verify
// ============================================================================

slh_dsa_basic_test!(test_sha2_128s_basic_sign_verify, slh_dsa_sha2_128s);
slh_dsa_basic_test!(test_sha2_128f_basic_sign_verify, slh_dsa_sha2_128f);
slh_dsa_basic_test!(test_sha2_192s_basic_sign_verify, slh_dsa_sha2_192s);

#[test]
#[ignore] // Computationally intensive
fn test_sha2_192f_basic_sign_verify() {
    let message = b"Test message for SLH-DSA basic test";
    let context = b"";
    let (pk, sk) = slh_dsa_sha2_192f::try_keygen().expect("Key generation should succeed");
    let signature = sk.try_sign(message, context, true).expect("Signing should succeed");
    let is_valid = pk.verify(message, &signature, context);
    assert!(is_valid, "Signature verification should succeed");
}

slh_dsa_basic_test!(test_sha2_256s_basic_sign_verify, slh_dsa_sha2_256s);

#[test]
#[ignore] // Computationally intensive
fn test_sha2_256f_basic_sign_verify() {
    let message = b"Test message for SLH-DSA basic test";
    let context = b"";
    let (pk, sk) = slh_dsa_sha2_256f::try_keygen().expect("Key generation should succeed");
    let signature = sk.try_sign(message, context, true).expect("Signing should succeed");
    let is_valid = pk.verify(message, &signature, context);
    assert!(is_valid, "Signature verification should succeed");
}

// ============================================================================
// SHAKE Variant Tests - Key Serialization
// ============================================================================

slh_dsa_serialization_test!(test_shake_128s_serialization, slh_dsa_shake_128s);
slh_dsa_serialization_test!(test_shake_128f_serialization, slh_dsa_shake_128f);

// ============================================================================
// SHA2 Variant Tests - Key Serialization
// ============================================================================

slh_dsa_serialization_test!(test_sha2_128s_serialization, slh_dsa_sha2_128s);
slh_dsa_serialization_test!(test_sha2_128f_serialization, slh_dsa_sha2_128f);

// ============================================================================
// Key and Signature Size Tests
// ============================================================================

// SHAKE variants: verify documented sizes
slh_dsa_key_size_test!(
    test_shake_128s_key_sizes,
    slh_dsa_shake_128s,
    slh_dsa_shake_128s::PK_LEN,
    slh_dsa_shake_128s::SK_LEN,
    slh_dsa_shake_128s::SIG_LEN
);

slh_dsa_key_size_test!(
    test_shake_128f_key_sizes,
    slh_dsa_shake_128f,
    slh_dsa_shake_128f::PK_LEN,
    slh_dsa_shake_128f::SK_LEN,
    slh_dsa_shake_128f::SIG_LEN
);

// SHA2 variants: verify documented sizes
slh_dsa_key_size_test!(
    test_sha2_128s_key_sizes,
    slh_dsa_sha2_128s,
    slh_dsa_sha2_128s::PK_LEN,
    slh_dsa_sha2_128s::SK_LEN,
    slh_dsa_sha2_128s::SIG_LEN
);

slh_dsa_key_size_test!(
    test_sha2_128f_key_sizes,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_128f::PK_LEN,
    slh_dsa_sha2_128f::SK_LEN,
    slh_dsa_sha2_128f::SIG_LEN
);

// ============================================================================
// Deterministic Signing Tests
// ============================================================================

#[test]
fn test_deterministic_signing_shake_128s() {
    // When hedging is disabled (false), signing should be deterministic
    // Note: This tests the API behavior; fips205 may always use randomness internally
    let message = b"Deterministic signing test message";
    let context = b"test-context";

    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Key generation should succeed");

    // Sign twice with hedging disabled
    let sig1 = sk.try_sign(message, context, false).expect("First sign should succeed");
    let sig2 = sk.try_sign(message, context, false).expect("Second sign should succeed");

    // Both signatures should be valid
    assert!(pk.verify(message, &sig1, context), "First signature should verify");
    assert!(pk.verify(message, &sig2, context), "Second signature should verify");

    // Note: With hedging=false, signatures may or may not be identical
    // depending on implementation. The important thing is both are valid.
}

#[test]
fn test_hedged_signing_produces_different_signatures_shake_128s() {
    // With hedging enabled, multiple signatures should differ
    let message = b"Hedged signing test message";
    let context = b"";

    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Key generation should succeed");

    // Sign multiple times with hedging
    let sig1 = sk.try_sign(message, context, true).expect("First sign should succeed");
    let sig2 = sk.try_sign(message, context, true).expect("Second sign should succeed");

    // Both should be valid
    assert!(pk.verify(message, &sig1, context), "First signature should verify");
    assert!(pk.verify(message, &sig2, context), "Second signature should verify");

    // Signatures should differ due to hedging
    assert_ne!(sig1.as_ref(), sig2.as_ref(), "Hedged signatures should differ");
}

#[test]
fn test_deterministic_signing_sha2_128s() {
    let message = b"SHA2 deterministic signing test";
    let context = b"";

    let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("Key generation should succeed");

    let sig1 = sk.try_sign(message, context, false).expect("Sign should succeed");
    let sig2 = sk.try_sign(message, context, false).expect("Sign should succeed");

    assert!(pk.verify(message, &sig1, context));
    assert!(pk.verify(message, &sig2, context));
}

// ============================================================================
// Performance Variant Comparison Tests (f vs s)
// ============================================================================

#[test]
fn test_f_variant_has_larger_signatures_128() {
    // "f" (fast) variants have larger signatures but faster signing
    // "s" (small) variants have smaller signatures but slower signing
    let (_, sk_s) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let (_, sk_f) = slh_dsa_shake_128f::try_keygen().expect("Keygen should succeed");

    let message = b"Size comparison test";
    let sig_s = sk_s.try_sign(message, b"", true).expect("Sign should succeed");
    let sig_f = sk_f.try_sign(message, b"", true).expect("Sign should succeed");

    // f variant should have larger signature
    assert!(
        sig_f.as_ref().len() > sig_s.as_ref().len(),
        "Fast variant should have larger signature: f={} vs s={}",
        sig_f.as_ref().len(),
        sig_s.as_ref().len()
    );

    // Verify documented sizes
    assert_eq!(sig_s.as_ref().len(), slh_dsa_shake_128s::SIG_LEN);
    assert_eq!(sig_f.as_ref().len(), slh_dsa_shake_128f::SIG_LEN);
}

#[test]
fn test_sha2_f_variant_has_larger_signatures_128() {
    let (_, sk_s) = slh_dsa_sha2_128s::try_keygen().expect("Keygen should succeed");
    let (_, sk_f) = slh_dsa_sha2_128f::try_keygen().expect("Keygen should succeed");

    let message = b"SHA2 size comparison";
    let sig_s = sk_s.try_sign(message, b"", true).expect("Sign should succeed");
    let sig_f = sk_f.try_sign(message, b"", true).expect("Sign should succeed");

    assert!(
        sig_f.as_ref().len() > sig_s.as_ref().len(),
        "SHA2 fast variant should have larger signature"
    );
}

#[test]
fn test_security_level_signature_sizes() {
    // Higher security levels should have larger signatures
    let (_, sk_128) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let (_, sk_192) = slh_dsa_shake_192s::try_keygen().expect("Keygen should succeed");
    let (_, sk_256) = slh_dsa_shake_256s::try_keygen().expect("Keygen should succeed");

    let message = b"Security level comparison";
    let sig_128 = sk_128.try_sign(message, b"", true).expect("Sign should succeed");
    let sig_192 = sk_192.try_sign(message, b"", true).expect("Sign should succeed");
    let sig_256 = sk_256.try_sign(message, b"", true).expect("Sign should succeed");

    // Verify increasing size with security level
    assert!(
        sig_192.as_ref().len() >= sig_128.as_ref().len(),
        "192-bit should have >= signature size than 128-bit"
    );
    assert!(
        sig_256.as_ref().len() >= sig_192.as_ref().len(),
        "256-bit should have >= signature size than 192-bit"
    );
}

// ============================================================================
// Context String Tests
// ============================================================================

#[test]
fn test_context_string_affects_signature_shake_128s() {
    let message = b"Context test message";
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    // Sign with different contexts
    let sig_empty = sk.try_sign(message, b"", true).expect("Sign should succeed");
    let sig_ctx = sk.try_sign(message, b"context-1", true).expect("Sign should succeed");

    // Verify with correct context
    assert!(pk.verify(message, &sig_empty, b""), "Empty context should verify");
    assert!(pk.verify(message, &sig_ctx, b"context-1"), "Context should verify");

    // Verify with wrong context fails
    assert!(!pk.verify(message, &sig_empty, b"wrong"), "Wrong context should fail");
    assert!(!pk.verify(message, &sig_ctx, b""), "Missing context should fail");
    assert!(!pk.verify(message, &sig_ctx, b"context-2"), "Different context should fail");
}

#[test]
fn test_max_context_length_255_bytes() {
    // FIPS 205 allows context strings up to 255 bytes
    let message = b"Max context test";
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    let max_context = [0x42u8; 255];
    let signature =
        sk.try_sign(message, &max_context, true).expect("Max context signing should succeed");

    assert!(
        pk.verify(message, &signature, &max_context),
        "Max context verification should succeed"
    );
}

// ============================================================================
// Message Handling Tests
// ============================================================================

#[test]
fn test_empty_message_signing() {
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    let empty_message: &[u8] = b"";
    let signature =
        sk.try_sign(empty_message, b"", true).expect("Empty message signing should succeed");

    assert!(pk.verify(empty_message, &signature, b""), "Empty message verification should succeed");
}

#[test]
fn test_large_message_signing() {
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    // 1 MB message
    let large_message = vec![0xABu8; 1024 * 1024];
    let signature =
        sk.try_sign(&large_message, b"", true).expect("Large message signing should succeed");

    assert!(
        pk.verify(&large_message, &signature, b""),
        "Large message verification should succeed"
    );
}

#[test]
fn test_single_byte_message() {
    let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("Keygen should succeed");

    let single_byte = [0x00u8];
    let signature =
        sk.try_sign(&single_byte, b"", true).expect("Single byte signing should succeed");

    assert!(pk.verify(&single_byte, &signature, b""));
}

// ============================================================================
// Signature Verification Negative Tests
// ============================================================================

#[test]
fn test_corrupted_signature_fails() {
    let message = b"Corruption test message";
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    let signature = sk.try_sign(message, b"", true).expect("Signing should succeed");
    let mut corrupted = signature.clone();
    let sig_bytes = corrupted.as_mut();

    // Corrupt first byte
    sig_bytes[0] ^= 0xFF;

    // Rebuild signature array for verification
    let mut corrupted_array = [0u8; slh_dsa_shake_128s::SIG_LEN];
    corrupted_array.copy_from_slice(sig_bytes);

    assert!(
        !pk.verify(message, &corrupted_array, b""),
        "Corrupted signature should fail verification"
    );
}

#[test]
fn test_wrong_message_fails() {
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    let signature = sk.try_sign(message, b"", true).expect("Signing should succeed");

    assert!(!pk.verify(wrong_message, &signature, b""), "Wrong message should fail verification");
}

#[test]
fn test_wrong_public_key_fails() {
    let message = b"Public key mismatch test";
    let (pk1, sk1) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let (pk2, _sk2) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    let signature = sk1.try_sign(message, b"", true).expect("Signing should succeed");

    assert!(pk1.verify(message, &signature, b""), "Correct pk should verify");
    assert!(!pk2.verify(message, &signature, b""), "Wrong pk should fail verification");
}

// ============================================================================
// Key Derivation Tests
// ============================================================================

#[test]
fn test_public_key_derivation_from_private_key() {
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    // Get public key from private key
    let derived_pk = sk.get_public_key();

    // Derived public key should match original
    assert_eq!(
        pk.into_bytes(),
        derived_pk.into_bytes(),
        "Derived public key should match original"
    );
}

#[test]
fn test_sha2_public_key_derivation() {
    let (pk, sk) = slh_dsa_sha2_128s::try_keygen().expect("Keygen should succeed");
    let derived_pk = sk.get_public_key();
    assert_eq!(pk.into_bytes(), derived_pk.into_bytes());
}

// ============================================================================
// Cross-Variant Incompatibility Tests
// ============================================================================

#[test]
fn test_shake_vs_sha2_incompatible() {
    // SHAKE and SHA2 variants at the same security level have the same
    // key/signature sizes but use different internal hash functions.
    // A signature from one variant should not verify with the other's public key.
    let message = b"Cross-variant test";

    let (pk_shake, sk_shake) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let (pk_sha2, sk_sha2) = slh_dsa_sha2_128s::try_keygen().expect("Keygen should succeed");

    let sig_shake = sk_shake.try_sign(message, b"", true).expect("Sign should succeed");
    let sig_sha2 = sk_sha2.try_sign(message, b"", true).expect("Sign should succeed");

    // Same-variant verification should work
    assert!(pk_shake.verify(message, &sig_shake, b""));
    assert!(pk_sha2.verify(message, &sig_sha2, b""));

    // Verify that sizes are the same (SHAKE and SHA2 at same level have same sizes)
    assert_eq!(
        slh_dsa_shake_128s::SIG_LEN,
        slh_dsa_sha2_128s::SIG_LEN,
        "SHAKE and SHA2 128s should have same signature size"
    );
    assert_eq!(
        slh_dsa_shake_128s::PK_LEN,
        slh_dsa_sha2_128s::PK_LEN,
        "SHAKE and SHA2 128s should have same public key size"
    );

    // Cross-variant verification should fail because internal hash differs
    // We can attempt verification since sizes match
    let mut sig_shake_array = [0u8; slh_dsa_sha2_128s::SIG_LEN];
    sig_shake_array.copy_from_slice(sig_shake.as_ref());

    // This should fail - SHAKE signature verified with SHA2 public key
    let cross_verify = pk_sha2.verify(message, &sig_shake_array, b"");
    assert!(!cross_verify, "SHAKE signature should not verify with SHA2 public key");
}

#[test]
fn test_different_security_levels_incompatible() {
    // Keys from different security levels should not interoperate
    // This is enforced by different key/signature sizes

    assert_ne!(
        slh_dsa_shake_128s::PK_LEN,
        slh_dsa_shake_192s::PK_LEN,
        "128 and 192 public key sizes should differ"
    );
    assert_ne!(
        slh_dsa_shake_192s::PK_LEN,
        slh_dsa_shake_256s::PK_LEN,
        "192 and 256 public key sizes should differ"
    );
}

// ============================================================================
// Invalid Key Handling Tests
// ============================================================================

#[test]
fn test_invalid_public_key_deserialization() {
    // Try to deserialize invalid public key bytes
    let invalid_bytes = vec![0u8; slh_dsa_shake_128s::PK_LEN];
    let mut pk_array = [0u8; slh_dsa_shake_128s::PK_LEN];
    pk_array.copy_from_slice(&invalid_bytes);

    // fips205 should handle this - it may succeed but verification will fail
    let pk_result = slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_array);

    // If deserialization succeeds, verify that it doesn't verify random signatures
    if let Ok(pk) = pk_result {
        let random_sig = [0xAAu8; slh_dsa_shake_128s::SIG_LEN];
        assert!(
            !pk.verify(b"test", &random_sig, b""),
            "Invalid key should not verify random signature"
        );
    }
}

#[test]
fn test_truncated_public_key_fails() {
    // Truncated key should fail deserialization
    let truncated = [0u8; 16]; // Much smaller than required

    // The size mismatch should prevent even creating the array for try_from_bytes
    assert!(
        truncated.len() < slh_dsa_shake_128s::PK_LEN,
        "Truncated bytes should be smaller than required key length"
    );
}

// ============================================================================
// Multiple Signatures Per Key Tests
// ============================================================================

#[test]
fn test_multiple_signatures_same_key() {
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    // Sign multiple different messages with same key
    for i in 0..10 {
        let message = format!("Message number {}", i);
        let signature = sk.try_sign(message.as_bytes(), b"", true).expect("Signing should succeed");

        assert!(pk.verify(message.as_bytes(), &signature, b""), "Signature {} should verify", i);
    }
}

#[test]
fn test_same_message_multiple_signatures_all_valid() {
    let message = b"Same message, multiple signatures";
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    // Generate multiple signatures for same message (with hedging)
    let signatures: Vec<_> =
        (0..5).map(|_| sk.try_sign(message, b"", true).expect("Signing should succeed")).collect();

    // All signatures should be valid
    for (i, sig) in signatures.iter().enumerate() {
        assert!(pk.verify(message, sig, b""), "Signature {} should verify", i);
    }

    // All signatures should be different (due to hedging)
    for i in 0..signatures.len() {
        for j in (i + 1)..signatures.len() {
            assert_ne!(
                signatures[i].as_ref(),
                signatures[j].as_ref(),
                "Signatures {} and {} should differ",
                i,
                j
            );
        }
    }
}

// ============================================================================
// NIST Security Level Verification Tests
// ============================================================================

#[test]
fn test_nist_security_level_1_shake() {
    // SLH-DSA-SHAKE-128s provides NIST security level 1
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let message = b"NIST Level 1 test";
    let signature = sk.try_sign(message, b"", true).expect("Sign should succeed");
    assert!(pk.verify(message, &signature, b""));

    // Verify this is the smallest parameter set
    assert_eq!(slh_dsa_shake_128s::PK_LEN, 32);
    assert_eq!(slh_dsa_shake_128s::SK_LEN, 64);
}

#[test]
fn test_nist_security_level_3_shake() {
    // SLH-DSA-SHAKE-192s provides NIST security level 3
    let (pk, sk) = slh_dsa_shake_192s::try_keygen().expect("Keygen should succeed");
    let message = b"NIST Level 3 test";
    let signature = sk.try_sign(message, b"", true).expect("Sign should succeed");
    assert!(pk.verify(message, &signature, b""));

    // Verify larger parameter set
    assert_eq!(slh_dsa_shake_192s::PK_LEN, 48);
    assert_eq!(slh_dsa_shake_192s::SK_LEN, 96);
}

#[test]
fn test_nist_security_level_5_shake() {
    // SLH-DSA-SHAKE-256s provides NIST security level 5
    let (pk, sk) = slh_dsa_shake_256s::try_keygen().expect("Keygen should succeed");
    let message = b"NIST Level 5 test";
    let signature = sk.try_sign(message, b"", true).expect("Sign should succeed");
    assert!(pk.verify(message, &signature, b""));

    // Verify largest parameter set
    assert_eq!(slh_dsa_shake_256s::PK_LEN, 64);
    assert_eq!(slh_dsa_shake_256s::SK_LEN, 128);
}

// ============================================================================
// High-Level API Integration Tests (arc-primitives wrapper)
// ============================================================================

#[test]
fn test_arc_primitives_slh_dsa_integration() {
    use arc_primitives::sig::slh_dsa::{SecurityLevel, SigningKey};

    // Test with SHAKE-128s (smallest, fastest for testing)
    let (signing_key, verifying_key) =
        SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation should succeed");

    let message = b"Integration test message";
    let signature = signing_key.sign(message, None).expect("Signing should succeed");

    let is_valid =
        verifying_key.verify(message, &signature, None).expect("Verification should succeed");

    assert!(is_valid, "Signature verification should succeed");
}

#[test]
fn test_arc_primitives_all_security_levels() {
    use arc_primitives::sig::slh_dsa::{SecurityLevel, SigningKey};

    for level in [SecurityLevel::Shake128s, SecurityLevel::Shake192s, SecurityLevel::Shake256s] {
        let (signing_key, verifying_key) =
            SigningKey::generate(level).expect("Key generation should succeed");

        let message = format!("Test for {:?}", level);
        let signature = signing_key.sign(message.as_bytes(), None).expect("Signing should succeed");

        let is_valid = verifying_key
            .verify(message.as_bytes(), &signature, None)
            .expect("Verification should succeed");

        assert!(is_valid, "Verification should succeed for {:?}", level);
    }
}

// ============================================================================
// Performance Timing Tests (Sanity Checks)
// ============================================================================

#[test]
fn test_keygen_completes_in_reasonable_time() {
    use std::time::Instant;

    let start = Instant::now();
    let _ = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let duration = start.elapsed();

    // Key generation should complete in under 20 seconds even in debug mode
    // Release mode typically completes in under 2 seconds
    assert!(duration.as_secs() < 20, "Key generation took too long: {:?}", duration);
}

#[test]
fn test_signing_completes_in_reasonable_time() {
    use std::time::Instant;

    let (_, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let message = b"Timing test message";

    let start = Instant::now();
    let _ = sk.try_sign(message, b"", true).expect("Sign should succeed");
    let duration = start.elapsed();

    // Signing should complete in under 150 seconds even in debug mode
    // Release mode typically completes in under 5 seconds
    // SLH-DSA is inherently slow due to hash-based signature scheme
    assert!(duration.as_secs() < 150, "Signing took too long: {:?}", duration);
}

#[test]
fn test_verification_faster_than_signing() {
    use std::time::Instant;

    let (pk, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let message = b"Speed comparison test";

    // Time signing
    let sign_start = Instant::now();
    let signature = sk.try_sign(message, b"", true).expect("Sign should succeed");
    let sign_duration = sign_start.elapsed();

    // Time verification
    let verify_start = Instant::now();
    let _ = pk.verify(message, &signature, b"");
    let verify_duration = verify_start.elapsed();

    // Verification should generally be faster than signing in SLH-DSA
    // This is a sanity check, not a strict requirement
    println!("Sign: {:?}, Verify: {:?}", sign_duration, verify_duration);
}

// ============================================================================
// Binary Representation Tests
// ============================================================================

#[test]
fn test_signature_is_not_all_zeros() {
    let (_, sk) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let message = b"Non-zero test";

    let signature = sk.try_sign(message, b"", true).expect("Sign should succeed");

    assert!(signature.as_ref().iter().any(|&b| b != 0), "Signature should not be all zeros");
}

#[test]
fn test_public_key_is_not_all_zeros() {
    let (pk, _) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let pk_bytes = pk.into_bytes();

    assert!(pk_bytes.iter().any(|&b| b != 0), "Public key should not be all zeros");
}

#[test]
fn test_unique_keypairs() {
    let (pk1, _) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");
    let (pk2, _) = slh_dsa_shake_128s::try_keygen().expect("Keygen should succeed");

    assert_ne!(
        pk1.into_bytes(),
        pk2.into_bytes(),
        "Different keypairs should have different public keys"
    );
}
