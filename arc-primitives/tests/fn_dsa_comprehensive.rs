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
//! Comprehensive FN-DSA (FIPS 206) Primitives Tests - Phase 2
//!
//! This test suite provides thorough coverage of FN-DSA (Few-Time Digital Signature Algorithm)
//! primitives including both security level variants, signing consistency, and edge cases.
//!
//! # Test Categories
//!
//! - **2.4.1**: FN-DSA-512 variant tests (128-bit security)
//! - **2.4.2**: FN-DSA-1024 variant tests (256-bit security)
//! - **2.4.3**: Signing consistency tests
//! - **2.4.4**: NIST KAT vector validation (if available)
//!
//! # Important Note on Stack Usage
//!
//! FN-DSA operations require significant stack space due to the underlying NTRU lattice
//! computations. In debug mode, stack overflow may occur. Tests are marked with `#[ignore]`
//! and should be run with release optimizations:
//!
//! ```bash
//! cargo test --test fn_dsa_comprehensive --release -- --ignored
//! ```
//!
//! For running all tests (both ignored and non-ignored):
//! ```bash
//! cargo test --test fn_dsa_comprehensive --release -- --include-ignored
//! ```

use arc_primitives::sig::fndsa::{
    FNDsaSecurityLevel, KeyPair, Signature, SigningKey, VerifyingKey,
};
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;

/// Helper to run FN-DSA tests with sufficient stack size
/// FN-DSA requires ~32MB stack for safe operation in debug builds
fn run_with_large_stack<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024) // 32 MB stack
        .spawn(f)
        .expect("Thread spawn failed")
        .join()
        .expect("Thread join failed")
}

// ============================================================================
// 2.4.1 FN-DSA-512 Variant Tests (128-bit security)
// ============================================================================

/// Test FN-DSA-512 key generation produces correct key sizes
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_512_key_generation() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        // Verify key sizes match FIPS 206 specification
        assert_eq!(
            keypair.signing_key().to_bytes().len(),
            FNDsaSecurityLevel::Level512.signing_key_size(),
            "Signing key should be 1281 bytes for FN-DSA-512"
        );
        assert_eq!(
            keypair.verifying_key().to_bytes().len(),
            FNDsaSecurityLevel::Level512.verifying_key_size(),
            "Verifying key should be 897 bytes for FN-DSA-512"
        );
    });
}

/// Test FN-DSA-512 signature generation produces correct size
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_512_signature_size() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let message = b"Test message for FN-DSA-512 signature size verification";
        let signature = keypair.sign(&mut rng, message).expect("Signing should succeed");

        assert_eq!(
            signature.len(),
            FNDsaSecurityLevel::Level512.signature_size(),
            "FN-DSA-512 signature should be 666 bytes"
        );
        assert_eq!(signature.len(), 666, "Explicit check: signature is 666 bytes");
    });
}

/// Test FN-DSA-512 sign and verify roundtrip
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_512_sign_verify_roundtrip() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let message = b"Critical data requiring cryptographic signature";
        let signature = keypair.sign(&mut rng, message).expect("Signing should succeed");

        let is_valid = keypair.verify(message, &signature).expect("Verification should succeed");
        assert!(is_valid, "Valid signature should verify successfully");
    });
}

/// Test FN-DSA-512 key serialization roundtrip
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_512_key_serialization_roundtrip() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        // Serialize and deserialize signing key
        let sk_bytes = keypair.signing_key().to_bytes();
        let mut restored_sk =
            SigningKey::from_bytes(sk_bytes.clone(), FNDsaSecurityLevel::Level512)
                .expect("Signing key deserialization should succeed");

        assert_eq!(
            keypair.signing_key().to_bytes(),
            restored_sk.to_bytes(),
            "Signing key roundtrip should preserve data"
        );

        // Serialize and deserialize verifying key
        let vk_bytes = keypair.verifying_key().to_bytes();
        let restored_vk = VerifyingKey::from_bytes(vk_bytes.clone(), FNDsaSecurityLevel::Level512)
            .expect("Verifying key deserialization should succeed");

        assert_eq!(
            keypair.verifying_key().to_bytes(),
            restored_vk.to_bytes(),
            "Verifying key roundtrip should preserve data"
        );

        // Verify restored keys can sign and verify
        let message = b"Test message for restored keys";
        let sig = restored_sk.sign(&mut rng, message).expect("Signing should succeed");
        let valid = restored_vk.verify(message, &sig).expect("Verification should succeed");
        assert!(valid, "Restored keys should work correctly");
    });
}

/// Test FN-DSA-512 rejects invalid verifying key length
#[test]
fn test_fndsa_512_invalid_verifying_key_length() {
    // Too short
    let short_bytes = vec![0u8; 100];
    let result = VerifyingKey::from_bytes(short_bytes, FNDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should reject short verifying key");

    // Too long
    let long_bytes = vec![0u8; 1000];
    let result = VerifyingKey::from_bytes(long_bytes, FNDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should reject long verifying key");

    // Wrong size (1024 key size for 512 level)
    let wrong_size = vec![0u8; FNDsaSecurityLevel::Level1024.verifying_key_size()];
    let result = VerifyingKey::from_bytes(wrong_size, FNDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should reject Level1024 key for Level512");
}

/// Test FN-DSA-512 rejects invalid signing key length
#[test]
fn test_fndsa_512_invalid_signing_key_length() {
    // Empty
    let empty = vec![];
    let result = SigningKey::from_bytes(empty, FNDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should reject empty signing key");

    // Too short
    let short = vec![0u8; 500];
    let result = SigningKey::from_bytes(short, FNDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should reject short signing key");

    // Too long
    let long = vec![0u8; 5000];
    let result = SigningKey::from_bytes(long, FNDsaSecurityLevel::Level512);
    assert!(result.is_err(), "Should reject long signing key");
}

// ============================================================================
// 2.4.2 FN-DSA-1024 Variant Tests (256-bit security)
// ============================================================================

/// Test FN-DSA-1024 key generation produces correct key sizes
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_1024_key_generation() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
            .expect("Key generation should succeed");

        // Verify key sizes match FIPS 206 specification
        assert_eq!(
            keypair.signing_key().to_bytes().len(),
            FNDsaSecurityLevel::Level1024.signing_key_size(),
            "Signing key should be 2305 bytes for FN-DSA-1024"
        );
        assert_eq!(
            keypair.verifying_key().to_bytes().len(),
            FNDsaSecurityLevel::Level1024.verifying_key_size(),
            "Verifying key should be 1793 bytes for FN-DSA-1024"
        );
    });
}

/// Test FN-DSA-1024 signature generation produces correct size
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_1024_signature_size() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
            .expect("Key generation should succeed");

        let message = b"Test message for FN-DSA-1024 signature size verification";
        let signature = keypair.sign(&mut rng, message).expect("Signing should succeed");

        assert_eq!(
            signature.len(),
            FNDsaSecurityLevel::Level1024.signature_size(),
            "FN-DSA-1024 signature should be 1280 bytes"
        );
        assert_eq!(signature.len(), 1280, "Explicit check: signature is 1280 bytes");
    });
}

/// Test FN-DSA-1024 sign and verify roundtrip
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_1024_sign_verify_roundtrip() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
            .expect("Key generation should succeed");

        let message = b"High-security message requiring 256-bit quantum protection";
        let signature = keypair.sign(&mut rng, message).expect("Signing should succeed");

        let is_valid = keypair.verify(message, &signature).expect("Verification should succeed");
        assert!(is_valid, "Valid signature should verify successfully");
    });
}

/// Test FN-DSA-1024 key serialization roundtrip
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_1024_key_serialization_roundtrip() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
            .expect("Key generation should succeed");

        // Serialize and deserialize signing key
        let sk_bytes = keypair.signing_key().to_bytes();
        let restored_sk = SigningKey::from_bytes(sk_bytes.clone(), FNDsaSecurityLevel::Level1024)
            .expect("Signing key deserialization should succeed");

        assert_eq!(
            keypair.signing_key().to_bytes(),
            restored_sk.to_bytes(),
            "Signing key roundtrip should preserve data"
        );

        // Serialize and deserialize verifying key
        let vk_bytes = keypair.verifying_key().to_bytes();
        let restored_vk = VerifyingKey::from_bytes(vk_bytes.clone(), FNDsaSecurityLevel::Level1024)
            .expect("Verifying key deserialization should succeed");

        assert_eq!(
            keypair.verifying_key().to_bytes(),
            restored_vk.to_bytes(),
            "Verifying key roundtrip should preserve data"
        );
    });
}

/// Test FN-DSA-1024 rejects invalid key lengths
#[test]
fn test_fndsa_1024_invalid_key_lengths() {
    // Wrong verifying key size (512 size for 1024 level)
    let wrong_vk = vec![0u8; FNDsaSecurityLevel::Level512.verifying_key_size()];
    let result = VerifyingKey::from_bytes(wrong_vk, FNDsaSecurityLevel::Level1024);
    assert!(result.is_err(), "Should reject Level512 verifying key for Level1024");

    // Wrong signing key size (512 size for 1024 level)
    let wrong_sk = vec![0u8; FNDsaSecurityLevel::Level512.signing_key_size()];
    let result = SigningKey::from_bytes(wrong_sk, FNDsaSecurityLevel::Level1024);
    assert!(result.is_err(), "Should reject Level512 signing key for Level1024");
}

// ============================================================================
// 2.4.3 Signing Consistency Tests
// ============================================================================

/// Test that same key produces valid signatures for multiple messages
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_multiple_messages_same_key() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let messages = [
            b"First message to sign".as_slice(),
            b"Second message with different content".as_slice(),
            b"Third message for testing multiple signatures".as_slice(),
        ];

        let signatures: Vec<Signature> = messages
            .iter()
            .map(|msg| keypair.sign(&mut rng, msg).expect("Signing should succeed"))
            .collect();

        // Verify each signature against its corresponding message
        for (msg, sig) in messages.iter().zip(signatures.iter()) {
            let valid = keypair.verify(msg, sig).expect("Verification should succeed");
            assert!(valid, "Signature should verify for its message");
        }

        // Verify cross-verification fails
        for i in 0..messages.len() {
            for j in 0..signatures.len() {
                if i != j {
                    let valid = keypair
                        .verify(messages[i], &signatures[j])
                        .expect("Verification should complete");
                    assert!(!valid, "Signature for message {} should not verify message {}", j, i);
                }
            }
        }
    });
}

/// Test that different keys produce different signatures for same message
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_different_keys_different_signatures() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair1 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");
        let mut keypair2 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let message = b"Common message signed by different keys";

        let sig1 = keypair1.sign(&mut rng, message).expect("Signing should succeed");
        let sig2 = keypair2.sign(&mut rng, message).expect("Signing should succeed");

        // Signatures should be different
        assert_ne!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "Different keys should produce different signatures"
        );

        // Each key should only verify its own signature
        assert!(
            keypair1.verify(message, &sig1).expect("Verification should complete"),
            "Keypair1 should verify its own signature"
        );
        assert!(
            !keypair1.verify(message, &sig2).expect("Verification should complete"),
            "Keypair1 should not verify keypair2's signature"
        );
        assert!(
            keypair2.verify(message, &sig2).expect("Verification should complete"),
            "Keypair2 should verify its own signature"
        );
        assert!(
            !keypair2.verify(message, &sig1).expect("Verification should complete"),
            "Keypair2 should not verify keypair1's signature"
        );
    });
}

/// Test signature verification rejects tampered message
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_tampered_message_rejected() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let original_message = b"Original message content";
        let signature = keypair.sign(&mut rng, original_message).expect("Signing should succeed");

        // Tampered messages
        let tampered_messages = [
            b"original message content".as_slice(),  // Case changed
            b"Original message content!".as_slice(), // Added character
            b"Original message conten".as_slice(),   // Truncated
            b"".as_slice(),                          // Empty
            b"Completely different message".as_slice(),
        ];

        for tampered in tampered_messages.iter() {
            let valid = keypair.verify(tampered, &signature).expect("Verification should complete");
            assert!(!valid, "Tampered message should not verify");
        }
    });
}

/// Test signature verification rejects corrupted signature
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_corrupted_signature_rejected() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let message = b"Message with signature to be corrupted";
        let signature = keypair.sign(&mut rng, message).expect("Signing should succeed");

        // Corrupt signature at various positions
        let positions_to_corrupt = [0, 100, 300, 500, 665]; // Various positions in 666-byte sig

        for &pos in &positions_to_corrupt {
            let mut corrupted_bytes = signature.to_bytes();
            if pos < corrupted_bytes.len() {
                corrupted_bytes[pos] ^= 0xFF; // Flip all bits at position
            }

            let corrupted_sig = Signature::from_bytes(corrupted_bytes)
                .expect("Corrupted signature construction should succeed");

            let valid =
                keypair.verify(message, &corrupted_sig).expect("Verification should complete");
            assert!(!valid, "Corrupted signature at position {} should not verify", pos);
        }
    });
}

/// Test empty message signing and verification
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_empty_message() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let empty_message = b"";
        let signature =
            keypair.sign(&mut rng, empty_message).expect("Signing empty message should succeed");

        let valid = keypair.verify(empty_message, &signature).expect("Verification should succeed");
        assert!(valid, "Valid signature for empty message should verify");
    });
}

/// Test large message signing and verification
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_large_message() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        // 1 MB message
        let large_message = vec![0xABu8; 1024 * 1024];
        let signature =
            keypair.sign(&mut rng, &large_message).expect("Signing large message should succeed");

        let valid =
            keypair.verify(&large_message, &signature).expect("Verification should succeed");
        assert!(valid, "Valid signature for large message should verify");
    });
}

/// Test deterministic key generation with seeded RNG
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_deterministic_keygen() {
    run_with_large_stack(|| {
        let seed = [42u8; 32];

        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let keypair1 = KeyPair::generate(&mut rng1, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        let mut rng2 = ChaCha20Rng::from_seed(seed);
        let keypair2 = KeyPair::generate(&mut rng2, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        // Same seed should produce same keys
        assert_eq!(
            keypair1.signing_key().to_bytes(),
            keypair2.signing_key().to_bytes(),
            "Same seed should produce same signing key"
        );
        assert_eq!(
            keypair1.verifying_key().to_bytes(),
            keypair2.verifying_key().to_bytes(),
            "Same seed should produce same verifying key"
        );
    });
}

// ============================================================================
// 2.4.4 NIST KAT Vector Validation
// ============================================================================

/// Test security level parameters match FIPS 206 specification
#[test]
fn test_fndsa_security_level_parameters() {
    // FN-DSA-512 parameters (128-bit security)
    let level512 = FNDsaSecurityLevel::Level512;
    assert_eq!(level512.to_logn(), 9, "Level512 logn should be 9");
    assert_eq!(level512.signature_size(), 666, "Level512 signature size should be 666");
    assert_eq!(level512.signing_key_size(), 1281, "Level512 signing key size should be 1281");
    assert_eq!(level512.verifying_key_size(), 897, "Level512 verifying key size should be 897");

    // FN-DSA-1024 parameters (256-bit security)
    let level1024 = FNDsaSecurityLevel::Level1024;
    assert_eq!(level1024.to_logn(), 10, "Level1024 logn should be 10");
    assert_eq!(level1024.signature_size(), 1280, "Level1024 signature size should be 1280");
    assert_eq!(level1024.signing_key_size(), 2305, "Level1024 signing key size should be 2305");
    assert_eq!(level1024.verifying_key_size(), 1793, "Level1024 verifying key size should be 1793");
}

/// Test default security level
#[test]
fn test_fndsa_default_security_level() {
    let default = FNDsaSecurityLevel::default();
    assert_eq!(default, FNDsaSecurityLevel::Level512, "Default security level should be Level512");
}

/// Test signature construction validation
#[test]
fn test_fndsa_signature_construction() {
    // Empty signature should fail
    let result = Signature::from_bytes(vec![]);
    assert!(result.is_err(), "Empty signature bytes should fail");

    // Valid bytes should succeed
    let valid_bytes = vec![0x42u8; 100];
    let sig = Signature::from_bytes(valid_bytes.clone()).expect("Valid bytes should succeed");
    assert_eq!(sig.len(), 100, "Signature length should match input");
    assert!(!sig.is_empty(), "Signature should not be empty");
    assert_eq!(sig.to_bytes(), valid_bytes, "to_bytes should return original bytes");
    assert_eq!(sig.as_ref(), valid_bytes.as_slice(), "as_ref should return slice");

    // From Vec<u8> conversion
    let from_vec: Signature = vec![0x11u8; 50].into();
    assert_eq!(from_vec.len(), 50, "From conversion should preserve length");
}

/// Test verifying key maintains security level
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_verifying_key_security_level() {
    run_with_large_stack(|| {
        let mut rng = OsRng;

        let keypair512 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");
        assert_eq!(
            keypair512.verifying_key().security_level(),
            FNDsaSecurityLevel::Level512,
            "Verifying key should maintain Level512"
        );

        let keypair1024 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
            .expect("Key generation should succeed");
        assert_eq!(
            keypair1024.verifying_key().security_level(),
            FNDsaSecurityLevel::Level1024,
            "Verifying key should maintain Level1024"
        );
    });
}

/// Test signing key maintains security level
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_signing_key_security_level() {
    run_with_large_stack(|| {
        let mut rng = OsRng;

        let keypair512 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");
        assert_eq!(
            keypair512.signing_key().security_level(),
            FNDsaSecurityLevel::Level512,
            "Signing key should maintain Level512"
        );

        let keypair1024 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
            .expect("Key generation should succeed");
        assert_eq!(
            keypair1024.signing_key().security_level(),
            FNDsaSecurityLevel::Level1024,
            "Signing key should maintain Level1024"
        );
    });
}

// ============================================================================
// Additional Security and Edge Case Tests
// ============================================================================

/// Test that signing key provides access to verifying key
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_signing_key_provides_verifying_key() {
    run_with_large_stack(|| {
        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        // Get verifying key bytes from signing key and from keypair directly
        let vk_bytes_from_sk = keypair.signing_key().verifying_key().to_bytes();
        let vk_bytes_direct = keypair.verifying_key().to_bytes();

        assert_eq!(
            vk_bytes_from_sk, vk_bytes_direct,
            "Verifying key from signing key should match direct verifying key"
        );

        // Verify signature using keypair's verify method
        let message = b"Test message";
        let signature = keypair.sign(&mut rng, message).expect("Signing should succeed");

        let valid = keypair.verify(message, &signature).expect("Verification should succeed");
        assert!(valid, "Keypair should verify its own signature");

        // Also verify using a restored verifying key
        let restored_vk = VerifyingKey::from_bytes(vk_bytes_direct, FNDsaSecurityLevel::Level512)
            .expect("Verifying key restoration should succeed");
        let valid_restored =
            restored_vk.verify(message, &signature).expect("Verification should succeed");
        assert!(valid_restored, "Restored verifying key should verify");
    });
}

/// Test key zeroization
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_key_zeroization() {
    run_with_large_stack(|| {
        use zeroize::Zeroize;

        let mut rng = OsRng;
        let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        // Get original bytes before zeroization
        let original_bytes = keypair.signing_key().to_bytes();
        assert!(
            original_bytes.iter().any(|&b| b != 0),
            "Original key should contain non-zero bytes"
        );

        // Zeroize the keypair
        keypair.zeroize();

        // After zeroization, the signing key bytes should be zeroed
        let zeroized_bytes = keypair.signing_key().to_bytes();
        assert!(zeroized_bytes.iter().all(|&b| b == 0), "Zeroized key bytes should all be zero");
    });
}

/// Test cross-level key rejection
#[test]
#[ignore = "FN-DSA has stack overflow issues in debug mode - run with --release"]
fn test_fndsa_cross_level_rejection() {
    run_with_large_stack(|| {
        let mut rng = OsRng;

        // Generate Level512 keypair
        let mut keypair512 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
            .expect("Key generation should succeed");

        // Generate Level1024 keypair
        let mut keypair1024 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
            .expect("Key generation should succeed");

        let message = b"Cross-level test message";

        // Sign with Level512
        let sig512 = keypair512.sign(&mut rng, message).expect("Signing should succeed");

        // Sign with Level1024
        let sig1024 = keypair1024.sign(&mut rng, message).expect("Signing should succeed");

        // Level512 signature should not verify with Level1024 key
        let cross_verify = keypair1024.verify(message, &sig512);
        // This may error or return false depending on implementation
        match cross_verify {
            Ok(valid) => assert!(!valid, "Level512 sig should not verify with Level1024 key"),
            Err(_) => {} // Error is also acceptable
        }

        // Level1024 signature should not verify with Level512 key
        let cross_verify = keypair512.verify(message, &sig1024);
        match cross_verify {
            Ok(valid) => assert!(!valid, "Level1024 sig should not verify with Level512 key"),
            Err(_) => {} // Error is also acceptable
        }
    });
}
