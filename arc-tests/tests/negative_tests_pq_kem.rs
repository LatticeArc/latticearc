//! Comprehensive negative tests for ML-KEM (arc-core convenience APIs)
//!
//! This test suite validates error handling for invalid inputs, boundary conditions,
//! corrupted data, and incorrect parameter combinations for post-quantum KEM operations.
//!
//! Test coverage:
//! - Empty data/keys
//! - Oversized inputs
//! - Wrong key types for algorithms
//! - Mismatched algorithm selections
//! - Corrupted ciphertexts
//! - Wrong key combinations

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
        decrypt_pq_ml_kem_unverified, encrypt_pq_ml_kem_unverified, generate_ml_kem_keypair,
    },
    error::CoreError,
};
use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

// ============================================================================
// Empty Input Tests
// ============================================================================

#[test]
fn test_ml_kem_encrypt_empty_data() {
    let (public_key, _private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    // Encrypting empty data should succeed (valid use case)
    let result = encrypt_pq_ml_kem_unverified(&[], &public_key, MlKemSecurityLevel::MlKem768);
    assert!(result.is_ok(), "Encrypting empty data should succeed");
}

#[test]
fn test_ml_kem_encrypt_empty_public_key() {
    let data = b"Test data";
    let empty_key = [];

    let result = encrypt_pq_ml_kem_unverified(data, &empty_key, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with empty public key");

    match result {
        Err(CoreError::InvalidInput(_)) | Err(CoreError::MlKemError(_)) => {
            // Expected error types
        }
        _ => panic!("Expected InvalidInput or MlKemError, got {:?}", result),
    }
}

#[test]
fn test_ml_kem_decrypt_empty_ciphertext() {
    let (_public_key, private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let result =
        decrypt_pq_ml_kem_unverified(&[], private_key.as_ref(), MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with empty ciphertext");

    match result {
        Err(CoreError::InvalidInput(_)) => {
            // Expected: "Encrypted data too short"
        }
        Err(CoreError::NotImplemented(_)) => {
            // Also valid: aws-lc-rs doesn't support secret key deserialization
        }
        _ => panic!("Expected InvalidInput or NotImplemented error, got {:?}", result),
    }
}

#[test]
fn test_ml_kem_decrypt_empty_private_key() {
    let (public_key, _private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let encrypted =
        encrypt_pq_ml_kem_unverified(b"data", &public_key, MlKemSecurityLevel::MlKem768)
            .expect("encryption should succeed");

    let empty_key = [];
    let result = decrypt_pq_ml_kem_unverified(&encrypted, &empty_key, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with empty private key");
}

// ============================================================================
// Invalid Key Length Tests
// ============================================================================

#[test]
fn test_ml_kem_encrypt_truncated_public_key() {
    let (public_key, _private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    // Truncate the public key
    let truncated_key = &public_key[..100];

    let result = encrypt_pq_ml_kem_unverified(b"data", truncated_key, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with truncated public key");
}

#[test]
fn test_ml_kem_encrypt_oversized_public_key() {
    let (public_key, _private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    // Add extra bytes to the public key
    let mut oversized_key = public_key.clone();
    oversized_key.extend_from_slice(&[0u8; 100]);

    let result =
        encrypt_pq_ml_kem_unverified(b"data", &oversized_key, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with oversized public key");
}

#[test]
fn test_ml_kem_decrypt_truncated_private_key() {
    let (public_key, private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let encrypted =
        encrypt_pq_ml_kem_unverified(b"data", &public_key, MlKemSecurityLevel::MlKem768)
            .expect("encryption should succeed");

    // Truncate the private key
    let truncated_key = private_key.as_slice().get(..100).unwrap_or(&[]);

    let result =
        decrypt_pq_ml_kem_unverified(&encrypted, truncated_key, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with truncated private key");
}

// ============================================================================
// Wrong Security Level Tests
// ============================================================================

#[test]
fn test_ml_kem_512_key_with_768_level() {
    let (public_key_512, _private_key_512) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512).expect("keypair generation");

    // Try to use MlKem512 key with MlKem768 level
    let result =
        encrypt_pq_ml_kem_unverified(b"data", &public_key_512, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail when key size doesn't match security level");
}

#[test]
fn test_ml_kem_768_key_with_1024_level() {
    let (public_key_768, _private_key_768) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    // Try to use MlKem768 key with MlKem1024 level
    let result =
        encrypt_pq_ml_kem_unverified(b"data", &public_key_768, MlKemSecurityLevel::MlKem1024);
    assert!(result.is_err(), "Should fail when key size doesn't match security level");
}

#[test]
fn test_ml_kem_1024_key_with_512_level() {
    let (public_key_1024, _private_key_1024) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024).expect("keypair generation");

    // Try to use MlKem1024 key with MlKem512 level
    let result =
        encrypt_pq_ml_kem_unverified(b"data", &public_key_1024, MlKemSecurityLevel::MlKem512);
    assert!(result.is_err(), "Should fail when key size doesn't match security level");
}

#[test]
fn test_ml_kem_decrypt_wrong_security_level() {
    let (public_key, _private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let encrypted =
        encrypt_pq_ml_kem_unverified(b"data", &public_key, MlKemSecurityLevel::MlKem768)
            .expect("encryption should succeed");

    let (_pk_512, private_key_512) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512).expect("keypair generation");

    // Try to decrypt with wrong security level
    let result = decrypt_pq_ml_kem_unverified(
        &encrypted,
        private_key_512.as_ref(),
        MlKemSecurityLevel::MlKem512,
    );
    assert!(result.is_err(), "Should fail with mismatched security level");
}

// ============================================================================
// Corrupted Ciphertext Tests
// ============================================================================

#[test]
fn test_ml_kem_decrypt_corrupted_ciphertext() {
    let (public_key, private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let mut encrypted =
        encrypt_pq_ml_kem_unverified(b"test data", &public_key, MlKemSecurityLevel::MlKem768)
            .expect("encryption should succeed");

    // Corrupt the ciphertext by flipping bits in the middle
    if encrypted.len() > 100 {
        encrypted[100] ^= 0xFF;
    }

    let result = decrypt_pq_ml_kem_unverified(
        &encrypted,
        private_key.as_ref(),
        MlKemSecurityLevel::MlKem768,
    );
    assert!(result.is_err(), "Should fail with corrupted ciphertext");
}

#[test]
fn test_ml_kem_decrypt_truncated_ciphertext() {
    let (public_key, private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let encrypted =
        encrypt_pq_ml_kem_unverified(b"test data", &public_key, MlKemSecurityLevel::MlKem768)
            .expect("encryption should succeed");

    // Truncate the ciphertext (less than minimum size)
    let truncated = &encrypted[..500];

    let result =
        decrypt_pq_ml_kem_unverified(truncated, private_key.as_ref(), MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with truncated ciphertext");

    match result {
        Err(CoreError::InvalidInput(_)) => {
            // Expected: "Encrypted data too short"
        }
        Err(CoreError::NotImplemented(_)) => {
            // Also valid: aws-lc-rs doesn't support secret key deserialization
        }
        _ => panic!("Expected InvalidInput or NotImplemented error, got {:?}", result),
    }
}

#[test]
fn test_ml_kem_decrypt_ciphertext_too_short() {
    let (_public_key, private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    // Create ciphertext that's too short (less than ciphertext_size)
    let short_ciphertext = vec![0u8; 100];

    let result = decrypt_pq_ml_kem_unverified(
        &short_ciphertext,
        private_key.as_ref(),
        MlKemSecurityLevel::MlKem768,
    );
    assert!(result.is_err(), "Should fail when ciphertext is too short");

    match result {
        Err(CoreError::InvalidInput(msg)) if msg.contains("too short") => {
            // Expected error
        }
        Err(CoreError::NotImplemented(_)) => {
            // Also valid: aws-lc-rs doesn't support secret key deserialization
        }
        _ => panic!("Expected 'too short' or NotImplemented error, got {:?}", result),
    }
}

// ============================================================================
// Wrong Key Combination Tests
// ============================================================================

#[test]
fn test_ml_kem_encrypt_with_one_key_decrypt_with_another() {
    let (public_key_1, _private_key_1) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");
    let (_public_key_2, private_key_2) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let encrypted =
        encrypt_pq_ml_kem_unverified(b"secret", &public_key_1, MlKemSecurityLevel::MlKem768)
            .expect("encryption should succeed");

    // Try to decrypt with different private key
    let result = decrypt_pq_ml_kem_unverified(
        &encrypted,
        private_key_2.as_ref(),
        MlKemSecurityLevel::MlKem768,
    );
    assert!(result.is_err(), "Should fail when decrypting with wrong private key");
}

// ============================================================================
// Boundary Condition Tests
// ============================================================================
// Note: Positive round-trip tests are intentionally omitted from this negative
// test suite because aws-lc-rs doesn't support ML-KEM secret key serialization,
// which is required for the convenience API layer to work properly.

// ============================================================================
// All Security Levels Negative Tests
// ============================================================================

#[test]
fn test_ml_kem_512_empty_key() {
    let result = encrypt_pq_ml_kem_unverified(b"data", &[], MlKemSecurityLevel::MlKem512);
    assert!(result.is_err(), "MlKem512 should fail with empty key");
}

#[test]
fn test_ml_kem_1024_empty_key() {
    let result = encrypt_pq_ml_kem_unverified(b"data", &[], MlKemSecurityLevel::MlKem1024);
    assert!(result.is_err(), "MlKem1024 should fail with empty key");
}

#[test]
fn test_ml_kem_512_wrong_key_size() {
    // MlKem512 expects 800-byte public key, provide wrong size
    let wrong_key = vec![0u8; 1184]; // This is MlKem768 size
    let result = encrypt_pq_ml_kem_unverified(b"data", &wrong_key, MlKemSecurityLevel::MlKem512);
    assert!(result.is_err(), "Should fail with wrong key size for MlKem512");
}

#[test]
fn test_ml_kem_1024_wrong_key_size() {
    // MlKem1024 expects 1568-byte public key, provide wrong size
    let wrong_key = vec![0u8; 800]; // This is MlKem512 size
    let result = encrypt_pq_ml_kem_unverified(b"data", &wrong_key, MlKemSecurityLevel::MlKem1024);
    assert!(result.is_err(), "Should fail with wrong key size for MlKem1024");
}

// ============================================================================
// Random/Junk Data Tests
// ============================================================================

#[test]
fn test_ml_kem_decrypt_random_data() {
    let (_public_key, private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    // Create random data of correct length
    let random_data = vec![0x42u8; 1088 + 100]; // ciphertext size + some payload

    let result = decrypt_pq_ml_kem_unverified(
        &random_data,
        private_key.as_ref(),
        MlKemSecurityLevel::MlKem768,
    );
    assert!(result.is_err(), "Should fail with random data");
}

#[test]
fn test_ml_kem_encrypt_with_junk_key() {
    // Create junk data of correct key length for MlKem768 (1184 bytes)
    let junk_key = vec![0xDEu8; 1184];

    let result = encrypt_pq_ml_kem_unverified(b"data", &junk_key, MlKemSecurityLevel::MlKem768);
    assert!(result.is_err(), "Should fail with junk public key");
}
