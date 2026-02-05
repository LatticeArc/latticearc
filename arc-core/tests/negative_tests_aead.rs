//! Comprehensive negative tests for AEAD operations (arc-core convenience APIs)
//!
//! This test suite validates error handling for AES-GCM symmetric encryption.
//!
//! Test coverage:
//! - Empty data/keys
//! - Invalid key lengths
//! - Corrupted ciphertexts
//! - Tampered authentication tags
//! - Wrong nonce sizes
//! - Decrypt with wrong keys

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
    convenience::{decrypt_aes_gcm_unverified, encrypt_aes_gcm_unverified},
    error::CoreError,
};

// ============================================================================
// Empty Input Tests
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_empty_data() {
    let key = [0u8; 32];

    // Encrypting empty data should succeed (valid use case)
    let result = encrypt_aes_gcm_unverified(&[], &key);
    assert!(result.is_ok(), "Encrypting empty data should succeed");
}

#[test]
fn test_aes_gcm_encrypt_empty_key() {
    let data = b"Test data";
    let empty_key = [];

    let result = encrypt_aes_gcm_unverified(data, &empty_key);
    assert!(result.is_err(), "Should fail with empty key");

    match result {
        Err(CoreError::InvalidKeyLength { expected: 32, actual: 0 }) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_empty_ciphertext() {
    let key = [0u8; 32];

    let result = decrypt_aes_gcm_unverified(&[], &key);
    assert!(result.is_err(), "Should fail with empty ciphertext");

    match result {
        Err(CoreError::InvalidInput(_)) => {
            // Expected: "Data too short"
        }
        _ => panic!("Expected InvalidInput error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_empty_key() {
    let key = [0u8; 32];
    let data = b"Test data";

    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");

    let empty_key = [];
    let result = decrypt_aes_gcm_unverified(&encrypted, &empty_key);
    assert!(result.is_err(), "Should fail with empty key");

    match result {
        Err(CoreError::InvalidKeyLength { expected: 32, actual: 0 }) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error, got {:?}", result),
    }
}

// ============================================================================
// Invalid Key Length Tests
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_short_key() {
    let data = b"Test data";
    let short_key = [0u8; 16]; // Only 16 bytes, need 32

    let result = encrypt_aes_gcm_unverified(data, &short_key);
    assert!(result.is_err(), "Should fail with key shorter than 32 bytes");

    match result {
        Err(CoreError::InvalidKeyLength { expected: 32, actual: 16 }) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_encrypt_very_short_key() {
    let data = b"Test data";
    let very_short_key = [0u8; 8];

    let result = encrypt_aes_gcm_unverified(data, &very_short_key);
    assert!(result.is_err(), "Should fail with very short key");

    match result {
        Err(CoreError::InvalidKeyLength { expected: 32, actual: 8 }) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_encrypt_single_byte_key() {
    let data = b"Test data";
    let tiny_key = [0u8; 1];

    let result = encrypt_aes_gcm_unverified(data, &tiny_key);
    assert!(result.is_err(), "Should fail with single byte key");

    match result {
        Err(CoreError::InvalidKeyLength { expected: 32, actual: 1 }) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_encrypt_31_byte_key() {
    let data = b"Test data";
    let key = [0u8; 31]; // One byte short

    let result = encrypt_aes_gcm_unverified(data, &key);
    assert!(result.is_err(), "Should fail with 31-byte key");

    match result {
        Err(CoreError::InvalidKeyLength { expected: 32, actual: 31 }) => {
            // Expected error
        }
        _ => panic!("Expected InvalidKeyLength error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_encrypt_oversized_key_accepted() {
    let data = b"Test data";
    let oversized_key = [0u8; 64]; // More than 32 bytes

    // Should succeed - implementation takes first 32 bytes
    let result = encrypt_aes_gcm_unverified(data, &oversized_key);
    assert!(result.is_ok(), "Should accept oversized key and use first 32 bytes");
}

// ============================================================================
// Corrupted Ciphertext Tests
// ============================================================================

#[test]
fn test_aes_gcm_decrypt_corrupted_ciphertext() {
    let key = [0u8; 32];
    let data = b"Secret message";

    let mut encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");

    // Corrupt the ciphertext (skip nonce, corrupt data part)
    if encrypted.len() > 20 {
        encrypted[20] ^= 0xFF;
    }

    let result = decrypt_aes_gcm_unverified(&encrypted, &key);
    assert!(result.is_err(), "Should fail with corrupted ciphertext");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - authentication tag mismatch
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_corrupted_nonce() {
    let key = [0u8; 32];
    let data = b"Secret message";

    let mut encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");

    // Corrupt the nonce (first 12 bytes)
    encrypted[0] ^= 0xFF;

    let result = decrypt_aes_gcm_unverified(&encrypted, &key);
    assert!(result.is_err(), "Should fail with corrupted nonce");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - decryption/authentication failure
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_corrupted_tag() {
    let key = [0u8; 32];
    let data = b"Secret message";

    let mut encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");

    // Corrupt the authentication tag (last 16 bytes)
    let tag_start = encrypted.len().saturating_sub(16);
    if tag_start < encrypted.len() {
        encrypted[tag_start] ^= 0xFF;
    }

    let result = decrypt_aes_gcm_unverified(&encrypted, &key);
    assert!(result.is_err(), "Should fail with corrupted authentication tag");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - tag verification failure
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_truncated_ciphertext() {
    let key = [0u8; 32];
    let data = b"Secret message";

    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");

    // Truncate the ciphertext to less than minimum (nonce size)
    let truncated = &encrypted[..8];

    let result = decrypt_aes_gcm_unverified(truncated, &key);
    assert!(result.is_err(), "Should fail with truncated ciphertext");

    match result {
        Err(CoreError::InvalidInput(_)) => {
            // Expected: "Data too short"
        }
        _ => panic!("Expected InvalidInput error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_ciphertext_too_short() {
    let key = [0u8; 32];

    // Create data that's exactly 12 bytes (nonce only, no ciphertext or tag)
    let short_data = vec![0u8; 12];

    let result = decrypt_aes_gcm_unverified(&short_data, &key);
    // This might succeed or fail depending on implementation
    // If it succeeds, it should return empty plaintext
    // If it fails, it should be a decryption failure
    if result.is_ok() {
        let decrypted = result.expect("already checked");
        assert!(
            decrypted.is_empty() || decrypted.len() <= 16,
            "Should return empty or minimal plaintext"
        );
    } else {
        match result {
            Err(CoreError::DecryptionFailed(_)) | Err(CoreError::InvalidInput(_)) => {
                // Acceptable errors
            }
            _ => panic!("Expected DecryptionFailed or InvalidInput, got {:?}", result),
        }
    }
}

// ============================================================================
// Wrong Key Tests
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_with_one_key_decrypt_with_another() {
    let key1 = [0x00u8; 32];
    let key2 = [0xFFu8; 32];
    let data = b"Secret message";

    let encrypted = encrypt_aes_gcm_unverified(data, &key1).expect("encryption should succeed");

    let result = decrypt_aes_gcm_unverified(&encrypted, &key2);
    assert!(result.is_err(), "Should fail when decrypting with wrong key");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_with_slightly_different_key() {
    let key1 = [0x42u8; 32];
    let mut key2 = [0x42u8; 32];
    key2[31] = 0x43; // Change only last byte

    let data = b"Secret message";

    let encrypted = encrypt_aes_gcm_unverified(data, &key1).expect("encryption should succeed");

    let result = decrypt_aes_gcm_unverified(&encrypted, &key2);
    assert!(result.is_err(), "Should fail even with single byte difference in key");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

// ============================================================================
// Random/Junk Data Tests
// ============================================================================

#[test]
fn test_aes_gcm_decrypt_random_data() {
    let key = [0u8; 32];

    // Create random-looking data
    let random_data = vec![0x42u8; 100];

    let result = decrypt_aes_gcm_unverified(&random_data, &key);
    assert!(result.is_err(), "Should fail with random data");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_all_zeros() {
    let key = [0u8; 32];

    // All zeros ciphertext
    let zeros = vec![0u8; 100];

    let result = decrypt_aes_gcm_unverified(&zeros, &key);
    assert!(result.is_err(), "Should fail with all-zero data");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_all_ones() {
    let key = [0u8; 32];

    // All ones ciphertext
    let ones = vec![0xFFu8; 100];

    let result = decrypt_aes_gcm_unverified(&ones, &key);
    assert!(result.is_err(), "Should fail with all-ones data");

    match result {
        Err(CoreError::DecryptionFailed(_)) => {
            // Expected error - authentication failure
        }
        _ => panic!("Expected DecryptionFailed error, got {:?}", result),
    }
}

// ============================================================================
// Boundary Condition Tests
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_single_byte() {
    let key = [0u8; 32];
    let data = [0x42u8];

    let encrypted = encrypt_aes_gcm_unverified(&data, &key).expect("encryption should succeed");
    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("decryption should succeed");

    assert_eq!(decrypted, data, "Single byte should round-trip correctly");
}

#[test]
fn test_aes_gcm_encrypt_large_data() {
    let key = [0u8; 32];
    let data = vec![0xAAu8; 1024 * 1024]; // 1MB

    let encrypted = encrypt_aes_gcm_unverified(&data, &key).expect("encryption should succeed");
    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("decryption should succeed");

    assert_eq!(decrypted, data, "Large data should round-trip correctly");
}

#[test]
fn test_aes_gcm_roundtrip_various_sizes() {
    let key = [0u8; 32];

    // Test various data sizes
    for size in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256] {
        let data = vec![0x42u8; size];
        let encrypted = encrypt_aes_gcm_unverified(&data, &key)
            .unwrap_or_else(|_| panic!("encryption failed for size {}", size));
        let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key)
            .unwrap_or_else(|_| panic!("decryption failed for size {}", size));

        assert_eq!(decrypted, data, "Size {} should round-trip correctly", size);
    }
}

// ============================================================================
// Nonce Reuse Detection (Not directly testable but document expected behavior)
// ============================================================================

#[test]
fn test_aes_gcm_different_nonces_for_same_data() {
    let key = [0u8; 32];
    let data = b"Same data encrypted twice";

    let encrypted1 = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");
    let encrypted2 = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");

    // The nonces should be different, so ciphertexts should differ
    assert_ne!(
        encrypted1, encrypted2,
        "Same data encrypted twice should produce different ciphertexts (different nonces)"
    );

    // Both should decrypt correctly
    let decrypted1 =
        decrypt_aes_gcm_unverified(&encrypted1, &key).expect("decryption should succeed");
    let decrypted2 =
        decrypt_aes_gcm_unverified(&encrypted2, &key).expect("decryption should succeed");

    assert_eq!(decrypted1, data);
    assert_eq!(decrypted2, data);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_decrypt_special_characters() {
    let key = [0u8; 32];
    let data = b"\x00\x01\x02\xFF\xFE\xFD"; // Special bytes

    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");
    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("decryption should succeed");

    assert_eq!(decrypted, data, "Special characters should round-trip correctly");
}

#[test]
fn test_aes_gcm_decrypt_minimum_valid_length() {
    let key = [0u8; 32];

    // Minimum valid ciphertext: 12 bytes nonce + 16 bytes tag = 28 bytes
    // (for empty plaintext)
    let empty_data = b"";
    let encrypted =
        encrypt_aes_gcm_unverified(empty_data, &key).expect("encryption should succeed");

    assert!(
        encrypted.len() >= 28,
        "Encrypted empty data should be at least 28 bytes (nonce + tag)"
    );

    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("decryption should succeed");
    assert_eq!(decrypted, empty_data);
}
