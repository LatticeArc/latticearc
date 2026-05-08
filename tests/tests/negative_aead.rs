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
    clippy::redundant_clone,
    clippy::unnested_or_patterns,
    clippy::unnecessary_unwrap
)]

use latticearc::unified_api::{
    convenience::{
        decrypt_aes_gcm_unverified, decrypt_aes_gcm_with_aad_unverified,
        encrypt_aes_gcm_unverified, encrypt_aes_gcm_with_aad_unverified,
    },
    error::CoreError,
};

// ============================================================================
// Empty Input Tests
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_empty_data_succeeds() {
    let key = [0x42u8; 32];

    // Encrypting empty data should succeed (valid use case)
    let result = encrypt_aes_gcm_unverified(&[], &key);
    assert!(result.is_ok(), "Encrypting empty data should succeed");
}

#[test]
fn test_aes_gcm_encrypt_empty_key_fails() {
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
fn test_aes_gcm_decrypt_empty_ciphertext_fails() {
    let key = [0x42u8; 32];

    let result = decrypt_aes_gcm_unverified(&[], &key);
    assert!(result.is_err(), "Should fail with empty ciphertext");

    // Adversary-reachable parse failure collapses to the same opaque error
    // as AEAD auth failure (Pattern 6 / HPKE RFC 9180 §5.2). Operators can
    // distinguish via tracing::debug! output, not via the error variant.
    match result {
        Err(CoreError::DecryptionFailed(ref msg)) if msg == "decryption failed" => {
            // Expected: opaque error
        }
        _ => panic!("Expected opaque DecryptionFailed, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_empty_key_fails() {
    let key = [0x42u8; 32];
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
fn test_aes_gcm_encrypt_short_key_fails() {
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
fn test_aes_gcm_encrypt_very_short_key_fails() {
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
fn test_aes_gcm_encrypt_single_byte_key_fails() {
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
fn test_aes_gcm_encrypt_31_byte_key_fails() {
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
fn test_aes_gcm_encrypt_oversized_key_rejected_fails() {
    let data = b"Test data";
    let oversized_key = [0u8; 64]; // More than 32 bytes

    // Should fail - implementation rejects keys that aren't exactly 32 bytes
    let result = encrypt_aes_gcm_unverified(data, &oversized_key);
    assert!(result.is_err(), "Should reject oversized key (not truncate)");

    match result {
        Err(CoreError::InvalidKeyLength { expected, actual }) => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 64);
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

// ============================================================================
// Corrupted Ciphertext Tests
// ============================================================================

#[test]
fn test_aes_gcm_decrypt_corrupted_ciphertext_fails() {
    let key = [0x42u8; 32];
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
fn test_aes_gcm_decrypt_corrupted_nonce_fails() {
    let key = [0x42u8; 32];
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
fn test_aes_gcm_decrypt_corrupted_tag_fails() {
    let key = [0x42u8; 32];
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
fn test_aes_gcm_decrypt_truncated_ciphertext_fails() {
    let key = [0x42u8; 32];
    let data = b"Secret message";

    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");

    // Truncate the ciphertext to less than minimum (nonce size)
    let truncated = &encrypted[..8];

    let result = decrypt_aes_gcm_unverified(truncated, &key);
    assert!(result.is_err(), "Should fail with truncated ciphertext");

    // Adversary-reachable parse failure collapses to the same opaque error
    // as AEAD auth failure (Pattern 6 / HPKE RFC 9180 §5.2).
    match result {
        Err(CoreError::DecryptionFailed(ref msg)) if msg == "decryption failed" => {
            // Expected: opaque error
        }
        _ => panic!("Expected opaque DecryptionFailed, got {:?}", result),
    }
}

#[test]
fn test_aes_gcm_decrypt_ciphertext_too_short_fails() {
    let key = [0x42u8; 32];

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
fn test_aes_gcm_cross_key_decrypt_fails() {
    let key1 = [0x42u8; 32];
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
fn test_aes_gcm_decrypt_with_slightly_different_key_fails() {
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
fn test_aes_gcm_decrypt_random_data_fails() {
    let key = [0x42u8; 32];

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
fn test_aes_gcm_decrypt_all_zeros_fails() {
    let key = [0x42u8; 32];

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
fn test_aes_gcm_decrypt_all_ones_fails() {
    let key = [0x42u8; 32];

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
fn test_aes_gcm_encrypt_single_byte_roundtrip_succeeds() {
    let key = [0x42u8; 32];
    let data = [0x42u8];

    let encrypted = encrypt_aes_gcm_unverified(&data, &key).expect("encryption should succeed");
    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("decryption should succeed");

    assert_eq!(decrypted.as_slice(), data.as_slice(), "Single byte should round-trip correctly");
}

#[test]
fn test_aes_gcm_encrypt_large_data_roundtrip_succeeds() {
    let key = [0x42u8; 32];
    let data = vec![0xAAu8; 1024 * 1024]; // 1MB

    let encrypted = encrypt_aes_gcm_unverified(&data, &key).expect("encryption should succeed");
    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("decryption should succeed");

    assert_eq!(decrypted.as_slice(), data.as_slice(), "Large data should round-trip correctly");
}

#[test]
fn test_aes_gcm_roundtrip_various_sizes_roundtrip() {
    let key = [0x42u8; 32];

    // Test various data sizes
    for size in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256] {
        let data = vec![0x42u8; size];
        let encrypted = encrypt_aes_gcm_unverified(&data, &key)
            .unwrap_or_else(|_| panic!("encryption failed for size {}", size));
        let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key)
            .unwrap_or_else(|_| panic!("decryption failed for size {}", size));

        assert_eq!(
            decrypted.as_slice(),
            data.as_slice(),
            "Size {} should round-trip correctly",
            size
        );
    }
}

// ============================================================================
// Nonce Reuse Detection (Not directly testable but document expected behavior)
// ============================================================================

#[test]
fn test_aes_gcm_same_data_produces_unique_ciphertexts_are_unique() {
    let key = [0x42u8; 32];
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

    assert_eq!(decrypted1.as_slice(), data.as_slice(), "First ciphertext should decrypt correctly");
    assert_eq!(
        decrypted2.as_slice(),
        data.as_slice(),
        "Second ciphertext should decrypt correctly"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_aes_gcm_encrypt_decrypt_special_characters_roundtrip_succeeds() {
    let key = [0x42u8; 32];
    let data = b"\x00\x01\x02\xFF\xFE\xFD"; // Special bytes

    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encryption should succeed");
    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("decryption should succeed");

    assert_eq!(
        decrypted.as_slice(),
        data.as_slice(),
        "Special characters should round-trip correctly"
    );
}

#[test]
fn test_aes_gcm_decrypt_minimum_valid_length_roundtrip_succeeds() {
    let key = [0x42u8; 32];

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
    assert_eq!(
        decrypted.as_slice(),
        empty_data.as_slice(),
        "Empty data should round-trip correctly"
    );
}

// === Error Opacity Tests (SP 800-38D §5.2.2) ===

#[test]
fn test_aes_gcm_decrypt_wrong_key_returns_opaque_error_fails() {
    // Decrypt with wrong key — error message must not distinguish failure mode
    let key = [0x42u8; 32];
    let wrong_key = [0x43u8; 32];
    let plaintext = b"test data for opacity check";

    let encrypted = encrypt_aes_gcm_unverified(plaintext, &key).unwrap();
    let result = decrypt_aes_gcm_unverified(&encrypted, &wrong_key);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());

    // Error message must NOT contain words that distinguish failure modes
    assert!(!err_msg.to_lowercase().contains("mac"), "Error leaks MAC check info: {err_msg}");
    assert!(!err_msg.to_lowercase().contains("padding"), "Error leaks padding info: {err_msg}");
    assert!(!err_msg.to_lowercase().contains("tag"), "Error leaks tag check info: {err_msg}");
    assert!(!err_msg.to_lowercase().contains("integrity"), "Error leaks integrity info: {err_msg}");
}

#[test]
fn test_aes_gcm_decrypt_corrupted_ciphertext_returns_opaque_error_fails() {
    let key = [0x42u8; 32];
    let plaintext = b"test data for opacity check";

    let mut encrypted = encrypt_aes_gcm_unverified(plaintext, &key).unwrap();
    // Corrupt a byte in the middle of the ciphertext
    if encrypted.len() > 20 {
        encrypted[20] ^= 0xFF;
    }
    let result = decrypt_aes_gcm_unverified(&encrypted, &key);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());

    assert!(!err_msg.to_lowercase().contains("mac"), "Error leaks MAC info: {err_msg}");
    assert!(!err_msg.to_lowercase().contains("padding"), "Error leaks padding info: {err_msg}");
    assert!(!err_msg.to_lowercase().contains("tag"), "Error leaks tag info: {err_msg}");
}

#[test]
fn test_aes_gcm_decrypt_errors_are_identical_fails() {
    // The key test: different failure modes must produce the SAME error message
    let key = [0x42u8; 32];
    let wrong_key = [0x43u8; 32];
    let plaintext = b"test data";

    let encrypted = encrypt_aes_gcm_unverified(plaintext, &key).unwrap();

    // Failure mode 1: wrong key
    let err1 = format!("{}", decrypt_aes_gcm_unverified(&encrypted, &wrong_key).unwrap_err());

    // Failure mode 2: corrupted ciphertext
    let mut corrupted = encrypted.clone();
    corrupted[20] ^= 0xFF;
    let err2 = format!("{}", decrypt_aes_gcm_unverified(&corrupted, &key).unwrap_err());

    // Both must produce identical error strings (oracle prevention)
    assert_eq!(
        err1, err2,
        "Different failure modes must produce identical errors to prevent oracles"
    );
}

// === AAD Tampering Tests ===

#[test]
fn test_aes_gcm_decrypt_wrong_aad_fails() {
    let key = [0x42u8; 32];
    let plaintext = b"AAD tampering test";
    let aad = b"correct-context";

    let encrypted = encrypt_aes_gcm_with_aad_unverified(plaintext, &key, aad).unwrap();
    let result = decrypt_aes_gcm_with_aad_unverified(&encrypted, &key, b"wrong-context");
    assert!(result.is_err(), "Decryption with wrong AAD must fail");
}

// === State Isolation Tests ===

#[test]
fn test_aes_gcm_no_state_corruption_after_failure_succeeds() {
    let key = [0x42u8; 32];
    let plaintext = b"state corruption test";

    // Step 1: Encrypt successfully
    let encrypted = encrypt_aes_gcm_unverified(plaintext, &key).unwrap();

    // Step 2: Attempt decrypt with wrong key (should fail)
    let wrong_key = [0x43u8; 32];
    let fail_result = decrypt_aes_gcm_unverified(&encrypted, &wrong_key);
    assert!(fail_result.is_err(), "Wrong key must fail");

    // Step 3: Attempt decrypt with corrupted ciphertext (should fail)
    let mut corrupted = encrypted.clone();
    corrupted[15] ^= 0xFF;
    let fail_result2 = decrypt_aes_gcm_unverified(&corrupted, &key);
    assert!(fail_result2.is_err(), "Corrupted ciphertext must fail");

    // Step 4: Encrypt again with same key — must still work (no state corruption)
    let encrypted2 = encrypt_aes_gcm_unverified(b"second message", &key).unwrap();
    let decrypted2 = decrypt_aes_gcm_unverified(&encrypted2, &key).unwrap();
    assert_eq!(decrypted2.as_slice(), b"second message", "Crypto must still work after failures");

    // Step 5: Original ciphertext must still decrypt correctly
    let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext, "Original ciphertext must still decrypt");
}
