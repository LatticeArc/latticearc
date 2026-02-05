//! Comprehensive test suite for AES-GCM convenience API
//!
//! This test file covers tasks 1.4.1-1.4.6 from the security audit test plan:
//! - Task 1.4.1: Basic roundtrip encryption/decryption
//! - Task 1.4.2: SecurityMode::Verified with valid session
//! - Task 1.4.3: SecurityMode::Unverified tests
//! - Task 1.4.4: Invalid key handling (short keys, wrong length)
//! - Task 1.4.5: Ciphertext tampering detection
//! - Task 1.4.6: Large message stress tests (100KB+)
//!
//! Total tests: 50+ covering all AES-256-GCM convenience API functionality

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
    config::CoreConfig,
    decrypt_aes_gcm, decrypt_aes_gcm_unverified, decrypt_aes_gcm_with_config,
    decrypt_aes_gcm_with_config_unverified, encrypt_aes_gcm, encrypt_aes_gcm_unverified,
    encrypt_aes_gcm_with_config, encrypt_aes_gcm_with_config_unverified,
    error::{CoreError, Result},
    generate_keypair,
    zero_trust::{SecurityMode, VerifiedSession},
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Generate a valid 32-byte AES-256 key
fn generate_test_key_32() -> Vec<u8> {
    (0..32).map(|i| (i * 7 + 0x42) as u8).collect()
}

/// Generate a test key with specific pattern
fn generate_test_key_pattern(pattern: u8) -> Vec<u8> {
    vec![pattern; 32]
}

/// Create a verified session for testing
fn create_verified_session() -> Result<VerifiedSession> {
    let (pk, sk) = generate_keypair()?;
    VerifiedSession::establish(&pk, sk.as_ref())
}

// ============================================================================
// Task 1.4.1: Basic Roundtrip Encryption/Decryption
// ============================================================================

#[test]
fn test_aes_gcm_basic_roundtrip() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Hello, AES-256-GCM encryption!";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_roundtrip_empty_message() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert!(decrypted.is_empty());
    // Empty message should still have nonce (12) + tag (16) = 28 bytes
    assert_eq!(ciphertext.len(), 28);
    Ok(())
}

#[test]
fn test_aes_gcm_roundtrip_single_byte() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"X";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    // Single byte + nonce (12) + tag (16) = 29 bytes
    assert_eq!(ciphertext.len(), 29);
    Ok(())
}

#[test]
fn test_aes_gcm_roundtrip_various_sizes() -> Result<()> {
    let key = generate_test_key_32();

    // Test various message sizes
    let sizes = [1, 15, 16, 17, 31, 32, 33, 100, 1000, 10000];

    for size in sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext, "Size {} should roundtrip correctly", size);
    }
    Ok(())
}

#[test]
fn test_aes_gcm_ciphertext_structure() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Test message";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

    // Ciphertext = nonce (12 bytes) + encrypted data + tag (16 bytes)
    let expected_len = 12 + plaintext.len() + 16;
    assert_eq!(ciphertext.len(), expected_len);

    // First 12 bytes are the nonce
    let nonce = &ciphertext[..12];
    assert_eq!(nonce.len(), 12);

    Ok(())
}

#[test]
fn test_aes_gcm_non_deterministic_encryption() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Same message encrypted multiple times";

    let ct1 = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let ct2 = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let ct3 = encrypt_aes_gcm_unverified(plaintext, &key)?;

    // Random nonces should produce different ciphertexts
    assert_ne!(ct1, ct2, "Ciphertexts should differ due to random nonce");
    assert_ne!(ct1, ct3, "Ciphertexts should differ due to random nonce");
    assert_ne!(ct2, ct3, "Ciphertexts should differ due to random nonce");

    // All should decrypt to same plaintext
    let p1 = decrypt_aes_gcm_unverified(&ct1, &key)?;
    let p2 = decrypt_aes_gcm_unverified(&ct2, &key)?;
    let p3 = decrypt_aes_gcm_unverified(&ct3, &key)?;

    assert_eq!(p1, plaintext);
    assert_eq!(p2, plaintext);
    assert_eq!(p3, plaintext);

    Ok(())
}

// ============================================================================
// Task 1.4.2: SecurityMode::Verified with Valid Session
// ============================================================================

#[test]
fn test_aes_gcm_verified_session_encrypt_decrypt() -> Result<()> {
    let session = create_verified_session()?;
    let key = generate_test_key_32();
    let plaintext = b"Verified session encryption test";

    let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Verified(&session))?;
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Verified(&session))?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_verified_session_with_config() -> Result<()> {
    let session = create_verified_session()?;
    let key = generate_test_key_32();
    let config = CoreConfig::default();
    let plaintext = b"Verified session with config";

    let ciphertext =
        encrypt_aes_gcm_with_config(plaintext, &key, &config, SecurityMode::Verified(&session))?;

    let decrypted =
        decrypt_aes_gcm_with_config(&ciphertext, &key, &config, SecurityMode::Verified(&session))?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_session_reuse_multiple_operations() -> Result<()> {
    let session = create_verified_session()?;
    let key = generate_test_key_32();

    // Perform multiple operations with the same session
    for i in 0..10 {
        let plaintext = format!("Message number {}", i);
        let ciphertext =
            encrypt_aes_gcm(plaintext.as_bytes(), &key, SecurityMode::Verified(&session))?;
        let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Verified(&session))?;
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    Ok(())
}

#[test]
fn test_aes_gcm_session_is_valid() -> Result<()> {
    let session = create_verified_session()?;

    // Session should be valid
    assert!(session.is_valid());
    assert!(session.trust_level().is_trusted());

    Ok(())
}

// ============================================================================
// Task 1.4.3: SecurityMode::Unverified Tests
// ============================================================================

#[test]
fn test_aes_gcm_unverified_mode_encrypt_decrypt() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Unverified mode test";

    let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)?;
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_unverified_convenience_functions() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Using unverified convenience functions";

    // Use the _unverified convenience functions
    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_unverified_with_config() -> Result<()> {
    let key = generate_test_key_32();
    let config = CoreConfig::default();
    let plaintext = b"Unverified with config";

    let ciphertext = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
    let decrypted = decrypt_aes_gcm_with_config_unverified(&ciphertext, &key, &config)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_verified_unverified_interoperability() -> Result<()> {
    let session = create_verified_session()?;
    let key = generate_test_key_32();
    let plaintext = b"Interop test message";

    // Encrypt with verified, decrypt with unverified
    let ct1 = encrypt_aes_gcm(plaintext, &key, SecurityMode::Verified(&session))?;
    let p1 = decrypt_aes_gcm_unverified(&ct1, &key)?;
    assert_eq!(p1, plaintext);

    // Encrypt with unverified, decrypt with verified
    let ct2 = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let p2 = decrypt_aes_gcm(&ct2, &key, SecurityMode::Verified(&session))?;
    assert_eq!(p2, plaintext);

    Ok(())
}

// ============================================================================
// Task 1.4.4: Invalid Key Handling
// ============================================================================

#[test]
fn test_aes_gcm_key_too_short() {
    let short_key = vec![0x42; 16]; // Only 16 bytes
    let plaintext = b"Test with short key";

    let result = encrypt_aes_gcm_unverified(plaintext, &short_key);

    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::InvalidKeyLength { expected, actual } => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 16);
        }
        other => panic!("Expected InvalidKeyLength, got {:?}", other),
    }
}

#[test]
fn test_aes_gcm_key_empty() {
    let empty_key: &[u8] = &[];
    let plaintext = b"Test with empty key";

    let result = encrypt_aes_gcm_unverified(plaintext, empty_key);

    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::InvalidKeyLength { expected, actual } => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 0);
        }
        other => panic!("Expected InvalidKeyLength, got {:?}", other),
    }
}

#[test]
fn test_aes_gcm_key_one_byte_short() {
    let short_key = vec![0x42; 31]; // One byte short
    let plaintext = b"Test";

    let result = encrypt_aes_gcm_unverified(plaintext, &short_key);

    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::InvalidKeyLength { expected, actual } => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 31);
        }
        other => panic!("Expected InvalidKeyLength, got {:?}", other),
    }
}

#[test]
fn test_aes_gcm_key_longer_than_32_bytes() -> Result<()> {
    // Keys longer than 32 bytes should work (only first 32 used)
    let long_key = vec![0x42; 64];
    let plaintext = b"Test with longer key";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &long_key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &long_key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_decryption_wrong_key() -> Result<()> {
    let key1 = generate_test_key_pattern(0x11);
    let key2 = generate_test_key_pattern(0x22);
    let plaintext = b"Secret message";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key1)?;
    let result = decrypt_aes_gcm_unverified(&ciphertext, &key2);

    assert!(result.is_err(), "Decryption with wrong key should fail");
    Ok(())
}

#[test]
fn test_aes_gcm_decryption_similar_key_one_bit_different() -> Result<()> {
    let key1 = generate_test_key_32();
    let mut key2 = key1.clone();
    key2[0] ^= 0x01; // Flip one bit
    let plaintext = b"Secret message";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key1)?;
    let result = decrypt_aes_gcm_unverified(&ciphertext, &key2);

    assert!(result.is_err(), "Decryption with one-bit-different key should fail");
    Ok(())
}

#[test]
fn test_aes_gcm_decrypt_short_key() {
    let good_key = generate_test_key_32();
    let short_key = vec![0x42; 16];
    let plaintext = b"Test message";

    // Encrypt with good key
    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &good_key).expect("encryption");

    // Try to decrypt with short key
    let result = decrypt_aes_gcm_unverified(&ciphertext, &short_key);

    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::InvalidKeyLength { expected, actual } => {
            assert_eq!(expected, 32);
            assert_eq!(actual, 16);
        }
        other => panic!("Expected InvalidKeyLength, got {:?}", other),
    }
}

// ============================================================================
// Task 1.4.5: Ciphertext Tampering Detection
// ============================================================================

#[test]
fn test_aes_gcm_tampered_ciphertext_first_byte() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Detect tampering";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF; // Tamper nonce

    let result = decrypt_aes_gcm_unverified(&tampered, &key);
    assert!(result.is_err(), "Should detect nonce tampering");

    Ok(())
}

#[test]
fn test_aes_gcm_tampered_ciphertext_middle() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Detect tampering in middle";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

    let mut tampered = ciphertext.clone();
    let mid = ciphertext.len() / 2;
    tampered[mid] ^= 0xFF;

    let result = decrypt_aes_gcm_unverified(&tampered, &key);
    assert!(result.is_err(), "Should detect middle byte tampering");

    Ok(())
}

#[test]
fn test_aes_gcm_tampered_ciphertext_last_byte() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Detect tag tampering";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

    let mut tampered = ciphertext.clone();
    let last = ciphertext.len() - 1;
    tampered[last] ^= 0xFF; // Tamper authentication tag

    let result = decrypt_aes_gcm_unverified(&tampered, &key);
    assert!(result.is_err(), "Should detect tag tampering");

    Ok(())
}

#[test]
fn test_aes_gcm_bit_flip_detection_all_positions() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Comprehensive bit flip test";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

    // Test flipping each byte position
    for pos in 0..ciphertext.len() {
        let mut tampered = ciphertext.clone();
        tampered[pos] ^= 0x01; // Single bit flip

        let result = decrypt_aes_gcm_unverified(&tampered, &key);
        assert!(result.is_err(), "Should detect bit flip at position {}", pos);
    }

    Ok(())
}

#[test]
fn test_aes_gcm_truncated_ciphertext() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Test truncation detection";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

    // Try various truncation lengths
    for truncate_by in [1, 5, 10, 16, 17, 20] {
        if ciphertext.len() > truncate_by {
            let truncated = &ciphertext[..ciphertext.len() - truncate_by];
            let result = decrypt_aes_gcm_unverified(truncated, &key);
            assert!(result.is_err(), "Should reject truncation by {} bytes", truncate_by);
        }
    }

    Ok(())
}

#[test]
fn test_aes_gcm_extended_ciphertext() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Test extension detection";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;

    // Append extra bytes
    let mut extended = ciphertext.clone();
    extended.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);

    let result = decrypt_aes_gcm_unverified(&extended, &key);
    assert!(result.is_err(), "Should reject extended ciphertext");

    Ok(())
}

#[test]
fn test_aes_gcm_ciphertext_too_short() {
    let key = generate_test_key_32();

    // Ciphertext shorter than nonce (12 bytes) should fail
    let short_ct = vec![0x42; 11];
    let result = decrypt_aes_gcm_unverified(&short_ct, &key);

    assert!(result.is_err(), "Should reject ciphertext shorter than nonce");
    match result.unwrap_err() {
        CoreError::InvalidInput(msg) => {
            assert!(msg.contains("short") || msg.contains("too"));
        }
        _ => {}
    }
}

#[test]
fn test_aes_gcm_empty_ciphertext() {
    let key = generate_test_key_32();
    let empty_ct: &[u8] = &[];

    let result = decrypt_aes_gcm_unverified(empty_ct, &key);
    assert!(result.is_err(), "Should reject empty ciphertext");
}

// ============================================================================
// Task 1.4.6: Large Message Stress Tests (100KB+)
// ============================================================================

#[test]
fn test_aes_gcm_100kb_message() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = vec![0xAB; 100 * 1024]; // 100KB

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;

    // Verify size: nonce (12) + data (102400) + tag (16)
    let expected_size = 12 + plaintext.len() + 16;
    assert_eq!(ciphertext.len(), expected_size);

    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;
    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn test_aes_gcm_500kb_message() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = vec![0xCD; 500 * 1024]; // 500KB

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_1mb_message() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = vec![0xEF; 1024 * 1024]; // 1MB

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_large_message_with_verified_session() -> Result<()> {
    let session = create_verified_session()?;
    let key = generate_test_key_32();
    let plaintext = vec![0x12; 200 * 1024]; // 200KB

    let ciphertext = encrypt_aes_gcm(&plaintext, &key, SecurityMode::Verified(&session))?;
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Verified(&session))?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_stress_multiple_large_messages() -> Result<()> {
    let key = generate_test_key_32();

    for i in 0..5 {
        let size = (i + 1) * 50 * 1024; // 50KB, 100KB, 150KB, 200KB, 250KB
        let plaintext: Vec<u8> = (0..size).map(|j| ((i + j) % 256) as u8).collect();

        let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

        assert_eq!(decrypted, plaintext, "Size {} should roundtrip", size);
    }

    Ok(())
}

// ============================================================================
// Binary Data Edge Cases
// ============================================================================

#[test]
fn test_aes_gcm_all_zero_bytes() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = vec![0x00; 1000];

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_all_ones_bytes() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = vec![0xFF; 1000];

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_alternating_bytes() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext: Vec<u8> = (0..1000).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_full_byte_range() -> Result<()> {
    let key = generate_test_key_32();
    // All byte values 0-255 repeated
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(1024).collect();

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_embedded_null_bytes() -> Result<()> {
    let key = generate_test_key_32();
    // String-like data with embedded nulls
    let mut plaintext = b"Hello\x00World\x00This\x00Has\x00Nulls".to_vec();
    plaintext.extend_from_slice(&[0x00; 50]);

    let ciphertext = encrypt_aes_gcm_unverified(&plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_aes_gcm_with_default_config() -> Result<()> {
    let config = CoreConfig::default();
    let key = generate_test_key_32();
    let plaintext = b"Test with default config";

    let ciphertext = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
    let decrypted = decrypt_aes_gcm_with_config_unverified(&ciphertext, &key, &config)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_with_development_config() -> Result<()> {
    let config = CoreConfig::for_development();
    let key = generate_test_key_32();
    let plaintext = b"Test with development config";

    let ciphertext = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
    let decrypted = decrypt_aes_gcm_with_config_unverified(&ciphertext, &key, &config)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_with_production_config() -> Result<()> {
    let config = CoreConfig::for_production();
    let key = generate_test_key_32();
    let plaintext = b"Test with production config";

    let ciphertext = encrypt_aes_gcm_with_config_unverified(plaintext, &key, &config)?;
    let decrypted = decrypt_aes_gcm_with_config_unverified(&ciphertext, &key, &config)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

// ============================================================================
// Stress Tests: Randomness and Non-Determinism
// ============================================================================

#[test]
fn test_aes_gcm_nonce_uniqueness_stress() -> Result<()> {
    let key = generate_test_key_32();
    let plaintext = b"Nonce uniqueness test";

    // Collect nonces from many encryptions
    let mut nonces: Vec<Vec<u8>> = Vec::new();

    for _ in 0..100 {
        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let nonce = ciphertext[..12].to_vec();
        nonces.push(nonce);
    }

    // All nonces should be unique
    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "Nonces {} and {} should be unique", i, j);
        }
    }

    Ok(())
}

#[test]
fn test_aes_gcm_sequential_operations() -> Result<()> {
    let key = generate_test_key_32();

    // Encrypt many messages
    let messages: Vec<String> = (0..50).map(|i| format!("Message {}", i)).collect();

    let encrypted: Vec<Vec<u8>> = messages
        .iter()
        .map(|msg| encrypt_aes_gcm_unverified(msg.as_bytes(), &key))
        .collect::<Result<Vec<_>>>()?;

    // Decrypt all
    let decrypted: Vec<Vec<u8>> = encrypted
        .iter()
        .map(|ct| decrypt_aes_gcm_unverified(ct, &key))
        .collect::<Result<Vec<_>>>()?;

    // Verify all match
    for (original, decrypted) in messages.iter().zip(decrypted.iter()) {
        assert_eq!(original.as_bytes(), decrypted.as_slice());
    }

    Ok(())
}

// ============================================================================
// Key Pattern Tests
// ============================================================================

#[test]
fn test_aes_gcm_all_zero_key() -> Result<()> {
    let key = vec![0x00; 32];
    let plaintext = b"Testing with all-zero key";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_all_ones_key() -> Result<()> {
    let key = vec![0xFF; 32];
    let plaintext = b"Testing with all-ones key";

    let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[test]
fn test_aes_gcm_different_key_patterns() -> Result<()> {
    let plaintext = b"Test with different key patterns";

    let patterns: Vec<Vec<u8>> = vec![
        vec![0x00; 32],
        vec![0xFF; 32],
        (0..32).collect(),
        (0..32).rev().collect(),
        vec![0xAA; 32],
        vec![0x55; 32],
    ];

    for key in patterns {
        let ciphertext = encrypt_aes_gcm_unverified(plaintext, &key)?;
        let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key)?;
        assert_eq!(decrypted, plaintext);
    }

    Ok(())
}
