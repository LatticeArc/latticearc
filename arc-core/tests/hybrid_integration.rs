//! Comprehensive integration tests for hybrid encryption APIs
//!
//! This test suite validates the hybrid encryption convenience APIs in arc-core,
//! which combine ML-KEM (FIPS 203) key encapsulation with AES-GCM symmetric encryption.
//!
//! ## Test Coverage
//!
//! **Working Tests** (Pure Symmetric Mode):
//! - Encrypt/decrypt workflows without KEM (pure AES-GCM)
//! - Invalid ciphertext handling
//! - Message variants (empty, small, large messages)
//! - SecurityMode verification
//! - CoreConfig integration
//! - Error conditions
//!
//! **KEM Limitations** (Tests Marked as Ignored):
//! - ML-KEM round-trip encryption/decryption tests are IGNORED
//! - Reason: aws-lc-rs does not support secret key deserialization
//! - The DecapsulationKey cannot be reconstructed from bytes
//! - This is a known limitation documented in ML_KEM_KEY_PERSISTENCE.md
//!
//! ## aws-lc-rs Limitation
//!
//! The underlying aws-lc-rs library does not expose ML-KEM DecapsulationKey bytes:
//! - Private keys cannot be serialized and restored for decryption
//! - The PrivateKey.as_slice() method returns placeholder bytes
//! - Decapsulation fails with: "aws-lc-rs does not support secret key deserialization"
//!
//! **Workarounds for Production**:
//! - Use ephemeral keys (session-based, keep DecapsulationKey in memory)
//! - HSM/KMS with native ML-KEM support
//! - Alternative KEM libraries with serialization support
//! - Use pure symmetric mode (tested here) for cases requiring key persistence

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
    convenience::{
        decrypt_hybrid, decrypt_hybrid_unverified, decrypt_hybrid_with_config,
        decrypt_hybrid_with_config_unverified, encrypt_hybrid, encrypt_hybrid_unverified,
        encrypt_hybrid_with_config, encrypt_hybrid_with_config_unverified, generate_ml_kem_keypair,
    },
    zero_trust::SecurityMode,
};
use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

// ============================================================================
// Helper Functions
// ============================================================================

fn generate_symmetric_key(size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    key
}

// ============================================================================
// Pure Symmetric Encryption Tests (No KEM) - THESE WORK
// ============================================================================

#[test]
fn test_hybrid_pure_symmetric_roundtrip() {
    let message = b"Test message for pure symmetric encryption (no KEM)";
    let symmetric_key = generate_symmetric_key(32);

    // Encrypt without KEM (pure AES-GCM)
    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");

    // Encapsulated key should be empty for pure symmetric
    assert!(
        result.encapsulated_key.is_empty(),
        "Encapsulated key should be empty for pure symmetric mode"
    );

    // Decrypt without KEM
    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Decrypted plaintext should match original message");
}

#[test]
fn test_hybrid_pure_symmetric_with_security_mode() {
    let message = b"Test with SecurityMode";
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid(message, None, &symmetric_key, SecurityMode::Unverified)
        .expect("encryption should succeed");

    let plaintext = decrypt_hybrid(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
        SecurityMode::Unverified,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Decrypted plaintext should match original message");
}

#[test]
fn test_hybrid_pure_symmetric_with_config() {
    let message = b"Test with CoreConfig";
    let symmetric_key = generate_symmetric_key(32);
    let config = CoreConfig::default();

    let result = encrypt_hybrid_with_config_unverified(message, None, &symmetric_key, &config)
        .expect("encryption should succeed");

    let plaintext = decrypt_hybrid_with_config_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
        &config,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Decrypted plaintext should match original message");
}

#[test]
fn test_hybrid_pure_symmetric_with_config_and_security_mode() {
    let message = b"Test with both config and SecurityMode";
    let symmetric_key = generate_symmetric_key(32);
    let config = CoreConfig::default();

    let result = encrypt_hybrid_with_config(
        message,
        None,
        &symmetric_key,
        &config,
        SecurityMode::Unverified,
    )
    .expect("encryption should succeed");

    let plaintext = decrypt_hybrid_with_config(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
        &config,
        SecurityMode::Unverified,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Decrypted plaintext should match original message");
}

// ============================================================================
// Message Variants Tests (Pure Symmetric)
// ============================================================================

#[test]
fn test_hybrid_pure_symmetric_empty_message() {
    let message = b"";
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encrypting empty message should succeed");

    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Empty message should decrypt correctly");
}

#[test]
fn test_hybrid_pure_symmetric_small_message() {
    let message = b"X";
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");

    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Small message should decrypt correctly");
}

#[test]
fn test_hybrid_pure_symmetric_large_message() {
    let message = vec![0x42u8; 1_000_000]; // 1MB
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(&message, None, &symmetric_key)
        .expect("encrypting large message should succeed");

    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Large message should decrypt correctly");
}

#[test]
fn test_hybrid_pure_symmetric_unicode_message() {
    let message = "こんにちは世界 🌍 مرحبا بالعالم Hello World";
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(message.as_bytes(), None, &symmetric_key)
        .expect("encryption should succeed");

    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message.as_bytes(), "Unicode message should decrypt correctly");
}

#[test]
fn test_hybrid_pure_symmetric_binary_message() {
    let message: Vec<u8> = (0..=255).collect();
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(&message, None, &symmetric_key)
        .expect("encryption should succeed");

    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Binary message should decrypt correctly");
}

// ============================================================================
// Invalid Ciphertext Handling Tests (Pure Symmetric)
// ============================================================================

#[test]
fn test_hybrid_pure_symmetric_modified_ciphertext_fails() {
    let message = b"Original message";
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");

    // Tamper with ciphertext
    let mut tampered_ciphertext = result.ciphertext.clone();
    if !tampered_ciphertext.is_empty() {
        tampered_ciphertext[0] ^= 0xFF;
    }

    let decryption_result = decrypt_hybrid_unverified(
        &tampered_ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    );

    assert!(decryption_result.is_err(), "Modified ciphertext should fail decryption");
}

#[test]
fn test_hybrid_pure_symmetric_wrong_symmetric_key_fails() {
    let message = b"Original message";
    let symmetric_key = generate_symmetric_key(32);

    // Use a different key with same size
    let mut wrong_key = vec![0xFFu8; 32];
    wrong_key[0] = 0xAA; // Make it different

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");

    let decryption_result =
        decrypt_hybrid_unverified(&result.ciphertext, None, &result.encapsulated_key, &wrong_key);

    // AES-GCM authentication should fail with wrong key
    assert!(
        decryption_result.is_err(),
        "Wrong symmetric key should fail decryption due to authentication tag mismatch"
    );
}

#[test]
fn test_hybrid_pure_symmetric_truncated_ciphertext_fails() {
    let message = b"Original message";
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");

    // Truncate ciphertext
    let truncated = if result.ciphertext.len() > 5 {
        &result.ciphertext[..result.ciphertext.len() - 5]
    } else {
        &[]
    };

    let decryption_result =
        decrypt_hybrid_unverified(truncated, None, &result.encapsulated_key, &symmetric_key);

    assert!(decryption_result.is_err(), "Truncated ciphertext should fail decryption");
}

#[test]
fn test_hybrid_pure_symmetric_empty_ciphertext_fails() {
    let symmetric_key = generate_symmetric_key(32);

    let decryption_result = decrypt_hybrid_unverified(&[], None, &[], &symmetric_key);

    assert!(decryption_result.is_err(), "Empty ciphertext should fail decryption");
}

// ============================================================================
// Error Conditions Tests
// ============================================================================

#[test]
fn test_hybrid_symmetric_key_too_short() {
    let message = b"Test message";
    let short_key = vec![0u8; 16]; // Only 16 bytes, need at least 32

    let result = encrypt_hybrid_unverified(message, None, &short_key);

    assert!(result.is_err(), "Symmetric key shorter than 32 bytes should fail encryption");
}

#[test]
fn test_hybrid_symmetric_key_minimum_size() {
    let message = b"Test message with minimum key size";
    let symmetric_key = vec![0x42u8; 32]; // Exactly 32 bytes

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("32-byte key should succeed");

    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Minimum size key should work correctly");
}

#[test]
fn test_hybrid_symmetric_key_larger_size() {
    let message = b"Test message with larger key size";
    let symmetric_key = vec![0x42u8; 64]; // 64 bytes (larger than minimum)

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("larger key should succeed");

    let plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        None,
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Larger size key should work correctly");
}

#[test]
fn test_hybrid_invalid_public_key_length() {
    let message = b"Test message";
    let symmetric_key = generate_symmetric_key(32);

    let invalid_pk = vec![0u8; 10]; // Too short for any ML-KEM level

    let result = encrypt_hybrid_unverified(message, Some(&invalid_pk), &symmetric_key);

    assert!(result.is_err(), "Invalid public key length should fail encryption");
}

// ============================================================================
// Serialization Tests (Pure Symmetric)
// ============================================================================

#[test]
fn test_hybrid_pure_symmetric_ciphertext_serialization() {
    let message = b"Test ciphertext serialization";
    let symmetric_key = generate_symmetric_key(32);

    let result = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");

    // Simulate serialization/deserialization
    let ciphertext_bytes = result.ciphertext.clone();
    let encap_key_bytes = result.encapsulated_key.clone();

    let plaintext =
        decrypt_hybrid_unverified(&ciphertext_bytes, None, &encap_key_bytes, &symmetric_key)
            .expect("decryption should succeed");

    assert_eq!(plaintext, message, "Serialized ciphertext should decrypt correctly");
}

#[test]
fn test_hybrid_pure_symmetric_multiple_messages() {
    let symmetric_key = generate_symmetric_key(32);

    // Encrypt multiple messages
    let msg1 = b"First message";
    let msg2 = b"Second message";
    let msg3 = b"Third message";

    let result1 =
        encrypt_hybrid_unverified(msg1, None, &symmetric_key).expect("encryption should succeed");
    let result2 =
        encrypt_hybrid_unverified(msg2, None, &symmetric_key).expect("encryption should succeed");
    let result3 =
        encrypt_hybrid_unverified(msg3, None, &symmetric_key).expect("encryption should succeed");

    // Decrypt all messages
    let plaintext1 = decrypt_hybrid_unverified(
        &result1.ciphertext,
        None,
        &result1.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    let plaintext2 = decrypt_hybrid_unverified(
        &result2.ciphertext,
        None,
        &result2.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    let plaintext3 = decrypt_hybrid_unverified(
        &result3.ciphertext,
        None,
        &result3.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption should succeed");

    assert_eq!(plaintext1, msg1, "First message should decrypt correctly");
    assert_eq!(plaintext2, msg2, "Second message should decrypt correctly");
    assert_eq!(plaintext3, msg3, "Third message should decrypt correctly");
}

#[test]
fn test_hybrid_pure_symmetric_non_deterministic() {
    let message = b"Same message";
    let symmetric_key = generate_symmetric_key(32);

    let result1 = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");
    let result2 = encrypt_hybrid_unverified(message, None, &symmetric_key)
        .expect("encryption should succeed");

    // Ciphertexts should differ due to random nonce in AES-GCM
    assert_ne!(
        result1.ciphertext, result2.ciphertext,
        "Encryption should be non-deterministic (different nonces)"
    );
}

#[test]
fn test_hybrid_pure_symmetric_stress_test() {
    let symmetric_key = generate_symmetric_key(32);

    // Perform 100 encrypt/decrypt cycles
    for i in 0..100 {
        let message = format!("Message number {}", i);

        let result = encrypt_hybrid_unverified(message.as_bytes(), None, &symmetric_key)
            .expect("encryption should succeed");

        let plaintext = decrypt_hybrid_unverified(
            &result.ciphertext,
            None,
            &result.encapsulated_key,
            &symmetric_key,
        )
        .expect("decryption should succeed");

        assert_eq!(
            plaintext,
            message.as_bytes(),
            "Sequential operation {} should work correctly",
            i
        );
    }
}

// ============================================================================
// ML-KEM Encryption Tests (Encryption Only - Decryption Doesn't Work)
// ============================================================================

#[test]
fn test_hybrid_mlkem512_encryption_succeeds() {
    let message = b"Test ML-KEM-512 encryption (decryption not tested)";
    let symmetric_key = generate_symmetric_key(32);

    let (kem_public_key, _) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512).expect("keypair generation");

    // Encryption should succeed
    let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption with ML-KEM-512 should succeed");

    // Encapsulated key should be 768 bytes for ML-KEM-512
    assert_eq!(
        result.encapsulated_key.len(),
        768,
        "ML-KEM-512 encapsulated key should be 768 bytes"
    );

    // Ciphertext should not be empty
    assert!(!result.ciphertext.is_empty(), "Ciphertext should not be empty");
}

#[test]
fn test_hybrid_mlkem768_encryption_succeeds() {
    let message = b"Test ML-KEM-768 encryption (decryption not tested)";
    let symmetric_key = generate_symmetric_key(32);

    let (kem_public_key, _) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption with ML-KEM-768 should succeed");

    // Encapsulated key should be 1088 bytes for ML-KEM-768
    assert_eq!(
        result.encapsulated_key.len(),
        1088,
        "ML-KEM-768 encapsulated key should be 1088 bytes"
    );
}

#[test]
fn test_hybrid_mlkem1024_encryption_succeeds() {
    let message = b"Test ML-KEM-1024 encryption (decryption not tested)";
    let symmetric_key = generate_symmetric_key(32);

    let (kem_public_key, _) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024).expect("keypair generation");

    let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption with ML-KEM-1024 should succeed");

    // Encapsulated key should be 1568 bytes for ML-KEM-1024
    assert_eq!(
        result.encapsulated_key.len(),
        1568,
        "ML-KEM-1024 encapsulated key should be 1568 bytes"
    );
}

#[test]
fn test_hybrid_mlkem_encryption_non_deterministic() {
    let message = b"Same message";
    let symmetric_key = generate_symmetric_key(32);

    let (kem_public_key, _) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let result1 = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption should succeed");
    let result2 = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption should succeed");

    // Encapsulated keys should differ due to randomness in KEM
    assert_ne!(
        result1.encapsulated_key, result2.encapsulated_key,
        "Encapsulated keys should be non-deterministic"
    );

    // Ciphertexts should also differ
    assert_ne!(result1.ciphertext, result2.ciphertext, "Ciphertexts should be non-deterministic");
}

// ============================================================================
// ML-KEM Round-trip Tests (IGNORED - aws-lc-rs limitation)
// ============================================================================

#[test]
#[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
fn test_hybrid_mlkem512_roundtrip_would_fail() {
    let message = b"This test is ignored because decryption doesn't work";
    let symmetric_key = generate_symmetric_key(32);

    let (kem_public_key, kem_private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512).expect("keypair generation");

    let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption should succeed");

    // This will fail with: "aws-lc-rs does not support secret key deserialization"
    let _plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        Some(kem_private_key.as_slice()),
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption would fail");
}

#[test]
#[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
fn test_hybrid_mlkem768_roundtrip_would_fail() {
    let message = b"This test is ignored because decryption doesn't work";
    let symmetric_key = generate_symmetric_key(32);

    let (kem_public_key, kem_private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption should succeed");

    let _plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        Some(kem_private_key.as_slice()),
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption would fail");
}

#[test]
#[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
fn test_hybrid_mlkem1024_roundtrip_would_fail() {
    let message = b"This test is ignored because decryption doesn't work";
    let symmetric_key = generate_symmetric_key(32);

    let (kem_public_key, kem_private_key) =
        generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024).expect("keypair generation");

    let result = encrypt_hybrid_unverified(message, Some(&kem_public_key), &symmetric_key)
        .expect("encryption should succeed");

    let _plaintext = decrypt_hybrid_unverified(
        &result.ciphertext,
        Some(kem_private_key.as_slice()),
        &result.encapsulated_key,
        &symmetric_key,
    )
    .expect("decryption would fail");
}
