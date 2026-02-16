//! Comprehensive tests for Hybrid Encryption Convenience API
//!
//! Tests the ML-KEM-768 + X25519 + HKDF-SHA256 + AES-256-GCM hybrid pipeline
//! exposed through `arc-core/src/convenience/hybrid.rs`.
//!
//! ## Test Categories
//!
//! 1. **Basic roundtrip** - Encrypt/decrypt with new hybrid API
//! 2. **SecurityMode::Verified with session** - Tests with valid verified sessions
//! 3. **HybridEncryptionResult structure validation** - Field sizes and structure
//! 4. **Multiple encryptions non-deterministic** - Randomness verification
//! 5. **Large message stress tests** - 100KB+
//! 6. **Ciphertext tampering** - Integrity verification
//! 7. **Cross-key rejection** - Wrong key decryption failure
//! 8. **Config variants** - with_config, unverified wrappers

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
    HybridEncryptionResult, SecurityMode, VerifiedSession, config::CoreConfig, decrypt_hybrid,
    decrypt_hybrid_unverified, decrypt_hybrid_with_config, decrypt_hybrid_with_config_unverified,
    encrypt_hybrid, encrypt_hybrid_unverified, encrypt_hybrid_with_config,
    encrypt_hybrid_with_config_unverified, error::Result, generate_hybrid_keypair,
    generate_keypair,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a valid verified session for testing
fn create_verified_session() -> Result<VerifiedSession> {
    let (public_key, private_key) = generate_keypair()?;
    VerifiedSession::establish(&public_key, private_key.as_ref())
}

// ============================================================================
// Basic Roundtrip Tests
// ============================================================================

#[test]
fn test_hybrid_encrypt_decrypt_roundtrip() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Basic hybrid roundtrip test";

    let encrypted = encrypt_hybrid(message, &pk, SecurityMode::Unverified)?;
    let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;

    assert_eq!(decrypted.as_slice(), message);
    Ok(())
}

#[test]
fn test_hybrid_unverified_roundtrip() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Unverified convenience variant";

    let encrypted = encrypt_hybrid_unverified(message, &pk)?;
    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;

    assert_eq!(decrypted.as_slice(), message);
    Ok(())
}

#[test]
fn test_hybrid_with_config_roundtrip() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let config = CoreConfig::default();
    let message = b"With-config roundtrip test";

    let encrypted = encrypt_hybrid_with_config(message, &pk, &config, SecurityMode::Unverified)?;
    let decrypted = decrypt_hybrid_with_config(&encrypted, &sk, &config, SecurityMode::Unverified)?;

    assert_eq!(decrypted.as_slice(), message);
    Ok(())
}

#[test]
fn test_hybrid_with_config_unverified_roundtrip() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let config = CoreConfig::default();
    let message = b"Config-unverified roundtrip";

    let encrypted = encrypt_hybrid_with_config_unverified(message, &pk, &config)?;
    let decrypted = decrypt_hybrid_with_config_unverified(&encrypted, &sk, &config)?;

    assert_eq!(decrypted.as_slice(), message);
    Ok(())
}

// ============================================================================
// SecurityMode::Verified with Valid Session Tests
// ============================================================================

#[test]
fn test_hybrid_encrypt_with_verified_session() -> Result<()> {
    let session = create_verified_session()?;
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Test message with verified session";

    let encrypted = encrypt_hybrid(message, &pk, SecurityMode::Verified(&session))?;
    let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Verified(&session))?;

    assert_eq!(decrypted.as_slice(), message);
    Ok(())
}

#[test]
fn test_hybrid_session_reuse_multiple_operations() -> Result<()> {
    let session = create_verified_session()?;
    let (pk, sk) = generate_hybrid_keypair()?;

    for i in 0..10 {
        let message = format!("Message number {}", i);
        let encrypted = encrypt_hybrid(message.as_bytes(), &pk, SecurityMode::Verified(&session))?;
        let decrypted = decrypt_hybrid(&encrypted, &sk, SecurityMode::Verified(&session))?;

        assert_eq!(decrypted, message.as_bytes(), "Session should be reusable for operation {}", i);
    }
    Ok(())
}

#[test]
fn test_hybrid_verified_session_validity_check() -> Result<()> {
    let session = create_verified_session()?;

    assert!(session.is_valid(), "Fresh session should be valid");
    session.verify_valid()?;
    assert!(!session.session_id().iter().all(|&b| b == 0), "Session ID should not be all zeros");
    assert!(!session.public_key().is_empty(), "Public key should not be empty");

    Ok(())
}

#[test]
fn test_security_mode_verified_validates_session() -> Result<()> {
    let session = create_verified_session()?;
    let mode = SecurityMode::Verified(&session);

    mode.validate()?;
    assert!(mode.is_verified(), "Mode should be verified");
    assert!(!mode.is_unverified(), "Mode should not be unverified");
    assert!(mode.session().is_some(), "Mode should have session");

    Ok(())
}

#[test]
fn test_security_mode_unverified_always_validates() -> Result<()> {
    let mode = SecurityMode::Unverified;

    mode.validate()?;
    assert!(!mode.is_verified(), "Mode should not be verified");
    assert!(mode.is_unverified(), "Mode should be unverified");
    assert!(mode.session().is_none(), "Mode should not have session");

    Ok(())
}

// ============================================================================
// HybridEncryptionResult Structure Validation
// ============================================================================

#[test]
fn test_hybrid_encryption_result_structure() -> Result<()> {
    let (pk, _sk) = generate_hybrid_keypair()?;
    let message = b"Test HybridEncryptionResult structure";

    let result = encrypt_hybrid_unverified(message, &pk)?;

    // ML-KEM-768 ciphertext = 1088 bytes
    assert_eq!(result.kem_ciphertext.len(), 1088, "ML-KEM-768 CT should be 1088 bytes");
    // X25519 ephemeral public key = 32 bytes
    assert_eq!(result.ecdh_ephemeral_pk.len(), 32, "X25519 PK should be 32 bytes");
    // AES-GCM nonce = 12 bytes
    assert_eq!(result.nonce.len(), 12, "AES-GCM nonce should be 12 bytes");
    // AES-GCM tag = 16 bytes
    assert_eq!(result.tag.len(), 16, "AES-GCM tag should be 16 bytes");
    // Symmetric ciphertext should be same length as plaintext
    assert_eq!(
        result.symmetric_ciphertext.len(),
        message.len(),
        "Symmetric ciphertext should match plaintext length"
    );

    Ok(())
}

#[test]
fn test_hybrid_encryption_result_debug_impl() -> Result<()> {
    let (pk, _sk) = generate_hybrid_keypair()?;
    let message = b"Test debug implementation";

    let result = encrypt_hybrid_unverified(message, &pk)?;

    let debug_output = format!("{:?}", result);
    assert!(debug_output.contains("HybridEncryptionResult"), "Debug should show struct name");

    Ok(())
}

#[test]
fn test_hybrid_encryption_result_field_independence() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Test field independence";

    let result = encrypt_hybrid_unverified(message, &pk)?;

    // Clone the result
    let cloned = HybridEncryptionResult {
        kem_ciphertext: result.kem_ciphertext.clone(),
        ecdh_ephemeral_pk: result.ecdh_ephemeral_pk.clone(),
        symmetric_ciphertext: result.symmetric_ciphertext.clone(),
        nonce: result.nonce.clone(),
        tag: result.tag.clone(),
    };

    // Decrypt the cloned result
    let plaintext = decrypt_hybrid_unverified(&cloned, &sk)?;
    assert_eq!(plaintext, message);

    Ok(())
}

// ============================================================================
// Multiple Encryptions Non-Deterministic Tests
// ============================================================================

#[test]
fn test_hybrid_encryption_non_deterministic() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Same message encrypted multiple times";

    let result1 = encrypt_hybrid_unverified(message, &pk)?;
    let result2 = encrypt_hybrid_unverified(message, &pk)?;
    let result3 = encrypt_hybrid_unverified(message, &pk)?;

    // KEM ciphertexts should differ (randomized encapsulation)
    assert_ne!(result1.kem_ciphertext, result2.kem_ciphertext, "KEM CTs should differ");
    assert_ne!(result1.kem_ciphertext, result3.kem_ciphertext, "KEM CTs should differ");

    // Ephemeral ECDH keys should differ
    assert_ne!(result1.ecdh_ephemeral_pk, result2.ecdh_ephemeral_pk, "ECDH PKs should differ");

    // Nonces should differ
    assert_ne!(result1.nonce, result2.nonce, "Nonces should differ");

    // All should decrypt correctly
    assert_eq!(decrypt_hybrid_unverified(&result1, &sk)?, message.to_vec());
    assert_eq!(decrypt_hybrid_unverified(&result2, &sk)?, message.to_vec());
    assert_eq!(decrypt_hybrid_unverified(&result3, &sk)?, message.to_vec());

    Ok(())
}

#[test]
fn test_encryption_randomness_stress_test() -> Result<()> {
    let (pk, _sk) = generate_hybrid_keypair()?;
    let message = b"Stress test for randomness";

    let mut kem_cts = Vec::new();
    let iterations = 20;

    for _ in 0..iterations {
        let result = encrypt_hybrid_unverified(message, &pk)?;
        kem_cts.push(result.kem_ciphertext);
    }

    // All KEM ciphertexts should be unique
    for i in 0..iterations {
        for j in (i + 1)..iterations {
            assert_ne!(kem_cts[i], kem_cts[j], "KEM CT {} and {} should differ", i, j);
        }
    }

    Ok(())
}

// ============================================================================
// Large Message Stress Tests
// ============================================================================

#[test]
fn test_hybrid_100kb_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = vec![0xAB; 100 * 1024]; // 100KB

    let encrypted = encrypt_hybrid_unverified(&message, &pk)?;
    assert_eq!(
        encrypted.symmetric_ciphertext.len(),
        message.len(),
        "Symmetric CT should match plaintext length"
    );

    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;
    assert_eq!(decrypted, message, "100KB message should roundtrip correctly");

    Ok(())
}

#[test]
fn test_hybrid_500kb_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = vec![0xCD; 500 * 1024]; // 500KB

    let encrypted = encrypt_hybrid_unverified(&message, &pk)?;
    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;
    assert_eq!(decrypted, message, "500KB message should roundtrip correctly");

    Ok(())
}

#[test]
fn test_hybrid_1mb_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = vec![0xEF; 1024 * 1024]; // 1MB

    let encrypted = encrypt_hybrid_unverified(&message, &pk)?;
    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;
    assert_eq!(decrypted, message, "1MB message should roundtrip correctly");

    Ok(())
}

// ============================================================================
// Ciphertext Tampering and Integrity Tests
// ============================================================================

#[test]
fn test_tampered_symmetric_ciphertext_detected() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Test tamper detection on symmetric ciphertext";

    let mut encrypted = encrypt_hybrid_unverified(message, &pk)?;

    if !encrypted.symmetric_ciphertext.is_empty() {
        encrypted.symmetric_ciphertext[0] ^= 0xFF;
    }

    let result = decrypt_hybrid_unverified(&encrypted, &sk);
    assert!(result.is_err(), "Tampered symmetric ciphertext should be detected");

    Ok(())
}

#[test]
fn test_tampered_kem_ciphertext_detected() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Test tamper detection on KEM ciphertext";

    let mut encrypted = encrypt_hybrid_unverified(message, &pk)?;

    if !encrypted.kem_ciphertext.is_empty() {
        encrypted.kem_ciphertext[0] ^= 0xFF;
    }

    let result = decrypt_hybrid_unverified(&encrypted, &sk);
    assert!(result.is_err(), "Tampered KEM ciphertext should be detected");

    Ok(())
}

#[test]
fn test_tampered_ecdh_pk_detected() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Test tamper detection on ECDH ephemeral PK";

    let mut encrypted = encrypt_hybrid_unverified(message, &pk)?;

    if !encrypted.ecdh_ephemeral_pk.is_empty() {
        encrypted.ecdh_ephemeral_pk[0] ^= 0xFF;
    }

    let result = decrypt_hybrid_unverified(&encrypted, &sk);
    assert!(result.is_err(), "Tampered ECDH ephemeral PK should be detected");

    Ok(())
}

#[test]
fn test_tampered_nonce_detected() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Test tamper detection on nonce";

    let mut encrypted = encrypt_hybrid_unverified(message, &pk)?;

    if !encrypted.nonce.is_empty() {
        encrypted.nonce[0] ^= 0xFF;
    }

    let result = decrypt_hybrid_unverified(&encrypted, &sk);
    assert!(result.is_err(), "Tampered nonce should be detected");

    Ok(())
}

#[test]
fn test_tampered_tag_detected() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"Test tamper detection on tag";

    let mut encrypted = encrypt_hybrid_unverified(message, &pk)?;

    if !encrypted.tag.is_empty() {
        encrypted.tag[0] ^= 0xFF;
    }

    let result = decrypt_hybrid_unverified(&encrypted, &sk);
    assert!(result.is_err(), "Tampered tag should be detected");

    Ok(())
}

// ============================================================================
// Cross-Key Rejection Tests
// ============================================================================

#[test]
fn test_wrong_secret_key_rejected() -> Result<()> {
    let (pk1, _sk1) = generate_hybrid_keypair()?;
    let (_pk2, sk2) = generate_hybrid_keypair()?;

    let message = b"Cross-key rejection test";

    let encrypted = encrypt_hybrid_unverified(message, &pk1)?;
    let result = decrypt_hybrid_unverified(&encrypted, &sk2);

    assert!(result.is_err(), "Decrypt with wrong hybrid key should fail");

    Ok(())
}

#[test]
fn test_multiple_keypairs_independent() -> Result<()> {
    let (pk1, sk1) = generate_hybrid_keypair()?;
    let (pk2, sk2) = generate_hybrid_keypair()?;

    let msg1 = b"Message for keypair 1";
    let msg2 = b"Message for keypair 2";

    let enc1 = encrypt_hybrid_unverified(msg1, &pk1)?;
    let enc2 = encrypt_hybrid_unverified(msg2, &pk2)?;

    // Each key decrypts its own message
    let dec1 = decrypt_hybrid_unverified(&enc1, &sk1)?;
    let dec2 = decrypt_hybrid_unverified(&enc2, &sk2)?;

    assert_eq!(dec1, msg1);
    assert_eq!(dec2, msg2);

    // Cross-decryption fails
    assert!(decrypt_hybrid_unverified(&enc1, &sk2).is_err(), "Cross-key 1->2 should fail");
    assert!(decrypt_hybrid_unverified(&enc2, &sk1).is_err(), "Cross-key 2->1 should fail");

    Ok(())
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_empty_message_roundtrip() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"";

    let encrypted = encrypt_hybrid_unverified(message, &pk)?;
    assert!(encrypted.symmetric_ciphertext.is_empty(), "Empty plaintext → empty symmetric CT");

    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;
    assert!(decrypted.is_empty(), "Decrypted empty message should be empty");

    Ok(())
}

#[test]
fn test_single_byte_message_roundtrip() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = b"X";

    let encrypted = encrypt_hybrid_unverified(message, &pk)?;
    assert_eq!(encrypted.symmetric_ciphertext.len(), 1, "Single byte symmetric CT");

    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;
    assert_eq!(decrypted, message);

    Ok(())
}

#[test]
fn test_all_zero_bytes_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = vec![0u8; 1000];

    let encrypted = encrypt_hybrid_unverified(&message, &pk)?;
    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;

    assert_eq!(decrypted, message, "All-zero bytes message should roundtrip");

    Ok(())
}

#[test]
fn test_all_255_bytes_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message = vec![0xFFu8; 1000];

    let encrypted = encrypt_hybrid_unverified(&message, &pk)?;
    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;

    assert_eq!(decrypted, message, "All-255 bytes message should roundtrip");

    Ok(())
}

#[test]
fn test_full_byte_range_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;
    let message: Vec<u8> = (0..=255).cycle().take(1024).collect();

    let encrypted = encrypt_hybrid_unverified(&message, &pk)?;
    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;

    assert_eq!(decrypted, message, "Full byte range message should roundtrip");

    Ok(())
}

// ============================================================================
// Multiple Messages with Same Keypair
// ============================================================================

#[test]
fn test_many_messages_same_keypair() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;

    let messages: Vec<Vec<u8>> = (0..50).map(|i| format!("Message {}", i).into_bytes()).collect();

    let encrypted: Vec<_> = messages
        .iter()
        .map(|msg| encrypt_hybrid_unverified(msg, &pk))
        .collect::<Result<Vec<_>>>()?;

    let decrypted: Vec<_> = encrypted
        .iter()
        .map(|enc| decrypt_hybrid_unverified(enc, &sk))
        .collect::<Result<Vec<_>>>()?;

    for (original, decrypted) in messages.iter().zip(decrypted.iter()) {
        assert_eq!(original, decrypted);
    }

    Ok(())
}
