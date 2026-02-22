//! Hybrid Encryption Tests via Unified API
//!
//! Tests the ML-KEM-768 + X25519 + HKDF-SHA256 + AES-256-GCM hybrid pipeline
//! through the unified `encrypt()`/`decrypt()` API with `EncryptKey::Hybrid`/`DecryptKey::Hybrid`.
//!
//! ## Test Categories
//!
//! 1. **Basic roundtrip** - Encrypt/decrypt with unified hybrid API
//! 2. **EncryptedOutput structure validation** - Field sizes and structure
//! 3. **Multiple encryptions non-deterministic** - Randomness verification
//! 4. **Large message stress tests** - 100KB+
//! 5. **Ciphertext tampering** - Integrity verification
//! 6. **Cross-key rejection** - Wrong key decryption failure
//! 7. **Edge cases** - Empty, single-byte, boundary values

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

use latticearc::{
    CryptoConfig, DecryptKey, EncryptKey, EncryptedOutput, SecurityMode, VerifiedSession, decrypt,
    encrypt, generate_hybrid_keypair, generate_keypair,
};

// ============================================================================
// Basic Roundtrip Tests
// ============================================================================

#[test]
fn test_hybrid_encrypt_decrypt_roundtrip() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Basic hybrid roundtrip test";

    let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

    assert_eq!(decrypted.as_slice(), message);
}

// ============================================================================
// SecurityMode::Verified with Valid Session Tests
// ============================================================================

#[test]
fn test_hybrid_encrypt_with_verified_session() {
    let (auth_pk, auth_sk) = generate_keypair().unwrap();
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Test message with verified session";

    let config = CryptoConfig::new().session(&session);
    let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), config).unwrap();
    let config = CryptoConfig::new().session(&session);
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config).unwrap();

    assert_eq!(decrypted.as_slice(), message);
}

#[test]
fn test_hybrid_session_reuse_multiple_operations() {
    let (auth_pk, auth_sk) = generate_keypair().unwrap();
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();
    let (pk, sk) = generate_hybrid_keypair().unwrap();

    for i in 0..10 {
        let message = format!("Message number {}", i);
        let config = CryptoConfig::new().session(&session);
        let encrypted = encrypt(message.as_bytes(), EncryptKey::Hybrid(&pk), config).unwrap();
        let config = CryptoConfig::new().session(&session);
        let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), config).unwrap();

        assert_eq!(decrypted, message.as_bytes(), "Session should be reusable for operation {}", i);
    }
}

#[test]
fn test_hybrid_verified_session_validity_check() {
    let (auth_pk, auth_sk) = generate_keypair().unwrap();
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();

    assert!(session.is_valid(), "Fresh session should be valid");
    session.verify_valid().unwrap();
    assert!(!session.session_id().iter().all(|&b| b == 0), "Session ID should not be all zeros");
    assert!(!session.public_key().is_empty(), "Public key should not be empty");
}

#[test]
fn test_security_mode_verified_validates_session() {
    let (auth_pk, auth_sk) = generate_keypair().unwrap();
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref()).unwrap();
    let mode = SecurityMode::Verified(&session);

    mode.validate().unwrap();
    assert!(mode.is_verified(), "Mode should be verified");
    assert!(!mode.is_unverified(), "Mode should not be unverified");
    assert!(mode.session().is_some(), "Mode should have session");
}

#[test]
fn test_security_mode_unverified_always_validates() {
    let mode = SecurityMode::Unverified;

    mode.validate().unwrap();
    assert!(!mode.is_verified(), "Mode should not be verified");
    assert!(mode.is_unverified(), "Mode should be unverified");
    assert!(mode.session().is_none(), "Mode should not have session");
}

// ============================================================================
// EncryptedOutput Structure Validation
// ============================================================================

#[test]
fn test_hybrid_encrypted_output_structure() {
    let (pk, _sk) = generate_hybrid_keypair().unwrap();
    let message = b"Test EncryptedOutput structure";

    let result = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

    let hybrid = result.hybrid_data.as_ref().expect("hybrid_data should be present");
    // ML-KEM-768 ciphertext = 1088 bytes
    assert_eq!(hybrid.ml_kem_ciphertext.len(), 1088, "ML-KEM-768 CT should be 1088 bytes");
    // X25519 ephemeral public key = 32 bytes
    assert_eq!(hybrid.ecdh_ephemeral_pk.len(), 32, "X25519 PK should be 32 bytes");
    // AES-GCM nonce = 12 bytes
    assert_eq!(result.nonce.len(), 12, "AES-GCM nonce should be 12 bytes");
    // AES-GCM tag = 16 bytes
    assert_eq!(result.tag.len(), 16, "AES-GCM tag should be 16 bytes");
    // Symmetric ciphertext should be same length as plaintext
    assert_eq!(result.ciphertext.len(), message.len(), "Ciphertext should match plaintext length");
}

// ============================================================================
// Multiple Encryptions Non-Deterministic Tests
// ============================================================================

#[test]
fn test_hybrid_encryption_non_deterministic() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Same message encrypted multiple times";

    let result1 = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let result2 = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let result3 = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

    let h1 = result1.hybrid_data.as_ref().unwrap();
    let h2 = result2.hybrid_data.as_ref().unwrap();
    let h3 = result3.hybrid_data.as_ref().unwrap();

    // KEM ciphertexts should differ (randomized encapsulation)
    assert_ne!(h1.ml_kem_ciphertext, h2.ml_kem_ciphertext, "KEM CTs should differ");
    assert_ne!(h1.ml_kem_ciphertext, h3.ml_kem_ciphertext, "KEM CTs should differ");

    // Ephemeral ECDH keys should differ
    assert_ne!(h1.ecdh_ephemeral_pk, h2.ecdh_ephemeral_pk, "ECDH PKs should differ");

    // Nonces should differ
    assert_ne!(result1.nonce, result2.nonce, "Nonces should differ");

    // All should decrypt correctly
    assert_eq!(
        decrypt(&result1, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap(),
        message.to_vec()
    );
    assert_eq!(
        decrypt(&result2, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap(),
        message.to_vec()
    );
    assert_eq!(
        decrypt(&result3, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap(),
        message.to_vec()
    );
}

#[test]
fn test_encryption_randomness_stress_test() {
    let (pk, _sk) = generate_hybrid_keypair().unwrap();
    let message = b"Stress test for randomness";

    let mut kem_cts = Vec::new();
    let iterations = 20;

    for _ in 0..iterations {
        let result = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
        let hybrid = result.hybrid_data.as_ref().unwrap();
        kem_cts.push(hybrid.ml_kem_ciphertext.clone());
    }

    // All KEM ciphertexts should be unique
    for i in 0..iterations {
        for j in (i + 1)..iterations {
            assert_ne!(kem_cts[i], kem_cts[j], "KEM CT {} and {} should differ", i, j);
        }
    }
}

// ============================================================================
// Large Message Stress Tests
// ============================================================================

#[test]
fn test_hybrid_100kb_message() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = vec![0xAB; 100 * 1024]; // 100KB

    let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    assert_eq!(
        encrypted.ciphertext.len(),
        message.len(),
        "Ciphertext should match plaintext length"
    );

    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
    assert_eq!(decrypted, message, "100KB message should roundtrip correctly");
}

#[test]
fn test_hybrid_500kb_message() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = vec![0xCD; 500 * 1024]; // 500KB

    let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
    assert_eq!(decrypted, message, "500KB message should roundtrip correctly");
}

#[test]
fn test_hybrid_1mb_message() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = vec![0xEF; 1024 * 1024]; // 1MB

    let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
    assert_eq!(decrypted, message, "1MB message should roundtrip correctly");
}

// ============================================================================
// Ciphertext Tampering and Integrity Tests
// ============================================================================

#[test]
fn test_tampered_symmetric_ciphertext_detected() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Test tamper detection on symmetric ciphertext";

    let mut encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

    if !encrypted.ciphertext.is_empty() {
        encrypted.ciphertext[0] ^= 0xFF;
    }

    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new());
    assert!(result.is_err(), "Tampered symmetric ciphertext should be detected");
}

#[test]
fn test_tampered_kem_ciphertext_detected() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Test tamper detection on KEM ciphertext";

    let mut encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

    if let Some(ref mut hybrid) = encrypted.hybrid_data
        && !hybrid.ml_kem_ciphertext.is_empty()
    {
        hybrid.ml_kem_ciphertext[0] ^= 0xFF;
    }

    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new());
    assert!(result.is_err(), "Tampered KEM ciphertext should be detected");
}

#[test]
fn test_tampered_ecdh_pk_detected() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Test tamper detection on ECDH ephemeral PK";

    let mut encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

    if let Some(ref mut hybrid) = encrypted.hybrid_data
        && !hybrid.ecdh_ephemeral_pk.is_empty()
    {
        hybrid.ecdh_ephemeral_pk[0] ^= 0xFF;
    }

    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new());
    assert!(result.is_err(), "Tampered ECDH ephemeral PK should be detected");
}

#[test]
fn test_tampered_nonce_detected() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Test tamper detection on nonce";

    let mut encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

    if !encrypted.nonce.is_empty() {
        encrypted.nonce[0] ^= 0xFF;
    }

    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new());
    assert!(result.is_err(), "Tampered nonce should be detected");
}

#[test]
fn test_tampered_tag_detected() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"Test tamper detection on tag";

    let mut encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();

    if !encrypted.tag.is_empty() {
        encrypted.tag[0] ^= 0xFF;
    }

    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new());
    assert!(result.is_err(), "Tampered tag should be detected");
}

// ============================================================================
// Cross-Key Rejection Tests
// ============================================================================

#[test]
fn test_wrong_secret_key_rejected() {
    let (pk1, _sk1) = generate_hybrid_keypair().unwrap();
    let (_pk2, sk2) = generate_hybrid_keypair().unwrap();

    let message = b"Cross-key rejection test";

    let encrypted = encrypt(message, EncryptKey::Hybrid(&pk1), CryptoConfig::new()).unwrap();
    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk2), CryptoConfig::new());

    assert!(result.is_err(), "Decrypt with wrong hybrid key should fail");
}

#[test]
fn test_multiple_keypairs_independent() {
    let (pk1, sk1) = generate_hybrid_keypair().unwrap();
    let (pk2, sk2) = generate_hybrid_keypair().unwrap();

    let msg1 = b"Message for keypair 1";
    let msg2 = b"Message for keypair 2";

    let enc1 = encrypt(msg1, EncryptKey::Hybrid(&pk1), CryptoConfig::new()).unwrap();
    let enc2 = encrypt(msg2, EncryptKey::Hybrid(&pk2), CryptoConfig::new()).unwrap();

    // Each key decrypts its own message
    let dec1 = decrypt(&enc1, DecryptKey::Hybrid(&sk1), CryptoConfig::new()).unwrap();
    let dec2 = decrypt(&enc2, DecryptKey::Hybrid(&sk2), CryptoConfig::new()).unwrap();

    assert_eq!(dec1, msg1);
    assert_eq!(dec2, msg2);

    // Cross-decryption fails
    assert!(
        decrypt(&enc1, DecryptKey::Hybrid(&sk2), CryptoConfig::new()).is_err(),
        "Cross-key 1->2 should fail"
    );
    assert!(
        decrypt(&enc2, DecryptKey::Hybrid(&sk1), CryptoConfig::new()).is_err(),
        "Cross-key 2->1 should fail"
    );
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_empty_message_roundtrip() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"";

    let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    assert!(encrypted.ciphertext.is_empty(), "Empty plaintext -> empty ciphertext");

    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
    assert!(decrypted.is_empty(), "Decrypted empty message should be empty");
}

#[test]
fn test_single_byte_message_roundtrip() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = b"X";

    let encrypted = encrypt(message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    assert_eq!(encrypted.ciphertext.len(), 1, "Single byte ciphertext");

    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_all_zero_bytes_message() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = vec![0u8; 1000];

    let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

    assert_eq!(decrypted, message, "All-zero bytes message should roundtrip");
}

#[test]
fn test_all_255_bytes_message() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message = vec![0xFFu8; 1000];

    let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

    assert_eq!(decrypted, message, "All-255 bytes message should roundtrip");
}

#[test]
fn test_full_byte_range_message() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();
    let message: Vec<u8> = (0..=255).cycle().take(1024).collect();

    let encrypted = encrypt(&message, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap();
    let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap();

    assert_eq!(decrypted, message, "Full byte range message should roundtrip");
}

// ============================================================================
// Multiple Messages with Same Keypair
// ============================================================================

#[test]
fn test_many_messages_same_keypair() {
    let (pk, sk) = generate_hybrid_keypair().unwrap();

    let messages: Vec<Vec<u8>> = (0..50).map(|i| format!("Message {}", i).into_bytes()).collect();

    let encrypted: Vec<EncryptedOutput> = messages
        .iter()
        .map(|msg| encrypt(msg, EncryptKey::Hybrid(&pk), CryptoConfig::new()).unwrap())
        .collect();

    let decrypted: Vec<Vec<u8>> = encrypted
        .iter()
        .map(|enc| decrypt(enc, DecryptKey::Hybrid(&sk), CryptoConfig::new()).unwrap())
        .collect();

    for (original, dec) in messages.iter().zip(decrypted.iter()) {
        assert_eq!(original, dec);
    }
}
