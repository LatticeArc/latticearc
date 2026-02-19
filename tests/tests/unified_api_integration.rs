//! Unified API integration tests for LatticeArc
//!
//! These tests verify that the LatticeArc unified API works correctly
//! for real-world use cases including encryption, hashing, HMAC,
//! and key derivation.

#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use latticearc::{
    SecurityMode, decrypt_aes_gcm, derive_key, encrypt_aes_gcm, hash_data, hmac, hmac_check,
};

// ============================================================================
// Basic Symmetric Encryption Tests (AES-GCM)
// ============================================================================

#[test]
fn test_aes_gcm_roundtrip() {
    let plaintext = b"Sensitive data that needs protection";
    let key = [0x42u8; 32]; // AES-256 key

    let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
        .expect("encryption should succeed");

    // Ciphertext should be plaintext + nonce(12) + tag(16) = plaintext + 28 bytes
    assert!(ciphertext.len() > plaintext.len(), "Ciphertext should be longer than plaintext");

    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
        .expect("decryption should succeed");

    assert_eq!(decrypted.as_slice(), plaintext, "Roundtrip should preserve plaintext");
}

#[test]
fn test_aes_gcm_different_keys_produce_different_ciphertext() {
    let plaintext = b"Test data";
    let key1 = [0x41u8; 32];
    let key2 = [0x42u8; 32];

    let ct1 = encrypt_aes_gcm(plaintext, &key1, SecurityMode::Unverified)
        .expect("encryption should succeed");
    let ct2 = encrypt_aes_gcm(plaintext, &key2, SecurityMode::Unverified)
        .expect("encryption should succeed");

    // Even with random nonces, different keys produce different ciphertexts
    assert_ne!(ct1, ct2, "Different keys should produce different ciphertexts");
}

#[test]
fn test_aes_gcm_random_nonces_produce_different_ciphertext() {
    let plaintext = b"Test data";
    let key = [0x42u8; 32];

    let ct1 = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
        .expect("encryption should succeed");
    let ct2 = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
        .expect("encryption should succeed");

    // Random nonces should make ciphertexts different
    assert_ne!(ct1, ct2, "Random nonces should produce different ciphertexts");
}

#[test]
fn test_aes_gcm_wrong_key_fails_decryption() {
    let plaintext = b"Test data";
    let key_enc = [0x41u8; 32];
    let key_dec = [0x42u8; 32];

    let ciphertext = encrypt_aes_gcm(plaintext, &key_enc, SecurityMode::Unverified)
        .expect("encryption should succeed");
    let result = decrypt_aes_gcm(&ciphertext, &key_dec, SecurityMode::Unverified);

    assert!(result.is_err(), "Wrong key should fail decryption");
}

#[test]
fn test_aes_gcm_tampered_ciphertext_fails() {
    let plaintext = b"Test data";
    let key = [0x42u8; 32];

    let mut ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
        .expect("encryption should succeed");

    // Tamper with ciphertext (after the nonce)
    if ciphertext.len() > 12 {
        ciphertext[12] ^= 0xFF;
    }

    let result = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified);
    assert!(result.is_err(), "Tampered ciphertext should fail authentication");
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    let plaintext = b"";
    let key = [0x42u8; 32];

    let ciphertext = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified)
        .expect("encryption should succeed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
        .expect("decryption should succeed");

    assert!(decrypted.is_empty(), "Empty plaintext should decrypt to empty");
}

#[test]
fn test_aes_gcm_key_too_short() {
    let plaintext = b"Test data";
    let short_key = [0x42u8; 16]; // AES-128 key (too short for this API)

    let result = encrypt_aes_gcm(plaintext, &short_key, SecurityMode::Unverified);
    assert!(result.is_err(), "Short key should fail");
}

// ============================================================================
// Hashing Tests
// ============================================================================

#[test]
fn test_hash_deterministic() {
    let data = b"Data to hash";

    let hash1 = hash_data(data);
    let hash2 = hash_data(data);

    assert_eq!(hash1, hash2, "Same data should produce same hash");
}

#[test]
fn test_hash_different_inputs() {
    let data1 = b"First data";
    let data2 = b"Second data";

    let hash1 = hash_data(data1);
    let hash2 = hash_data(data2);

    assert_ne!(hash1, hash2, "Different data should produce different hashes");
}

#[test]
fn test_hash_empty_input() {
    let empty = b"";
    let hash = hash_data(empty);
    // SHA-3-256 produces 32-byte output even for empty input
    assert_eq!(hash.len(), 32, "Hash should be 32 bytes");
}

#[test]
fn test_hash_large_input() {
    let large_data = vec![0x42u8; 1_000_000]; // 1MB
    let hash = hash_data(&large_data);
    assert_eq!(hash.len(), 32, "Hash should be 32 bytes");
}

#[test]
fn test_hash_output_size() {
    let data = b"Test data";
    let hash = hash_data(data);

    // SHA-3-256 produces 32-byte output
    assert_eq!(hash.len(), 32, "Hash should be 32 bytes");
}

// ============================================================================
// HMAC Tests
// ============================================================================

#[test]
fn test_hmac_roundtrip() {
    let message = b"Message to authenticate";
    let key = b"secret key for hmac";

    let tag = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");
    let is_valid = hmac_check(message, key, &tag, SecurityMode::Unverified)
        .expect("HMAC verify should succeed");

    assert!(is_valid, "Valid HMAC should verify");
}

#[test]
fn test_hmac_wrong_key() {
    let message = b"Message to authenticate";
    let key1 = b"correct key";
    let key2 = b"wrong key";

    let tag = hmac(message, key1, SecurityMode::Unverified).expect("HMAC should succeed");
    let is_valid = hmac_check(message, key2, &tag, SecurityMode::Unverified)
        .expect("HMAC verify should succeed");

    assert!(!is_valid, "Wrong key should fail HMAC verification");
}

#[test]
fn test_hmac_tampered_message() {
    let message = b"Original message";
    let key = b"secret key";

    let tag = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");

    let tampered_message = b"Tampered message";
    let is_valid = hmac_check(tampered_message, key, &tag, SecurityMode::Unverified)
        .expect("HMAC verify should succeed");

    assert!(!is_valid, "Tampered message should fail HMAC verification");
}

#[test]
fn test_hmac_deterministic() {
    let message = b"Test message";
    let key = b"test key";

    let tag1 = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");
    let tag2 = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");

    assert_eq!(tag1, tag2, "Same inputs should produce same HMAC");
}

#[test]
fn test_hmac_empty_message() {
    let message = b"";
    let key = b"key";

    let tag = hmac(message, key, SecurityMode::Unverified).expect("HMAC should succeed");
    let is_valid = hmac_check(message, key, &tag, SecurityMode::Unverified)
        .expect("HMAC verify should succeed");

    assert!(is_valid, "Empty message HMAC should verify");
}

// ============================================================================
// Key Derivation Tests
// ============================================================================

#[test]
fn test_key_derivation_deterministic() {
    let master_key = b"master secret key";
    let context = b"encryption-key";

    let derived1 = derive_key(master_key, context, 32, SecurityMode::Unverified)
        .expect("key derivation should succeed");
    let derived2 = derive_key(master_key, context, 32, SecurityMode::Unverified)
        .expect("key derivation should succeed");

    assert_eq!(derived1, derived2, "Same inputs should derive same key");
}

#[test]
fn test_key_derivation_different_contexts() {
    let master_key = b"master secret key";
    let context1 = b"encryption-key";
    let context2 = b"signing-key";

    let derived1 = derive_key(master_key, context1, 32, SecurityMode::Unverified)
        .expect("key derivation should succeed");
    let derived2 = derive_key(master_key, context2, 32, SecurityMode::Unverified)
        .expect("key derivation should succeed");

    assert_ne!(derived1, derived2, "Different contexts should derive different keys");
}

#[test]
fn test_key_derivation_different_lengths() {
    let master_key = b"master secret key";
    let context = b"key-context";

    let key16 = derive_key(master_key, context, 16, SecurityMode::Unverified)
        .expect("key derivation should succeed");
    let key32 = derive_key(master_key, context, 32, SecurityMode::Unverified)
        .expect("key derivation should succeed");

    assert_eq!(key16.len(), 16);
    assert_eq!(key32.len(), 32);
    // First 16 bytes should be the same
    assert_eq!(&key16[..], &key32[..16]);
}

#[test]
fn test_derived_key_can_be_used_for_encryption() {
    let master_key = b"master secret key for derivation";
    let context = b"aes-encryption-key";

    let derived_key = derive_key(master_key, context, 32, SecurityMode::Unverified)
        .expect("key derivation should succeed");
    let plaintext = b"Data encrypted with derived key";

    let ciphertext = encrypt_aes_gcm(plaintext, &derived_key, SecurityMode::Unverified)
        .expect("encryption with derived key should succeed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &derived_key, SecurityMode::Unverified)
        .expect("decryption with derived key should succeed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

// ============================================================================
// Large Data Tests
// ============================================================================

#[test]
fn test_large_data_encryption() {
    // Test with 1MB of data
    let large_data = vec![0x42u8; 1_000_000];
    let key = [0x42u8; 32];

    let ciphertext = encrypt_aes_gcm(&large_data, &key, SecurityMode::Unverified)
        .expect("large data encryption should succeed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
        .expect("large data decryption should succeed");

    assert_eq!(decrypted, large_data, "Large data roundtrip should preserve data");
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_single_byte_encryption() {
    let single_byte = b"X";
    let key = [0x42u8; 32];

    let ciphertext = encrypt_aes_gcm(single_byte, &key, SecurityMode::Unverified)
        .expect("single byte encryption should succeed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
        .expect("single byte decryption should succeed");

    assert_eq!(decrypted.as_slice(), single_byte);
}

#[test]
fn test_unicode_data_encryption() {
    let unicode_data = "こんにちは世界 🌍 مرحبا بالعالم";
    let key = [0x42u8; 32];

    let ciphertext = encrypt_aes_gcm(unicode_data.as_bytes(), &key, SecurityMode::Unverified)
        .expect("unicode encryption should succeed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
        .expect("unicode decryption should succeed");

    let decrypted_str = std::str::from_utf8(&decrypted).expect("should be valid UTF-8");
    assert_eq!(decrypted_str, unicode_data);
}

#[test]
fn test_binary_data_encryption() {
    // Test with binary data including null bytes
    let binary_data: Vec<u8> = (0..=255).collect();
    let key = [0x42u8; 32];

    let ciphertext = encrypt_aes_gcm(&binary_data, &key, SecurityMode::Unverified)
        .expect("binary encryption should succeed");
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified)
        .expect("binary decryption should succeed");

    assert_eq!(decrypted, binary_data);
}

// ============================================================================
// Integration: Key Derivation + Encryption + HMAC
// ============================================================================

#[test]
fn test_multiple_keys_from_single_master() {
    let master_key = b"master key for multi-purpose derivation";

    // Derive separate keys for different purposes
    let enc_key = derive_key(master_key, b"encryption", 32, SecurityMode::Unverified)
        .expect("derivation should succeed");
    let mac_key = derive_key(master_key, b"authentication", 32, SecurityMode::Unverified)
        .expect("derivation should succeed");

    // Verify keys are different
    assert_ne!(enc_key, mac_key, "Different contexts should derive different keys");

    // Use encryption key for AES-GCM
    let plaintext = b"Confidential data";
    let ciphertext = encrypt_aes_gcm(plaintext, &enc_key, SecurityMode::Unverified)
        .expect("encryption should succeed");

    // Use MAC key for HMAC
    let tag = hmac(&ciphertext, &mac_key, SecurityMode::Unverified).expect("HMAC should succeed");
    let is_valid = hmac_check(&ciphertext, &mac_key, &tag, SecurityMode::Unverified)
        .expect("verify should succeed");
    assert!(is_valid, "HMAC should verify");

    // Decrypt and verify original data
    let decrypted = decrypt_aes_gcm(&ciphertext, &enc_key, SecurityMode::Unverified)
        .expect("decryption should succeed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_encrypt_then_mac_pattern() {
    let plaintext = b"Important data requiring both confidentiality and integrity";

    // Use different keys for encryption and authentication (good practice)
    let enc_key =
        derive_key(b"master", b"enc", 32, SecurityMode::Unverified).expect("key derivation");
    let mac_key =
        derive_key(b"master", b"mac", 32, SecurityMode::Unverified).expect("key derivation");

    // Encrypt
    let ciphertext =
        encrypt_aes_gcm(plaintext, &enc_key, SecurityMode::Unverified).expect("encryption");

    // Compute HMAC over ciphertext (Encrypt-then-MAC)
    let tag = hmac(&ciphertext, &mac_key, SecurityMode::Unverified).expect("HMAC");

    // Verify MAC first
    assert!(
        hmac_check(&ciphertext, &mac_key, &tag, SecurityMode::Unverified).expect("verify"),
        "MAC should verify"
    );

    // Then decrypt
    let decrypted =
        decrypt_aes_gcm(&ciphertext, &enc_key, SecurityMode::Unverified).expect("decryption");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_hash_then_sign_pattern() {
    // Simulating a hash-then-sign pattern (without actual signing, just HMAC for demo)
    let document = b"Important legal document content";

    // Hash the document
    let doc_hash = hash_data(document);

    // "Sign" the hash (using HMAC as a stand-in for actual signature)
    let signing_key = b"document signing key";
    let signature = hmac(&doc_hash, signing_key, SecurityMode::Unverified).expect("HMAC");

    // Verify
    let is_valid =
        hmac_check(&doc_hash, signing_key, &signature, SecurityMode::Unverified).expect("verify");
    assert!(is_valid, "Hash+HMAC verification should pass");
}

#[test]
fn test_complete_secure_message_workflow() {
    // Complete workflow: derive keys, encrypt, authenticate
    let master_secret = b"shared master secret between parties";

    // Derive encryption and MAC keys
    let enc_key = derive_key(master_secret, b"message-encryption", 32, SecurityMode::Unverified)
        .expect("enc key derivation");
    let mac_key =
        derive_key(master_secret, b"message-authentication", 32, SecurityMode::Unverified)
            .expect("mac key derivation");

    // Original message
    let message = b"Secret message: Meet at location X at time Y";

    // Encrypt the message
    let ciphertext =
        encrypt_aes_gcm(message, &enc_key, SecurityMode::Unverified).expect("encryption");

    // Create HMAC over ciphertext
    let mac = hmac(&ciphertext, &mac_key, SecurityMode::Unverified).expect("HMAC");

    // Simulate transmission: (ciphertext, mac)

    // Receiver side: verify MAC first
    let mac_valid =
        hmac_check(&ciphertext, &mac_key, &mac, SecurityMode::Unverified).expect("MAC verify");
    assert!(mac_valid, "MAC should verify");

    // Then decrypt
    let decrypted =
        decrypt_aes_gcm(&ciphertext, &enc_key, SecurityMode::Unverified).expect("decryption");
    assert_eq!(decrypted.as_slice(), message, "Original message recovered");
}
