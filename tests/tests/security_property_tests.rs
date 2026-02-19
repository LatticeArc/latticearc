#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Security Property Tests
//!
//! Validates core cryptographic security properties through the `latticearc` public API:
//! ciphertext integrity, signature non-forgeability, message integrity, key uniqueness,
//! nonce uniqueness, and HMAC integrity.
//!
//! Run with: `cargo test --package latticearc --test security_property_tests --all-features --release -- --nocapture`

use latticearc::{
    CryptoConfig, SecurityLevel, SecurityMode, decrypt_aes_gcm, decrypt_hybrid, encrypt_aes_gcm,
    encrypt_hybrid, generate_hybrid_keypair, generate_signing_keypair, hmac, hmac_check,
    sign_with_key, verify,
};

// ============================================================================
// Ciphertext Integrity — Modified Ciphertext Must Fail Decryption
// ============================================================================

#[test]
fn test_aes_gcm_tampered_ciphertext_fails() {
    let key = [0x42u8; 32];
    let plaintext = b"Ciphertext integrity test";

    let mut ct =
        encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");

    // Flip a byte in the ciphertext body (past the 12-byte nonce)
    if ct.len() > 12 {
        ct[12] ^= 0xFF;
    }

    let result = decrypt_aes_gcm(&ct, &key, SecurityMode::Unverified);
    assert!(result.is_err(), "Tampered AES-GCM ciphertext must fail decryption");
}

#[test]
fn test_hybrid_tampered_ciphertext_fails() {
    let (pk, sk) = generate_hybrid_keypair().expect("keygen failed");
    let plaintext = b"Hybrid integrity test";

    let mut encrypted =
        encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified).expect("encrypt failed");

    if !encrypted.symmetric_ciphertext.is_empty() {
        encrypted.symmetric_ciphertext[0] ^= 0xFF;
    }

    let result = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified);
    assert!(result.is_err(), "Tampered hybrid ciphertext must fail decryption");
}

#[test]
fn test_aes_gcm_truncated_ciphertext_fails() {
    let key = [0x33u8; 32];
    let plaintext = b"Truncation test";

    let ct = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");

    // Truncate to just the nonce
    let truncated = &ct[..12];
    let result = decrypt_aes_gcm(truncated, &key, SecurityMode::Unverified);
    assert!(result.is_err(), "Truncated ciphertext must fail decryption");
}

// ============================================================================
// Signature Non-Forgeability — Wrong Key Must Fail Verification
// ============================================================================

#[test]
fn test_signature_wrong_key_fails() {
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk_a, sk_a, _) = generate_signing_keypair(config).expect("keygen A failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk_b, _sk_b, _) = generate_signing_keypair(config).expect("keygen B failed");

    let message = b"Signed by key A";

    // Sign with key A
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let mut signed = sign_with_key(message, &sk_a, &pk_a, config).expect("sign failed");

    // Replace public key with B's key — verification must fail
    signed.metadata.public_key = pk_b;

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = verify(&signed, config);
    match result {
        Ok(false) | Err(_) => {} // Expected
        Ok(true) => panic!("Signature with wrong key must not verify"),
    }
}

#[test]
fn test_hybrid_wrong_key_fails() {
    let (pk1, _sk1) = generate_hybrid_keypair().expect("keygen 1 failed");
    let (_pk2, sk2) = generate_hybrid_keypair().expect("keygen 2 failed");

    let encrypted =
        encrypt_hybrid(b"cross-key test", &pk1, SecurityMode::Unverified).expect("encrypt failed");

    let result = decrypt_hybrid(&encrypted, &sk2, SecurityMode::Unverified);
    assert!(result.is_err(), "Decrypt with wrong hybrid key must fail");
}

// ============================================================================
// Message Integrity — Modified Message Must Fail Verification
// ============================================================================

#[test]
fn test_signature_tampered_message_fails() {
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, _) = generate_signing_keypair(config).expect("keygen failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let mut signed = sign_with_key(b"original", &sk, &pk, config).expect("sign failed");

    // Tamper with the signed data
    signed.data = b"tampered".to_vec();

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = verify(&signed, config);
    match result {
        Ok(false) | Err(_) => {} // Expected
        Ok(true) => panic!("Tampered message must not verify"),
    }
}

// ============================================================================
// Key Uniqueness — Different Keypairs Produce Different Ciphertexts
// ============================================================================

#[test]
fn test_aes_gcm_different_keys_different_output() {
    let plaintext = b"Key uniqueness test";

    let ct1 =
        encrypt_aes_gcm(plaintext, &[0x11u8; 32], SecurityMode::Unverified).expect("enc1 failed");
    let ct2 =
        encrypt_aes_gcm(plaintext, &[0x22u8; 32], SecurityMode::Unverified).expect("enc2 failed");

    assert_ne!(ct1, ct2, "Different keys must produce different ciphertexts");
}

#[test]
fn test_signing_keypair_uniqueness() {
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk1, _sk1, _) = generate_signing_keypair(config).expect("keygen1 failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk2, _sk2, _) = generate_signing_keypair(config).expect("keygen2 failed");

    assert_ne!(pk1, pk2, "Different keypairs must have different public keys");
}

// ============================================================================
// Nonce Uniqueness — Same Plaintext Encrypts Differently Each Time
// ============================================================================

#[test]
fn test_aes_gcm_nonce_uniqueness() {
    let key = [0xBBu8; 32];
    let plaintext = b"Same plaintext, different nonce";

    let ct1 = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("enc1 failed");
    let ct2 = encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("enc2 failed");

    assert_ne!(ct1, ct2, "Same plaintext must encrypt differently due to random nonce");
}

#[test]
fn test_hybrid_nonce_uniqueness() {
    let (pk, _sk) = generate_hybrid_keypair().expect("keygen failed");
    let plaintext = b"Hybrid nonce test";

    let enc1 = encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified).expect("enc1 failed");
    let enc2 = encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified).expect("enc2 failed");

    // Each encryption uses fresh KEM + nonce, so ciphertexts differ
    assert_ne!(
        enc1.symmetric_ciphertext, enc2.symmetric_ciphertext,
        "Hybrid must encrypt differently each time"
    );
}

// ============================================================================
// HMAC Integrity — Modified Tag/Data Must Fail
// ============================================================================

#[test]
fn test_hmac_wrong_data_fails() {
    let key = b"hmac-key-for-integrity-testing!!";
    let data = b"Authentic data";

    let tag = hmac(data, key, SecurityMode::Unverified).expect("hmac failed");

    let ok =
        hmac_check(b"wrong data", key, &tag, SecurityMode::Unverified).expect("hmac_check failed");
    assert!(!ok, "HMAC with wrong data must fail");
}

#[test]
fn test_hmac_tampered_tag_fails() {
    let key = b"hmac-key-for-integrity-testing!!";
    let data = b"Authentic data";

    let mut tag = hmac(data, key, SecurityMode::Unverified).expect("hmac failed");

    if !tag.is_empty() {
        tag[0] ^= 0xFF;
    }

    let ok = hmac_check(data, key, &tag, SecurityMode::Unverified).expect("hmac_check failed");
    assert!(!ok, "HMAC with tampered tag must fail");
}

// ============================================================================
// AES-GCM Wrong Key Must Fail
// ============================================================================

#[test]
fn test_aes_gcm_wrong_key_fails() {
    let plaintext = b"Wrong key rejection";
    let ct =
        encrypt_aes_gcm(plaintext, &[0x11u8; 32], SecurityMode::Unverified).expect("enc failed");
    let result = decrypt_aes_gcm(&ct, &[0x22u8; 32], SecurityMode::Unverified);
    assert!(result.is_err(), "Decrypt with wrong AES key must fail");
}
