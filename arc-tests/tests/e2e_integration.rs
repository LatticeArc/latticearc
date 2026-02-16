#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! End-to-End Integration Tests
//!
//! Validates that all public `latticearc` facade APIs produce correct results
//! across multiple security levels and configurations.
//!
//! Run with: `cargo test --package latticearc --test e2e_integration --all-features --release -- --nocapture`

use latticearc::{
    CryptoConfig, SecurityLevel, SecurityMode, decrypt_aes_gcm, decrypt_hybrid, derive_key,
    deserialize_signed_data, encrypt_aes_gcm, encrypt_hybrid, generate_hybrid_keypair,
    generate_signing_keypair, hash_data, hmac, hmac_check, serialize_signed_data, sign_ed25519,
    sign_with_key, verify, verify_ed25519,
};

// ============================================================================
// Encrypt/Decrypt Roundtrip — Multiple Security Levels
// ============================================================================

#[test]
fn test_aes_gcm_roundtrip_256() {
    let key = [0xABu8; 32];
    let plaintext = b"AES-256-GCM end-to-end roundtrip";

    let ciphertext =
        encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");
    let decrypted =
        decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified).expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    let key = [0x99u8; 32];
    let plaintext = b"";

    let ciphertext =
        encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");
    let decrypted =
        decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified).expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_aes_gcm_large_plaintext() {
    let key = [0x77u8; 32];
    let plaintext = vec![0xFFu8; 64 * 1024]; // 64 KiB

    let ciphertext =
        encrypt_aes_gcm(&plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");
    let decrypted =
        decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified).expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext.as_slice());
}

// ============================================================================
// Sign/Verify Roundtrip — Multiple Security Levels
// ============================================================================

#[test]
fn test_sign_verify_high_security() {
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen failed");
    assert!(!scheme.is_empty());

    let message = b"Sign/verify at High security level";

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&signed, config).expect("verify failed");
    assert!(is_valid, "Signature should verify at High level");
}

#[test]
fn test_sign_verify_maximum_security() {
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen failed");
    assert!(!scheme.is_empty());

    let message = b"Sign/verify at Maximum security level";

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let is_valid = verify(&signed, config).expect("verify failed");
    assert!(is_valid, "Signature should verify at Maximum level");
}

// ============================================================================
// Hybrid Encrypt/Decrypt Roundtrip
// ============================================================================

#[test]
fn test_hybrid_encrypt_decrypt_roundtrip() {
    let (pk, sk) = generate_hybrid_keypair().expect("keygen failed");

    let plaintext = b"True hybrid ML-KEM-768 + X25519 encryption";

    let encrypted =
        encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified).expect("encrypt failed");
    assert_eq!(encrypted.kem_ciphertext.len(), 1088, "ML-KEM-768 CT = 1088 bytes");
    assert_eq!(encrypted.ecdh_ephemeral_pk.len(), 32, "X25519 PK = 32 bytes");

    let decrypted =
        decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_hybrid_different_plaintexts() {
    let (pk, sk) = generate_hybrid_keypair().expect("keygen failed");

    for msg in [b"short" as &[u8], b"", &[0xAA; 4096]] {
        let encrypted = encrypt_hybrid(msg, &pk, SecurityMode::Unverified).expect("encrypt failed");
        let decrypted =
            decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified).expect("decrypt failed");
        assert_eq!(decrypted.as_slice(), msg);
    }
}

// ============================================================================
// Hash + HMAC Roundtrip
// ============================================================================

#[test]
fn test_hash_deterministic() {
    let data = b"Hash determinism check";
    let h1 = hash_data(data);
    let h2 = hash_data(data);
    assert_eq!(h1, h2, "SHA3-256 must be deterministic");
    assert_eq!(h1.len(), 32, "SHA3-256 = 32 bytes");
}

#[test]
fn test_hash_collision_resistance() {
    let h1 = hash_data(b"data-a");
    let h2 = hash_data(b"data-b");
    assert_ne!(h1, h2, "Different inputs should hash differently");
}

#[test]
fn test_hmac_roundtrip() {
    let key = b"hmac-secret-key-32-bytes-exact!!";
    let data = b"Message to authenticate";

    let tag = hmac(data, key, SecurityMode::Unverified).expect("hmac failed");
    assert!(!tag.is_empty());

    let ok = hmac_check(data, key, &tag, SecurityMode::Unverified).expect("hmac_check failed");
    assert!(ok, "HMAC should verify");
}

#[test]
fn test_hmac_wrong_key_fails() {
    let key = b"hmac-secret-key-32-bytes-exact!!";
    let data = b"Message to authenticate";

    let tag = hmac(data, key, SecurityMode::Unverified).expect("hmac failed");

    let wrong_key = b"wrong-key-32-bytes-long-for-test";
    let ok =
        hmac_check(data, wrong_key, &tag, SecurityMode::Unverified).expect("hmac_check failed");
    assert!(!ok, "HMAC with wrong key should fail");
}

// ============================================================================
// Key Derivation Workflow
// ============================================================================

#[test]
fn test_kdf_derive_consistent() {
    let password = b"secure-password";
    let salt = b"application-salt";

    let k1 = derive_key(password, salt, 32, SecurityMode::Unverified).expect("derive failed");
    let k2 = derive_key(password, salt, 32, SecurityMode::Unverified).expect("derive failed");

    assert_eq!(k1, k2, "Same inputs = same derived key");
    assert_eq!(k1.len(), 32);
}

#[test]
fn test_kdf_different_salt() {
    let password = b"secure-password";
    let k1 = derive_key(password, b"salt-a", 32, SecurityMode::Unverified).expect("derive failed");
    let k2 = derive_key(password, b"salt-b", 32, SecurityMode::Unverified).expect("derive failed");
    assert_ne!(k1, k2, "Different salts = different keys");
}

// ============================================================================
// Ed25519 Sign/Verify Roundtrip
// ============================================================================

#[test]
fn test_ed25519_roundtrip() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let sk_bytes = signing_key.to_bytes();
    let pk_bytes = signing_key.verifying_key().to_bytes();

    let message = b"Ed25519 integration test";

    let signature =
        sign_ed25519(message, &sk_bytes, SecurityMode::Unverified).expect("sign failed");
    let is_valid = verify_ed25519(message, &signature, &pk_bytes, SecurityMode::Unverified)
        .expect("verify failed");
    assert!(is_valid, "Ed25519 signature should verify");
}

// ============================================================================
// Config-Driven Multi-Algorithm Workflow
// ============================================================================

#[test]
fn test_complete_encrypt_sign_workflow() {
    // Derive encryption key
    let enc_key =
        derive_key(b"password", b"salt", 32, SecurityMode::Unverified).expect("derive failed");

    // Encrypt data
    let plaintext = b"Workflow payload";
    let ciphertext =
        encrypt_aes_gcm(plaintext, &enc_key, SecurityMode::Unverified).expect("encrypt failed");

    // Sign the ciphertext
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (sign_pk, sign_sk, _) = generate_signing_keypair(config).expect("keygen failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(&ciphertext, &sign_sk, &sign_pk, config).expect("sign failed");

    // Serialize + deserialize
    let serialized = serialize_signed_data(&signed).expect("serialize failed");
    assert!(!serialized.is_empty());
    let loaded = deserialize_signed_data(&serialized).expect("deserialize failed");

    // Verify
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&loaded, config).expect("verify failed");
    assert!(is_valid);

    // Decrypt
    let decrypted =
        decrypt_aes_gcm(&loaded.data, &enc_key, SecurityMode::Unverified).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_hybrid_then_sign_workflow() {
    let (h_pk, h_sk) = generate_hybrid_keypair().expect("keygen failed");

    // Hybrid encrypt
    let plaintext = b"Hybrid + signature workflow";
    let encrypted =
        encrypt_hybrid(plaintext, &h_pk, SecurityMode::Unverified).expect("encrypt failed");

    // Sign the ciphertext portion
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (s_pk, s_sk, _) = generate_signing_keypair(config).expect("keygen failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed =
        sign_with_key(&encrypted.symmetric_ciphertext, &s_sk, &s_pk, config).expect("sign failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&signed, config).expect("verify failed");
    assert!(is_valid);

    // Decrypt
    let decrypted =
        decrypt_hybrid(&encrypted, &h_sk, SecurityMode::Unverified).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext);
}
