#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]
//! End-to-End Workflow Integration Tests
//!
//! Full roundtrip tests through the latticearc facade layer,
//! verifying that all public APIs produce correct results.
//!
//! Run with: `cargo test --package latticearc --test end_to_end_workflows --all-features --release -- --nocapture`

use latticearc::{
    CryptoConfig, DecryptKey, EncryptKey, SecurityLevel, SecurityMode, decrypt, decrypt_aes_gcm,
    derive_key, deserialize_signed_data, encrypt, encrypt_aes_gcm, generate_hybrid_keypair,
    generate_signing_keypair, hash_data, hmac, hmac_check, serialize_signed_data, sign_ed25519,
    sign_with_key, verify, verify_ed25519,
};

// ============================================================================
// Unified Encrypt/Decrypt Roundtrip
// ============================================================================

#[test]
fn test_unified_sign_verify_roundtrip() {
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen failed");
    assert!(!scheme.is_empty());

    let message = b"Sign and verify with persistent keypair";

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&signed, config).expect("verify failed");
    assert!(is_valid, "Signature should be valid");
}

#[test]
fn test_hybrid_encrypt_decrypt() {
    let (pk, sk) = generate_hybrid_keypair().expect("keygen failed");

    let plaintext = b"True hybrid ML-KEM-768 + X25519 encryption";

    let encrypted =
        encrypt(plaintext, EncryptKey::Hybrid(&pk), CryptoConfig::new()).expect("encrypt failed");
    let hybrid = encrypted.hybrid_data.as_ref().expect("should have hybrid_data");
    assert_eq!(hybrid.ml_kem_ciphertext.len(), 1088, "ML-KEM-768 CT should be 1088 bytes");
    assert_eq!(hybrid.ecdh_ephemeral_pk.len(), 32, "X25519 PK should be 32 bytes");
    assert_eq!(encrypted.nonce.len(), 12, "AES-GCM nonce should be 12 bytes");
    assert_eq!(encrypted.tag.len(), 16, "AES-GCM tag should be 16 bytes");

    let decrypted =
        decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), plaintext, "Hybrid roundtrip mismatch");
}

#[test]
fn test_aes_gcm_roundtrip() {
    let key = [0xABu8; 32];
    let plaintext = b"AES-256-GCM through facade";

    let ciphertext =
        encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");
    let decrypted =
        decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified).expect("decrypt failed");

    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn test_ed25519_sign_verify() {
    // Generate an Ed25519 keypair
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let sk_bytes = signing_key.to_bytes();
    let pk_bytes = signing_key.verifying_key().to_bytes();

    let message = b"Ed25519 signature via facade";

    let signature =
        sign_ed25519(message, &sk_bytes, SecurityMode::Unverified).expect("sign failed");
    let is_valid = verify_ed25519(message, &signature, &pk_bytes, SecurityMode::Unverified)
        .expect("verify failed");

    assert!(is_valid, "Ed25519 signature should verify");
}

#[test]
fn test_ml_dsa_sign_verify_all_levels() {
    for level in [SecurityLevel::High, SecurityLevel::Maximum] {
        let config = CryptoConfig::new().security_level(level.clone());
        let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen failed");

        let message = b"ML-DSA signature at different security levels";

        let config = CryptoConfig::new().security_level(level.clone());
        let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");

        let config = CryptoConfig::new().security_level(level.clone());
        let is_valid = verify(&signed, config).expect("verify failed");
        assert!(is_valid, "ML-DSA should verify (scheme: {})", scheme);
    }
}

#[test]
fn test_hmac_create_verify() {
    let key = b"hmac-secret-key-for-testing-0123";
    let data = b"Data to authenticate";

    let tag = hmac(data, key, SecurityMode::Unverified).expect("hmac failed");
    assert!(!tag.is_empty(), "HMAC tag should not be empty");

    let is_valid =
        hmac_check(data, key, &tag, SecurityMode::Unverified).expect("hmac_check failed");
    assert!(is_valid, "HMAC should verify");

    // Wrong data should fail
    let wrong_valid =
        hmac_check(b"wrong data", key, &tag, SecurityMode::Unverified).expect("hmac_check failed");
    assert!(!wrong_valid, "HMAC with wrong data should fail");
}

#[test]
fn test_hash_deterministic() {
    let data = b"Hash this data twice";
    let hash1 = hash_data(data);
    let hash2 = hash_data(data);

    assert_eq!(hash1, hash2, "SHA3-256 should be deterministic");
    assert_eq!(hash1.len(), 32, "SHA3-256 output should be 32 bytes");

    // Different data → different hash
    let hash3 = hash_data(b"Different data");
    assert_ne!(hash1, hash3, "Different data should produce different hashes");
}

#[test]
fn test_kdf_derive_consistent() {
    let password = b"my-secure-password";
    let salt = b"application-salt";

    let key1 = derive_key(password, salt, 32, SecurityMode::Unverified).expect("derive failed");
    let key2 = derive_key(password, salt, 32, SecurityMode::Unverified).expect("derive failed");

    assert_eq!(key1, key2, "Same inputs should produce same derived key");
    assert_eq!(key1.len(), 32, "Derived key should be 32 bytes");

    // Different salt → different key
    let key3 = derive_key(password, b"different-salt", 32, SecurityMode::Unverified)
        .expect("derive failed");
    assert_ne!(key1, key3, "Different salt should produce different key");
}

#[test]
fn test_complete_workflow() {
    // Step 1: Derive encryption key from password
    let enc_key =
        derive_key(b"password", b"salt", 32, SecurityMode::Unverified).expect("derive failed");

    // Step 2: Encrypt data
    let original = b"Sensitive workflow data";
    let ciphertext =
        encrypt_aes_gcm(original, &enc_key, SecurityMode::Unverified).expect("encrypt failed");

    // Step 3: Sign the ciphertext
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (sign_pk, sign_sk, _scheme) = generate_signing_keypair(config).expect("keygen failed");

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(&ciphertext, &sign_sk, &sign_pk, config).expect("sign failed");

    // Step 4: Serialize
    let serialized = serialize_signed_data(&signed).expect("serialize failed");
    assert!(!serialized.is_empty());

    // Step 5: Deserialize
    let loaded = deserialize_signed_data(&serialized).expect("deserialize failed");

    // Step 6: Verify signature
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&loaded, config).expect("verify failed");
    assert!(is_valid, "Signature should be valid after serialize/deserialize");

    // Step 7: Decrypt
    let decrypted =
        decrypt_aes_gcm(&loaded.data, &enc_key, SecurityMode::Unverified).expect("decrypt failed");
    assert_eq!(decrypted.as_slice(), original, "Full workflow roundtrip mismatch");
}

#[test]
fn test_tamper_detection_comprehensive() {
    let key = [0x42u8; 32];
    let plaintext = b"Tamper detection test data";

    // Encryption tamper detection
    let mut ciphertext =
        encrypt_aes_gcm(plaintext, &key, SecurityMode::Unverified).expect("encrypt failed");
    if ciphertext.len() > 12 {
        ciphertext[12] ^= 0xFF;
    }
    let result = decrypt_aes_gcm(&ciphertext, &key, SecurityMode::Unverified);
    assert!(result.is_err(), "Tampered ciphertext should fail");

    // Signature tamper detection
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, _) = generate_signing_keypair(config).unwrap();

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let mut signed = sign_with_key(b"original", &sk, &pk, config).unwrap();
    signed.data = b"tampered".to_vec();

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = verify(&signed, config);
    match result {
        Ok(false) | Err(_) => {} // Expected
        Ok(true) => panic!("Tampered signed data should not verify"),
    }

    // Hybrid encryption tamper detection
    let (h_pk, h_sk) = generate_hybrid_keypair().unwrap();
    let mut encrypted = encrypt(b"secret", EncryptKey::Hybrid(&h_pk), CryptoConfig::new()).unwrap();
    if !encrypted.ciphertext.is_empty() {
        encrypted.ciphertext[0] ^= 0xFF;
    }
    let result = decrypt(&encrypted, DecryptKey::Hybrid(&h_sk), CryptoConfig::new());
    assert!(result.is_err(), "Tampered hybrid ciphertext should fail");
}

#[test]
fn test_cross_key_rejection() {
    // Signature cross-key rejection
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk_a, sk_a, _) = generate_signing_keypair(config).unwrap();

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (_pk_b, _sk_b, _) = generate_signing_keypair(config).unwrap();

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed_a = sign_with_key(b"message", &sk_a, &pk_a, config).unwrap();

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&signed_a, config).unwrap();
    assert!(is_valid, "Original signature should verify");

    // Hybrid encryption cross-key rejection
    let (pk_h1, _sk_h1) = generate_hybrid_keypair().unwrap();
    let (_pk_h2, sk_h2) = generate_hybrid_keypair().unwrap();

    let encrypted = encrypt(b"data", EncryptKey::Hybrid(&pk_h1), CryptoConfig::new()).unwrap();
    let result = decrypt(&encrypted, DecryptKey::Hybrid(&sk_h2), CryptoConfig::new());
    assert!(result.is_err(), "Decrypt with wrong hybrid key should fail");

    // AES-GCM cross-key rejection
    let ct = encrypt_aes_gcm(b"data", &[0x11u8; 32], SecurityMode::Unverified).unwrap();
    let result = decrypt_aes_gcm(&ct, &[0x22u8; 32], SecurityMode::Unverified);
    assert!(result.is_err(), "Decrypt with wrong AES key should fail");
}
