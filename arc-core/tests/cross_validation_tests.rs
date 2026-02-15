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
    clippy::needless_borrows_for_generic_args
)]
//! Cross-validation tests: verify arc-core convenience APIs produce identical
//! results to calling arc-primitives directly.
//!
//! These tests ensure the wrapper layer doesn't silently change behavior,
//! truncate data, or introduce subtle incompatibilities.

use arc_core::convenience::{decrypt_aes_gcm_unverified, encrypt_aes_gcm_unverified};
use arc_primitives::aead::{AeadCipher, aes_gcm::AesGcm256};

#[cfg(not(feature = "fips"))]
use arc_core::convenience::{sign_ed25519_unverified, verify_ed25519_unverified};
#[cfg(not(feature = "fips"))]
use arc_primitives::ec::ed25519::{Ed25519KeyPair, Ed25519Signature};
#[cfg(not(feature = "fips"))]
use arc_primitives::ec::traits::{EcKeyPair, EcSignature};

/// Helper to split wrapper-format encrypted data into (nonce, ciphertext, tag).
fn split_wrapper_format(encrypted: &[u8]) -> (&[u8; 12], &[u8], &[u8; 16]) {
    let nonce: &[u8; 12] = encrypted[..12].try_into().expect("nonce is 12 bytes");
    let ct_and_tag = &encrypted[12..];
    let ct_len = ct_and_tag.len().saturating_sub(16);
    let ciphertext = &ct_and_tag[..ct_len];
    let tag: &[u8; 16] = ct_and_tag[ct_len..].try_into().expect("tag is 16 bytes");
    (nonce, ciphertext, tag)
}

// ============================================================================
// Ed25519: wrapper vs primitives (deterministic — signatures must match)
// ============================================================================

#[cfg(not(feature = "fips"))]
#[test]
fn test_ed25519_sign_wrapper_matches_primitives() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");
    let sk_bytes = keypair.secret_key_bytes();
    let pk_bytes = keypair.public_key_bytes();

    let message = b"cross-validation test message";

    // Sign via primitives
    let prim_sig = keypair.sign(message).expect("primitives sign should succeed");
    let prim_sig_bytes = Ed25519Signature::signature_bytes(&prim_sig);

    // Sign via convenience wrapper
    let wrapper_sig_bytes =
        sign_ed25519_unverified(message, &sk_bytes).expect("wrapper sign should succeed");

    // Ed25519 is deterministic — signatures MUST be identical
    assert_eq!(
        prim_sig_bytes, wrapper_sig_bytes,
        "Primitives and wrapper must produce identical Ed25519 signatures"
    );

    // Cross-verify: wrapper signature verified by primitives
    Ed25519Signature::verify(&pk_bytes, message, &prim_sig)
        .expect("primitives should verify wrapper-generated signature");

    // Cross-verify: primitives signature verified by wrapper
    let valid = verify_ed25519_unverified(message, &wrapper_sig_bytes, &pk_bytes)
        .expect("wrapper should verify primitives-generated signature");
    assert!(valid, "wrapper verification of primitives signature should return true");
}

#[cfg(not(feature = "fips"))]
#[test]
fn test_ed25519_cross_verify_various_messages() {
    let keypair = Ed25519KeyPair::generate().expect("keygen should succeed");
    let sk_bytes = keypair.secret_key_bytes();
    let pk_bytes = keypair.public_key_bytes();

    let messages: &[&[u8]] = &[
        b"",                         // empty
        b"a",                        // single byte
        b"Hello, World!",            // typical
        &[0xFF; 1000],               // 1KB of 0xFF
        b"\x00\x01\x02\x03\x04\x05", // binary data
    ];

    for msg in messages {
        let prim_sig = keypair.sign(msg).expect("primitives sign");
        let prim_bytes = Ed25519Signature::signature_bytes(&prim_sig);

        let wrapper_bytes = sign_ed25519_unverified(msg, &sk_bytes).expect("wrapper sign");

        assert_eq!(
            prim_bytes,
            wrapper_bytes,
            "Signatures must match for message of length {}",
            msg.len()
        );

        // Cross-verify both directions
        let valid = verify_ed25519_unverified(msg, &prim_bytes, &pk_bytes).expect("wrapper verify");
        assert!(valid, "Wrapper should verify primitives sig for len={}", msg.len());
    }
}

// ============================================================================
// AES-256-GCM: encrypt with one layer, decrypt with the other
// ============================================================================

#[test]
fn test_aes_gcm_wrapper_encrypt_primitives_decrypt() {
    let key = [0x42u8; 32];
    let plaintext = b"cross-validation AES-GCM test";

    // Encrypt via convenience wrapper (nonce || ciphertext || tag)
    let encrypted =
        encrypt_aes_gcm_unverified(plaintext, &key).expect("wrapper encrypt should succeed");

    assert!(encrypted.len() >= 28, "Encrypted data should be at least nonce + tag = 28 bytes");

    let (nonce, ciphertext, tag) = split_wrapper_format(&encrypted);

    // Decrypt via primitives
    let cipher = AesGcm256::new(&key).expect("primitives cipher creation should succeed");
    let decrypted = cipher
        .decrypt(nonce, ciphertext, tag, None)
        .expect("primitives decrypt of wrapper ciphertext should succeed");

    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "Primitives decryption of wrapper ciphertext must match original plaintext"
    );
}

#[test]
fn test_aes_gcm_primitives_encrypt_wrapper_decrypt() {
    let key = [0x42u8; 32];
    let plaintext = b"cross-validation AES-GCM test (reverse)";

    // Encrypt via primitives
    let cipher = AesGcm256::new(&key).expect("primitives cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("primitives encrypt should succeed");

    // Build the wrapper format: nonce || ciphertext || tag
    let mut encrypted = Vec::with_capacity(12 + ciphertext.len() + 16);
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);
    encrypted.extend_from_slice(&tag);

    // Decrypt via convenience wrapper
    let decrypted =
        decrypt_aes_gcm_unverified(&encrypted, &key).expect("wrapper decrypt should succeed");

    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "Wrapper decryption of primitives ciphertext must match original plaintext"
    );
}

#[test]
fn test_aes_gcm_cross_validation_various_sizes() {
    let key = [0xAB; 32];

    for size in [0, 1, 15, 16, 17, 64, 256, 1024] {
        let plaintext = vec![0x55u8; size];

        // Direction 1: wrapper encrypt → primitives decrypt
        let encrypted = encrypt_aes_gcm_unverified(&plaintext, &key).expect("wrapper encrypt");
        let (nonce, ciphertext, tag) = split_wrapper_format(&encrypted);

        let cipher = AesGcm256::new(&key).expect("cipher creation");
        let decrypted = cipher.decrypt(nonce, ciphertext, tag, None).expect("primitives decrypt");
        assert_eq!(
            decrypted, plaintext,
            "Cross-validation failed for size={} (wrapper->primitives)",
            size
        );

        // Direction 2: primitives encrypt → wrapper decrypt
        let nonce2 = AesGcm256::generate_nonce();
        let (ct2, tag2) = cipher.encrypt(&nonce2, &plaintext, None).expect("primitives encrypt");
        let mut enc2 = Vec::with_capacity(12 + ct2.len() + 16);
        enc2.extend_from_slice(&nonce2);
        enc2.extend_from_slice(&ct2);
        enc2.extend_from_slice(&tag2);

        let dec2 = decrypt_aes_gcm_unverified(&enc2, &key).expect("wrapper decrypt");
        assert_eq!(
            dec2, plaintext,
            "Cross-validation failed for size={} (primitives->wrapper)",
            size
        );
    }
}
