//! ChaCha20-Poly1305 Known Answer Tests (RFC 8439)
//!
//! Test vectors derived from RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols).
//! These tests validate the ChaCha20-Poly1305 implementation against official IETF values.

#![allow(clippy::expect_used)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::indexing_slicing)]

use super::common::{constant_time_eq, decode_hex};
use arc_primitives::aead::AeadCipher;
use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher as ChaCha20Poly1305;

/// RFC 8439 Section 2.8.2 Test Vector
/// AEAD_CHACHA20_POLY1305 Test Vector
const RFC8439_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const RFC8439_NONCE: &str = "070000004041424344454647";
const RFC8439_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const RFC8439_PLAINTEXT: &str = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";
const RFC8439_CIPHERTEXT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
const RFC8439_TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

/// Test ChaCha20-Poly1305 with RFC 8439 main test vector
#[test]
fn test_chacha20_poly1305_rfc8439_main() {
    let key = decode_hex(RFC8439_KEY).expect("key decode");
    let nonce = decode_hex(RFC8439_NONCE).expect("nonce decode");
    let aad = decode_hex(RFC8439_AAD).expect("aad decode");
    let plaintext = decode_hex(RFC8439_PLAINTEXT).expect("plaintext decode");
    let expected_ct = decode_hex(RFC8439_CIPHERTEXT).expect("ciphertext decode");
    let expected_tag = decode_hex(RFC8439_TAG).expect("tag decode");

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    let cipher = ChaCha20Poly1305::new(&key_arr).expect("cipher creation");

    let (ct, tag) = cipher.encrypt(&nonce_arr, &plaintext, Some(&aad)).expect("encryption");

    assert_eq!(ct, expected_ct, "Ciphertext mismatch");
    assert!(
        constant_time_eq(&tag, &expected_tag),
        "Tag mismatch: got {}, expected {}",
        hex::encode(&tag),
        hex::encode(&expected_tag)
    );

    // Test decryption
    let decrypted = cipher.decrypt(&nonce_arr, &ct, &tag, Some(&aad)).expect("decryption");
    assert_eq!(decrypted, plaintext, "Decryption mismatch");
}

/// Test ChaCha20-Poly1305 with empty message and AAD
#[test]
fn test_chacha20_poly1305_empty_message_with_aad() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"";
    let aad = b"some authenticated data";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption");

    assert!(ct.is_empty(), "Ciphertext for empty plaintext should be empty");
    assert_eq!(tag.len(), 16, "Tag should be 16 bytes");

    // Verify decryption works
    let decrypted = cipher.decrypt(&nonce, &ct, &tag, Some(aad)).expect("decryption");
    assert!(decrypted.is_empty(), "Decrypted should be empty");
}

/// Test ChaCha20-Poly1305 roundtrip with generated key
#[test]
fn test_chacha20_poly1305_roundtrip() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"Test message for ChaCha20-Poly1305 roundtrip";
    let aad = b"Additional authenticated data";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption");
    let decrypted = cipher.decrypt(&nonce, &ct, &tag, Some(aad)).expect("decryption");

    assert_eq!(decrypted.as_slice(), plaintext);
}

/// Test ChaCha20-Poly1305 without AAD
#[test]
fn test_chacha20_poly1305_no_aad() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"Test message without AAD";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");
    let decrypted = cipher.decrypt(&nonce, &ct, &tag, None).expect("decryption");

    assert_eq!(decrypted.as_slice(), plaintext);
}

/// Test authentication tag tampering detection
#[test]
fn test_chacha20_poly1305_tag_tampering() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"Test message";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct, mut tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");

    // Tamper with tag
    tag[0] ^= 0xFF;

    let result = cipher.decrypt(&nonce, &ct, &tag, None);
    assert!(result.is_err(), "Decryption should fail with tampered tag");
}

/// Test ciphertext tampering detection
#[test]
fn test_chacha20_poly1305_ciphertext_tampering() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"Test message for tampering";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (mut ct, tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");

    // Tamper with ciphertext
    if !ct.is_empty() {
        ct[0] ^= 0xFF;
    }

    let result = cipher.decrypt(&nonce, &ct, &tag, None);
    assert!(result.is_err(), "Decryption should fail with tampered ciphertext");
}

/// Test AAD tampering detection
#[test]
fn test_chacha20_poly1305_aad_tampering() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"Test message";
    let aad = b"Original AAD";
    let tampered_aad = b"Tampered AAD";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).expect("encryption");

    let result = cipher.decrypt(&nonce, &ct, &tag, Some(tampered_aad));
    assert!(result.is_err(), "Decryption should fail with tampered AAD");
}

/// Test empty plaintext encryption
#[test]
fn test_chacha20_poly1305_empty_plaintext() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");

    assert!(ct.is_empty(), "Ciphertext for empty plaintext should be empty");
    assert_eq!(tag.len(), 16, "Tag should be 16 bytes");

    let decrypted = cipher.decrypt(&nonce, &ct, &tag, None).expect("decryption");
    assert!(decrypted.is_empty(), "Decrypted should be empty");
}

/// Test different nonces produce different ciphertexts
#[test]
fn test_chacha20_poly1305_nonce_uniqueness() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce1 = ChaCha20Poly1305::generate_nonce();
    let nonce2 = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"Same message";

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct1, _tag1) = cipher.encrypt(&nonce1, plaintext, None).expect("encryption 1");
    let (ct2, _tag2) = cipher.encrypt(&nonce2, plaintext, None).expect("encryption 2");

    assert_ne!(nonce1, nonce2, "Nonces should be different");
    assert_ne!(ct1, ct2, "Different nonces should produce different ciphertexts");
}

/// Test large message encryption/decryption
#[test]
fn test_chacha20_poly1305_large_message() {
    let key = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = vec![0x42u8; 1_000_000]; // 1MB message

    let cipher = ChaCha20Poly1305::new(&key).expect("cipher creation");
    let (ct, tag) = cipher.encrypt(&nonce, &plaintext, None).expect("encryption");
    let decrypted = cipher.decrypt(&nonce, &ct, &tag, None).expect("decryption");

    assert_eq!(decrypted, plaintext, "Large message roundtrip failed");
}

/// Test wrong key fails decryption
#[test]
fn test_chacha20_poly1305_wrong_key() {
    let key1 = ChaCha20Poly1305::generate_key();
    let key2 = ChaCha20Poly1305::generate_key();
    let nonce = ChaCha20Poly1305::generate_nonce();
    let plaintext = b"Test message";

    let cipher1 = ChaCha20Poly1305::new(&key1).expect("cipher 1 creation");
    let cipher2 = ChaCha20Poly1305::new(&key2).expect("cipher 2 creation");

    let (ct, tag) = cipher1.encrypt(&nonce, plaintext, None).expect("encryption");
    let result = cipher2.decrypt(&nonce, &ct, &tag, None);

    assert!(result.is_err(), "Decryption should fail with wrong key");
}
