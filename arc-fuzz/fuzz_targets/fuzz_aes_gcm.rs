#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for AES-GCM encryption/decryption
//!
//! Tests that AES-GCM operations handle arbitrary input data
//! without crashing and correctly reject invalid inputs.

use libfuzzer_sys::fuzz_target;
use arc_primitives::aead::aes_gcm::{AesGcm128, AesGcm256};
use arc_primitives::aead::AeadCipher;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes: key (16 or 32) + nonce (12) + some plaintext
    if data.len() < 45 {
        return;
    }

    // Test AES-GCM-128
    test_aes_gcm_128(data);

    // Test AES-GCM-256
    test_aes_gcm_256(data);
});

fn test_aes_gcm_128(data: &[u8]) {
    // Split input: 16 bytes key, 12 bytes nonce, rest plaintext
    let key = &data[..16];
    let nonce_slice = &data[16..28];
    let plaintext = &data[28..];

    // Convert nonce slice to array
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_slice);

    // Create cipher
    if let Ok(cipher) = AesGcm128::new(key) {
        // Test encryption
        if let Ok((ciphertext, tag)) = cipher.encrypt(&nonce, plaintext, None) {
            // Test decryption roundtrip
            if let Ok(decrypted) = cipher.decrypt(&nonce, &ciphertext, &tag, None) {
                assert_eq!(plaintext, decrypted.as_slice(), "Roundtrip must preserve plaintext");
            }

            // Test with corrupted tag (should fail)
            let mut bad_tag = tag;
            bad_tag[0] ^= 0xFF;
            let result = cipher.decrypt(&nonce, &ciphertext, &bad_tag, None);
            assert!(result.is_err(), "Corrupted tag must fail verification");

            // Test with corrupted ciphertext (should fail)
            if !ciphertext.is_empty() {
                let mut bad_ct = ciphertext.clone();
                bad_ct[0] ^= 0xFF;
                let result = cipher.decrypt(&nonce, &bad_ct, &tag, None);
                assert!(result.is_err(), "Corrupted ciphertext must fail verification");
            }

            // Test with AAD
            let aad = b"additional authenticated data";
            if let Ok((ct_with_aad, tag_with_aad)) = cipher.encrypt(&nonce, plaintext, Some(aad)) {
                // Correct AAD should work
                assert!(cipher.decrypt(&nonce, &ct_with_aad, &tag_with_aad, Some(aad)).is_ok());

                // Wrong AAD should fail
                let wrong_aad = b"wrong data";
                let result = cipher.decrypt(&nonce, &ct_with_aad, &tag_with_aad, Some(wrong_aad));
                assert!(result.is_err(), "Wrong AAD must fail verification");

                // No AAD when expected should fail
                let result = cipher.decrypt(&nonce, &ct_with_aad, &tag_with_aad, None);
                assert!(result.is_err(), "Missing AAD must fail verification");
            }
        }
    }

    // Test invalid key lengths
    let short_key = &data[..8.min(data.len())];
    assert!(AesGcm128::new(short_key).is_err(), "Short key must be rejected");
}

fn test_aes_gcm_256(data: &[u8]) {
    if data.len() < 45 {
        return;
    }

    // Split input: 32 bytes key, 12 bytes nonce, rest plaintext
    let key = &data[..32];
    let nonce_slice = &data[32..44];
    let plaintext = &data[44..];

    // Convert nonce slice to array
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_slice);

    // Create cipher
    if let Ok(cipher) = AesGcm256::new(key) {
        // Test encryption
        if let Ok((ciphertext, tag)) = cipher.encrypt(&nonce, plaintext, None) {
            // Test decryption roundtrip
            if let Ok(decrypted) = cipher.decrypt(&nonce, &ciphertext, &tag, None) {
                assert_eq!(plaintext, decrypted.as_slice(), "Roundtrip must preserve plaintext");
            }

            // Test with corrupted tag (should fail)
            let mut bad_tag = tag;
            bad_tag[0] ^= 0xFF;
            let result = cipher.decrypt(&nonce, &ciphertext, &bad_tag, None);
            assert!(result.is_err(), "Corrupted tag must fail verification");

            // Test with corrupted ciphertext (should fail)
            if !ciphertext.is_empty() {
                let mut bad_ct = ciphertext.clone();
                bad_ct[0] ^= 0xFF;
                let result = cipher.decrypt(&nonce, &bad_ct, &tag, None);
                assert!(result.is_err(), "Corrupted ciphertext must fail verification");
            }

            // Test nonce reuse detection (implicit - different ciphertexts)
            if let Ok((ct2, tag2)) = cipher.encrypt(&nonce, plaintext, None) {
                // Same key+nonce should produce same ciphertext (deterministic)
                assert_eq!(ciphertext, ct2, "Same inputs should produce same ciphertext");
                assert_eq!(tag, tag2, "Same inputs should produce same tag");
            }
        }
    }

    // Test invalid key lengths
    let short_key = &data[..16.min(data.len())];
    assert!(AesGcm256::new(short_key).is_err(), "Short key must be rejected");
}
