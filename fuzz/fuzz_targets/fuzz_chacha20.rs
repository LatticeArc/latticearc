#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ChaCha20-Poly1305 AEAD
//!
//! Tests that ChaCha20-Poly1305 encrypt/decrypt operations don't crash
//! with arbitrary input data and handle all error cases gracefully.

use libfuzzer_sys::fuzz_target;
use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;
use arc_primitives::aead::AeadCipher;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key + 12 bytes nonce + some plaintext
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

    // Create cipher - this should always succeed with 32-byte key
    if let Ok(cipher) = ChaCha20Poly1305Cipher::new(key) {
        // Test encryption
        if let Ok((ciphertext, tag)) = cipher.encrypt(&nonce, plaintext, None) {
            // Test decryption roundtrip
            if let Ok(decrypted) = cipher.decrypt(&nonce, &ciphertext, &tag, None) {
                // Verify roundtrip integrity
                assert_eq!(plaintext, decrypted.as_slice(), "Roundtrip must preserve plaintext");
            }

            // Test with corrupted tag (should fail gracefully)
            let mut bad_tag = tag;
            bad_tag[0] ^= 0xFF;
            let result = cipher.decrypt(&nonce, &ciphertext, &bad_tag, None);
            assert!(result.is_err(), "Corrupted tag must fail verification");

            // Test with corrupted ciphertext (should fail gracefully)
            if !ciphertext.is_empty() {
                let mut bad_ct = ciphertext.clone();
                bad_ct[0] ^= 0xFF;
                let result = cipher.decrypt(&nonce, &bad_ct, &tag, None);
                assert!(result.is_err(), "Corrupted ciphertext must fail verification");
            }

            // Test with AAD
            let aad = b"additional data";
            if let Ok((ct_with_aad, tag_with_aad)) = cipher.encrypt(&nonce, plaintext, Some(aad)) {
                // Correct AAD should work
                assert!(cipher.decrypt(&nonce, &ct_with_aad, &tag_with_aad, Some(aad)).is_ok());

                // Wrong AAD should fail
                let wrong_aad = b"wrong data";
                let result = cipher.decrypt(&nonce, &ct_with_aad, &tag_with_aad, Some(wrong_aad));
                assert!(result.is_err(), "Wrong AAD must fail verification");
            }

            // Test empty plaintext
            if let Ok((empty_ct, empty_tag)) = cipher.encrypt(&nonce, &[], None) {
                assert!(empty_ct.is_empty(), "Empty plaintext should produce empty ciphertext");
                assert_eq!(empty_tag.len(), 16, "Tag should be 16 bytes");
                assert!(cipher.decrypt(&nonce, &empty_ct, &empty_tag, None).is_ok());
            }
        }
    }

    // Test invalid key lengths (should fail gracefully)
    if data.len() >= 16 {
        let short_key = &data[..16];
        assert!(ChaCha20Poly1305Cipher::new(short_key).is_err(), "Short key must be rejected");
    }

    // Test very short keys
    if data.len() >= 8 {
        let tiny_key = &data[..8];
        assert!(ChaCha20Poly1305Cipher::new(tiny_key).is_err(), "Tiny key must be rejected");
    }

    // Test with fuzzed nonce bytes for decryption
    if let Ok(cipher) = ChaCha20Poly1305Cipher::new(key) {
        if let Ok((ciphertext, tag)) = cipher.encrypt(&nonce, plaintext, None) {
            // Corrupt nonce
            let mut bad_nonce = nonce;
            bad_nonce[0] ^= 0xFF;

            // Decryption with wrong nonce should fail
            let result = cipher.decrypt(&bad_nonce, &ciphertext, &tag, None);
            assert!(result.is_err(), "Wrong nonce must fail verification");
        }
    }

    // Test multiple encryptions produce different results (due to different nonces)
    if data.len() >= 56 {
        let nonce2_slice = &data[44..56];
        let mut nonce2 = [0u8; 12];
        nonce2.copy_from_slice(nonce2_slice);

        if nonce != nonce2 {
            if let Ok(cipher) = ChaCha20Poly1305Cipher::new(key) {
                if let (Ok((ct1, _tag1)), Ok((ct2, _tag2))) = (
                    cipher.encrypt(&nonce, plaintext, None),
                    cipher.encrypt(&nonce2, plaintext, None),
                ) {
                    // Different nonces should produce different ciphertexts
                    if !plaintext.is_empty() {
                        assert_ne!(
                            ct1, ct2,
                            "Different nonces should produce different ciphertexts"
                        );
                    }
                }
            }
        }
    }
});
