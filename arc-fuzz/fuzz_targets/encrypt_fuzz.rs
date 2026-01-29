#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for AES-GCM encryption/decryption
//!
//! Tests that encrypt_aes_gcm/decrypt_aes_gcm roundtrip correctly
//! with arbitrary plaintext data.

use libfuzzer_sys::fuzz_target;
use arc_core::{encrypt_aes_gcm, decrypt_aes_gcm};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key + some plaintext
    if data.len() < 33 {
        return;
    }

    // Use first 32 bytes as key, rest as plaintext
    let key = &data[..32];
    let plaintext = &data[32..];

    // Test encryption
    if let Ok(encrypted) = encrypt_aes_gcm(plaintext, key) {
        // Test decryption
        if let Ok(decrypted) = decrypt_aes_gcm(&encrypted, key) {
            // Verify roundtrip
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }
});
