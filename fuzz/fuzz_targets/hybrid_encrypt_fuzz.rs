#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for hybrid encryption
//!
//! Tests that the unified encrypt/decrypt API roundtrips correctly
//! with arbitrary plaintext data using ML-KEM-768 + X25519 + AES-GCM hybrid encryption.

use libfuzzer_sys::fuzz_target;
use latticearc::{CryptoConfig, DecryptKey, EncryptKey, decrypt, encrypt, generate_hybrid_keypair};

fuzz_target!(|data: &[u8]| {
    // Use entire fuzz input as plaintext (can be empty)
    let plaintext = data;

    // Generate hybrid keypair (ML-KEM-768 + X25519)
    let (pk, sk) = match generate_hybrid_keypair() {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test hybrid encryption via unified API
    if let Ok(encrypted) = encrypt(plaintext, EncryptKey::Hybrid(&pk), CryptoConfig::new()) {
        // Test hybrid decryption
        if let Ok(decrypted) = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()) {
            // Verify roundtrip
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }
});
