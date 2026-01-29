#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for hybrid encryption
//!
//! Tests that encrypt_hybrid/decrypt_hybrid roundtrip correctly
//! with arbitrary plaintext data using ML-KEM + AES-GCM.

use libfuzzer_sys::fuzz_target;
use arc_core::convenience::{encrypt_hybrid, decrypt_hybrid, generate_ml_kem_keypair};
use arc_core::zero_trust::SecurityMode;
use arc_primitives::kem::ml_kem::MlKemSecurityLevel;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for symmetric key + some plaintext
    if data.len() < 33 {
        return;
    }

    // Use first 32 bytes as symmetric key, rest as plaintext
    let symmetric_key = &data[..32];
    let plaintext = &data[32..];

    // Generate ML-KEM keypair for hybrid encryption
    let (public_key, private_key) = match generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test hybrid encryption with KEM (using Unverified mode for fuzzing)
    if let Ok(encrypted) = encrypt_hybrid(plaintext, Some(&public_key), symmetric_key, SecurityMode::Unverified) {
        // Test hybrid decryption
        if let Ok(decrypted) = decrypt_hybrid(
            &encrypted.ciphertext,
            Some(private_key.as_ref()),
            &encrypted.encapsulated_key,
            symmetric_key,
            SecurityMode::Unverified,
        ) {
            // Verify roundtrip
            assert_eq!(plaintext, decrypted.as_slice());
        }
    }
});
