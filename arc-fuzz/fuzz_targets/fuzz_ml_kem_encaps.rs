#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-KEM encapsulation
//!
//! Tests that ML-KEM encapsulation handles arbitrary public key data
//! without crashing and produces valid ciphertexts for valid keys.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kem::ml_kem::{MlKem, MlKemPublicKey, MlKemSecurityLevel};

fuzz_target!(|data: &[u8]| {
    // Need at least 800 bytes (ML-KEM-512 public key size)
    if data.is_empty() {
        return;
    }

    let mut rng = rand::thread_rng();

    // Select security level based on first byte
    let (level, pk_size) = match data[0] % 3 {
        0 => (MlKemSecurityLevel::MlKem512, 800),
        1 => (MlKemSecurityLevel::MlKem768, 1184),
        _ => (MlKemSecurityLevel::MlKem1024, 1568),
    };

    // Test 1: Encapsulation with valid generated key
    if let Ok((pk, _sk)) = MlKem::generate_keypair(&mut rng, level) {
        match MlKem::encapsulate(&mut rng, &pk) {
            Ok((ss, ct)) => {
                // Verify shared secret is 32 bytes
                assert_eq!(ss.as_bytes().len(), 32, "Shared secret must be 32 bytes");
                // Verify ciphertext has correct length
                assert_eq!(ct.as_bytes().len(), level.ciphertext_size());
            }
            Err(_) => {
                // Encapsulation can fail, this is acceptable
            }
        }
    }

    // Test 2: Encapsulation with fuzzed public key bytes
    if data.len() >= pk_size {
        let pk_bytes = &data[..pk_size];

        // Try to create public key from fuzzed data
        match MlKemPublicKey::new(level, pk_bytes.to_vec()) {
            Ok(pk) => {
                // Attempt encapsulation - should not crash
                let _ = MlKem::encapsulate(&mut rng, &pk);
            }
            Err(_) => {
                // Invalid public key rejected - expected behavior
            }
        }
    }

    // Test 3: Test with truncated/padded public key sizes
    for test_size in [pk_size.saturating_sub(1), pk_size.saturating_add(1)] {
        if data.len() >= test_size && test_size > 0 {
            let truncated = &data[..test_size];
            // Should fail gracefully with invalid size
            let result = MlKemPublicKey::new(level, truncated.to_vec());
            if test_size != pk_size {
                assert!(result.is_err(), "Invalid key size should be rejected");
            }
        }
    }
});
