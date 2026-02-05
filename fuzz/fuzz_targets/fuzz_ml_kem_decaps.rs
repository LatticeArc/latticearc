#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-KEM decapsulation
//!
//! Tests that ML-KEM decapsulation handles arbitrary ciphertext data
//! without crashing and correctly rejects malformed inputs.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kem::ml_kem::{MlKem, MlKemCiphertext, MlKemSecurityLevel};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut rng = rand::thread_rng();

    // Select security level based on first byte
    let (level, ct_size) = match data[0] % 3 {
        0 => (MlKemSecurityLevel::MlKem512, 768),
        1 => (MlKemSecurityLevel::MlKem768, 1088),
        _ => (MlKemSecurityLevel::MlKem1024, 1568),
    };

    // Test 1: Generate valid keypair and test with valid ciphertext
    if let Ok((pk, sk)) = MlKem::generate_keypair(&mut rng, level) {
        if let Ok((_ss1, ct)) = MlKem::encapsulate(&mut rng, &pk) {
            // Decapsulation with aws-lc-rs limitation will error,
            // but should not crash
            let _ = MlKem::decapsulate(&sk, &ct);
        }
    }

    // Test 2: Test with fuzzed ciphertext bytes
    if data.len() >= ct_size {
        let ct_bytes = &data[..ct_size];

        // Try to create ciphertext from fuzzed data
        match MlKemCiphertext::new(level, ct_bytes.to_vec()) {
            Ok(ct) => {
                // Generate keypair for decapsulation attempt
                if let Ok((_pk, sk)) = MlKem::generate_keypair(&mut rng, level) {
                    // Attempt decapsulation - should not crash
                    let _ = MlKem::decapsulate(&sk, &ct);
                }
            }
            Err(_) => {
                // Invalid ciphertext rejected - expected behavior
            }
        }
    }

    // Test 3: Test with corrupted valid ciphertext
    if let Ok((pk, sk)) = MlKem::generate_keypair(&mut rng, level) {
        if let Ok((_ss, ct)) = MlKem::encapsulate(&mut rng, &pk) {
            // Corrupt the ciphertext
            let ct_bytes = ct.as_bytes();
            if !ct_bytes.is_empty() && !data.is_empty() {
                let mut corrupted = ct_bytes.to_vec();
                // Calculate the length first to avoid borrow issues
                let len = corrupted.len();
                // XOR with fuzz data
                for (i, b) in data.iter().enumerate() {
                    let idx = i % len;
                    corrupted[idx] ^= b;
                }

                if let Ok(corrupted_ct) = MlKemCiphertext::new(level, corrupted) {
                    // Decapsulation with corrupted data should not crash
                    let _ = MlKem::decapsulate(&sk, &corrupted_ct);
                }
            }
        }
    }

    // Test 4: Test invalid ciphertext lengths
    for test_size in [ct_size.saturating_sub(10), ct_size.saturating_add(10)] {
        if data.len() >= test_size && test_size > 0 {
            let sized_data: Vec<u8> = data.iter().cycle().take(test_size).copied().collect();
            // Should fail gracefully with invalid size
            let result = MlKemCiphertext::new(level, sized_data);
            if test_size != ct_size {
                assert!(result.is_err(), "Invalid ciphertext size should be rejected");
            }
        }
    }
});
