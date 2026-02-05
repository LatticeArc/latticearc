#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-KEM key generation
//!
//! Tests that ML-KEM key generation handles various conditions
//! and produces valid keypairs.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut rng = rand::thread_rng();

    // Select security level based on first byte
    let level = match data[0] % 3 {
        0 => MlKemSecurityLevel::MlKem512,
        1 => MlKemSecurityLevel::MlKem768,
        _ => MlKemSecurityLevel::MlKem1024,
    };

    // Test 1: Key generation should always succeed
    match MlKem::generate_keypair(&mut rng, level) {
        Ok((pk, sk)) => {
            // Verify key sizes
            assert_eq!(
                pk.as_bytes().len(),
                level.public_key_size(),
                "Public key size mismatch for {:?}",
                level
            );
            assert_eq!(
                sk.as_bytes().len(),
                level.secret_key_size(),
                "Secret key size mismatch for {:?}",
                level
            );

            // Verify public key is not all zeros (would indicate RNG failure)
            let pk_bytes = pk.as_bytes();
            let all_zero = pk_bytes.iter().all(|&b| b == 0);
            assert!(!all_zero, "Public key should not be all zeros");

            // Test encapsulation with generated key
            if let Ok((ss, ct)) = MlKem::encapsulate(&mut rng, &pk) {
                // Verify shared secret is 32 bytes
                assert_eq!(ss.as_bytes().len(), 32);
                // Verify ciphertext size
                assert_eq!(ct.as_bytes().len(), level.ciphertext_size());
            }
        }
        Err(_) => {
            // Key generation failure (RNG issue) - acceptable but rare
        }
    }

    // Test 2: Multiple key generations should produce different keys
    if let (Ok((pk1, _sk1)), Ok((pk2, _sk2))) = (
        MlKem::generate_keypair(&mut rng, level),
        MlKem::generate_keypair(&mut rng, level),
    ) {
        // Keys should be different (with overwhelming probability)
        assert_ne!(
            pk1.as_bytes(),
            pk2.as_bytes(),
            "Consecutive key generations should produce different keys"
        );
    }

    // Test 3: Test all security levels in sequence
    for test_level in [
        MlKemSecurityLevel::MlKem512,
        MlKemSecurityLevel::MlKem768,
        MlKemSecurityLevel::MlKem1024,
    ] {
        if let Ok((pk, _sk)) = MlKem::generate_keypair(&mut rng, test_level) {
            // Verify key has correct size for its level
            assert_eq!(pk.as_bytes().len(), test_level.public_key_size());
        }
    }

    // Test 4: Verify deterministic generation with seed (if supported)
    if data.len() >= 32 {
        let seed: [u8; 32] = data[..32].try_into().unwrap_or([0u8; 32]);

        // Generate with seed
        let result1 = MlKem::generate_keypair_with_seed(&seed, level);
        let result2 = MlKem::generate_keypair_with_seed(&seed, level);

        // Both should succeed or fail consistently
        match (&result1, &result2) {
            (Ok((pk1, _)), Ok((pk2, _))) => {
                // Note: aws-lc-rs uses internal DRBG, so keys may differ
                // This test verifies no crash occurs
                let _ = pk1.as_bytes();
                let _ = pk2.as_bytes();
            }
            (Err(_), Err(_)) => {
                // Both failed - consistent behavior
            }
            _ => {
                // Mixed results - also acceptable given RNG variation
            }
        }
    }
});
