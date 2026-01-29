#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-KEM key encapsulation
//!
//! Tests that ML-KEM encapsulate/decapsulate produces matching shared secrets.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

fuzz_target!(|data: &[u8]| {
    // Use first byte to select security level
    let level = if data.is_empty() {
        MlKemSecurityLevel::MlKem768
    } else {
        match data[0] % 3 {
            0 => MlKemSecurityLevel::MlKem512,
            1 => MlKemSecurityLevel::MlKem768,
            _ => MlKemSecurityLevel::MlKem1024,
        }
    };

    // Generate keypair
    let mut rng = rand::thread_rng();
    if let Ok((pk, sk)) = MlKem::generate_keypair(&mut rng, level) {
        // Encapsulate to get shared secret and ciphertext
        if let Ok((ss1, ct)) = MlKem::encapsulate(&mut rng, &pk) {
            // Decapsulate to recover shared secret
            if let Ok(ss2) = MlKem::decapsulate(&sk, &ct) {
                // Shared secrets must match
                assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            }
        }
    }
});
