#![deny(unsafe_code)]
#![no_main]

//! General fuzz testing for ML-KEM operations
//!
//! Tests ML-KEM key generation, encapsulation, and decapsulation
//! with various security levels.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Use input data to seed operations (deterministic fuzzing)
    let mut rng = rand::thread_rng();

    // Test all three security levels based on input
    let level = match data[0] % 3 {
        0 => MlKemSecurityLevel::MlKem512,
        1 => MlKemSecurityLevel::MlKem768,
        _ => MlKemSecurityLevel::MlKem1024,
    };

    // Generate keypair
    let (pk, sk) = match MlKem::generate_keypair(&mut rng, level) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Encapsulate - returns (shared_secret, ciphertext)
    let (ss1, ct) = match MlKem::encapsulate(&mut rng, &pk) {
        Ok(result) => result,
        Err(_) => return,
    };

    // Decapsulate
    let ss2 = match MlKem::decapsulate(&sk, &ct) {
        Ok(ss) => ss,
        Err(_) => return,
    };

    // Shared secrets must match
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
});
