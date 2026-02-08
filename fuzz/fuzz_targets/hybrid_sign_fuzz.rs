#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for digital signatures
//!
//! Tests that sign_with_key/verify roundtrip correctly with arbitrary message data.

use libfuzzer_sys::fuzz_target;
use arc_core::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};

fuzz_target!(|data: &[u8]| {
    // Need at least some data to sign
    if data.is_empty() {
        return;
    }

    // Use default crypto config for fuzzing
    let config = CryptoConfig::default();

    // Generate a keypair, then sign with it
    if let Ok((pk, sk, _scheme)) = generate_signing_keypair(config.clone()) {
        if let Ok(signed) = sign_with_key(data, &sk, &pk, config.clone()) {
            // Test verification
            if let Ok(valid) = verify(&signed, config) {
                // Signature of correct message should verify
                assert!(valid);
            }
        }
    }
});
