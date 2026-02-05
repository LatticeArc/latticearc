#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for digital signatures
//!
//! Tests that sign/verify roundtrip correctly with arbitrary message data.

use libfuzzer_sys::fuzz_target;
use arc_core::{sign, verify, CryptoConfig};

fuzz_target!(|data: &[u8]| {
    // Need at least some data to sign
    if data.is_empty() {
        return;
    }

    // Use default crypto config for fuzzing
    let config = CryptoConfig::default();

    // Test signing (generates keypair internally)
    if let Ok(signed) = sign(data, config.clone()) {
        // Test verification
        if let Ok(valid) = verify(&signed, config) {
            // Signature of correct message should verify
            assert!(valid);
        }
    }
});
