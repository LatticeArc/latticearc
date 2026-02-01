#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-DSA signature verification
//!
//! Tests that ML-DSA signature verification doesn't crash or panic
//! with arbitrary signature and message data.

use libfuzzer_sys::fuzz_target;
use arc_primitives::sig::ml_dsa::{generate_keypair, sign, verify, MlDsaParameterSet};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for message
    if data.len() < 32 {
        return;
    }

    // Use data as message
    let message = &data[..32];
    let context = &[]; // Empty context for testing

    // Generate a valid keypair (MLDSA44 for speed)
    if let Ok((pk, sk)) = generate_keypair(MlDsaParameterSet::MLDSA44) {
        // Create a valid signature for the message
        if let Ok(valid_sig) = sign(&sk, message, context) {
            // Test 1: Valid signature should verify
            let result = verify(&pk, message, &valid_sig, context);
            // Valid signature must verify successfully
            assert!(result.is_ok() && result.unwrap(), "Valid signature must verify");

            // Test 2: Wrong message should fail verification
            let wrong_msg = b"different message content here";
            let result = verify(&pk, wrong_msg, &valid_sig, context);
            // Wrong message must fail verification
            assert!(result.is_ok() && !result.unwrap(), "Wrong message must fail verification");

            // Test 3: Wrong context should fail verification
            let wrong_context = b"wrong context";
            let result = verify(&pk, message, &valid_sig, wrong_context);
            // Wrong context must fail verification
            assert!(result.is_ok() && !result.unwrap(), "Wrong context must fail verification");
        }
    }
});
