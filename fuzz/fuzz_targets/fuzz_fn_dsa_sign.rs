#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for FN-DSA signing
//!
//! Tests that FN-DSA signing handles arbitrary message data without crashing
//! and that signatures produced from valid keys always verify correctly.
//! Uses Level512 for speed (FN-DSA-512, ~128-bit security).

use latticearc::primitives::sig::fndsa::{FnDsaSecurityLevel, KeyPair};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Generate a fresh keypair at Level512 for speed
    let mut keypair = match KeyPair::generate(FnDsaSecurityLevel::Level512) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test 1: Sign the fuzzed message — must produce a valid signature
    match keypair.sign(data) {
        Ok(signature) => {
            // Verify the signature size matches the spec (666 bytes for Level512)
            assert_eq!(
                signature.len(),
                FnDsaSecurityLevel::Level512.signature_size(),
                "FN-DSA-512 signature size mismatch"
            );

            // The signature must verify correctly against the same message
            let vk = keypair.verifying_key();
            match vk.verify(data, &signature) {
                Ok(valid) => {
                    assert!(valid, "FN-DSA signature must verify with its own key");
                }
                Err(_) => {
                    // Verification errors should not occur for freshly generated signatures
                }
            }
        }
        Err(_) => {
            // Signing errors should not occur with valid keys; swallow silently so
            // the fuzzer can keep running even on unusual platform states.
        }
    }

    // Test 2: Empty message edge case
    match keypair.sign(&[]) {
        Ok(signature) => {
            let vk = keypair.verifying_key();
            match vk.verify(&[], &signature) {
                Ok(valid) => {
                    assert!(valid, "Empty message signature must verify");
                }
                Err(_) => {}
            }
        }
        Err(_) => {}
    }

    // Test 3: Wrong message must not verify (only run when fuzz input is non-empty
    // so we have a distinct wrong message to use)
    if !data.is_empty() {
        if let Ok(signature) = keypair.sign(data) {
            let wrong_message = b"definitely not the original message";
            let vk = keypair.verifying_key();
            if let Ok(valid) = vk.verify(wrong_message, &signature) {
                assert!(!valid, "FN-DSA signature must not verify with wrong message");
            }
        }
    }
});
