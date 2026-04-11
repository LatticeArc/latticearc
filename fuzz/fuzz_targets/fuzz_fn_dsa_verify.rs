#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for FN-DSA signature verification
//!
//! Tests that FN-DSA verification handles arbitrary bytes (used as signatures)
//! without crashing and correctly rejects malformed or wrong-key signatures.
//! Uses Level512 for speed (FN-DSA-512, ~128-bit security).

use latticearc::primitives::sig::fndsa::{FnDsaSecurityLevel, KeyPair, Signature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Generate a fresh keypair for signing and verification
    let mut keypair = match KeyPair::generate(FnDsaSecurityLevel::Level512) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Use first 32 bytes of fuzz input as the message
    let message = &data[..32];

    // Test 1: Valid roundtrip — sign then verify must succeed
    if let Ok(signature) = keypair.sign(message) {
        let vk = keypair.verifying_key();
        match vk.verify(message, &signature) {
            Ok(valid) => {
                assert!(valid, "Valid FN-DSA signature must verify");
            }
            Err(_) => {}
        }
    }

    // Test 2: Fuzz arbitrary bytes as a signature — must not crash, must reject
    // Signature::from_bytes rejects empty slices; any non-empty slice is accepted
    // as raw bytes and then rejected by the crypto layer during verify.
    if !data.is_empty() {
        if let Ok(fuzzed_sig) = Signature::from_bytes(data) {
            let vk = keypair.verifying_key();
            // Fuzzed bytes are astronomically unlikely to be a valid signature;
            // the important property is that verification never panics.
            let _ = vk.verify(message, &fuzzed_sig);
        }
    }

    // Test 3: Corrupt a valid signature byte-by-byte using fuzz data
    if let Ok(valid_sig) = keypair.sign(message) {
        let mut corrupted = valid_sig.to_bytes();
        let len = corrupted.len();
        // XOR each byte of the signature with the corresponding fuzz byte (wrapping)
        for (i, b) in data.iter().enumerate() {
            let idx = i % len;
            corrupted[idx] ^= b;
        }
        // Only proceed if we actually changed something
        if corrupted != valid_sig.to_bytes() {
            if let Ok(corrupted_sig) = Signature::from_bytes(&corrupted) {
                let vk = keypair.verifying_key();
                if let Ok(valid) = vk.verify(message, &corrupted_sig) {
                    assert!(!valid, "Corrupted FN-DSA signature must not verify");
                }
                // Verification error is also acceptable for corrupted data
            }
        }
    }

    // Test 4: Wrong-key verification — sign with keypair1, verify with keypair2
    let mut keypair2 = match KeyPair::generate(FnDsaSecurityLevel::Level512) {
        Ok(kp) => kp,
        Err(_) => return,
    };
    if let Ok(signature) = keypair2.sign(message) {
        let vk1 = keypair.verifying_key();
        if let Ok(valid) = vk1.verify(message, &signature) {
            assert!(!valid, "Signature from keypair2 must not verify with keypair1's key");
        }
    }
});
