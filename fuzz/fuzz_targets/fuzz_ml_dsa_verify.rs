#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-DSA signature verification
//!
//! Tests that ML-DSA verification handles arbitrary signature and message data
//! without crashing and correctly rejects invalid signatures.

use latticearc::primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaPublicKey, MlDsaSignature, generate_keypair,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Select parameter set based on first byte
    let param = match data[0] % 3 {
        0 => MlDsaParameterSet::MlDsa44,
        1 => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    };

    // Use portions of data for message
    let message = &data[1..32.min(data.len())];

    // Generate a valid keypair
    let (pk, sk) = match generate_keypair(param) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test 1: Verify valid signature
    if let Ok(valid_sig) = sk.sign(message, &[]) {
        match pk.verify(message, &valid_sig, &[]) {
            Ok(is_valid) => {
                assert!(is_valid, "Valid signature must verify");
            }
            Err(_) => {}
        }
    }

    // Test 2: Verify with corrupted signature
    if let Ok(sig) = sk.sign(message, &[]) {
        // Clone the signature data for corruption
        let original_sig_bytes = sig.as_bytes().to_vec();
        let mut corrupted_data = original_sig_bytes.clone();
        let len = corrupted_data.len();

        // Corrupt signature bytes using fuzz data
        for (i, b) in data.iter().enumerate() {
            let idx = i % len;
            corrupted_data[idx] ^= b;
        }

        // Round-11 audit fix (MEDIUM #19 prior): the XOR can collapse to
        // a no-op when `data` is empty or all-zero — both are common
        // libfuzzer corpus seeds. Skip the assertion in that case rather
        // than panic on a still-valid signature. Without this guard, the
        // harness produces false-positive crashes that mask real findings.
        if corrupted_data == original_sig_bytes {
            return;
        }

        // Create corrupted signature
        if let Ok(corrupted_sig) = MlDsaSignature::new(param, corrupted_data) {
            // Corrupted signature should fail verification
            match pk.verify(message, &corrupted_sig, &[]) {
                Ok(is_valid) => {
                    assert!(!is_valid, "Corrupted signature must fail verification");
                }
                Err(_) => {
                    // Error is also acceptable for malformed signature
                }
            }
        }
    }

    // Test 3: Verify with wrong message
    if let Ok(sig) = sk.sign(message, &[]) {
        let wrong_message = b"completely different message content";
        match pk.verify(wrong_message, &sig, &[]) {
            Ok(is_valid) => {
                assert!(!is_valid, "Signature must fail with wrong message");
            }
            Err(_) => {}
        }
    }

    // Test 4: Verify with fuzzed public key bytes
    if data.len() >= param.public_key_size() {
        let pk_bytes = &data[..param.public_key_size()];
        match MlDsaPublicKey::new(param, pk_bytes.to_vec()) {
            Ok(fuzzed_pk) => {
                // Create a valid signature for the message
                if let Ok(sig) = sk.sign(message, &[]) {
                    // Verify with fuzzed public key - should fail
                    let _ = fuzzed_pk.verify(message, &sig, &[]);
                    // No assertion - may crash, error, or return false
                }
            }
            Err(_) => {
                // Invalid public key rejected - expected
            }
        }
    }

    // Test 5: Verify with fuzzed signature bytes
    if data.len() >= param.signature_size() {
        let sig_bytes = &data[..param.signature_size()];
        match MlDsaSignature::new(param, sig_bytes.to_vec()) {
            Ok(fuzzed_sig) => {
                // Verify fuzzed signature - should fail
                match pk.verify(message, &fuzzed_sig, &[]) {
                    Ok(is_valid) => {
                        // Fuzzed signature should almost certainly be invalid
                        // (astronomically unlikely to be valid)
                        let _ = is_valid;
                    }
                    Err(_) => {
                        // Error is acceptable for malformed data
                    }
                }
            }
            Err(_) => {
                // Invalid signature format rejected - expected
            }
        }
    }

    // Test 6: Verify with truncated signature
    if let Ok(sig) = sk.sign(message, &[]) {
        let truncated_len = sig.len().saturating_sub(10);
        if truncated_len > 0 {
            let truncated_data = sig.as_bytes()[..truncated_len].to_vec();
            let result = MlDsaSignature::new(param, truncated_data);
            assert!(result.is_err(), "Truncated signature should be rejected");
        }
    }

    // Test 7: Cross-parameter set verification (should fail)
    let other_param = match param {
        MlDsaParameterSet::MlDsa44 => MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa65 => MlDsaParameterSet::MlDsa87,
        MlDsaParameterSet::MlDsa87 => MlDsaParameterSet::MlDsa44,
        _ => return, // Handle any future variants
    };

    if let Ok((other_pk, _other_sk)) = generate_keypair(other_param) {
        if let Ok(sig) = sk.sign(message, &[]) {
            // Verify signature from MlDsa44 with MlDsa65 key - should fail
            match other_pk.verify(message, &sig, &[]) {
                Ok(is_valid) => {
                    assert!(!is_valid, "Cross-parameter verification must fail");
                }
                Err(_) => {
                    // Error is expected for parameter mismatch
                }
            }
        }
    }
});
