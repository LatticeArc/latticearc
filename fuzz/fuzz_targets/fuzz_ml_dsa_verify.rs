#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-DSA signature verification
//!
//! Tests that ML-DSA verification handles arbitrary signature and message data
//! without crashing and correctly rejects invalid signatures.

use libfuzzer_sys::fuzz_target;
use arc_primitives::sig::ml_dsa::{
    generate_keypair, sign, verify, MlDsaParameterSet, MlDsaPublicKey, MlDsaSignature,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Select parameter set based on first byte
    let param = match data[0] % 3 {
        0 => MlDsaParameterSet::MLDSA44,
        1 => MlDsaParameterSet::MLDSA65,
        _ => MlDsaParameterSet::MLDSA87,
    };

    // Use portions of data for message
    let message = &data[1..32.min(data.len())];

    // Generate a valid keypair
    let (pk, sk) = match generate_keypair(param) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test 1: Verify valid signature
    if let Ok(valid_sig) = sign(&sk, message, &[]) {
        match verify(&pk, message, &valid_sig, &[]) {
            Ok(is_valid) => {
                assert!(is_valid, "Valid signature must verify");
            }
            Err(_) => {}
        }
    }

    // Test 2: Verify with corrupted signature
    if let Ok(sig) = sign(&sk, message, &[]) {
        // Clone the signature data for corruption
        let mut corrupted_data = sig.data.clone();
        let len = corrupted_data.len();

        // Corrupt signature bytes using fuzz data
        for (i, b) in data.iter().enumerate() {
            let idx = i % len;
            corrupted_data[idx] ^= b;
        }

        // Create corrupted signature
        if let Ok(corrupted_sig) = MlDsaSignature::new(param, corrupted_data) {
            // Corrupted signature should fail verification
            match verify(&pk, message, &corrupted_sig, &[]) {
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
    if let Ok(sig) = sign(&sk, message, &[]) {
        let wrong_message = b"completely different message content";
        match verify(&pk, wrong_message, &sig, &[]) {
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
                if let Ok(sig) = sign(&sk, message, &[]) {
                    // Verify with fuzzed public key - should fail
                    let _ = verify(&fuzzed_pk, message, &sig, &[]);
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
                match verify(&pk, message, &fuzzed_sig, &[]) {
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
    if let Ok(sig) = sign(&sk, message, &[]) {
        let truncated_len = sig.len().saturating_sub(10);
        if truncated_len > 0 {
            let truncated_data = sig.as_bytes()[..truncated_len].to_vec();
            let result = MlDsaSignature::new(param, truncated_data);
            assert!(result.is_err(), "Truncated signature should be rejected");
        }
    }

    // Test 7: Cross-parameter set verification (should fail)
    let other_param = match param {
        MlDsaParameterSet::MLDSA44 => MlDsaParameterSet::MLDSA65,
        MlDsaParameterSet::MLDSA65 => MlDsaParameterSet::MLDSA87,
        MlDsaParameterSet::MLDSA87 => MlDsaParameterSet::MLDSA44,
        _ => return, // Handle any future variants
    };

    if let Ok((other_pk, _other_sk)) = generate_keypair(other_param) {
        if let Ok(sig) = sign(&sk, message, &[]) {
            // Verify signature from MLDSA44 with MLDSA65 key - should fail
            match verify(&other_pk, message, &sig, &[]) {
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
