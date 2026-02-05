#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-DSA signing
//!
//! Tests that ML-DSA signing handles arbitrary message data
//! without crashing and produces valid signatures.

use libfuzzer_sys::fuzz_target;
use arc_primitives::sig::ml_dsa::{generate_keypair, sign, verify, MlDsaParameterSet};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Select parameter set based on first byte
    let param = match data[0] % 3 {
        0 => MlDsaParameterSet::MLDSA44,
        1 => MlDsaParameterSet::MLDSA65,
        _ => MlDsaParameterSet::MLDSA87,
    };

    // Use remaining data as message
    let message = if data.len() > 1 { &data[1..] } else { &[] };

    // Generate keypair
    let (pk, sk) = match generate_keypair(param) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test 1: Sign the fuzzed message (no context)
    match sign(&sk, message, &[]) {
        Ok(signature) => {
            // Verify signature has correct size
            assert_eq!(
                signature.len(),
                param.signature_size(),
                "Signature size mismatch for {:?}",
                param
            );

            // Verify signature is valid
            match verify(&pk, message, &signature, &[]) {
                Ok(is_valid) => {
                    assert!(is_valid, "Valid signature must verify");
                }
                Err(_) => {
                    // Verification error - should not happen for valid sig
                }
            }
        }
        Err(_) => {
            // Signing failure - should not happen with valid key
        }
    }

    // Test 2: Sign with context (max 255 bytes)
    let context_len = (data.get(0).copied().unwrap_or(0) as usize) % 256;
    let context: Vec<u8> = data.iter().cycle().take(context_len).copied().collect();

    if context.len() <= 255 {
        match sign(&sk, message, &context) {
            Ok(signature) => {
                // Verify with same context
                match verify(&pk, message, &signature, &context) {
                    Ok(is_valid) => {
                        assert!(is_valid, "Signature with context must verify");
                    }
                    Err(_) => {}
                }

                // Verify with different context should fail
                let wrong_context = vec![0xFFu8; context_len.saturating_add(1) % 256];
                if wrong_context != context {
                    match verify(&pk, message, &signature, &wrong_context) {
                        Ok(is_valid) => {
                            assert!(!is_valid, "Signature must fail with wrong context");
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        }
    }

    // Test 3: Empty message signing
    if let Ok(sig) = sign(&sk, &[], &[]) {
        match verify(&pk, &[], &sig, &[]) {
            Ok(is_valid) => {
                assert!(is_valid, "Empty message signature must verify");
            }
            Err(_) => {}
        }
    }

    // Test 4: Large message signing (if enough fuzz data)
    if data.len() >= 1000 {
        if let Ok(sig) = sign(&sk, data, &[]) {
            match verify(&pk, data, &sig, &[]) {
                Ok(is_valid) => {
                    assert!(is_valid, "Large message signature must verify");
                }
                Err(_) => {}
            }
        }
    }
});
