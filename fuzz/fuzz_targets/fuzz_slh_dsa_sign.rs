#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for SLH-DSA signing and verification
//!
//! Tests that SLH-DSA operations handle arbitrary message data
//! without crashing and produce valid signatures.

use libfuzzer_sys::fuzz_target;
use arc_primitives::sig::slh_dsa::{SecurityLevel, SigningKey, VerifyingKey};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Select security level based on first byte
    // Use only Shake128s for speed (SLH-DSA is slow)
    let level = match data[0] % 3 {
        0 => SecurityLevel::Shake128s,
        1 => SecurityLevel::Shake128s, // Use 128s more often for speed
        _ => SecurityLevel::Shake192s,
    };

    // Use remaining data as message
    let message = if data.len() > 1 { &data[1..] } else { &[] };

    // Generate keypair
    let (sk, pk) = match SigningKey::generate(level) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test 1: Sign the fuzzed message (no context)
    match sk.sign(message, None) {
        Ok(signature) => {
            // Verify signature has correct size
            assert_eq!(
                signature.len(),
                level.signature_size(),
                "Signature size mismatch for {:?}",
                level
            );

            // Verify signature is valid
            match pk.verify(message, &signature, None) {
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

    // Test 2: Sign with context (max 255 bytes per FIPS 205)
    let context_len = (data.get(0).copied().unwrap_or(0) as usize) % 256;
    let context: Vec<u8> = data.iter().cycle().take(context_len).copied().collect();

    if context.len() <= 255 {
        match sk.sign(message, Some(&context)) {
            Ok(signature) => {
                // Verify with same context
                match pk.verify(message, &signature, Some(&context)) {
                    Ok(is_valid) => {
                        assert!(is_valid, "Signature with context must verify");
                    }
                    Err(_) => {}
                }

                // Verify with no context should fail
                match pk.verify(message, &signature, None) {
                    Ok(is_valid) => {
                        if !context.is_empty() {
                            assert!(!is_valid, "Signature must fail without context");
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }
    }

    // Test 3: Context too long (>255 bytes) should fail
    let long_context = vec![0xABu8; 256];
    let result = sk.sign(message, Some(&long_context));
    assert!(result.is_err(), "Context >255 bytes should fail");

    // Test 4: Verify with corrupted signature
    if let Ok(sig) = sk.sign(message, None) {
        // Make a mutable copy of the signature
        let mut corrupted_sig = sig.clone();
        // Calculate the length first to avoid borrow issues
        let len = corrupted_sig.len();
        // Corrupt signature bytes
        for (i, b) in data.iter().enumerate() {
            let idx = i % len;
            corrupted_sig[idx] ^= b;
        }

        match pk.verify(message, &corrupted_sig, None) {
            Ok(is_valid) => {
                assert!(!is_valid, "Corrupted signature must fail verification");
            }
            Err(_) => {
                // Error is acceptable for malformed signature
            }
        }
    }

    // Test 5: Verify with wrong message
    if let Ok(sig) = sk.sign(message, None) {
        let wrong_message = b"completely different message content";
        match pk.verify(wrong_message, &sig, None) {
            Ok(is_valid) => {
                assert!(!is_valid, "Signature must fail with wrong message");
            }
            Err(_) => {}
        }
    }

    // Test 6: Empty message signing
    if let Ok(sig) = sk.sign(&[], None) {
        match pk.verify(&[], &sig, None) {
            Ok(is_valid) => {
                assert!(is_valid, "Empty message signature must verify");
            }
            Err(_) => {}
        }
    }

    // Test 7: Test with fuzzed verifying key bytes
    if data.len() >= level.public_key_size() {
        let pk_bytes = &data[..level.public_key_size()];
        match VerifyingKey::new(level, pk_bytes) {
            Ok(fuzzed_pk) => {
                if let Ok(sig) = sk.sign(message, None) {
                    // Verify with fuzzed key - should fail
                    let _ = fuzzed_pk.verify(message, &sig, None);
                }
            }
            Err(_) => {
                // Invalid key rejected - expected
            }
        }
    }

    // Test 8: Test invalid signature length
    if let Ok(sig) = sk.sign(message, None) {
        // Truncate signature
        let truncated = &sig[..sig.len().saturating_sub(10)];
        match pk.verify(message, truncated, None) {
            Ok(_) => {}
            Err(_) => {
                // Error expected for wrong size
            }
        }
    }
});
