#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-DSA signing
//!
//! Tests that ML-DSA signing handles arbitrary message data
//! without crashing and produces valid signatures.

use latticearc::primitives::sig::ml_dsa::{MlDsaParameterSet, PrehashAlgorithm, generate_keypair};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Select parameter set based on first byte
    let param = match data[0] % 3 {
        0 => MlDsaParameterSet::MlDsa44,
        1 => MlDsaParameterSet::MlDsa65,
        _ => MlDsaParameterSet::MlDsa87,
    };

    // Use remaining data as message
    let message = if data.len() > 1 { &data[1..] } else { &[] };

    // Generate keypair
    let (pk, sk) = match generate_keypair(param) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test 1: Sign the fuzzed message (no context). Verify-Err on a
    // freshly-generated signature is a contract violation; panic so the
    // fuzzer surfaces it instead of accepting Err as a legitimate path.
    match sk.sign(message, &[]) {
        Ok(signature) => {
            // Verify signature has correct size
            assert_eq!(
                signature.len(),
                param.signature_size(),
                "Signature size mismatch for {:?}",
                param
            );

            // Verify signature is valid
            match pk.verify(message, &signature, &[]) {
                Ok(is_valid) => {
                    assert!(is_valid, "Valid signature must verify");
                }
                Err(e) => panic!("verify error on fresh ML-DSA signature ({param:?}): {e}"),
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
        match sk.sign(message, &context) {
            Ok(signature) => {
                // Verify with same context
                match pk.verify(message, &signature, &context) {
                    Ok(is_valid) => {
                        assert!(is_valid, "Signature with context must verify");
                    }
                    Err(e) => panic!(
                        "verify error on fresh ML-DSA signature with context ({param:?}): {e}"
                    ),
                }

                // Verify with different context should fail
                let wrong_context = vec![0xFFu8; context_len.saturating_add(1) % 256];
                if wrong_context != context {
                    match pk.verify(message, &signature, &wrong_context) {
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
    if let Ok(sig) = sk.sign(&[], &[]) {
        match pk.verify(&[], &sig, &[]) {
            Ok(is_valid) => {
                assert!(is_valid, "Empty message signature must verify");
            }
            Err(_) => {}
        }
    }

    // Test 4: Large message signing (if enough fuzz data)
    if data.len() >= 1000 {
        if let Ok(sig) = sk.sign(data, &[]) {
            match pk.verify(data, &sig, &[]) {
                Ok(is_valid) => {
                    assert!(is_valid, "Large message signature must verify");
                }
                Err(_) => {}
            }
        }
    }

    // Test 5: HashML-DSA (pre-hashed) mode. The fuzz input doubles as the
    // digest (first 64 bytes, zero-padded) and the context (next up to 255
    // bytes). Arbitrary digest bytes are valid input — the signer never sees
    // the content — so a fresh signature must verify under the same
    // (digest, hash, context) and must not verify under the plain mode, a
    // different context, or a different hash with the same digest length.
    let mut digest64 = [0u8; 64];
    let take = data.len().min(64);
    digest64[..take].copy_from_slice(&data[..take]);
    let ph_ctx_len = 1 + (data.get(64).copied().unwrap_or(0) as usize) % 255;
    let ph_context: Vec<u8> = data.iter().skip(65).cycle().take(ph_ctx_len).copied().collect();
    let ph_context = if ph_context.is_empty() { vec![0x01] } else { ph_context };
    for hash in [PrehashAlgorithm::Sha512, PrehashAlgorithm::Shake256] {
        match sk.sign_prehashed(&digest64, hash, &ph_context) {
            Ok(sig) => {
                assert_eq!(sig.len(), param.signature_size());
                assert!(
                    pk.verify_prehashed(&digest64, hash, &sig, &ph_context)
                        .expect("fresh HashML-DSA signature must verify without error"),
                    "HashML-DSA signature must verify"
                );
                let other_hash = match hash {
                    PrehashAlgorithm::Sha512 => PrehashAlgorithm::Shake256,
                    _ => PrehashAlgorithm::Sha512,
                };
                assert!(
                    !pk.verify_prehashed(&digest64, other_hash, &sig, &ph_context)
                        .expect("verify runs"),
                    "different pre-hash OID must not verify"
                );
                let mut wrong_ctx = ph_context.clone();
                wrong_ctx[0] ^= 0xff;
                assert!(
                    !pk.verify_prehashed(&digest64, hash, &sig, &wrong_ctx).expect("verify runs"),
                    "different context must not verify"
                );
                assert!(
                    !pk.verify(&digest64, &sig, &ph_context).expect("verify runs"),
                    "HashML-DSA signature must not verify as pure ML-DSA"
                );
            }
            Err(e) => panic!("HashML-DSA sign failed on valid input ({param:?}, {hash:?}): {e}"),
        }
    }
    // Empty context and wrong digest length must be rejected, never panic.
    assert!(sk.sign_prehashed(&digest64, PrehashAlgorithm::Sha512, &[]).is_err());
    assert!(sk.sign_prehashed(&digest64[..32], PrehashAlgorithm::Sha512, &ph_context).is_err());
    // 32-byte pre-hashes are only permitted at ML-DSA-44.
    let digest32 = &digest64[..32];
    let allowed = PrehashAlgorithm::Sha256.is_permitted_for(param);
    assert_eq!(
        sk.sign_prehashed(digest32, PrehashAlgorithm::Sha256, &ph_context).is_ok(),
        allowed,
        "SHA-256 pre-hash permission must follow the FIPS 204 strength floor"
    );
});
