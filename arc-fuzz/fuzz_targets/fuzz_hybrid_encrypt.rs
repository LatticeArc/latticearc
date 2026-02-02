#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for hybrid encryption (ML-KEM + AES-GCM)
//!
//! Tests that hybrid encryption handles arbitrary plaintext data
//! without crashing and produces valid ciphertexts.

use libfuzzer_sys::fuzz_target;
use arc_hybrid::encrypt_hybrid::{encrypt, HybridEncryptionContext};
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut rng = rand::thread_rng();

    // Use data as plaintext
    let plaintext = data;

    // Generate ML-KEM keypair for testing
    let (pk, _sk) = match MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Test 1: Encrypt with default context
    match encrypt(&mut rng, pk.as_bytes(), plaintext, None) {
        Ok(ciphertext) => {
            // Verify ciphertext components have expected sizes
            assert_eq!(
                ciphertext.kem_ciphertext.len(),
                1088,
                "KEM ciphertext must be 1088 bytes for ML-KEM-768"
            );
            assert_eq!(ciphertext.nonce.len(), 12, "Nonce must be 12 bytes");
            assert_eq!(ciphertext.tag.len(), 16, "Tag must be 16 bytes");

            // Symmetric ciphertext should match plaintext length
            assert_eq!(
                ciphertext.symmetric_ciphertext.len(),
                plaintext.len(),
                "Symmetric ciphertext length should match plaintext"
            );
        }
        Err(_) => {
            // Encryption can fail for various reasons - acceptable
        }
    }

    // Test 2: Encrypt with custom context
    let context = HybridEncryptionContext {
        info: b"Custom-Info-String".to_vec(),
        aad: data.get(..16.min(data.len())).unwrap_or(&[]).to_vec(),
    };

    match encrypt(&mut rng, pk.as_bytes(), plaintext, Some(&context)) {
        Ok(ciphertext) => {
            assert_eq!(ciphertext.kem_ciphertext.len(), 1088);
            assert_eq!(ciphertext.nonce.len(), 12);
            assert_eq!(ciphertext.tag.len(), 16);
        }
        Err(_) => {}
    }

    // Test 3: Encrypt empty plaintext
    match encrypt(&mut rng, pk.as_bytes(), &[], None) {
        Ok(ciphertext) => {
            assert!(ciphertext.symmetric_ciphertext.is_empty());
            assert_eq!(ciphertext.tag.len(), 16);
        }
        Err(_) => {}
    }

    // Test 4: Invalid public key length
    let invalid_pk = &data[..800.min(data.len())];
    if invalid_pk.len() != 1184 {
        let result = encrypt(&mut rng, invalid_pk, plaintext, None);
        assert!(result.is_err(), "Invalid public key length should fail");
    }

    // Test 5: Fuzzed public key bytes (correct length but invalid content)
    if data.len() >= 1184 {
        let fuzzed_pk = &data[..1184];
        // This may or may not fail depending on whether the fuzzed bytes
        // are a valid ML-KEM public key structure
        let _ = encrypt(&mut rng, fuzzed_pk, plaintext, None);
    }

    // Test 6: Large AAD
    let large_aad = HybridEncryptionContext {
        info: b"Large-AAD-Test".to_vec(),
        aad: data.to_vec(), // Use entire fuzz input as AAD
    };
    let _ = encrypt(&mut rng, pk.as_bytes(), plaintext, Some(&large_aad));

    // Test 7: Multiple encryptions of same plaintext should produce different results
    if let (Ok(ct1), Ok(ct2)) = (
        encrypt(&mut rng, pk.as_bytes(), plaintext, None),
        encrypt(&mut rng, pk.as_bytes(), plaintext, None),
    ) {
        // Nonces should differ (random)
        assert_ne!(ct1.nonce, ct2.nonce, "Nonces should be different for each encryption");

        // KEM ciphertexts should differ (random encapsulation)
        assert_ne!(
            ct1.kem_ciphertext, ct2.kem_ciphertext,
            "KEM ciphertexts should be different"
        );
    }
});
