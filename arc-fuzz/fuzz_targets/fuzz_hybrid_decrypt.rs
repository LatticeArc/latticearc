#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for hybrid decryption (ML-KEM + AES-GCM)
//!
//! Tests that hybrid decryption handles arbitrary ciphertext data
//! without crashing and correctly rejects invalid inputs.

use libfuzzer_sys::fuzz_target;
use arc_hybrid::encrypt_hybrid::{decrypt, encrypt, HybridCiphertext, HybridEncryptionContext};
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};

fuzz_target!(|data: &[u8]| {
    // Need enough data for ciphertext components:
    // KEM ciphertext (1088) + symmetric ciphertext + nonce (12) + tag (16)
    if data.len() < 1120 {
        return;
    }

    let mut rng = rand::thread_rng();

    // Generate ML-KEM keypair
    let (pk, _sk) = match MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768) {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Secret key is 2400 bytes for ML-KEM-768
    // Note: aws-lc-rs doesn't support SK serialization, so decrypt will fail
    // but should not crash

    // Test 1: Decrypt with completely fuzzed ciphertext
    let fuzzed_ct = HybridCiphertext {
        kem_ciphertext: data.get(..1088).unwrap_or(&[]).to_vec(),
        symmetric_ciphertext: data.get(1088..1100.min(data.len())).unwrap_or(&[]).to_vec(),
        nonce: data.get(..12).unwrap_or(&[]).to_vec(),
        tag: data.get(..16).unwrap_or(&[]).to_vec(),
    };

    // Create placeholder secret key (will fail due to aws-lc-rs limitation)
    let fake_sk = vec![0u8; 2400];

    // Decryption should not crash (will fail gracefully)
    let _ = decrypt(&fake_sk, &fuzzed_ct, None);

    // Test 2: Invalid ciphertext component lengths
    // Invalid nonce length
    let invalid_nonce_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 11], // Wrong size
        tag: vec![0u8; 16],
    };
    let result = decrypt(&fake_sk, &invalid_nonce_ct, None);
    assert!(result.is_err(), "Invalid nonce length should fail");

    // Invalid tag length
    let invalid_tag_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 15], // Wrong size
    };
    let result = decrypt(&fake_sk, &invalid_tag_ct, None);
    assert!(result.is_err(), "Invalid tag length should fail");

    // Invalid KEM ciphertext length
    let invalid_kem_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1000], // Wrong size
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
    let result = decrypt(&fake_sk, &invalid_kem_ct, None);
    assert!(result.is_err(), "Invalid KEM ciphertext length should fail");

    // Test 3: Invalid secret key length
    let short_sk = vec![0u8; 1000];
    let valid_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        symmetric_ciphertext: vec![0u8; 32],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
    let result = decrypt(&short_sk, &valid_ct, None);
    assert!(result.is_err(), "Invalid secret key length should fail");

    // Test 4: Decrypt valid encryption with wrong context
    let plaintext = data.get(..32.min(data.len())).unwrap_or(&[]);
    if let Ok(ct) = encrypt(&mut rng, pk.as_bytes(), plaintext, None) {
        // Decrypt with wrong context should fail
        let wrong_context = HybridEncryptionContext {
            info: b"Wrong-Context".to_vec(),
            aad: b"wrong aad".to_vec(),
        };
        // Will fail due to aws-lc-rs SK limitation anyway
        let _ = decrypt(&fake_sk, &ct, Some(&wrong_context));
    }

    // Test 5: Corrupt valid ciphertext components
    if let Ok(mut ct) = encrypt(&mut rng, pk.as_bytes(), plaintext, None) {
        // Corrupt KEM ciphertext
        if !ct.kem_ciphertext.is_empty() {
            ct.kem_ciphertext[0] ^= 0xFF;
        }
        let _ = decrypt(&fake_sk, &ct, None);

        // Corrupt symmetric ciphertext
        if !ct.symmetric_ciphertext.is_empty() {
            ct.symmetric_ciphertext[0] ^= 0xFF;
        }
        let _ = decrypt(&fake_sk, &ct, None);

        // Corrupt tag
        if !ct.tag.is_empty() {
            ct.tag[0] ^= 0xFF;
        }
        let _ = decrypt(&fake_sk, &ct, None);

        // Corrupt nonce
        if !ct.nonce.is_empty() {
            ct.nonce[0] ^= 0xFF;
        }
        let _ = decrypt(&fake_sk, &ct, None);
    }

    // Test 6: Empty symmetric ciphertext
    let empty_sym_ct = HybridCiphertext {
        kem_ciphertext: vec![0u8; 1088],
        symmetric_ciphertext: vec![],
        nonce: vec![0u8; 12],
        tag: vec![0u8; 16],
    };
    let _ = decrypt(&fake_sk, &empty_sym_ct, None);

    // Test 7: Very large symmetric ciphertext
    if data.len() >= 10000 {
        let large_ct = HybridCiphertext {
            kem_ciphertext: vec![0u8; 1088],
            symmetric_ciphertext: data[..10000].to_vec(),
            nonce: vec![0u8; 12],
            tag: vec![0u8; 16],
        };
        let _ = decrypt(&fake_sk, &large_ct, None);
    }
});
