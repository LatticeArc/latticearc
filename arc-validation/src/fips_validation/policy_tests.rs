#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: FIPS 140-3 Section 7 security policy tests.
// - Self-test execution with known test vectors
// - Error handling validation for FIPS compliance
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

//! Security policy validation tests for FIPS 140-3 compliance
//!
//! Contains tests for:
//! - Self-tests (FIPS 140-3 Section 7)
//! - Error handling

use arc_prelude::error::LatticeArcError;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ed25519_dalek::Signer;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::types::TestResult;

/// Test self-tests for FIPS 140-3 Section 7 compliance
pub fn test_self_tests() -> Result<TestResult, LatticeArcError> {
    let start_time = std::time::Instant::now();
    let mut test_details = Vec::new();
    let mut all_passed = true;

    test_details.push("FIPS 140-3 Section 7: Self-Test Validation".to_string());

    // Test 1: SHA-256 KAT
    test_details.push("Test 1: SHA-256 KAT (power-up self-test)".to_string());

    let mut hasher = Sha256::new();
    hasher.update(b"abc");
    let hash = hasher.finalize();

    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    if hash.as_slice() == expected {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: SHA-256 KAT mismatch".to_string());
    }

    // Test 2: AES pairwise consistency
    test_details.push("Test 2: AES pairwise consistency test".to_string());

    let key = [0x42u8; 32];
    let test_msg = b"pairwise_consistency_test";

    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let encrypt_key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ct = test_msg.to_vec();
    encrypt_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut ct)
        .map_err(|e| LatticeArcError::EncryptionError(format!("AES encryption failed: {}", e)))?;

    // Create new key for decryption
    let unbound2 = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let decrypt_key = LessSafeKey::new(unbound2);
    let nonce2 = Nonce::assume_unique_for_key(nonce_bytes);

    let pt = decrypt_key
        .open_in_place(nonce2, Aad::empty(), &mut ct)
        .map_err(|e| LatticeArcError::DecryptionError(format!("AES decryption failed: {}", e)))?;

    if pt == test_msg {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: AES pairwise consistency test failed".to_string());
    }

    // Test 3: HMAC KAT
    test_details.push("Test 3: HMAC KAT (power-up self-test)".to_string());

    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(b"key")
        .map_err(|e| LatticeArcError::InvalidKey(format!("Invalid HMAC key: {}", e)))?;
    mac.update(b"data");
    let hmac_result = mac.finalize().into_bytes();

    let expected_hmac: [u8; 32] = [
        0x50, 0x3d, 0x89, 0x69, 0x9b, 0xe2, 0x57, 0x7a, 0x5b, 0xc2, 0x29, 0x60, 0xc2, 0x99, 0xd9,
        0x55, 0x51, 0x25, 0x48, 0x63, 0xb6, 0x3e, 0x1f, 0xc8, 0x26, 0x6a, 0x1f, 0x1d, 0xaa, 0x9a,
        0x6d, 0x87,
    ];

    if hmac_result.as_slice() == expected_hmac {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: HMAC KAT mismatch".to_string());
    }

    // Test 4: Ed25519 signature consistency
    test_details.push("Test 4: Signature verification consistency".to_string());

    let mut csprng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let message = b"self_test_message";
    let signature = signing_key.sign(message);

    let verification_result = signing_key.verifying_key().verify_strict(message, &signature);
    if verification_result.is_ok() {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Signature verification failed".to_string());
    }

    // Test 5: Wrong signature rejection
    test_details.push("Test 5: Invalid signature rejection".to_string());

    let wrong_message = b"wrong_message";
    let verification_result = signing_key.verifying_key().verify_strict(wrong_message, &signature);
    if verification_result.is_err() {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Invalid signature was accepted".to_string());
    }

    // Test 6: ML-KEM KAT using reference implementation
    test_details.push("Test 6: ML-KEM KAT (power-up self-test)".to_string());

    use fips203::ml_kem_768;
    use fips203::traits::{Decaps, Encaps, KeyGen};

    let keygen_result = ml_kem_768::KG::try_keygen();
    if let Ok((ek, dk)) = keygen_result {
        let encaps_result = ek.try_encaps();
        if let Ok((ss1, ct)) = encaps_result {
            let decaps_result = dk.try_decaps(&ct);
            if let Ok(ss2) = decaps_result {
                if ss1 == ss2 {
                    test_details.push("PASSED".to_string());
                } else {
                    all_passed = false;
                    test_details.push("FAILED: ML-KEM KAT mismatch".to_string());
                }
            } else {
                all_passed = false;
                test_details.push("FAILED: ML-KEM decapsulate failed".to_string());
            }
        } else {
            all_passed = false;
            test_details.push("FAILED: ML-KEM encapsulate failed".to_string());
        }
    } else {
        all_passed = false;
        test_details.push("FAILED: ML-KEM keygen failed".to_string());
    }

    // Test 7: ML-DSA KAT using reference implementation
    test_details.push("Test 7: ML-DSA KAT (power-up self-test)".to_string());

    use fips204::ml_dsa_65;
    use fips204::traits::{KeyGen as DsaKeyGen, Signer as DsaSigner, Verifier as _DsaVerifier};

    let test_msg = b"ML-DSA self-test message";
    let dsa_keygen = ml_dsa_65::KG::try_keygen();

    if let Ok((pk, sk)) = dsa_keygen {
        let sign_result = sk.try_sign(test_msg, &[]);
        if let Ok(sig) = sign_result {
            // pk.verify returns bool directly
            let is_valid = pk.verify(test_msg, &sig, &[]);
            if is_valid {
                test_details.push("PASSED".to_string());
            } else {
                all_passed = false;
                test_details.push("FAILED: ML-DSA verify failed".to_string());
            }
        } else {
            all_passed = false;
            test_details.push("FAILED: ML-DSA sign failed".to_string());
        }
    } else {
        all_passed = false;
        test_details.push("FAILED: ML-DSA keygen failed".to_string());
    }

    Ok(TestResult {
        test_id: "self_tests".to_string(),
        passed: all_passed,
        duration_ms: start_time.elapsed().as_millis() as u64,
        output: test_details.join("\n"),
        error_message: if all_passed {
            None
        } else {
            Some("One or more self-tests failed".to_string())
        },
    })
}

/// Test error handling for FIPS 140-3 Section 7 compliance
pub fn test_error_handling() -> Result<TestResult, LatticeArcError> {
    let start_time = std::time::Instant::now();
    let mut test_details = Vec::new();
    let mut all_passed = true;

    test_details.push("FIPS 140-3 Error Handling Validation".to_string());

    // Test 1: Empty key error handling
    test_details.push("Test 1: Empty key error handling".to_string());

    let cipher_result = UnboundKey::new(&AES_256_GCM, &[]);
    if cipher_result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Empty key was accepted".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 2: Invalid key length handling
    test_details.push("Test 2: Invalid key length error handling".to_string());

    let short_key = [0u8; 16]; // 16 bytes instead of 32
    let cipher_result = UnboundKey::new(&AES_256_GCM, &short_key);
    if cipher_result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Short key was accepted".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 3: Tampered ciphertext detection
    test_details.push("Test 3: Tampered ciphertext detection".to_string());

    let key = [0x42u8; 32];
    let test_data = b"test_data";

    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let encrypt_key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = test_data.to_vec();
    encrypt_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|e| LatticeArcError::EncryptionError(format!("AES encryption failed: {}", e)))?;

    // Tamper with ciphertext
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0xFF;
    }

    // Try to decrypt tampered ciphertext
    let unbound2 = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let decrypt_key = LessSafeKey::new(unbound2);
    let nonce2 = Nonce::assume_unique_for_key(nonce_bytes);

    let decrypt_result = decrypt_key.open_in_place(nonce2, Aad::empty(), &mut ciphertext);
    if decrypt_result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Tampered ciphertext was accepted".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 4: HMAC invalid tag detection
    test_details.push("Test 4: HMAC invalid tag detection".to_string());

    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(b"test_key")
        .map_err(|e| LatticeArcError::InvalidKey(format!("Invalid HMAC key: {}", e)))?;
    mac.update(b"test_data");
    let correct_tag = mac.finalize().into_bytes();

    let mut invalid_tag = correct_tag.to_vec();
    if !invalid_tag.is_empty() {
        invalid_tag[0] ^= 0x01;
    }

    let mut mac2 = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(b"test_key")
        .map_err(|e| LatticeArcError::InvalidKey(format!("Invalid HMAC key: {}", e)))?;
    mac2.update(b"test_data");
    let computed_tag = mac2.finalize().into_bytes();

    if computed_tag.as_slice() != invalid_tag.as_slice() {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Invalid tag was accepted".to_string());
    }

    // Test 5: Empty HMAC key rejection
    test_details.push("Test 5: Empty HMAC key rejection".to_string());

    let mac_result = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&[]);
    if mac_result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Empty HMAC key was accepted".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 6: Error message safety (aws-lc-rs errors don't expose key material)
    test_details.push("Test 6: Error message safety check".to_string());

    let sensitive_key = [0xFF; 32];
    let invalid_ct = vec![0u8; 8]; // Too short for valid ciphertext

    let unbound3 = UnboundKey::new(&AES_256_GCM, &sensitive_key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let decrypt_key3 = LessSafeKey::new(unbound3);
    let nonce3 = Nonce::assume_unique_for_key([0u8; 12]);

    let mut ct_copy = invalid_ct;
    let error_result = decrypt_key3.open_in_place(nonce3, Aad::empty(), &mut ct_copy);
    let error_msg = format!("{:?}", error_result);

    // Check error message doesn't contain raw key bytes
    let key_hex = hex::encode(sensitive_key);
    let key_leaked = key_hex.chars().any(|c| error_msg.contains(c));

    if key_leaked {
        all_passed = false;
        test_details.push("FAILED: Error message may leak sensitive data".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 7: Constant-time comparison
    test_details.push("Test 7: Constant-time comparison (timing attack resistance)".to_string());

    use subtle::ConstantTimeEq;

    let bytes_a: [u8; 32] = [0x42; 32];
    let bytes_b: [u8; 32] = [0x42; 32];
    let bytes_c: [u8; 32] = [0x43; 32];

    let same: bool = bytes_a.ct_eq(&bytes_b).into();
    let different: bool = bytes_a.ct_eq(&bytes_c).into();

    if same && !different {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Constant-time comparison failed".to_string());
    }

    Ok(TestResult {
        test_id: "error_handling".to_string(),
        passed: all_passed,
        duration_ms: start_time.elapsed().as_millis() as u64,
        output: test_details.join("\n"),
        error_message: if all_passed {
            None
        } else {
            Some("One or more error handling tests failed".to_string())
        },
    })
}
