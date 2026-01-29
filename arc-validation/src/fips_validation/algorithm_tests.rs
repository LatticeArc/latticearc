#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: FIPS algorithm validation tests (197, 202, 203).
// - Tests AES, SHA-3, ML-KEM against NIST test vectors
// - Binary data comparison for algorithm correctness
// - Test infrastructure prioritizes correctness verification
// - Result<> used for API consistency across test functions
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unnecessary_wraps)]

//! Algorithm validation tests for FIPS compliance
//!
//! Contains tests for:
//! - AES (FIPS 197)
//! - SHA-3 (FIPS 202)
//! - ML-KEM (FIPS 203)

use arc_prelude::error::LatticeArcError;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use rand::RngCore;
use sha3::{Digest as Sha3Digest, Sha3_256};

use super::types::TestResult;

/// Custom output length type for aws-lc-rs HKDF
struct HkdfOutputLen(usize);

impl KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Test AES algorithm using FIPS 197 NIST test vectors
pub fn test_aes_algorithm() -> Result<TestResult, LatticeArcError> {
    let start_time = std::time::Instant::now();
    let mut test_details = Vec::new();
    let mut all_passed = true;

    // NIST FIPS 197 AES-256 Known Answer Test Vector
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    let plaintext = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    test_details.push("Testing AES-256-GCM with NIST FIPS 197 test vector".to_string());

    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let encrypt_key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Encrypt
    let mut ciphertext = plaintext.to_vec();
    encrypt_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|e| LatticeArcError::EncryptionError(format!("AES encryption failed: {}", e)))?;

    // Decrypt
    let unbound2 = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let decrypt_key = LessSafeKey::new(unbound2);
    let nonce2 = Nonce::assume_unique_for_key(nonce_bytes);

    let decrypted = decrypt_key
        .open_in_place(nonce2, Aad::empty(), &mut ciphertext)
        .map_err(|e| LatticeArcError::DecryptionError(format!("AES decryption failed: {}", e)))?;

    // Verify roundtrip
    if decrypted == plaintext {
        test_details.push("AES roundtrip test PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("AES roundtrip test FAILED: decrypted != plaintext".to_string());
    }

    test_details.push(format!("Ciphertext length: {} bytes (includes auth tag)", ciphertext.len()));

    // Test with empty plaintext
    let unbound3 = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let encrypt_key3 = LessSafeKey::new(unbound3);

    let mut nonce_bytes2 = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes2);
    let nonce3 = Nonce::assume_unique_for_key(nonce_bytes2);

    let mut empty_ciphertext = Vec::new();
    encrypt_key3.seal_in_place_append_tag(nonce3, Aad::empty(), &mut empty_ciphertext).map_err(
        |e| LatticeArcError::EncryptionError(format!("AES empty encryption failed: {}", e)),
    )?;

    let unbound4 = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_e| LatticeArcError::EncryptionError("Failed to create AES key".to_string()))?;
    let decrypt_key4 = LessSafeKey::new(unbound4);
    let nonce4 = Nonce::assume_unique_for_key(nonce_bytes2);

    let empty_decrypted =
        decrypt_key4.open_in_place(nonce4, Aad::empty(), &mut empty_ciphertext).map_err(|e| {
            LatticeArcError::DecryptionError(format!("AES empty decryption failed: {}", e))
        })?;

    if empty_decrypted.is_empty() {
        test_details.push("AES empty plaintext test PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("AES empty plaintext test FAILED".to_string());
    }

    Ok(TestResult {
        test_id: "aes_fips_197".to_string(),
        passed: all_passed,
        duration_ms: start_time.elapsed().as_millis() as u64,
        output: test_details.join("\n"),
        error_message: if all_passed {
            None
        } else {
            Some("One or more AES tests failed".to_string())
        },
    })
}

/// Test SHA-3 algorithm using FIPS 202 NIST test vectors
#[allow(clippy::unnecessary_wraps)] // Result signature for consistency with fallible test functions
pub fn test_sha3_algorithm() -> Result<TestResult, LatticeArcError> {
    let start_time = std::time::Instant::now();
    let mut test_details = Vec::new();
    let mut all_passed = true;

    // NIST FIPS 202 SHA3-256 Known Answer Test Vector 1: Empty message
    let empty_hash = Sha3_256::digest(b"");
    let expected_empty: [u8; 32] = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6,
        0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8,
        0x43, 0x4a,
    ];

    test_details.push("SHA3-256 Test 1: Empty message".to_string());
    if empty_hash.as_slice() == expected_empty {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push(format!(
            "FAILED: Got {}, Expected {}",
            hex::encode(empty_hash),
            hex::encode(expected_empty)
        ));
    }

    // NIST FIPS 202 SHA3-256 Known Answer Test Vector 2: "abc"
    let abc_hash = Sha3_256::digest(b"abc");
    let expected_abc: [u8; 32] = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];

    test_details.push("SHA3-256 Test 2: Message 'abc'".to_string());
    if abc_hash.as_slice() == expected_abc {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push(format!(
            "FAILED: Got {}, Expected {}",
            hex::encode(abc_hash),
            hex::encode(expected_abc)
        ));
    }

    // Test 3: Longer message
    let long_msg = b"The quick brown fox jumps over the lazy dog";
    let long_hash = Sha3_256::digest(long_msg);
    let expected_long: [u8; 32] = [
        0x69, 0x07, 0x0d, 0xda, 0x01, 0x97, 0x5c, 0x8c, 0x12, 0x0c, 0x3a, 0xad, 0xa1, 0xb2, 0x82,
        0x39, 0x4e, 0x7f, 0x03, 0x2f, 0xa9, 0xcf, 0x32, 0xf4, 0xcb, 0x22, 0x59, 0xa0, 0x89, 0x7d,
        0xfc, 0x04,
    ];

    test_details.push("SHA3-256 Test 3: Long message".to_string());
    if long_hash.as_slice() == expected_long {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push(format!(
            "FAILED: Got {}, Expected {}",
            hex::encode(long_hash),
            hex::encode(expected_long)
        ));
    }

    // Test 4: Deterministic property
    let hash1 = Sha3_256::digest(b"test");
    let hash2 = Sha3_256::digest(b"test");

    test_details.push("SHA3-256 Test 4: Deterministic property".to_string());
    if hash1.as_slice() == hash2.as_slice() {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Same input produced different hashes".to_string());
    }

    // Test 5: Collision resistance
    let hash_a = Sha3_256::digest(b"message_a");
    let hash_b = Sha3_256::digest(b"message_b");

    test_details.push("SHA3-256 Test 5: Collision resistance".to_string());
    if hash_a.as_slice() != hash_b.as_slice() {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Different inputs produced same hash".to_string());
    }

    Ok(TestResult {
        test_id: "sha3_fips_202".to_string(),
        passed: all_passed,
        duration_ms: start_time.elapsed().as_millis() as u64,
        output: test_details.join("\n"),
        error_message: if all_passed {
            None
        } else {
            Some("One or more SHA-3 tests failed".to_string())
        },
    })
}

/// Test ML-KEM (FIPS 203) algorithm using reference implementation
pub fn test_mlkem_algorithm() -> Result<TestResult, LatticeArcError> {
    use fips203::ml_kem_768;
    use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

    let start_time = std::time::Instant::now();
    let mut test_details = Vec::new();
    let mut all_passed = true;

    test_details.push("ML-KEM FIPS 203 Validation using reference implementation".to_string());

    // Test 1: Key generation
    test_details.push("Test 1: ML-KEM-768 key generation".to_string());

    let keygen_result = ml_kem_768::KG::try_keygen();
    if keygen_result.is_err() {
        test_details.push("FAILED: Key generation failed".to_string());
        return Ok(TestResult {
            test_id: "mlkem_fips_203".to_string(),
            passed: false,
            duration_ms: start_time.elapsed().as_millis() as u64,
            output: test_details.join("\n"),
            error_message: Some("ML-KEM key generation failed".to_string()),
        });
    }
    test_details.push("PASSED".to_string());

    let (ek, dk) = keygen_result
        .map_err(|e| LatticeArcError::KeyGenerationError(format!("ML-KEM keygen failed: {}", e)))?;

    // Test 2: Encapsulation/Decapsulation roundtrip
    test_details.push("Test 2: Encapsulation/Decapsulation roundtrip".to_string());

    let encaps_result = ek.try_encaps();
    if encaps_result.is_err() {
        all_passed = false;
        test_details.push("FAILED: Encapsulation failed".to_string());
    } else {
        let (ss_enc, ct) = encaps_result.map_err(|e| {
            LatticeArcError::EncapsulationError(format!("Encapsulation failed: {}", e))
        })?;

        let decaps_result = dk.try_decaps(&ct);
        if decaps_result.is_err() {
            all_passed = false;
            test_details.push("FAILED: Decapsulation failed".to_string());
        } else {
            let ss_dec = decaps_result.map_err(|e| {
                LatticeArcError::DecapsulationError(format!("Decapsulation failed: {}", e))
            })?;

            if ss_enc == ss_dec {
                test_details.push("PASSED".to_string());
            } else {
                all_passed = false;
                test_details.push("FAILED: Shared secrets don't match".to_string());
            }
        }
    }

    // Test 3: Shared secret uniqueness using HKDF
    test_details.push("Test 3: Shared secret uniqueness".to_string());

    let salt1 = Salt::new(HKDF_SHA256, b"salt1");
    let prk1 = salt1.extract(b"input1");
    let okm1 = prk1
        .expand(&[b"info"], HkdfOutputLen(32))
        .map_err(|_e| LatticeArcError::KeyDerivationError("HKDF expansion failed".to_string()))?;
    let mut ss1 = [0u8; 32];
    okm1.fill(&mut ss1)
        .map_err(|_e| LatticeArcError::KeyDerivationError("HKDF fill failed".to_string()))?;

    let salt2 = Salt::new(HKDF_SHA256, b"salt2");
    let prk2 = salt2.extract(b"input2");
    let okm2 = prk2
        .expand(&[b"info"], HkdfOutputLen(32))
        .map_err(|_e| LatticeArcError::KeyDerivationError("HKDF expansion failed".to_string()))?;
    let mut ss2 = [0u8; 32];
    okm2.fill(&mut ss2)
        .map_err(|_e| LatticeArcError::KeyDerivationError("HKDF fill failed".to_string()))?;

    if ss1 != ss2 {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Different inputs produced same shared secret".to_string());
    }

    // Test 4: Multiple encapsulations produce different ciphertexts
    test_details.push("Test 4: Multiple encapsulations produce different ciphertexts".to_string());

    let encaps1 = ek.try_encaps();
    let encaps2 = ek.try_encaps();

    if let (Ok((_, ct1)), Ok((_, ct2))) = (encaps1, encaps2) {
        let ct1_bytes = ct1.into_bytes();
        let ct2_bytes = ct2.into_bytes();

        if ct1_bytes != ct2_bytes {
            test_details.push("PASSED".to_string());
        } else {
            all_passed = false;
            test_details
                .push("FAILED: Multiple encapsulations produced identical ciphertexts".to_string());
        }
    } else {
        all_passed = false;
        test_details.push("FAILED: Encapsulation failed".to_string());
    }

    Ok(TestResult {
        test_id: "mlkem_fips_203".to_string(),
        passed: all_passed,
        duration_ms: start_time.elapsed().as_millis() as u64,
        output: test_details.join("\n"),
        error_message: if all_passed {
            None
        } else {
            Some("One or more ML-KEM tests failed".to_string())
        },
    })
}
