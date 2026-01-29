#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: FIPS 140-3 Section 4 interface validation tests.
// - API interface testing for compliance
// - Key management interface validation
// - Test infrastructure prioritizes correctness verification
// - Result<> used for API consistency across test functions
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unnecessary_wraps)]

//! Interface validation tests for FIPS 140-3 compliance
//!
//! Contains tests for:
//! - API interfaces (FIPS 140-3 Section 4)
//! - Key management interfaces

use arc_prelude::error::LatticeArcError;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use hmac::{Hmac, digest::KeyInit as HmacKeyInit};
use rand::RngCore;
use sha2::Sha256;

use super::types::TestResult;

/// Custom output length type for aws-lc-rs HKDF
struct HkdfOutputLen(usize);

impl KeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Test API interfaces for FIPS 140-3 Section 4 compliance
pub fn test_api_interfaces() -> Result<TestResult, LatticeArcError> {
    let start_time = std::time::Instant::now();
    let mut test_details = Vec::new();
    let mut all_passed = true;

    test_details.push("FIPS 140-3 Section 4: API Interface Validation".to_string());

    // Test 1: Empty key rejection
    test_details.push("Test 1: Empty key rejection".to_string());
    let result = UnboundKey::new(&AES_256_GCM, &[]);
    if result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Empty key was not rejected".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 2: Invalid key length rejection
    test_details.push("Test 2: Invalid key length rejection".to_string());
    let short_key = [0u8; 16];
    let result = UnboundKey::new(&AES_256_GCM, &short_key);
    if result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Short key was not rejected".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 3: Valid key acceptance
    test_details.push("Test 3: Valid key acceptance".to_string());
    let valid_key = [0u8; 32];
    let result = UnboundKey::new(&AES_256_GCM, &valid_key);
    if result.is_err() {
        all_passed = false;
        test_details.push("FAILED: Valid key was rejected".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 4: Invalid ciphertext error handling
    test_details.push("Test 4: Invalid ciphertext error handling".to_string());
    let unbound = UnboundKey::new(&AES_256_GCM, &valid_key)
        .map_err(|_e| LatticeArcError::InvalidInput("key creation failed".to_string()))?;
    let key = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_e| LatticeArcError::InvalidInput("nonce creation failed".to_string()))?;
    let mut invalid_ct = vec![0u8; 8];
    let result = key.open_in_place(nonce, Aad::empty(), &mut invalid_ct);
    if result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Invalid ciphertext was accepted".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 5: Nonce uniqueness
    test_details.push("Test 5: Nonce generation uniqueness".to_string());
    let mut nonce1 = [0u8; 12];
    let mut nonce2 = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce1);
    rand::thread_rng().fill_bytes(&mut nonce2);
    if nonce1 != nonce2 {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Generated identical nonces".to_string());
    }

    // Test 6: HMAC empty key rejection
    test_details.push("Test 6: HMAC empty key rejection".to_string());
    let result = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&[]);
    if result.is_ok() {
        all_passed = false;
        test_details.push("FAILED: Empty HMAC key was not rejected".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    // Test 7: HMAC valid key acceptance
    test_details.push("Test 7: HMAC valid key acceptance".to_string());
    let result = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(b"valid_key");
    if result.is_err() {
        all_passed = false;
        test_details.push("FAILED: Valid HMAC key was rejected".to_string());
    } else {
        test_details.push("PASSED".to_string());
    }

    Ok(TestResult {
        test_id: "api_interfaces".to_string(),
        passed: all_passed,
        duration_ms: start_time.elapsed().as_millis() as u64,
        output: test_details.join("\n"),
        error_message: if all_passed {
            None
        } else {
            Some("One or more API interface tests failed".to_string())
        },
    })
}

/// Test key management for FIPS 140-3 compliance
pub fn test_key_management() -> Result<TestResult, LatticeArcError> {
    let start_time = std::time::Instant::now();
    let mut test_details = Vec::new();
    let mut all_passed = true;

    test_details.push("FIPS Key Management Validation".to_string());

    // Test 1: Key generation uniqueness
    test_details.push("Test 1: Key generation uniqueness".to_string());

    let mut keys = Vec::new();
    for _ in 0..10 {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        keys.push(key);
    }

    let unique_count: std::collections::HashSet<_> = keys.iter().collect();
    if unique_count.len() == keys.len() {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Generated duplicate keys".to_string());
    }

    // Test 2: Key serialization roundtrip
    test_details.push("Test 2: Key serialization/deserialization".to_string());

    let mut csprng = rand::rngs::OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let sk_bytes = signing_key.to_bytes();

    let signing_key_restored = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
    if signing_key_restored.to_bytes() == sk_bytes {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Key serialization failed".to_string());
    }

    // Test 3: KDF determinism (NIST SP 800-108)
    test_details.push("Test 3: Key derivation (NIST SP 800-108)".to_string());

    let master_key = b"master_key_123456789";
    let salt_bytes = b"salt_12345678901234567890";
    let salt = Salt::new(HKDF_SHA256, salt_bytes);
    let prk = salt.extract(master_key);

    let mut derived_key1 = [0u8; 32];
    let mut derived_key2 = [0u8; 32];

    let okm1 = prk
        .expand(&[b"latticearc_derivation"], HkdfOutputLen(32))
        .map_err(|_e| LatticeArcError::InvalidInput("KDF failed".to_string()))?;
    okm1.fill(&mut derived_key1)
        .map_err(|_e| LatticeArcError::InvalidInput("KDF fill failed".to_string()))?;

    // Re-extract for second derivation (PRK is consumed)
    let salt2 = Salt::new(HKDF_SHA256, salt_bytes);
    let prk2 = salt2.extract(master_key);
    let okm2 = prk2
        .expand(&[b"latticearc_derivation"], HkdfOutputLen(32))
        .map_err(|_e| LatticeArcError::InvalidInput("KDF failed".to_string()))?;
    okm2.fill(&mut derived_key2)
        .map_err(|_e| LatticeArcError::InvalidInput("KDF fill failed".to_string()))?;

    if derived_key1 == derived_key2 {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: KDF not deterministic".to_string());
    }

    // Test 4: KDF domain separation
    test_details.push("Test 4: KDF domain separation".to_string());

    let salt3 = Salt::new(HKDF_SHA256, salt_bytes);
    let prk3 = salt3.extract(master_key);
    let mut derived_key3 = [0u8; 32];
    let okm3 = prk3
        .expand(&[b"different_info_label"], HkdfOutputLen(32))
        .map_err(|_e| LatticeArcError::InvalidInput("KDF failed".to_string()))?;
    okm3.fill(&mut derived_key3)
        .map_err(|_e| LatticeArcError::InvalidInput("KDF fill failed".to_string()))?;

    if derived_key1 != derived_key3 {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: Different derivations produced same key".to_string());
    }

    // Test 5: AES key usage
    test_details.push("Test 5: AES key generation and usage".to_string());

    let aes_key_bytes = [0x42u8; 32];
    let unbound = UnboundKey::new(&AES_256_GCM, &aes_key_bytes)
        .map_err(|_e| LatticeArcError::InvalidInput("key creation failed".to_string()))?;
    let key = LessSafeKey::new(unbound);
    let test_data = b"test_encryption_data";

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_e| LatticeArcError::InvalidInput("nonce creation failed".to_string()))?;

    let mut ciphertext = test_data.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|e| LatticeArcError::InvalidInput(format!("AES encryption failed: {}", e)))?;

    // Create new key for decryption (nonce consumed)
    let unbound2 = UnboundKey::new(&AES_256_GCM, &aes_key_bytes)
        .map_err(|_e| LatticeArcError::InvalidInput("key creation failed".to_string()))?;
    let key2 = LessSafeKey::new(unbound2);
    let nonce2 = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_e| LatticeArcError::InvalidInput("nonce creation failed".to_string()))?;

    let decrypted = key2
        .open_in_place(nonce2, Aad::empty(), &mut ciphertext)
        .map_err(|e| LatticeArcError::InvalidInput(format!("AES decryption failed: {}", e)))?;

    if decrypted == test_data {
        test_details.push("PASSED".to_string());
    } else {
        all_passed = false;
        test_details.push("FAILED: AES key usage failed".to_string());
    }

    Ok(TestResult {
        test_id: "key_management".to_string(),
        passed: all_passed,
        duration_ms: start_time.elapsed().as_millis() as u64,
        output: test_details.join("\n"),
        error_message: if all_passed {
            None
        } else {
            Some("One or more key management tests failed".to_string())
        },
    })
}
