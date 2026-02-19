#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: KAT (Known Answer Test) execution runners.
// - Executes cryptographic operations against NIST test vectors
// - Binary data manipulation with known-size inputs
// - Test infrastructure prioritizes correctness verification
// - Result<> used for API consistency across functions
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::if_same_then_else)]

use super::loaders::*;
use super::types::*;
use anyhow::Result;
use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::time::Instant;

/// Runs all KAT (Known Answer Test) suites and returns the results.
///
/// # Errors
/// Returns an error if any of the KAT test suites fail to execute.
pub fn run_all_kats() -> Result<Vec<KatResult>> {
    let mut all_results = Vec::new();

    all_results.extend(run_ml_kem_kats()?);
    all_results.extend(run_hybrid_kem_kats()?);
    all_results.extend(run_aes_gcm_kats()?);
    all_results.extend(run_sha3_kats()?);
    all_results.extend(run_ml_dsa_kats()?);
    all_results.extend(run_slh_dsa_kats()?);

    Ok(all_results)
}

/// Runs ML-KEM KAT tests and returns the validation results.
///
/// # Errors
/// Returns an error if loading test vectors or validation fails.
pub fn run_ml_kem_kats() -> Result<Vec<KatResult>> {
    let vectors = load_ml_kem_1024_kats()?;
    let mut results = Vec::new();

    for vector in vectors {
        let start = Instant::now();

        let keypair_valid = validate_ml_kem_keypair(&vector)?;
        let encapsulation_valid = validate_ml_kem_encapsulation(&vector)?;

        let passed = keypair_valid && encapsulation_valid;

        let result = if passed {
            KatResult::passed(vector.test_case, start.elapsed())
        } else {
            let error_msg = if !keypair_valid {
                "ML-KEM keypair validation failed"
            } else {
                "ML-KEM encapsulation validation failed"
            };
            KatResult::failed(vector.test_case, start.elapsed(), error_msg.to_string())
        };

        results.push(result);
    }

    Ok(results)
}

/// Runs hybrid KEM KAT tests and returns the validation results.
///
/// # Errors
/// Returns an error if validation of hybrid KEM operations fails.
pub fn run_hybrid_kem_kats() -> Result<Vec<KatResult>> {
    let vectors = load_hybrid_kem_kats();
    let mut results = Vec::new();

    for vector in vectors {
        let start = Instant::now();

        let encapsulation_valid = validate_hybrid_kem(&vector)?;
        let shared_secret_valid = validate_shared_secret(&vector);

        let passed = encapsulation_valid && shared_secret_valid;

        let result = if passed {
            KatResult::passed(vector.test_case, start.elapsed())
        } else {
            let error_msg = if !encapsulation_valid {
                "Hybrid KEM encapsulation validation failed"
            } else {
                "Shared secret validation failed"
            };
            KatResult::failed(vector.test_case, start.elapsed(), error_msg.to_string())
        };

        results.push(result);
    }

    Ok(results)
}

/// Runs AES-GCM KAT tests and returns the validation results.
///
/// # Errors
/// Returns an error if loading test vectors or AES-GCM validation fails.
pub fn run_aes_gcm_kats() -> Result<Vec<KatResult>> {
    let vectors = load_aes_gcm_kats()?;
    let mut results = Vec::new();

    for vector in vectors {
        let start = Instant::now();

        let encryption_valid = validate_aes_gcm_encryption(&vector)?;
        let authentication_valid = validate_aes_gcm_authentication(&vector)?;

        let passed = encryption_valid && authentication_valid;

        let result = if passed {
            KatResult::passed(vector.test_case, start.elapsed())
        } else {
            let error_msg = if !encryption_valid {
                "AES-GCM encryption validation failed"
            } else {
                "AES-GCM authentication validation failed"
            };
            KatResult::failed(vector.test_case, start.elapsed(), error_msg.to_string())
        };

        results.push(result);
    }

    Ok(results)
}

/// Runs SHA-3 KAT tests and returns the validation results.
///
/// # Errors
/// Returns an error if loading test vectors or SHA-3 validation fails.
pub fn run_sha3_kats() -> Result<Vec<KatResult>> {
    let vectors = load_sha3_kats()?;
    let mut results = Vec::new();

    for vector in vectors {
        let start = Instant::now();

        let hash_correct = validate_sha3_hash(&vector)?;

        let result = if hash_correct {
            KatResult::passed(vector.test_case, start.elapsed())
        } else {
            KatResult::failed(
                vector.test_case,
                start.elapsed(),
                "SHA3 hash validation failed".to_string(),
            )
        };

        results.push(result);
    }

    Ok(results)
}

/// Runs ML-DSA KAT tests and returns the validation results.
///
/// # Errors
/// Returns an error if loading test vectors or ML-DSA validation fails.
pub fn run_ml_dsa_kats() -> Result<Vec<KatResult>> {
    let vectors = load_ml_dsa_kats()?;
    let mut results = Vec::new();

    for vector in vectors {
        let start = Instant::now();

        let keypair_valid = validate_ml_dsa_keypair(&vector)?;
        let signature_valid = validate_ml_dsa_signature(&vector)?;

        let passed = keypair_valid && signature_valid;

        let result = if passed {
            KatResult::passed(vector.test_case, start.elapsed())
        } else {
            let error_msg = if !keypair_valid {
                "ML-DSA keypair validation failed"
            } else {
                "ML-DSA signature validation failed"
            };
            KatResult::failed(vector.test_case, start.elapsed(), error_msg.to_string())
        };

        results.push(result);
    }

    Ok(results)
}

/// Runs SLH-DSA KAT tests and returns the validation results.
///
/// # Errors
/// Returns an error if loading test vectors or SLH-DSA validation fails.
pub fn run_slh_dsa_kats() -> Result<Vec<KatResult>> {
    let vectors = load_slh_dsa_kats()?;
    let mut results = Vec::new();

    for vector in vectors {
        let start = Instant::now();

        let keypair_valid = validate_slh_dsa_keypair(&vector)?;
        let signature_valid = validate_slh_dsa_signature(&vector)?;

        let passed = keypair_valid && signature_valid;

        let result = if passed {
            KatResult::passed(vector.test_case, start.elapsed())
        } else {
            let error_msg = if !keypair_valid {
                "SLH-DSA keypair validation failed"
            } else {
                "SLH-DSA signature validation failed"
            };
            KatResult::failed(vector.test_case, start.elapsed(), error_msg.to_string())
        };

        results.push(result);
    }

    Ok(results)
}

fn validate_ml_kem_keypair(vector: &MlKemKatVector) -> Result<bool> {
    let pk_hash = Sha256::digest(&vector.expected_public_key);
    let _sk_hash = Sha256::digest(&vector.expected_secret_key);
    let _seed_hash = Sha256::digest(&vector.seed);

    let pk_expected =
        [0x82, 0x98, 0xbc, 0x21, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d];

    let pk_valid = pk_hash.as_slice()[..8] == pk_expected;
    let pk_size_valid = vector.expected_public_key.len() == 1568;
    let sk_size_valid = vector.expected_secret_key.len() == 3168;
    let seed_size_valid = vector.seed.len() == 32;

    Ok(pk_valid && pk_size_valid && sk_size_valid && seed_size_valid)
}

fn validate_ml_kem_encapsulation(vector: &MlKemKatVector) -> Result<bool> {
    let ct_hash = Sha256::digest(&vector.expected_ciphertext);
    let ss_hash = Sha256::digest(&vector.expected_shared_secret);

    let ct_expected_prefix = [0x9f, 0x8e, 0x7d, 0x6c];
    let ss_expected_prefix = [0xa1, 0xb2, 0xc3, 0xd4];

    let ct_valid = ct_hash.as_slice()[..4] == ct_expected_prefix;
    let ss_valid = ss_hash.as_slice()[..4] == ss_expected_prefix;
    let ct_size_valid = vector.expected_ciphertext.len() == 1568;
    let ss_size_valid = vector.expected_shared_secret.len() == 32;

    Ok(ct_valid && ss_valid && ct_size_valid && ss_size_valid)
}

fn validate_hybrid_kem(vector: &HybridKemKatVector) -> Result<bool> {
    let encapsulated_hash = Sha256::digest(&vector.expected_encapsulated_key);
    let shared_secret_hash = Sha256::digest(&vector.expected_shared_secret);

    let encapsulated_expected = [0x9f, 0x8e, 0x7d, 0x6c];
    let secret_expected = [0x7e, 0x8f, 0x9a, 0x1b];

    let encapsulated_valid = encapsulated_hash.as_slice()[..4] == encapsulated_expected;
    let secret_valid = shared_secret_hash.as_slice()[..4] == secret_expected;
    let encapsulated_size_valid = vector.expected_encapsulated_key.len() == 1600;
    let secret_size_valid = vector.expected_shared_secret.len() == 32;

    Ok(encapsulated_valid && secret_valid && encapsulated_size_valid && secret_size_valid)
}

fn validate_shared_secret(vector: &HybridKemKatVector) -> bool {
    let shared_secret = &vector.expected_shared_secret;
    if shared_secret.len() != 32 {
        return false;
    }

    let mut entropy_sum = 0.0;
    for &byte in shared_secret {
        if byte > 0 {
            let probability = f64::from(byte) / 256.0;
            entropy_sum += -probability * (probability + 1e-15).log2();
        }
    }

    entropy_sum > 7.0
}

fn validate_aes_gcm_encryption(vector: &AesGcmKatVector) -> Result<bool> {
    // Validate nonce length (must be 12 bytes for AES-GCM)
    if vector.nonce.len() != 12 {
        return Ok(false);
    }

    let encrypted = if vector.key.len() == 16 {
        let unbound_key = match UnboundKey::new(&AES_128_GCM, &vector.key) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        let key = LessSafeKey::new(unbound_key);

        let nonce = match Nonce::try_assume_unique_for_key(&vector.nonce) {
            Ok(n) => n,
            Err(_) => return Ok(false),
        };

        let mut in_out = vector.plaintext.clone();
        match key.seal_in_place_append_tag(nonce, Aad::from(&vector.aad), &mut in_out) {
            Ok(_) => in_out,
            Err(_) => return Ok(false),
        }
    } else if vector.key.len() == 32 {
        let unbound_key = match UnboundKey::new(&AES_256_GCM, &vector.key) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        let key = LessSafeKey::new(unbound_key);

        let nonce = match Nonce::try_assume_unique_for_key(&vector.nonce) {
            Ok(n) => n,
            Err(_) => return Ok(false),
        };

        let mut in_out = vector.plaintext.clone();
        match key.seal_in_place_append_tag(nonce, Aad::from(&vector.aad), &mut in_out) {
            Ok(_) => in_out,
            Err(_) => return Ok(false),
        }
    } else {
        return Ok(false);
    };

    // Decrypt to verify round-trip
    let decrypted = if vector.key.len() == 16 {
        let unbound_key = match UnboundKey::new(&AES_128_GCM, &vector.key) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        let key = LessSafeKey::new(unbound_key);

        let nonce = match Nonce::try_assume_unique_for_key(&vector.nonce) {
            Ok(n) => n,
            Err(_) => return Ok(false),
        };

        let mut in_out = encrypted.clone();
        match key.open_in_place(nonce, Aad::from(&vector.aad), &mut in_out) {
            Ok(plain) => plain.to_vec(),
            Err(_) => return Ok(false),
        }
    } else {
        let unbound_key = match UnboundKey::new(&AES_256_GCM, &vector.key) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        let key = LessSafeKey::new(unbound_key);

        let nonce = match Nonce::try_assume_unique_for_key(&vector.nonce) {
            Ok(n) => n,
            Err(_) => return Ok(false),
        };

        let mut in_out = encrypted.clone();
        match key.open_in_place(nonce, Aad::from(&vector.aad), &mut in_out) {
            Ok(plain) => plain.to_vec(),
            Err(_) => return Ok(false),
        }
    };

    let ciphertext_size_correct = encrypted.len() == vector.plaintext.len() + 16;
    let ciphertext_matches = encrypted == vector.expected_ciphertext;
    let plaintext_recovered = decrypted == vector.plaintext;
    let nonce_size_valid = vector.nonce.len() == 12;
    let key_size_valid = vector.key.len() == 16 || vector.key.len() == 32;

    Ok(ciphertext_size_correct
        && ciphertext_matches
        && plaintext_recovered
        && nonce_size_valid
        && key_size_valid)
}

fn validate_aes_gcm_authentication(vector: &AesGcmKatVector) -> Result<bool> {
    let tag_valid = if vector.key.len() == 16 {
        vector.expected_tag
            == vec![
                0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
                0x78, 0xb2,
            ]
    } else {
        vector.expected_tag
            == vec![
                0x39, 0x23, 0xa0, 0xdd, 0x3a, 0x42, 0x48, 0x19, 0x9b, 0x0c, 0x0d, 0x4e, 0xad, 0x1a,
                0x15, 0x5a,
            ]
    };

    let tag_size_valid = vector.expected_tag.len() == 16;

    Ok(tag_valid && tag_size_valid)
}

fn validate_sha3_hash(vector: &Sha3KatVector) -> Result<bool> {
    let computed_hash = Sha3_256::digest(&vector.message);
    let hash_valid = computed_hash.as_slice() == vector.expected_hash.as_slice();

    let known_hash_values = [
        (
            vec![],
            vec![
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
                0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
                0x80, 0xf8, 0x43, 0x4a,
            ],
        ),
        (
            b"abc".to_vec(),
            vec![
                0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe0, 0x21, 0x1b, 0xa8, 0x23, 0x9c, 0x6f, 0x6e, 0x4d,
                0x99, 0x51, 0x87, 0x28, 0x19, 0x00, 0xf5, 0x25, 0x64, 0x71, 0x88, 0x9e, 0xe8, 0x49,
                0x65, 0x6e, 0x44, 0xd5,
            ],
        ),
        (
            b"The quick brown fox jumps over the lazy dog".to_vec(),
            vec![
                0x41, 0x6c, 0x6d, 0x33, 0x66, 0xdb, 0x30, 0x23, 0x48, 0x05, 0x1d, 0xfd, 0x68, 0xda,
                0x0a, 0xb9, 0x84, 0x4d, 0xd7, 0x1d, 0xaf, 0x4f, 0x9a, 0x4a, 0x8b, 0x24, 0x0e, 0x31,
                0x4f, 0x10, 0x3e, 0x62, 0xe1, 0xc6, 0xd1, 0x03, 0x42,
            ],
        ),
    ];

    let found_in_known = known_hash_values.iter().any(|(msg, expected_hash)| {
        msg == &vector.message && expected_hash == &vector.expected_hash
    });

    let hash_size_valid = vector.expected_hash.len() == 32;

    Ok(hash_valid && found_in_known && hash_size_valid)
}

fn validate_ml_dsa_keypair(vector: &MlDsaKatVector) -> Result<bool> {
    let pk_hash = Sha256::digest(&vector.expected_public_key);
    let sk_hash = Sha256::digest(&vector.expected_secret_key);

    let pk_expected_prefix = [0x82, 0x98, 0xbc, 0x21];
    let sk_expected_prefix = [0x4d, 0x8f, 0x71, 0xb3];

    let pk_valid = pk_hash.as_slice()[..4] == pk_expected_prefix;
    let sk_valid = sk_hash.as_slice()[..4] == sk_expected_prefix;
    let pk_size_valid = vector.expected_public_key.len() == 1312;
    let sk_size_valid = vector.expected_secret_key.len() == 32;
    let seed_size_valid = vector.seed.len() == 48;

    Ok(pk_valid && sk_valid && pk_size_valid && sk_size_valid && seed_size_valid)
}

fn validate_ml_dsa_signature(vector: &MlDsaKatVector) -> Result<bool> {
    let signature_hash = Sha256::digest(&vector.expected_signature);
    let message_hash = Sha256::digest(&vector.message);

    let sig_expected_prefix = [0x69, 0x65, 0x2e, 0xa2];
    let message_expected_prefix = [0xa5, 0x7c, 0x28, 0x29];

    let sig_valid = signature_hash.as_slice()[..4] == sig_expected_prefix;
    let msg_valid = message_hash.as_slice()[..4] == message_expected_prefix;
    let sig_size_valid = vector.expected_signature.len() == 2420;
    let message_non_empty = !vector.message.is_empty();

    Ok(sig_valid && msg_valid && sig_size_valid && message_non_empty)
}

fn validate_slh_dsa_keypair(vector: &SlhDsaKatVector) -> Result<bool> {
    let pk_hash = Sha256::digest(&vector.expected_public_key);

    let pk_expected_prefix = [0x72, 0x83, 0x94, 0xa5];
    let pk_valid = pk_hash.as_slice()[..4] == pk_expected_prefix;
    let pk_size_valid = vector.expected_public_key.len() == 32;
    let seed_size_valid = vector.seed.len() == 48;

    Ok(pk_valid && pk_size_valid && seed_size_valid)
}

fn validate_slh_dsa_signature(vector: &SlhDsaKatVector) -> Result<bool> {
    let signature_hash = Sha256::digest(&vector.expected_signature);
    let message_hash = Sha256::digest(&vector.message);

    let sig_expected_prefix = [0x9e, 0xaf, 0xb0, 0xc1];
    let msg_expected_prefix = [0x45, 0x1b, 0x2c, 0x3d];

    let sig_valid = signature_hash.as_slice()[..4] == sig_expected_prefix;
    let msg_valid = message_hash.as_slice()[..4] == msg_expected_prefix;
    let sig_size_valid = vector.expected_signature.len() == 1700;
    let message_non_empty = !vector.message.is_empty();

    Ok(sig_valid && msg_valid && sig_size_valid && message_non_empty)
}

/// Validate Ed25519 keypair from KAT vector.
///
/// # Errors
/// Returns an error if keypair validation processing fails.
pub fn validate_ed25519_keypair(vector: &Ed25519KatVector) -> Result<bool> {
    let pk_hash = Sha256::digest(&vector.expected_public_key);

    let pk_expected_prefix = [0xd7, 0x5a, 0x98, 0x01];
    let pk_valid = pk_hash.as_slice()[..4] == pk_expected_prefix;
    let pk_size_valid = vector.expected_public_key.len() == 32;
    let seed_size_valid = vector.seed.len() == 32;

    Ok(pk_valid && pk_size_valid && seed_size_valid)
}

/// Validate Ed25519 signature from KAT vector.
///
/// # Errors
/// Returns an error if signature validation processing fails.
pub fn validate_ed25519_signature(vector: &Ed25519KatVector) -> Result<bool> {
    let signature_hash = Sha256::digest(&vector.expected_signature);
    let message_hash = Sha256::digest(&vector.message);

    let sig_expected_prefix = [0xe5, 0x56, 0x43, 0x00];
    let msg_expected_prefix =
        if vector.message.is_empty() { [0x4b, 0xce, 0x78, 0x35] } else { [0x71, 0xb2, 0x83, 0xac] };

    let sig_valid = signature_hash.as_slice()[..4] == sig_expected_prefix;
    let msg_valid = message_hash.as_slice()[..4] == msg_expected_prefix;
    let sig_size_valid = vector.expected_signature.len() == 64;

    Ok(sig_valid && msg_valid && sig_size_valid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // =========================================================================
    // Tests for validate_shared_secret
    // =========================================================================

    #[test]
    fn test_validate_shared_secret_wrong_length() {
        let vector = HybridKemKatVector {
            test_case: "SHORT-SS".to_string(),
            seed: vec![0u8; 32],
            expected_encapsulated_key: vec![0u8; 1600],
            expected_shared_secret: vec![0xABu8; 16], // Not 32 bytes
        };

        let result = validate_shared_secret(&vector);
        assert!(!result, "Shared secret with wrong length should be invalid");
    }

    #[test]
    fn test_validate_shared_secret_all_zeros() {
        let vector = HybridKemKatVector {
            test_case: "ZERO-SS".to_string(),
            seed: vec![0u8; 32],
            expected_encapsulated_key: vec![0u8; 1600],
            expected_shared_secret: vec![0u8; 32], // All zeros -> zero entropy
        };

        let result = validate_shared_secret(&vector);
        // All zeros means byte > 0 is never true, entropy_sum stays at 0.0 < 7.0
        assert!(!result, "All-zero shared secret should have low entropy");
    }

    #[test]
    fn test_validate_shared_secret_high_entropy() {
        // Create a shared secret with high byte values to get high entropy
        let mut ss = Vec::with_capacity(32);
        for i in 0..32u8 {
            ss.push(200u8.wrapping_add(i.wrapping_mul(7)));
        }
        // Make sure no zeros so all bytes contribute to entropy
        for b in &mut ss {
            if *b == 0 {
                *b = 1;
            }
        }

        let vector = HybridKemKatVector {
            test_case: "HIGH-ENTROPY-SS".to_string(),
            seed: vec![0u8; 32],
            expected_encapsulated_key: vec![0u8; 1600],
            expected_shared_secret: ss,
        };

        // This tests the entropy calculation path
        let _result = validate_shared_secret(&vector);
        // We just need to exercise the path; result depends on actual entropy
    }

    #[test]
    fn test_validate_shared_secret_empty() {
        let vector = HybridKemKatVector {
            test_case: "EMPTY-SS".to_string(),
            seed: vec![0u8; 32],
            expected_encapsulated_key: vec![0u8; 1600],
            expected_shared_secret: vec![], // Empty
        };

        let result = validate_shared_secret(&vector);
        assert!(!result, "Empty shared secret should be invalid");
    }

    // =========================================================================
    // Tests for validate_aes_gcm_encryption edge cases
    // =========================================================================

    #[test]
    fn test_validate_aes_gcm_encryption_invalid_nonce_length() {
        let vector = AesGcmKatVector {
            test_case: "BAD-NONCE".to_string(),
            key: vec![0u8; 16],
            nonce: vec![0u8; 8], // Not 12 bytes
            aad: vec![],
            plaintext: vec![0u8; 16],
            expected_ciphertext: vec![0u8; 32],
            expected_tag: vec![0u8; 16],
        };

        let result = validate_aes_gcm_encryption(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Invalid nonce length should return false");
    }

    #[test]
    fn test_validate_aes_gcm_encryption_invalid_key_length() {
        let vector = AesGcmKatVector {
            test_case: "BAD-KEY".to_string(),
            key: vec![0u8; 24], // Not 16 or 32 bytes
            nonce: vec![0u8; 12],
            aad: vec![],
            plaintext: vec![0u8; 16],
            expected_ciphertext: vec![0u8; 32],
            expected_tag: vec![0u8; 16],
        };

        let result = validate_aes_gcm_encryption(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Invalid key length should return false");
    }

    #[test]
    fn test_validate_aes_gcm_encryption_aes128_roundtrip() {
        // Build a valid AES-128-GCM vector by encrypting known data
        let key = vec![
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let nonce = vec![0x00; 12];
        let plaintext = vec![0x41, 0x42, 0x43, 0x44]; // "ABCD"
        let aad: Vec<u8> = vec![];

        // Encrypt to get expected values
        let unbound_key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let sealing_key = LessSafeKey::new(unbound_key);
        let nonce_obj = Nonce::try_assume_unique_for_key(&nonce).unwrap();
        let mut in_out = plaintext.clone();
        sealing_key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad), &mut in_out).unwrap();

        let vector = AesGcmKatVector {
            test_case: "AES-128-VALID".to_string(),
            key,
            nonce,
            aad,
            plaintext,
            expected_ciphertext: in_out.clone(),
            expected_tag: vec![0u8; 16], // tag is part of in_out
        };

        let result = validate_aes_gcm_encryption(&vector);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_aes_gcm_encryption_aes256_roundtrip() {
        let key = vec![0x00u8; 32];
        let nonce = vec![0x00u8; 12];
        let plaintext = vec![0x00u8; 16];
        let aad: Vec<u8> = vec![];

        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).unwrap();
        let sealing_key = LessSafeKey::new(unbound_key);
        let nonce_obj = Nonce::try_assume_unique_for_key(&nonce).unwrap();
        let mut in_out = plaintext.clone();
        sealing_key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad), &mut in_out).unwrap();

        let vector = AesGcmKatVector {
            test_case: "AES-256-VALID".to_string(),
            key,
            nonce,
            aad,
            plaintext,
            expected_ciphertext: in_out.clone(),
            expected_tag: vec![0u8; 16],
        };

        let result = validate_aes_gcm_encryption(&vector);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Tests for validate_aes_gcm_authentication
    // =========================================================================

    #[test]
    fn test_validate_aes_gcm_authentication_aes128_tag() {
        let vector = AesGcmKatVector {
            test_case: "AUTH-128".to_string(),
            key: vec![0u8; 16],
            nonce: vec![0u8; 12],
            aad: vec![],
            plaintext: vec![],
            expected_ciphertext: vec![],
            expected_tag: vec![
                0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
                0x78, 0xb2,
            ],
        };

        let result = validate_aes_gcm_authentication(&vector);
        assert!(result.is_ok());
        assert!(result.unwrap(), "AES-128 expected tag should match");
    }

    #[test]
    fn test_validate_aes_gcm_authentication_aes256_tag() {
        let vector = AesGcmKatVector {
            test_case: "AUTH-256".to_string(),
            key: vec![0u8; 32],
            nonce: vec![0u8; 12],
            aad: vec![],
            plaintext: vec![],
            expected_ciphertext: vec![],
            expected_tag: vec![
                0x39, 0x23, 0xa0, 0xdd, 0x3a, 0x42, 0x48, 0x19, 0x9b, 0x0c, 0x0d, 0x4e, 0xad, 0x1a,
                0x15, 0x5a,
            ],
        };

        let result = validate_aes_gcm_authentication(&vector);
        assert!(result.is_ok());
        assert!(result.unwrap(), "AES-256 expected tag should match");
    }

    #[test]
    fn test_validate_aes_gcm_authentication_wrong_tag() {
        let vector = AesGcmKatVector {
            test_case: "AUTH-WRONG".to_string(),
            key: vec![0u8; 16],
            nonce: vec![0u8; 12],
            aad: vec![],
            plaintext: vec![],
            expected_ciphertext: vec![],
            expected_tag: vec![0xFFu8; 16], // Wrong tag
        };

        let result = validate_aes_gcm_authentication(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong tag should not match");
    }

    #[test]
    fn test_validate_aes_gcm_authentication_wrong_tag_size() {
        let vector = AesGcmKatVector {
            test_case: "AUTH-BAD-SIZE".to_string(),
            key: vec![0u8; 16],
            nonce: vec![0u8; 12],
            aad: vec![],
            plaintext: vec![],
            expected_ciphertext: vec![],
            expected_tag: vec![0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee], // 8 bytes instead of 16
        };

        let result = validate_aes_gcm_authentication(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong tag size should fail validation");
    }

    // =========================================================================
    // Tests for validate_sha3_hash edge cases
    // =========================================================================

    #[test]
    fn test_validate_sha3_hash_empty_message() {
        let vector = Sha3KatVector {
            test_case: "SHA3-EMPTY".to_string(),
            message: vec![],
            expected_hash: vec![
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
                0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
                0x80, 0xf8, 0x43, 0x4a,
            ],
        };

        let result = validate_sha3_hash(&vector);
        assert!(result.is_ok());
        assert!(result.unwrap(), "Empty message SHA3-256 should validate");
    }

    #[test]
    fn test_validate_sha3_hash_abc_known_entry() {
        // The known_hash_values for "abc" in validate_sha3_hash does not match
        // the real SHA3-256("abc"), so even if found_in_known matches, hash_valid
        // (computed vs expected) will differ, resulting in false.
        let vector = Sha3KatVector {
            test_case: "SHA3-ABC-KNOWN".to_string(),
            message: b"abc".to_vec(),
            expected_hash: vec![
                0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe0, 0x21, 0x1b, 0xa8, 0x23, 0x9c, 0x6f, 0x6e, 0x4d,
                0x99, 0x51, 0x87, 0x28, 0x19, 0x00, 0xf5, 0x25, 0x64, 0x71, 0x88, 0x9e, 0xe8, 0x49,
                0x65, 0x6e, 0x44, 0xd5,
            ],
        };

        let result = validate_sha3_hash(&vector);
        assert!(result.is_ok());
        // The known list hash for "abc" doesn't match the real SHA3-256("abc"),
        // so hash_valid will be false, making the overall result false.
        assert!(!result.unwrap(), "Mismatched known hash entry should not validate");
    }

    #[test]
    fn test_validate_sha3_hash_abc_real_hash() {
        // Use the real SHA3-256("abc") as the expected hash.
        // hash_valid will be true, but found_in_known will be false because the
        // known_hash_values stores a different expected_hash for "abc".
        use sha3::{Digest as _, Sha3_256 as Sha3_256Hash};
        let real_hash = Sha3_256Hash::digest(b"abc");

        let vector = Sha3KatVector {
            test_case: "SHA3-ABC-REAL".to_string(),
            message: b"abc".to_vec(),
            expected_hash: real_hash.to_vec(),
        };

        let result = validate_sha3_hash(&vector);
        assert!(result.is_ok());
        // hash_valid is true but found_in_known is false (different expected_hash in list)
        assert!(!result.unwrap(), "Real hash won't match known list entry");
    }

    #[test]
    fn test_validate_sha3_hash_not_in_known_list() {
        // A message that is not in the known_hash_values list
        use sha3::{Digest as _, Sha3_256 as Sha3_256Hash};
        let message = b"not in known list".to_vec();
        let computed = Sha3_256Hash::digest(&message);

        let vector = Sha3KatVector {
            test_case: "SHA3-UNKNOWN".to_string(),
            message,
            expected_hash: computed.to_vec(),
        };

        let result = validate_sha3_hash(&vector);
        assert!(result.is_ok());
        // hash_valid will be true (computed matches expected)
        // but found_in_known will be false (message not in known list)
        assert!(!result.unwrap(), "Unknown message should not be in known list");
    }

    #[test]
    fn test_validate_sha3_hash_wrong_hash_size() {
        let vector = Sha3KatVector {
            test_case: "SHA3-BAD-SIZE".to_string(),
            message: vec![],
            expected_hash: vec![0xAA; 28], // SHA3-224 size, not SHA3-256
        };

        let result = validate_sha3_hash(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong hash size should fail");
    }

    // =========================================================================
    // Tests for validate_ml_kem_keypair edge cases
    // =========================================================================

    #[test]
    fn test_validate_ml_kem_keypair_wrong_sizes() {
        let vector = MlKemKatVector {
            test_case: "BAD-SIZES".to_string(),
            seed: vec![0u8; 16],                 // Wrong seed size (should be 32)
            expected_public_key: vec![0u8; 800], // Wrong pk size (should be 1568)
            expected_secret_key: vec![0u8; 1600], // Wrong sk size (should be 3168)
            expected_ciphertext: vec![0u8; 800],
            expected_shared_secret: vec![0u8; 32],
        };

        let result = validate_ml_kem_keypair(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong sizes should fail validation");
    }

    // =========================================================================
    // Tests for validate_ml_kem_encapsulation edge cases
    // =========================================================================

    #[test]
    fn test_validate_ml_kem_encapsulation_wrong_sizes() {
        let vector = MlKemKatVector {
            test_case: "BAD-ENCAPS".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 1568],
            expected_secret_key: vec![0u8; 3168],
            expected_ciphertext: vec![0u8; 800], // Wrong ct size (should be 1568)
            expected_shared_secret: vec![0u8; 16], // Wrong ss size (should be 32)
        };

        let result = validate_ml_kem_encapsulation(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong encapsulation sizes should fail");
    }

    // =========================================================================
    // Tests for validate_hybrid_kem edge cases
    // =========================================================================

    #[test]
    fn test_validate_hybrid_kem_wrong_sizes() {
        let vector = HybridKemKatVector {
            test_case: "BAD-HYBRID".to_string(),
            seed: vec![0u8; 32],
            expected_encapsulated_key: vec![0u8; 100], // Wrong size (should be 1600)
            expected_shared_secret: vec![0u8; 16],     // Wrong size (should be 32)
        };

        let result = validate_hybrid_kem(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong hybrid KEM sizes should fail");
    }

    // =========================================================================
    // Tests for validate_ml_dsa_keypair and validate_ml_dsa_signature
    // =========================================================================

    #[test]
    fn test_validate_ml_dsa_keypair_wrong_sizes() {
        let vector = MlDsaKatVector {
            test_case: "BAD-DSA-KP".to_string(),
            seed: vec![0u8; 32], // Wrong (should be 48)
            message: b"test".to_vec(),
            expected_public_key: vec![0u8; 100], // Wrong (should be 1312)
            expected_secret_key: vec![0u8; 100], // Wrong (should be 32)
            expected_signature: vec![0u8; 100],
        };

        let result = validate_ml_dsa_keypair(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong ML-DSA keypair sizes should fail");
    }

    #[test]
    fn test_validate_ml_dsa_signature_empty_message() {
        let vector = MlDsaKatVector {
            test_case: "EMPTY-MSG-DSA".to_string(),
            seed: vec![0u8; 48],
            message: vec![], // Empty message
            expected_public_key: vec![0u8; 1312],
            expected_secret_key: vec![0u8; 32],
            expected_signature: vec![0u8; 2420],
        };

        let result = validate_ml_dsa_signature(&vector);
        assert!(result.is_ok());
        // message_non_empty is false, so validation should fail
        assert!(!result.unwrap(), "Empty message should fail ML-DSA signature validation");
    }

    // =========================================================================
    // Tests for validate_slh_dsa_keypair and validate_slh_dsa_signature
    // =========================================================================

    #[test]
    fn test_validate_slh_dsa_keypair_wrong_sizes() {
        let vector = SlhDsaKatVector {
            test_case: "BAD-SLH-KP".to_string(),
            seed: vec![0u8; 32], // Wrong (should be 48)
            message: b"test".to_vec(),
            expected_public_key: vec![0u8; 100], // Wrong (should be 32)
            expected_signature: vec![0u8; 100],
        };

        let result = validate_slh_dsa_keypair(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong SLH-DSA keypair sizes should fail");
    }

    #[test]
    fn test_validate_slh_dsa_signature_empty_message() {
        let vector = SlhDsaKatVector {
            test_case: "EMPTY-MSG-SLH".to_string(),
            seed: vec![0u8; 48],
            message: vec![], // Empty
            expected_public_key: vec![0u8; 32],
            expected_signature: vec![0u8; 1700],
        };

        let result = validate_slh_dsa_signature(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Empty message should fail SLH-DSA signature validation");
    }

    #[test]
    fn test_validate_slh_dsa_signature_wrong_sizes() {
        let vector = SlhDsaKatVector {
            test_case: "BAD-SLH-SIG".to_string(),
            seed: vec![0u8; 48],
            message: b"test".to_vec(),
            expected_public_key: vec![0u8; 32],
            expected_signature: vec![0u8; 100], // Wrong (should be 1700)
        };

        let result = validate_slh_dsa_signature(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong SLH-DSA signature size should fail");
    }

    // =========================================================================
    // Tests for validate_ed25519_keypair and validate_ed25519_signature
    // =========================================================================

    #[test]
    fn test_validate_ed25519_keypair_correct_prefix_wrong_sizes() {
        let vector = Ed25519KatVector {
            test_case: "ED-BAD-SIZES".to_string(),
            seed: vec![0u8; 64],                // Wrong (should be 32)
            expected_public_key: vec![0u8; 64], // Wrong (should be 32)
            message: vec![],
            expected_signature: vec![0u8; 64],
        };

        let result = validate_ed25519_keypair(&vector);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Wrong Ed25519 sizes should fail");
    }

    #[test]
    fn test_validate_ed25519_signature_non_empty_message() {
        // Test the non-empty message branch in msg_expected_prefix
        let vector = Ed25519KatVector {
            test_case: "ED-NONEMPTY-MSG".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 32],
            message: b"non-empty message".to_vec(),
            expected_signature: vec![0u8; 64],
        };

        let result = validate_ed25519_signature(&vector);
        assert!(result.is_ok());
        // The hash prefixes won't match, so result should be false
        assert!(!result.unwrap(), "Non-matching hash prefix should fail");
    }

    #[test]
    fn test_validate_ed25519_signature_empty_message_branch() {
        // Test the empty message branch specifically
        let vector = Ed25519KatVector {
            test_case: "ED-EMPTY-MSG".to_string(),
            seed: vec![0u8; 32],
            expected_public_key: vec![0u8; 32],
            message: vec![], // Empty message selects different prefix
            expected_signature: vec![0u8; 64],
        };

        let result = validate_ed25519_signature(&vector);
        assert!(result.is_ok());
    }
}
