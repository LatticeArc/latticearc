#![deny(unsafe_code)]
// Test files use unwrap() and expect() for simplicity - test failures will show clear panics
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![deny(clippy::panic)]

//! Comprehensive Performance Benchmark Tests for LatticeArc
//!
//! This module contains 45+ tests covering:
//! - Cryptographic Operation Benchmarks (15+ tests)
//! - Throughput Tests (10+ tests)
//! - Memory Usage Tests (10+ tests)
//! - Scalability Tests (10+ tests)
//!
//! Note: Tests validate operations complete within reasonable bounds,
//! not exact timing (timing varies by hardware). Assertions use bounds
//! like "completes in under N seconds" rather than exact benchmarks.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use arc_perf::{Histogram, MetricsCollector, Timer, benchmark, time_operation};

// ============================================================================
// TEST HELPER FUNCTIONS
// ============================================================================

/// Maximum time allowed for single cryptographic operations (generous for CI)
const MAX_SINGLE_OP_TIME: Duration = Duration::from_secs(10);

/// Maximum time allowed for bulk operations
const MAX_BULK_OP_TIME: Duration = Duration::from_secs(30);

/// Maximum time allowed for large message operations
const MAX_LARGE_MSG_TIME: Duration = Duration::from_secs(60);

/// Helper to run an operation and verify it completes within a time bound
fn timed_operation<F, R>(name: &str, max_duration: Duration, operation: F) -> R
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = operation();
    let elapsed = start.elapsed();

    assert!(
        elapsed < max_duration,
        "{} took {:?}, expected less than {:?}",
        name,
        elapsed,
        max_duration
    );

    result
}

/// Helper to run multiple iterations and return average duration
fn measure_iterations<F>(iterations: usize, operation: F) -> Duration
where
    F: Fn(),
{
    let start = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let total = start.elapsed();

    Duration::from_nanos(total.as_nanos().checked_div(iterations as u128).unwrap_or(0) as u64)
}

// ============================================================================
// SECTION 1: CRYPTOGRAPHIC OPERATION BENCHMARKS (15+ tests)
// ============================================================================

/// Test 1: ML-KEM-512 keygen completes within reasonable time
#[test]
fn test_mlkem_512_keygen_timing_bound() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    timed_operation("ML-KEM-512 keygen", MAX_SINGLE_OP_TIME, || {
        let result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512);
        assert!(result.is_ok(), "ML-KEM-512 keygen should succeed");
    });
}

/// Test 2: ML-KEM-768 keygen completes within reasonable time
#[test]
fn test_mlkem_768_keygen_timing_bound() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    timed_operation("ML-KEM-768 keygen", MAX_SINGLE_OP_TIME, || {
        let result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768);
        assert!(result.is_ok(), "ML-KEM-768 keygen should succeed");
    });
}

/// Test 3: ML-KEM-1024 keygen completes within reasonable time
#[test]
fn test_mlkem_1024_keygen_timing_bound() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    timed_operation("ML-KEM-1024 keygen", MAX_SINGLE_OP_TIME, || {
        let result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024);
        assert!(result.is_ok(), "ML-KEM-1024 keygen should succeed");
    });
}

/// Test 4: ML-KEM encapsulation completes within reasonable time
#[test]
fn test_mlkem_encapsulation_timing_bound() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    timed_operation("ML-KEM encapsulation", MAX_SINGLE_OP_TIME, || {
        let result = MlKem::encapsulate(&mut rng, &pk);
        assert!(result.is_ok(), "ML-KEM encapsulation should succeed");
    });
}

/// Test 5: ML-DSA-44 keygen completes within reasonable time
#[test]
fn test_mldsa_44_keygen_timing_bound() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

    timed_operation("ML-DSA-44 keygen", MAX_SINGLE_OP_TIME, || {
        let result = generate_keypair(MlDsaParameterSet::MLDSA44);
        assert!(result.is_ok(), "ML-DSA-44 keygen should succeed");
    });
}

/// Test 6: ML-DSA-65 keygen completes within reasonable time
#[test]
fn test_mldsa_65_keygen_timing_bound() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

    timed_operation("ML-DSA-65 keygen", MAX_SINGLE_OP_TIME, || {
        let result = generate_keypair(MlDsaParameterSet::MLDSA65);
        assert!(result.is_ok(), "ML-DSA-65 keygen should succeed");
    });
}

/// Test 7: ML-DSA-87 keygen completes within reasonable time
#[test]
fn test_mldsa_87_keygen_timing_bound() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

    timed_operation("ML-DSA-87 keygen", MAX_SINGLE_OP_TIME, || {
        let result = generate_keypair(MlDsaParameterSet::MLDSA87);
        assert!(result.is_ok(), "ML-DSA-87 keygen should succeed");
    });
}

/// Test 8: ML-DSA signing completes within reasonable time
#[test]
fn test_mldsa_sign_timing_bound() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign};

    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");
    let message = b"Test message for signing performance";

    timed_operation("ML-DSA signing", MAX_SINGLE_OP_TIME, || {
        let result = sign(&sk, message, &[]);
        assert!(result.is_ok(), "ML-DSA signing should succeed");
    });
}

/// Test 9: ML-DSA verification completes within reasonable time
#[test]
fn test_mldsa_verify_timing_bound() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign, verify};

    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");
    let message = b"Test message for verification performance";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");

    timed_operation("ML-DSA verification", MAX_SINGLE_OP_TIME, || {
        let result = verify(&pk, message, &signature, &[]);
        assert!(result.is_ok(), "ML-DSA verification should succeed");
        assert!(result.unwrap(), "Signature should be valid");
    });
}

/// Test 10: AES-GCM-256 encryption completes within reasonable time
#[test]
fn test_aes_gcm_256_encrypt_timing_bound() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let plaintext = vec![0xAB; 1024]; // 1KB

    timed_operation("AES-GCM-256 encryption", MAX_SINGLE_OP_TIME, || {
        let result = cipher.encrypt(&nonce, &plaintext, None);
        assert!(result.is_ok(), "AES-GCM encryption should succeed");
    });
}

/// Test 11: AES-GCM-256 decryption completes within reasonable time
#[test]
fn test_aes_gcm_256_decrypt_timing_bound() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let plaintext = vec![0xAB; 1024]; // 1KB
    let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();

    timed_operation("AES-GCM-256 decryption", MAX_SINGLE_OP_TIME, || {
        let result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
        assert!(result.is_ok(), "AES-GCM decryption should succeed");
    });
}

/// Test 12: ChaCha20-Poly1305 encryption completes within reasonable time
#[test]
fn test_chacha20_poly1305_encrypt_timing_bound() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;

    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let plaintext = vec![0xAB; 1024]; // 1KB

    timed_operation("ChaCha20-Poly1305 encryption", MAX_SINGLE_OP_TIME, || {
        let result = cipher.encrypt(&nonce, &plaintext, None);
        assert!(result.is_ok(), "ChaCha20-Poly1305 encryption should succeed");
    });
}

/// Test 13: SHA-256 hashing completes within reasonable time
#[test]
fn test_sha256_hash_timing_bound() {
    use arc_primitives::hash::sha2::sha256;

    let data = vec![0xAB; 1024]; // 1KB

    timed_operation("SHA-256 hashing", MAX_SINGLE_OP_TIME, || {
        let result = sha256(&data);
        assert!(result.is_ok(), "SHA-256 hashing should succeed");
    });
}

/// Test 14: SHA-512 hashing completes within reasonable time
#[test]
fn test_sha512_hash_timing_bound() {
    use arc_primitives::hash::sha2::sha512;

    let data = vec![0xAB; 1024]; // 1KB

    timed_operation("SHA-512 hashing", MAX_SINGLE_OP_TIME, || {
        let result = sha512(&data);
        assert!(result.is_ok(), "SHA-512 hashing should succeed");
    });
}

/// Test 15: HKDF derivation completes within reasonable time
#[test]
fn test_hkdf_derivation_timing_bound() {
    use arc_primitives::kdf::hkdf::hkdf;

    let ikm = vec![0xAB; 32];
    let salt = vec![0xCD; 16];
    let info = b"test info";

    timed_operation("HKDF derivation", MAX_SINGLE_OP_TIME, || {
        let result = hkdf(&ikm, Some(&salt), Some(info), 64);
        assert!(result.is_ok(), "HKDF derivation should succeed");
    });
}

/// Test 16: AES-GCM-128 encryption completes within reasonable time
#[test]
fn test_aes_gcm_128_encrypt_timing_bound() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm128;

    let key = AesGcm128::generate_key();
    let cipher = AesGcm128::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm128::generate_nonce();
    let plaintext = vec![0xAB; 1024]; // 1KB

    timed_operation("AES-GCM-128 encryption", MAX_SINGLE_OP_TIME, || {
        let result = cipher.encrypt(&nonce, &plaintext, None);
        assert!(result.is_ok(), "AES-GCM-128 encryption should succeed");
    });
}

// ============================================================================
// SECTION 2: THROUGHPUT TESTS (10+ tests)
// ============================================================================

/// Test 17: AES-GCM-256 bulk encryption throughput sanity check
#[test]
fn test_aes_gcm_256_bulk_encryption_throughput() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let plaintext = vec![0xAB; 1024 * 1024]; // 1MB

    let iterations = 10;
    let start = Instant::now();

    for _ in 0..iterations {
        let nonce = AesGcm256::generate_nonce();
        let _result = cipher.encrypt(&nonce, &plaintext, None).unwrap();
    }

    let elapsed = start.elapsed();
    let total_mb = (iterations * plaintext.len()) as f64 / (1024.0 * 1024.0);
    let throughput_mbps = total_mb / elapsed.as_secs_f64();

    // Sanity check: should be able to encrypt at least 10 MB/s on any reasonable hardware
    assert!(
        throughput_mbps > 10.0,
        "AES-GCM throughput {:.2} MB/s is too low (expected > 10 MB/s)",
        throughput_mbps
    );
}

/// Test 18: ChaCha20-Poly1305 bulk encryption throughput sanity check
#[test]
fn test_chacha20_poly1305_bulk_encryption_throughput() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;

    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let plaintext = vec![0xAB; 1024 * 1024]; // 1MB

    let iterations = 10;
    let start = Instant::now();

    for _ in 0..iterations {
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let _result = cipher.encrypt(&nonce, &plaintext, None).unwrap();
    }

    let elapsed = start.elapsed();
    let total_mb = (iterations * plaintext.len()) as f64 / (1024.0 * 1024.0);
    let throughput_mbps = total_mb / elapsed.as_secs_f64();

    // Sanity check: should be able to encrypt at least 10 MB/s
    assert!(
        throughput_mbps > 10.0,
        "ChaCha20-Poly1305 throughput {:.2} MB/s is too low (expected > 10 MB/s)",
        throughput_mbps
    );
}

/// Test 19: ML-KEM keygen rate is reasonable
#[test]
fn test_mlkem_keygen_rate() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        let _result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();
    }
    let elapsed = start.elapsed();

    let rate = iterations as f64 / elapsed.as_secs_f64();

    // Sanity check: should generate at least 10 keypairs per second
    assert!(rate > 10.0, "ML-KEM keygen rate {:.2}/s is too low (expected > 10/s)", rate);
}

/// Test 20: ML-DSA signing rate is reasonable
#[test]
fn test_mldsa_sign_rate() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign};

    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let message = b"Test message for signing rate measurement";
    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        let _result = sign(&sk, message, &[]).unwrap();
    }
    let elapsed = start.elapsed();

    let rate = iterations as f64 / elapsed.as_secs_f64();

    // Sanity check: should sign at least 10 messages per second
    assert!(rate > 10.0, "ML-DSA signing rate {:.2}/s is too low (expected > 10/s)", rate);
}

/// Test 21: ML-DSA verification rate is reasonable
#[test]
fn test_mldsa_verify_rate() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign, verify};

    let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let message = b"Test message for verification rate measurement";
    let signature = sign(&sk, message, &[]).expect("signing should succeed");
    let iterations = 100;

    let start = Instant::now();
    for _ in 0..iterations {
        let _result = verify(&pk, message, &signature, &[]).unwrap();
    }
    let elapsed = start.elapsed();

    let rate = iterations as f64 / elapsed.as_secs_f64();

    // Sanity check: should verify at least 10 signatures per second
    assert!(rate > 10.0, "ML-DSA verification rate {:.2}/s is too low (expected > 10/s)", rate);
}

/// Test 22: SHA-256 throughput is reasonable
#[test]
fn test_sha256_throughput() {
    use arc_primitives::hash::sha2::sha256;

    let data = vec![0xAB; 1024 * 1024]; // 1MB
    let iterations = 10;

    let start = Instant::now();
    for _ in 0..iterations {
        let _result = sha256(&data).unwrap();
    }
    let elapsed = start.elapsed();

    let total_mb = (iterations * data.len()) as f64 / (1024.0 * 1024.0);
    let throughput_mbps = total_mb / elapsed.as_secs_f64();

    // Sanity check: SHA-256 should be able to hash at least 50 MB/s
    assert!(
        throughput_mbps > 50.0,
        "SHA-256 throughput {:.2} MB/s is too low (expected > 50 MB/s)",
        throughput_mbps
    );
}

/// Test 23: SHA-512 throughput is reasonable
#[test]
fn test_sha512_throughput() {
    use arc_primitives::hash::sha2::sha512;

    let data = vec![0xAB; 1024 * 1024]; // 1MB
    let iterations = 10;

    let start = Instant::now();
    for _ in 0..iterations {
        let _result = sha512(&data).unwrap();
    }
    let elapsed = start.elapsed();

    let total_mb = (iterations * data.len()) as f64 / (1024.0 * 1024.0);
    let throughput_mbps = total_mb / elapsed.as_secs_f64();

    // Sanity check: SHA-512 should be able to hash at least 50 MB/s
    assert!(
        throughput_mbps > 50.0,
        "SHA-512 throughput {:.2} MB/s is too low (expected > 50 MB/s)",
        throughput_mbps
    );
}

/// Test 24: HKDF derivation rate is reasonable
#[test]
fn test_hkdf_derivation_rate() {
    use arc_primitives::kdf::hkdf::hkdf;

    let ikm = vec![0xAB; 32];
    let salt = vec![0xCD; 16];
    let info = b"test info";
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _result = hkdf(&ikm, Some(&salt), Some(info), 32).unwrap();
    }
    let elapsed = start.elapsed();

    let rate = iterations as f64 / elapsed.as_secs_f64();

    // Sanity check: should derive at least 1000 keys per second
    assert!(rate > 1000.0, "HKDF derivation rate {:.2}/s is too low (expected > 1000/s)", rate);
}

/// Test 25: Batch signature processing completes within bounds
#[test]
fn test_batch_signature_processing() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign};

    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");

    let batch_size = 50;
    let messages: Vec<Vec<u8>> =
        (0..batch_size).map(|i| format!("Message number {}", i).into_bytes()).collect();

    timed_operation("Batch signature processing", MAX_BULK_OP_TIME, || {
        for message in &messages {
            let _result = sign(&sk, message, &[]).unwrap();
        }
    });
}

/// Test 26: ML-KEM encapsulation rate is reasonable
#[test]
fn test_mlkem_encapsulation_rate() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    let iterations = 100;
    let start = Instant::now();

    for _ in 0..iterations {
        let _result = MlKem::encapsulate(&mut rng, &pk).unwrap();
    }

    let elapsed = start.elapsed();
    let rate = iterations as f64 / elapsed.as_secs_f64();

    // Sanity check: should encapsulate at least 50 times per second
    assert!(rate > 50.0, "ML-KEM encapsulation rate {:.2}/s is too low (expected > 50/s)", rate);
}

// ============================================================================
// SECTION 3: MEMORY USAGE TESTS (10+ tests)
// ============================================================================

/// Test 27: ML-KEM-512 key sizes match FIPS 203 specification
#[test]
fn test_mlkem_512_key_sizes() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
        .expect("keygen should succeed");

    // FIPS 203 specifies these sizes
    assert_eq!(pk.as_bytes().len(), 800, "ML-KEM-512 public key should be 800 bytes");
    assert_eq!(sk.as_bytes().len(), 1632, "ML-KEM-512 secret key should be 1632 bytes");
}

/// Test 28: ML-KEM-768 key sizes match FIPS 203 specification
#[test]
fn test_mlkem_768_key_sizes() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    // FIPS 203 specifies these sizes
    assert_eq!(pk.as_bytes().len(), 1184, "ML-KEM-768 public key should be 1184 bytes");
    assert_eq!(sk.as_bytes().len(), 2400, "ML-KEM-768 secret key should be 2400 bytes");
}

/// Test 29: ML-KEM-1024 key sizes match FIPS 203 specification
#[test]
fn test_mlkem_1024_key_sizes() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let (pk, sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024)
        .expect("keygen should succeed");

    // FIPS 203 specifies these sizes
    assert_eq!(pk.as_bytes().len(), 1568, "ML-KEM-1024 public key should be 1568 bytes");
    assert_eq!(sk.as_bytes().len(), 3168, "ML-KEM-1024 secret key should be 3168 bytes");
}

/// Test 30: ML-KEM ciphertext sizes match specification
#[test]
fn test_mlkem_ciphertext_sizes() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    // ML-KEM-512
    let (pk512, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512).unwrap();
    let (_ss, ct512) = MlKem::encapsulate(&mut rng, &pk512).unwrap();
    assert_eq!(ct512.as_bytes().len(), 768, "ML-KEM-512 ciphertext should be 768 bytes");

    // ML-KEM-768
    let (pk768, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).unwrap();
    let (_ss, ct768) = MlKem::encapsulate(&mut rng, &pk768).unwrap();
    assert_eq!(ct768.as_bytes().len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");

    // ML-KEM-1024
    let (pk1024, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024).unwrap();
    let (_ss, ct1024) = MlKem::encapsulate(&mut rng, &pk1024).unwrap();
    assert_eq!(ct1024.as_bytes().len(), 1568, "ML-KEM-1024 ciphertext should be 1568 bytes");
}

/// Test 31: ML-DSA key sizes match FIPS 204 specification
#[test]
fn test_mldsa_key_sizes() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

    // ML-DSA-44
    let (pk44, sk44) = generate_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    assert_eq!(pk44.len(), 1312, "ML-DSA-44 public key should be 1312 bytes");
    assert_eq!(sk44.len(), 2560, "ML-DSA-44 secret key should be 2560 bytes");

    // ML-DSA-65
    let (pk65, sk65) = generate_keypair(MlDsaParameterSet::MLDSA65).unwrap();
    assert_eq!(pk65.len(), 1952, "ML-DSA-65 public key should be 1952 bytes");
    assert_eq!(sk65.len(), 4032, "ML-DSA-65 secret key should be 4032 bytes");

    // ML-DSA-87
    let (pk87, sk87) = generate_keypair(MlDsaParameterSet::MLDSA87).unwrap();
    assert_eq!(pk87.len(), 2592, "ML-DSA-87 public key should be 2592 bytes");
    assert_eq!(sk87.len(), 4896, "ML-DSA-87 secret key should be 4896 bytes");
}

/// Test 32: ML-DSA signature sizes match FIPS 204 specification
#[test]
fn test_mldsa_signature_sizes() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign};

    let message = b"Test message for signature size check";

    // ML-DSA-44
    let (_pk44, sk44) = generate_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let sig44 = sign(&sk44, message, &[]).unwrap();
    assert_eq!(sig44.len(), 2420, "ML-DSA-44 signature should be 2420 bytes");

    // ML-DSA-65
    let (_pk65, sk65) = generate_keypair(MlDsaParameterSet::MLDSA65).unwrap();
    let sig65 = sign(&sk65, message, &[]).unwrap();
    assert_eq!(sig65.len(), 3309, "ML-DSA-65 signature should be 3309 bytes");

    // ML-DSA-87
    let (_pk87, sk87) = generate_keypair(MlDsaParameterSet::MLDSA87).unwrap();
    let sig87 = sign(&sk87, message, &[]).unwrap();
    assert_eq!(sig87.len(), 4627, "ML-DSA-87 signature should be 4627 bytes");
}

/// Test 33: AES-GCM ciphertext expansion is correct (no expansion + 16 byte tag)
#[test]
fn test_aes_gcm_ciphertext_expansion() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();

    // Test various plaintext sizes
    for size in [0, 1, 16, 64, 256, 1024, 4096] {
        let plaintext = vec![0xAB; size];
        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();

        // Ciphertext length equals plaintext length (stream cipher mode)
        assert_eq!(
            ciphertext.len(),
            plaintext.len(),
            "AES-GCM ciphertext should have same length as plaintext for size {}",
            size
        );

        // Tag is always 16 bytes
        assert_eq!(tag.len(), 16, "AES-GCM tag should always be 16 bytes");
    }
}

/// Test 34: ChaCha20-Poly1305 ciphertext expansion is correct
#[test]
fn test_chacha20_poly1305_ciphertext_expansion() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;

    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();

    // Test various plaintext sizes
    for size in [0, 1, 16, 64, 256, 1024, 4096] {
        let plaintext = vec![0xAB; size];
        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();

        // Ciphertext length equals plaintext length
        assert_eq!(
            ciphertext.len(),
            plaintext.len(),
            "ChaCha20-Poly1305 ciphertext should have same length as plaintext for size {}",
            size
        );

        // Tag is always 16 bytes
        assert_eq!(tag.len(), 16, "ChaCha20-Poly1305 tag should always be 16 bytes");
    }
}

/// Test 35: SHA hash output sizes are correct
#[test]
fn test_sha_hash_output_sizes() {
    use arc_primitives::hash::sha2::{sha256, sha384, sha512};

    let data = b"Test data for hash output size verification";

    let hash256 = sha256(data).unwrap();
    assert_eq!(hash256.len(), 32, "SHA-256 output should be 32 bytes");

    let hash384 = sha384(data).unwrap();
    assert_eq!(hash384.len(), 48, "SHA-384 output should be 48 bytes");

    let hash512 = sha512(data).unwrap();
    assert_eq!(hash512.len(), 64, "SHA-512 output should be 64 bytes");
}

/// Test 36: No memory leak in repeated keygen operations
#[test]
fn test_no_memory_leak_keygen() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let iterations = 100;

    // Simply run many iterations; if there's a major leak, the test process
    // would eventually run out of memory or slow down significantly
    timed_operation("Repeated keygen (leak test)", MAX_BULK_OP_TIME, || {
        for _ in 0..iterations {
            let _keypair = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768);
        }
    });
}

/// Test 37: No memory leak in repeated encryption operations
#[test]
fn test_no_memory_leak_encryption() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let plaintext = vec![0xAB; 1024]; // 1KB
    let iterations = 1000;

    timed_operation("Repeated encryption (leak test)", MAX_BULK_OP_TIME, || {
        for _ in 0..iterations {
            let nonce = AesGcm256::generate_nonce();
            let _result = cipher.encrypt(&nonce, &plaintext, None);
        }
    });
}

// ============================================================================
// SECTION 4: SCALABILITY TESTS (10+ tests)
// ============================================================================

/// Test 38: AES-GCM scales with data size (increasing data sizes)
#[test]
fn test_aes_gcm_scaling_with_data_size() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    let sizes = [1024, 4096, 16384, 65536, 262144]; // 1KB to 256KB
    let mut durations = Vec::with_capacity(sizes.len());

    for &size in &sizes {
        let plaintext = vec![0xAB; size];
        let nonce = AesGcm256::generate_nonce();

        let start = Instant::now();
        let _result = cipher.encrypt(&nonce, &plaintext, None).unwrap();
        durations.push((size, start.elapsed()));
    }

    // Verify that larger sizes don't cause catastrophic slowdown
    // (should scale roughly linearly)
    for (size, duration) in &durations {
        assert!(
            duration.as_secs() < 5,
            "AES-GCM encryption of {} bytes took too long: {:?}",
            size,
            duration
        );
    }
}

/// Test 39: SHA-256 scales with data size
#[test]
fn test_sha256_scaling_with_data_size() {
    use arc_primitives::hash::sha2::sha256;

    let sizes = [1024, 4096, 16384, 65536, 262144]; // 1KB to 256KB

    for &size in &sizes {
        let data = vec![0xAB; size];

        let start = Instant::now();
        let _result = sha256(&data).unwrap();
        let duration = start.elapsed();

        assert!(
            duration.as_secs() < 5,
            "SHA-256 hashing of {} bytes took too long: {:?}",
            size,
            duration
        );
    }
}

/// Test 40: Concurrent ML-KEM operations scale reasonably
#[test]
fn test_concurrent_mlkem_operations() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let thread_count = 4;
    let operations_per_thread = 10;
    let success_count = Arc::new(AtomicUsize::new(0));

    let start = Instant::now();
    let mut handles = vec![];

    for _ in 0..thread_count {
        let success_count_clone = Arc::clone(&success_count);
        let handle = thread::spawn(move || {
            let mut rng = OsRng;
            for _ in 0..operations_per_thread {
                if MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768).is_ok() {
                    success_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    let elapsed = start.elapsed();
    let total_ops = success_count.load(Ordering::SeqCst);

    assert_eq!(
        total_ops,
        thread_count * operations_per_thread,
        "All concurrent operations should succeed"
    );

    // Should complete all operations within reasonable time
    assert!(
        elapsed < MAX_BULK_OP_TIME,
        "Concurrent ML-KEM operations took {:?}, expected less than {:?}",
        elapsed,
        MAX_BULK_OP_TIME
    );
}

/// Test 41: Concurrent AES-GCM operations scale reasonably
#[test]
fn test_concurrent_aes_gcm_operations() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let thread_count = 4;
    let operations_per_thread = 100;
    let success_count = Arc::new(AtomicUsize::new(0));

    let key = AesGcm256::generate_key();
    let plaintext = vec![0xAB; 1024]; // 1KB

    let start = Instant::now();
    let mut handles = vec![];

    for _ in 0..thread_count {
        let success_count_clone = Arc::clone(&success_count);
        let key_clone = key;
        let plaintext_clone = plaintext.clone();
        let handle = thread::spawn(move || {
            let cipher = AesGcm256::new(&key_clone).expect("cipher creation should succeed");
            for _ in 0..operations_per_thread {
                let nonce = AesGcm256::generate_nonce();
                if cipher.encrypt(&nonce, &plaintext_clone, None).is_ok() {
                    success_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    let elapsed = start.elapsed();
    let total_ops = success_count.load(Ordering::SeqCst);

    assert_eq!(
        total_ops,
        thread_count * operations_per_thread,
        "All concurrent operations should succeed"
    );

    assert!(elapsed < MAX_BULK_OP_TIME, "Concurrent AES-GCM operations took {:?}", elapsed);
}

/// Test 42: Large message handling (1MB)
#[test]
fn test_large_message_1mb() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let plaintext = vec![0xAB; 1024 * 1024]; // 1MB

    timed_operation("1MB encryption", MAX_LARGE_MSG_TIME, || {
        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();
        assert_eq!(plaintext, decrypted, "Decrypted data should match original");
    });
}

/// Test 43: Large message handling (10MB)
#[test]
fn test_large_message_10mb() {
    use arc_primitives::aead::AeadCipher;
    use arc_primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();
    let plaintext = vec![0xAB; 10 * 1024 * 1024]; // 10MB

    timed_operation("10MB encryption", MAX_LARGE_MSG_TIME, || {
        let (ciphertext, tag) = cipher.encrypt(&nonce, &plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).unwrap();
        assert_eq!(plaintext.len(), decrypted.len(), "Decrypted length should match");
    });
}

/// Test 44: Large message hashing (10MB)
#[test]
fn test_large_message_hashing_10mb() {
    use arc_primitives::hash::sha2::sha256;

    let data = vec![0xAB; 10 * 1024 * 1024]; // 10MB

    timed_operation("10MB SHA-256 hashing", MAX_LARGE_MSG_TIME, || {
        let hash = sha256(&data).unwrap();
        assert_eq!(hash.len(), 32, "SHA-256 output should be 32 bytes");
    });
}

/// Test 45: Performance histogram for cryptographic operations
#[test]
fn test_performance_histogram_crypto_ops() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let mut histogram = Histogram::new(100);

    // Collect timing samples
    for _ in 0..100 {
        let mut timer = Timer::start();
        let _result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768);
        histogram.record(timer.stop());
    }

    let stats = histogram.calculate_statistics();

    // Verify we got reasonable statistics
    assert_eq!(stats.count, 100, "Should have 100 samples");
    assert!(stats.min <= stats.median, "Min should be <= median");
    assert!(stats.median <= stats.max, "Median should be <= max");
    assert!(stats.percentile_99 >= stats.percentile_90, "P99 should be >= P90");
}

/// Test 46: Metrics collector for tracking crypto performance
#[test]
fn test_metrics_collector_crypto_tracking() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;
    let collector = MetricsCollector::new();

    // Track keygen operations
    for _ in 0..10 {
        let start = Instant::now();
        let _result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512);
        collector.record_operation("mlkem512_keygen", start.elapsed());
    }

    // Track encapsulation operations
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512).unwrap();
    for _ in 0..10 {
        let start = Instant::now();
        let _result = MlKem::encapsulate(&mut rng, &pk);
        collector.record_operation("mlkem512_encaps", start.elapsed());
    }

    // Verify metrics were collected
    assert_eq!(collector.get_count("mlkem512_keygen"), 10);
    assert_eq!(collector.get_count("mlkem512_encaps"), 10);

    let keygen_stats = collector.get_statistics("mlkem512_keygen");
    assert_eq!(keygen_stats.count, 10);
    assert!(keygen_stats.average > Duration::ZERO);
}

/// Test 47: HKDF scaling with output length
#[test]
fn test_hkdf_scaling_with_output_length() {
    use arc_primitives::kdf::hkdf::hkdf;

    let ikm = vec![0xAB; 32];
    let salt = vec![0xCD; 16];
    let info = b"test info";

    let output_lengths = [32, 64, 128, 256, 512, 1024, 2048, 4096];

    for &length in &output_lengths {
        let start = Instant::now();
        let result = hkdf(&ikm, Some(&salt), Some(info), length).unwrap();
        let duration = start.elapsed();

        assert_eq!(result.key.len(), length, "HKDF output should be {} bytes", length);
        assert!(
            duration.as_secs() < 1,
            "HKDF with {} byte output took too long: {:?}",
            length,
            duration
        );
    }
}

/// Test 48: ML-KEM shared secret is always 32 bytes
#[test]
fn test_mlkem_shared_secret_size() {
    use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
    use rand::rngs::OsRng;

    let mut rng = OsRng;

    // All security levels should produce 32-byte shared secrets
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level).unwrap();
        let (shared_secret, _ct) = MlKem::encapsulate(&mut rng, &pk).unwrap();

        assert_eq!(
            shared_secret.as_bytes().len(),
            32,
            "{:?} shared secret should be 32 bytes",
            level
        );
    }
}

/// Test 49: Concurrent signature operations scale reasonably
#[test]
fn test_concurrent_signature_operations() {
    use arc_primitives::sig::ml_dsa::{MlDsaParameterSet, generate_keypair, sign};

    let thread_count = 4;
    let operations_per_thread = 20;
    let success_count = Arc::new(AtomicUsize::new(0));

    // Generate keypair once (shared across threads - but each thread signs)
    let (_pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).unwrap();
    let sk_bytes = sk.as_bytes().to_vec();

    let start = Instant::now();
    let mut handles = vec![];

    for thread_id in 0..thread_count {
        let success_count_clone = Arc::clone(&success_count);
        let sk_bytes_clone = sk_bytes.clone();
        let handle = thread::spawn(move || {
            // Recreate secret key from bytes for this thread
            let sk = arc_primitives::sig::ml_dsa::MlDsaSecretKey::new(
                MlDsaParameterSet::MLDSA44,
                sk_bytes_clone,
            )
            .expect("SK reconstruction should succeed");

            for i in 0..operations_per_thread {
                let message = format!("Thread {} message {}", thread_id, i);
                if sign(&sk, message.as_bytes(), &[]).is_ok() {
                    success_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    let elapsed = start.elapsed();
    let total_ops = success_count.load(Ordering::SeqCst);

    assert_eq!(
        total_ops,
        thread_count * operations_per_thread,
        "All concurrent signature operations should succeed"
    );

    assert!(elapsed < MAX_BULK_OP_TIME, "Concurrent signature operations took {:?}", elapsed);
}

/// Test 50: Performance comparison baseline - establish that operations are measurable
#[test]
fn test_performance_measurement_baseline() {
    // This test establishes that our performance measurement infrastructure works correctly

    // Test 1: Timer measures non-zero time for actual work
    let mut timer = Timer::start();
    let mut sum: u64 = 0;
    for i in 0..100000 {
        sum = sum.wrapping_add(i);
    }
    let elapsed = timer.stop();
    assert!(elapsed > Duration::ZERO, "Timer should measure non-zero time");
    assert!(sum > 0, "Work should produce result"); // Prevent optimization

    // Test 2: Benchmark function produces statistics
    let stats = benchmark(100, || {
        let mut x: u64 = 0;
        for i in 0..1000 {
            x = x.wrapping_add(i);
        }
        let _ = x; // Prevent optimization
    });

    assert_eq!(stats.count, 100, "Should have 100 samples");
    assert!(stats.average > Duration::ZERO, "Average should be > 0");
    assert!(stats.min <= stats.average, "Min should be <= average");
    assert!(stats.max >= stats.average, "Max should be >= average");

    // Test 3: time_operation works correctly
    let duration = time_operation(|| {
        std::thread::sleep(Duration::from_millis(1));
    });
    assert!(duration >= Duration::from_millis(1), "time_operation should measure at least 1ms");
}
