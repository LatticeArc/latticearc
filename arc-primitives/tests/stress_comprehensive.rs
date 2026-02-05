#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::single_match,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::explicit_auto_deref,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::print_stdout,
    clippy::unused_unit,
    clippy::expect_fun_call,
    clippy::useless_vec,
    clippy::cloned_instead_of_copied,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::manual_let_else
)]
//! Comprehensive Stress and Load Tests for arc-primitives
//!
//! This test suite provides extensive stress testing for all cryptographic
//! primitives in the arc-primitives crate, ensuring stability under high load.
//!
//! ## Test Categories
//!
//! 1. **High-Volume Operation Tests**: 1000+ sequential operations
//! 2. **Resource Exhaustion Tests**: Memory pressure and large buffer handling
//! 3. **Long-Running Stability Tests**: Extended operation sequences (10000+ ops)
//! 4. **Edge Case Stress Tests**: Boundary conditions under load
//!
//! ## Coverage
//!
//! - ML-KEM (FIPS 203): Key generation, encapsulation at scale
//! - ML-DSA (FIPS 204): Sign/verify cycles at scale
//! - AES-GCM: Encrypt/decrypt cycles at scale
//! - ChaCha20-Poly1305: Encrypt/decrypt cycles at scale
//! - ECDH (X25519, P-256): Key agreement at scale
//! - SHA-2/SHA-3: Hash operations at scale
//! - CSPRNG: Random byte generation at scale
//!
//! Tests marked with `#[ignore]` are very long-running and should be run
//! separately in CI with extended timeouts.

#![deny(unsafe_code)]

use std::collections::HashSet;
use std::time::{Duration, Instant};

use arc_primitives::aead::AeadCipher;
use arc_primitives::aead::aes_gcm::{AesGcm128, AesGcm256};
use arc_primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;
use arc_primitives::hash::sha2::{sha256, sha384, sha512};
use arc_primitives::hash::sha3::{sha3_256, sha3_512};
use arc_primitives::kem::ecdh::{EcdhP256KeyPair, EcdhP384KeyPair, X25519KeyPair};
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use arc_primitives::rand::{random_bytes, random_u32, random_u64};
use arc_primitives::sig::ml_dsa::{self, MlDsaParameterSet};
use rand::rngs::OsRng;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Standard iteration count for high-volume tests
const HIGH_VOLUME_ITERATIONS: usize = 1000;

/// Iteration count for very long-running tests
const EXTENDED_ITERATIONS: usize = 10000;

/// Maximum allowed time for standard stress tests (seconds)
const STANDARD_TIMEOUT_SECS: u64 = 120;

/// Size for large buffer tests (100MB)
const LARGE_BUFFER_SIZE: usize = 100 * 1024 * 1024;

/// Medium buffer size for moderate stress tests (10MB)
const MEDIUM_BUFFER_SIZE: usize = 10 * 1024 * 1024;

// ============================================================================
// SECTION 1: High-Volume Operation Tests - Key Generation (15+ tests)
// ============================================================================

/// Test 1000 sequential ML-KEM-512 key generations
#[test]
fn test_high_volume_mlkem_512_keygen() {
    let mut rng = OsRng;
    let mut success_count = 0;
    let start = Instant::now();

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512);
        if result.is_ok() {
            success_count += 1;
        }
    }

    let duration = start.elapsed();
    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} ML-KEM-512 key generations should succeed",
        HIGH_VOLUME_ITERATIONS
    );
    assert!(
        duration < Duration::from_secs(STANDARD_TIMEOUT_SECS),
        "Operations should complete within timeout (took {:?})",
        duration
    );
}

/// Test 1000 sequential ML-KEM-768 key generations
#[test]
fn test_high_volume_mlkem_768_keygen() {
    let mut rng = OsRng;
    let mut success_count = 0;

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768);
        if result.is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} ML-KEM-768 key generations should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential ML-KEM-1024 key generations
#[test]
fn test_high_volume_mlkem_1024_keygen() {
    let mut rng = OsRng;
    let mut success_count = 0;

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024);
        if result.is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} ML-KEM-1024 key generations should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential ML-DSA-44 sign/verify cycles
#[test]
fn test_high_volume_mldsa_44_sign_verify() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let context: &[u8] = &[];
    let mut success_count = 0;

    for i in 0..HIGH_VOLUME_ITERATIONS {
        let message = format!("Message number {} for stress testing", i);
        let sig_result = ml_dsa::sign(&sk, message.as_bytes(), context);
        if let Ok(sig) = sig_result {
            let verify_result = ml_dsa::verify(&pk, message.as_bytes(), &sig, context);
            if let Ok(valid) = verify_result {
                if valid {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} ML-DSA-44 sign/verify cycles should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential ML-DSA-65 sign/verify cycles
#[test]
fn test_high_volume_mldsa_65_sign_verify() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");
    let context: &[u8] = &[];
    let mut success_count = 0;

    for i in 0..HIGH_VOLUME_ITERATIONS {
        let message = format!("Message {} for ML-DSA-65 stress", i);
        let sig_result = ml_dsa::sign(&sk, message.as_bytes(), context);
        if let Ok(sig) = sig_result {
            let verify_result = ml_dsa::verify(&pk, message.as_bytes(), &sig, context);
            if let Ok(valid) = verify_result {
                if valid {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} ML-DSA-65 sign/verify cycles should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential AES-GCM-256 encrypt/decrypt cycles
#[test]
fn test_high_volume_aes_gcm_256_encrypt_decrypt() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let mut success_count = 0;

    for i in 0..HIGH_VOLUME_ITERATIONS {
        let nonce = AesGcm256::generate_nonce();
        let plaintext = format!("Plaintext message {} for encryption stress test", i);

        let enc_result = cipher.encrypt(&nonce, plaintext.as_bytes(), None);
        if let Ok((ciphertext, tag)) = enc_result {
            let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
            if let Ok(decrypted) = dec_result {
                if decrypted == plaintext.as_bytes() {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} AES-GCM-256 encrypt/decrypt cycles should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential AES-GCM-128 encrypt/decrypt cycles
#[test]
fn test_high_volume_aes_gcm_128_encrypt_decrypt() {
    let key = AesGcm128::generate_key();
    let cipher = AesGcm128::new(&key).expect("cipher creation should succeed");
    let mut success_count = 0;

    for i in 0..HIGH_VOLUME_ITERATIONS {
        let nonce = AesGcm128::generate_nonce();
        let plaintext = format!("AES-128 message {}", i);

        let enc_result = cipher.encrypt(&nonce, plaintext.as_bytes(), None);
        if let Ok((ciphertext, tag)) = enc_result {
            let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
            if let Ok(decrypted) = dec_result {
                if decrypted == plaintext.as_bytes() {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} AES-GCM-128 encrypt/decrypt cycles should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential ChaCha20-Poly1305 encrypt/decrypt cycles
#[test]
fn test_high_volume_chacha20_poly1305_encrypt_decrypt() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let mut success_count = 0;

    for i in 0..HIGH_VOLUME_ITERATIONS {
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = format!("ChaCha20 message {}", i);

        let enc_result = cipher.encrypt(&nonce, plaintext.as_bytes(), None);
        if let Ok((ciphertext, tag)) = enc_result {
            let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
            if let Ok(decrypted) = dec_result {
                if decrypted == plaintext.as_bytes() {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} ChaCha20-Poly1305 encrypt/decrypt cycles should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test rapid key rotation simulation (1000 key changes)
#[test]
fn test_rapid_key_rotation_simulation() {
    let mut success_count = 0;
    let plaintext = b"Data to encrypt with rotating keys";

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        // Generate new key
        let key = AesGcm256::generate_key();
        let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
        let nonce = AesGcm256::generate_nonce();

        // Encrypt and decrypt with new key
        let enc_result = cipher.encrypt(&nonce, plaintext, None);
        if let Ok((ciphertext, tag)) = enc_result {
            let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
            if let Ok(decrypted) = dec_result {
                if decrypted == plaintext {
                    success_count += 1;
                }
            }
        }
        // Key and cipher go out of scope here (rotation)
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} key rotation cycles should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test burst operation handling (100 ops in quick succession)
#[test]
fn test_burst_operations() {
    let mut rng = OsRng;
    const BURST_SIZE: usize = 100;
    const BURST_COUNT: usize = 10;
    let mut total_success = 0;

    for _ in 0..BURST_COUNT {
        // Burst of key generations
        for _ in 0..BURST_SIZE {
            if MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512).is_ok() {
                total_success += 1;
            }
        }
    }

    assert_eq!(total_success, BURST_SIZE * BURST_COUNT, "All burst operations should succeed");
}

/// Test 1000 sequential X25519 key generations and agreements
#[test]
fn test_high_volume_x25519_key_agreement() {
    let mut success_count = 0;

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let alice_result = X25519KeyPair::generate();
        let bob_result = X25519KeyPair::generate();

        if let (Ok(alice), Ok(bob)) = (alice_result, bob_result) {
            let alice_pk = alice.public_key_bytes().to_vec();
            let bob_pk = bob.public_key_bytes().to_vec();

            let alice_ss = alice.agree(&bob_pk);
            let bob_ss = bob.agree(&alice_pk);

            if let (Ok(a_ss), Ok(b_ss)) = (alice_ss, bob_ss) {
                if a_ss == b_ss {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} X25519 key agreements should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential P-256 key agreements
#[test]
fn test_high_volume_p256_key_agreement() {
    let mut success_count = 0;

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let alice_result = EcdhP256KeyPair::generate();
        let bob_result = EcdhP256KeyPair::generate();

        if let (Ok(alice), Ok(bob)) = (alice_result, bob_result) {
            let alice_pk = alice.public_key_bytes().to_vec();
            let bob_pk = bob.public_key_bytes().to_vec();

            let alice_ss = alice.agree(&bob_pk);
            let bob_ss = bob.agree(&alice_pk);

            if let (Ok(a_ss), Ok(b_ss)) = (alice_ss, bob_ss) {
                if a_ss == b_ss {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} P-256 key agreements should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential SHA-256 hash operations
#[test]
fn test_high_volume_sha256_hash() {
    let mut success_count = 0;

    for i in 0..HIGH_VOLUME_ITERATIONS {
        let input = format!("Data to hash: iteration {}", i);
        if sha256(input.as_bytes()).is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} SHA-256 operations should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential SHA3-256 hash operations
#[test]
fn test_high_volume_sha3_256_hash() {
    let mut success_count = 0;

    for i in 0..HIGH_VOLUME_ITERATIONS {
        let input = format!("SHA3 data: iteration {}", i);
        // sha3_256 returns [u8; 32] directly (no Result wrapper)
        let hash = sha3_256(input.as_bytes());
        if hash.len() == 32 {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} SHA3-256 operations should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test 1000 sequential random byte generations
#[test]
fn test_high_volume_random_bytes() {
    let mut all_values: HashSet<Vec<u8>> = HashSet::new();

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let bytes = random_bytes(32);
        all_values.insert(bytes);
    }

    // All random values should be unique
    assert_eq!(
        all_values.len(),
        HIGH_VOLUME_ITERATIONS,
        "All {} random byte generations should produce unique values",
        HIGH_VOLUME_ITERATIONS
    );
}

// ============================================================================
// SECTION 2: Resource Exhaustion Tests (10+ tests)
// ============================================================================

/// Test operations with large buffer (100MB encryption)
#[test]
#[ignore = "Very resource intensive - requires 100MB+ memory"]
fn test_large_buffer_encryption_100mb() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();

    // 100MB buffer - at the limit
    let large_data = vec![0xABu8; LARGE_BUFFER_SIZE];

    let enc_result = cipher.encrypt(&nonce, &large_data, None);
    // This may fail due to resource limits which is expected
    if let Ok((ciphertext, tag)) = enc_result {
        let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
        if let Ok(decrypted) = dec_result {
            assert_eq!(
                decrypted.len(),
                LARGE_BUFFER_SIZE,
                "Decrypted data should match original size"
            );
        }
    }
    // If it fails, that's acceptable for resource limits
}

/// Test operations with medium buffer (10MB)
#[test]
fn test_medium_buffer_encryption_10mb() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let nonce = AesGcm256::generate_nonce();

    let medium_data = vec![0xCDu8; MEDIUM_BUFFER_SIZE];

    let (ciphertext, tag) =
        cipher.encrypt(&nonce, &medium_data, None).expect("encryption should succeed");
    let decrypted =
        cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption should succeed");

    assert_eq!(decrypted.len(), MEDIUM_BUFFER_SIZE);
    assert_eq!(decrypted, medium_data);
}

/// Test SHA-256 with large input (10MB)
#[test]
fn test_sha256_large_input() {
    let large_data = vec![0x42u8; MEDIUM_BUFFER_SIZE];
    let hash = sha256(&large_data).expect("hashing should succeed");
    assert_eq!(hash.len(), 32);

    // Verify determinism
    let hash2 = sha256(&large_data).expect("second hash should succeed");
    assert_eq!(hash, hash2, "Hashing same data should produce same result");
}

/// Test SHA-512 with large input (10MB)
#[test]
fn test_sha512_large_input() {
    let large_data = vec![0x55u8; MEDIUM_BUFFER_SIZE];
    let hash = sha512(&large_data).expect("hashing should succeed");
    assert_eq!(hash.len(), 64);
}

/// Test SHA3-512 with large input (10MB)
#[test]
fn test_sha3_512_large_input() {
    let large_data = vec![0x77u8; MEDIUM_BUFFER_SIZE];
    // sha3_512 returns [u8; 64] directly (no Result wrapper)
    let hash = sha3_512(&large_data);
    assert_eq!(hash.len(), 64);
}

/// Test maximum key count handling (generate and store many keys)
#[test]
fn test_maximum_key_count_handling() {
    let mut rng = OsRng;
    const KEY_COUNT: usize = 500;
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(KEY_COUNT);

    for _ in 0..KEY_COUNT {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keygen should succeed");
        keys.push(pk.to_bytes());
    }

    assert_eq!(keys.len(), KEY_COUNT);

    // Verify all keys are unique
    let unique_keys: HashSet<Vec<u8>> = keys.into_iter().collect();
    assert_eq!(unique_keys.len(), KEY_COUNT, "All generated keys should be unique");
}

/// Test memory pressure with repeated allocations/deallocations
#[test]
fn test_memory_pressure_allocation_cycles() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");

    // Perform many allocations and let them go out of scope
    for cycle in 0..100 {
        let nonce = AesGcm256::generate_nonce();
        // Allocate 1MB buffer
        let data = vec![0xABu8; 1024 * 1024];
        let (ciphertext, tag) =
            cipher.encrypt(&nonce, &data, None).expect("encryption should succeed");
        let decrypted =
            cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption should succeed");
        assert_eq!(decrypted.len(), data.len(), "Cycle {} should succeed", cycle);
        // All allocations go out of scope here
    }
}

/// Test signing with large messages (100KB)
#[test]
fn test_sign_large_message() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let context: &[u8] = &[];

    // 100KB message
    let large_message = vec![0x42u8; 100 * 1024];

    let signature = ml_dsa::sign(&sk, &large_message, context).expect("signing should succeed");
    let is_valid = ml_dsa::verify(&pk, &large_message, &signature, context)
        .expect("verification should succeed");

    assert!(is_valid, "Large message signature should be valid");
}

/// Test random u64 generation volume
#[test]
fn test_high_volume_random_u64() {
    let mut values: HashSet<u64> = HashSet::new();

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let val = random_u64();
        values.insert(val);
    }

    // All values should be unique (probability of collision is negligible for u64)
    assert_eq!(values.len(), HIGH_VOLUME_ITERATIONS, "All random u64 values should be unique");
}

/// Test random u32 distribution under volume
#[test]
fn test_high_volume_random_u32_distribution() {
    let mut values: HashSet<u32> = HashSet::new();

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let val = random_u32();
        values.insert(val);
    }

    // With 1000 samples from 2^32 space, expect very high uniqueness
    assert!(
        values.len() > 990,
        "Should have high uniqueness: {} unique out of {}",
        values.len(),
        HIGH_VOLUME_ITERATIONS
    );
}

// ============================================================================
// SECTION 3: Long-Running Stability Tests (10+ tests)
// ============================================================================

/// Extended operation sequence - 10000+ ML-KEM operations
#[test]
#[ignore = "Very long-running test - 10000+ operations"]
fn test_extended_mlkem_operations() {
    let mut rng = OsRng;
    let mut success_count = 0;
    let start = Instant::now();

    for _ in 0..EXTENDED_ITERATIONS {
        let keygen_result = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512);
        if let Ok((pk, _sk)) = keygen_result {
            if MlKem::encapsulate(&mut rng, &pk).is_ok() {
                success_count += 1;
            }
        }
    }

    let duration = start.elapsed();
    assert_eq!(
        success_count, EXTENDED_ITERATIONS,
        "All {} extended operations should succeed",
        EXTENDED_ITERATIONS
    );

    // Track performance
    let ops_per_sec = EXTENDED_ITERATIONS as f64 / duration.as_secs_f64();
    assert!(ops_per_sec > 10.0, "Should achieve reasonable throughput: {:.2} ops/sec", ops_per_sec);
}

/// Extended operation sequence - 10000+ hash operations
#[test]
#[ignore = "Very long-running test - 10000+ operations"]
fn test_extended_hash_operations() {
    let mut success_count = 0;

    for i in 0..EXTENDED_ITERATIONS {
        let data = format!("Extended hash test data iteration {}", i);
        if sha256(data.as_bytes()).is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, EXTENDED_ITERATIONS,
        "All {} extended hash operations should succeed",
        EXTENDED_ITERATIONS
    );
}

/// Test state accumulation detection over many operations
#[test]
fn test_state_accumulation_detection() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let plaintext = b"Test data for state accumulation check";

    // Record timings for first and last batches
    let mut first_batch_times: Vec<Duration> = Vec::new();
    let mut last_batch_times: Vec<Duration> = Vec::new();

    // First batch
    for _ in 0..100 {
        let nonce = AesGcm256::generate_nonce();
        let start = Instant::now();
        let _ = cipher.encrypt(&nonce, plaintext, None);
        first_batch_times.push(start.elapsed());
    }

    // Do many operations
    for _ in 0..1000 {
        let nonce = AesGcm256::generate_nonce();
        let _ = cipher.encrypt(&nonce, plaintext, None);
    }

    // Last batch
    for _ in 0..100 {
        let nonce = AesGcm256::generate_nonce();
        let start = Instant::now();
        let _ = cipher.encrypt(&nonce, plaintext, None);
        last_batch_times.push(start.elapsed());
    }

    // Compare average times - should not degrade significantly
    let first_avg: f64 = first_batch_times.iter().map(|d| d.as_nanos() as f64).sum::<f64>()
        / first_batch_times.len() as f64;
    let last_avg: f64 = last_batch_times.iter().map(|d| d.as_nanos() as f64).sum::<f64>()
        / last_batch_times.len() as f64;

    // Performance should not degrade by more than 5x
    assert!(
        last_avg < first_avg * 5.0,
        "Performance should not degrade: first_avg={:.0}ns, last_avg={:.0}ns",
        first_avg,
        last_avg
    );
}

/// Test consistent performance over time for signing
#[test]
fn test_consistent_signing_performance() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let context: &[u8] = &[];
    let message = b"Performance consistency test message";

    let mut timings: Vec<Duration> = Vec::new();

    for _ in 0..500 {
        let start = Instant::now();
        let sig = ml_dsa::sign(&sk, message, context).expect("signing should succeed");
        let _ = ml_dsa::verify(&pk, message, &sig, context).expect("verification should succeed");
        timings.push(start.elapsed());
    }

    // Calculate standard deviation
    let mean: f64 = timings.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / timings.len() as f64;
    let variance: f64 = timings
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / timings.len() as f64;
    let std_dev = variance.sqrt();

    // Coefficient of variation should be reasonable (less than 100%)
    let cv = std_dev / mean;
    assert!(
        cv < 1.0,
        "Timing should be consistent: mean={:.0}ns, std_dev={:.0}ns, cv={:.2}",
        mean,
        std_dev,
        cv
    );
}

/// Test no degradation over iterations for keygen
#[test]
fn test_no_keygen_degradation() {
    let mut rng = OsRng;
    const BATCH_SIZE: usize = 50;
    const NUM_BATCHES: usize = 10;

    let mut batch_times: Vec<Duration> = Vec::new();

    for batch in 0..NUM_BATCHES {
        let start = Instant::now();
        for _ in 0..BATCH_SIZE {
            let _ = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768);
        }
        let batch_duration = start.elapsed();
        batch_times.push(batch_duration);

        // Ensure each batch completes
        assert!(
            batch_duration < Duration::from_secs(60),
            "Batch {} took too long: {:?}",
            batch,
            batch_duration
        );
    }

    // Last batch should not take more than 3x the first batch
    let first_batch = batch_times.first().expect("should have first batch");
    let last_batch = batch_times.last().expect("should have last batch");
    assert!(
        last_batch.as_nanos() < first_batch.as_nanos() * 3,
        "No significant degradation: first={:?}, last={:?}",
        first_batch,
        last_batch
    );
}

/// Extended encryption stability test
#[test]
#[ignore = "Very long-running test"]
fn test_extended_encryption_stability() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let mut success_count = 0;

    for i in 0..EXTENDED_ITERATIONS {
        let nonce = AesGcm256::generate_nonce();
        let plaintext = format!("Extended encryption test {}", i);

        let enc_result = cipher.encrypt(&nonce, plaintext.as_bytes(), None);
        if let Ok((ciphertext, tag)) = enc_result {
            let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
            if let Ok(decrypted) = dec_result {
                if decrypted == plaintext.as_bytes() {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, EXTENDED_ITERATIONS,
        "All {} extended encryption operations should succeed",
        EXTENDED_ITERATIONS
    );
}

/// Test extended ECDH operations
#[test]
#[ignore = "Long-running test - 5000 operations"]
fn test_extended_ecdh_operations() {
    let mut success_count = 0;
    const ECDH_ITERATIONS: usize = 5000;

    for _ in 0..ECDH_ITERATIONS {
        let alice = X25519KeyPair::generate().expect("alice keygen should succeed");
        let bob = X25519KeyPair::generate().expect("bob keygen should succeed");

        let alice_pk = alice.public_key_bytes().to_vec();
        let bob_pk = bob.public_key_bytes().to_vec();

        let alice_ss = alice.agree(&bob_pk).expect("alice agree should succeed");
        let bob_ss = bob.agree(&alice_pk).expect("bob agree should succeed");

        if alice_ss == bob_ss {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, ECDH_ITERATIONS,
        "All {} ECDH operations should succeed",
        ECDH_ITERATIONS
    );
}

/// Test P-384 extended operations
#[test]
fn test_extended_p384_operations() {
    let mut success_count = 0;
    const P384_ITERATIONS: usize = 200;

    for _ in 0..P384_ITERATIONS {
        let alice = EcdhP384KeyPair::generate().expect("alice keygen should succeed");
        let bob = EcdhP384KeyPair::generate().expect("bob keygen should succeed");

        let alice_pk = alice.public_key_bytes().to_vec();
        let bob_pk = bob.public_key_bytes().to_vec();

        let alice_ss = alice.agree(&bob_pk).expect("alice agree should succeed");
        let bob_ss = bob.agree(&alice_pk).expect("bob agree should succeed");

        if alice_ss == bob_ss {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, P384_ITERATIONS,
        "All {} P-384 operations should succeed",
        P384_ITERATIONS
    );
}

/// Test hash function consistency over extended runs
#[test]
fn test_extended_hash_consistency() {
    let test_data = b"Consistency check data";
    let reference_hash = sha256(test_data).expect("reference hash should succeed");

    for i in 0..1000 {
        let hash = sha256(test_data).expect("hash should succeed");
        assert_eq!(hash, reference_hash, "Hash should be consistent at iteration {}", i);
    }
}

/// Test extended SHA-384 operations
#[test]
fn test_extended_sha384_operations() {
    let mut success_count = 0;

    for i in 0..2000 {
        let data = format!("SHA-384 extended test iteration {}", i);
        if sha384(data.as_bytes()).is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(success_count, 2000, "All SHA-384 operations should succeed");
}

// ============================================================================
// SECTION 4: Edge Case Stress Tests (10+ tests)
// ============================================================================

/// Test empty input handling under load
#[test]
fn test_empty_input_under_load() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let empty_plaintext: &[u8] = &[];
    let mut success_count = 0;

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let nonce = AesGcm256::generate_nonce();
        let enc_result = cipher.encrypt(&nonce, empty_plaintext, None);
        if let Ok((ciphertext, tag)) = enc_result {
            assert!(ciphertext.is_empty(), "Empty plaintext should produce empty ciphertext");
            let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
            if let Ok(decrypted) = dec_result {
                if decrypted.is_empty() {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} empty input operations should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test empty message signing under load
#[test]
fn test_empty_message_signing_under_load() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let empty_message: &[u8] = &[];
    let context: &[u8] = &[];
    let mut success_count = 0;

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let sig_result = ml_dsa::sign(&sk, empty_message, context);
        if let Ok(sig) = sig_result {
            let verify_result = ml_dsa::verify(&pk, empty_message, &sig, context);
            if let Ok(valid) = verify_result {
                if valid {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(
        success_count, HIGH_VOLUME_ITERATIONS,
        "All {} empty message sign/verify should succeed",
        HIGH_VOLUME_ITERATIONS
    );
}

/// Test maximum size inputs repeatedly
#[test]
fn test_maximum_size_inputs_repeatedly() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&key).expect("cipher creation should succeed");

    // Test with 1MB data repeatedly
    let large_data = vec![0xAAu8; 1024 * 1024];
    let mut success_count = 0;

    for _ in 0..50 {
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let enc_result = cipher.encrypt(&nonce, &large_data, None);
        if let Ok((ciphertext, tag)) = enc_result {
            let dec_result = cipher.decrypt(&nonce, &ciphertext, &tag, None);
            if let Ok(decrypted) = dec_result {
                if decrypted == large_data {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(success_count, 50, "All large input operations should succeed");
}

/// Test alternating operation patterns
#[test]
fn test_alternating_operation_patterns() {
    let mut rng = OsRng;
    let aes_key = AesGcm256::generate_key();
    let aes_cipher = AesGcm256::new(&aes_key).expect("AES cipher creation should succeed");
    let chacha_key = ChaCha20Poly1305Cipher::generate_key();
    let chacha_cipher =
        ChaCha20Poly1305Cipher::new(&chacha_key).expect("ChaCha cipher creation should succeed");

    let mut success_count = 0;

    for i in 0..500 {
        let plaintext = format!("Alternating pattern test {}", i);

        if i % 2 == 0 {
            // AES-GCM operation
            let nonce = AesGcm256::generate_nonce();
            let enc_result = aes_cipher.encrypt(&nonce, plaintext.as_bytes(), None);
            if let Ok((ciphertext, tag)) = enc_result {
                let dec_result = aes_cipher.decrypt(&nonce, &ciphertext, &tag, None);
                if let Ok(decrypted) = dec_result {
                    if decrypted == plaintext.as_bytes() {
                        success_count += 1;
                    }
                }
            }
        } else {
            // ChaCha20-Poly1305 operation
            let nonce = ChaCha20Poly1305Cipher::generate_nonce();
            let enc_result = chacha_cipher.encrypt(&nonce, plaintext.as_bytes(), None);
            if let Ok((ciphertext, tag)) = enc_result {
                let dec_result = chacha_cipher.decrypt(&nonce, &ciphertext, &tag, None);
                if let Ok(decrypted) = dec_result {
                    if decrypted == plaintext.as_bytes() {
                        success_count += 1;
                    }
                }
            }
        }

        // Also do some key generation
        let _ = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512);
    }

    assert_eq!(success_count, 500, "All alternating operations should succeed");
}

/// Test random operation sequences
#[test]
fn test_random_operation_sequences() {
    let mut rng = OsRng;
    let mut success_count = 0;

    for _ in 0..500 {
        // Pick a random operation type based on random value
        let op_type = random_u32() % 5;

        let success = match op_type {
            0 => {
                // ML-KEM keygen
                MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512).is_ok()
            }
            1 => {
                // SHA-256 hash
                sha256(b"random op test").is_ok()
            }
            2 => {
                // AES-GCM encrypt
                let key = AesGcm256::generate_key();
                if let Ok(cipher) = AesGcm256::new(&key) {
                    let nonce = AesGcm256::generate_nonce();
                    cipher.encrypt(&nonce, b"test", None).is_ok()
                } else {
                    false
                }
            }
            3 => {
                // X25519 keygen
                X25519KeyPair::generate().is_ok()
            }
            _ => {
                // Random bytes
                random_bytes(32).len() == 32
            }
        };

        if success {
            success_count += 1;
        }
    }

    assert_eq!(success_count, 500, "All random operations should succeed");
}

/// Test hash with varying input sizes
#[test]
fn test_varying_input_sizes_hash() {
    let sizes = [0, 1, 16, 64, 256, 1024, 4096, 16384, 65536];

    for &size in &sizes {
        let data = vec![0xABu8; size];
        let hash = sha256(&data).expect(&format!("hashing {} bytes should succeed", size));
        assert_eq!(hash.len(), 32, "SHA-256 output should be 32 bytes for {} byte input", size);
    }
}

/// Test encryption with varying AAD sizes
#[test]
fn test_varying_aad_sizes() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let plaintext = b"Test plaintext";
    let aad_sizes = [0, 1, 16, 64, 256, 1024, 4096, 16384];

    for &size in &aad_sizes {
        let nonce = AesGcm256::generate_nonce();
        let aad = vec![0xCDu8; size];

        let (ciphertext, tag) = cipher
            .encrypt(&nonce, plaintext, Some(&aad))
            .expect(&format!("encryption with {} byte AAD should succeed", size));
        let decrypted = cipher
            .decrypt(&nonce, &ciphertext, &tag, Some(&aad))
            .expect(&format!("decryption with {} byte AAD should succeed", size));

        assert_eq!(
            decrypted.as_slice(),
            plaintext,
            "Decryption should match for {} byte AAD",
            size
        );
    }
}

/// Test signing with varying message sizes
#[test]
fn test_varying_message_sizes_signing() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let context: &[u8] = &[];
    let sizes = [0, 1, 16, 64, 256, 1024, 4096, 16384];

    for &size in &sizes {
        let message = vec![0x42u8; size];
        let signature = ml_dsa::sign(&sk, &message, context)
            .expect(&format!("signing {} byte message should succeed", size));
        let is_valid = ml_dsa::verify(&pk, &message, &signature, context)
            .expect(&format!("verification of {} byte message should succeed", size));

        assert!(is_valid, "Signature should be valid for {} byte message", size);
    }
}

/// Test context string variations under load
#[test]
fn test_context_variations_under_load() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");
    let message = b"Context variation test";
    let mut success_count = 0;

    for i in 0..500 {
        // Use different context each time
        let context = format!("context-{}", i);
        let sig_result = ml_dsa::sign(&sk, message, context.as_bytes());
        if let Ok(sig) = sig_result {
            let verify_result = ml_dsa::verify(&pk, message, &sig, context.as_bytes());
            if let Ok(valid) = verify_result {
                if valid {
                    success_count += 1;
                }
            }
        }
    }

    assert_eq!(success_count, 500, "All context variation operations should succeed");
}

/// Test nonce uniqueness under high volume
#[test]
fn test_nonce_uniqueness_under_volume() {
    let mut nonces: HashSet<[u8; 12]> = HashSet::new();

    for _ in 0..HIGH_VOLUME_ITERATIONS {
        let nonce = AesGcm256::generate_nonce();
        nonces.insert(nonce);
    }

    assert_eq!(nonces.len(), HIGH_VOLUME_ITERATIONS, "All nonces should be unique");
}

/// Test mixed algorithm stress
#[test]
fn test_mixed_algorithm_stress() {
    let mut rng = OsRng;
    let mut ml_kem_count = 0;
    let mut ml_dsa_count = 0;
    let mut aead_count = 0;
    let mut hash_count = 0;

    let aes_key = AesGcm256::generate_key();
    let aes_cipher = AesGcm256::new(&aes_key).expect("cipher creation should succeed");
    let (dsa_pk, dsa_sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");

    for i in 0..200 {
        // ML-KEM
        if MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512).is_ok() {
            ml_kem_count += 1;
        }

        // ML-DSA
        let msg = format!("Message {}", i);
        if let Ok(sig) = ml_dsa::sign(&dsa_sk, msg.as_bytes(), &[]) {
            if let Ok(valid) = ml_dsa::verify(&dsa_pk, msg.as_bytes(), &sig, &[]) {
                if valid {
                    ml_dsa_count += 1;
                }
            }
        }

        // AEAD
        let nonce = AesGcm256::generate_nonce();
        if let Ok((ct, tag)) = aes_cipher.encrypt(&nonce, msg.as_bytes(), None) {
            if let Ok(pt) = aes_cipher.decrypt(&nonce, &ct, &tag, None) {
                if pt == msg.as_bytes() {
                    aead_count += 1;
                }
            }
        }

        // Hash - sha256 returns Result, sha3_256 returns array directly
        if sha256(msg.as_bytes()).is_ok() {
            let _h2 = sha3_256(msg.as_bytes()); // sha3 never fails
            hash_count += 1;
        }
    }

    assert_eq!(ml_kem_count, 200, "All ML-KEM operations should succeed");
    assert_eq!(ml_dsa_count, 200, "All ML-DSA operations should succeed");
    assert_eq!(aead_count, 200, "All AEAD operations should succeed");
    assert_eq!(hash_count, 200, "All hash operations should succeed");
}

// ============================================================================
// SECTION 5: Performance Baseline Tests
// ============================================================================

/// Establish performance baseline for ML-KEM-768
#[test]
fn test_mlkem_768_performance_baseline() {
    let mut rng = OsRng;
    const SAMPLE_SIZE: usize = 100;

    let start = Instant::now();
    for _ in 0..SAMPLE_SIZE {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
            .expect("keygen should succeed");
        let _ = MlKem::encapsulate(&mut rng, &pk).expect("encapsulate should succeed");
    }
    let duration = start.elapsed();

    let ops_per_sec = (SAMPLE_SIZE * 2) as f64 / duration.as_secs_f64();
    assert!(ops_per_sec > 50.0, "Should achieve minimum throughput: {:.2} ops/sec", ops_per_sec);
}

/// Establish performance baseline for AES-GCM-256
#[test]
fn test_aes_gcm_256_performance_baseline() {
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("cipher creation should succeed");
    let plaintext = vec![0xABu8; 1024]; // 1KB
    const SAMPLE_SIZE: usize = 1000;

    let start = Instant::now();
    for _ in 0..SAMPLE_SIZE {
        let nonce = AesGcm256::generate_nonce();
        let (ct, tag) = cipher.encrypt(&nonce, &plaintext, None).expect("encrypt should succeed");
        let _ = cipher.decrypt(&nonce, &ct, &tag, None).expect("decrypt should succeed");
    }
    let duration = start.elapsed();

    let ops_per_sec = (SAMPLE_SIZE * 2) as f64 / duration.as_secs_f64();
    assert!(ops_per_sec > 1000.0, "Should achieve high throughput: {:.2} ops/sec", ops_per_sec);
}

/// Establish performance baseline for SHA-256
#[test]
fn test_sha256_performance_baseline() {
    let data = vec![0xABu8; 1024]; // 1KB
    const SAMPLE_SIZE: usize = 10000;

    let start = Instant::now();
    for _ in 0..SAMPLE_SIZE {
        let _ = sha256(&data).expect("hash should succeed");
    }
    let duration = start.elapsed();

    let ops_per_sec = SAMPLE_SIZE as f64 / duration.as_secs_f64();
    assert!(ops_per_sec > 10000.0, "Should achieve high throughput: {:.2} ops/sec", ops_per_sec);
}

// ============================================================================
// Summary Test
// ============================================================================

/// Comprehensive stress test summary
#[test]
fn test_stress_comprehensive_summary() {
    let mut rng = OsRng;

    // 1. ML-KEM operations
    let (pk_kem, _sk_kem) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("ML-KEM keygen should succeed");
    let (ss, _ct) =
        MlKem::encapsulate(&mut rng, &pk_kem).expect("ML-KEM encapsulate should succeed");
    assert_eq!(ss.as_bytes().len(), 32);

    // 2. ML-DSA operations
    let (pk_dsa, sk_dsa) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA65).expect("ML-DSA keygen should succeed");
    let sig = ml_dsa::sign(&sk_dsa, b"test", &[]).expect("ML-DSA sign should succeed");
    let valid = ml_dsa::verify(&pk_dsa, b"test", &sig, &[]).expect("ML-DSA verify should succeed");
    assert!(valid);

    // 3. AES-GCM operations
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("AES-GCM should be created");
    let nonce = AesGcm256::generate_nonce();
    let (ct, tag) = cipher.encrypt(&nonce, b"test", None).expect("AES-GCM encrypt should succeed");
    let pt = cipher.decrypt(&nonce, &ct, &tag, None).expect("AES-GCM decrypt should succeed");
    assert_eq!(pt, b"test");

    // 4. ChaCha20-Poly1305 operations
    let chacha_key = ChaCha20Poly1305Cipher::generate_key();
    let chacha_cipher =
        ChaCha20Poly1305Cipher::new(&chacha_key).expect("ChaCha20 should be created");
    let chacha_nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let (chacha_ct, chacha_tag) = chacha_cipher
        .encrypt(&chacha_nonce, b"test", None)
        .expect("ChaCha20 encrypt should succeed");
    let chacha_pt = chacha_cipher
        .decrypt(&chacha_nonce, &chacha_ct, &chacha_tag, None)
        .expect("ChaCha20 decrypt should succeed");
    assert_eq!(chacha_pt, b"test");

    // 5. ECDH operations
    let alice = X25519KeyPair::generate().expect("X25519 keygen should succeed");
    let bob = X25519KeyPair::generate().expect("X25519 keygen should succeed");
    let alice_pk = *alice.public_key_bytes();
    let bob_pk = *bob.public_key_bytes();
    let alice_ss = alice.agree(&bob_pk).expect("X25519 agree should succeed");
    let bob_ss = bob.agree(&alice_pk).expect("X25519 agree should succeed");
    assert_eq!(alice_ss, bob_ss);

    // 6. Hash operations
    // sha256 returns Result, sha3_256 returns array directly
    let hash = sha256(b"test").expect("SHA-256 should succeed");
    assert_eq!(hash.len(), 32);

    let hash3 = sha3_256(b"test"); // sha3 returns [u8; 32] directly
    assert_eq!(hash3.len(), 32);

    // 7. RNG operations
    let rand_bytes = random_bytes(32);
    assert_eq!(rand_bytes.len(), 32);

    // All basic operations verified - stress tests ensure they work
    // correctly under high load and extended operation sequences
}
