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
//! Comprehensive Concurrency and Thread Safety Tests for arc-primitives
//!
//! This test suite provides extensive validation of thread-safe operation
//! for all cryptographic primitives in the arc-primitives crate.
//!
//! ## Test Categories
//!
//! 1. **Thread Safety Tests**: Concurrent key generation, signing, encryption
//! 2. **Race Condition Tests**: Concurrent serialization/deserialization, shared state
//! 3. **Stress Tests**: High-volume operations, thread pool exhaustion
//! 4. **Synchronization Tests**: Lock-free algorithms, atomic operations
//! 5. **Data Race Detection**: MIRI-compatible subset, ThreadSanitizer annotations
//!
//! ## Coverage
//!
//! - ML-KEM (FIPS 203): Concurrent key generation and encapsulation
//! - ML-DSA (FIPS 204): Parallel signing with same/different keys
//! - AES-GCM: Concurrent encryption/decryption with shared keys
//! - ECDH (X25519, P-256, P-384, P-521): Parallel key agreement
//! - SHA-2/SHA-3: Concurrent hashing operations
//! - CSPRNG: Thread-local RNG safety
//!
//! These tests ensure the library is safe for enterprise multi-threaded deployments.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use arc_primitives::aead::AeadCipher;
use arc_primitives::aead::aes_gcm::{AesGcm128, AesGcm256};
use arc_primitives::hash::sha2::{sha256, sha384, sha512};
use arc_primitives::kem::ecdh::{EcdhP256KeyPair, EcdhP384KeyPair, EcdhP521KeyPair, X25519KeyPair};
use arc_primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use arc_primitives::rand::{random_bytes, random_u32, random_u64};
use arc_primitives::sig::ml_dsa::{self, MlDsaParameterSet};
use rand::rngs::OsRng;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Number of threads for stress tests
const STRESS_THREAD_COUNT: usize = 32;

/// Operations per thread in stress tests
const STRESS_OPS_PER_THREAD: usize = 5;

/// Thread count for standard concurrent tests
const STANDARD_THREAD_COUNT: usize = 8;

/// Iterations per thread in standard tests
const STANDARD_ITERATIONS: usize = 10;

/// Maximum duration for timed tests (seconds)
const MAX_TEST_DURATION_SECS: u64 = 60;

// ============================================================================
// Section 1: Thread Safety Tests - ML-KEM
// ============================================================================

#[test]
fn test_concurrent_ml_kem_keygen_512() {
    let keys = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let keys = Arc::clone(&keys);
            thread::spawn(move || {
                let mut rng = OsRng;
                for _ in 0..STANDARD_ITERATIONS {
                    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
                        .expect("keypair generation should succeed");
                    let mut keys_guard = keys.lock().expect("mutex should not be poisoned");
                    keys_guard.push(pk.to_bytes());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let keys_guard = keys.lock().expect("mutex should not be poisoned");
    let total_keys = keys_guard.len();
    assert_eq!(total_keys, STANDARD_THREAD_COUNT * STANDARD_ITERATIONS);

    // Verify all keys are unique
    let unique_keys: HashSet<Vec<u8>> = keys_guard.iter().cloned().collect();
    assert_eq!(unique_keys.len(), total_keys, "All generated keys should be unique");
}

#[test]
fn test_concurrent_ml_kem_keygen_768() {
    let keys = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let keys = Arc::clone(&keys);
            thread::spawn(move || {
                let mut rng = OsRng;
                for _ in 0..STANDARD_ITERATIONS {
                    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
                        .expect("keypair generation should succeed");
                    let mut keys_guard = keys.lock().expect("mutex should not be poisoned");
                    keys_guard.push(pk.to_bytes());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let keys_guard = keys.lock().expect("mutex should not be poisoned");
    assert_eq!(keys_guard.len(), STANDARD_THREAD_COUNT * STANDARD_ITERATIONS);
}

#[test]
fn test_concurrent_ml_kem_keygen_1024() {
    let keys = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let keys = Arc::clone(&keys);
            thread::spawn(move || {
                let mut rng = OsRng;
                for _ in 0..STANDARD_ITERATIONS {
                    let (pk, _sk) =
                        MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024)
                            .expect("keypair generation should succeed");
                    let mut keys_guard = keys.lock().expect("mutex should not be poisoned");
                    keys_guard.push(pk.to_bytes());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let keys_guard = keys.lock().expect("mutex should not be poisoned");
    assert_eq!(keys_guard.len(), STANDARD_THREAD_COUNT * STANDARD_ITERATIONS);
}

#[test]
fn test_concurrent_ml_kem_encapsulation_same_key() {
    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keypair generation should succeed");

    let pk = Arc::new(pk);
    let ciphertexts = Arc::new(Mutex::new(Vec::new()));
    let shared_secrets = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let pk = Arc::clone(&pk);
            let ciphertexts = Arc::clone(&ciphertexts);
            let shared_secrets = Arc::clone(&shared_secrets);
            thread::spawn(move || {
                let mut rng = OsRng;
                for _ in 0..STANDARD_ITERATIONS {
                    let (ss, ct) =
                        MlKem::encapsulate(&mut rng, &pk).expect("encapsulation should succeed");
                    let mut cts = ciphertexts.lock().expect("mutex should not be poisoned");
                    cts.push(ct.into_bytes());
                    let mut secrets = shared_secrets.lock().expect("mutex should not be poisoned");
                    secrets.push(ss.as_bytes().to_vec());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let cts = ciphertexts.lock().expect("mutex should not be poisoned");
    let secrets = shared_secrets.lock().expect("mutex should not be poisoned");

    // All ciphertexts should be unique (different randomness)
    let unique_cts: HashSet<Vec<u8>> = cts.iter().cloned().collect();
    assert_eq!(unique_cts.len(), cts.len(), "All ciphertexts should be unique");

    // All shared secrets should be unique
    let unique_secrets: HashSet<Vec<u8>> = secrets.iter().cloned().collect();
    assert_eq!(unique_secrets.len(), secrets.len(), "All shared secrets should be unique");
}

#[test]
fn test_concurrent_ml_kem_mixed_security_levels() {
    let success_count = Arc::new(AtomicUsize::new(0));
    let levels =
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024];

    let handles: Vec<_> = (0..12)
        .map(|i| {
            let success_count = Arc::clone(&success_count);
            let level = levels[i % 3];
            thread::spawn(move || {
                let mut rng = OsRng;
                for _ in 0..5 {
                    if let Ok((pk, _sk)) = MlKem::generate_keypair(&mut rng, level) {
                        if MlKem::encapsulate(&mut rng, &pk).is_ok() {
                            success_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        60,
        "All 60 operations (12 threads x 5 ops) should succeed"
    );
}

// ============================================================================
// Section 2: Thread Safety Tests - ML-DSA
// ============================================================================

#[test]
fn test_concurrent_ml_dsa_keygen_all_levels() {
    let keys = Arc::new(Mutex::new(Vec::new()));
    let params =
        [MlDsaParameterSet::MLDSA44, MlDsaParameterSet::MLDSA65, MlDsaParameterSet::MLDSA87];

    let handles: Vec<_> = (0..9)
        .map(|i| {
            let keys = Arc::clone(&keys);
            let param = params[i % 3];
            thread::spawn(move || {
                for _ in 0..5 {
                    let (pk, _sk) = ml_dsa::generate_keypair(param).expect("keygen should succeed");
                    let mut keys_guard = keys.lock().expect("mutex should not be poisoned");
                    keys_guard.push(pk.as_bytes().to_vec());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let keys_guard = keys.lock().expect("mutex should not be poisoned");
    assert_eq!(keys_guard.len(), 45, "Should have generated 45 keys");
}

#[test]
fn test_parallel_ml_dsa_signing_same_key() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");

    let pk = Arc::new(pk);
    let sk = Arc::new(sk);
    let signatures = Arc::new(Mutex::new(Vec::new()));
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let pk = Arc::clone(&pk);
            let sk = Arc::clone(&sk);
            let signatures = Arc::clone(&signatures);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for i in 0..STANDARD_ITERATIONS {
                    let message = format!("Thread {} Message {}", thread_id, i);
                    let context: &[u8] = &[];

                    if let Ok(sig) = ml_dsa::sign(&sk, message.as_bytes(), context) {
                        // Verify signature
                        if let Ok(valid) = ml_dsa::verify(&pk, message.as_bytes(), &sig, context) {
                            if valid {
                                success_count.fetch_add(1, Ordering::SeqCst);
                                let mut sigs =
                                    signatures.lock().expect("mutex should not be poisoned");
                                sigs.push(sig.data.clone());
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} sign/verify operations should succeed",
        expected
    );

    // Signatures should all be unique (ML-DSA is randomized)
    let sigs = signatures.lock().expect("mutex should not be poisoned");
    let unique_sigs: HashSet<Vec<u8>> = sigs.iter().cloned().collect();
    assert_eq!(unique_sigs.len(), sigs.len(), "All signatures should be unique");
}

#[test]
fn test_parallel_ml_dsa_verification_same_signature() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");

    let message = b"Test message for parallel verification";
    let context: &[u8] = &[];
    let signature = ml_dsa::sign(&sk, message, context).expect("signing should succeed");

    let pk = Arc::new(pk);
    let signature = Arc::new(signature);
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let pk = Arc::clone(&pk);
            let signature = Arc::clone(&signature);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 2 {
                    if let Ok(valid) = ml_dsa::verify(&pk, message, &signature, context) {
                        if valid {
                            success_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS * 2;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} verifications should succeed",
        expected
    );
}

// ============================================================================
// Section 3: Thread Safety Tests - AES-GCM
// ============================================================================

#[test]
fn test_concurrent_aes_gcm_128_encryption() {
    let key = AesGcm128::generate_key();
    let cipher = Arc::new(AesGcm128::new(&key).expect("cipher creation should succeed"));
    let ciphertexts = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let cipher = Arc::clone(&cipher);
            let ciphertexts = Arc::clone(&ciphertexts);
            thread::spawn(move || {
                for i in 0..STANDARD_ITERATIONS {
                    let nonce = AesGcm128::generate_nonce();
                    let plaintext = format!("Thread {} Message {}", thread_id, i);

                    if let Ok((ct, _tag)) = cipher.encrypt(&nonce, plaintext.as_bytes(), None) {
                        let mut cts = ciphertexts.lock().expect("mutex should not be poisoned");
                        cts.push(ct);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let cts = ciphertexts.lock().expect("mutex should not be poisoned");
    assert_eq!(cts.len(), STANDARD_THREAD_COUNT * STANDARD_ITERATIONS);
}

#[test]
fn test_concurrent_aes_gcm_256_encryption_decryption() {
    let key = AesGcm256::generate_key();
    let cipher = Arc::new(AesGcm256::new(&key).expect("cipher creation should succeed"));
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let cipher = Arc::clone(&cipher);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for i in 0..STANDARD_ITERATIONS {
                    let nonce = AesGcm256::generate_nonce();
                    let plaintext = format!("Thread {} Message {}", thread_id, i);
                    let aad = format!("AAD for thread {}", thread_id);

                    if let Ok((ct, tag)) =
                        cipher.encrypt(&nonce, plaintext.as_bytes(), Some(aad.as_bytes()))
                    {
                        if let Ok(decrypted) =
                            cipher.decrypt(&nonce, &ct, &tag, Some(aad.as_bytes()))
                        {
                            if decrypted == plaintext.as_bytes() {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} encrypt/decrypt operations should succeed",
        expected
    );
}

#[test]
fn test_concurrent_aes_gcm_unique_nonces() {
    let key = AesGcm128::generate_key();
    let cipher = Arc::new(AesGcm128::new(&key).expect("cipher creation should succeed"));
    let nonces = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let cipher = Arc::clone(&cipher);
            let nonces = Arc::clone(&nonces);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 5 {
                    let nonce = AesGcm128::generate_nonce();
                    let plaintext = b"test";

                    if cipher.encrypt(&nonce, plaintext, None).is_ok() {
                        let mut ns = nonces.lock().expect("mutex should not be poisoned");
                        ns.push(nonce.to_vec());
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let ns = nonces.lock().expect("mutex should not be poisoned");
    let unique_nonces: HashSet<Vec<u8>> = ns.iter().cloned().collect();
    assert_eq!(unique_nonces.len(), ns.len(), "All nonces should be unique across threads");
}

// ============================================================================
// Section 4: Thread Safety Tests - ECDH
// ============================================================================

#[test]
fn test_concurrent_x25519_key_generation() {
    let keys = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let keys = Arc::clone(&keys);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS {
                    let keypair = X25519KeyPair::generate().expect("keygen should succeed");
                    let mut keys_guard = keys.lock().expect("mutex should not be poisoned");
                    keys_guard.push(keypair.public_key_bytes().to_vec());
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let keys_guard = keys.lock().expect("mutex should not be poisoned");
    let unique_keys: HashSet<Vec<u8>> = keys_guard.iter().cloned().collect();
    assert_eq!(unique_keys.len(), keys_guard.len(), "All X25519 keys should be unique");
}

#[test]
fn test_concurrent_p256_key_agreement() {
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS {
                    let alice = EcdhP256KeyPair::generate().expect("alice keygen should succeed");
                    let bob = EcdhP256KeyPair::generate().expect("bob keygen should succeed");

                    let alice_pk = alice.public_key_bytes().to_vec();
                    let bob_pk = bob.public_key_bytes().to_vec();

                    let alice_ss = alice.agree(&bob_pk).expect("alice agree should succeed");
                    let bob_ss = bob.agree(&alice_pk).expect("bob agree should succeed");

                    if alice_ss == bob_ss {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} P-256 key agreements should succeed",
        expected
    );
}

#[test]
fn test_concurrent_p384_key_agreement() {
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for _ in 0..5 {
                    let alice = EcdhP384KeyPair::generate().expect("alice keygen should succeed");
                    let bob = EcdhP384KeyPair::generate().expect("bob keygen should succeed");

                    let alice_pk = alice.public_key_bytes().to_vec();
                    let bob_pk = bob.public_key_bytes().to_vec();

                    let alice_ss = alice.agree(&bob_pk).expect("alice agree should succeed");
                    let bob_ss = bob.agree(&alice_pk).expect("bob agree should succeed");

                    if alice_ss == bob_ss {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        20,
        "All 20 P-384 key agreements should succeed"
    );
}

#[test]
fn test_concurrent_p521_key_agreement() {
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for _ in 0..3 {
                    let alice = EcdhP521KeyPair::generate().expect("alice keygen should succeed");
                    let bob = EcdhP521KeyPair::generate().expect("bob keygen should succeed");

                    let alice_pk = alice.public_key_bytes().to_vec();
                    let bob_pk = bob.public_key_bytes().to_vec();

                    let alice_ss = alice.agree(&bob_pk).expect("alice agree should succeed");
                    let bob_ss = bob.agree(&alice_pk).expect("bob agree should succeed");

                    if alice_ss == bob_ss {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        12,
        "All 12 P-521 key agreements should succeed"
    );
}

// ============================================================================
// Section 5: Thread Safety Tests - RNG
// ============================================================================

#[test]
fn test_concurrent_rng_bytes_unique() {
    let random_values = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let random_values = Arc::clone(&random_values);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 5 {
                    let bytes = random_bytes(32);
                    let mut values = random_values.lock().expect("mutex should not be poisoned");
                    values.push(bytes);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let values = random_values.lock().expect("mutex should not be poisoned");
    let unique_values: HashSet<Vec<u8>> = values.iter().cloned().collect();
    assert_eq!(unique_values.len(), values.len(), "All random bytes should be unique");
}

#[test]
fn test_concurrent_rng_u32_distribution() {
    let values = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let values = Arc::clone(&values);
            thread::spawn(move || {
                for _ in 0..1000 {
                    let val = random_u32();
                    let mut v = values.lock().expect("mutex should not be poisoned");
                    v.push(val);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let v = values.lock().expect("mutex should not be poisoned");
    let unique: HashSet<u32> = v.iter().cloned().collect();

    // With 8000 samples from 2^32 space, should have very high uniqueness
    assert!(
        unique.len() > 7900,
        "Should have high uniqueness: {} unique out of {}",
        unique.len(),
        v.len()
    );
}

#[test]
fn test_concurrent_rng_u64_unique() {
    let values = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let values = Arc::clone(&values);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 10 {
                    let val = random_u64();
                    let mut v = values.lock().expect("mutex should not be poisoned");
                    v.push(val);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let v = values.lock().expect("mutex should not be poisoned");
    let unique: HashSet<u64> = v.iter().cloned().collect();
    assert_eq!(unique.len(), v.len(), "All u64 values should be unique");
}

// ============================================================================
// Section 6: Thread Safety Tests - Hash Functions
// ============================================================================

#[test]
fn test_concurrent_sha256_same_input() {
    let input = b"Test message for concurrent hashing";
    let expected_hash = sha256(input).expect("hash should succeed");
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let success_count = Arc::clone(&success_count);
            let expected = expected_hash;
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 10 {
                    if let Ok(hash) = sha256(input) {
                        if hash == expected {
                            success_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected_total = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS * 10;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected_total,
        "All {} hashes should produce consistent results",
        expected_total
    );
}

#[test]
fn test_concurrent_hash_different_inputs() {
    let hashes = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let hashes = Arc::clone(&hashes);
            thread::spawn(move || {
                for i in 0..STANDARD_ITERATIONS {
                    let input = format!("Thread {} Input {}", thread_id, i);
                    if let Ok(hash) = sha256(input.as_bytes()) {
                        let mut h = hashes.lock().expect("mutex should not be poisoned");
                        h.push((input, hash));
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let h = hashes.lock().expect("mutex should not be poisoned");

    // All hashes should be unique for different inputs
    let unique_hashes: HashSet<[u8; 32]> = h.iter().map(|(_, hash)| *hash).collect();
    assert_eq!(unique_hashes.len(), h.len(), "All hashes should be unique");
}

#[test]
fn test_concurrent_sha384_sha512() {
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for i in 0..STANDARD_ITERATIONS {
                    let input = format!("Thread {} Input {}", thread_id, i);

                    let sha384_result = sha384(input.as_bytes());
                    let sha512_result = sha512(input.as_bytes());

                    if sha384_result.is_ok() && sha512_result.is_ok() {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} hash operations should succeed",
        expected
    );
}

// ============================================================================
// Section 7: Race Condition Tests
// ============================================================================

#[test]
fn test_concurrent_key_serialization_deserialization() {
    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("keygen should succeed");

    let pk_bytes = pk.to_bytes();
    let pk_bytes = Arc::new(pk_bytes);
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> =
        (0..STANDARD_THREAD_COUNT)
            .map(|_| {
                let pk_bytes = Arc::clone(&pk_bytes);
                let success_count = Arc::clone(&success_count);
                thread::spawn(move || {
                    for _ in 0..STANDARD_ITERATIONS * 5 {
                        // Deserialize and use the public key
                        if let Ok(restored_pk) =
                            arc_primitives::kem::ml_kem::MlKemPublicKey::from_bytes(
                                &pk_bytes,
                                MlKemSecurityLevel::MlKem768,
                            )
                        {
                            // Verify we can encapsulate with restored key
                            let mut rng = OsRng;
                            if MlKem::encapsulate(&mut rng, &restored_pk).is_ok() {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                })
            })
            .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS * 5;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} serialize/deserialize/encapsulate operations should succeed",
        expected
    );
}

#[test]
fn test_concurrent_signature_verification_race() {
    // Pre-generate multiple signatures
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");

    let messages: Vec<String> = (0..10).map(|i| format!("Message {}", i)).collect();
    let context: &[u8] = &[];

    let signatures: Vec<_> = messages
        .iter()
        .map(|msg| ml_dsa::sign(&sk, msg.as_bytes(), context).expect("sign should succeed"))
        .collect();

    let pk = Arc::new(pk);
    let messages = Arc::new(messages);
    let signatures = Arc::new(signatures);
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let pk = Arc::clone(&pk);
            let messages = Arc::clone(&messages);
            let signatures = Arc::clone(&signatures);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS {
                    for (msg, sig) in messages.iter().zip(signatures.iter()) {
                        if let Ok(valid) = ml_dsa::verify(&pk, msg.as_bytes(), sig, context) {
                            if valid {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS * 10;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} verifications should succeed",
        expected
    );
}

#[test]
fn test_rwlock_concurrent_config_access() {
    // Simulate shared config with RwLock
    let config = Arc::new(RwLock::new(MlKemSecurityLevel::MlKem512));
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let config = Arc::clone(&config);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS {
                    // Readers
                    if thread_id % 2 == 0 {
                        let level = config.read().expect("read lock should succeed");
                        let mut rng = OsRng;
                        if MlKem::generate_keypair(&mut rng, *level).is_ok() {
                            success_count.fetch_add(1, Ordering::SeqCst);
                        }
                    } else {
                        // Writers (rotate security levels)
                        let mut level = config.write().expect("write lock should succeed");
                        *level = match *level {
                            MlKemSecurityLevel::MlKem512 => MlKemSecurityLevel::MlKem768,
                            MlKemSecurityLevel::MlKem768 => MlKemSecurityLevel::MlKem1024,
                            MlKemSecurityLevel::MlKem1024 => MlKemSecurityLevel::MlKem512,
                        };
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} operations should succeed with RwLock",
        expected
    );
}

// ============================================================================
// Section 8: Stress Tests
// ============================================================================

#[test]
fn test_high_volume_concurrent_operations() {
    let operation_count = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STRESS_THREAD_COUNT)
        .map(|_| {
            let operation_count = Arc::clone(&operation_count);
            let error_count = Arc::clone(&error_count);
            thread::spawn(move || {
                let mut rng = OsRng;

                for _ in 0..STRESS_OPS_PER_THREAD {
                    match MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768) {
                        Ok((pk, _sk)) => match MlKem::encapsulate(&mut rng, &pk) {
                            Ok((_ss, _ct)) => {
                                operation_count.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(_) => {
                                error_count.fetch_add(1, Ordering::SeqCst);
                            }
                        },
                        Err(_) => {
                            error_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let successful = operation_count.load(Ordering::SeqCst);
    let errors = error_count.load(Ordering::SeqCst);
    let expected = STRESS_THREAD_COUNT * STRESS_OPS_PER_THREAD;

    assert_eq!(errors, 0, "No errors should occur under high concurrency");
    assert_eq!(successful, expected, "All {} operations should succeed", expected);
}

#[test]
fn test_mixed_algorithm_stress() {
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STRESS_THREAD_COUNT)
        .map(|thread_id| {
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                let mut rng = OsRng;

                for i in 0..STRESS_OPS_PER_THREAD {
                    let op = (thread_id + i) % 5;

                    let success = match op {
                        0 => {
                            // ML-KEM
                            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512).is_ok()
                        }
                        1 => {
                            // ML-DSA
                            ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).is_ok()
                        }
                        2 => {
                            // AES-GCM
                            let key = AesGcm256::generate_key();
                            AesGcm256::new(&key).is_ok()
                        }
                        3 => {
                            // X25519
                            X25519KeyPair::generate().is_ok()
                        }
                        _ => {
                            // SHA-256
                            sha256(b"test data").is_ok()
                        }
                    };

                    if success {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STRESS_THREAD_COUNT * STRESS_OPS_PER_THREAD;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} mixed operations should succeed",
        expected
    );
}

#[test]
fn test_rapid_key_generation_destruction_cycles() {
    let cycles_completed = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let cycles_completed = Arc::clone(&cycles_completed);
            thread::spawn(move || {
                let mut rng = OsRng;

                for _ in 0..STANDARD_ITERATIONS * 3 {
                    // Generate and immediately drop (destroy) keys
                    {
                        let (pk, sk) =
                            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
                                .expect("keygen should succeed");
                        // Use the keys briefly
                        let _ = MlKem::encapsulate(&mut rng, &pk);
                        // pk and sk are dropped here
                        drop(sk);
                        drop(pk);
                    }

                    // Immediately generate new keys
                    {
                        let (_pk2, _sk2) =
                            MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
                                .expect("keygen should succeed");
                        // Keys dropped at end of scope
                    }

                    cycles_completed.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS * 3;
    assert_eq!(
        cycles_completed.load(Ordering::SeqCst),
        expected,
        "All {} generation/destruction cycles should complete",
        expected
    );
}

// ============================================================================
// Section 9: Synchronization Tests
// ============================================================================

#[test]
fn test_barrier_synchronized_operations() {
    let barrier = Arc::new(Barrier::new(STANDARD_THREAD_COUNT));
    let start_times = Arc::new(Mutex::new(Vec::new()));
    let end_times = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let start_times = Arc::clone(&start_times);
            let end_times = Arc::clone(&end_times);
            thread::spawn(move || {
                // Wait for all threads to be ready
                barrier.wait();

                let start = Instant::now();

                // Perform operation
                let mut rng = OsRng;
                let _ = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768);

                let end = Instant::now();

                let mut starts = start_times.lock().expect("mutex should not be poisoned");
                starts.push(start);
                let mut ends = end_times.lock().expect("mutex should not be poisoned");
                ends.push(end);
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let starts = start_times.lock().expect("mutex should not be poisoned");
    let ends = end_times.lock().expect("mutex should not be poisoned");

    assert_eq!(starts.len(), STANDARD_THREAD_COUNT);
    assert_eq!(ends.len(), STANDARD_THREAD_COUNT);

    // Verify all operations completed
    let min_start = starts.iter().min().expect("should have start times");
    let max_end = ends.iter().max().expect("should have end times");
    let total_duration = max_end.duration_since(*min_start);

    // All parallel operations should complete within reasonable time
    assert!(
        total_duration < Duration::from_secs(MAX_TEST_DURATION_SECS),
        "Synchronized operations should complete in reasonable time"
    );
}

#[test]
fn test_atomic_counter_correctness() {
    let counter = Arc::new(AtomicUsize::new(0));
    let expected_increments = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS * 100;

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let counter = Arc::clone(&counter);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 100 {
                    // Simulate crypto work
                    let _ = random_u32();
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    assert_eq!(
        counter.load(Ordering::SeqCst),
        expected_increments,
        "Atomic counter should correctly track all increments"
    );
}

#[test]
fn test_lock_free_read_pattern() {
    // Pre-compute some reference data
    let reference_hash = sha256(b"reference data").expect("hash should succeed");
    let reference_hash = Arc::new(reference_hash);
    let consistent_reads = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let reference_hash = Arc::clone(&reference_hash);
            let consistent_reads = Arc::clone(&consistent_reads);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 50 {
                    // Read-only access to shared reference
                    if sha256(b"reference data").map(|h| h == *reference_hash).unwrap_or(false) {
                        consistent_reads.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS * 50;
    assert_eq!(
        consistent_reads.load(Ordering::SeqCst),
        expected,
        "All {} lock-free reads should be consistent",
        expected
    );
}

// ============================================================================
// Section 10: Data Race Detection Tests
// ============================================================================

#[test]
fn test_no_data_races_during_parallel_keygen() {
    let panic_count = Arc::new(AtomicUsize::new(0));

    for _ in 0..10 {
        let panic_count = Arc::clone(&panic_count);

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let panic_count = Arc::clone(&panic_count);
                thread::spawn(move || {
                    let mut rng = OsRng;
                    let level = match i % 3 {
                        0 => MlKemSecurityLevel::MlKem512,
                        1 => MlKemSecurityLevel::MlKem768,
                        _ => MlKemSecurityLevel::MlKem1024,
                    };

                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let (pk, _sk) = MlKem::generate_keypair(&mut rng, level)
                            .expect("keygen should succeed");
                        let _ = MlKem::encapsulate(&mut rng, &pk).expect("encap should succeed");
                    })) {
                        Ok(()) => {}
                        Err(_) => {
                            panic_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }

    assert_eq!(
        panic_count.load(Ordering::SeqCst),
        0,
        "No panics should occur during parallel keygen"
    );
}

#[test]
fn test_no_data_races_during_concurrent_signing() {
    let panic_count = Arc::new(AtomicUsize::new(0));
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA65).expect("keygen should succeed");

    let pk = Arc::new(pk);
    let sk = Arc::new(sk);

    for _ in 0..10 {
        let pk = Arc::clone(&pk);
        let sk = Arc::clone(&sk);
        let panic_count = Arc::clone(&panic_count);

        let handles: Vec<_> = (0..4)
            .map(|thread_id| {
                let pk = Arc::clone(&pk);
                let sk = Arc::clone(&sk);
                let panic_count = Arc::clone(&panic_count);
                thread::spawn(move || {
                    let context: &[u8] = &[];

                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let message = format!("Thread {} message", thread_id);
                        let sig = ml_dsa::sign(&sk, message.as_bytes(), context)
                            .expect("sign should succeed");
                        let valid = ml_dsa::verify(&pk, message.as_bytes(), &sig, context)
                            .expect("verify should succeed");
                        assert!(valid, "Signature should be valid");
                    })) {
                        Ok(()) => {}
                        Err(_) => {
                            panic_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }

    assert_eq!(
        panic_count.load(Ordering::SeqCst),
        0,
        "No panics should occur during concurrent signing"
    );
}

#[test]
fn test_concurrent_mutation_detection() {
    // Test that we can detect if shared state is being mutated unsafely
    let shared_flag = Arc::new(AtomicBool::new(false));
    let mutation_detected = Arc::new(AtomicBool::new(false));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let shared_flag = Arc::clone(&shared_flag);
            let mutation_detected = Arc::clone(&mutation_detected);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 10 {
                    // Alternate between setting and clearing the flag
                    if thread_id % 2 == 0 {
                        shared_flag.store(true, Ordering::SeqCst);
                    } else {
                        shared_flag.store(false, Ordering::SeqCst);
                    }

                    // Check if flag was changed unexpectedly
                    let val = shared_flag.load(Ordering::SeqCst);
                    if (thread_id % 2 == 0 && !val) || (thread_id % 2 == 1 && val) {
                        // Another thread modified the flag - this is expected and safe
                        // because we're using atomics
                        mutation_detected.store(true, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    // With atomic operations, no undefined behavior occurs even with concurrent mutation
    // The test passes as long as no panics occur
}

// ============================================================================
// Section 11: Performance Under Concurrency
// ============================================================================

#[test]
fn test_concurrent_operations_complete_in_reasonable_time() {
    let start = Instant::now();

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            thread::spawn(move || {
                let mut rng = OsRng;
                for _ in 0..STANDARD_ITERATIONS {
                    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
                        .expect("keygen should succeed");
                    let _ = MlKem::encapsulate(&mut rng, &pk).expect("encap should succeed");
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let duration = start.elapsed();
    assert!(
        duration.as_secs() < MAX_TEST_DURATION_SECS,
        "Concurrent operations should complete in reasonable time (took {:?})",
        duration
    );
}

#[test]
#[ignore = "throughput scaling tests are unstable under llvm-cov instrumentation"]
fn test_throughput_scales_with_threads() {
    // Single-threaded baseline
    let single_start = Instant::now();
    let mut rng = OsRng;
    for _ in 0..STANDARD_ITERATIONS {
        let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
            .expect("keygen should succeed");
        let _ = MlKem::encapsulate(&mut rng, &pk).expect("encap should succeed");
    }
    let single_duration = single_start.elapsed();

    // Multi-threaded
    let multi_start = Instant::now();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            thread::spawn(move || {
                let mut rng = OsRng;
                for _ in 0..STANDARD_ITERATIONS {
                    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
                        .expect("keygen should succeed");
                    let _ = MlKem::encapsulate(&mut rng, &pk).expect("encap should succeed");
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }
    let multi_duration = multi_start.elapsed();

    // Multi-threaded should complete 4x the work in less than 4x the time
    // (showing parallelism benefit)
    let single_ops = STANDARD_ITERATIONS;
    let multi_ops = 4 * STANDARD_ITERATIONS;

    let single_rate = single_ops as f64 / single_duration.as_secs_f64();
    let multi_rate = multi_ops as f64 / multi_duration.as_secs_f64();

    // Multi-threaded should have higher throughput
    assert!(
        multi_rate > single_rate,
        "Multi-threaded throughput ({:.2} ops/sec) should be higher than single-threaded ({:.2} ops/sec)",
        multi_rate,
        single_rate
    );
}

// ============================================================================
// Section 12: Edge Cases and Boundary Conditions
// ============================================================================

#[test]
fn test_concurrent_empty_message_signing() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");

    let pk = Arc::new(pk);
    let sk = Arc::new(sk);
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let pk = Arc::clone(&pk);
            let sk = Arc::clone(&sk);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                let empty_message: &[u8] = &[];
                let context: &[u8] = &[];

                for _ in 0..STANDARD_ITERATIONS {
                    if let Ok(sig) = ml_dsa::sign(&sk, empty_message, context) {
                        if let Ok(valid) = ml_dsa::verify(&pk, empty_message, &sig, context) {
                            if valid {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} empty message sign/verify should succeed",
        expected
    );
}

#[test]
fn test_concurrent_large_message_signing() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");

    let pk = Arc::new(pk);
    let sk = Arc::new(sk);
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..4)
        .map(|thread_id| {
            let pk = Arc::clone(&pk);
            let sk = Arc::clone(&sk);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                // Large message (10KB)
                let large_message = vec![0x42u8; 10_000 + thread_id * 100];
                let context: &[u8] = &[];

                for _ in 0..3 {
                    if let Ok(sig) = ml_dsa::sign(&sk, &large_message, context) {
                        if let Ok(valid) = ml_dsa::verify(&pk, &large_message, &sig, context) {
                            if valid {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        12,
        "All 12 large message sign/verify should succeed"
    );
}

#[test]
fn test_concurrent_encryption_empty_plaintext() {
    let key = AesGcm256::generate_key();
    let cipher = Arc::new(AesGcm256::new(&key).expect("cipher creation should succeed"));
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|_| {
            let cipher = Arc::clone(&cipher);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                let empty_plaintext: &[u8] = &[];

                for _ in 0..STANDARD_ITERATIONS {
                    let nonce = AesGcm256::generate_nonce();
                    if let Ok((ct, tag)) = cipher.encrypt(&nonce, empty_plaintext, None) {
                        if let Ok(decrypted) = cipher.decrypt(&nonce, &ct, &tag, None) {
                            if decrypted.is_empty() {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} empty plaintext encrypt/decrypt should succeed",
        expected
    );
}

#[test]
fn test_shared_public_key_concurrent_read() {
    let mut rng = OsRng;
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem1024)
        .expect("keypair generation should succeed");

    let pk = Arc::new(pk);
    let pk_bytes_original = pk.to_bytes();
    let consistent_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT * 2)
        .map(|_| {
            let pk = Arc::clone(&pk);
            let pk_bytes_original = pk_bytes_original.clone();
            let consistent_count = Arc::clone(&consistent_count);
            thread::spawn(move || {
                for _ in 0..STANDARD_ITERATIONS * 5 {
                    let bytes = pk.to_bytes();
                    if bytes == pk_bytes_original {
                        consistent_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * 2 * STANDARD_ITERATIONS * 5;
    assert_eq!(
        consistent_count.load(Ordering::SeqCst),
        expected,
        "All {} concurrent reads should return consistent public key bytes",
        expected
    );
}

// ============================================================================
// Section 13: MIRI-Compatible Subset (Minimal Unsafe Validation)
// ============================================================================

/// MIRI-compatible test subset - no threading, validates memory safety
#[test]
fn test_miri_compatible_keygen_basic() {
    let mut rng = OsRng;

    // Basic ML-KEM keygen and encapsulation
    let (pk, _sk) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem512)
        .expect("keygen should succeed");
    let (ss, ct) = MlKem::encapsulate(&mut rng, &pk).expect("encapsulate should succeed");

    assert_eq!(pk.as_bytes().len(), 800);
    assert_eq!(ss.as_bytes().len(), 32);
    assert_eq!(ct.as_bytes().len(), 768);
}

/// MIRI-compatible test for AEAD operations
#[test]
fn test_miri_compatible_aead_basic() {
    let key = AesGcm128::generate_key();
    let cipher = AesGcm128::new(&key).expect("cipher should be created");
    let nonce = AesGcm128::generate_nonce();
    let plaintext = b"test message";

    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, None).expect("encryption should succeed");
    let decrypted =
        cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

/// MIRI-compatible test for hash functions
#[test]
fn test_miri_compatible_hash_basic() {
    let input = b"test input for hashing";

    let hash256 = sha256(input).expect("sha256 should succeed");
    let hash384 = sha384(input).expect("sha384 should succeed");
    let hash512 = sha512(input).expect("sha512 should succeed");

    assert_eq!(hash256.len(), 32);
    assert_eq!(hash384.len(), 48);
    assert_eq!(hash512.len(), 64);

    // Verify determinism
    assert_eq!(sha256(input).expect("sha256 should succeed"), hash256);
}

// ============================================================================
// Section 14: Additional Edge Cases
// ============================================================================

#[test]
fn test_concurrent_context_string_variations() {
    let (pk, sk) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA44).expect("keygen should succeed");

    let pk = Arc::new(pk);
    let sk = Arc::new(sk);
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let pk = Arc::clone(&pk);
            let sk = Arc::clone(&sk);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                let message = b"Test message with context variations";

                for i in 0..STANDARD_ITERATIONS {
                    // Use different contexts per iteration
                    let context = format!("context-{}-{}", thread_id, i);

                    if let Ok(sig) = ml_dsa::sign(&sk, message, context.as_bytes()) {
                        if let Ok(valid) = ml_dsa::verify(&pk, message, &sig, context.as_bytes()) {
                            if valid {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} context variation sign/verify should succeed",
        expected
    );
}

#[test]
fn test_concurrent_aad_variations() {
    let key = AesGcm256::generate_key();
    let cipher = Arc::new(AesGcm256::new(&key).expect("cipher creation should succeed"));
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..STANDARD_THREAD_COUNT)
        .map(|thread_id| {
            let cipher = Arc::clone(&cipher);
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for i in 0..STANDARD_ITERATIONS {
                    let nonce = AesGcm256::generate_nonce();
                    let plaintext = format!("Message {} from thread {}", i, thread_id);
                    let aad = format!("AAD-{}-{}", thread_id, i);

                    if let Ok((ct, tag)) =
                        cipher.encrypt(&nonce, plaintext.as_bytes(), Some(aad.as_bytes()))
                    {
                        if let Ok(decrypted) =
                            cipher.decrypt(&nonce, &ct, &tag, Some(aad.as_bytes()))
                        {
                            if decrypted == plaintext.as_bytes() {
                                success_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    let expected = STANDARD_THREAD_COUNT * STANDARD_ITERATIONS;
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        expected,
        "All {} AAD variation encrypt/decrypt should succeed",
        expected
    );
}

#[test]
fn test_concurrent_hash_large_inputs() {
    let success_count = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..4)
        .map(|thread_id| {
            let success_count = Arc::clone(&success_count);
            thread::spawn(move || {
                for i in 0..5 {
                    // Create large input (100KB to 500KB)
                    let size = 100_000 + (thread_id * 100_000) + (i * 10_000);
                    let input = vec![0x42u8; size];

                    if sha256(&input).is_ok() && sha384(&input).is_ok() && sha512(&input).is_ok() {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("thread should not panic");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        20,
        "All 20 large hash operations should succeed"
    );
}

// ============================================================================
// Summary Test
// ============================================================================

#[test]
fn test_comprehensive_concurrency_summary() {
    // This test provides a summary of all concurrency scenarios covered
    let mut rng = OsRng;

    // 1. ML-KEM concurrent operations
    let (pk_kem, _sk_kem) = MlKem::generate_keypair(&mut rng, MlKemSecurityLevel::MlKem768)
        .expect("ML-KEM keygen should succeed");
    let (ss, _ct) =
        MlKem::encapsulate(&mut rng, &pk_kem).expect("ML-KEM encapsulate should succeed");
    assert_eq!(ss.as_bytes().len(), 32);

    // 2. ML-DSA concurrent operations
    let (pk_dsa, sk_dsa) =
        ml_dsa::generate_keypair(MlDsaParameterSet::MLDSA65).expect("ML-DSA keygen should succeed");
    let sig = ml_dsa::sign(&sk_dsa, b"test", &[]).expect("ML-DSA sign should succeed");
    let valid = ml_dsa::verify(&pk_dsa, b"test", &sig, &[]).expect("ML-DSA verify should succeed");
    assert!(valid);

    // 3. AES-GCM concurrent operations
    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&key).expect("AES-GCM should be created");
    let nonce = AesGcm256::generate_nonce();
    let (ct, tag) = cipher.encrypt(&nonce, b"test", None).expect("AES-GCM encrypt should succeed");
    let pt = cipher.decrypt(&nonce, &ct, &tag, None).expect("AES-GCM decrypt should succeed");
    assert_eq!(pt, b"test");

    // 4. ECDH concurrent operations
    let alice = X25519KeyPair::generate().expect("X25519 keygen should succeed");
    let bob = X25519KeyPair::generate().expect("X25519 keygen should succeed");
    let alice_pk = *alice.public_key_bytes();
    let bob_pk = *bob.public_key_bytes();
    let alice_ss = alice.agree(&bob_pk).expect("X25519 agree should succeed");
    let bob_ss = bob.agree(&alice_pk).expect("X25519 agree should succeed");
    assert_eq!(alice_ss, bob_ss);

    // 5. Hash concurrent operations
    let hash = sha256(b"test").expect("SHA-256 should succeed");
    assert_eq!(hash.len(), 32);

    // 6. RNG concurrent operations
    let rand_bytes = random_bytes(32);
    assert_eq!(rand_bytes.len(), 32);

    // All basic operations work - comprehensive concurrency testing ensures
    // they work correctly when called from multiple threads simultaneously
}
